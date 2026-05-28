/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief HTTP from a test
 *
 * One request through curl on the agent, and the whole answer parsed
 * back out of what it printed.
 */

#define TE_LGR_USER "TAPI HTTP"

#include "te_config.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_sleep.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_http.h"
#include "tapi_http_internal.h"

/**
 * What curl is asked to print after the body.
 *
 * curl can only write this at the end, so a body that contains the
 * same text would be mistaken for it. The marker is searched for from
 * the end of the output for that reason, and it is long and unlikely
 * enough that a response would have to be built to defeat it
 * deliberately.
 */
#define HTTP_MARKER "__TAPI_HTTP_END_a4f1__"

/** How often tapi_http_wait_ready() asks again, ms. */
#define HTTP_POLL_MS 250

const tapi_http_request_opt tapi_http_request_default_opt = {
    .follow = true,
};

/* See description in tapi_http_internal.h */
void
tapi_http_arg(te_vec *args, const char *fmt, ...)
{
    te_string built = TE_STRING_INIT;
    char *arg;
    va_list ap;

    va_start(ap, fmt);
    te_string_append_va(&built, fmt, ap);
    va_end(ap);

    arg = built.ptr;
    TE_VEC_APPEND(args, arg);
}

/* See description in tapi_http_internal.h */
char *
tapi_http_trim(char *text)
{
    size_t len;
    char *start = text;

    while (*start == ' ' || *start == '\t' || *start == '\r')
        start++;

    if (start != text)
        memmove(text, start, strlen(start) + 1);

    len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t' ||
                       text[len - 1] == '\r' || text[len - 1] == '\n'))
    {
        text[--len] = '\0';
    }

    return text;
}

/** Build the curl command line. */
static void
http_build_args(const tapi_http_request_opt *opt, te_vec *args)
{
    size_t i;

    /* Quiet, but not about errors: a failure has to reach the log. */
    tapi_http_arg(args, "-sS");
    /* Headers and body on stdout, which is what gets parsed. */
    tapi_http_arg(args, "-i");

    if (opt->method != NULL && strcasecmp(opt->method, "HEAD") == 0)
    {
        /*
         * -I rather than -X HEAD. With -X HEAD curl still expects a
         * body, the server correctly sends none, and the request
         * hangs until its timeout - a trap old enough to have its own
         * entry in curl's manual.
         */
        tapi_http_arg(args, "-I");
    }
    else if (opt->method != NULL)
    {
        tapi_http_arg(args, "-X");
        tapi_http_arg(args, "%s", opt->method);
    }

    for (i = 0; i < opt->n_headers; i++)
    {
        tapi_http_arg(args, "-H");
        tapi_http_arg(args, "%s", opt->headers[i]);
    }

    if (opt->body != NULL)
    {
        tapi_http_arg(args, "--data-binary");
        tapi_http_arg(args, "%s", opt->body);
    }

    if (opt->follow)
    {
        tapi_http_arg(args, "-L");
        if (opt->max_redirects != 0)
        {
            tapi_http_arg(args, "--max-redirs");
            tapi_http_arg(args, "%u", opt->max_redirects);
        }
    }

    if (opt->insecure)
        tapi_http_arg(args, "-k");

    if (opt->resolve_to != NULL)
    {
        tapi_http_arg(args, "--resolve");
        tapi_http_arg(args, "%s", opt->resolve_to);
    }

    if (opt->timeout_s != 0)
    {
        tapi_http_arg(args, "--max-time");
        tapi_http_arg(args, "%u", opt->timeout_s);
    }

    for (i = 0; i < opt->n_extra_args; i++)
        tapi_http_arg(args, "%s", opt->extra_args[i]);

    tapi_http_arg(args, "-w");
    tapi_http_arg(args, "\n" HTTP_MARKER " %%{http_code} %%{scheme} "
                        "%%{url_effective}\n");

    tapi_http_arg(args, "%s", opt->url);
}

/** Add one header field to a response. */
static void
http_add_header(tapi_http_response *response, const char *name,
                const char *value)
{
    tapi_http_header_field *grown;

    grown = TE_ALLOC((response->n_headers + 1) * sizeof(*grown));
    if (response->n_headers != 0)
    {
        memcpy(grown, response->headers,
               response->n_headers * sizeof(*grown));
    }
    free(response->headers);
    response->headers = grown;

    response->headers[response->n_headers].name = TE_STRDUP(name);
    response->headers[response->n_headers].value = TE_STRDUP(value);
    response->n_headers++;
}

/** Add one status to the redirect chain. */
static void
http_add_chain(tapi_http_response *response, unsigned int status)
{
    unsigned int *grown;

    grown = TE_ALLOC((response->n_chain + 1) * sizeof(*grown));
    if (response->n_chain != 0)
        memcpy(grown, response->chain, response->n_chain * sizeof(*grown));
    free(response->chain);
    response->chain = grown;

    response->chain[response->n_chain++] = status;
}

/** Is this the start of a status line? */
static bool
http_is_status_line(const char *line)
{
    return strncmp(line, "HTTP/", 5) == 0;
}

/**
 * Parse the header blocks curl printed.
 *
 * With @c -L there is one block per response, the redirects included,
 * each ending in an empty line. The last block describes the answer;
 * the ones before it are the chain that led to it, and only their
 * status codes are kept. The body is whatever follows the last block.
 */
static void
http_parse(const char *text, tapi_http_response *response)
{
    const char *pos = text;

    while (pos != NULL && *pos != '\0')
    {
        const char *line_end;
        bool status_seen = false;

        if (!http_is_status_line(pos))
            break;

        /* A new block: whatever was collected belonged to a redirect. */
        while (response->n_headers != 0)
        {
            response->n_headers--;
            free(response->headers[response->n_headers].name);
            free(response->headers[response->n_headers].value);
        }
        free(response->version);
        free(response->reason);
        response->version = NULL;
        response->reason = NULL;

        for (; pos != NULL && *pos != '\0'; pos = line_end)
        {
            size_t len;
            char *line;

            line_end = strchr(pos, '\n');
            len = line_end != NULL ? (size_t)(line_end - pos) : strlen(pos);
            if (line_end != NULL)
                line_end++;

            line = TE_ALLOC(len + 1);
            memcpy(line, pos, len);
            tapi_http_trim(line);

            if (*line == '\0')
            {
                /* The empty line ends the block; the rest is body. */
                free(line);
                pos = line_end;
                break;
            }

            if (!status_seen && http_is_status_line(line))
            {
                char *space = strchr(line, ' ');

                status_seen = true;
                if (space != NULL)
                {
                    unsigned int status = 0;
                    char *reason;

                    *space = '\0';
                    response->version = TE_STRDUP(line);

                    reason = space + 1;
                    while (*reason == ' ')
                        reason++;

                    (void)te_strtoui(reason, 10, &status);
                    response->status = status;
                    http_add_chain(response, status);

                    while (*reason != '\0' && *reason != ' ')
                        reason++;
                    while (*reason == ' ')
                        reason++;
                    response->reason = TE_STRDUP(reason);
                }
            }
            else
            {
                char *colon = strchr(line, ':');

                if (colon != NULL)
                {
                    *colon = '\0';
                    http_add_header(response, tapi_http_trim(line),
                                    tapi_http_trim(colon + 1));
                }
            }

            free(line);
        }

        /*
         * If what follows is another status line, this block was a
         * redirect and the loop goes round again. Otherwise it is the
         * body.
         */
        if (pos == NULL || !http_is_status_line(pos))
        {
            if (pos != NULL)
                te_string_append(&response->body, "%s", pos);
            break;
        }
    }
}

/** Read the trailer curl was asked to print, and cut it off the body. */
static void
http_take_marker(te_string *text, tapi_http_response *response)
{
    char *found = NULL;
    char *scan = text->ptr;
    char *scheme;
    char *url;

    if (scan == NULL)
        return;

    /* From the end: a body is allowed to contain anything. */
    for (scan = strstr(scan, HTTP_MARKER); scan != NULL;
         scan = strstr(scan + 1, HTTP_MARKER))
    {
        found = scan;
    }

    if (found == NULL)
        return;

    scheme = found + strlen(HTTP_MARKER);
    /* " <code> <scheme> <url>" */
    while (*scheme == ' ')
        scheme++;
    while (*scheme != '\0' && *scheme != ' ')
        scheme++;
    while (*scheme == ' ')
        scheme++;

    url = scheme;
    while (*url != '\0' && *url != ' ')
        url++;

    if (*url == ' ')
    {
        size_t scheme_len = (size_t)(url - scheme);

        response->over_tls = scheme_len == 5 &&
                             strncasecmp(scheme, "https", 5) == 0;

        url++;
        response->final_url = TE_STRDUP(url);
        tapi_http_trim(response->final_url);
    }

    /* Cut the marker and the newline before it out of the output. */
    while (found > text->ptr && found[-1] == '\n')
        found--;
    *found = '\0';
    text->len = strlen(text->ptr);
}

/* See description in tapi_http.h */
te_errno
tapi_http_request(tapi_job_factory_t *factory,
                  const tapi_http_request_opt *opt, int timeout_ms,
                  tapi_http_response *response)
{
    te_vec args = TE_VEC_INIT(char *);
    tapi_devtool_output output;
    tapi_devtool_run run;
    te_string text = TE_STRING_INIT;
    te_errno rc;

    memset(response, 0, sizeof(*response));
    response->body = (te_string)TE_STRING_INIT;

    if (opt->url == NULL)
    {
        ERROR("There is no URL to request");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    http_build_args(opt, &args);

    rc = tapi_http_cmd(factory, "curl", "curl", &args, timeout_ms, &run);
    te_vec_deep_free(&args);
    if (rc != 0)
        return rc;

    tapi_devtool_run_get_output(&run, &output);
    te_string_append(&text, "%s", output.out != NULL ? output.out : "");

    http_take_marker(&text, response);
    http_parse(te_string_value(&text), response);

    if (response->status == 0)
    {
        /*
         * curl said nothing that parses as a response. Its own
         * complaint is on stderr and is what the caller needs, so it
         * goes in the log rather than being swallowed.
         */
        ERROR("Nothing answered at %s: %s", opt->url,
              output.err != NULL && output.err[0] != '\0' ?
                  output.err : "no reply");
        rc = TE_RC(TE_TAPI, TE_ECONNREFUSED);
    }

    te_string_free(&text);
    tapi_devtool_run_fini(&run);

    if (rc != 0)
        tapi_http_response_free(response);

    return rc;
}

/* See description in tapi_http.h */
const char *
tapi_http_header(const tapi_http_response *response, const char *name)
{
    return tapi_http_header_nth(response, name, 0);
}

/* See description in tapi_http.h */
const char *
tapi_http_header_nth(const tapi_http_response *response, const char *name,
                     unsigned int index)
{
    unsigned int seen = 0;
    size_t i;

    for (i = 0; i < response->n_headers; i++)
    {
        if (strcasecmp(response->headers[i].name, name) != 0)
            continue;

        if (seen == index)
            return response->headers[i].value;

        seen++;
    }

    return NULL;
}

/* See description in tapi_http.h */
unsigned int
tapi_http_header_count(const tapi_http_response *response, const char *name)
{
    unsigned int count = 0;
    size_t i;

    for (i = 0; i < response->n_headers; i++)
    {
        if (strcasecmp(response->headers[i].name, name) == 0)
            count++;
    }

    return count;
}

/* See description in tapi_http.h */
void
tapi_http_response_log(const tapi_http_response *response)
{
    te_string chain = TE_STRING_INIT;
    size_t i;

    for (i = 0; i < response->n_chain; i++)
        te_string_append(&chain, "%s%u", i == 0 ? "" : " -> ",
                         response->chain[i]);

    RING("%s %u %s (%s)%s",
         response->version != NULL ? response->version : "HTTP/?",
         response->status,
         response->reason != NULL ? response->reason : "",
         te_string_value(&chain),
         response->over_tls ? " over TLS" : "");

    for (i = 0; i < response->n_headers; i++)
    {
        RING("  %s: %s", response->headers[i].name,
             response->headers[i].value);
    }

    RING("  %zu bytes of body", response->body.len);

    te_string_free(&chain);
}

/* See description in tapi_http.h */
void
tapi_http_response_free(tapi_http_response *response)
{
    size_t i;

    for (i = 0; i < response->n_headers; i++)
    {
        free(response->headers[i].name);
        free(response->headers[i].value);
    }
    free(response->headers);
    free(response->version);
    free(response->reason);
    free(response->chain);
    free(response->final_url);
    te_string_free(&response->body);

    memset(response, 0, sizeof(*response));
    response->body = (te_string)TE_STRING_INIT;
}

/* See description in tapi_http.h */
te_errno
tapi_http_wait_ready(tapi_job_factory_t *factory, const char *url,
                     int timeout_ms)
{
    tapi_http_request_opt opt = tapi_http_request_default_opt;
    int waited_ms;

    opt.url = url;
    opt.method = "HEAD";
    opt.follow = false;
    /*
     * A service that is starting refuses the connection rather than
     * hanging, so a short per-attempt limit keeps the poll a poll.
     */
    opt.timeout_s = 2;

    for (waited_ms = 0; waited_ms < timeout_ms; waited_ms += HTTP_POLL_MS)
    {
        tapi_http_response response;

        if (tapi_http_request(factory, &opt, HTTP_POLL_MS * 8,
                              &response) == 0)
        {
            /* Any status is an answer: a 404 means it is listening. */
            RING("%s answered %u after %d ms", url, response.status,
                 waited_ms);
            tapi_http_response_free(&response);
            return 0;
        }

        te_motivated_msleep(HTTP_POLL_MS, "waiting for the endpoint");
    }

    ERROR("Nothing answered at %s within %d ms", url, timeout_ms);

    return TE_RC(TE_TAPI, TE_ETIMEDOUT);
}

/* See description in tapi_http.h */
bool
tapi_http_available(tapi_job_factory_t *factory, int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    tapi_devtool_output output;
    tapi_devtool_run run;
    bool ok;

    tapi_http_arg(&args, "--version");

    if (tapi_http_cmd(factory, "curl", "curl", &args, timeout_ms,
                      &run) != 0)
    {
        te_vec_deep_free(&args);
        return false;
    }

    tapi_devtool_run_get_output(&run, &output);
    ok = output.status.type == TAPI_JOB_STATUS_EXITED &&
         output.status.value == 0;

    if (!ok)
        RING("There is no curl on the agent");

    te_vec_deep_free(&args);
    tapi_devtool_run_fini(&run);

    return ok;
}
