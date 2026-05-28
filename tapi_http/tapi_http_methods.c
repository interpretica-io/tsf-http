/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What the endpoint lets you do to it
 */

#define TE_LGR_USER "TAPI HTTP"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"

#include "tapi_http_methods.h"
#include "tapi_http_internal.h"

/**
 * The methods asked about.
 *
 * @a send says whether the method is put on the wire. The four that
 * are sent are the ones HTTP defines as safe - they are not allowed to
 * change anything, and a server where they do has a defect of a kind
 * this cannot find anyway. The rest are only ever read out of an
 * OPTIONS answer, because sending them means asking a service under
 * test to modify or delete something, and a scanner that does that has
 * stopped being a scanner.
 */
static const struct {
    const char *name;
    bool send;
} methods_table[] = {
    { "GET",     true },
    { "HEAD",    true },
    { "OPTIONS", true },
    { "TRACE",   true },
    { "POST",    false },
    { "PUT",     false },
    { "DELETE",  false },
    { "PATCH",   false },
    { "CONNECT", false },
};

/** Does an Allow header list this method? */
static bool
methods_allowed(const char *allow, const char *method)
{
    size_t len = strlen(method);
    const char *pos = allow;

    if (allow == NULL)
        return false;

    while ((pos = strcasestr(pos, method)) != NULL)
    {
        char before = pos == allow ? ',' : pos[-1];
        char after = pos[len];

        /*
         * On word boundaries: "POST" must not be found inside
         * "POSTMAN", and more to the point "GET" must not be found
         * inside "TARGET".
         */
        if ((before == ',' || before == ' ') &&
            (after == '\0' || after == ',' || after == ' '))
        {
            return true;
        }

        pos += len;
    }

    return false;
}

/* See description in tapi_http_methods.h */
te_errno
tapi_http_methods_probe(tapi_job_factory_t *factory, const char *url,
                        int timeout_ms, tapi_http_methods *methods)
{
    size_t i;

    memset(methods, 0, sizeof(*methods));
    methods->url = TE_STRDUP(url);
    methods->n_results = TE_ARRAY_LEN(methods_table);
    methods->results = TE_ALLOC(methods->n_results *
                                sizeof(*methods->results));

    for (i = 0; i < methods->n_results; i++)
    {
        tapi_http_request_opt opt = tapi_http_request_default_opt;
        tapi_http_response response;

        methods->results[i].method = methods_table[i].name;

        if (!methods_table[i].send)
            continue;

        opt.url = url;
        opt.method = methods_table[i].name;
        /*
         * Not followed: a redirect is an answer about this URL, and
         * following it would report on a different one.
         */
        opt.follow = false;

        if (tapi_http_request(factory, &opt, timeout_ms, &response) != 0)
            continue;

        methods->results[i].status = response.status;
        methods->results[i].sent = true;

        if (strcmp(methods_table[i].name, "OPTIONS") == 0)
        {
            const char *allow = tapi_http_header(&response, "Allow");

            methods->options_answered = response.status < 400;
            if (allow != NULL)
                methods->allow = TE_STRDUP(allow);
        }

        tapi_http_response_free(&response);
    }

    /* Now that Allow is known, mark what it advertised. */
    for (i = 0; i < methods->n_results; i++)
    {
        methods->results[i].advertised =
            methods_allowed(methods->allow, methods->results[i].method);
    }

    return 0;
}

/* See description in tapi_http_methods.h */
unsigned int
tapi_http_methods_status(const tapi_http_methods *methods,
                         const char *method)
{
    size_t i;

    for (i = 0; i < methods->n_results; i++)
    {
        if (strcasecmp(methods->results[i].method, method) == 0)
            return methods->results[i].status;
    }

    return 0;
}

/* See description in tapi_http_methods.h */
void
tapi_http_methods_check(const tapi_http_methods *methods,
                        tapi_cybersec_report *report)
{
    static const char *const changing[] = { "PUT", "DELETE", "PATCH" };
    unsigned int trace = tapi_http_methods_status(methods, "TRACE");
    size_t i;

    /*
     * TRACE is the one worth sending: it is safe by definition, it is
     * never needed, and a server that answers it echoes back whatever
     * a browser was made to send - headers and cookies included.
     */
    if (trace >= 200 && trace < 300)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
            "http.trace-enabled", methods->url,
            "TRACE is answered with %u. It echoes the request back, "
            "including headers a browser was made to send, and nothing "
            "needs it.", trace);
    }

    if (!methods->options_answered)
    {
        /*
         * Reported rather than passed over: what follows is read out
         * of an Allow header, and without one the absence of a finding
         * says nothing at all.
         */
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "http.no-options", methods->url,
            "OPTIONS was not answered, so what else this endpoint allows "
            "was not established. Only the methods that are safe to send "
            "were tried.");
        return;
    }

    for (i = 0; i < TE_ARRAY_LEN(changing); i++)
    {
        if (!methods_allowed(methods->allow, changing[i]))
            continue;

        /*
         * The endpoint's own statement, not something this sent. It is
         * worth a finding because it is so often the default of a
         * server nobody configured, and the subject is the method so
         * that two of them are two findings.
         */
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
            "http.changing-method-allowed", changing[i],
            "%s says it allows %s (Allow: %s). Nothing was sent; whether "
            "it is reachable without credentials is for a test that knows "
            "what it may touch.", methods->url, changing[i],
            methods->allow);
    }
}

/* See description in tapi_http_methods.h */
void
tapi_http_methods_log(const tapi_http_methods *methods)
{
    size_t i;

    RING("%s allows: %s", methods->url,
         methods->allow != NULL ? methods->allow : "(no Allow header)");

    for (i = 0; i < methods->n_results; i++)
    {
        const tapi_http_method_result *result = &methods->results[i];

        if (result->sent)
        {
            RING("  %-8s answered %u%s", result->method, result->status,
                 result->advertised ? ", advertised" : "");
        }
        else if (result->advertised)
        {
            RING("  %-8s advertised, not sent", result->method);
        }
    }
}

/* See description in tapi_http_methods.h */
void
tapi_http_methods_free(tapi_http_methods *methods)
{
    free(methods->results);
    free(methods->allow);
    free(methods->url);
    memset(methods, 0, sizeof(*methods));
}
