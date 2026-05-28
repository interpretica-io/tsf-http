/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What the response headers say about the service
 */

#define TE_LGR_USER "TAPI HTTP"

#include "te_config.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"

#include "tapi_http_headers.h"
#include "tapi_http_internal.h"

/** 180 days, which is what the HSTS preload list asks for. */
#define HTTP_HSTS_MIN_AGE 15552000

const tapi_http_headers_policy tapi_http_headers_default_policy = {
    .kind          = TAPI_HTTP_KIND_PAGE,
    .require_hsts  = true,
    .hsts_min_age  = HTTP_HSTS_MIN_AGE,
    .require_csp   = true,
    .check_banner  = true,
    .check_cookies = true,
    .check_cors    = true,
};

/** Does @p text contain a digit anywhere? A version usually does. */
static bool
headers_has_digit(const char *text)
{
    for (; *text != '\0'; text++)
    {
        if (*text >= '0' && *text <= '9')
            return true;
    }

    return false;
}

/* See description in tapi_http_headers.h */
bool
tapi_http_cookie_has(const char *set_cookie, const char *attribute)
{
    size_t len = strlen(attribute);
    const char *pos = set_cookie;

    /*
     * Attributes come after the first ';', so the cookie's own name
     * and value are skipped: a cookie called "HttpOnly", or one whose
     * value contains the word, must not look like a cookie that has
     * the flag.
     */
    pos = strchr(pos, ';');

    while (pos != NULL)
    {
        pos++;
        while (*pos == ' ' || *pos == '\t')
            pos++;

        if (strncasecmp(pos, attribute, len) == 0)
        {
            char after = pos[len];

            if (after == '\0' || after == ';' || after == '=' ||
                after == ' ')
            {
                return true;
            }
        }

        pos = strchr(pos, ';');
    }

    return false;
}

/* See description in tapi_http_headers.h */
void
tapi_http_cookie_name(const char *set_cookie, te_string *dest)
{
    size_t len = strcspn(set_cookie, "=;");

    te_string_append(dest, "%.*s", (int)len, set_cookie);
}

/** The max-age of an HSTS header, or 0 when there is none. */
static unsigned int
headers_hsts_age(const char *value)
{
    const char *age = strcasestr(value, "max-age");
    unsigned int result = 0;

    if (age == NULL)
        return 0;

    age += strlen("max-age");
    while (*age == ' ' || *age == '=')
        age++;

    /*
     * The digits and nothing after them: the header is
     * "max-age=31536000; includeSubDomains", and te_strtoui() refuses
     * the whole of that - which would read as an age of zero and
     * report a short max-age on a header that is perfectly fine.
     */
    if (!tapi_http_number(age, &result))
        return 0;

    return result;
}

/** Check the headers that only matter to a browser. */
static void
headers_check_browser(const tapi_http_response *response,
                      const tapi_http_headers_policy *policy,
                      const char *subject, tapi_cybersec_report *report)
{
    const char *value;

    if (policy->kind != TAPI_HTTP_KIND_PAGE)
        return;

    if (policy->require_csp)
    {
        unsigned int count = tapi_http_header_count(
                                response, "Content-Security-Policy");

        if (count == 0)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "http.no-csp", subject,
                "There is no Content-Security-Policy, so a script injected "
                "into a page has nothing stopping it.");
        }
        else if (count > 1)
        {
            /*
             * Not a stricter policy: a browser enforces the
             * intersection, which is rarely what the second one was
             * added for, and the two are easy to leave contradicting
             * each other.
             */
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                "http.duplicate-csp", subject,
                "There are %u Content-Security-Policy headers; a browser "
                "enforces the intersection of them, not the last one.",
                count);
        }
        else
        {
            value = tapi_http_header(response, "Content-Security-Policy");
            if (strstr(value, "unsafe-inline") != NULL ||
                strstr(value, "unsafe-eval") != NULL)
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                    "http.weak-csp", subject,
                    "The Content-Security-Policy allows unsafe-inline or "
                    "unsafe-eval, which is most of what it exists to stop: "
                    "%s", value);
            }
        }
    }

    value = tapi_http_header(response, "X-Content-Type-Options");
    if (value == NULL || strcasecmp(value, "nosniff") != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
            "http.no-nosniff", subject,
            "X-Content-Type-Options is not 'nosniff', so a browser may "
            "decide for itself what a response really is.");
    }

    if (tapi_http_header(response, "X-Frame-Options") == NULL &&
        (tapi_http_header(response, "Content-Security-Policy") == NULL ||
         strstr(tapi_http_header(response, "Content-Security-Policy"),
                "frame-ancestors") == NULL))
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
            "http.framable", subject,
            "Neither X-Frame-Options nor a frame-ancestors directive is "
            "set, so the page can be framed by anyone.");
    }

    if (tapi_http_header(response, "Referrer-Policy") == NULL)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "http.no-referrer-policy", subject,
            "There is no Referrer-Policy, so the full URL of this page "
            "travels to whatever it links to.");
    }
}

/** Check the cookies a response sets. */
static void
headers_check_cookies(const tapi_http_response *response,
                      const tapi_http_headers_policy *policy,
                      tapi_cybersec_report *report)
{
    unsigned int count;
    unsigned int i;

    if (!policy->check_cookies)
        return;

    count = tapi_http_header_count(response, "Set-Cookie");

    for (i = 0; i < count; i++)
    {
        const char *cookie = tapi_http_header_nth(response, "Set-Cookie", i);
        te_string name = TE_STRING_INIT;

        tapi_http_cookie_name(cookie, &name);

        /*
         * The subject is the cookie, not the endpoint, so two bad
         * cookies are two findings and the verdict names which one.
         */
        if (!tapi_http_cookie_has(cookie, "HttpOnly"))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "http.cookie-no-httponly", te_string_value(&name),
                "Cookie '%s' has no HttpOnly, so a script on the page can "
                "read it.", te_string_value(&name));
        }

        if (response->over_tls && !tapi_http_cookie_has(cookie, "Secure"))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "http.cookie-no-secure", te_string_value(&name),
                "Cookie '%s' has no Secure, so a browser will send it over "
                "a plain connection too.", te_string_value(&name));
        }

        if (!tapi_http_cookie_has(cookie, "SameSite"))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                "http.cookie-no-samesite", te_string_value(&name),
                "Cookie '%s' has no SameSite; the browser default is Lax, "
                "which is not the same as saying so.",
                te_string_value(&name));
        }

        te_string_free(&name);
    }
}

/* See description in tapi_http_headers.h */
void
tapi_http_headers_check(const tapi_http_response *response,
                        const tapi_http_headers_policy *policy,
                        tapi_cybersec_report *report)
{
    const char *subject;
    const char *value;

    if (policy == NULL)
        policy = &tapi_http_headers_default_policy;

    /*
     * The URL the request ended at, which is what the findings are
     * about; it does not change between runs, so TRC can match it.
     */
    subject = response->final_url != NULL ? response->final_url : "endpoint";

    if (policy->require_hsts && response->over_tls)
    {
        value = tapi_http_header(response, "Strict-Transport-Security");

        if (value == NULL)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "http.no-hsts", subject,
                "There is no Strict-Transport-Security, so a browser that "
                "has been here before will still try plain HTTP first.");
        }
        else if (headers_hsts_age(value) < policy->hsts_min_age)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                "http.short-hsts", subject,
                "Strict-Transport-Security lasts %u seconds, less than the "
                "%u expected: '%s'", headers_hsts_age(value),
                policy->hsts_min_age, value);
        }
    }

    headers_check_browser(response, policy, subject, report);
    headers_check_cookies(response, policy, report);

    if (policy->check_cors)
    {
        value = tapi_http_header(response, "Access-Control-Allow-Origin");

        if (value != NULL && strcmp(value, "*") == 0)
        {
            const char *creds = tapi_http_header(
                                    response,
                                    "Access-Control-Allow-Credentials");

            /*
             * A browser refuses this combination outright, which is
             * the point: the service asked for something that cannot
             * work, so whoever wrote it did not test it and does not
             * know what it grants.
             */
            if (creds != NULL && strcasecmp(creds, "true") == 0)
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                    "http.cors-wildcard-credentials", subject,
                    "Access-Control-Allow-Origin is '*' together with "
                    "Access-Control-Allow-Credentials: true. A browser "
                    "rejects that pair, so the policy it was meant to "
                    "express is not the one in force.");
            }
            else
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                    "http.cors-wildcard", subject,
                    "Access-Control-Allow-Origin is '*', so any site can "
                    "read what this endpoint returns.");
            }
        }
    }

    if (policy->check_banner)
    {
        static const char *const banners[] = {
            "Server", "X-Powered-By", "X-AspNet-Version",
            "X-AspNetMvc-Version", "X-Generator",
        };
        size_t i;

        for (i = 0; i < TE_ARRAY_LEN(banners); i++)
        {
            value = tapi_http_header(response, banners[i]);

            /*
             * A name alone is no use to anyone; a version number is
             * the difference between knowing what to attack and
             * having to find out.
             */
            if (value != NULL && headers_has_digit(value))
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                    "http.version-banner", banners[i],
                    "%s says '%s', which names a version to look up.",
                    banners[i], value);
            }
        }
    }
}
