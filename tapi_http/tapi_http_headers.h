/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What the response headers say about the service
 *
 * @defgroup tapi_http_headers Response headers as a posture
 * @ingroup tapi_http
 * @{
 *
 * The headers a service sends are its security configuration, written
 * down where anyone can read it. This reads it and reports what is
 * missing, what is too permissive, and what says more than it should.
 *
 * @code
 * tapi_cybersec_report report;
 * tapi_http_response response;
 *
 * tapi_cybersec_report_init(&report);
 * CHECK_RC(tapi_http_request(factory, &opt, 10000, &response));
 * tapi_http_headers_check(&response, NULL, &report);
 * tapi_cybersec_report_log(&report);
 * @endcode
 *
 * @note Severity here is about a service on a network, not about a
 *       page in a browser. A missing @c Content-Security-Policy on a
 *       JSON API is worth less than on a page that renders user input,
 *       and #tapi_http_headers_policy is how a test says which it has.
 */

#ifndef __TSF_TAPI_HTTP_HEADERS_H__
#define __TSF_TAPI_HTTP_HEADERS_H__

#include "te_defs.h"
#include "te_errno.h"

#include "tapi_cybersec.h"
#include "tapi_http.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What the endpoint is, which decides what it ought to send. */
typedef enum tapi_http_kind {
    /**
     * A page a browser renders. Everything applies: framing, content
     * type sniffing, the content security policy, referrers.
     */
    TAPI_HTTP_KIND_PAGE = 0,
    /**
     * An API that answers with data. The headers about rendering do
     * not apply; transport and cookies still do.
     */
    TAPI_HTTP_KIND_API,
} tapi_http_kind;

/** What to expect of the headers. */
typedef struct tapi_http_headers_policy {
    /** What the endpoint is. */
    tapi_http_kind kind;
    /**
     * Require @c Strict-Transport-Security.
     *
     * Only meaningful over TLS - a browser ignores the header on a
     * plain connection, so asking for it there would be a finding
     * nobody can act on. Checked only when the response came over
     * TLS.
     */
    bool require_hsts;
    /** Least @c max-age that counts as HSTS being on, seconds. */
    unsigned int hsts_min_age;
    /** Require a @c Content-Security-Policy. */
    bool require_csp;
    /** Report a @c Server or @c X-Powered-By that names a version. */
    bool check_banner;
    /** Report cookies without @c Secure, @c HttpOnly or @c SameSite. */
    bool check_cookies;
    /** Report a permissive @c Access-Control-Allow-Origin. */
    bool check_cors;
} tapi_http_headers_policy;

/**
 * The default policy: a browser page, everything checked.
 *
 * @c hsts_min_age is @c 15552000 - 180 days - which is what the
 * preload list requires and what most guidance settles on.
 */
extern const tapi_http_headers_policy tapi_http_headers_default_policy;

/**
 * Read a response's headers and add what is wrong to @p report.
 *
 * @param[in]  response     A response.
 * @param[in]  policy       What to expect, or @c NULL for the default.
 * @param[out] report       Report to append findings to.
 */
extern void tapi_http_headers_check(
                            const tapi_http_response *response,
                            const tapi_http_headers_policy *policy,
                            tapi_cybersec_report *report);

/**
 * Does a @c Set-Cookie value carry an attribute?
 *
 * Matched on attribute boundaries, so @c "HttpOnly" is not found in a
 * cookie whose *value* happens to contain it.
 *
 * @param set_cookie    A @c Set-Cookie value.
 * @param attribute     Attribute name, e.g. @c "HttpOnly".
 *
 * @return @c true when the attribute is there.
 */
extern bool tapi_http_cookie_has(const char *set_cookie,
                                 const char *attribute);

/**
 * The name of a cookie in a @c Set-Cookie value.
 *
 * @param[in]  set_cookie   A @c Set-Cookie value.
 * @param[out] dest         String to append the name to.
 */
extern void tapi_http_cookie_name(const char *set_cookie, te_string *dest);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HTTP_HEADERS_H__ */

/**@} <!-- END tapi_http_headers --> */
