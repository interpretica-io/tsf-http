/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What the endpoint lets you do to it
 *
 * @defgroup tapi_http_methods Methods an endpoint answers
 * @ingroup tapi_http
 * @{
 *
 * @c OPTIONS is asked first, because an endpoint that answers it has
 * already said what it allows and nothing else needs doing. Where it
 * does not answer, the methods are asked one at a time - and only the
 * ones that change nothing.
 *
 * @section tapi_http_methods_safety What is and is not sent
 *
 * @c GET, @c HEAD, @c OPTIONS and @c TRACE are safe by definition:
 * they are not allowed to have side effects, and a server that gives
 * them any has a defect this will not find. Those are sent.
 *
 * @c PUT, @c DELETE and @c PATCH are not sent. They are asked about
 * through @c OPTIONS - which is the server's own statement - and
 * reported on that basis. A test that genuinely needs to know whether
 * @c DELETE works has to send it itself, against something it is
 * willing to lose.
 *
 * @code
 * tapi_http_methods methods;
 *
 * CHECK_RC(tapi_http_methods_probe(factory, url, 10000, &methods));
 * tapi_http_methods_check(&methods, url, &report);
 * tapi_http_methods_free(&methods);
 * @endcode
 */

#ifndef __TSF_TAPI_HTTP_METHODS_H__
#define __TSF_TAPI_HTTP_METHODS_H__

#include "te_defs.h"
#include "te_errno.h"

#include "tapi_cybersec.h"
#include "tapi_http.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What an endpoint said about one method. */
typedef struct tapi_http_method_result {
    /** The method. */
    const char *method;
    /** Status it answered with, or @c 0 when it was not sent. */
    unsigned int status;
    /** @c true when @c OPTIONS listed it in @c Allow. */
    bool advertised;
    /** @c true when it was actually sent. */
    bool sent;
} tapi_http_method_result;

/** What an endpoint allows. */
typedef struct tapi_http_methods {
    /** One entry per method asked about. */
    tapi_http_method_result *results;
    /** Number of @a results. */
    size_t n_results;
    /** The @c Allow header of the @c OPTIONS response, or @c NULL. */
    char *allow;
    /** @c true when @c OPTIONS itself was answered. */
    bool options_answered;
    /** The URL this is about. */
    char *url;
} tapi_http_methods;

/**
 * Find out what an endpoint answers.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  url          The URL to ask.
 * @param[in]  timeout_ms   Timeout for each request, ms.
 * @param[out] methods      What it said; release with
 *                          tapi_http_methods_free().
 *
 * @return Status code.
 */
extern te_errno tapi_http_methods_probe(tapi_job_factory_t *factory,
                                        const char *url, int timeout_ms,
                                        tapi_http_methods *methods);

/**
 * Turn what the endpoint allows into findings.
 *
 * @param[in]  methods      Result of tapi_http_methods_probe().
 * @param[out] report       Report to append findings to.
 */
extern void tapi_http_methods_check(const tapi_http_methods *methods,
                                    tapi_cybersec_report *report);

/**
 * Did the endpoint answer this method?
 *
 * @param methods       Result of tapi_http_methods_probe().
 * @param method        Method name.
 *
 * @return The status it answered with, or @c 0.
 */
extern unsigned int tapi_http_methods_status(
                                const tapi_http_methods *methods,
                                const char *method);

/**
 * Write what the endpoint allows into the log.
 *
 * @param methods       Result of tapi_http_methods_probe().
 */
extern void tapi_http_methods_log(const tapi_http_methods *methods);

/**
 * Release the result.
 *
 * @param methods       Result of tapi_http_methods_probe().
 */
extern void tapi_http_methods_free(tapi_http_methods *methods);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HTTP_METHODS_H__ */

/**@} <!-- END tapi_http_methods --> */
