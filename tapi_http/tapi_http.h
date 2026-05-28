/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief HTTP from a test
 *
 * @defgroup tapi_http HTTP (tapi_http)
 * @{
 *
 * One request, the whole response, and what is wrong with it.
 *
 * @section tapi_http_why What this is for
 *
 * TE can already generate HTTP load - @c tapi_wrk does that, and does
 * it better than anything here would. This is the other question: not
 * how fast the endpoint answers, but *what it answers with*.
 *
 * Nearly everything that goes wrong with an HTTP service in the field
 * is in the response headers, and none of it is visible to a load
 * generator or to a browser that simply works. A missing
 * @c Strict-Transport-Security, a session cookie without @c HttpOnly,
 * @c Access-Control-Allow-Origin: @c * next to
 * @c Access-Control-Allow-Credentials: @c true, a @c Server header
 * naming the exact build, @c TRACE still answering. Each one is a line
 * of configuration, each one is invisible until someone looks, and
 * each one is exactly the kind of thing a test should hold in place
 * once it is fixed.
 *
 * - @ref tapi_http_headers - the response headers, as a security posture;
 * - @ref tapi_http_methods - what the endpoint lets you do to it;
 * - @ref tapi_http_server - a deliberately wrong server, for testing
 *   the client end.
 *
 * @section tapi_http_model How it works
 *
 * Requests are made with @c curl on the agent, because a test should
 * ask the question from where the device is, not from the engine. The
 * response comes back whole: status, every header in order, and the
 * body.
 *
 * @code
 * tapi_http_request_opt opt = tapi_http_request_default_opt;
 * tapi_http_response response;
 *
 * opt.url = "http://dut.example.net/api/health";
 * CHECK_RC(tapi_http_request(factory, &opt, 10000, &response));
 *
 * RING("status %u", response.status);
 * RING("server is %s", tapi_http_header(&response, "Server"));
 * tapi_http_response_free(&response);
 * @endcode
 *
 * @section tapi_http_scope What it does not do
 *
 * It asks the endpoints the suite's own configuration names, and it
 * asks them politely: one request, the method the caller chose, no
 * guessing of paths and no payloads meant to break anything. It reads
 * what a service says about itself and reports it. Finding a way in is
 * not what this is for.
 */

#ifndef __TSF_TAPI_HTTP_H__
#define __TSF_TAPI_HTTP_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default timeout for one request, ms. */
#define TAPI_HTTP_TIMEOUT_MS 30000

/** One header of a response, as it was sent. */
typedef struct tapi_http_header_field {
    /** Field name, as received; compare it case-insensitively. */
    char *name;
    /** Field value, with the surrounding whitespace removed. */
    char *value;
} tapi_http_header_field;

/** What an endpoint answered. */
typedef struct tapi_http_response {
    /** Status code, or @c 0 when there was no reply at all. */
    unsigned int status;
    /** The version the server answered with, e.g. @c "HTTP/1.1". */
    char *version;
    /** The reason phrase, which may be empty on HTTP/2. */
    char *reason;
    /** Every header of the final response, in the order received. */
    tapi_http_header_field *headers;
    /** Number of @a headers. */
    size_t n_headers;
    /** The body, which may be empty. */
    te_string body;
    /**
     * The status of every response including the redirects that led
     * here, in order. The last is @a status.
     */
    unsigned int *chain;
    /** Number of @a chain entries. */
    size_t n_chain;
    /** The URL the request ended at, after any redirects. */
    char *final_url;
    /** @c true when the request was made over TLS. */
    bool over_tls;
} tapi_http_response;

/** How to make a request. */
typedef struct tapi_http_request_opt {
    /** The URL to ask. Required. */
    const char *url;
    /** Method; @c NULL means @c GET. */
    const char *method;
    /**
     * Headers to send, as @c "Name: value" strings.
     *
     * A test that needs a session sends its cookie here; nothing in
     * this library ever invents credentials of its own.
     */
    const char **headers;
    /** Number of @a headers. */
    size_t n_headers;
    /** Request body, or @c NULL. */
    const char *body;
    /** Follow redirects rather than reporting the first one. */
    bool follow;
    /** Maximum redirects to follow; @c 0 means curl's default. */
    unsigned int max_redirects;
    /**
     * Accept a certificate that does not verify.
     *
     * Off by default, deliberately. A test that turns this on to make
     * a request work has found a defect and hidden it; use
     * @ref tapi_tls to report it instead.
     */
    bool insecure;
    /** Resolve the URL's host to this address instead, or @c NULL. */
    const char *resolve_to;
    /** Seconds to wait for the whole request; @c 0 for the default. */
    unsigned int timeout_s;
    /** Extra curl arguments, for what this does not wrap. */
    const char **extra_args;
    /** Number of @a extra_args. */
    size_t n_extra_args;
} tapi_http_request_opt;

/** Defaults for #tapi_http_request_opt. */
extern const tapi_http_request_opt tapi_http_request_default_opt;

/**
 * Make one request and read the whole answer.
 *
 * A reply that is an error - 404, 500 - is an answer, not a failure:
 * it comes back in @a status. The status code of this function is
 * about whether the question could be asked at all.
 *
 * @param[in]  factory      Job factory; curl runs on this agent.
 * @param[in]  opt          What to ask.
 * @param[in]  timeout_ms   Timeout for the job, ms.
 * @param[out] response     The answer; release it with
 *                          tapi_http_response_free().
 *
 * @return Status code.
 * @retval TE_EINVAL        No URL was given.
 * @retval TE_ECONNREFUSED  Nothing answered.
 */
extern te_errno tapi_http_request(tapi_job_factory_t *factory,
                                  const tapi_http_request_opt *opt,
                                  int timeout_ms,
                                  tapi_http_response *response);

/**
 * The value of a header, case-insensitively.
 *
 * @param response      A response.
 * @param name          Header name.
 *
 * @return The value, or @c NULL when the header is not there. It
 *         belongs to @p response.
 */
extern const char *tapi_http_header(const tapi_http_response *response,
                                    const char *name);

/**
 * How many times a header appears.
 *
 * Worth asking: two @c Content-Security-Policy headers are not a
 * stricter policy but a request smuggling hazard, and two
 * @c Set-Cookie headers are perfectly normal.
 *
 * @param response      A response.
 * @param name          Header name.
 *
 * @return The count.
 */
extern unsigned int tapi_http_header_count(
                                const tapi_http_response *response,
                                const char *name);

/**
 * Get the n-th occurrence of a header.
 *
 * @param response      A response.
 * @param name          Header name.
 * @param index         Which one, counting from @c 0.
 *
 * @return The value, or @c NULL.
 */
extern const char *tapi_http_header_nth(const tapi_http_response *response,
                                        const char *name,
                                        unsigned int index);

/**
 * Write a response into the log.
 *
 * @param response      A response.
 */
extern void tapi_http_response_log(const tapi_http_response *response);

/**
 * Release a response.
 *
 * @param response      A response.
 */
extern void tapi_http_response_free(tapi_http_response *response);

/**
 * Wait until an endpoint answers at all.
 *
 * For a service the test has just started: it asks, and asks again,
 * until something replies or the time runs out. Any status counts -
 * a 404 is an answer.
 *
 * @param factory       Job factory.
 * @param url           The URL to ask.
 * @param timeout_ms    How long to keep trying, ms.
 *
 * @return Status code.
 * @retval TE_ETIMEDOUT Nothing answered in time.
 */
extern te_errno tapi_http_wait_ready(tapi_job_factory_t *factory,
                                     const char *url, int timeout_ms);

/**
 * Is @c curl there?
 *
 * @param factory       Job factory.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when a request can be made at all.
 */
extern bool tapi_http_available(tapi_job_factory_t *factory, int timeout_ms);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HTTP_H__ */

/**@} <!-- END tapi_http --> */
