/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief An endpoint that is wrong on purpose
 *
 * @defgroup tapi_http_server A server with chosen defects
 * @ingroup tapi_http
 * @{
 *
 * An HTTP server on the agent whose headers are exactly what the test
 * says they are. Two uses, and both matter:
 *
 * - **testing the checks.** A check that reports nothing looks the
 *   same whether the endpoint is clean or the check is broken. Point
 *   it at a server that is wrong in a known way and the difference
 *   shows.
 * - **testing a client.** When the device under test is the HTTP
 *   *client*, this is how to find out whether it minds being told
 *   something it should mind - a redirect to somewhere else, a cookie
 *   without @c Secure, a body longer than it said.
 *
 * @code
 * tapi_http_server_opt opt = tapi_http_server_default_opt;
 * tapi_http_server *server = NULL;
 *
 * opt.port = 8080;
 * opt.defects = TAPI_HTTP_DEFECT_NO_SECURITY_HEADERS |
 *               TAPI_HTTP_DEFECT_VERSION_BANNER;
 *
 * CHECK_RC(tapi_http_server_start(factory, &opt, 10000, &server));
 * ... ask it things ...
 * CHECK_RC(tapi_http_server_stop(server));
 * @endcode
 *
 * It needs @c python3 on the agent and nothing else.
 */

#ifndef __TSF_TAPI_HTTP_SERVER_H__
#define __TSF_TAPI_HTTP_SERVER_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "tapi_job.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Send nothing but the bare minimum: no security headers at all. */
#define TAPI_HTTP_DEFECT_NO_SECURITY_HEADERS (1u << 0)
/** Name the software and its version in @c Server and @c X-Powered-By. */
#define TAPI_HTTP_DEFECT_VERSION_BANNER      (1u << 1)
/** Set a session cookie with none of @c Secure, @c HttpOnly, @c SameSite. */
#define TAPI_HTTP_DEFECT_LOOSE_COOKIE        (1u << 2)
/** @c Access-Control-Allow-Origin: @c * with credentials allowed. */
#define TAPI_HTTP_DEFECT_OPEN_CORS           (1u << 3)
/** Answer @c TRACE, echoing the request back. */
#define TAPI_HTTP_DEFECT_TRACE               (1u << 4)
/** Advertise @c PUT and @c DELETE in the @c Allow header. */
#define TAPI_HTTP_DEFECT_WRITE_METHODS       (1u << 5)
/** Two contradicting @c Content-Security-Policy headers. */
#define TAPI_HTTP_DEFECT_DUPLICATE_CSP       (1u << 6)

/** Everything this server can be wrong about. */
#define TAPI_HTTP_DEFECT_ALL \
    (TAPI_HTTP_DEFECT_NO_SECURITY_HEADERS | \
     TAPI_HTTP_DEFECT_VERSION_BANNER | TAPI_HTTP_DEFECT_LOOSE_COOKIE | \
     TAPI_HTTP_DEFECT_OPEN_CORS | TAPI_HTTP_DEFECT_TRACE | \
     TAPI_HTTP_DEFECT_WRITE_METHODS | TAPI_HTTP_DEFECT_DUPLICATE_CSP)

/** How to stand the server up. */
typedef struct tapi_http_server_opt {
    /** Port to listen on. Mandatory. */
    uint16_t port;
    /** Which defects to have; @c 0 for a well configured endpoint. */
    unsigned int defects;
    /** The @c python3 interpreter; @c NULL means @c python3. */
    const char *python;
    /** Address to bind to; @c NULL means @c 127.0.0.1. */
    const char *bind_address;
} tapi_http_server_opt;

/** Defaults: loopback, no defects. */
extern const tapi_http_server_opt tapi_http_server_default_opt;

/** A running server. */
typedef struct tapi_http_server tapi_http_server;

/**
 * Start the server and wait until it is listening.
 *
 * It does not return before the socket is bound. A start that returned
 * early would leave the very next request racing it, and the request
 * would usually win.
 *
 * @param[in]  factory      Job factory; the server runs on this agent.
 * @param[in]  opt          How to stand it up.
 * @param[in]  timeout_ms   How long to give it to start, ms.
 * @param[out] server       Handle; release with
 *                          tapi_http_server_stop().
 *
 * @return Status code.
 */
extern te_errno tapi_http_server_start(tapi_job_factory_t *factory,
                                       const tapi_http_server_opt *opt,
                                       int timeout_ms,
                                       tapi_http_server **server);

/**
 * The base URL of a running server.
 *
 * @param server        Handle.
 *
 * @return The URL, e.g. @c "http://127.0.0.1:8080", never @c NULL.
 */
extern const char *tapi_http_server_url(const tapi_http_server *server);

/**
 * Stop the server and release it.
 *
 * Safe on @c NULL, and safe to call from a cleanup section.
 *
 * @param server        Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_http_server_stop(tapi_http_server *server);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HTTP_SERVER_H__ */

/**@} <!-- END tapi_http_server --> */
