/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief An endpoint that is wrong on purpose
 *
 * A python3 script written to the agent and run there. python3 rather
 * than a real web server because every agent already has it, and what
 * is wanted is control over individual headers rather than a service.
 */

#define TE_LGR_USER "TAPI HTTP SERVER"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "te_alloc.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_http_server.h"
#include "tapi_http_internal.h"

/** How long the server is given to bind its socket, ms. */
#define HTTP_SERVER_READY_MS 15000

/** How long it is given to die when asked, ms. */
#define HTTP_SERVER_TERM_MS 5000

/** What the script prints once the socket is bound. */
#define HTTP_SERVER_READY_LINE "TAPI_HTTP_READY"

struct tapi_http_server {
    /** The python job. */
    tapi_devtool_run run;
    /** Agent it runs on. */
    char *ta;
    /** The script, removed when the server goes away. */
    char *script;
    /** Base URL, built once. */
    char *url;
};

const tapi_http_server_opt tapi_http_server_default_opt = {
    .port = 0,
    .defects = 0,
    .python = NULL,
    .bind_address = NULL,
};

/**
 * The server, as a python3 script.
 *
 * Written out whole rather than assembled from pieces: what an
 * endpoint sends is the thing under test, and a reader has to be able
 * to see all of it at once to trust a finding about it. The defect
 * mask arrives in argv, so the same script serves every combination.
 *
 * It prints a line once the socket is bound and before it serves
 * anything, which is what tapi_http_server_start() waits for.
 */
static const char http_server_script[] =
"import sys, http.server, socketserver\n"
"PORT = int(sys.argv[1])\n"
"ADDR = sys.argv[2]\n"
"D = int(sys.argv[3])\n"
"NO_SEC, BANNER, COOKIE, CORS, TRACE, WRITE, DUPCSP = (\n"
"    1, 2, 4, 8, 16, 32, 64)\n"
"\n"
"class H(http.server.BaseHTTPRequestHandler):\n"
"    protocol_version = 'HTTP/1.1'\n"
"    server_version = 'probe'\n"
"    sys_version = ''\n"
"\n"
"    def _common(self):\n"
"        if D & BANNER:\n"
"            self.send_header('Server', 'probe/2.4.51 (Unix) mod_x/1.2')\n"
"            self.send_header('X-Powered-By', 'PHP/8.1.2')\n"
"        if not (D & NO_SEC):\n"
"            self.send_header('Strict-Transport-Security',\n"
"                             'max-age=31536000; includeSubDomains')\n"
"            self.send_header('X-Content-Type-Options', 'nosniff')\n"
"            self.send_header('X-Frame-Options', 'DENY')\n"
"            self.send_header('Referrer-Policy', 'no-referrer')\n"
"            if not (D & DUPCSP):\n"
"                self.send_header('Content-Security-Policy',\n"
"                                 \"default-src 'self'\")\n"
"        if D & DUPCSP:\n"
"            self.send_header('Content-Security-Policy', \"default-src 'self'\")\n"
"            self.send_header('Content-Security-Policy', \"default-src *\")\n"
"        if D & COOKIE:\n"
"            self.send_header('Set-Cookie', 'sid=deadbeef; Path=/')\n"
"        else:\n"
"            self.send_header('Set-Cookie',\n"
"                             'sid=deadbeef; Path=/; Secure; HttpOnly; '\n"
"                             'SameSite=Strict')\n"
"        if D & CORS:\n"
"            self.send_header('Access-Control-Allow-Origin', '*')\n"
"            self.send_header('Access-Control-Allow-Credentials', 'true')\n"
"\n"
"    def _send(self, code, body=b'', ctype='text/html'):\n"
"        self.send_response(code)\n"
"        self._common()\n"
"        self.send_header('Content-Type', ctype)\n"
"        self.send_header('Content-Length', str(len(body)))\n"
"        self.end_headers()\n"
"        if body:\n"
"            self.wfile.write(body)\n"
"\n"
"    def do_GET(self):\n"
"        if self.path == '/redirect':\n"
"            self.send_response(302)\n"
"            self.send_header('Location', '/')\n"
"            self.send_header('Content-Length', '0')\n"
"            self.end_headers()\n"
"            return\n"
"        self._send(200, b'<html><body>probe</body></html>')\n"
"\n"
"    def do_HEAD(self):\n"
"        self._send(200)\n"
"\n"
"    def do_POST(self):\n"
"        length = int(self.headers.get('Content-Length', 0))\n"
"        self.rfile.read(length)\n"
"        self._send(200, b'ok', 'text/plain')\n"
"\n"
"    def do_OPTIONS(self):\n"
"        allow = 'GET, HEAD, POST, OPTIONS'\n"
"        if D & TRACE:\n"
"            allow += ', TRACE'\n"
"        if D & WRITE:\n"
"            allow += ', PUT, DELETE'\n"
"        self.send_response(204)\n"
"        self._common()\n"
"        self.send_header('Allow', allow)\n"
"        self.send_header('Content-Length', '0')\n"
"        self.end_headers()\n"
"\n"
"    def do_TRACE(self):\n"
"        if not (D & TRACE):\n"
"            self._send(405, b'no', 'text/plain')\n"
"            return\n"
"        echo = ('TRACE %s %s\\r\\n' % (self.path, self.request_version))\n"
"        echo += str(self.headers)\n"
"        self._send(200, echo.encode(), 'message/http')\n"
"\n"
"    def log_message(self, *args):\n"
"        pass\n"
"\n"
"class S(socketserver.ThreadingTCPServer):\n"
"    allow_reuse_address = True\n"
"    daemon_threads = True\n"
"\n"
"srv = S((ADDR, PORT), H)\n"
"print('" HTTP_SERVER_READY_LINE " %d' % PORT, flush=True)\n"
"srv.serve_forever()\n";

/** Remove the script and free the handle. */
static void
http_server_cleanup(tapi_http_server *server)
{
    if (server == NULL)
        return;

    if (server->script != NULL && server->ta != NULL)
        (void)tapi_file_ta_unlink_fmt(server->ta, "%s", server->script);

    free(server->script);
    free(server->ta);
    free(server->url);
    free(server);
}

/* See description in tapi_http_server.h */
te_errno
tapi_http_server_start(tapi_job_factory_t *factory,
                       const tapi_http_server_opt *opt, int timeout_ms,
                       tapi_http_server **server)
{
    const char *ta = tapi_job_factory_ta(factory);
    const char *address;
    te_vec args = TE_VEC_INIT(char *);
    te_string path = TE_STRING_INIT;
    tapi_http_server *result;
    char *tmp_dir;
    te_errno rc;

    if (opt->port == 0)
    {
        ERROR("The server needs a port to listen on");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    address = opt->bind_address != NULL ? opt->bind_address : "127.0.0.1";

    result = TE_ALLOC(sizeof(*result));
    result->run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;
    result->ta = TE_STRDUP(ta);

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
    {
        ERROR("Failed to get the temporary directory of TA %s", ta);
        http_server_cleanup(result);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    tapi_file_make_custom_pathname(&path, tmp_dir, ".py");
    free(tmp_dir);

    rc = tapi_file_create_ta(ta, path.ptr, "%s", http_server_script);
    if (rc != 0)
    {
        ERROR("Failed to put the server script on TA %s: %r", ta, rc);
        te_string_free(&path);
        http_server_cleanup(result);
        return rc;
    }

    result->script = TE_STRDUP(path.ptr);
    te_string_free(&path);

    tapi_http_arg(&args, "%s", result->script);
    tapi_http_arg(&args, "%u", opt->port);
    tapi_http_arg(&args, "%s", address);
    tapi_http_arg(&args, "%u", opt->defects);

    RING("Standing up an endpoint on %s:%u with defects %#x",
         address, opt->port, opt->defects);

    rc = tapi_http_spawn(factory, "http-server",
                         opt->python != NULL ? opt->python : "python3",
                         &args, &result->run);
    te_vec_deep_free(&args);

    if (rc != 0)
    {
        http_server_cleanup(result);
        return rc;
    }

    /*
     * Wait for the socket, not for the process. The script prints its
     * line after the bind and before it serves anything, so a request
     * made once this returns cannot be refused for being early.
     */
    rc = tapi_devtool_run_expect(&result->run, HTTP_SERVER_READY_LINE,
                                 timeout_ms > 0 ? timeout_ms :
                                     HTTP_SERVER_READY_MS);
    if (rc != 0)
    {
        ERROR("The endpoint never started listening on %s:%u", address,
              opt->port);
        (void)tapi_devtool_run_stop(&result->run);
        tapi_devtool_run_fini(&result->run);
        http_server_cleanup(result);
        return rc;
    }

    {
        te_string url = TE_STRING_INIT;

        te_string_append(&url, "http://%s:%u", address, opt->port);
        result->url = url.ptr;
    }

    *server = result;

    return 0;
}

/* See description in tapi_http_server.h */
const char *
tapi_http_server_url(const tapi_http_server *server)
{
    return server->url;
}

/* See description in tapi_http_server.h */
te_errno
tapi_http_server_stop(tapi_http_server *server)
{
    te_errno rc;

    if (server == NULL)
        return 0;

    rc = tapi_devtool_run_stop(&server->run);
    if (rc == 0)
        (void)tapi_devtool_run_wait(&server->run, HTTP_SERVER_TERM_MS);

    tapi_devtool_run_fini(&server->run);
    http_server_cleanup(server);

    return rc;
}
