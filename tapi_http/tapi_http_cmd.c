/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief HTTP TAPI: running a tool on an agent
 *
 * Everything in this library is a command on the agent, and this is
 * the one place one is run.
 */

#define TE_LGR_USER "TAPI HTTP"

#include "te_config.h"

#include "logger_api.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_http_internal.h"

/** Arguments of a command, as a plain vector of strings. */
typedef struct http_cmd_opt {
    /** Number of arguments. */
    size_t n_args;
    /** Arguments after argv[0]. */
    const char **args;
} http_cmd_opt;

static const tapi_job_opt_bind http_cmd_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(http_cmd_opt, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/* See description in tapi_http_internal.h */
te_errno
tapi_http_cmd(tapi_job_factory_t *factory, const char *name,
              const char *program, const te_vec *args, int timeout_ms,
              tapi_devtool_run *run)
{
    http_cmd_opt opt = {
        .n_args = te_vec_size(args),
        .args = te_vec_size(args) == 0 ? NULL :
                (const char **)te_vec_get((te_vec *)args, 0),
    };
    te_errno rc;

    *run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;

    rc = tapi_devtool_run_init(run, factory, name, program, http_cmd_binds,
                               &opt, NULL);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(run, timeout_ms);

    if (rc != 0)
        tapi_devtool_run_fini(run);

    return rc;
}

/* See description in tapi_http_internal.h */
te_errno
tapi_http_spawn(tapi_job_factory_t *factory, const char *name,
                const char *program, const te_vec *args,
                tapi_devtool_run *run)
{
    http_cmd_opt opt = {
        .n_args = te_vec_size(args),
        .args = te_vec_size(args) == 0 ? NULL :
                (const char **)te_vec_get((te_vec *)args, 0),
    };
    te_errno rc;

    *run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;

    rc = tapi_devtool_run_init(run, factory, name, program, http_cmd_binds,
                               &opt, NULL);
    if (rc != 0)
        return rc;

    /* Started and left running: the caller waits for it to be ready. */
    rc = tapi_devtool_run_start(run);
    if (rc != 0)
        tapi_devtool_run_fini(run);

    return rc;
}
