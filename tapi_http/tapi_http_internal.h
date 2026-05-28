/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief HTTP TAPI: internal helpers
 *
 * Internal to tsf-http; not installed.
 */

#ifndef __TSF_TAPI_HTTP_INTERNAL_H__
#define __TSF_TAPI_HTTP_INTERNAL_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_devtool_run.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Append one argument to a vector, taking ownership of it. */
extern void tapi_http_arg(te_vec *args, const char *fmt, ...)
    TE_LIKE_PRINTF(2, 3);

/**
 * Run @p program with @p args and wait for it.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  name         Tool name for log messages.
 * @param[in]  program      Program name or path.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] run          Run handle; release it with
 *                          tapi_devtool_run_fini().
 *
 * @return Status code of running the command, not of the command.
 */
extern te_errno tapi_http_cmd(tapi_job_factory_t *factory, const char *name,
                              const char *program, const te_vec *args,
                              int timeout_ms, tapi_devtool_run *run);

/**
 * Start @p program with @p args and leave it running.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  name         Tool name for log messages.
 * @param[in]  program      Program name or path.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[out] run          Run handle; release it with
 *                          tapi_devtool_run_fini().
 *
 * @return Status code.
 */
extern te_errno tapi_http_spawn(tapi_job_factory_t *factory,
                                const char *name, const char *program,
                                const te_vec *args, tapi_devtool_run *run);

/**
 * Trim whitespace from both ends of @p text, in place.
 *
 * @param text          String to trim.
 *
 * @return @p text.
 */
extern char *tapi_http_trim(char *text);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_HTTP_INTERNAL_H__ */
