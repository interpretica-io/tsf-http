/* SPDX-License-Identifier: MIT */
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
 * Read the number @p text starts with.
 *
 * te_strtoui() refuses a string with anything after the digits, which
 * is right for a field that should be a number and wrong for every
 * number this library reads: a status line is "200 OK" and an HSTS
 * header is "31536000; includeSubDomains". Both are numbers followed
 * by something, and asking te_strtoui() for them gets a parse error
 * and a zero that reads exactly like "no status at all".
 *
 * @param[in]  text     Text beginning with digits.
 * @param[out] value    Where to put the number.
 *
 * @return @c true when @p text began with a digit.
 */
extern bool tapi_http_number(const char *text, unsigned int *value);

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
