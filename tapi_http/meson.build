# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side HTTP - one request
# and the whole answer, what the response headers say about the
# service, what the endpoint lets you do to it, and a server that is
# wrong on purpose. Built as a shared library on the engine platform;
# see below for why there is no static one.

if get_option('engine')
    build_lib_shared = true
endif
# Shared on the engine and nothing on an agent, which is the rule TE
# applies to its own engine-side libraries. The default for an external
# repository is the opposite - lib/meson.build builds one static and
# agent-side, because that is what external libraries used to be - and
# the obvious override, "static as well when there are agents", is the
# rule for a library that lives on both sides. This one does not: it
# calls tapi and tapi_job, which are engine libraries with no static
# variant, so asking for a static build of it fails the configure with
# "Tried to get unknown variable dep_lib_static_tapi" before a line is
# compiled.
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_http.h',
    'tapi_http_headers.h',
    'tapi_http_methods.h',
    'tapi_http_server.h',
)

# tapi_http_internal.h is internal to this library and is not installed.
sources += files(
    'tapi_http.c',
    'tapi_http_cmd.c',
    'tapi_http_headers.c',
    'tapi_http_methods.c',
    'tapi_http_server.c',
)

te_libs += [
    'tapi',
    'tapi_job',
    'tapi_devtool',
    'tapi_cybersec',
]
