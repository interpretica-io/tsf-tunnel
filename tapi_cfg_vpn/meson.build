# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side TAPI for the
# /agent/vpn configuration subtree, plus the cm_vpn.yml Configurator
# model installed to share/cm. Built as a shared library on the engine
# platform; see below for why there is no static one.

if get_option('engine')
    build_lib_shared = true
endif
# Shared on the engine and nothing on an agent. The default for an
# external repository is static and agent-side, and the obvious override
# ("static as well when there are agents") is for a library that lives on
# both sides. This one is engine-only and calls confapi, so a static
# build fails the configure with "Tried to get unknown variable
# dep_lib_static_confapi" before a line is compiled.
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_cfg_vpn.h',
)

sources += files(
    'tapi_cfg_vpn.c',
)

te_libs += [
    'confapi',
    'conf_oid',
    'tools',
    'logger_ten',
]

if get_option('engine')
    install_data(
        files('cm_vpn.yml'),
        install_dir: join_paths(get_option('datadir'), 'cm'),
    )
endif
