# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): agent-side VPN configuration
# subtree. Linked wholly into agents so that the constructor in
# ta_vpn_conf_ext.c registers the /agent/vpn subtree without Test Agent
# modifications. Drives the low level - ip, wg, ip xfrm - by default,
# with wg-quick and swanctl as alternative backends.

link_whole = true

headers += files(
    'ta_vpn.h',
)

sources += files(
    'ta_vpn.c',
    'ta_vpn_conf_ext.c',
    'ta_vpn_ipsec.c',
    'ta_vpn_wg.c',
)

# libcrypto: WireGuard keys are X25519, generated in process rather than
# by shelling out to wg genkey.
deps += [ dependency('libcrypto') ]

te_libs += [
    'agentlib',
    'rpc_types',
    'tools',
    'rcfpch',
    'tapi_cfg_vpn',
]
