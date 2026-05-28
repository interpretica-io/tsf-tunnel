/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief VPN agent library
 *
 * Registration of the VPN configuration subtree as a Test Agent
 * configuration extension.
 */

#include "te_config.h"

#include "rcf_pch_conf_ext.h"
#include "ta_vpn.h"

TE_RCF_PCH_CONF_EXT(ta_unix_conf_vpn_init);
