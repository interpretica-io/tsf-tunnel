/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Engine-side TAPI for the /agent/vpn subtree
 *
 * Thin over the Configurator: each call is a get, set, add or delete of
 * one instance. The subtree does the work on the agent; this is the
 * vocabulary a test uses to drive it.
 */

#define TE_LGR_USER "TAPI CFG VPN"

#include "te_config.h"

#include <string.h>

#include "conf_api.h"
#include "logger_api.h"
#include "te_str.h"

#include "tapi_cfg_vpn.h"

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_set_backend(const char *ta, tapi_cfg_vpn_backend backend)
{
    static const char *const names[] = { "kernel", "wg-quick", "swanctl" };

    return cfg_set_instance_fmt(CFG_VAL(STRING, names[backend]),
                                "/agent:%s/vpn:/backend:", ta);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_commit(const char *ta)
{
    return cfg_commit_fmt("/agent:%s/vpn:", ta);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_add(const char *ta, const char *name)
{
    return cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
                                "/agent:%s/vpn:/wireguard:%s", ta, name);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_del(const char *ta, const char *name)
{
    return cfg_del_instance_fmt(false, "/agent:%s/vpn:/wireguard:%s", ta,
                                name);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_set_private_key(const char *ta, const char *name,
                                const char *priv)
{
    return cfg_set_instance_fmt(CFG_VAL(STRING, priv),
                                "/agent:%s/vpn:/wireguard:%s/private_key:",
                                ta, name);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_get_public_key(const char *ta, const char *name, char *pub)
{
    char *value = NULL;
    te_errno rc;

    rc = cfg_get_instance_string_fmt(&value,
             "/agent:%s/vpn:/wireguard:%s/public_key:", ta, name);
    if (rc != 0)
        return rc;

    te_strlcpy(pub, value, TAPI_CFG_VPN_KEY_LEN);
    free(value);

    return 0;
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_genkey(const char *ta, const char *name, char *pub)
{
    te_errno rc;

    /*
     * The key is made on the agent, not here: the "generate" token asks
     * it to, and only the public key is read back - the private half
     * never crosses to the engine.
     */
    rc = cfg_set_instance_fmt(CFG_VAL(STRING, "generate"),
             "/agent:%s/vpn:/wireguard:%s/private_key:", ta, name);
    if (rc != 0)
        return rc;

    return tapi_cfg_vpn_wg_get_public_key(ta, name, pub);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_set_listen_port(const char *ta, const char *name,
                                uint16_t port)
{
    return cfg_set_instance_fmt(CFG_VAL(INT32, (int32_t)port),
             "/agent:%s/vpn:/wireguard:%s/listen_port:", ta, name);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_set_address(const char *ta, const char *name,
                            const char *cidr)
{
    return cfg_set_instance_fmt(CFG_VAL(STRING, cidr),
             "/agent:%s/vpn:/wireguard:%s/address:", ta, name);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_get_status(const char *ta, const char *name, bool *up)
{
    int value = 0;
    te_errno rc;

    rc = cfg_get_instance_int_fmt(&value,
             "/agent:%s/vpn:/wireguard:%s/status:", ta, name);
    if (rc == 0)
        *up = value != 0;

    return rc;
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_peer_add(const char *ta, const char *name,
                         const char *peer_pub)
{
    return cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
             "/agent:%s/vpn:/wireguard:%s/peer:%s", ta, name, peer_pub);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_peer_set_endpoint(const char *ta, const char *name,
                                  const char *peer_pub, const char *endpoint)
{
    return cfg_set_instance_fmt(CFG_VAL(STRING, endpoint),
             "/agent:%s/vpn:/wireguard:%s/peer:%s/endpoint:", ta, name,
             peer_pub);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_peer_set_allowed_ips(const char *ta, const char *name,
                                     const char *peer_pub,
                                     const char *allowed)
{
    return cfg_set_instance_fmt(CFG_VAL(STRING, allowed),
             "/agent:%s/vpn:/wireguard:%s/peer:%s/allowed_ips:", ta, name,
             peer_pub);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_wg_peer_handshake(const char *ta, const char *name,
                               const char *peer_pub, int *seconds)
{
    return cfg_get_instance_int_fmt(seconds,
             "/agent:%s/vpn:/wireguard:%s/peer:%s/latest_handshake:", ta,
             name, peer_pub);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_ipsec_add(const char *ta, const char *label, const char *local,
                       const char *remote, uint32_t spi)
{
    te_errno rc;

    rc = cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
                              "/agent:%s/vpn:/ipsec:%s", ta, label);
    if (rc != 0)
        return rc;

    rc = cfg_set_instance_fmt(CFG_VAL(STRING, local),
                              "/agent:%s/vpn:/ipsec:%s/local:", ta, label);
    if (rc != 0)
        return rc;

    rc = cfg_set_instance_fmt(CFG_VAL(STRING, remote),
                              "/agent:%s/vpn:/ipsec:%s/remote:", ta, label);
    if (rc != 0)
        return rc;

    return cfg_set_instance_fmt(CFG_VAL(INT32, (int32_t)spi),
                                "/agent:%s/vpn:/ipsec:%s/spi:", ta, label);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_ipsec_set_enc(const char *ta, const char *label,
                           const char *alg, const char *key_hex)
{
    te_errno rc;

    rc = cfg_set_instance_fmt(CFG_VAL(STRING, alg != NULL ? alg : ""),
                              "/agent:%s/vpn:/ipsec:%s/enc_alg:", ta, label);
    if (rc != 0)
        return rc;

    return cfg_set_instance_fmt(CFG_VAL(STRING,
                                        key_hex != NULL ? key_hex : ""),
                                "/agent:%s/vpn:/ipsec:%s/enc_key:", ta,
                                label);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_ipsec_set_auth(const char *ta, const char *label,
                            const char *alg, const char *key_hex)
{
    te_errno rc;

    rc = cfg_set_instance_fmt(CFG_VAL(STRING, alg != NULL ? alg : ""),
                              "/agent:%s/vpn:/ipsec:%s/auth_alg:", ta,
                              label);
    if (rc != 0)
        return rc;

    return cfg_set_instance_fmt(CFG_VAL(STRING,
                                        key_hex != NULL ? key_hex : ""),
                                "/agent:%s/vpn:/ipsec:%s/auth_key:", ta,
                                label);
}

/* See description in tapi_cfg_vpn.h */
te_errno
tapi_cfg_vpn_ipsec_get_status(const char *ta, const char *label, bool *up)
{
    int value = 0;
    te_errno rc;

    rc = cfg_get_instance_int_fmt(&value,
                                  "/agent:%s/vpn:/ipsec:%s/status:", ta,
                                  label);
    if (rc == 0)
        *up = value != 0;

    return rc;
}
