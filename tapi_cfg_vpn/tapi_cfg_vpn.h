/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Engine-side TAPI for the /agent/vpn subtree
 *
 * @defgroup tapi_cfg_vpn VPN configuration (tapi_cfg_vpn)
 * @{
 *
 * WireGuard and IPsec on an agent, through the Configurator, at the
 * level of the kernel primitives that carry them - a WireGuard private
 * key, an xfrm SPI, an encryption algorithm by its kernel name - with
 * a daemon (wg-quick, strongSwan) as an alternative backend.
 *
 * TE already has OpenVPN and L2TP as Configurator trees and VXLAN as a
 * tunnel; this fills the gap those left, which is the two VPNs that
 * matter and were missing: WireGuard and hand-programmed IPsec.
 *
 * @code
 * char pub[TAPI_CFG_VPN_KEY_LEN];
 *
 * CHECK_RC(tapi_cfg_vpn_wg_add(ta, "wg0"));
 * CHECK_RC(tapi_cfg_vpn_wg_genkey(ta, "wg0", pub));
 * CHECK_RC(tapi_cfg_vpn_wg_set_listen_port(ta, "wg0", 51820));
 * CHECK_RC(tapi_cfg_vpn_wg_peer_add(ta, "wg0", peer_pub));
 * CHECK_RC(tapi_cfg_vpn_wg_peer_set_endpoint(ta, "wg0", peer_pub,
 *                                            "203.0.113.1:51820"));
 * CHECK_RC(tapi_cfg_vpn_commit(ta));
 * @endcode
 */

#ifndef __TSF_TAPI_CFG_VPN_H__
#define __TSF_TAPI_CFG_VPN_H__

#include "te_defs.h"
#include "te_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A base64 key plus a terminator. */
#define TAPI_CFG_VPN_KEY_LEN 45

/** How the subtree is applied. */
typedef enum tapi_cfg_vpn_backend {
    /** ip, wg, ip xfrm - the default. */
    TAPI_CFG_VPN_KERNEL = 0,
    /** WireGuard through wg-quick. */
    TAPI_CFG_VPN_WG_QUICK,
    /** IPsec through strongSwan's swanctl. */
    TAPI_CFG_VPN_SWANCTL,
} tapi_cfg_vpn_backend;

/**
 * Choose how the agent applies the subtree.
 *
 * @param ta        Agent.
 * @param backend   The backend.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_set_backend(const char *ta,
                                         tapi_cfg_vpn_backend backend);

/**
 * Apply everything configured under @c /agent/vpn.
 *
 * @param ta        Agent.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_commit(const char *ta);

/**
 * Add a WireGuard interface.
 *
 * @param ta        Agent.
 * @param name      Interface name, e.g. @c "wg0".
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_wg_add(const char *ta, const char *name);

/**
 * Remove a WireGuard interface.
 *
 * @param ta        Agent.
 * @param name      Interface name.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_wg_del(const char *ta, const char *name);

/**
 * Give the interface a private key, letting the agent generate it, and
 * read back the public key.
 *
 * The private key never leaves the agent; only the public one comes
 * back, which is what a test hands to the far end.
 *
 * @param[in]  ta       Agent.
 * @param[in]  name     Interface name.
 * @param[out] pub      Buffer of @ref TAPI_CFG_VPN_KEY_LEN for the
 *                      derived public key.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_wg_genkey(const char *ta, const char *name,
                                       char *pub);

/**
 * Set the interface's private key explicitly.
 *
 * @param ta        Agent.
 * @param name      Interface name.
 * @param priv      Private key, base64.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_wg_set_private_key(const char *ta,
                                                const char *name,
                                                const char *priv);

/**
 * Read the interface's public key.
 *
 * @param[in]  ta       Agent.
 * @param[in]  name     Interface name.
 * @param[out] pub      Buffer of @ref TAPI_CFG_VPN_KEY_LEN.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_wg_get_public_key(const char *ta,
                                               const char *name, char *pub);

/** Set the interface's listen port. */
extern te_errno tapi_cfg_vpn_wg_set_listen_port(const char *ta,
                                                const char *name,
                                                uint16_t port);

/** Set the address on the interface, CIDR. */
extern te_errno tapi_cfg_vpn_wg_set_address(const char *ta, const char *name,
                                            const char *cidr);

/** Is the interface up? */
extern te_errno tapi_cfg_vpn_wg_get_status(const char *ta, const char *name,
                                           bool *up);

/** Add a peer to the interface, named by its public key. */
extern te_errno tapi_cfg_vpn_wg_peer_add(const char *ta, const char *name,
                                         const char *peer_pub);

/** Set where to reach a peer, host:port. */
extern te_errno tapi_cfg_vpn_wg_peer_set_endpoint(const char *ta,
                                                  const char *name,
                                                  const char *peer_pub,
                                                  const char *endpoint);

/** Set the prefixes routed to a peer, comma-separated. */
extern te_errno tapi_cfg_vpn_wg_peer_set_allowed_ips(const char *ta,
                                                     const char *name,
                                                     const char *peer_pub,
                                                     const char *allowed);

/**
 * Read seconds since a peer's last handshake.
 *
 * The one number that says whether the tunnel is alive: a peer that
 * has never completed a handshake reads @c -1, and one that stopped
 * answering shows the gap growing.
 *
 * @param[in]  ta       Agent.
 * @param[in]  name     Interface name.
 * @param[in]  peer_pub The peer's public key.
 * @param[out] seconds  Seconds since the handshake, or @c -1.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_wg_peer_handshake(const char *ta,
                                               const char *name,
                                               const char *peer_pub,
                                               int *seconds);

/**
 * Add an IPsec security association.
 *
 * @param ta        Agent.
 * @param label     A name for the SA.
 * @param local     Source address.
 * @param remote    Destination address.
 * @param spi       Security parameter index.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_ipsec_add(const char *ta, const char *label,
                                       const char *local, const char *remote,
                                       uint32_t spi);

/**
 * Set an SA's encryption.
 *
 * Passing an empty @p alg leaves the SA null-encrypted, which is a
 * misconfiguration a test may want to build on purpose.
 *
 * @param ta        Agent.
 * @param label     The SA.
 * @param alg       Algorithm as the kernel names it, or @c "".
 * @param key_hex   Key, hex with a @c 0x prefix.
 *
 * @return Status code.
 */
extern te_errno tapi_cfg_vpn_ipsec_set_enc(const char *ta, const char *label,
                                           const char *alg,
                                           const char *key_hex);

/** Set an SA's integrity algorithm and key. */
extern te_errno tapi_cfg_vpn_ipsec_set_auth(const char *ta,
                                            const char *label,
                                            const char *alg,
                                            const char *key_hex);

/** Is the SA present in the kernel? */
extern te_errno tapi_cfg_vpn_ipsec_get_status(const char *ta,
                                              const char *label, bool *up);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_CFG_VPN_H__ */

/**@} <!-- END tapi_cfg_vpn --> */
