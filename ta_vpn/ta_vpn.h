/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief VPN agent library
 *
 * The model behind the @c /agent/vpn configuration subtree, and the
 * backends that apply it: the kernel directly (@c ip, @c wg,
 * @c ip @c xfrm), or a daemon (@c wg-quick, @c swanctl).
 *
 * Internal to tsf-tunnel; not installed.
 */

#ifndef __TSF_TA_VPN_H__
#define __TSF_TA_VPN_H__

#include "te_config.h"

#include <net/if.h>
#include <sys/queue.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Base64 of a 32-byte key is 44 characters, plus a terminator. */
#define TA_VPN_KEY_B64 45

/** How the subtree is pushed to the system. */
typedef enum ta_vpn_backend {
    /** @c ip, @c wg and @c ip @c xfrm - the default and the point. */
    TA_VPN_BACKEND_KERNEL = 0,
    /** WireGuard through @c wg-quick. */
    TA_VPN_BACKEND_WG_QUICK,
    /** IPsec through strongSwan's @c swanctl. */
    TA_VPN_BACKEND_SWANCTL,
} ta_vpn_backend;

/** One peer of a WireGuard interface. */
typedef struct ta_vpn_wg_peer {
    /** Its public key, base64; also the instance name. */
    char public_key[TA_VPN_KEY_B64];
    /** Where to reach it, host:port, or empty. */
    char *endpoint;
    /** Comma-separated prefixes routed here. */
    char *allowed_ips;
    /** Optional preshared key, base64, or empty. */
    char preshared_key[TA_VPN_KEY_B64];
    /** Keepalive seconds, 0 for none. */
    unsigned int persistent_keepalive;
    /** Next peer of the same interface. */
    SLIST_ENTRY(ta_vpn_wg_peer) links;
} ta_vpn_wg_peer;

/** One WireGuard interface. */
typedef struct ta_vpn_wg {
    /** Interface name, e.g. "wg0"; also the instance name. */
    char name[IF_NAMESIZE];
    /** Private key, base64. */
    char private_key[TA_VPN_KEY_B64];
    /** Listen port, 0 for ephemeral. */
    unsigned int listen_port;
    /** Firewall mark, 0 for none. */
    unsigned int fwmark;
    /** Address to put on the interface, CIDR, or empty. */
    char *address;
    /** Peers. */
    SLIST_HEAD(, ta_vpn_wg_peer) peers;
    /** Next interface. */
    SLIST_ENTRY(ta_vpn_wg) links;
} ta_vpn_wg;

/** One IPsec security association, one direction. */
typedef struct ta_vpn_ipsec_sa {
    /** A label chosen by the test; the instance name. */
    char *label;
    /** Source address. */
    char *local;
    /** Destination address. */
    char *remote;
    /** Security parameter index. */
    uint32_t spi;
    /** "esp" or "ah". */
    char proto[8];
    /** "transport" or "tunnel". */
    char mode[12];
    /** Encryption algorithm, kernel name, or empty. */
    char *enc_alg;
    /** Encryption key, hex with 0x, or empty. */
    char *enc_key;
    /** Integrity algorithm, or empty. */
    char *auth_alg;
    /** Integrity key, hex with 0x, or empty. */
    char *auth_key;
    /** Next SA. */
    SLIST_ENTRY(ta_vpn_ipsec_sa) links;
} ta_vpn_ipsec_sa;

/** The whole model. */
typedef struct ta_vpn_model {
    /** Chosen backend. */
    ta_vpn_backend backend;
    /** WireGuard interfaces. */
    SLIST_HEAD(, ta_vpn_wg) wg;
    /** IPsec SAs. */
    SLIST_HEAD(, ta_vpn_ipsec_sa) ipsec;
} ta_vpn_model;

/** The one model instance. */
extern ta_vpn_model *ta_vpn_get_model(void);

/**
 * Generate a WireGuard key pair.
 *
 * X25519 through libcrypto, which - verified against the @c wg tool -
 * derives the same public key WireGuard would. No shelling out to
 * @c wg @c genkey: the key is made in process.
 *
 * @param[out] priv_b64  Buffer of @ref TA_VPN_KEY_B64.
 * @param[out] pub_b64   Buffer of @ref TA_VPN_KEY_B64, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno ta_vpn_wg_genkey(char *priv_b64, char *pub_b64);

/**
 * Derive a WireGuard public key from a private one.
 *
 * @param[in]  priv_b64  The private key, base64.
 * @param[out] pub_b64   Buffer of @ref TA_VPN_KEY_B64.
 *
 * @return Status code.
 */
extern te_errno ta_vpn_wg_pubkey(const char *priv_b64, char *pub_b64);

/**
 * Build the @c "wg set" arguments for an interface, as one shell line.
 *
 * The low-level form: @c "wg set wg0 private-key /path listen-port N
 * peer <pub> endpoint ... allowed-ips ...". The private and preshared
 * keys are written to files under @p key_dir, because @c wg reads them
 * from files and never from the command line where the process list
 * would show them.
 *
 * @param[in]  wg       The interface.
 * @param[in]  key_dir  A directory to drop key files in.
 * @param[out] cmd      String to append the command to.
 *
 * @return Status code.
 */
extern te_errno ta_vpn_wg_build_set(const ta_vpn_wg *wg, const char *key_dir,
                                    te_string *cmd);

/**
 * Parse one interface out of @c "wg show <if> dump".
 *
 * The dump is tab-separated: the first line is the interface's own
 * keys, port and fwmark; each following line is a peer. This reads the
 * live handshake and transfer counters back into @p out, which need not
 * be the model's own interface.
 *
 * @param[in]  text     The dump.
 * @param[out] handshake   Seconds since the first peer's handshake, or
 *                          -1; may be @c NULL.
 * @param[out] rx          Bytes received, or @c NULL.
 * @param[out] tx          Bytes sent, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno ta_vpn_wg_parse_dump(const char *text, int64_t *handshake,
                                     int64_t *rx, int64_t *tx);

/**
 * Apply one WireGuard interface to the system through the kernel.
 *
 * @c ip @c link @c add @c type @c wireguard, @c wg @c set, @c ip @c addr,
 * @c ip @c link @c set @c up. Removes an interface of the same name
 * first, so applying is idempotent.
 *
 * @param wg    The interface.
 *
 * @return Status code.
 */
extern te_errno ta_vpn_wg_apply_kernel(const ta_vpn_wg *wg);

/** Apply one WireGuard interface through @c wg-quick. */
extern te_errno ta_vpn_wg_apply_quick(const ta_vpn_wg *wg);

/** Take a WireGuard interface down. */
extern te_errno ta_vpn_wg_teardown(const char *name);

/** Is a WireGuard interface up? */
extern bool ta_vpn_wg_is_up(const char *name);

/**
 * Build the @c "ip xfrm state add" arguments for an SA, as one line.
 *
 * @param[in]  sa       The SA.
 * @param[out] cmd      String to append the command to.
 *
 * @return Status code.
 */
extern te_errno ta_vpn_ipsec_build_state(const ta_vpn_ipsec_sa *sa,
                                         te_string *cmd);

/** Apply one IPsec SA to the kernel with @c ip @c xfrm. */
extern te_errno ta_vpn_ipsec_apply_kernel(const ta_vpn_ipsec_sa *sa);

/** Apply one IPsec SA through strongSwan's @c swanctl. */
extern te_errno ta_vpn_ipsec_apply_swanctl(const ta_vpn_ipsec_sa *sa);

/** Remove one IPsec SA from the kernel. */
extern te_errno ta_vpn_ipsec_teardown(const ta_vpn_ipsec_sa *sa);

/** Is an SA of this SPI/proto present in the kernel? */
extern bool ta_vpn_ipsec_is_up(const ta_vpn_ipsec_sa *sa);

/** Registration constructor. */
extern te_errno ta_unix_conf_vpn_init(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TA_VPN_H__ */
