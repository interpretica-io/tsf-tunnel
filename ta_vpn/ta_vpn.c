/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief VPN agent library: the /agent/vpn configuration subtree
 *
 * The Configurator nodes and the one commit that pushes the model to
 * the system through the chosen backend. The nodes are deliberately
 * low-level - a WireGuard private key, an xfrm SPI, an encryption
 * algorithm by its kernel name - rather than a "connect me to this
 * VPN" abstraction, because the point of reaching a VPN from a test is
 * to be able to build it wrong on purpose.
 */

#define TE_LGR_USER "TA VPN"

#include "te_config.h"

#include <net/if.h>
#include <string.h>

#include "agentlib.h"
#include "logger_api.h"
#include "rcf_pch.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"

#include "ta_vpn.h"

static rcf_pch_cfg_object node_vpn;

/* The one model. */
static ta_vpn_model model = {
    .backend = TA_VPN_BACKEND_KERNEL,
    .wg = SLIST_HEAD_INITIALIZER(model.wg),
    .ipsec = SLIST_HEAD_INITIALIZER(model.ipsec),
};

/* See description in ta_vpn.h */
ta_vpn_model *
ta_vpn_get_model(void)
{
    return &model;
}

static ta_vpn_wg *
vpn_find_wg(const char *name)
{
    ta_vpn_wg *wg;

    SLIST_FOREACH(wg, &model.wg, links)
    {
        if (strcmp(wg->name, name) == 0)
            return wg;
    }

    return NULL;
}

static ta_vpn_wg_peer *
vpn_find_peer(ta_vpn_wg *wg, const char *pub)
{
    ta_vpn_wg_peer *peer;

    if (wg == NULL)
        return NULL;

    SLIST_FOREACH(peer, &wg->peers, links)
    {
        if (strcmp(peer->public_key, pub) == 0)
            return peer;
    }

    return NULL;
}

static ta_vpn_ipsec_sa *
vpn_find_sa(const char *label)
{
    ta_vpn_ipsec_sa *sa;

    SLIST_FOREACH(sa, &model.ipsec, links)
    {
        if (strcmp(sa->label, label) == 0)
            return sa;
    }

    return NULL;
}

/* --- backend ---------------------------------------------------------- */

static te_errno
node_vpn_backend_get(unsigned int gid, const char *oid, char *value,
                     const char *empty)
{
    static const char *const names[] = { "kernel", "wg-quick", "swanctl" };

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    snprintf(value, RCF_MAX_VAL, "%s", names[model.backend]);

    return 0;
}

static te_errno
node_vpn_backend_set(unsigned int gid, const char *oid, const char *value,
                     const char *empty)
{
    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (strcmp(value, "kernel") == 0)
        model.backend = TA_VPN_BACKEND_KERNEL;
    else if (strcmp(value, "wg-quick") == 0)
        model.backend = TA_VPN_BACKEND_WG_QUICK;
    else if (strcmp(value, "swanctl") == 0)
        model.backend = TA_VPN_BACKEND_SWANCTL;
    else
        return TE_RC(TE_TA_UNIX, TE_EINVAL);

    return 0;
}

/* --- WireGuard interface collection ----------------------------------- */

static te_errno
node_wg_add(unsigned int gid, const char *oid, const char *value,
            const char *empty, const char *name)
{
    ta_vpn_wg *wg;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(value);
    UNUSED(empty);

    if (strlen(name) >= IF_NAMESIZE)
        return TE_RC(TE_TA_UNIX, TE_EINVAL);

    if (vpn_find_wg(name) != NULL)
        return TE_RC(TE_TA_UNIX, TE_EEXIST);

    wg = TE_ALLOC(sizeof(*wg));
    te_strlcpy(wg->name, name, sizeof(wg->name));
    SLIST_INIT(&wg->peers);
    SLIST_INSERT_HEAD(&model.wg, wg, links);

    return 0;
}

static te_errno
node_wg_del(unsigned int gid, const char *oid, const char *empty,
            const char *name)
{
    ta_vpn_wg *wg = vpn_find_wg(name);
    ta_vpn_wg_peer *peer;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (wg == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    (void)ta_vpn_wg_teardown(wg->name);

    while ((peer = SLIST_FIRST(&wg->peers)) != NULL)
    {
        SLIST_REMOVE_HEAD(&wg->peers, links);
        free(peer->endpoint);
        free(peer->allowed_ips);
        free(peer);
    }

    SLIST_REMOVE(&model.wg, wg, ta_vpn_wg, links);
    free(wg->address);
    free(wg);

    return 0;
}

static te_errno
node_wg_list(unsigned int gid, const char *oid, const char *sub_id,
             char **list, const char *empty)
{
    ta_vpn_wg *wg;
    te_string str = TE_STRING_INIT;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(sub_id);
    UNUSED(empty);

    SLIST_FOREACH(wg, &model.wg, links)
        te_string_append(&str, "%s%s", str.ptr != NULL ? " " : "", wg->name);

    *list = str.ptr;

    return 0;
}

/* --- WireGuard interface fields --------------------------------------- */

#define WG_FIELD_STR(field, member)                                     \
static te_errno                                                        \
node_wg_ ## field ## _get(unsigned int gid, const char *oid,          \
    char *value, const char *empty, const char *name)                 \
{                                                                     \
    ta_vpn_wg *wg = vpn_find_wg(name);                                \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (wg == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);             \
    snprintf(value, RCF_MAX_VAL, "%s",                               \
        wg->member != NULL ? wg->member : "");                       \
    return 0;                                                        \
}                                                                     \
static te_errno                                                       \
node_wg_ ## field ## _set(unsigned int gid, const char *oid,          \
    const char *value, const char *empty, const char *name)           \
{                                                                     \
    ta_vpn_wg *wg = vpn_find_wg(name);                                \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (wg == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);             \
    free(wg->member);                                                 \
    wg->member = TE_STRDUP(value);                                    \
    return 0;                                                        \
}

WG_FIELD_STR(address, address)

/* private_key is a fixed buffer, not a pointer. */
static te_errno
node_wg_private_key_get(unsigned int gid, const char *oid, char *value,
                        const char *empty, const char *name)
{
    ta_vpn_wg *wg = vpn_find_wg(name);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (wg == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    snprintf(value, RCF_MAX_VAL, "%s", wg->private_key);

    return 0;
}

static te_errno
node_wg_private_key_set(unsigned int gid, const char *oid, const char *value,
                        const char *empty, const char *name)
{
    ta_vpn_wg *wg = vpn_find_wg(name);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (wg == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    /*
     * "generate" is the engine asking the agent to make a key, so the
     * private half is born here and never crosses to the engine - only
     * the public key does, read back through the volatile node. Any
     * other value is taken as a real key.
     */
    if (strcmp(value, "generate") == 0 || value[0] == '\0')
        return ta_vpn_wg_genkey(wg->private_key, NULL);

    te_strlcpy(wg->private_key, value, sizeof(wg->private_key));

    return 0;
}

/* public_key is derived from the private one, live. */
static te_errno
node_wg_public_key_get(unsigned int gid, const char *oid, char *value,
                       const char *empty, const char *name)
{
    ta_vpn_wg *wg = vpn_find_wg(name);
    char pub[TA_VPN_KEY_B64] = {0};

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (wg == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    if (wg->private_key[0] != '\0')
        (void)ta_vpn_wg_pubkey(wg->private_key, pub);

    snprintf(value, RCF_MAX_VAL, "%s", pub);

    return 0;
}

#define WG_FIELD_UINT(field, member)                                   \
static te_errno                                                        \
node_wg_ ## field ## _get(unsigned int gid, const char *oid,          \
    char *value, const char *empty, const char *name)                 \
{                                                                     \
    ta_vpn_wg *wg = vpn_find_wg(name);                                \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (wg == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);             \
    snprintf(value, RCF_MAX_VAL, "%u", wg->member);                  \
    return 0;                                                        \
}                                                                     \
static te_errno                                                       \
node_wg_ ## field ## _set(unsigned int gid, const char *oid,          \
    const char *value, const char *empty, const char *name)           \
{                                                                     \
    ta_vpn_wg *wg = vpn_find_wg(name);                                \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (wg == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);             \
    wg->member = (unsigned int)strtoul(value, NULL, 10);            \
    return 0;                                                        \
}

WG_FIELD_UINT(listen_port, listen_port)
WG_FIELD_UINT(fwmark, fwmark)

static te_errno
node_wg_status_get(unsigned int gid, const char *oid, char *value,
                   const char *empty, const char *name)
{
    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    snprintf(value, RCF_MAX_VAL, "%d", ta_vpn_wg_is_up(name) ? 1 : 0);

    return 0;
}

/* --- WireGuard peer collection ---------------------------------------- */

static te_errno
node_peer_add(unsigned int gid, const char *oid, const char *value,
              const char *empty, const char *wg_name, const char *pub)
{
    ta_vpn_wg *wg = vpn_find_wg(wg_name);
    ta_vpn_wg_peer *peer;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(value);
    UNUSED(empty);

    if (wg == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    if (strlen(pub) >= TA_VPN_KEY_B64)
        return TE_RC(TE_TA_UNIX, TE_EINVAL);

    if (vpn_find_peer(wg, pub) != NULL)
        return TE_RC(TE_TA_UNIX, TE_EEXIST);

    peer = TE_ALLOC(sizeof(*peer));
    te_strlcpy(peer->public_key, pub, sizeof(peer->public_key));
    SLIST_INSERT_HEAD(&wg->peers, peer, links);

    return 0;
}

static te_errno
node_peer_del(unsigned int gid, const char *oid, const char *empty,
              const char *wg_name, const char *pub)
{
    ta_vpn_wg *wg = vpn_find_wg(wg_name);
    ta_vpn_wg_peer *peer = vpn_find_peer(wg, pub);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (peer == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    SLIST_REMOVE(&wg->peers, peer, ta_vpn_wg_peer, links);
    free(peer->endpoint);
    free(peer->allowed_ips);
    free(peer);

    return 0;
}

static te_errno
node_peer_list(unsigned int gid, const char *oid, const char *sub_id,
               char **list, const char *empty, const char *wg_name)
{
    ta_vpn_wg *wg = vpn_find_wg(wg_name);
    ta_vpn_wg_peer *peer;
    te_string str = TE_STRING_INIT;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(sub_id);
    UNUSED(empty);

    if (wg == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    SLIST_FOREACH(peer, &wg->peers, links)
        te_string_append(&str, "%s%s", str.ptr != NULL ? " " : "",
                         peer->public_key);

    *list = str.ptr;

    return 0;
}

/* --- WireGuard peer fields -------------------------------------------- */

#define PEER_FIELD_STR(field, member)                                  \
static te_errno                                                        \
node_peer_ ## field ## _get(unsigned int gid, const char *oid,        \
    char *value, const char *empty, const char *wg_name,              \
    const char *pub)                                                   \
{                                                                     \
    ta_vpn_wg_peer *p = vpn_find_peer(vpn_find_wg(wg_name), pub);     \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (p == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);             \
    snprintf(value, RCF_MAX_VAL, "%s",                               \
        p->member != NULL ? p->member : "");                         \
    return 0;                                                        \
}                                                                     \
static te_errno                                                       \
node_peer_ ## field ## _set(unsigned int gid, const char *oid,        \
    const char *value, const char *empty, const char *wg_name,        \
    const char *pub)                                                   \
{                                                                     \
    ta_vpn_wg_peer *p = vpn_find_peer(vpn_find_wg(wg_name), pub);     \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (p == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);             \
    free(p->member);                                                  \
    p->member = TE_STRDUP(value);                                     \
    return 0;                                                        \
}

PEER_FIELD_STR(endpoint, endpoint)
PEER_FIELD_STR(allowed_ips, allowed_ips)

static te_errno
node_peer_preshared_key_get(unsigned int gid, const char *oid, char *value,
                            const char *empty, const char *wg_name,
                            const char *pub)
{
    ta_vpn_wg_peer *p = vpn_find_peer(vpn_find_wg(wg_name), pub);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (p == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    snprintf(value, RCF_MAX_VAL, "%s", p->preshared_key);

    return 0;
}

static te_errno
node_peer_preshared_key_set(unsigned int gid, const char *oid,
                            const char *value, const char *empty,
                            const char *wg_name, const char *pub)
{
    ta_vpn_wg_peer *p = vpn_find_peer(vpn_find_wg(wg_name), pub);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (p == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    te_strlcpy(p->preshared_key, value, sizeof(p->preshared_key));

    return 0;
}

static te_errno
node_peer_persistent_keepalive_get(unsigned int gid, const char *oid,
                                   char *value, const char *empty,
                                   const char *wg_name, const char *pub)
{
    ta_vpn_wg_peer *p = vpn_find_peer(vpn_find_wg(wg_name), pub);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (p == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    snprintf(value, RCF_MAX_VAL, "%u", p->persistent_keepalive);

    return 0;
}

static te_errno
node_peer_persistent_keepalive_set(unsigned int gid, const char *oid,
                                   const char *value, const char *empty,
                                   const char *wg_name, const char *pub)
{
    ta_vpn_wg_peer *p = vpn_find_peer(vpn_find_wg(wg_name), pub);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (p == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    p->persistent_keepalive = (unsigned int)strtoul(value, NULL, 10);

    return 0;
}

/* The three volatile peer counters all read the same live dump. */
#define PEER_DUMP_FIELD(field, which)                                   \
static te_errno                                                        \
node_peer_ ## field ## _get(unsigned int gid, const char *oid,        \
    char *value, const char *empty, const char *wg_name,              \
    const char *pub)                                                   \
{                                                                     \
    int64_t hs = -1, rx = 0, tx = 0;                                  \
    te_string dump = TE_STRING_INIT;                                  \
    pid_t pid; FILE *f; char buf[1024]; size_t n = 0;                \
    UNUSED(gid); UNUSED(oid); UNUSED(empty); UNUSED(pub);            \
    if (ta_popen_r_fmt(&pid, &f, "wg show %s dump 2>/dev/null",       \
                       wg_name) == 0)                                  \
    {                                                                 \
        while (fgets(buf, sizeof(buf), f) != NULL)                   \
            te_string_append(&dump, "%s", buf);                      \
        (void)ta_pclose_r(pid, f);                                    \
        ta_vpn_wg_parse_dump(dump.ptr != NULL ? dump.ptr : "",      \
                             &hs, &rx, &tx);                          \
    }                                                                 \
    (void)n;                                                          \
    snprintf(value, RCF_MAX_VAL, "%lld", (long long)(which));        \
    te_string_free(&dump);                                            \
    return 0;                                                        \
}

PEER_DUMP_FIELD(latest_handshake, hs)
PEER_DUMP_FIELD(rx_bytes, rx)
PEER_DUMP_FIELD(tx_bytes, tx)

/* --- IPsec SA collection ---------------------------------------------- */

static te_errno
node_ipsec_add(unsigned int gid, const char *oid, const char *value,
               const char *empty, const char *label)
{
    ta_vpn_ipsec_sa *sa;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(value);
    UNUSED(empty);

    if (vpn_find_sa(label) != NULL)
        return TE_RC(TE_TA_UNIX, TE_EEXIST);

    sa = TE_ALLOC(sizeof(*sa));
    sa->label = TE_STRDUP(label);
    te_strlcpy(sa->proto, "esp", sizeof(sa->proto));
    te_strlcpy(sa->mode, "tunnel", sizeof(sa->mode));
    SLIST_INSERT_HEAD(&model.ipsec, sa, links);

    return 0;
}

static te_errno
node_ipsec_del(unsigned int gid, const char *oid, const char *empty,
               const char *label)
{
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (sa == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    (void)ta_vpn_ipsec_teardown(sa);

    SLIST_REMOVE(&model.ipsec, sa, ta_vpn_ipsec_sa, links);
    free(sa->label);
    free(sa->local);
    free(sa->remote);
    free(sa->enc_alg);
    free(sa->enc_key);
    free(sa->auth_alg);
    free(sa->auth_key);
    free(sa);

    return 0;
}

static te_errno
node_ipsec_list(unsigned int gid, const char *oid, const char *sub_id,
                char **list, const char *empty)
{
    ta_vpn_ipsec_sa *sa;
    te_string str = TE_STRING_INIT;

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(sub_id);
    UNUSED(empty);

    SLIST_FOREACH(sa, &model.ipsec, links)
        te_string_append(&str, "%s%s", str.ptr != NULL ? " " : "",
                         sa->label);

    *list = str.ptr;

    return 0;
}

/* --- IPsec SA fields -------------------------------------------------- */

#define SA_FIELD_STR(field, member)                                    \
static te_errno                                                        \
node_ipsec_ ## field ## _get(unsigned int gid, const char *oid,       \
    char *value, const char *empty, const char *label)                \
{                                                                     \
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);                        \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (sa == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);            \
    snprintf(value, RCF_MAX_VAL, "%s",                              \
        sa->member != NULL ? sa->member : "");                       \
    return 0;                                                        \
}                                                                     \
static te_errno                                                       \
node_ipsec_ ## field ## _set(unsigned int gid, const char *oid,       \
    const char *value, const char *empty, const char *label)          \
{                                                                     \
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);                        \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (sa == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);            \
    free(sa->member);                                                 \
    sa->member = TE_STRDUP(value);                                    \
    return 0;                                                        \
}

SA_FIELD_STR(local, local)
SA_FIELD_STR(remote, remote)
SA_FIELD_STR(enc_alg, enc_alg)
SA_FIELD_STR(enc_key, enc_key)
SA_FIELD_STR(auth_alg, auth_alg)
SA_FIELD_STR(auth_key, auth_key)

#define SA_FIELD_BUF(field, member)                                    \
static te_errno                                                        \
node_ipsec_ ## field ## _get(unsigned int gid, const char *oid,       \
    char *value, const char *empty, const char *label)                \
{                                                                     \
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);                        \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (sa == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);            \
    snprintf(value, RCF_MAX_VAL, "%s", sa->member);                 \
    return 0;                                                        \
}                                                                     \
static te_errno                                                       \
node_ipsec_ ## field ## _set(unsigned int gid, const char *oid,       \
    const char *value, const char *empty, const char *label)          \
{                                                                     \
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);                        \
    UNUSED(gid); UNUSED(oid); UNUSED(empty);                          \
    if (sa == NULL) return TE_RC(TE_TA_UNIX, TE_ENOENT);            \
    te_strlcpy(sa->member, value, sizeof(sa->member));              \
    return 0;                                                        \
}

SA_FIELD_BUF(proto, proto)
SA_FIELD_BUF(mode, mode)

static te_errno
node_ipsec_spi_get(unsigned int gid, const char *oid, char *value,
                   const char *empty, const char *label)
{
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (sa == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    snprintf(value, RCF_MAX_VAL, "%u", sa->spi);

    return 0;
}

static te_errno
node_ipsec_spi_set(unsigned int gid, const char *oid, const char *value,
                   const char *empty, const char *label)
{
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (sa == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    sa->spi = (uint32_t)strtoul(value, NULL, 0);

    return 0;
}

static te_errno
node_ipsec_status_get(unsigned int gid, const char *oid, char *value,
                      const char *empty, const char *label)
{
    ta_vpn_ipsec_sa *sa = vpn_find_sa(label);

    UNUSED(gid);
    UNUSED(oid);
    UNUSED(empty);

    if (sa == NULL)
        return TE_RC(TE_TA_UNIX, TE_ENOENT);

    snprintf(value, RCF_MAX_VAL, "%d", ta_vpn_ipsec_is_up(sa) ? 1 : 0);

    return 0;
}

/* --- commit: push the whole model to the system ----------------------- */

static te_errno
node_vpn_commit(unsigned int gid, const cfg_oid *p_oid)
{
    ta_vpn_wg *wg;
    ta_vpn_ipsec_sa *sa;
    te_errno rc = 0;

    UNUSED(gid);
    UNUSED(p_oid);

    SLIST_FOREACH(wg, &model.wg, links)
    {
        te_errno one = model.backend == TA_VPN_BACKEND_WG_QUICK ?
                       ta_vpn_wg_apply_quick(wg) :
                       ta_vpn_wg_apply_kernel(wg);

        if (one != 0)
            rc = one;
    }

    SLIST_FOREACH(sa, &model.ipsec, links)
    {
        te_errno one = model.backend == TA_VPN_BACKEND_SWANCTL ?
                       ta_vpn_ipsec_apply_swanctl(sa) :
                       ta_vpn_ipsec_apply_kernel(sa);

        if (one != 0)
            rc = one;
    }

    return rc;
}

/* --- the node chain, declared child-last as Configurator wants -------- */

/* peer fields */
RCF_PCH_CFG_NODE_RWC(node_peer_tx_bytes, "tx_bytes", NULL, NULL,
                     node_peer_tx_bytes_get, NULL, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_peer_rx_bytes, "rx_bytes", NULL, &node_peer_tx_bytes,
                     node_peer_rx_bytes_get, NULL, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_peer_latest_handshake, "latest_handshake", NULL,
                     &node_peer_rx_bytes, node_peer_latest_handshake_get,
                     NULL, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_peer_persistent_keepalive, "persistent_keepalive",
                     NULL, &node_peer_latest_handshake,
                     node_peer_persistent_keepalive_get,
                     node_peer_persistent_keepalive_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_peer_preshared_key, "preshared_key", NULL,
                     &node_peer_persistent_keepalive,
                     node_peer_preshared_key_get, node_peer_preshared_key_set,
                     &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_peer_allowed_ips, "allowed_ips", NULL,
                     &node_peer_preshared_key, node_peer_allowed_ips_get,
                     node_peer_allowed_ips_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_peer_endpoint, "endpoint", NULL,
                     &node_peer_allowed_ips, node_peer_endpoint_get,
                     node_peer_endpoint_set, &node_vpn);
RCF_PCH_CFG_NODE_COLLECTION(node_wg_peer, "peer", &node_peer_endpoint, NULL,
                            node_peer_add, node_peer_del, node_peer_list,
                            NULL);

/* interface fields; the peer collection is the last sibling */
RCF_PCH_CFG_NODE_RWC(node_wg_status, "status", NULL, &node_wg_peer,
                     node_wg_status_get, NULL, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_wg_address, "address", NULL, &node_wg_status,
                     node_wg_address_get, node_wg_address_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_wg_fwmark, "fwmark", NULL, &node_wg_address,
                     node_wg_fwmark_get, node_wg_fwmark_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_wg_listen_port, "listen_port", NULL,
                     &node_wg_fwmark, node_wg_listen_port_get,
                     node_wg_listen_port_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_wg_public_key, "public_key", NULL,
                     &node_wg_listen_port, node_wg_public_key_get, NULL,
                     &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_wg_private_key, "private_key", NULL,
                     &node_wg_public_key, node_wg_private_key_get,
                     node_wg_private_key_set, &node_vpn);
RCF_PCH_CFG_NODE_COLLECTION(node_wireguard, "wireguard", &node_wg_private_key,
                            NULL, node_wg_add, node_wg_del, node_wg_list,
                            NULL);

/* ipsec fields */
RCF_PCH_CFG_NODE_RWC(node_ipsec_status, "status", NULL, NULL,
                     node_ipsec_status_get, NULL, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_auth_key, "auth_key", NULL,
                     &node_ipsec_status, node_ipsec_auth_key_get,
                     node_ipsec_auth_key_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_auth_alg, "auth_alg", NULL,
                     &node_ipsec_auth_key, node_ipsec_auth_alg_get,
                     node_ipsec_auth_alg_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_enc_key, "enc_key", NULL,
                     &node_ipsec_auth_alg, node_ipsec_enc_key_get,
                     node_ipsec_enc_key_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_enc_alg, "enc_alg", NULL, &node_ipsec_enc_key,
                     node_ipsec_enc_alg_get, node_ipsec_enc_alg_set,
                     &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_mode, "mode", NULL, &node_ipsec_enc_alg,
                     node_ipsec_mode_get, node_ipsec_mode_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_proto, "proto", NULL, &node_ipsec_mode,
                     node_ipsec_proto_get, node_ipsec_proto_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_spi, "spi", NULL, &node_ipsec_proto,
                     node_ipsec_spi_get, node_ipsec_spi_set, &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_remote, "remote", NULL, &node_ipsec_spi,
                     node_ipsec_remote_get, node_ipsec_remote_set,
                     &node_vpn);
RCF_PCH_CFG_NODE_RWC(node_ipsec_local, "local", NULL, &node_ipsec_remote,
                     node_ipsec_local_get, node_ipsec_local_set, &node_vpn);
RCF_PCH_CFG_NODE_COLLECTION(node_ipsec, "ipsec", &node_ipsec_local,
                            &node_wireguard, node_ipsec_add, node_ipsec_del,
                            node_ipsec_list, NULL);

/* backend, then the vpn root that commits */
RCF_PCH_CFG_NODE_RWC(node_vpn_backend, "backend", NULL, &node_ipsec,
                     node_vpn_backend_get, node_vpn_backend_set, &node_vpn);

RCF_PCH_CFG_NODE_NA_COMMIT(node_vpn, "vpn", &node_vpn_backend, NULL,
                           node_vpn_commit);

/* See description in ta_vpn.h */
te_errno
ta_unix_conf_vpn_init(void)
{
    te_errno rc;

    rc = rcf_pch_rsrc_info("/agent/vpn", rcf_pch_rsrc_grab_dummy,
                           rcf_pch_rsrc_release_dummy);
    if (rc != 0)
        return rc;

    return rcf_pch_add_node("/agent", &node_vpn);
}
