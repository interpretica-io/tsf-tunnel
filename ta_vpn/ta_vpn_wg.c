/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief VPN agent library: WireGuard, at the level of ip and wg
 */

#define TE_LGR_USER "TA VPN WG"

#include "te_config.h"

#include <net/if.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "agentlib.h"
#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"

#include "ta_vpn.h"

/** Base64-encode @p len bytes of @p raw into @p out. */
static void
wg_b64(const uint8_t *raw, size_t len, char *out)
{
    /* EVP_EncodeBlock writes the NUL and returns the length without it. */
    EVP_EncodeBlock((unsigned char *)out, raw, (int)len);
}

/** Decode a 32-byte base64 key; returns false on anything but 32 bytes. */
static bool
wg_unb64(const char *b64, uint8_t *raw)
{
    uint8_t buf[48];
    int n;

    if (b64 == NULL || strlen(b64) != 44)
        return false;

    n = EVP_DecodeBlock((unsigned char *)buf, (const unsigned char *)b64,
                        44);
    /* EVP_DecodeBlock rounds up to 3-byte groups: 44 chars -> 33 bytes,
     * and the trailing '=' means the last byte is padding. */
    if (n < 32)
        return false;

    memcpy(raw, buf, 32);

    return true;
}

/** Public key from a raw private key, both 32 bytes. */
static te_errno
wg_derive(const uint8_t *priv, uint8_t *pub)
{
    EVP_PKEY *key;
    size_t len = 32;
    te_errno rc = 0;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (key == NULL)
        return TE_RC(TE_TA_UNIX, TE_EFAIL);

    if (EVP_PKEY_get_raw_public_key(key, pub, &len) != 1 || len != 32)
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);

    EVP_PKEY_free(key);

    return rc;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_genkey(char *priv_b64, char *pub_b64)
{
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    uint8_t priv[32];
    uint8_t pub[32];
    size_t len = 32;
    te_errno rc = 0;

    if (key == NULL)
        return TE_RC(TE_TA_UNIX, TE_EFAIL);

    if (EVP_PKEY_get_raw_private_key(key, priv, &len) != 1 || len != 32)
    {
        EVP_PKEY_free(key);
        return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    wg_b64(priv, 32, priv_b64);

    if (pub_b64 != NULL)
    {
        len = 32;
        if (EVP_PKEY_get_raw_public_key(key, pub, &len) == 1)
            wg_b64(pub, 32, pub_b64);
        else
            rc = TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    EVP_PKEY_free(key);

    return rc;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_pubkey(const char *priv_b64, char *pub_b64)
{
    uint8_t priv[32];
    uint8_t pub[32];
    te_errno rc;

    if (!wg_unb64(priv_b64, priv))
        return TE_RC(TE_TA_UNIX, TE_EINVAL);

    rc = wg_derive(priv, pub);
    if (rc == 0)
        wg_b64(pub, 32, pub_b64);

    return rc;
}

/** Write a base64 key to a mode-600 file and give back its path. */
static te_errno
wg_key_file(const char *key_dir, const char *name, const char *key_b64,
            te_string *path)
{
    FILE *f;

    te_string_append(path, "%s/%s.key", key_dir, name);

    f = fopen(path->ptr, "w");
    if (f == NULL)
        return TE_OS_RC(TE_TA_UNIX, errno);

    (void)chmod(path->ptr, 0600);
    fprintf(f, "%s\n", key_b64);
    fclose(f);

    return 0;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_build_set(const ta_vpn_wg *wg, const char *key_dir,
                    te_string *cmd)
{
    const ta_vpn_wg_peer *peer;
    te_string path = TE_STRING_INIT;
    te_errno rc;

    te_string_append(cmd, "wg set %s", wg->name);

    if (wg->private_key[0] != '\0')
    {
        rc = wg_key_file(key_dir, wg->name, wg->private_key, &path);
        if (rc != 0)
        {
            te_string_free(&path);
            return rc;
        }
        te_string_append(cmd, " private-key %s", path.ptr);
    }

    if (wg->listen_port != 0)
        te_string_append(cmd, " listen-port %u", wg->listen_port);
    if (wg->fwmark != 0)
        te_string_append(cmd, " fwmark %u", wg->fwmark);

    SLIST_FOREACH(peer, &wg->peers, links)
    {
        te_string_append(cmd, " peer %s", peer->public_key);

        if (peer->preshared_key[0] != '\0')
        {
            te_string pskpath = TE_STRING_INIT;
            char label[IF_NAMESIZE + 8];

            te_snprintf(label, sizeof(label), "%s-psk", wg->name);
            rc = wg_key_file(key_dir, label, peer->preshared_key,
                             &pskpath);
            if (rc == 0)
                te_string_append(cmd, " preshared-key %s", pskpath.ptr);
            te_string_free(&pskpath);
        }

        if (peer->endpoint != NULL && peer->endpoint[0] != '\0')
            te_string_append(cmd, " endpoint %s", peer->endpoint);

        /* allowed-ips is mandatory for wg; empty means route nothing. */
        te_string_append(cmd, " allowed-ips %s",
                         peer->allowed_ips != NULL &&
                         peer->allowed_ips[0] != '\0' ?
                             peer->allowed_ips : "0.0.0.0/0");

        if (peer->persistent_keepalive != 0)
            te_string_append(cmd, " persistent-keepalive %u",
                             peer->persistent_keepalive);
    }

    te_string_free(&path);

    return 0;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_parse_dump(const char *text, int64_t *handshake, int64_t *rx,
                     int64_t *tx)
{
    const char *line;
    bool first = true;

    if (handshake != NULL)
        *handshake = -1;
    if (rx != NULL)
        *rx = 0;
    if (tx != NULL)
        *tx = 0;

    /*
     * The first line is the interface itself; every line after it is a
     * peer, tab-separated:
     *   pubkey  psk  endpoint  allowed-ips  handshake  rx  tx  keepalive
     * The handshake is a Unix time, 0 for never. This sums transfer
     * across peers and takes the most recent handshake.
     */
    for (line = text; line != NULL && *line != '\0'; )
    {
        const char *end = strchr(line, '\n');
        size_t len = end != NULL ? (size_t)(end - line) : strlen(line);

        if (!first && len > 0)
        {
            char buf[512];
            char *field;
            char *save = NULL;
            int col = 0;

            if (len < sizeof(buf))
            {
                memcpy(buf, line, len);
                buf[len] = '\0';

                for (field = strtok_r(buf, "\t", &save); field != NULL;
                     field = strtok_r(NULL, "\t", &save), col++)
                {
                    int64_t v = strtoll(field, NULL, 10);

                    if (col == 4 && handshake != NULL && v > 0)
                    {
                        int64_t ago = (int64_t)time(NULL) - v;

                        if (*handshake < 0 || ago < *handshake)
                            *handshake = ago;
                    }
                    else if (col == 5 && rx != NULL)
                    {
                        *rx += v;
                    }
                    else if (col == 6 && tx != NULL)
                    {
                        *tx += v;
                    }
                }
            }
        }

        first = false;
        line = end != NULL ? end + 1 : NULL;
    }

    return 0;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_apply_kernel(const ta_vpn_wg *wg)
{
    te_string cmd = TE_STRING_INIT;
    const char *key_dir = getenv("TMPDIR");
    te_errno rc;

    if (key_dir == NULL)
        key_dir = "/tmp";

    /* Idempotent: a stale interface of this name goes first. */
    (void)ta_system_fmt("ip link del dev %s 2>/dev/null", wg->name);

    if (ta_system_fmt("ip link add dev %s type wireguard", wg->name) != 0)
    {
        ERROR("Could not create WireGuard interface %s; is the module "
              "loaded?", wg->name);
        return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    rc = ta_vpn_wg_build_set(wg, key_dir, &cmd);
    if (rc != 0)
    {
        te_string_free(&cmd);
        return rc;
    }

    if (ta_system(cmd.ptr) != 0)
    {
        ERROR("wg set failed for %s", wg->name);
        te_string_free(&cmd);
        return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    if (wg->address != NULL && wg->address[0] != '\0')
        (void)ta_system_fmt("ip addr add %s dev %s", wg->address, wg->name);

    if (ta_system_fmt("ip link set up dev %s", wg->name) != 0)
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);

    te_string_free(&cmd);

    return rc;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_apply_quick(const ta_vpn_wg *wg)
{
    const ta_vpn_wg_peer *peer;
    te_string conf = TE_STRING_INIT;
    te_string path = TE_STRING_INIT;
    const char *dir = getenv("TMPDIR");
    FILE *f;
    te_errno rc = 0;

    if (dir == NULL)
        dir = "/tmp";

    /*
     * wg-quick reads a .conf whose name is the interface name. It is
     * the same key material as the kernel path, only laid out as a file
     * a daemon reads instead of as commands - which is the whole point
     * of offering it as an alternative.
     */
    te_string_append(&conf, "[Interface]\nPrivateKey = %s\n",
                     wg->private_key);
    if (wg->listen_port != 0)
        te_string_append(&conf, "ListenPort = %u\n", wg->listen_port);
    if (wg->address != NULL && wg->address[0] != '\0')
        te_string_append(&conf, "Address = %s\n", wg->address);

    SLIST_FOREACH(peer, &wg->peers, links)
    {
        te_string_append(&conf, "\n[Peer]\nPublicKey = %s\n",
                         peer->public_key);
        if (peer->preshared_key[0] != '\0')
            te_string_append(&conf, "PresharedKey = %s\n",
                             peer->preshared_key);
        if (peer->endpoint != NULL && peer->endpoint[0] != '\0')
            te_string_append(&conf, "Endpoint = %s\n", peer->endpoint);
        te_string_append(&conf, "AllowedIPs = %s\n",
                         peer->allowed_ips != NULL ? peer->allowed_ips :
                             "0.0.0.0/0");
        if (peer->persistent_keepalive != 0)
            te_string_append(&conf, "PersistentKeepalive = %u\n",
                             peer->persistent_keepalive);
    }

    te_string_append(&path, "%s/%s.conf", dir, wg->name);

    f = fopen(path.ptr, "w");
    if (f == NULL)
    {
        rc = TE_OS_RC(TE_TA_UNIX, errno);
        goto out;
    }
    (void)chmod(path.ptr, 0600);
    fputs(conf.ptr, f);
    fclose(f);

    (void)ta_system_fmt("wg-quick down %s 2>/dev/null", path.ptr);
    if (ta_system_fmt("wg-quick up %s", path.ptr) != 0)
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);

out:
    te_string_free(&conf);
    te_string_free(&path);

    return rc;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_wg_teardown(const char *name)
{
    (void)ta_system_fmt("ip link del dev %s 2>/dev/null", name);

    return 0;
}

/* See description in ta_vpn.h */
bool
ta_vpn_wg_is_up(const char *name)
{
    return ta_system_fmt("ip link show dev %s up >/dev/null 2>&1",
                         name) == 0;
}
