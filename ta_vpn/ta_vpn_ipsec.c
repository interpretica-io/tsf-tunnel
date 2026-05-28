/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief VPN agent library: IPsec, at the level of the kernel's xfrm
 *
 * No IKE, no daemon in the default path: a security association is
 * programmed straight into the kernel with @c ip @c xfrm, the way a
 * test that wants to control every parameter - including leaving the
 * encryption off to prove a point - needs. strongSwan is the
 * alternative for a test that wants a real negotiation.
 */

#define TE_LGR_USER "TA VPN IPSEC"

#include "te_config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agentlib.h"
#include "logger_api.h"
#include "te_str.h"
#include "te_string.h"

#include "ta_vpn.h"

/* See description in ta_vpn.h */
te_errno
ta_vpn_ipsec_build_state(const ta_vpn_ipsec_sa *sa, te_string *cmd)
{
    if (sa->local == NULL || sa->remote == NULL)
    {
        ERROR("An SA needs a local and a remote address");
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }

    te_string_append(cmd, "ip xfrm state add src %s dst %s proto %s spi %u "
                     "mode %s", sa->local, sa->remote,
                     sa->proto[0] != '\0' ? sa->proto : "esp", sa->spi,
                     sa->mode[0] != '\0' ? sa->mode : "tunnel");

    /*
     * The order is the kernel's: auth before enc for ESP. An SA with no
     * enc line is a null-encrypted SA - integrity but no confidentiality
     * - which is a real and testable misconfiguration, so it is allowed
     * to be built rather than rejected here. tapi_cfg_vpn's audit is
     * what calls it out.
     */
    if (sa->auth_alg != NULL && sa->auth_alg[0] != '\0')
        te_string_append(cmd, " auth '%s' %s", sa->auth_alg,
                         sa->auth_key != NULL ? sa->auth_key : "0x");

    if (sa->enc_alg != NULL && sa->enc_alg[0] != '\0')
        te_string_append(cmd, " enc '%s' %s", sa->enc_alg,
                         sa->enc_key != NULL ? sa->enc_key : "0x");

    return 0;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_ipsec_apply_kernel(const ta_vpn_ipsec_sa *sa)
{
    te_string cmd = TE_STRING_INIT;
    te_errno rc;

    /* Idempotent: drop a stale SA with this SPI first. */
    (void)ta_vpn_ipsec_teardown(sa);

    rc = ta_vpn_ipsec_build_state(sa, &cmd);
    if (rc != 0)
    {
        te_string_free(&cmd);
        return rc;
    }

    if (ta_system(cmd.ptr) != 0)
    {
        ERROR("Could not add xfrm state (spi %u); is the kernel's IPsec "
              "present?", sa->spi);
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    te_string_free(&cmd);

    return rc;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_ipsec_apply_swanctl(const ta_vpn_ipsec_sa *sa)
{
    te_string conf = TE_STRING_INIT;
    te_string path = TE_STRING_INIT;
    const char *dir = getenv("TMPDIR");
    FILE *f;
    te_errno rc = 0;

    if (dir == NULL)
        dir = "/tmp";

    /*
     * A swanctl connection stanza. This hands the parameters to
     * strongSwan and lets it run IKE, rather than programming the SA by
     * hand - the difference between testing the kernel's crypto and
     * testing a real negotiation. proposals are left to strongSwan's
     * defaults unless the model named an algorithm.
     */
    te_string_append(&conf,
        "connections {\n  %s {\n    local_addrs = %s\n"
        "    remote_addrs = %s\n    children {\n      %s {\n"
        "        mode = %s\n",
        sa->label, sa->local != NULL ? sa->local : "%any",
        sa->remote != NULL ? sa->remote : "%any", sa->label,
        sa->mode[0] != '\0' ? sa->mode : "tunnel");

    if (sa->enc_alg != NULL && sa->enc_alg[0] != '\0')
        te_string_append(&conf, "        esp_proposals = %s\n", sa->enc_alg);

    te_string_append(&conf, "      }\n    }\n  }\n}\n");

    te_string_append(&path, "%s/swanctl-%s.conf", dir, sa->label);

    f = fopen(path.ptr, "w");
    if (f == NULL)
    {
        te_string_free(&conf);
        te_string_free(&path);
        return TE_OS_RC(TE_TA_UNIX, errno);
    }
    fputs(conf.ptr, f);
    fclose(f);

    if (ta_system_fmt("swanctl --load-all --file %s", path.ptr) != 0)
        rc = TE_RC(TE_TA_UNIX, TE_EFAIL);

    te_string_free(&conf);
    te_string_free(&path);

    return rc;
}

/* See description in ta_vpn.h */
te_errno
ta_vpn_ipsec_teardown(const ta_vpn_ipsec_sa *sa)
{
    (void)ta_system_fmt("ip xfrm state delete src %s dst %s proto %s "
                        "spi %u 2>/dev/null",
                        sa->local != NULL ? sa->local : "0.0.0.0",
                        sa->remote != NULL ? sa->remote : "0.0.0.0",
                        sa->proto[0] != '\0' ? sa->proto : "esp", sa->spi);

    return 0;
}

/* See description in ta_vpn.h */
bool
ta_vpn_ipsec_is_up(const ta_vpn_ipsec_sa *sa)
{
    /*
     * The SPI is printed as hex with a 0x prefix in "ip xfrm state".
     * Grepping for it is coarse but true to what the kernel reports,
     * and this is a volatile "is it there" rather than a full readback.
     */
    return ta_system_fmt("ip xfrm state 2>/dev/null | grep -qi 'spi 0x%x'",
                         sa->spi) == 0;
}
