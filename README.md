# tsf-tunnel

VPN tunnels on a Test Agent, packaged as an external Test Environment
(TE) repository.

Libraries:

- `tapi_cfg_vpn` — engine-side TAPI for the `/agent/vpn` Configurator
  subtree (shared library, plus `cm_vpn.yml` installed to `share/cm`);
- `ta_vpn` — agent-side implementation of the subtree, registered via
  `TE_RCF_PCH_CONF_EXT()` so no Test Agent needs modifying.

## The gap it fills

TE already configures **OpenVPN** and **L2TP** as Configurator trees,
and **VXLAN** as a tunnel. What it has never had is the two VPNs that
matter most now and were missing entirely: **WireGuard** and
hand-programmed **IPsec**. This is those two.

## A Configurator tree, applied at the low level

The shape is TE's: a `/agent/vpn` subtree a test drives through the
Configurator, exactly as it drives `/agent/wifi` or `/agent/openvpn`.
What is different is underneath. The subtree is deliberately
**low-level** — a WireGuard private key, a listen port, a peer's
allowed IPs; an IPsec SPI, an encryption algorithm by its *kernel*
name, a raw key — rather than a "connect me to this VPN" abstraction.

That is the point of reaching a VPN from a test: to be able to build it
**wrong on purpose**. A high-level wrapper that only produced valid
configurations could not set up a null-encrypted IPsec SA, or a
WireGuard peer with `AllowedIPs = 0.0.0.0/0` where it should be a single
host, and those are the configurations a security test exists to catch.

By default the agent applies the tree with the kernel's own tools:

- **WireGuard**: `ip link add … type wireguard`, `wg set`, `ip addr`,
  `ip link set up`; state read back from `wg show <if> dump`.
- **IPsec**: `ip xfrm state add …` straight into the kernel — no IKE,
  no daemon, every parameter under the test's control.

## Daemons as an alternative backend

`/agent/vpn/backend` selects how the same tree is applied. Beside
`kernel` there are two daemon modes, for a test that wants a real
implementation rather than the raw primitives:

- `wg-quick` — WireGuard through a written `.conf` and `wg-quick up`;
- `swanctl` — IPsec through strongSwan, which runs an actual IKE
  negotiation rather than a hand-programmed SA.

The model is the same in every case; only the last step changes.

## Keys are made on the agent

`tapi_cfg_vpn_wg_genkey()` asks the agent to generate a WireGuard key
and reads back only the **public** half. The private key is created in
process on the agent with libcrypto's X25519 — not by shelling out to
`wg genkey` — and never crosses to the engine. What comes back is what
a test hands to the far end.

## What was verified

The low-level backend was cross-checked against the real WireGuard
tooling; the Configurator layer was compiled against TE's own
agent-side headers.

- **WireGuard keys — against the `wg` tool.** The in-process X25519
  key generation and public-key derivation were run and compared to
  `wg pubkey`: a key `ta_vpn` generates, and a key `wg genkey`
  generates, derive the **same** public key both ways. WireGuard's own
  clamping is inside X25519, so libcrypto and `wg` agree exactly.
- **`wg show dump` parsing — against the documented tab format.** A
  real-shaped dump parses to the right handshake age and transfer
  counts.
- **The command builders — against the tools' syntax.** `wg set …`
  and `ip xfrm state add …` are generated and inspected, including the
  null-encryption SA (no `enc` clause), which is a real, testable
  misconfiguration the builder is meant to allow.
- **The whole subtree compiles** against TE's `rcfpch`/`agentlib`
  headers — every node, the commit, and the registration constructor —
  and the engine TAPI against `confapi`.

What has **not** been done is applying the tree on a running agent.
The kernel available here has neither the `wireguard` module nor
`xfrm`, so `ip link add type wireguard` and `ip xfrm` could not be run,
and neither could a live commit. The Configurator glue is therefore
compile-verified, not run-verified; the node instance-argument
conventions were mirrored exactly from `tsf-wifi`, which is upstream.
The first rig with a WireGuard-capable kernel should confirm a commit
end to end.

## Usage

```yaml
repositories:
  - name: tsf_tunnel
    url: https://github.com/interpretica-io/tsf-tunnel.git
    ref: <tag>
    libs:
      - tapi_cfg_vpn
      - ta_vpn
```

```
TE_EXT_REPO_USE([tsf_tunnel], [], [tapi_cfg_vpn])
TE_EXT_REPO_USE([tsf_tunnel], [<agent platform>], [])
TE_TA_TYPE([<ta type>], [<agent platform>], [unix],
           [...], [], [], [], [... tapi_cfg_vpn ta_vpn])
```

Requires TE with `TE_EXT_REPO` support. On the agent it needs
`wireguard-tools` and `iproute2`, plus `strongswan` for the `swanctl`
backend — and a kernel with WireGuard and xfrm.
