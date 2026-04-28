# Xray-core (VLESS L3 / VPN fork)

[English](./README.md) · [Русский](./README.ru.md)

This is a soft fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core) that turns the VLESS protocol from a stream proxy into a real Layer-3 VPN. Connected clients get a virtual IP inside a configurable subnet, can address the server's host services through the gateway IP, and can reach each other peer-to-peer. The fork keeps the rest of Xray-core (REALITY, XHTTP, XUDP, routing, sniffing, balancers, etc.) byte-compatible with upstream — you can run a stock VLESS-REALITY setup on this build with no behavioural change.

> **Status: testing.** Releases are tagged `v0.0.x-test` while the protocol additions and the wire format are stabilised. It is safe to deploy alongside non-VPN VLESS clients on the same inbound, but please don't pin production users to a specific test release yet.

## What this fork adds

| | Upstream Xray-core | This fork |
|---|---|---|
| VLESS as a stream proxy (TCP / UDP per connection) | ✓ | ✓ |
| Per-client virtual IPv4 inside a subnet | — | ✓ |
| Kernel TUN interface on the client (Linux / Darwin) | — | ✓ |
| `ping` / ICMP across the tunnel | — | ✓ |
| Peer-to-peer between connected clients (10.0.0.x ↔ 10.0.0.y) | — | ✓ |
| Reach VPS host services via the gateway IP (`curl http://10.0.0.1:port`) | — | ✓ |
| `inbound.Tag` propagated to L3 sub-flows so `inboundTag:` routing rules work | — | ✓ |

The user-visible config is a single optional `virtualNetwork` block on the VLESS inbound (server side) and on the VLESS outbound (client side). When the block is absent, VLESS behaves exactly like upstream.

## How it works (one-paragraph version)

When a client connects, it sends an extended VLESS request carrying the user's UUID. The server's IPAM assigns or recalls a virtual IPv4 from the configured subnet for that UUID, replies with a 4-byte preamble carrying `(assigned_ip, gateway_ip, prefix_len)`, and from then on both sides exchange raw IPv4 packets over the same VLESS stream using a 2-byte length prefix. Server-side, packets enter a [gVisor](https://github.com/google/gvisor) userspace netstack: TCP/UDP destined to peer addresses is forwarded directly between client streams, and TCP/UDP destined to the gateway is rewritten to loopback and dispatched through the normal Xray outbound chain (so routing rules, freedom, blackhole, `domain:` rules, etc. all keep working). Client-side, on Linux and macOS the outbound creates a kernel TUN interface (`xray0` by default), assigns the virtual IP, and bridges it 1:1 with the framed VLESS stream.

## Server-side example

Add the `virtualNetwork` block to your VLESS inbound:

```jsonc
{
  "inbounds": [
    {
      "tag": "inbound-443",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "11111111-1111-1111-1111-111111111111", "email": "alice" },
          { "id": "22222222-2222-2222-2222-222222222222", "email": "bob"   }
        ],
        "decryption": "none",
        "virtualNetwork": {
          "enabled": true,
          "subnet": "10.0.0.0/24",
          "persistMapping": true
        }
      },
      "streamSettings": { /* REALITY / XHTTP / etc. — unchanged */ }
    }
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch. When `false` the inbound behaves exactly like upstream VLESS. |
| `subnet` | `10.0.0.0/24` | IPv4 subnet handed out by the IPAM. The first usable address is the gateway. |
| `persistMapping` | `true` | Persist `UUID → virtual IP` mappings across restarts so the same client always gets the same IP. |

The gateway IP (e.g. `10.0.0.1` for `10.0.0.0/24`) is reserved by the gVisor netstack. Connections to the gateway IP are rewritten to `127.0.0.1` on the host so they reach services bound on `0.0.0.0` or loopback. Connections to other addresses inside the subnet are matched against the IPAM and forwarded into the owning client's stream (peer-to-peer); connections to addresses outside the subnet are dispatched through the normal Xray outbound chain (routing rules, freedom, blackhole, …).

## Client-side example (Linux / macOS)

The client outbound creates a kernel TUN device. **You need root** (or `cap_net_admin`).

```jsonc
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "vps.example.com",
          "port":    443,
          "users": [{
            "id":         "11111111-1111-1111-1111-111111111111",
            "encryption": "none",
            "flow":       ""
          }]
        }],
        "virtualNetwork": {
          "enabled":       true,
          "subnet":        "10.0.0.0/24",
          "interfaceName": "xray0",
          "mtu":           1420,
          "defaultRoute":  true
        }
      },
      "streamSettings": { /* REALITY / XHTTP / etc. */ }
    }
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch. When `false` the outbound behaves exactly like upstream VLESS. |
| `subnet` | `10.0.0.0/24` | Must match the server. |
| `interfaceName` | `xray0` | Name of the kernel TUN device created on the host. |
| `mtu` | `1420` | TUN MTU. The default leaves headroom for the VLESS / TLS / IP layers below. |
| `defaultRoute` | `true` | When `true`, the outbound rewrites the host's default route through the TUN, i.e. **all** traffic goes through the tunnel. Set to `false` for split-tunnel — only the subnet is routed through the TUN, the rest of the host's traffic stays on its existing default route. |

After `xray run`, the host should have:

```
$ ip addr show xray0
xray0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>
    inet 10.0.0.45/24 scope global xray0

$ ping 10.0.0.1                # gateway (server's gVisor stack)
$ curl http://10.0.0.1:8080    # VPS host service listening on 0.0.0.0:8080
$ ping 10.0.0.46               # another connected client (peer-to-peer)
$ curl https://example.com     # only when defaultRoute=true
```

## `vless://` link extensions

The fork's `vless://` URI parser recognises three extra query parameters so a single share-link can carry the VPN config:

| Param | Meaning |
|---|---|
| `vnet=1` | Enable `virtualNetwork` on the outbound. |
| `vnetSubnet=10.0.0.0/24` | Override `subnet`. URL-encode the slash as `%2F`. |
| `vnetDefaultRoute=1` / `vnetDefaultRoute=0` | Override `defaultRoute`. |

A complete share link looks like:

```
vless://<uuid>@vps.example.com:443?type=tcp&security=reality&pbk=...&fp=chrome&sni=...&sid=...&spx=%2F&vnet=1&vnetSubnet=10.0.0.0%2F24&vnetDefaultRoute=1#vps
```

Clients that don't understand the new params silently ignore them and behave as a stock VLESS proxy.

## 3x-ui companion fork

For a panel that exposes the new fields in the UI (per-inbound `virtualNetwork` toggle, subnet editor, share-link generator that emits the `vnet*` params), use the companion 3x-ui fork:

- https://github.com/sevaktigranyan305-netizen/3x-ui

It bundles a matching Xray-core binary in every release tarball, so `x-ui update` on the server upgrades both the panel and the core in one step.

## Routing rules

L3 sub-flows surface in the Xray dispatcher with three pieces of context that routing rules can match on:

- `sourceIP` — the client's virtual IP (e.g. `10.0.0.42`).
- `inboundTag` — the original VLESS inbound's tag, propagated from the parent connection.
- `domain` (when sniffing fires) — sniffed from HTTP/TLS like any other inbound.

That means rules like `{"inboundTag":["inbound-443"], "domain":["geosite:cn"], "outboundTag":"direct"}` keep working for tunnel traffic exactly as they do for stock VLESS. Sniffing on L3 sub-flows runs in `RouteOnly` mode — sniffed domains feed the routing engine but never override the dispatch destination, so the gateway-IP rewrite and the peer-to-peer fast path stay intact.

## Building

The build is unchanged from upstream:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid=" -v ./main
```

Reproducible / cross-platform builds, the Windows PowerShell variant, and the 32-bit MIPS gotcha are all the same as in upstream — see the upstream [Xray-core README](https://github.com/XTLS/Xray-core#one-line-compilation) for the full set.

Pre-built binaries for every test tag are attached to each [release](https://github.com/sevaktigranyan305-netizen/Xray-core/releases) (Linux / macOS / Windows / FreeBSD / Android — amd64, arm64, 386, arm, mips, mipsle, riscv64, etc., 22 assets total).

## Compatibility & limitations

- **Server platforms:** any platform Xray-core itself supports — the server side is gVisor-only and never touches the kernel.
- **Client platforms:** kernel TUN works on Linux and macOS (Darwin). Windows / Android / iOS clients can still connect, but currently bring up the TUN through their own platform glue (e.g. the platform's VPN service for Android) — refer to your client's documentation.
- **IPv6:** the virtual subnet is IPv4-only. The underlying VLESS transport (the TLS / REALITY / XHTTP layer) can run on either v4 or v6.
- **NAT / port-forwarding from the public internet to a peer:** out of scope. Peers can talk to each other and to the server's host; they're not reachable from the public internet unless you publish them yourself.
- **`vless://` URI extensions** (`vnet`, `vnetSubnet`, `vnetDefaultRoute`) are a fork-local convention; share-links generated here are still valid stock VLESS links for clients that don't support the VPN mode.

## Credits

- Upstream [Xray-core](https://github.com/XTLS/Xray-core) — everything except the `proxy/vless/virtualnet/` package and the small dispatch-glue patches in `proxy/vless/inbound`, `proxy/vless/outbound`, and `infra/conf` is upstream Xray-core, MPL-2.0.
- [gVisor](https://github.com/google/gvisor) — the userspace netstack that powers the server side.
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) — the kernel TUN device wrapper used on the client side.

## License

[Mozilla Public License 2.0](./LICENSE) — same as upstream Xray-core.
