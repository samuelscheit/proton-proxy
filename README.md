# Proton multi-tunnel HTTP CONNECT proxy

This service exposes an HTTP CONNECT proxy whose outbound TCP connections are
sent through one or more ProtonVPN **OpenVPN or WireGuard** profiles. It is
designed for multiple connections in one container/network namespace without
letting their routes bleed into each other.

## What multi-tunnel mode does

Place downloaded Proton `.ovpn` (OpenVPN) or `.conf` (WireGuard) files in
`ovpn_configs/` and start the container with `MAX_CONNECTIONS` set to the
number of profiles to use (or `0`, the default, to use all of them). The
service then starts all selected tunnel workers concurrently:

| Endpoint | Behavior |
| --- | --- |
| `http://host:8100` | Selects a healthy tunnel by the optional `proton-session` proxy-auth token; callers without one are distributed round-robin. |
| `http://host:8101` | Pins requests to the first selected profile (`tun0` or `wg0`). |
| `http://host:8102` | Pins requests to the second selected profile (`tun1` or `wg1`). |
| `…` | One subsequent listener per selected profile. |

`BASE_PROXY_PORT` changes `8100`; `PORT_GAP` changes the interval between the
rotating listener and per-tunnel listeners.

The rotating listener supports sticky sessions without exposing tunnel state:
send `Proxy-Authorization: Basic <base64(proton-session:<64-hex-token>)>` on
each CONNECT request. The same token is rendezvous-hashed to the same healthy
tunnel, so a chat/session can keep one VPN exit across multiple connections.
If that tunnel is unavailable, the token is remapped to another healthy tunnel;
once it returns, normal rendezvous selection restores the original mapping.
Credentials with any other username are ignored, and the token is never logged.
When a gateway request with a valid session token reaches a fixed-profile
listener whose profile is temporarily unavailable, the listener remaps that
request to a healthy tunnel deterministically. Unauthenticated fixed-listener
requests retain strict pinning and receive `503` until that profile is ready.

### Isolation model

Opening several VPN interfaces alone is **not** sufficient: a normal socket
can still follow the container's default route. For each tunnel, this service
creates a private Linux policy-routing table and a unique fwmark. The native
dialer then applies all of the following to every outbound socket before it
connects:

1. `SO_BINDTODEVICE=tunN` (OpenVPN) or `wgN` (WireGuard)
2. the tunnel-specific `SO_MARK`
3. a local bind to the IPv4 address assigned to that interface

The marked socket therefore resolves through only its matching policy-routing
table. The global/default route remains untouched. If the required interface,
route, mark, or source address cannot be used, the connection fails closed;
there is no direct-route fallback.

## Prerequisites

- Docker / Docker Compose
- A ProtonVPN account and downloaded profiles from the
  [Proton downloads page](https://account.protonvpn.com/downloads)
- `NET_ADMIN` and `/dev/net/tun` access in the container

WireGuard profiles additionally require the Linux WireGuard kernel module on
the Docker host. The image includes `wireguard-tools`; it does not install a
kernel module inside the container.

`PVPN_USERNAME` and `PVPN_PASSWORD` are ProtonVPN OpenVPN/IKEv2 credentials,
not your normal Proton account login. `PROTON_USERNAME` and `PROTON_PASSWORD`
are only needed to automatically reset an expired OpenVPN credential pair.

## Quick start

```bash
git clone https://github.com/samuelscheit/proton-proxy
cd proton-proxy
cp .env.example.txt .env
mkdir -p ovpn_configs
find ~/Downloads -maxdepth 1 -type f \( -name '*.ovpn' -o -name '*.conf' \) -exec cp {} ovpn_configs/ \;
# Set PVPN_USERNAME and PVPN_PASSWORD in .env when using OpenVPN profiles.
# Set MAX_CONNECTIONS=3 to use three profiles, for example.
docker compose up --build
```

The bundled compose file publishes `8100-8200`. Do not publish the sidecar
ports when it is used from another service on the same Docker network; use its
internal DNS name instead.

## Runtime settings

| Variable | Default | Meaning |
| --- | ---: | --- |
| `MAX_CONNECTIONS` | `0` | Maximum selected `.ovpn`/WireGuard `.conf` files; `0` uses every profile. |
| `BASE_PROXY_PORT` | `8100` | Rotating HTTP CONNECT listener. |
| `PORT_GAP` | `1` | Port increment for individual tunnel listeners. |
| `CONNECT_TIMEOUT_MS` | `30000` | Per-outbound-connect timeout. |
| `TUN_IP_WAIT_MS` | `30000` | How long to wait for an OpenVPN interface IPv4 assignment. |
| `STARTUP_TIMEOUT_MS` | `120000` | How long startup waits for at least one healthy tunnel. |
| `REQUIRE_TUN_IP` | `true` | Refuse to serve a tunnel until it has an IPv4 address. Keep enabled. |
| `RESET_CREDENTIALS_ON_START` | `false` | Explicitly reset the shared Proton OpenVPN credential pair at boot. Normally leave disabled. |
| `ROUTING_TABLE_BASE` | `10000` | First private Linux routing table ID. |
| `ROUTING_MARK_BASE` | `5898240` | First socket fwmark (`0x5a0000`). |
| `ROUTING_RULE_PRIORITY_BASE` | `12000` | First policy-rule priority. |

A Proton credential reset invalidates the account-wide OpenVPN credential pair.
When `AUTH_FAILED` occurs, the service coalesces concurrent failures into one
reset and restarts all active OpenVPN workers with the replacement pair.
WireGuard profiles authenticate with their embedded keys and do not use the
OpenVPN credential variables. Proton may enforce a plan-specific
simultaneous-connection limit. Profiles over that limit keep retrying
independently; they never share another profile's route or fall back to the
host's default route.

### WireGuard profiles

Proton's WireGuard downloads are INI-style `.conf` files containing
`[Interface]`/`[Peer]`, `PrivateKey`, `Address`, `AllowedIPs`, and `Endpoint`.
They are not OpenVPN files and must not be renamed to `.ovpn`. The proxy
recognizes them by their contents, creates isolated `wg0`, `wg1`, … interfaces,
and assigns each a private policy-routing table. The profile's IPv4 `Address`,
`MTU`, and peer directives are applied without running any
`PostUp`/`PostDown` shell hooks; `DNS` is deliberately not allowed to replace
the container resolver.
The WireGuard transport mark is kept at zero so encrypted UDP handshakes use
the container's normal host route while marked application sockets use only
their selected tunnel table. IPv6 routes are not used by the HTTP dialer yet;
IPv4 destinations are fail-closed when no tunnel is ready.

The Docker host must load the WireGuard kernel module and the service must have
`NET_ADMIN` plus `/dev/net/tun`, for example:

```bash
sudo modprobe wireguard
docker compose --profile proton up --build
```

## Operational notes

- Only IPv4 destinations are supported by the tunnel dialer. Destination
  hostnames are resolved to IPv4 before the socket is opened.
- The proxy buffers up to 64 KiB while waiting for a complete HTTP header.
  This handles TCP-fragmented CONNECT requests correctly.
- A rotating-port request made before any tunnel is healthy receives HTTP 503;
  it is never forwarded directly.
- Per-tunnel ports are useful for diagnostics. Use the rotating port for normal
  request distribution.
