# AOWIS-NETWORK architecture and security

## Layers and ownership

```text
AOWIS client / service (Qt optional)
   |  one connection manager / server profile
   v
C++ WireGuardClient  ----  narrow, synchronous C ABI
                               |
                          Go runtime (embedded C archive)
                               |
                         loopback TCP SOCKS5
                               |
                        gVisor userspace TCP/IP
                               |
                         wireguard-go device
                               |
                   OS UDP socket -> remote peer
```

The SOCKS5 listener is started **inside the same process**, not as a child
process, and is used to bridge ordinary OS-backed clients into the in-memory
TCP/IP stack. Nothing creates OS TUN/TAP interfaces, global proxies, or routes.
The gVisor integration is provided by upstream wireguard-go's `tun/netstack`.

`WireGuardClient::start()` validates basic C++ parameters, calls the Go engine,
initializes an in-memory netstack and one WireGuard device, and allocates an
**ephemeral** TCP listener on `127.0.0.1:0` (OS-assigned local port). Each
instance obtains independent, random, high-entropy SOCKS5 username/password
credentials. `stop()` closes the listener, both halves of forwarded streams,
and the WireGuard device. Destruction calls `stop()`.

The Go boundary exposes no pointers to Go objects: the C ABI takes copied
configuration strings and returns an opaque integer handle, loopback port and
credentials. The C++ type owns that handle and cannot be copied or moved.
Each server profile should have an independent `WireGuardClient`, even when
multiple profiles share a WireGuard peer.

## Current security properties

- No direct fallback: an absent/failed embedded engine returns an error.
- Proxied destinations use **in-tunnel** DNS when DNS servers are supplied.
- The WireGuard public endpoint uses normal host-side DNS and UDP transport.
- Allowed IPs are applied to the WireGuard peer, not as OS route changes.
- Only authenticated SOCKS5 TCP CONNECT is accepted. SOCKS5 UDP is not
  implemented; an attacker cannot use unauthenticated `NO AUTH` negotiation.
- The local listener binds only to IPv4 loopback; it does not bind a LAN port.
- A successful local proxy start is **not** handshake health. Do not display
  `connected` in the GUI until actual peer/session health is implemented.
- Private keys are passed in memory but secure persistent storage and
  zeroization of every runtime copy are **not** implemented yet.
- This tunnel does not replace DVMDB authentication, repository identity
  checking, TLS where applicable, or user authorization.
- Qt clients must configure a SOCKS5 proxy **per network manager**, never with
  `QNetworkProxy::setApplicationProxy()`. Do not reuse proxied Qt clients for
  unrelated direct-server requests.

## Build dependencies

`bridge/go.mod` pins `golang.zx2c4.com/wireguard` to a specific upstream commit,
and its dependency graph pins `gvisor.dev/gvisor`. `bridge/go.sum` records
module checksums; the build uses `go build -mod=readonly` and requires cgo.
The Go static archive is a **build output**, not checked into the repository.
The build links one Go runtime into native consumers of `aowis-network`.

A dedicated in-process peer test exercises the actual encrypted data path:
client SOCKS5 -> gVisor TCP -> wireguard-go UDP -> independent server
wireguard-go -> server gVisor HTTP, with no OS VPN interface. It is a
repeatable local harness, **not** proof of interoperability with an external
OS WireGuard server; that remains a separate qualification task.

At present the native implementation targets Linux development. Windows and
Android are intended downstream targets, but their cross toolchains and CGO
linkage are not yet qualified; browser/WASM requires a different transport.

## Non-goals of the transport library

Do not embed application protocols (DVMDB working-copy semantics, map tile
lookup, renderer image processing, server database models) into this library.
Keep server-specific policies in the callers and transport-neutral
communication/credentials in AOWIS-NETWORK.
