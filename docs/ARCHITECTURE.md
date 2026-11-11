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

## Configuration parsing and storage

`parseWireGuardConf()` (src/wireguard_conf.cpp) is the single WireGuard
`.conf` parser of AOWIS. It defines the supported subset as exactly what
`WireGuardClient` and the Go bridge can run: one interface address, IP DNS
servers, CIDR allowed IPs, `host:port` endpoints, 32-byte base64 keys. Shape
checks happen in C++; netip in the bridge performs the final parse when the
tunnel starts. Unsupported directives are errors rather than silently dropped,
except wg-quick host directives that cannot change the tunnel's meaning
(hooks, routing table, fwmark, listen port), which are warnings and are never
executed.

Storage is not this library's job: AOWIS-CONFIG keeps the original text
verbatim (with keys) in the owning application's private configuration root
and does not parse it. Applications parse on import/edit for diagnostics and
again right before `start()`.

## Current security properties

- No direct fallback: an absent/failed embedded engine returns an error.
- Proxied destinations use **in-tunnel** DNS when DNS servers are supplied.
- The WireGuard public endpoint uses normal host-side DNS and UDP transport.
  A host-name endpoint is resolved at start and again after 135 s without a
  handshake; the peer then moves to the next resolved address (or the new
  one if the name moved). Numeric endpoints are never changed.
- Allowed IPs are applied to the WireGuard peer, not as OS route changes.
- Only authenticated SOCKS5 TCP CONNECT is accepted. SOCKS5 UDP is not
  implemented; an attacker cannot use unauthenticated `NO AUTH` negotiation.
- The local listener binds only to IPv4 loopback; it does not bind a LAN port.
- A successful local proxy start is **not** handshake health. Peer health is
  reported by `WireGuardClient::telemetry()` (last handshake, encrypted
  rx/tx bytes, keepalive, resolved endpoint, SOCKS5 relay counters), sampled
  on demand from wireguard-go's UAPI `get` (`AowisWGTelemetry`). Telemetry is
  redacted: keys and configuration text never cross the ABI.
- Private keys are passed in memory but secure persistent storage and
  zeroization of every runtime copy are **not** implemented yet.
- This tunnel does not replace DVMDB authentication, repository identity
  checking, TLS where applicable, or user authorization.
- Qt clients must configure a SOCKS5 proxy **per network manager**, never with
  `QNetworkProxy::setApplicationProxy()`. Do not reuse proxied Qt clients for
  unrelated direct-server requests.

## Qt HTTP adapter (optional CMake target)

`AOWIS::NetworkQt` wraps a **private** `QNetworkAccessManager` behind
`QtSocks5HttpClient`. It is configured per service origin (scheme/host/port),
not via `QNetworkProxy::setApplicationProxy`. The adapter accepts
`WireGuardClient::proxy()` only after the tunnel has started; an unavailable
proxy produces failed replies. It checks each requested URL and enforces
`QNetworkRequest::ManualRedirectPolicy` before using Qt's network manager.

Only the intended service origin may be requested. Qt's documented proxy
bypass for loopback destinations is handled by refusing loopback/wildcard
service addresses, rather than assuming `setProxy()` overrides Qt's socket
behavior. The SOCKS5 proxy has `HostNameLookupCapability`, so service names
can be resolved inside the tunnel instead of via local OS DNS. Both the
outer WireGuard peer's UDP endpoint and local SOCKS5 listener remain handled
by the host network stack, as intended. HTTPS still uses Qt's TLS checks.

A tunnel and its Qt client must be managed together: create the Qt adapter
after tunnel startup, destroy the adapter and its replies before stopping the
tunnel, and recreate the adapter after restart. The adapter does not presently
own the tunnel or report real peer reachability. An HTTP redirect is returned
to the caller and must be processed manually; no implicit redirect follows a
URL outside the service's origin.

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

The additional Qt-to-real-WireGuard test uses a **test-only Go executable**
(`bridge/testpeer`) with its own ephemeral loopback UDP listener and an HTTP
server reachable exclusively over the server's in-memory gVisor netstack.
The C++ test launches that server through Qt `QProcess`, generates a client
through the ordinary `WireGuardClient`/Go C ABI, and issues Qt HTTP GET/POST
through the real authenticated SOCKS5 proxy. It also confirms wrong-key
failure, origin blocking, and stopped-proxy failure. The test peer is never a
runtime dependency for the application and is not installed as a production
server. This test remains distinct from interoperability, TLS, IPv6 and
cross-platform tests.

At present the native implementation targets Linux development. Windows and
Android are intended downstream targets, but their cross toolchains and CGO
linkage are not yet qualified; browser/WASM requires a different transport.

## Non-goals of the transport library

Do not embed application protocols (DVMDB working-copy semantics, map tile
lookup, renderer image processing, server database models) into this library.
Keep server-specific policies in the callers and transport-neutral
communication/credentials in AOWIS-NETWORK.
