# Current implementation and next milestones

## Implemented foundation

- C++17 `AOWIS::Network` CMake target and Qt-independent `WireGuardClient` API
- Embedded Go C-archive integration, wireguard-go and gVisor netstack with
  pinned dependencies
- Per-instance loopback SOCKS5 TCP listener with mandatory random credentials
- Remote/in-tunnel DNS, explicit allowed IPs and no OS network privileges
- C++ validation tests and Go protocol/forwarding unit tests
- A self-contained userspace peer-to-peer integration harness (new, awaiting
  execution against the pinned Go dependency cache): encrypted HTTP through
  the SOCKS5 adapter, WireGuard handshake assertions, wrong peer key, proxy
  shutdown/restart, independent tunnel credentials and no OS-host TCP bypass
- Existing repository patch/snapshot mechanics, plus Linux build scripts

## Next work (ordered)

1. **Finish end-to-end qualification:** run the newly added in-process WireGuard
   integration harness on a normal development machine and address any
   failures; then extend with dropped UDP packets, DNS routing, repeated
   teardown, and a C++-to-Go ABI smoke test. The new tests do not require root,
   Docker, a kernel VPN interface, or an external peer.
2. **Qt integration adapter:** configure a dedicated `QNetworkAccessManager`
   with per-server authenticated SOCKS5 settings; verify Qt proxy authentication,
   remote DNS, TLS, cancellation, and pool/reconnect behavior.
3. **GUI integration:** add transport selection to server profiles; ensure
   DVMDB and MAP requests, background health checks and checkout flows all use
   the intended per-server connection manager and fail closed.
4. **Security/lifecycle:** secure key storage, WireGuard `.conf` import,
   handshake status, retries/reconnect, timed shutdown, logging hygiene and
   proxy lifetime ownership; implement meaningful live peer-health signals.
5. **Platforms:** validate Windows and Android cross-builds with CGO and Qt;
   verify app lifecycle and packaging, then integrate Mobile.
6. **Later transports:** a browser/WebAssembly-compatible gateway for clients
   without UDP sockets, and optional server-side embedded WireGuard services.

Do not assert cross-platform support, successful handshakes, or production
security based on the current foundation alone.
