# Current implementation and next milestones

## Implemented foundation

- C++17 `AOWIS::Network` CMake target and Qt-independent `WireGuardClient` API
- Embedded Go C-archive integration, wireguard-go and gVisor netstack with
  pinned dependencies
- Per-instance loopback SOCKS5 TCP listener with mandatory random credentials
- Remote/in-tunnel DNS, explicit allowed IPs and no OS network privileges
- C++ validation tests and Go protocol/forwarding unit tests
- A self-contained userspace peer-to-peer integration harness: encrypted HTTP
  through the SOCKS5 adapter, WireGuard handshake assertions, wrong peer key,
  proxy shutdown/restart, independent tunnel credentials and no OS-host TCP bypass.
  All 40 scenarios passed in 10 consecutive Linux runs after the diagnostic
  timeout adjustment. Phase timings localized occasional ~5.2-second reconnects
  to SOCKS5 CONNECT *after* rapid same-key peer restart (not first HTTP or
  shutdown). wireguard-go enforces a 20 ms per-peer handshake-initiation rate
  limit, consistent with the observed first-initiation drop and ~5-second
  retransmission. The normal restart test now stays outside that window; an
  additional immediate-restart test covers the expected retry behavior.
  The subsequent run completed 3/3 CTest groups and 10 repetitions each of
  the normal and immediate-restart scenarios (20/20). Normal restarts finished
  in milliseconds; one immediate restart took 5.198 seconds before SOCKS5
  CONNECT, consistent with the upstream handshake retry timer. This strongly
  supports the rate-limit explanation but is not an instrumented WireGuard
  packet-level proof.
- Optional `AOWIS::NetworkQt` adapter for HTTP requests through authenticated
  SOCKS5; a dedicated private `QNetworkAccessManager` per service origin,
  explicit request guard, manual redirects and remote SOCKS5 DNS. Qt test
  harness uses a fake SOCKS5 endpoint for authentication, method forwarding
  and fail-closed assertions. Full Qt test execution awaits a Qt-enabled build.
- Existing repository patch/snapshot mechanics, plus Linux build scripts

## Next work (ordered)

1. **Qt adapter qualification:** run `aowis-network-qt-http` on Linux with
   Qt 6, then add a C++/Qt-to-real-WireGuard peer smoke test and verify HTTPS,
   cancellation, pooling and reconnect behavior. Stage 3 adapter introduced,
   but the sandbox has no Qt6 headers/libraries to compile its Qt target.
2. **Additional tunnel qualification:** dropped UDP packets, DNS routing,
   repeated teardown and C++/Go ABI integration checks; don't change
   upstream WireGuard handshake timers or mask rapid-restart retransmissions.
3. **GUI integration:** add per-server transport selection, wire the DVMDB and
   MAP clients, background health and checkout flows into the correct adapter,
   and enforce fail-closed transport selection.
4. **Security/lifecycle:** secure key storage, WireGuard `.conf` import,
   handshake status, retries/reconnect, timed shutdown, logging hygiene and
   proxy lifetime ownership; implement meaningful peer-health signals.
5. **Platforms:** qualify Windows and Android CGO and Qt builds, lifecycle and
   packaging, then reuse the library in Mobile.
6. **Later transports:** browser/WebAssembly-compatible gateway and optional
   server-side embedded WireGuard.

Do not assert cross-platform support, complete Qt integration, or production
security based on the current foundation alone.
