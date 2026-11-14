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
  and fail-closed assertions. The user-reported Qt6 build passed all four
  CTest suites on Linux after enabling this adapter.
- Test-only Go WireGuard peer executable plus native C++/Qt full-stack CTest:
  private HTTP server inside server gVisor, public C++ API and Go C ABI on the
  client, Qt GET/POST through the authenticated SOCKS5 proxy. Tests include
  wrong-key rejection, blocked loopback destinations and stopped-tunnel failure.
  The new complete-path test is implemented but has not yet run in a Qt-enabled
  environment; its execution must be confirmed on the developer's machine.
- `parseWireGuardConf()`: the single AOWIS `.conf` parser, accepting exactly
  the subset the embedded engine runs (one interface address, one peer),
  wg(8)-compatible syntax, warnings for ignored wg-quick host directives,
  value-free line-numbered diagnostics; `aowis-network-wireguard-conf` CTest
  and an ASan/UBSan mutation run. Not yet exercised against the real engine
  with parsed output on the developer's machine.
- Existing repository patch/snapshot mechanics, plus Linux build scripts

## Next work (ordered)

1. **Qualification:** done on Linux (`./tools/qualify_wireguard.sh [runs]`:
   full suite, Go race detector, repeated Go and Qt e2e runs; 10/10 runs each,
   no races). Covered: full-stack Qt flow, cold start/restart, cancellation,
   pooling, reconnect, endpoint re-resolution and in-tunnel DNS (names resolved
   only by the peer's DNS server, `localhost` never reaches the host, no
   resolver without `DNS =`). HTTPS and packet loss are deliberately not
   tested separately: TLS is opaque TCP payload to the tunnel and loss is
   handled by WireGuard/TCP, neither involves AOWIS code.
2. **Repeat qualification per platform** as part of item 5.
3. **GUI integration:** implemented: per-connection transport selection for
   DVMDB and the map server, shared tunnels per profile, fail-closed
   selection, DVMDB and map health checks through the tunnel, and DVMDB
   private checkouts and personal-repository working-copy traffic.
4. **Security/lifecycle:** implemented: handshake/traffic telemetry
   (`WireGuardClient::telemetry()`), peer host-name re-resolution with
   multi-address failover after 135 s without a handshake (as wireguard-tools'
   `reresolve-dns.sh`), and after 15 s of unanswered packets before the first
   handshake; the GUI shares one tunnel per profile and retries
   failed tunnel starts. Open: an idle shutdown policy, only worthwhile once
   consumers stop polling continuously. (Key storage belongs to AOWIS-CONFIG;
   `.conf` parsing is implemented, see below.)
5. **Platforms:** Windows: the engine is cross-built as a C archive
   (`tools/build_wireguard_engine.sh`, Linux Go + MinGW-w64) and linked via
   `AOWIS_NETWORK_WIREGUARD_ARCHIVE` by Standalone's Wine/MinGW build; the
   first runtime check on Windows is open. Then Android CGO and Qt builds,
   lifecycle and packaging, and reuse in Mobile.
6. **Later transports:** browser/WebAssembly-compatible gateway and optional
   server-side embedded WireGuard.

Do not assert cross-platform support, complete Qt integration, or production
security based on the current foundation alone.
