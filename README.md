# AOWIS-NETWORK

Shared, application-embedded network transport for AOWIS native clients and
services. **Current capability:** one independent userspace WireGuard tunnel per
`aowis::network::WireGuardClient`, with a per-tunnel authenticated SOCKS5 TCP
proxy on `127.0.0.1` and no OS VPN interface or privileged network setup.

The engine uses [wireguard-go](https://github.com/WireGuard/wireguard-go) and
its existing [gVisor netstack](https://gvisor.dev/docs/architecture_guide/networking/)
integration. It is linked into the application as a Go **C archive** through a
small C ABI. No Go child process, wireproxy executable or kernel TUN/TAP device is used.
The core library has no Qt dependency; the Qt HTTP adapter is a separate
optional target.

**Current scope is a foundation, not a GUI feature.** AOWIS GUI and Mobile are
not integrated yet; the tunnel has no UI, `.conf` importer, secure key store,
handshake-health reporting, or automatic reconnect policy. SOCKS5 supports
TCP CONNECT only. Browser/WebAssembly builds are not supported by this engine.

## Build and test (Linux)

Requires CMake >= 3.23, Ninja, C++17, a C toolchain, CGO-enabled Go >= 1.23.1,
and network access **on first build** to fetch pinned Go dependencies.
`bridge/go.mod` and `bridge/go.sum` pin/check module content. Go modules are
fetched into the usual Go module cache, not vendored into this repository.

```bash
./compile_linux.sh
./compile_linux_tests.sh
```

With WireGuard enabled, CTest now executes three test groups: the C++ API
checks, SOCKS5 protocol tests, and **a real userspace WireGuard-to-WireGuard
loopback UDP integration suite**. The integration suite creates two independent
in-process peers and a private HTTP service reachable only via the in-memory
netstack, and checks encrypted HTTP, handshake records, wrong-key rejection,
proxy shutdown/restart, per-tunnel credential isolation, and rejection of
accidental direct access to an OS-only HTTP listener. It needs loopback
TCP and UDP sockets but no admin rights, Docker, external VPN server, or
privileged network interface. The tests must run successfully on a system with
the pinned Go dependencies present before this milestone is considered verified.
After diagnostic runs, the initial encrypted HTTP connection was fast (4–34 ms),
while a same-key client restart sometimes took ~5.2 seconds at SOCKS5 CONNECT.
This aligns with wireguard-go's **20 ms per-peer handshake-initiation flood
limit**: the server may discard a rapid second initiation, and the client then
retries on WireGuard's normal ~5-second handshake timer. The regular restart
scenario now waits a bounded 30 ms after shutdown to avoid that intentional
flood-protection window; an **additional immediate-restart test** keeps the
no-wait scenario and confirms it still succeeds via the tunnel, even if a
handshake retransmission is required. This does not change wireguard-go's
protocol security limits or production session start/stop behavior.

Failures report SOCKS/HTTP progress, redacted peer handshake/traffic counters,
server handler count, and a diagnostic HTTP request made **through gVisor**,
not through host networking. No failure authorizes direct-network fallback.

To rerun only the actual WireGuard end-to-end tests:

```bash
ctest --test-dir build-linux-tests --output-on-failure \
  -R '^aowis-network-wireguard-e2e$'
```

For offline development of the C++ interface **only**, explicitly disable the
Go engine (the resulting library cannot establish any tunnel and fails closed):

```bash
cmake -S . -B build-cpp-only -G Ninja \
  -DAOWIS_NETWORK_WITH_WIREGUARD=OFF -DBUILD_TESTING=ON
cmake --build build-cpp-only
ctest --test-dir build-cpp-only --output-on-failure
```

## Optional Qt HTTP transport (Stage 3)

Qt 6 Network is detected automatically by CMake. When present the additional
`AOWIS::NetworkQt` target is built, with a separate `aowis-network-qt-http`
CTest test. The WireGuard engine (`AOWIS::Network`) itself **does not depend
on Qt**. To require Qt explicitly, configure with
`-DAOWIS_NETWORK_WITH_QT=ON`; to disable it use `=OFF` (default `AUTO`).

The companion `QtSocks5HttpClient` owns one private `QNetworkAccessManager`
configured for the **authenticated** SOCKS5 listener from a running tunnel.
It supports GET, HEAD, POST, PUT, DELETE and custom HTTP methods. Requests are
restricted to the configured HTTP(S) **scheme, hostname and effective port**;
invalid/other destinations fail asynchronously without opening a network
connection. Loopback and wildcard service addresses are rejected because Qt
can bypass proxies for local addresses. This intentionally means a service
configured as `localhost` is **not supported** by the Qt adapter even if the
remote peer's service uses loopback. Use a private tunnel IP or hostname.

HTTP redirects are always manual, even if the caller supplies a different
redirect policy. The caller may follow an approved redirect by issuing a new
request through the adapter; cross-endpoint redirects fail closed. DNS names
are supplied to the SOCKS5 endpoint for in-tunnel DNS resolution. TLS requests
continue to use Qt's normal certificate verification. A configured local
proxy is **not** evidence of a completed WireGuard handshake.

```cpp
#include "aowis/network/qt_http_client.h"

// After aowis::network::WireGuardClient::start(config) succeeds:
aowis::network::QtSocks5HttpClient http(
    tunnel.proxy(), QUrl("http://10.30.0.1:8080"));
if (!http.isConfigured()) {
    // Handle http.configurationError(); do not try a direct request.
}
QNetworkReply* reply = http.get(
    QNetworkRequest(QUrl("http://10.30.0.1:8080/health")));
// Observe reply->finished() / reply->errorOccurred(), then deleteLater().
```

Construct the adapter **after** starting the tunnel; destroy the adapter and
its outstanding replies **before** stopping/restarting it. Recreate the adapter
after restart because SOCKS credentials and port are regenerated. Do not
expose a raw `QNetworkAccessManager` with mutable proxy settings in the GUI.

The Qt unit test uses a simulated authenticated SOCKS5 server to exercise
proxy-side hostname forwarding, HTTP requests, wrong credentials, destination
blocking and manual redirects. These tests are distinct from the Go real-peer
encrypted HTTP tests. A complete **Qt-to-real-WireGuard** test, TLS test and
cross-platform validation are future tasks.

## C++ integration

Include `aowis/network/wireguard_client.h`; link `AOWIS::Network` via
`add_subdirectory()` or the `aowis-network` CMake target. Qt is **not** required
by the library. Example:

```cpp
#include "aowis/network/wireguard_client.h"

aowis::network::WireGuardClient tunnel;
aowis::network::WireGuardConfig config;
config.address = "10.30.0.2/32";
config.privateKey = privateKeyFromSecureStorage;
config.peerPublicKey = serverPublicKey;
config.endpoint = "vpn.example.com:51820";
config.allowedIPs = {"10.30.0.0/24"};
std::string error;
if (!tunnel.start(config, &error)) {
    // Do NOT fall back to a direct HTTP connection.
}
// tunnel.proxy() supplies a loopback address, port, username and password.
// Attach them to ONLY this server's HTTP client's SOCKS5 proxy settings.
// Keep tunnel alive for the lifetime of that HTTP client.
```

Calling `start()` successfully means the loopback listener is ready; it does
**not** establish that the remote peer has completed a WireGuard handshake.
A tunnel-dependent request fails when the peer is unreachable; it must never
be retried via a direct connection unless the user explicitly changes transport.

The SOCKS5 listener **always requires random per-instance credentials** and
binds only to IPv4 loopback. Domain names are resolved by gVisor's in-tunnel
DNS, not the OS resolver, for proxied connections. The **public WireGuard peer
endpoint hostname** is resolved by the host networking stack, as expected.
For domain-name services inside the tunnel configure an in-tunnel DNS server;
for an IP-literal service address this is unnecessary.

See [architecture and security](docs/ARCHITECTURE.md) and
[current roadmap](docs/ROADMAP.md).

## Source snapshots and patch ZIPs

The repository uses the same patch workflow as AOWIS-GUI:

```bash
# From AOWIS-NETWORK checkout:
./tools/zip_network_project.sh
# Creates ../network.zip (full source snapshot, excluding .git and build outputs).

./tools/apply_patch.sh ~/Downloads/aowis-network-example.zip
# Applies patch, refreshes mtimes and rebuilds ../network.zip.
```

Patch archives must be named `aowis-network-*.zip` and contain only added or
modified files under the `AOWIS-NETWORK/` root. Optional deletions go into
`AOWIS-NETWORK/.aowis-patch-delete.txt`, one repository-relative file per line.
The patch tool validates paths and archive integrity before writing, refuses
symlink traversal and preserves executable permissions. Required tools:
Bash, `python3`, `zip`, and basic Linux utilities.
