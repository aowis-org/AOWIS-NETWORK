#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aowis::network {

// One private tunnel and one authenticated loopback SOCKS5 listener per instance.
// No OS VPN interface, route changes, privileges, or subprocesses are required.
struct WireGuardConfig {
    std::string address;                         // E.g. 10.50.0.2/32
    std::vector<std::string> dnsServers;          // Optional DNS servers inside tunnel
    std::string privateKey;                      // WireGuard base64, never log
    std::string peerPublicKey;                   // WireGuard base64
    std::string preSharedKey;                    // Optional WireGuard base64
    std::string endpoint;                        // Public host:UDP port of peer
    std::vector<std::string> allowedIPs;          // E.g. 10.50.0.0/24
    int persistentKeepaliveSeconds = 25;          // 0 disables
    int mtu = 1420;
};

// Pass to a per-connection SOCKS5-aware HTTP client. Never configure this as
// a process-global proxy: unrelated AOWIS traffic must not enter this tunnel.
struct Socks5Proxy {
    std::string host = "127.0.0.1";
    std::uint16_t port = 0;
    std::string username;
    std::string password;
};

// Redacted runtime state of one running tunnel, sampled on demand from the
// embedded engine. Contains no keys or configuration text. Timestamps are
// Unix epoch milliseconds (wall clock).
struct WireGuardTelemetry {
    std::int64_t startedUnixMs = 0;               // Local engine start
    std::int64_t lastHandshakeUnixMs = 0;         // 0: no handshake completed yet
    std::uint64_t receivedBytes = 0;              // Encrypted UDP payload from peer
    std::uint64_t sentBytes = 0;                  // Encrypted UDP payload to peer
    std::uint64_t persistentKeepaliveSeconds = 0; // 0: disabled
    std::uint64_t activeProxyConnections = 0;     // Relays currently open
    std::uint64_t acceptedProxyConnections = 0;   // Authenticated CONNECT requests
    std::uint64_t failedProxyDials = 0;           // In-tunnel dials that failed
    std::string peerEndpoint;                     // Resolved numeric host:port
};

class WireGuardClient final {
public:
    WireGuardClient() = default;
    ~WireGuardClient();

    WireGuardClient(const WireGuardClient&) = delete;
    WireGuardClient& operator=(const WireGuardClient&) = delete;
    WireGuardClient(WireGuardClient&&) = delete;
    WireGuardClient& operator=(WireGuardClient&&) = delete;

    // Starts the embedded engine; success means the local proxy is listening,
    // NOT that a remote WireGuard handshake has occurred.
    bool start(const WireGuardConfig& config, std::string* error = nullptr);
    void stop();
    bool isRunning() const;
    Socks5Proxy proxy() const;
    // Samples the running engine. Returns false (and leaves *out untouched)
    // when the tunnel is not running or the engine cannot report. Cheap
    // enough for once-per-second polling; safe concurrently with proxied
    // traffic, but not with start()/stop() on the same instance.
    bool telemetry(WireGuardTelemetry* out, std::string* error = nullptr) const;

private:
    std::uint64_t handle_ = 0;
    Socks5Proxy proxy_;
};

} // namespace aowis::network
