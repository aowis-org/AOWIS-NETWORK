#include "aowis/network/wireguard_client.h"

#ifdef AOWIS_NETWORK_WITH_WIREGUARD
#include "wireguard_abi.h"
#endif

#include <array>
#include <string>

namespace aowis::network {
namespace {

#ifdef AOWIS_NETWORK_WITH_WIREGUARD
std::string join(const std::vector<std::string>& values)
{
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) {
            result += ',';
        }
        result += value;
    }
    return result;
}
#endif

bool validate(const WireGuardConfig& config, std::string* error)
{
    const bool complete = !config.address.empty() && !config.privateKey.empty()
        && !config.peerPublicKey.empty() && !config.endpoint.empty()
        && !config.allowedIPs.empty();
    if (!complete) {
        if (error != nullptr) {
            *error = "WireGuard requires an address, private key, peer public key, endpoint and allowed IPs";
        }
        return false;
    }
    if (config.mtu < 576 || config.mtu > 65535
        || config.persistentKeepaliveSeconds < 0 || config.persistentKeepaliveSeconds > 65535) {
        if (error != nullptr) {
            *error = "Invalid WireGuard MTU or keepalive interval";
        }
        return false;
    }
    for (const std::string& dns : config.dnsServers) {
        if (dns.empty() || dns.find(',') != std::string::npos) {
            if (error != nullptr) {
                *error = "Invalid WireGuard DNS server";
            }
            return false;
        }
    }
    for (const std::string& allowedIP : config.allowedIPs) {
        if (allowedIP.empty() || allowedIP.find(',') != std::string::npos) {
            if (error != nullptr) {
                *error = "Invalid WireGuard allowed IP";
            }
            return false;
        }
    }
    return true;
}

} // namespace

WireGuardClient::~WireGuardClient()
{
    this->stop();
}

bool WireGuardClient::start(const WireGuardConfig& config, std::string* error)
{
    if (this->isRunning()) {
        if (error != nullptr) {
            *error = "WireGuard tunnel is already running";
        }
        return false;
    }
    if (!validate(config, error)) {
        return false;
    }
#ifndef AOWIS_NETWORK_WITH_WIREGUARD
    if (error != nullptr) {
        *error = "AOWIS-Network was built without the embedded WireGuard engine";
    }
    return false;
#else
    std::uint16_t port = 0;
    std::array<char, 96> username{};
    std::array<char, 96> password{};
    std::array<char, 512> bridgeError{};
    const std::string dns = join(config.dnsServers);
    const std::string allowedIPs = join(config.allowedIPs);

    const std::uint64_t handle = AowisWGStart(
        config.address.c_str(), dns.c_str(), config.privateKey.c_str(),
        config.peerPublicKey.c_str(), config.preSharedKey.c_str(),
        config.endpoint.c_str(), allowedIPs.c_str(), config.mtu,
        config.persistentKeepaliveSeconds, &port, username.data(),
        static_cast<int>(username.size()), password.data(),
        static_cast<int>(password.size()), bridgeError.data(),
        static_cast<int>(bridgeError.size()));
    if (handle == 0) {
        if (error != nullptr) {
            *error = bridgeError.data();
        }
        return false;
    }
    this->handle_ = handle;
    this->proxy_.port = port;
    this->proxy_.username = username.data();
    this->proxy_.password = password.data();
    if (error != nullptr) {
        error->clear();
    }
    return true;
#endif
}

void WireGuardClient::stop()
{
#ifdef AOWIS_NETWORK_WITH_WIREGUARD
    if (this->handle_ != 0) {
        AowisWGStop(this->handle_);
    }
#endif
    this->handle_ = 0;
    this->proxy_ = Socks5Proxy{};
}

bool WireGuardClient::isRunning() const
{
    return this->handle_ != 0;
}

Socks5Proxy WireGuardClient::proxy() const
{
    return this->proxy_;
}

} // namespace aowis::network
