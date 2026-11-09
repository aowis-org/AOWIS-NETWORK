#include "aowis/network/wireguard_client.h"

#include <cassert>
#include <string>

int main()
{
    aowis::network::WireGuardClient client;
    assert(!client.isRunning());
    assert(client.proxy().port == 0);

    std::string error;
    aowis::network::WireGuardConfig invalid;
    assert(!client.start(invalid, &error));
    assert(!error.empty());

    invalid.address = "10.0.0.2/32";
    invalid.privateKey = "invalid";
    invalid.peerPublicKey = "invalid";
    invalid.endpoint = "example.com:51820";
    invalid.allowedIPs = {"10.0.0.0/24"};
    invalid.mtu = 1;
    assert(!client.start(invalid, &error));
    assert(error == "Invalid WireGuard MTU or keepalive interval");

    invalid.mtu = 1420;
    // A real engine must reject malformed keys and must not start a local
    // proxy on invalid configuration. This does not require a remote peer.
    assert(!client.start(invalid, &error));
    assert(!client.isRunning());
    assert(client.proxy().port == 0);
    client.stop();
    client.stop();
    return 0;
}
