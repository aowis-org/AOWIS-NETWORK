#include "aowis/network/wireguard_conf.h"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using aowis::network::WireGuardConfDiagnostic;
using aowis::network::WireGuardConfIssue;
using aowis::network::WireGuardConfParse;
using aowis::network::WireGuardConfSeverity;
using aowis::network::parseWireGuardConf;

// Throws instead of assert(): the checks must also run in NDEBUG builds.
void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

bool has(const WireGuardConfParse& parse, WireGuardConfIssue issue)
{
    for (const WireGuardConfDiagnostic& diagnostic : parse.diagnostics) {
        if (diagnostic.issue == issue) {
            return true;
        }
    }
    return false;
}

const std::string privateKey = "k5yQ1m2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0=";
const std::string publicKey = "V0hERXJ4MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU=";
const std::string sharedKey = "/BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq=";

std::string valid()
{
    return "# office VPN\r\n"
           "[Interface]\r\n"
           "PrivateKey = " + privateKey + "\r\n"
           "Address = 10.77.0.2/32\r\n"
           "DNS = 10.77.0.1, corp.example\r\n"
           "MTU = 1380\r\n"
           "\r\n"
           "[Peer]\r\n"
           "PublicKey = " + publicKey + "\r\n"
           "PresharedKey = " + sharedKey + "\r\n"
           "Endpoint = vpn.example.invalid:51820\r\n"
           "AllowedIPs = 10.77.0.0/24\r\n"
           "AllowedIPs = 10.78.0.1\r\n"
           "PersistentKeepalive = 15\r\n";
}

void parsesSupportedProfile()
{
    const WireGuardConfParse parse = parseWireGuardConf(valid());
    require(parse.ok(), "valid profile rejected");
    const aowis::network::WireGuardConfig& config = parse.config;
    require(config.privateKey == privateKey && config.peerPublicKey == publicKey
            && config.preSharedKey == sharedKey, "keys not extracted");
    require(config.address == "10.77.0.2/32", "address");
    require(config.dnsServers.size() == 1 && config.dnsServers[0] == "10.77.0.1", "DNS servers");
    require(has(parse, WireGuardConfIssue::ignored_dns_search_domain), "search domain not reported");
    require(config.mtu == 1380 && config.persistentKeepaliveSeconds == 15, "numbers");
    require(config.endpoint == "vpn.example.invalid:51820", "endpoint");
    require(config.allowedIPs.size() == 2 && config.allowedIPs[1] == "10.78.0.1/32",
            "AllowedIPs lines must append and bare addresses become host routes");
}

void followsWgSyntax()
{
    const std::string text = "\xef\xbb\xbf[ interface ] # comment\n"
                             "privatekey=" + privateKey + "#trailing\n"
                             "ADDRESS = fd00::2/64\n"
                             "[PEER]\n"
                             "publickey = " + publicKey + "\n"
                             "endpoint = [2001:db8::1]:51820\n"
                             "allowedips = ::/0, 0.0.0.0/0\n"
                             "persistentkeepalive = off\n";
    const WireGuardConfParse parse = parseWireGuardConf(text);
    require(parse.ok(), "wg(8)-style case, blanks, BOM and comments rejected");
    require(parse.config.address == "fd00::2/64" && parse.config.persistentKeepaliveSeconds == 0,
            "values from relaxed syntax");
    require(parseWireGuardConf(valid().replace(valid().find("PersistentKeepalive = 15\r\n"), 26, ""))
                    .config.persistentKeepaliveSeconds == 25,
            "missing PersistentKeepalive must keep the engine default");
}

void ignoresHooksWithWarnings()
{
    const std::string text = valid() + "";
    std::string withHooks = text;
    withHooks.insert(withHooks.find("MTU"), "PostUp = rm -rf /\r\nListenPort = 51820\r\nTable = off\r\n");
    const WireGuardConfParse parse = parseWireGuardConf(withHooks);
    require(parse.ok(), "ignorable wg-quick directives must not block");
    require(has(parse, WireGuardConfIssue::ignored_directive), "ignored directive not reported");
    for (const WireGuardConfDiagnostic& diagnostic : parse.diagnostics) {
        require(diagnostic.severity == WireGuardConfSeverity::warning, "hook produced an error");
    }
}

void rejectsWhatTheEngineCannotRun()
{
    struct Case {
        std::string text;
        WireGuardConfIssue issue;
        const char* name;
    };
    const std::string peer = "[Peer]\nPublicKey = " + publicKey + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/8\n";
    const std::string iface = "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n";
    const Case cases[] = {
        {"", WireGuardConfIssue::missing_interface, "empty"},
        {iface, WireGuardConfIssue::missing_peer, "no peer"},
        {iface + peer + peer, WireGuardConfIssue::multiple_peers, "two peers"},
        {iface + iface + peer, WireGuardConfIssue::duplicate_interface, "two interfaces"},
        {"[Interface]\nAddress = 10.0.0.2/32\n" + peer, WireGuardConfIssue::missing_private_key, "no key"},
        {"[Interface]\nPrivateKey = " + privateKey + "\n" + peer, WireGuardConfIssue::missing_address, "no address"},
        {"[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32, fd00::2/64\n" + peer,
         WireGuardConfIssue::multiple_addresses, "two addresses"},
        {"[Interface]\nPrivateKey = /etc/wireguard/private.key\nAddress = 10.0.0.2/32\n" + peer,
         WireGuardConfIssue::invalid_key, "key file path"},
        {iface + "PrivateKey = " + privateKey + "\n" + peer, WireGuardConfIssue::duplicate_directive, "duplicate key"},
        {iface + "Include = /tmp/x\n" + peer, WireGuardConfIssue::unknown_directive, "unknown directive"},
        {iface + peer + "[Other]\n", WireGuardConfIssue::unexpected_section, "unknown section"},
        {"PrivateKey = " + privateKey + "\n" + iface + peer, WireGuardConfIssue::directive_outside_section, "outside"},
        {iface + "garbage line\n" + peer, WireGuardConfIssue::invalid_line, "no equals"},
        {iface + "MTU = 100\n" + peer, WireGuardConfIssue::invalid_number, "MTU range"},
        {iface + "DNS = 10.0.0.1, \n" + peer, WireGuardConfIssue::invalid_dns, "empty DNS"},
        {iface + "[Peer]\nPublicKey = " + publicKey + "\nEndpoint = fd00::1:51820\nAllowedIPs = 10.0.0.0/8\n",
         WireGuardConfIssue::invalid_endpoint, "unbracketed IPv6 endpoint"},
        {iface + "[Peer]\nPublicKey = " + publicKey + "\nEndpoint = host:0\nAllowedIPs = 10.0.0.0/8\n",
         WireGuardConfIssue::invalid_endpoint, "port zero"},
        {iface + "[Peer]\nPublicKey = " + publicKey + "\nEndpoint = host:1\nAllowedIPs = 10.0.0.0/33\n",
         WireGuardConfIssue::invalid_allowed_ip, "prefix length"},
        {iface + "[Peer]\nPublicKey = " + publicKey + "\nEndpoint = host:1\n", WireGuardConfIssue::missing_allowed_ips,
         "no AllowedIPs"},
        {iface + "Address\n" + peer, WireGuardConfIssue::invalid_line, "key without value"},
        {iface + "MTU = \n" + peer, WireGuardConfIssue::empty_value, "empty value"},
        {std::string("[Interface]\nA\0B = 1\n", 19), WireGuardConfIssue::invalid_text, "NUL"},
    };
    for (const Case& test : cases) {
        const WireGuardConfParse parse = parseWireGuardConf(test.text);
        require(!parse.ok(), std::string("accepted: ") + test.name);
        require(has(parse, test.issue), std::string("wrong diagnostic: ") + test.name);
        require(parse.config.privateKey.empty() && parse.config.address.empty(),
                std::string("half-parsed config leaked: ") + test.name);
    }
}

void diagnosticsNeverEchoInput()
{
    std::string text = valid();
    text.insert(text.find("[Peer]"), "Zebrafish = " + privateKey + "\r\n");
    text += "Bogus = " + sharedKey + "\r\n[Mystery " + publicKey + "]\r\n";
    const WireGuardConfParse parse = parseWireGuardConf(text);
    require(!parse.ok(), "unknown directives accepted");
    for (const WireGuardConfDiagnostic& diagnostic : parse.diagnostics) {
        require(diagnostic.message.find(privateKey) == std::string::npos
                && diagnostic.message.find(sharedKey) == std::string::npos
                && diagnostic.message.find(publicKey) == std::string::npos
                && diagnostic.message.find("Zebrafish") == std::string::npos,
                "diagnostic echoes input");
        require(diagnostic.line > 0, "per-line problem without line number");
    }
}

void capsDiagnostics()
{
    std::string text = "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.2/32\n";
    for (int index = 0; index < 700; ++index) {
        text += "ListenPort = 1\n";
    }
    text += "[Peer]\nPublicKey = " + publicKey + "\nEndpoint = h:1\nAllowedIPs = 10.0.0.0/8\nNope = 1\n";
    const WireGuardConfParse parse = parseWireGuardConf(text);
    require(parse.diagnostics.size() == 512, "diagnostics not capped");
    require(!parse.ok(), "error beyond the cap was lost");
}

} // namespace

int main()
{
    try {
        parsesSupportedProfile();
        followsWgSyntax();
        ignoresHooksWithWarnings();
        rejectsWhatTheEngineCannotRun();
        diagnosticsNeverEchoInput();
        capsDiagnostics();
        std::cout << "WireGuard .conf parser tests passed\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << "FAILED: " << failure.what() << '\n';
        return 1;
    }
}
