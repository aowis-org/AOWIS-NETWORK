#include "aowis/network/wireguard_conf.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aowis::network {
namespace {

constexpr std::size_t maxDiagnostics = 512;

bool isBlank(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

std::string_view trim(std::string_view text)
{
    while (!text.empty() && isBlank(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && isBlank(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

std::string lowercase(std::string_view text)
{
    std::string result(text);
    for (char& c : result) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return result;
}

std::string withoutBlanks(std::string_view text)
{
    std::string result;
    result.reserve(text.size());
    for (char c : text) {
        if (!isBlank(c)) {
            result += c;
        }
    }
    return result;
}

bool isDigit(char c)
{
    return c >= '0' && c <= '9';
}

bool isHex(char c)
{
    return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Decimal without sign or leading '+'; false on overflow beyond maximum.
bool parseNumber(std::string_view text, std::uint32_t maximum, std::uint32_t& value)
{
    if (text.empty() || text.size() > 10) {
        return false;
    }
    std::uint64_t result = 0;
    for (char c : text) {
        if (!isDigit(c)) {
            return false;
        }
        result = result * 10U + static_cast<std::uint64_t>(c - '0');
    }
    if (result > maximum) {
        return false;
    }
    value = static_cast<std::uint32_t>(result);
    return true;
}

// 32 bytes in standard base64: 43 alphabet characters and one '='.
bool isKey(std::string_view value)
{
    if (value.size() != 44 || value[43] != '=') {
        return false;
    }
    for (std::size_t index = 0; index < 43; ++index) {
        const char c = value[index];
        const bool alphabet = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isDigit(c)
            || c == '+' || c == '/';
        if (!alphabet) {
            return false;
        }
    }
    return true;
}

bool isIPv4(std::string_view text)
{
    int parts = 0;
    while (true) {
        const std::size_t dot = text.find('.');
        const std::string_view part = text.substr(0, dot);
        std::uint32_t value = 0;
        if (part.empty() || part.size() > 3 || !parseNumber(part, 255, value)) {
            return false;
        }
        ++parts;
        if (dot == std::string_view::npos) {
            break;
        }
        text.remove_prefix(dot + 1);
    }
    return parts == 4;
}

// Shape check only (hex groups, at most one "::", optional trailing IPv4);
// netip in the engine performs the authoritative parse at start().
bool isIPv6(std::string_view text)
{
    if (text.size() < 2 || text.size() > 45 || text.find(':') == std::string_view::npos) {
        return false;
    }
    const std::size_t compressed = text.find("::");
    if (compressed != std::string_view::npos && text.find("::", compressed + 1) != std::string_view::npos) {
        return false;
    }
    const std::size_t lastColon = text.rfind(':');
    const std::string_view tail = text.substr(lastColon + 1);
    const bool ipv4Tail = tail.find('.') != std::string_view::npos;
    if (ipv4Tail && !isIPv4(tail)) {
        return false;
    }
    const std::string_view groups = ipv4Tail ? text.substr(0, lastColon + 1) : text;
    int run = 0;
    for (char c : groups) {
        if (c == ':') {
            run = 0;
        } else if (isHex(c) && ++run <= 4) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

bool isAddress(std::string_view text)
{
    return isIPv4(text) || isIPv6(text);
}

// addr/bits with bits within the family's range.
bool isPrefix(std::string_view text)
{
    const std::size_t slash = text.find('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    const std::string_view address = text.substr(0, slash);
    std::uint32_t bits = 0;
    if (isIPv4(address)) {
        return parseNumber(text.substr(slash + 1), 32, bits);
    }
    return isIPv6(address) && parseNumber(text.substr(slash + 1), 128, bits);
}

bool isHostname(std::string_view text)
{
    if (text.empty() || text.size() > 253) {
        return false;
    }
    for (char c : text) {
        const bool allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isDigit(c)
            || c == '-' || c == '.' || c == '_';
        if (!allowed) {
            return false;
        }
    }
    return true;
}

// host:port or [IPv6]:port, port 1-65535. Hostnames are resolved by the
// engine through the host's resolver, as for wg-quick.
bool isEndpoint(std::string_view text)
{
    std::string_view host;
    std::string_view port;
    if (!text.empty() && text.front() == '[') {
        const std::size_t close = text.find(']');
        if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':') {
            return false;
        }
        host = text.substr(1, close - 1);
        port = text.substr(close + 2);
        if (!isIPv6(host)) {
            return false;
        }
    } else {
        const std::size_t colon = text.rfind(':');
        if (colon == std::string_view::npos || text.find(':') != colon) {
            return false; // A bare IPv6 endpoint must use brackets.
        }
        host = text.substr(0, colon);
        port = text.substr(colon + 1);
        if (!isIPv4(host) && !isHostname(host)) {
            return false;
        }
    }
    std::uint32_t number = 0;
    return parseNumber(port, 65535, number) && number != 0;
}

std::vector<std::string_view> splitList(std::string_view value)
{
    std::vector<std::string_view> items;
    while (true) {
        const std::size_t comma = value.find(',');
        items.push_back(trim(value.substr(0, comma)));
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return items;
}

class Parser {
public:
    WireGuardConfParse run(std::string_view text)
    {
        if (text.size() > maxWireGuardConfBytes || text.find('\0') != std::string_view::npos) {
            this->add(WireGuardConfSeverity::error, WireGuardConfIssue::invalid_text, 0,
                      "WireGuard configuration contains NUL bytes or exceeds 2 MiB");
            return this->finish();
        }
        std::size_t position = 0;
        while (position < text.size()) {
            ++this->line_;
            const std::size_t end = text.find('\n', position);
            const std::size_t limit = end == std::string_view::npos ? text.size() : end;
            std::string_view line = text.substr(position, limit - position);
            position = end == std::string_view::npos ? text.size() : end + 1;
            if (this->line_ == 1 && line.substr(0, 3) == "\xef\xbb\xbf") {
                line.remove_prefix(3);
            }
            // wg(8) strips everything from '#' to the end of the line.
            line = trim(line.substr(0, line.find('#')));
            if (!line.empty()) {
                this->handleLine(line);
            }
        }
        this->checkRequired();
        return this->finish();
    }

private:
    enum class Section { none, interface, peer, other };

    void add(WireGuardConfSeverity severity, WireGuardConfIssue issue, std::size_t line, const char* message)
    {
        if (severity == WireGuardConfSeverity::error) {
            this->result_.hasErrors = true;
        }
        if (this->result_.diagnostics.size() < maxDiagnostics) {
            this->result_.diagnostics.push_back({severity, issue, line, message});
        }
    }

    void error(WireGuardConfIssue issue, const char* message)
    {
        this->add(WireGuardConfSeverity::error, issue, this->line_, message);
    }

    void warning(WireGuardConfIssue issue, const char* message)
    {
        this->add(WireGuardConfSeverity::warning, issue, this->line_, message);
    }

    void handleLine(std::string_view line)
    {
        if (line.front() == '[') {
            const std::string header = lowercase(withoutBlanks(line));
            if (header == "[interface]") {
                if (this->hasInterface_) {
                    this->error(WireGuardConfIssue::duplicate_interface, "Only one [Interface] section is allowed");
                    this->section_ = Section::other;
                    return;
                }
                this->hasInterface_ = true;
                this->section_ = Section::interface;
            } else if (header == "[peer]") {
                if (this->hasPeer_) {
                    this->error(WireGuardConfIssue::multiple_peers,
                                "The embedded WireGuard client supports exactly one [Peer]");
                    this->section_ = Section::other;
                    return;
                }
                this->hasPeer_ = true;
                this->section_ = Section::peer;
            } else {
                this->error(WireGuardConfIssue::unexpected_section, "Unknown WireGuard section");
                this->section_ = Section::other;
            }
            this->seen_.clear();
            return;
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string_view::npos) {
            this->error(WireGuardConfIssue::invalid_line, "Expected a [Section] or a key = value line");
            return;
        }
        const std::string key = lowercase(trim(line.substr(0, equals)));
        const std::string_view value = trim(line.substr(equals + 1));
        if (this->section_ == Section::none) {
            this->error(WireGuardConfIssue::directive_outside_section,
                        "Directive must be inside [Interface] or [Peer]");
            return;
        }
        if (this->section_ == Section::other) {
            return; // Already reported at the section header.
        }
        if (key.empty() || value.empty()) {
            this->error(WireGuardConfIssue::empty_value, "Directive name and value must not be empty");
            return;
        }
        if (this->section_ == Section::interface) {
            this->interfaceDirective(key, value);
        } else {
            this->peerDirective(key, value);
        }
    }

    // Scalar directives may appear once per section; list directives append.
    bool firstOccurrence(const std::string& key)
    {
        for (const std::string& seen : this->seen_) {
            if (seen == key) {
                this->error(WireGuardConfIssue::duplicate_directive, "Directive appears more than once in this section");
                return false;
            }
        }
        this->seen_.push_back(key);
        return true;
    }

    void interfaceDirective(const std::string& key, std::string_view value)
    {
        WireGuardConfig& config = this->result_.config;
        if (key == "privatekey") {
            if (!this->firstOccurrence(key)) {
                return;
            }
            if (!isKey(value)) {
                this->error(WireGuardConfIssue::invalid_key, "PrivateKey must be a 32-byte base64 WireGuard key");
                return;
            }
            config.privateKey = std::string(value);
        } else if (key == "address") {
            for (std::string_view item : splitList(value)) {
                if (!isAddress(item) && !isPrefix(item)) {
                    this->error(WireGuardConfIssue::invalid_address, "Address must be an IP address or prefix");
                    continue;
                }
                ++this->addressCount_;
                if (this->addressCount_ > 1) {
                    if (this->addressCount_ == 2) {
                        this->error(WireGuardConfIssue::multiple_addresses,
                                    "The embedded WireGuard client supports exactly one interface Address");
                    }
                    continue;
                }
                config.address = std::string(item);
            }
        } else if (key == "dns") {
            for (std::string_view item : splitList(value)) {
                if (item.empty()) {
                    this->error(WireGuardConfIssue::invalid_dns, "DNS entries must not be empty");
                } else if (isAddress(item)) {
                    config.dnsServers.emplace_back(item);
                } else if (isHostname(item)) {
                    this->warning(WireGuardConfIssue::ignored_dns_search_domain,
                                  "DNS search domain is ignored by the embedded WireGuard client");
                } else {
                    this->error(WireGuardConfIssue::invalid_dns, "DNS entry is neither an IP address nor a domain");
                }
            }
        } else if (key == "mtu") {
            std::uint32_t mtu = 0;
            if (!this->firstOccurrence(key)) {
                return;
            }
            if (!parseNumber(value, 65535, mtu) || mtu < 576) {
                this->error(WireGuardConfIssue::invalid_number, "MTU must be a number from 576 to 65535");
                return;
            }
            config.mtu = static_cast<int>(mtu);
        } else if (key == "listenport" || key == "fwmark" || key == "table" || key == "saveconfig"
                   || key == "preup" || key == "postup" || key == "predown" || key == "postdown") {
            this->warning(WireGuardConfIssue::ignored_directive,
                          "Directive is ignored by the embedded WireGuard client; hook commands are never run");
        } else {
            this->error(WireGuardConfIssue::unknown_directive, "Unsupported [Interface] directive");
        }
    }

    void peerDirective(const std::string& key, std::string_view value)
    {
        WireGuardConfig& config = this->result_.config;
        if (key == "publickey" || key == "presharedkey") {
            if (!this->firstOccurrence(key)) {
                return;
            }
            if (!isKey(value)) {
                this->error(WireGuardConfIssue::invalid_key, "Peer keys must be 32-byte base64 WireGuard keys");
                return;
            }
            (key == "publickey" ? config.peerPublicKey : config.preSharedKey) = std::string(value);
        } else if (key == "endpoint") {
            if (!this->firstOccurrence(key)) {
                return;
            }
            if (!isEndpoint(value)) {
                this->error(WireGuardConfIssue::invalid_endpoint,
                            "Endpoint must be host:port or [IPv6]:port with a port from 1 to 65535");
                return;
            }
            config.endpoint = std::string(value);
        } else if (key == "allowedips") {
            for (std::string_view item : splitList(value)) {
                if (isPrefix(item)) {
                    config.allowedIPs.emplace_back(item);
                } else if (isIPv4(item)) {
                    config.allowedIPs.push_back(std::string(item) + "/32"); // wg(8): bare address = host route
                } else if (isIPv6(item)) {
                    config.allowedIPs.push_back(std::string(item) + "/128");
                } else {
                    this->error(WireGuardConfIssue::invalid_allowed_ip, "AllowedIPs entries must be IP prefixes");
                }
            }
        } else if (key == "persistentkeepalive") {
            std::uint32_t seconds = 0;
            if (!this->firstOccurrence(key)) {
                return;
            }
            if (lowercase(value) == "off") {
                config.persistentKeepaliveSeconds = 0;
            } else if (parseNumber(value, 65535, seconds)) {
                config.persistentKeepaliveSeconds = static_cast<int>(seconds);
            } else {
                this->error(WireGuardConfIssue::invalid_number,
                            "PersistentKeepalive must be off or a number from 0 to 65535");
            }
        } else {
            this->error(WireGuardConfIssue::unknown_directive, "Unsupported [Peer] directive");
        }
    }

    void checkRequired()
    {
        const WireGuardConfig& config = this->result_.config;
        const WireGuardConfSeverity e = WireGuardConfSeverity::error;
        if (!this->hasInterface_) {
            this->add(e, WireGuardConfIssue::missing_interface, 0, "Missing [Interface] section");
        } else {
            if (config.privateKey.empty() && !this->seenIssue(WireGuardConfIssue::invalid_key)) {
                this->add(e, WireGuardConfIssue::missing_private_key, 0, "[Interface] has no PrivateKey");
            }
            if (this->addressCount_ == 0 && !this->seenIssue(WireGuardConfIssue::invalid_address)) {
                this->add(e, WireGuardConfIssue::missing_address, 0, "[Interface] has no Address");
            }
        }
        if (!this->hasPeer_) {
            this->add(e, WireGuardConfIssue::missing_peer, 0, "Missing [Peer] section");
            return;
        }
        if (config.peerPublicKey.empty() && !this->seenIssue(WireGuardConfIssue::invalid_key)) {
            this->add(e, WireGuardConfIssue::missing_peer_public_key, 0, "[Peer] has no PublicKey");
        }
        if (config.endpoint.empty() && !this->seenIssue(WireGuardConfIssue::invalid_endpoint)) {
            this->add(e, WireGuardConfIssue::missing_endpoint, 0, "[Peer] has no Endpoint");
        }
        if (config.allowedIPs.empty() && !this->seenIssue(WireGuardConfIssue::invalid_allowed_ip)) {
            this->add(e, WireGuardConfIssue::missing_allowed_ips, 0, "[Peer] has no AllowedIPs");
        }
    }

    bool seenIssue(WireGuardConfIssue issue) const
    {
        for (const WireGuardConfDiagnostic& diagnostic : this->result_.diagnostics) {
            if (diagnostic.issue == issue) {
                return true;
            }
        }
        return false;
    }

    WireGuardConfParse finish()
    {
        if (this->result_.hasErrors) {
            this->result_.config = WireGuardConfig{};
        }
        return std::move(this->result_);
    }

    WireGuardConfParse result_;
    Section section_ = Section::none;
    std::vector<std::string> seen_;
    std::size_t line_ = 0;
    std::size_t addressCount_ = 0;
    bool hasInterface_ = false;
    bool hasPeer_ = false;
};

} // namespace

WireGuardConfParse parseWireGuardConf(std::string_view text)
{
    Parser parser;
    return parser.run(text);
}

} // namespace aowis::network
