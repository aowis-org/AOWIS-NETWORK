#pragma once

#include "aowis/network/wireguard_client.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace aowis::network {

// The single authoritative WireGuard .conf parser of AOWIS. It accepts
// exactly what the embedded engine (WireGuardClient) can run, so the GUI's
// import/edit diagnostics, the tunnel start and storage never disagree.
// AOWIS-CONFIG stores the text verbatim and does not parse it.
//
// Syntax follows wg(8)/wg-quick: section names and keys are case-insensitive,
// blanks inside a section header are ignored, everything from '#' to the end
// of a line is a comment, a UTF-8 BOM and CRLF line ends are accepted, and
// repeated AllowedIPs/DNS/Address lines append. Supported subset:
//   [Interface]  PrivateKey (required), Address (required, exactly one),
//                DNS (IP addresses; search domains are ignored with a
//                warning), MTU (576-65535)
//   [Peer]       exactly one: PublicKey (required), PresharedKey,
//                Endpoint (required, host:port or [IPv6]:port),
//                AllowedIPs (required; bare addresses become /32 or /128),
//                PersistentKeepalive (0-65535 or "off")
// ListenPort, FwMark, Table, SaveConfig and PreUp/PostUp/PreDown/PostDown are
// ignored with a warning; hook commands are never executed. Every other
// directive or section is an error, so a profile cannot silently acquire a
// different meaning. Addresses are shape-checked here; the engine performs
// the final parse (and endpoint DNS resolution) in WireGuardClient::start().
// Without PersistentKeepalive the WireGuardConfig default (25 s) is kept.
enum class WireGuardConfSeverity { warning, error };

enum class WireGuardConfIssue {
    invalid_text,             // NUL byte or oversized text
    invalid_line,             // not a [section] and not key = value
    unexpected_section,
    duplicate_interface,
    multiple_peers,           // the embedded client supports exactly one peer
    directive_outside_section,
    empty_value,
    duplicate_directive,
    unknown_directive,
    ignored_directive,        // warning
    invalid_key,
    multiple_addresses,
    invalid_address,
    invalid_dns,
    ignored_dns_search_domain, // warning
    invalid_allowed_ip,
    invalid_endpoint,
    invalid_number,
    missing_interface,
    missing_peer,
    missing_private_key,
    missing_address,
    missing_peer_public_key,
    missing_endpoint,
    missing_allowed_ips,
};

struct WireGuardConfDiagnostic {
    WireGuardConfSeverity severity;
    WireGuardConfIssue issue;
    std::size_t line;    // 1-based line number, 0 for whole-file issues
    std::string message; // Never contains text, keys or values from the input
};

struct WireGuardConfParse {
    // Complete only when ok(); reset to defaults when there are errors, so a
    // half-parsed configuration (and its key) is never handed onwards.
    WireGuardConfig config;
    std::vector<WireGuardConfDiagnostic> diagnostics; // At most 512 entries
    bool hasErrors = false; // Also counts errors beyond the diagnostics cap

    bool ok() const { return !this->hasErrors; }
};

inline constexpr std::size_t maxWireGuardConfBytes = 2U * 1024U * 1024U;

WireGuardConfParse parseWireGuardConf(std::string_view text);

} // namespace aowis::network
