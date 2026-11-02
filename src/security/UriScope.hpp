#pragma once
//
// pm::security::uri — compatibility re-exports of core/uri plus security scope matching.
//
// Capability grants scope resources by URI pattern. A scope is matched against a
// request's resource on three axes:
//   * scheme  — exact (lowercased), or `*` to match any scheme
//   * host    — glob (`*`, `?`, `*.github.com`); empty pattern host = any
//   * path    — glob (PathSecurity glob: `*`, `?`, `**`)
// Ports, when present in the pattern, must match exactly.
//
// Supported schemes (see `k_uri_schemes`): file, http, https, ftp, ws, wss.
// `fs://` is accepted as an alias and normalized to `file://` (decision:
// file:// is canonical per RFC 8089). A bare scope with no `scheme://` is treated
// as a filesystem path glob for backward compatibility.
//
// File URIs are handled leniently: everything after `file:` (minus leading
// slashes) is the path, with an empty host — so `file://**`, `file:///C:/x` and
// `file://**.png` all parse to a path with no authority.
//

#include "net/uri.hpp"
#include "security/types.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pm::security::uri {

/// Schemes the matcher understands out of the box (RFC-compliant tokens).
inline constexpr std::array<std::string_view, 6> k_uri_schemes{
    "file", "http", "https", "ftp", "ws", "wss"};

using pm::uri::ParsedUri;
using pm::uri::ParseOptions;
using pm::uri::host_is_private_or_invalid;
using pm::uri::parse_http_uri;
using pm::uri::parse_uri;
using pm::uri::parse_uri_lenient;
using pm::uri::percent_decode;

/// Build the effective URI of a request target. Prefers a real filesystem path
/// (treated as `file:` with the given path) and falls back to the target's URI
/// string for network resources.
ParsedUri uri_from_target(const ResourceTarget& target);

/// True when @p scope matches the given target (scheme/host/port/path).
bool scope_matches_target(std::string_view scope, const ResourceTarget& target);

/// True when any of @p scopes matches the target. Empty `scopes` = no constraint
/// (caller decides; PermissionStore treats empty as "match").
bool scope_matches_any(const std::vector<std::string>& scopes, const ResourceTarget& target);

} // namespace pm::security::uri
