#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace pm::uri {

/// Parsed RFC-style URI. Scheme and host are normalized to lowercase;
/// bracketed IPv6 hosts are stored without brackets.
struct ParsedUri {
    bool valid = false;
    bool has_authority = false;
    bool bracketed_ipv6 = false;
    std::string scheme;
    std::string authority;
    std::string userinfo;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
    std::string fragment;
    std::string original;
};

/// Tightening options used at trust boundaries such as shell and WebView URLs.
struct ParseOptions {
    bool reject_userinfo = false;
    bool reject_percent_encoded_authority = false;
    bool require_authority_host = false;
};

std::optional<ParsedUri> parse_uri(std::string_view in, ParseOptions options = {});
/// Same as parse_uri, but raw spaces are encoded as %20 first. Agent tool
/// URLs often contain an unescaped space; a strict parse then fails and an
/// origin grant such as https://host/** never matches.
std::optional<ParsedUri> parse_uri_lenient(std::string_view in, ParseOptions options = {});
std::optional<ParsedUri> parse_http_uri(std::string_view in, ParseOptions options = {});
std::optional<std::string> percent_decode(std::string_view in, bool reject_encoded_percent = false);
bool host_is_private_or_invalid(const ParsedUri& uri, std::string& reason);

} // namespace pm::uri
