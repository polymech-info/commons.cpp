#include "security/UriScope.hpp"
#include "security/PathSecurity.hpp"

#include <algorithm>
#include <cctype>

namespace pm::security::uri {
namespace {

std::string lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string to_slashes(std::string value) {
    std::replace(value.begin(), value.end(), '\\', '/');
    return value;
}

} // namespace

ParsedUri uri_from_target(const ResourceTarget& target) {
    if (!target.path.empty()) {
        ParsedUri uri;
        uri.valid = true;
        uri.scheme = "file";
        uri.path = to_slashes(target.path.generic_string());
        uri.original = uri.path;
        return uri;
    }
    if (!target.uri.empty()) {
        if (auto parsed = parse_uri_lenient(target.uri))
            return *parsed;
    }
    return {};
}

bool scope_matches_target(std::string_view scope, const ResourceTarget& target) {
    // Shell commands are intentionally represented as cmd://<raw command>.
    // Raw command text commonly contains spaces, quotes, pipes, and redirects,
    // so it is not a valid RFC authority and must not pass through the generic
    // URI parser. Match the complete command URI as a glob instead. This is
    // what makes the consent surface's suggested cmd://** session grant cover
    // subsequent commands while the run tool's validator remains the hard
    // safety boundary.
    constexpr std::string_view cmd_scheme = "cmd://";
    if (scope.size() >= cmd_scheme.size() &&
        scope.substr(0, cmd_scheme.size()) == cmd_scheme) {
        if (target.uri.size() < cmd_scheme.size() ||
            target.uri.compare(0, cmd_scheme.size(), cmd_scheme) != 0)
            return false;
        return PathSecurity::globMatch(lower(target.uri), lower(scope));
    }

    const auto pattern = parse_uri_lenient(scope);
    if (!pattern || !pattern->valid) return false;
    ResourceTarget effective = target;
    const bool http_scope = pattern->scheme == "http" || pattern->scheme == "https";
    const bool http_target = target.uri.rfind("http://", 0) == 0
        || target.uri.rfind("https://", 0) == 0;
    if (http_scope && http_target)
        effective.path.clear();
    const ParsedUri uri = uri_from_target(effective);
    if (!uri.valid) return false;

    if (pattern->scheme.empty()) {
        if (!uri.scheme.empty() && uri.scheme != "file") return false;
        // Bare path glob. UNC `//server/share/file` is a filesystem path; if a
        // stored scope was parsed as host+path, rebuild the UNC so it matches
        // uri_from_target's full path.
        std::string pat = pattern->path;
        if (!pattern->host.empty()) {
            pat = "//" + pattern->host;
            if (pattern->path.empty() || pattern->path.front() != '/')
                pat += '/';
            pat += pattern->path;
        }
        return PathSecurity::globMatch(lower(uri.path), lower(pat));
    }
    if (pattern->scheme != "*" && pattern->scheme != uri.scheme) return false;
    if (!pattern->host.empty() && !PathSecurity::globMatch(uri.host, pattern->host))
        return false;
    if (!pattern->port.empty() && pattern->port != uri.port) return false;
    if (!pattern->path.empty()
        && !PathSecurity::globMatch(lower(uri.path), lower(pattern->path)))
        return false;
    return true;
}

bool scope_matches_any(const std::vector<std::string>& scopes, const ResourceTarget& target) {
    for (const auto& scope : scopes)
        if (scope_matches_target(scope, target))
            return true;
    return false;
}

} // namespace pm::security::uri
