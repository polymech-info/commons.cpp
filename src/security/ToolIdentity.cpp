#include "security/ToolIdentity.hpp"
#include "security/PathSecurity.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace pm::security {

std::string ToolIdentityResolver::hashFile(const std::filesystem::path& file) const {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (file.empty() || !fs::is_regular_file(file, ec) || ec) return {};

    std::ifstream in(file, std::ios::binary);
    if (!in) return {};

    if (sodium_init() < 0) return {};

    crypto_hash_sha256_state state;
    if (crypto_hash_sha256_init(&state) != 0) return {};

    std::vector<unsigned char> buf(64 * 1024);
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = in.gcount();
        if (n > 0) {
            crypto_hash_sha256_update(
                &state, buf.data(), static_cast<unsigned long long>(n));
        }
    }
    if (!in.eof()) return {};

    unsigned char digest[crypto_hash_sha256_BYTES];
    if (crypto_hash_sha256_final(&state, digest) != 0) return {};

    char hex[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), digest, sizeof(digest));
    return std::string(hex);
}

bool ToolIdentityResolver::resolve(ToolIdentity& id,
                                   const std::filesystem::path& executable,
                                   const std::filesystem::path& manifest) const {
    if (!executable.empty()) id.executableHash = hashFile(executable);
    if (!manifest.empty()) id.manifestHash = hashFile(manifest);
    return true;
}

std::string ToolIdentityResolver::identityKey(const ToolIdentity& id) {
    std::string key = id.provider;
    key += '|';
    key += id.toolId;
    if (!id.serverId.empty()) {
        key += '|';
        key += id.serverId;
    }
    return key;
}

namespace {

// Component match for grant→request identity. A granted value may use glob
// wildcards (`*`, `?`) so one grant can cover a family of tools, e.g.
// provider=mcp, toolId=*, serverId=github = "any tool from MCP server github".
// An empty granted value means "unbound" (matches anything) — preserving the
// simple builtin case where serverId is empty.
bool component_matches(const std::string& granted, const std::string& current) {
    if (granted.empty()) return true;
    std::string g = granted, c = current;
    std::transform(g.begin(), g.end(), g.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    std::transform(c.begin(), c.end(), c.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return PathSecurity::globMatch(c, g);
}

} // namespace

bool ToolIdentityResolver::matches(const ToolIdentity& granted, const ToolIdentity& current) {
    // Wildcard-aware identity match (provider / toolId / serverId).
    if (!component_matches(granted.provider, current.provider)) return false;
    if (!component_matches(granted.toolId, current.toolId)) return false;
    if (!component_matches(granted.serverId, current.serverId)) return false;

    // A grant bound to a specific hash is void if the current hash differs.
    // Empty granted hashes mean "unbound" (Phase 1 default) and skip the check.
    if (!granted.executableHash.empty() &&
        granted.executableHash != current.executableHash)
        return false;
    if (!granted.manifestHash.empty() &&
        granted.manifestHash != current.manifestHash)
        return false;
    return true;
}

} // namespace pm::security
