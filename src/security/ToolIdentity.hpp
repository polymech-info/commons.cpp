#pragma once
//
// pm::security::ToolIdentityResolver — hash-bound tool identity.
//
// Grants are bound to a tool's executable + manifest hash. When either changes,
// previously persisted grants must be invalidated (design.md "MCP rules",
// "Windows secure storage backend"). This resolver computes/refreshes the hash
// fields on a `ToolIdentity` and answers "does this request still match the
// identity a grant was issued for?".
//
// Phase 1 (this file): API surface + a stable identity key. SHA-256 hashing of
// the executable/manifest is a Phase 2 TODO (reuse the vendored picosha2).
//
// The `ToolIdentity` value type lives in types.hpp.
//

#include "security/types.hpp"

#include <filesystem>
#include <string>

namespace pm::security {

class ToolIdentityResolver {
public:
    /// Fill `executableHash` / `manifestHash` on @p id from the given files.
    /// No-op for files that do not exist. Returns false if hashing failed.
    bool resolve(ToolIdentity& id,
                 const std::filesystem::path& executable,
                 const std::filesystem::path& manifest) const;

    /// SHA-256 (hex) of a file's contents, or empty on failure.
    std::string hashFile(const std::filesystem::path& file) const;

    /// Stable key used to look up grants for this identity (provider+toolId+
    /// serverId). Hash binding is verified separately via `matches`.
    static std::string identityKey(const ToolIdentity& id);

    /// True when @p current is the same tool *and* its hashes still match
    /// @p granted. A hash mismatch means the grant must be invalidated.
    static bool matches(const ToolIdentity& granted, const ToolIdentity& current);
};

} // namespace pm::security
