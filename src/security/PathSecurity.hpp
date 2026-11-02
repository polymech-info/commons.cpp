#pragma once
//
// pm::security::PathSecurity — strict path canonicalization and scope checks.
//
// Untrusted callers (LLM/MCP/plugins) must never get past prefix-string checks.
// This class canonicalizes a path, verifies containment with a real (resolved)
// comparison, and matches against glob/pathspec scopes.
//
// Phase 1 (this file): std::filesystem-based canonicalize + isInside + a small
// glob matcher. Win32 reparse-point / junction / UNC / TOCTOU handling is a
// Phase 2 TODO (see docs/security/todos.md).
//
// Design reference: docs/security/design.md ("Path security").
//

#include "security/types.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace pm::security {

/// A path that has been canonicalized (resolved, normalized). Wrapping the
/// resolved value in its own type makes "did you canonicalize?" a compile-time
/// concern rather than a convention.
struct CanonicalPath {
    std::filesystem::path value;
    bool resolved = false;  ///< true when the real on-disk path was resolved

    bool empty() const noexcept { return value.empty(); }
};

class PathSecurity {
public:
    /// Resolve symlinks/junctions and normalize @p p. Falls back to a lexical
    /// normalization when the path does not exist yet (e.g. write targets).
    CanonicalPath canonicalize(const std::filesystem::path& p) const;

    /// True when @p child is the same as or nested under @p root. Operates on
    /// already-canonicalized paths; never a raw string-prefix test.
    bool isInside(const CanonicalPath& child, const CanonicalPath& root) const;

    /// True when @p p matches any of the glob/pathspec @p scopes.
    bool matchesAnyScope(const CanonicalPath& p,
                         const std::vector<std::string>& scopes) const;

    /// Glob match for a single normalized (forward-slash) path against a single
    /// `**` / `*` / `?` pattern. Public for reuse by the classifier/policy.
    static bool globMatch(std::string_view path, std::string_view pattern) noexcept;

    /// Normalize to lowercase forward-slash form for matching (Windows-friendly).
    static std::string normalizeForMatch(const std::filesystem::path& p);
};

} // namespace pm::security
