#include "security/PathSecurity.hpp"

// Shared sanitizer utilities — used to keep path/pattern normalisation in sync
// with the rest of the codebase. str_san::clean_path is the reference for
// backslash→forward-slash and double-slash collapsing; path_sanitizer provides
// the subpath-validation API used by higher-level callers.
#include "string/string_sanitizers.hpp"
#include "fs/path_sanitizer.hpp"

#include <algorithm>
#include <cctype>
#include <system_error>

namespace pm::security {

namespace {

// Backtracking glob matcher supporting `**` (any depth), `*` (within a segment),
// and `?` (single char). Inputs are expected pre-normalized (lowercase, '/').
bool glob_impl(std::string_view s, std::string_view p) noexcept {
    std::size_t si = 0, pi = 0;
    std::size_t star = std::string_view::npos, star_s = 0;
    bool double_star = false;

    while (si < s.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
            ++si; ++pi;
        } else if (pi < p.size() && p[pi] == '*') {
            // Collapse "**" → cross-segment wildcard; "*" → within-segment.
            double_star = (pi + 1 < p.size() && p[pi + 1] == '*');
            star = pi;
            star_s = si;
            pi += double_star ? 2 : 1;
            // skip a trailing '/' right after "**/" so "a/**/b" matches "a/b"
            if (double_star && pi < p.size() && p[pi] == '/') ++pi;
        } else if (star != std::string_view::npos) {
            // Backtrack: let the last '*' consume s[star_s].
            if (!double_star && s[star_s] == '/') {
                // single '*' must not cross a segment boundary
                pi = star;
                star = std::string_view::npos;
                continue;
            }
            pi = star + (double_star ? 2 : 1);
            if (double_star && pi < p.size() && p[pi] == '/') ++pi;
            ++star_s;
            si = star_s;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;  // trailing stars match empty
    return pi == p.size();
}

/// Normalize a raw scope pattern (user-supplied glob) for case-insensitive matching:
///   1. Backslash → forward-slash (mirrors `media::str_san::clean_path` step 1).
///   2. Collapse consecutive forward-slashes (mirrors `clean_path` step 2).
///   3. Lowercase all characters.
///
/// Unlike `clean_path`, we deliberately preserve leading and trailing '/'
/// because security glob patterns use them as path anchors (e.g. "/etc/",
/// "**/windows/system32/config/").
std::string normalize_scope_pattern(std::string_view raw) {
    std::string s(raw);
    // Step 1 — backslash normalisation (same as media::str_san::clean_path).
    for (char& c : s)
        if (c == '\\') c = '/';
    // Step 2 — collapse "//+" → "/" (same as media::str_san::clean_path).
    for (std::size_t i = 0; i < s.size();) {
        if (s[i] == '/') {
            std::size_t j = i + 1;
            while (j < s.size() && s[j] == '/') ++j;
            if (j > i + 1)
                s.erase(i + 1, j - (i + 1));
            else
                ++i;
        } else {
            ++i;
        }
    }
    // Step 3 — lowercase.
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

std::string PathSecurity::normalizeForMatch(const std::filesystem::path& p) {
    // std::filesystem::path::generic_string() already uses '/' as separator, so
    // we only need to lowercase. The approach mirrors media::str_san (see
    // normalize_scope_pattern above) but operates on an already-canonical path.
    std::string s = p.generic_string();
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool PathSecurity::globMatch(std::string_view path, std::string_view pattern) noexcept {
    return glob_impl(path, pattern);
}

CanonicalPath PathSecurity::canonicalize(const std::filesystem::path& p) const {
    namespace fs = std::filesystem;
    std::error_code ec;

    // Prefer the real on-disk path (resolves symlinks). For not-yet-existing
    // targets (writes), fall back to lexically-normal weakly_canonical.
    fs::path real = fs::canonical(p, ec);
    if (!ec) {
        return CanonicalPath{real.lexically_normal(), /*resolved=*/true};
    }

    ec.clear();
    fs::path weak = fs::weakly_canonical(p, ec);
    if (!ec) {
        return CanonicalPath{weak.lexically_normal(), /*resolved=*/false};
    }

    // TODO(security, Phase 2): on Windows, resolve junctions/reparse points via
    // GetFinalPathNameByHandleW, normalize drive casing, and handle UNC paths;
    // re-check the real path *after* open to defeat TOCTOU swaps.
    return CanonicalPath{p.lexically_normal(), /*resolved=*/false};
}

bool PathSecurity::isInside(const CanonicalPath& child, const CanonicalPath& root) const {
    if (child.empty() || root.empty()) return false;

    auto rit = root.value.begin();
    auto cit = child.value.begin();
    for (; rit != root.value.end(); ++rit, ++cit) {
        if (cit == child.value.end()) return false;  // child is shorter than root
        if (*rit != *cit) return false;              // component-wise, not string-prefix
    }
    return true;  // every root component is a prefix of child's components
}

bool PathSecurity::matchesAnyScope(const CanonicalPath& p,
                                   const std::vector<std::string>& scopes) const {
    const std::string norm = normalizeForMatch(p.value);
    for (const auto& scope : scopes) {
        if (globMatch(norm, normalize_scope_pattern(scope))) return true;
    }
    return false;
}

} // namespace pm::security
