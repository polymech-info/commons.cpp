#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace pm::filters {

// Gitignore pattern model. Flags match the roles in git's dir.h
// (PATTERN_FLAG_NODIR / ENDSWITH / MUSTBEDIR / NEGATIVE): a pattern with no
// slash matches the name in any directory, a trailing slash matches only a
// directory and everything under it, '!' negates, and the last match wins.
// This is an original matcher for those rules, not a copy of git's sources.
enum PatternFlag : unsigned {
    PatternNodir = 1,
    PatternEndswith = 4,
    PatternMustBeDir = 8,
    PatternNegative = 16,
};

struct PathPattern {
    std::string text;
    unsigned flags = 0;
    int line = 0;
};

struct PatternList {
    std::vector<PathPattern> patterns;
};

[[nodiscard]] PatternList parse_gitignore(std::string_view text);

// `rel` is relative to the ignore file's directory, with '/' separators.
// Returns the winning pattern, or nullptr when nothing matched.
[[nodiscard]] const PathPattern* last_match(
    const PatternList& list,
    std::string_view rel,
    bool is_dir);

} // namespace pm::filters
