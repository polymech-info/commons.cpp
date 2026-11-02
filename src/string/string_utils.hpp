#pragma once
//
// Lightweight, dependency-free string + fuzzy-matching utilities.
//
// Also hosts path-shaped-string heuristics (`looks_like_path`, `path_leaf`,
// `path_ext_lower`) used by the launcher and shell resolver — no filesystem I/O,
// distinct from `media::path::looks_like_local_path` (rejects URLs) and
// `pm::vfs::ops::leaf_name` (scheme-aware URI leaf).
//
// Kept separate from argv expansion and from fuzzy matching. Filesystem
// normalization stays in `media::path`.
//
// Used for keyword/intent matching (e.g. info_lookup mapping a natural-language
// query onto CLI command text) without pulling in a full NLP stack. The design
// is deliberately small and cross-platform: a crude stemmer + normalised
// Levenshtein + a minimal domain glossary + coverage scoring. `fuzz_ratio` is a
// drop-in target for RapidFuzz if SIMD speed is ever needed.
//
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace media::strutil {

/// ASCII case-insensitive prefix (`vfs://`, `SSH://`, `HTTP://`).
/// The prefix is treated as ASCII; a non-ASCII code unit in `text` cannot match.
[[nodiscard]] inline bool starts_with_ascii_ci(
    std::string_view text,
    std::string_view prefix) noexcept
{
    if (text.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const auto a = static_cast<unsigned char>(text[i]);
        const auto b = static_cast<unsigned char>(prefix[i]);
        const auto al = (a >= 'A' && a <= 'Z') ? static_cast<unsigned char>(a - 'A' + 'a') : a;
        const auto bl = (b >= 'A' && b <= 'Z') ? static_cast<unsigned char>(b - 'A' + 'a') : b;
        if (al != bl)
            return false;
    }
    return true;
}

[[nodiscard]] inline bool starts_with_ascii_ci(
    std::wstring_view text,
    std::string_view prefix) noexcept
{
    if (text.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const auto raw = static_cast<unsigned>(text[i]);
        if (raw > 127)
            return false;
        const auto a = static_cast<unsigned char>(raw);
        const auto b = static_cast<unsigned char>(prefix[i]);
        const auto al = (a >= 'A' && a <= 'Z') ? static_cast<unsigned char>(a - 'A' + 'a') : a;
        const auto bl = (b >= 'A' && b <= 'Z') ? static_cast<unsigned char>(b - 'A' + 'a') : b;
        if (al != bl)
            return false;
    }
    return true;
}

// ── Path / URI display tokens ───────────────────────────────────────────────
//
// Heuristics on the string itself — no filesystem I/O. Distinct from:
//   media::path::looks_like_local_path  UTF-8, rejects `://` (real local paths)
//   pm::vfs::ops::leaf_name             scheme-aware VFS URI leaf

namespace detail {

template<typename Char>
[[nodiscard]] inline bool looks_like_path_impl(std::basic_string_view<Char> s) noexcept
{
    if (s.size() >= 2) {
        const Char drive = s[0];
        if (s[1] == static_cast<Char>(':')
            && ((drive >= static_cast<Char>('A') && drive <= static_cast<Char>('Z'))
                || (drive >= static_cast<Char>('a') && drive <= static_cast<Char>('z'))))
            return true;
        if (s[0] == static_cast<Char>('\\') && s[1] == static_cast<Char>('\\'))
            return true;
    }
    const Char scheme[] = {
        static_cast<Char>(':'), static_cast<Char>('/'), static_cast<Char>('/'), Char(0)
    };
    if (s.find(scheme) != std::basic_string_view<Char>::npos)
        return true;
    return s.find(static_cast<Char>('\\')) != std::basic_string_view<Char>::npos
        || s.find(static_cast<Char>('/')) != std::basic_string_view<Char>::npos;
}

template<typename Char>
[[nodiscard]] inline bool is_ascii_letter(Char c) noexcept
{
    return (c >= static_cast<Char>('A') && c <= static_cast<Char>('Z'))
        || (c >= static_cast<Char>('a') && c <= static_cast<Char>('z'));
}

template<typename Char>
[[nodiscard]] inline bool is_path_sep(Char c) noexcept
{
    return c == static_cast<Char>('\\') || c == static_cast<Char>('/');
}

template<typename Char>
[[nodiscard]] inline bool contains_url_scheme(std::basic_string_view<Char> s) noexcept
{
    const Char scheme[] = {
        static_cast<Char>(':'), static_cast<Char>('/'), static_cast<Char>('/'), Char(0)
    };
    return s.find(scheme) != std::basic_string_view<Char>::npos;
}

template<typename Char>
[[nodiscard]] inline bool is_absolute_drive_path(std::basic_string_view<Char> path) noexcept
{
    return path.size() >= 3
        && is_ascii_letter(path[0])
        && path[1] == static_cast<Char>(':')
        && is_path_sep(path[2]);
}

template<typename Char>
[[nodiscard]] inline std::basic_string<Char> path_leaf_impl(std::basic_string_view<Char> in)
{
    std::basic_string<Char> s(in);
    // `?#` end a URL. A local name may contain `#` (`report#2.png`).
    if (contains_url_scheme<Char>(s)) {
        const Char query[] = { static_cast<Char>('?'), static_cast<Char>('#'), Char(0) };
        const size_t q = s.find_first_of(query);
        if (q != std::basic_string<Char>::npos)
            s.resize(q);
    }
    while (!s.empty() && is_path_sep(s.back()))
        s.pop_back();
    const Char seps[] = { static_cast<Char>('\\'), static_cast<Char>('/'), Char(0) };
    const size_t slash = s.find_last_of(seps);
    if (slash != std::basic_string<Char>::npos)
        s = s.substr(slash + 1);
    return s;
}

template<typename Char>
[[nodiscard]] inline std::basic_string<Char> path_ext_lower_impl(std::basic_string_view<Char> path)
{
    std::basic_string<Char> s(path);
    const bool url = contains_url_scheme<Char>(s);
    if (url) {
        const Char cut[] = { static_cast<Char>('?'), static_cast<Char>('#'), Char(0) };
        const size_t q = s.find_first_of(cut);
        if (q != std::basic_string<Char>::npos)
            s.resize(q);
    }
    while (!s.empty() && is_path_sep(s.back()))
        s.pop_back();
    const Char seps[] = { static_cast<Char>('\\'), static_cast<Char>('/'), Char(0) };
    const size_t slash = s.find_last_of(seps);
    std::basic_string<Char> leaf = (slash == std::basic_string<Char>::npos)
        ? std::move(s) : s.substr(slash + 1);
    if (!url) {
        const size_t query = leaf.find(static_cast<Char>('?'));
        if (query != std::basic_string<Char>::npos)
            leaf.resize(query);
        const size_t dot = leaf.rfind(static_cast<Char>('.'));
        const size_t hash = leaf.find(static_cast<Char>('#'));
        if (dot != std::basic_string<Char>::npos
            && hash != std::basic_string<Char>::npos
            && hash > dot)
            leaf.resize(hash);
    }
    if (leaf.empty())
        return {};
    // `.gitignore` is a dotfile, not an extension. `.config.json` still yields `.json`.
    if (leaf.front() == static_cast<Char>('.')
        && leaf.find(static_cast<Char>('.'), 1) == std::basic_string<Char>::npos)
        return {};
    const size_t dot = leaf.rfind(static_cast<Char>('.'));
    if (dot == std::basic_string<Char>::npos || dot == 0)
        return {};
    std::basic_string<Char> ext = leaf.substr(dot);
    for (Char& c : ext) {
        if (c >= static_cast<Char>('A') && c <= static_cast<Char>('Z'))
            c = static_cast<Char>(c + (static_cast<Char>('a') - static_cast<Char>('A')));
    }
    return ext;
}

template<typename Char>
[[nodiscard]] inline bool is_windows_local_file_path_impl(std::basic_string_view<Char> path) noexcept
{
    if (path.size() >= 4
        && path[0] == static_cast<Char>('\\') && path[1] == static_cast<Char>('\\')
        && path[2] == static_cast<Char>('?') && path[3] == static_cast<Char>('\\')) {
        const auto rest = path.substr(4);
        if (rest.size() >= 4 && is_path_sep(rest[3])) {
            const Char u = rest[0] >= static_cast<Char>('A') && rest[0] <= static_cast<Char>('Z')
                ? static_cast<Char>(rest[0] - static_cast<Char>('A') + static_cast<Char>('a')) : rest[0];
            const Char n = rest[1] >= static_cast<Char>('A') && rest[1] <= static_cast<Char>('Z')
                ? static_cast<Char>(rest[1] - static_cast<Char>('A') + static_cast<Char>('a')) : rest[1];
            const Char c = rest[2] >= static_cast<Char>('A') && rest[2] <= static_cast<Char>('Z')
                ? static_cast<Char>(rest[2] - static_cast<Char>('A') + static_cast<Char>('a')) : rest[2];
            if (u == static_cast<Char>('u') && n == static_cast<Char>('n') && c == static_cast<Char>('c'))
                return false;
        }
        return is_absolute_drive_path(rest);
    }
    return is_absolute_drive_path(path);
}

} // namespace detail

/// Display heuristic: drive (`C:`), UNC (`\\`), URL (`://`), or any slash.
/// A MIME token such as `application/json` matches because of the slash.
/// Do not use this to split or rewrite process arguments.
[[nodiscard]] inline bool looks_like_path(std::string_view s) noexcept
{
    return detail::looks_like_path_impl<char>(s);
}
[[nodiscard]] inline bool looks_like_path(std::wstring_view s) noexcept
{
    return detail::looks_like_path_impl<wchar_t>(s);
}

/// Last path component. Strips a URL query/fragment and trailing slashes.
/// `#` in a local filename is kept.
[[nodiscard]] inline std::string path_leaf(std::string_view s)
{
    return detail::path_leaf_impl<char>(s);
}
[[nodiscard]] inline std::wstring path_leaf(std::wstring_view s)
{
    return detail::path_leaf_impl<wchar_t>(s);
}

/// `.ext` of the leaf, ASCII-lowercased. Empty for no extension and for a
/// leading-dot name (`.gitignore`). Query (`?`) and a fragment after the
/// extension (`file.png#preview`) are dropped. `folder.name/file` is empty.
[[nodiscard]] inline std::string path_ext_lower(std::string_view path)
{
    return detail::path_ext_lower_impl<char>(path);
}
[[nodiscard]] inline std::wstring path_ext_lower(std::wstring_view path)
{
    return detail::path_ext_lower_impl<wchar_t>(path);
}

/// Absolute drive path (`X:\` or `X:/`) or `\\?\X:\`. Drive-relative (`C:foo`),
/// a non-letter colon (`1:abc`), and `\\?\UNC\` are not local.
[[nodiscard]] inline bool is_windows_local_file_path(std::string_view path) noexcept
{
    return detail::is_windows_local_file_path_impl<char>(path);
}
[[nodiscard]] inline bool is_windows_local_file_path(std::wstring_view path) noexcept
{
    return detail::is_windows_local_file_path_impl<wchar_t>(path);
}

// ── Structured argv ─────────────────────────────────────────────────────────
//
// Element boundaries stay as the caller supplied them. The one expansion is a
// bare `${CURRENT_SELECTION}` element, which becomes one path argument each.
// Quoting and escaping happen at process launch, not here.

/// Expand `${CURRENT_SELECTION}` and normalize those paths. Every other
/// element is copied unchanged, including spaces, quotes, and apostrophes.
std::vector<std::string> normalize_command_args(
    const std::vector<std::string>& args,
    const std::vector<std::string>& selection_paths = {});

std::vector<std::wstring> normalize_command_args(
    const std::vector<std::wstring>& args,
    const std::vector<std::wstring>& selection_paths = {});

/// ASCII lower-case. Only `A`–`Z` fold; no locale.
std::string lower_ascii(std::string s);

/// Trim leading/trailing ASCII whitespace (space, tab, CR, LF).
std::string trim(std::string s);

/// Split into lower-cased ASCII alphanumeric tokens (keeps '-' and '_').
/// Bytes outside ASCII letters and digits are separators.
std::vector<std::string> tokenize(const std::string& text);

/// Crude English suffix stemmer: collapses inflections toward a common root
/// ("capturing"/"captured"/"captures" -> "captur..."). Exact stem equality is
/// not required by callers — final comparison is fuzzy.
std::string stem(std::string t);

/// Normalised Levenshtein similarity in [0,1]; 1.0 == identical.
/// Returns 0 when either side is longer than 64, or when the length gap
/// cannot reach 0.82 (`|m-n|/max > 0.18`).
double fuzz_ratio(const std::string& a, const std::string& b);

/// Minimal domain glossary: returns the synonym group containing `token`
/// (including `token`), or just `{token}`. Only genuine cross-lexical synonyms
/// that neither stemming nor edit-distance can bridge live here.
std::vector<std::string> glossary_expand(const std::string& token);

/// True for generic/function words that carry no selective signal.
bool is_stop_word(const std::string& t);

/// One query token matches a haystack token by whole-token equality, stem
/// equality, glossary, or fuzzy distance (`>= 0.82`, stem length `>= 4`).
/// Substring hits (`cat` inside `concatenate`) do not match.
bool token_matches(const std::vector<std::string>& hay_tokens,
                   const std::string& full_hay,
                   const std::string& qtok);

/// Coverage in [0,1]: fraction of meaningful query tokens that map onto the
/// haystack. An empty query scores 0. Repeated query tokens count once.
double match_score(const std::string& haystack, const std::string& query);

/// Boolean gate: at least half the meaningful query tokens map onto the
/// haystack (`match_score(haystack, query) >= 0.5`).
bool matches_query(const std::string& haystack, const std::string& query);

// ── ${var} substitution ───────────────────────────────────────────────────────
//
// Single left-to-right scan, not a regex and not recursive. A value that
// itself contains `${…}` is not expanded again. Nested `${a${b}}` is not a
// token. Names match `[A-Za-z0-9_:]+`, including a leading digit. Unresolved
// tokens stay literal; refusing them is the launch site's job.

using VariableResolver = std::function<std::optional<std::string>(std::string_view name)>;

/// First `${name}` (`[A-Za-z0-9_:]+`) in `input`, or empty.
[[nodiscard]] std::string first_variable_token(std::string_view input);
[[nodiscard]] std::string first_variable_token(std::wstring_view input);

/// First leftover `${name}` among the fields of a command about to run.
/// Empty arguments are ignored. A shell line is scanned too: `${name}` in
/// that charset is a command variable, not a shell expansion.
[[nodiscard]] std::string unresolved_launch_token(
    std::string_view executable,
    const std::vector<std::string>& args,
    std::string_view shell,
    std::string_view cwd,
    std::string_view open_path = {},
    std::string_view open_url = {});

[[nodiscard]] std::string unresolved_launch_token(
    std::wstring_view executable,
    const std::vector<std::wstring>& args,
    std::wstring_view shell,
    std::wstring_view cwd,
    std::wstring_view open_path = {},
    std::wstring_view open_url = {});

/// True when `input` contains at least one `${…}` token.
bool has_variable_tokens(const std::string& input);

/// When `input` is exactly `${name}`, returns trimmed `name`; otherwise nullopt.
std::optional<std::string> whole_variable_token(const std::string& input);

/// Replace `${name}` tokens via `resolve`. Whole-value `${name}` is replaced when
/// resolved. Unresolved tokens stay literal. Sets `*changed_out` when any token
/// was substituted.
std::string substitute_variables(const std::string& input,
                                 const VariableResolver& resolve,
                                 bool* changed_out = nullptr);

// ── Optional embedding backend ────────────────────────────────────────────────
//
// When FEATURE_LLAMA is enabled and a model is loaded, callers can register it
// here so that higher-level matching (e.g. info_lookup) can optionally fall back
// to semantic similarity when the lightweight scorer returns a low score.
//
// The bridge uses std::function to avoid including llama headers in this header.

#if (defined(FEATURE_LLAMA) && FEATURE_LLAMA) \
    || (defined(FEATURE_COMMAND_LLAMA_INFERENCE) && FEATURE_COMMAND_LLAMA_INFERENCE)

/// Signature of the semantic-match function supplied by the llama bridge.
/// Returns cosine similarity in [-1, 1] (>= 0.7 is a confident match).
using EmbedMatchFn = std::function<float(const std::string& query,
                                          const std::string& haystack)>;

/// Register (or clear with nullptr) the global embedding-match backend.
/// Thread-safe with respect to calls to embed_match_score / has_embed_backend.
/// Call once at startup after loading the model.
void set_embed_backend(EmbedMatchFn fn);

/// Returns true when an embedding backend has been registered.
bool has_embed_backend();

/// Cosine similarity from the registered backend (or -1 if not available).
float embed_match_score(const std::string& query, const std::string& haystack);

#endif // FEATURE_LLAMA || FEATURE_COMMAND_LLAMA_INFERENCE

} // namespace media::strutil
