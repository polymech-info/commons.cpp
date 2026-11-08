#include "fs/fs_guard.hpp"

#include "fs/glob_paths.hpp"
#include "fs/path_sanitizer.hpp"
#include "fs/file_extensions.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

#include <filesystem>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif
#include "string/string_utils.hpp"
#if defined(__APPLE__)
#include <sys/stat.h>
#endif

namespace media::llm {

namespace fs = std::filesystem;

namespace {


static bool str_starts_with_sv(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static bool str_ends_with_sv(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size()
        && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool path_matches_dir_prefix(std::string_view path, std::string_view dir_prefix) {
    if (dir_prefix.empty()) return path.empty();
    if (dir_prefix.back() != '/') return str_starts_with_sv(path, dir_prefix);
    if (str_starts_with_sv(path, dir_prefix)) return true;
    const std::string_view dir = dir_prefix.substr(0, dir_prefix.size() - 1);
    return path == dir;
}

// path::string() / generic_string() narrow through the ANSI code page and
// throw when a character does not fit. A U+FFFD from a bad pipe decode does that.
static std::string guard_path_utf8(const fs::path& p) {
    try {
        return media::path::path_to_utf8(p);
    } catch (...) {
        return {};
    }
}

static std::string norm_path_for_sensitive(const fs::path& abs) {
    std::string s = guard_path_utf8(abs);
    for (char& c : s)
        if (c == '\\') c = '/';
#if defined(_WIN32)
    s = media::strutil::lower_ascii(s);
#endif
    return s;
}

static std::string norm_sensitive_pattern_row(const char* row) {
    std::string s(row);
    for (char& c : s)
        if (c == '\\') c = '/';
#if defined(_WIN32)
    s = media::strutil::lower_ascii(s);
#endif
    return s;
}

#if defined(_WIN32)
static void retarget_windows_pattern_drive(std::string& pat, const std::string& norm_path) {
    if (norm_path.size() < 2 || norm_path[1] != ':' || pat.size() < 2 || pat[1] != ':') return;
    if (std::tolower(static_cast<unsigned char>(pat[0])) != 'c') return;
    pat[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(norm_path[0])));
}
#endif

static bool path_matches_star_pattern(std::string_view path, std::string_view pat) {
    const std::size_t star = pat.find('*');
    if (star == std::string_view::npos) {
        if (pat.empty()) return path.empty();
        if (pat.back() == '/') return str_starts_with_sv(path, pat);
        return path == pat;
    }
    const std::string_view left = pat.substr(0, star);
    if (!str_starts_with_sv(path, left)) return false;
    path.remove_prefix(left.size());
    const std::string_view patrest = pat.substr(star + 1);
    if (path.empty()) return false;
    const std::size_t slash = path.find('/');
    if (slash == std::string_view::npos) return path_matches_star_pattern(path, patrest);
    const std::string_view tail = path.substr(slash);
    return path_matches_star_pattern(tail, patrest);
}

static bool path_blocked_by_prefix_list(const fs::path& abs) {
    const std::string norm = norm_path_for_sensitive(abs);
    for (const char* const* pp = pmui::k_sensitive_path_prefixes; *pp; ++pp) {
        std::string pat = norm_sensitive_pattern_row(*pp);
#if defined(_WIN32)
        retarget_windows_pattern_drive(pat, norm);
#endif
        if (pat.find("**") != std::string::npos) {
            if (media::path_matches_path_glob(norm, pat)) return true;
            continue;
        }
        if (pat.find('*') != std::string::npos) {
            if (path_matches_star_pattern(norm, pat)) return true;
        } else if (!pat.empty() && pat.back() == '/') {
            if (path_matches_dir_prefix(norm, pat)) return true;
        } else {
            if (norm == pat) return true;
        }
    }
    return false;
}

static bool filename_is_dotfile(const fs::path& p) {
    const std::string fn = guard_path_utf8(p.filename());
    return !fn.empty() && fn[0] == '.';
}

#if defined(_WIN32)
static bool win_is_hidden(const fs::path& p) {
    const std::wstring w = p.wstring();
    const DWORD a = GetFileAttributesW(w.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    return (a & FILE_ATTRIBUTE_HIDDEN) != 0;
}
#endif

#if defined(__APPLE__)
static bool apple_is_uf_hidden(const fs::path& p) {
    struct stat st {};
    if (stat(media::path::path_to_utf8(p).c_str(), &st) != 0) return false;
    return (st.st_flags & UF_HIDDEN) != 0;
}
#endif

static bool file_has_platform_hidden(const fs::path& p) {
#if defined(_WIN32)
    if (win_is_hidden(p)) return true;
#elif defined(__APPLE__)
    if (apple_is_uf_hidden(p)) return true;
#endif
    (void)p;
    return false;
}

static bool write_ext_is_allowed_media(std::string_view ext) {
    for (const char* a : pmui::k_llm_write_allowed_media_exts) {
        if (ext == a) return true;
    }
    return false;
}

static bool write_abs_prefix_blocked_for_write(const std::string& norm) {
    for (const char* const* pp = pmui::k_llm_write_blocked_abs_prefixes; *pp; ++pp) {
        std::string pat = norm_sensitive_pattern_row(*pp);
#if defined(_WIN32)
        retarget_windows_pattern_drive(pat, norm);
#endif
        if (path_matches_dir_prefix(norm, pat)) return true;
    }
    return false;
}

static bool write_extension_in_blocklist(std::string_view ext) {
    for (const char* const* pp = pmui::k_llm_write_blocked_exts; *pp; ++pp) {
        if (ext == *pp) return true;
    }
    return false;
}

} // namespace

static fs::path normalize_guard_path(const fs::path& path) {
    const std::string cleaned = media::path::normalize_local_path(guard_path_utf8(path), true);
    if (cleaned.empty())
        return {};
    return media::path::path_from_utf8(cleaned);
}

std::string llm_fs_guard_write_deny_reason(const fs::path& path) {
    fs::path p = normalize_guard_path(path);
    if (p.empty())
        return "invalid path";
    std::error_code ec;
    if (fs::exists(p, ec)) {
        const fs::path c = fs::weakly_canonical(p, ec);
        if (!ec && !c.empty()) p = c;
    } else {
        p = p.lexically_normal();
    }

    const std::string norm = norm_path_for_sensitive(p);
    if (write_abs_prefix_blocked_for_write(norm)) return "refusing write to system or protected location";

    // Sensitive folders / credential files (git, npm, .ssh, cloud creds, …) must
    // never be written — checked BEFORE the media allowlist so a writable image
    // extension can't be used to plant a file inside e.g. ~/.ssh or ~/.git.
    if (path_blocked_by_prefix_list(p)) return "refusing write to sensitive path or filename";
    if (filename_is_dotfile(p)) return "refusing write to dot-named path";

    std::string ext = guard_path_utf8(p.extension());
    ext = media::strutil::lower_ascii(ext);
    if (write_ext_is_allowed_media(ext)) return {};
    if (write_extension_in_blocklist(ext)) {
        // Classify the blocked extension so the agent gets a recovery hint
        // instead of trial-and-error shell workarounds.
        for (const char* const* se = pmui::k_llm_write_script_exts; *se; ++se) {
            if (ext == *se) {
                const std::string stem = guard_path_utf8(p.stem());
                return std::string("script/batch extension '") + ext
                    + "' is not writable directly (security policy). "
                    "Write the content to '" + stem + ".txt' instead, "
                    "then use `run` with `cmd /c copy /y \"" + stem + ".txt\" \""
                    + stem + ext + "\"` to produce the final file. "
                    "Do NOT try PowerShell Out-File or echo redirects — they are fragile on Windows.";
            }
        }
        return std::string("refusing disallowed file type for write ('") + ext + "')";
    }
    return {};
}

bool llm_is_sensitive_path(const fs::path& path) {
    fs::path p = normalize_guard_path(path);
    if (p.empty())
        return true;
    std::error_code ec;
    if (fs::exists(p, ec)) {
        const fs::path c = fs::weakly_canonical(p, ec);
        if (!ec && !c.empty()) p = c;
    } else {
        p = p.lexically_normal();
    }
    return path_blocked_by_prefix_list(p);
}

namespace {

std::string llm_fs_guard_deny_reason_impl(const fs::path& path, bool allow_dot_and_hidden)
{
    fs::path p = normalize_guard_path(path);
    if (p.empty())
        return "invalid path";
    std::error_code ec;
    if (fs::exists(p, ec)) {
        const fs::path c = fs::weakly_canonical(p, ec);
        if (!ec && !c.empty()) p = c;
    } else {
        p = p.lexically_normal();
    }

    if (!allow_dot_and_hidden && filename_is_dotfile(p))
        return "refusing dot-named path";
    if (path_blocked_by_prefix_list(p))
        return "refusing sensitive path or filename";
    if (!allow_dot_and_hidden
        && fs::exists(p, ec)
        && file_has_platform_hidden(p)) {
        return "refusing hidden file";
    }
    return {};
}

} // namespace

std::string llm_fs_guard_deny_reason(const fs::path& path)
{
    return llm_fs_guard_deny_reason_impl(path, /*allow_dot_and_hidden=*/false);
}

std::string llm_fs_guard_viewer_deny_reason(const fs::path& path)
{
    return llm_fs_guard_deny_reason_impl(path, /*allow_dot_and_hidden=*/true);
}

} // namespace media::llm
