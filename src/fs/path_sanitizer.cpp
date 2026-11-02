#include "fs/path_sanitizer.hpp"

#include "net/url_fetch.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <regex>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace media::path {

namespace {

void trim_in_place(std::string &s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(0, 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
}

void strip_utf8_bom(std::string &s) {
    if (s.size() >= 3 &&
        static_cast<unsigned char>(s[0]) == 0xEF &&
        static_cast<unsigned char>(s[1]) == 0xBB &&
        static_cast<unsigned char>(s[2]) == 0xBF)
        s.erase(0, 3);
}

// ASCII control chars (incl. \r \n \t \0) are invalid in Windows path components.
void strip_control_chars(std::string &s) {
    s.erase(std::remove_if(s.begin(), s.end(), [](unsigned char c) {
        return c < 0x20 || c == 0x7F;
    }), s.end());
}

// Mirrors media::str_san::clean_path duplicate-slash collapse, but keeps both
// `/` and `\` so Windows drive paths stay native until lexically_normal().
void collapse_duplicate_separators(std::string &s) {
    for (size_t i = 0; i < s.size();) {
        const char c = s[i];
        if (c == '/' || c == '\\') {
            size_t j = i + 1;
            while (j < s.size() && (s[j] == '/' || s[j] == '\\'))
                ++j;
            if (j > i + 1)
                s.erase(i + 1, j - (i + 1));
            else
                ++i;
        } else {
            ++i;
        }
    }
}

// Shared preflight for pasted/tool paths: BOM, outer whitespace, controls.
void sanitize_path_input(std::string &s) {
    strip_utf8_bom(s);
    trim_in_place(s);
    strip_control_chars(s);
    trim_in_place(s);
}

void decode_percent_escapes(std::string &s) {
    for (int p = 0; p < 4; ++p) {
        for (size_t i = 0; i + 2 < s.size(); ++i) {
            if (s[i] != '%') continue;
            const char a  = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i + 1])));
            const char b2 = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i + 2])));
            if (a == '2' && b2 == 'e') {
                s.replace(i, 3, 1, '.');
                i += 2;
            }
        }
        for (size_t i = 0; i + 2 < s.size(); ++i) {
            if (s[i] != '%') continue;
            const char a  = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i + 1])));
            const char b2 = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i + 2])));
            if (a == '2' && b2 == 'f') {
                s.replace(i, 3, 1, '/');
                i += 2;
            }
        }
        for (size_t i = 0; i + 2 < s.size(); ++i) {
            if (s[i] != '%') continue;
            const char a  = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i + 1])));
            const char b2 = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i + 2])));
            if (a == '5' && b2 == 'c') {
                s.replace(i, 3, 1, '\\');
                i += 2;
            }
        }
    }
}

void strip_not_allowed_for_path(std::string &s) {
    static const std::regex not_allowed(R"([:$!"`+|=])");
    s = std::regex_replace(s, not_allowed, std::string());
}

void slash_unify(std::string &s) {
    for (char &c : s) {
        if (c == '\\') c = '/';
    }
}

bool has_double_percent_encoding(const std::string &s) {
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        if (s[i] != '%') continue;
        if (std::tolower(static_cast<unsigned char>(s[i + 1])) == '2'
            && std::tolower(static_cast<unsigned char>(s[i + 2])) == '5')
            return true;
    }
    return false;
}

bool home_escape(const std::string &s) { return s == "~" || (s.size() >= 2 && s[0] == '~' && s[1] == '/'); }

bool looks_like_local_path_impl(const std::string &s) {
    if (s.empty() || s.find("${") != std::string::npos)
        return false;
    if (s.find("://") != std::string::npos)
        return false;
    if (s.size() >= 2 && std::isalpha(static_cast<unsigned char>(s[0])) && s[1] == ':')
        return true;
    if (s.size() >= 2 && s[0] == '\\' && s[1] == '\\')
        return true;
    if (s[0] == '/')
        return true;
    if (s.find(' ') == std::string::npos
        && (s.find('/') != std::string::npos || s.find('\\') != std::string::npos))
        return true;
    return false;
}

void decode_strip_slashform(const std::string &in, std::string &out) {
    out = in;
    decode_percent_escapes(out);
    strip_not_allowed_for_path(out);
    slash_unify(out);
}

/** Ref `sanitizeSubpath` traversal block (path-sanitizer.ts 111–120). */
bool subpath_traversal_violation(const std::string &normalized, std::string &err) {
    err.clear();
    const std::string   probe  = normalized + std::string("/");
    static const std::regex mid(R"(([/\\])\.\.([/\\]))");
    if (std::regex_search(probe, mid)) {
        err = "EFORBIDDEN: path traversal";
        return true;
    }
    if (normalized.rfind("../", 0) == 0) {
        err = "EFORBIDDEN: path traversal";
        return true;
    }
    if (normalized == "..") {
        err = "EFORBIDDEN: path traversal";
        return true;
    }
    if (normalized.size() >= 3 && normalized.substr(normalized.size() - 3) == "/..") {
        err = "EFORBIDDEN: path traversal";
        return true;
    }
    const std::string t = std::string("/") + normalized + std::string("/");
    if (t.find("/../") != std::string::npos) {
        err = "EFORBIDDEN: path traversal";
        return true;
    }
    return false;
}

bool pre_checks_vfs(const std::string &input, std::string &err) {
    if (input.find('\0') != std::string::npos) {
        err = "EFORBIDDEN: null byte in path";
        return false;
    }
    if (has_double_percent_encoding(input)) {
        err = "EFORBIDDEN: double-encoded path segment";
        return false;
    }
    if (home_escape(input)) {
        err = "EFORBIDDEN: home directory access denied";
        return false;
    }
    return true;
}

void utf8_truncate_255(std::string &s) {
    if (s.size() <= 255) return;
    s.resize(255);
    while (!s.empty() && (static_cast<unsigned char>(s.back()) & 0xc0) == 0x80) s.pop_back();
}

static void trim_segs_edges(std::string &seg) {
    while (!seg.empty() && (seg.front() == ' ' || seg.back() == ' ')) {
        if (seg.front() == ' ') seg.erase(0, 1);
        if (!seg.empty() && seg.back() == ' ') seg.pop_back();
    }
}

static bool remote_name_byte_forbidden(unsigned char c)
{
    if (c < 0x20 || c == 0x7f)
        return true;
    switch (c) {
    case '<': case '>': case ':': case '"': case '/': case '\\':
    case '|': case '?': case '*':
        return true;
    default:
        return false;
    }
}

static std::string clean_write_segment(const std::string &seg, bool is_last, bool all_dirs) {
    (void)is_last;
    (void)all_dirs;
    std::string out;
    out.reserve(seg.size());
    for (unsigned char c : seg) {
        if (!remote_name_byte_forbidden(c))
            out.push_back(static_cast<char>(c));
    }
    trim_segs_edges(out);
    if (out.size() > 200) {
        out.resize(200);
        while (!out.empty() && (static_cast<unsigned char>(out.back()) & 0xc0) == 0x80)
            out.pop_back();
        trim_segs_edges(out);
    }
    for (const char c : out) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return out;
    }
    return std::string();
}

} // namespace

bool looks_like_local_path(const std::string &s) {
    return looks_like_local_path_impl(s);
}

std::string sanitize_subpath(const std::string &input, std::string &err) {
    err.clear();
    std::string t = input;
    trim_in_place(t);
    if (t.empty()) return std::string();

    if (!pre_checks_vfs(t, err)) return std::string();

    std::string normalized;
    decode_strip_slashform(t, normalized);
    if (subpath_traversal_violation(normalized, err)) return std::string();

    std::string cleaned = normalized;
    while (!cleaned.empty() && cleaned[0] == '/')
        cleaned.erase(0, 1);
    if (cleaned.size() >= 2) {
        const char c0 = static_cast<char>(std::tolower(static_cast<unsigned char>(cleaned[0])));
        if (c0 >= 'a' && c0 <= 'z' && cleaned[1] == ':') {
            err = "EFORBIDDEN: absolute path";
            return std::string();
        }
    }

    std::string sanitized = cleaned;
    for (size_t i = 0; i < sanitized.size();) {
        if (sanitized[i] == '/') {
            size_t j = i + 1;
            while (j < sanitized.size() && sanitized[j] == '/') ++j;
            if (j > i + 1)
                sanitized.erase(i + 1, j - (i + 1));
            else
                ++i;
        } else
            ++i;
    }
    {
        const fs::path n = path_from_utf8(sanitized).lexically_normal();
        sanitized = path_to_generic_utf8(n);
    }
    slash_unify(sanitized);
    while (!sanitized.empty() && sanitized[0] == '/') sanitized.erase(0, 1);
    while (!sanitized.empty() && sanitized.back() == '/') sanitized.pop_back();
    if (sanitized == ".") sanitized.clear();

    size_t a = 0;
    for (size_t i = 0; i <= sanitized.size(); ++i) {
        if (i == sanitized.size() || sanitized[i] == '/') {
            if (a < i) {
                const std::string seg = sanitized.substr(a, i - a);
                if (seg == "..") {
                    err = "EFORBIDDEN: path traversal survived normalization";
                    return std::string();
                }
            }
            a = i + 1;
        }
    }
    return sanitized;
}

std::string sanitize_write_path(const std::string &subpath, std::string &err, bool is_directory) {
    (void)err;
    if (subpath.empty()) return std::string();
    const bool all_dirs = is_directory;
    std::string work   = subpath;
    for (char &c : work) {
        if (c == '\\') c = '/';
    }
    std::vector<std::string> segs;
    {
        size_t a = 0;
        for (size_t i = 0; i <= work.size(); ++i) {
            if (i == work.size() || work[i] == '/') {
                if (a < i) segs.push_back(work.substr(a, i - a));
                a = i + 1;
            }
        }
    }
    std::vector<std::string> cleaned;
    for (size_t i = 0; i < segs.size(); ++i) {
        if (segs[i].empty()) continue;
        const bool  is_last = (i + 1 == segs.size());
        std::string c       = clean_write_segment(segs[i], is_last, all_dirs);
        if (!c.empty()) cleaned.push_back(std::move(c));
    }
    std::string out;
    for (size_t i = 0; i < cleaned.size(); ++i) {
        if (i) out += '/';
        out += cleaned[i];
    }
    return out;
}

std::string sanitize_filename(const std::string &input, const std::string &replacement) {
    static const std::regex k_illegal(R"([/?<>\\:*|"])");
    static const std::regex k_ctrl(R"([\x00-\x1f\x80-\x9f])");
    static const std::regex k_dots(R"(^\.+$)");
    static const std::regex k_winres(R"(^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$)", std::regex::icase);
    static const std::regex k_trailds(R"([. ]+$)");
    std::string s = std::regex_replace(std::string(input), k_illegal, replacement);
    s = std::regex_replace(s, k_ctrl, replacement);
    s = std::regex_replace(s, k_dots, replacement);
    s = std::regex_replace(s, k_winres, replacement);
    s = std::regex_replace(s, k_trailds, replacement);
    utf8_truncate_255(s);
    return s;
}

bool is_safe_path_component(std::string_view name) {
    if (name.empty() || name == "." || name == "..") return false;
    if (name.find('\0') != std::string_view::npos) return false;
    if (name.size() > 255) return false;

    static const std::regex k_illegal(R"([/?<>\\:*|"])");
    static const std::regex k_ctrl(R"([\x00-\x1f\x80-\x9f])");
    static const std::regex k_winres(
        R"(^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$)",
        std::regex::icase);

    const std::string s(name);
    if (std::regex_search(s, k_illegal)) return false;
    if (std::regex_search(s, k_ctrl)) return false;
    if (std::regex_match(s, k_winres)) return false;
    return true;
}

std::string normalize_local_path(const std::string &input, bool force) {
    if (input.empty())
        return input;
    std::string s = input;
    sanitize_path_input(s);
    if (s.empty())
        return s;
    if (s.find("${") != std::string::npos)
        return s;
    if (s.find("://") != std::string::npos)
        return s;
    if (!force && !looks_like_local_path(s))
        return s;
    collapse_duplicate_separators(s);
    try {
        return path_to_utf8(fs::u8path(s).lexically_normal());
    } catch (...) {
        return force ? std::string{} : s;
    }
}

#if defined(_WIN32)
namespace {

std::wstring utf8_to_wide(std::string_view utf8) {
    if (utf8.empty()) return {};
    const int size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        utf8.data(),
        static_cast<int>(utf8.size()),
        nullptr,
        0);
    if (size <= 0) return {};
    std::wstring wide(static_cast<size_t>(size), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            utf8.data(),
            static_cast<int>(utf8.size()),
            wide.data(),
            size)
        != size) {
        return {};
    }
    return wide;
}

std::string wide_to_utf8(std::wstring_view wide) {
    if (wide.empty()) return {};
    const int size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        wide.data(),
        static_cast<int>(wide.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (size <= 0) return {};
    std::string utf8(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            wide.data(),
            static_cast<int>(wide.size()),
            utf8.data(),
            size,
            nullptr,
            nullptr)
        != size) {
        return {};
    }
    return utf8;
}

std::wstring strip_extended_prefix(std::wstring path) {
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        return L"\\\\" + path.substr(8);
    }
    if (path.rfind(L"\\\\?\\", 0) == 0) {
        return path.substr(4);
    }
    return path;
}

} // namespace

std::wstring normalize_local_path_w(const std::wstring& input, bool force) {
    if (input.empty()) return input;
    const std::string utf8 = wide_to_utf8(input);
    if (utf8.empty()) return {};
    const std::string normalized = normalize_local_path(utf8, force);
    if (normalized.empty()) return {};
    return utf8_to_wide(normalized);
}

bool is_safe_path_component_w(std::wstring_view name) noexcept {
    if (name.empty() || name == L"." || name == L"..") return false;
    if (name.size() > 255) return false;
    for (wchar_t ch : name) {
        if (ch < 32 || ch == 127) return false;
        switch (ch) {
        case L'/':
        case L'\\':
        case L':':
        case L'|':
        case L'?':
        case L'*':
        case L'"':
        case L'<':
        case L'>':
            return false;
        default:
            break;
        }
    }
    const std::string utf8 = wide_to_utf8(name);
    return !utf8.empty() && is_safe_path_component(utf8);
}

std::wstring path_compare_key_w(std::wstring path) {
    path = strip_extended_prefix(std::move(path));
    for (wchar_t& ch : path) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch - L'A' + L'a');
        } else if (ch == L'/') {
            ch = L'\\';
        }
    }
    while (path.size() > 3
        && (path.back() == L'\\' || path.back() == L'/')) {
        path.pop_back();
    }
    return path;
}
#endif

bool validate_path_spec_for_input_selection(const std::string &raw, std::string &err) {
    err.clear();
    if (is_http_url(raw)) return validate_url_spec_for_input_selection(raw, err);
    if (raw.find('\0') != std::string::npos) {
        err = "EFORBIDDEN: null byte in path";
        return false;
    }
    if (has_double_percent_encoding(raw)) {
        err = "EFORBIDDEN: double-encoded path segment";
        return false;
    }
    if (home_escape(raw)) {
        err = "EFORBIDDEN: home directory access denied";
        return false;
    }
    std::string normalized;
    decode_strip_slashform(raw, normalized);
    return !subpath_traversal_violation(normalized, err);
}

bool validate_url_spec_for_input_selection(const std::string &raw, std::string &err) {
    err.clear();
    if (raw.find('\0') != std::string::npos) {
        err = "EFORBIDDEN: null byte in URL";
        return false;
    }
    if (!is_http_url(raw)) {
        err = "url spec: not an http(s) URL (future schemes may be allowed here)";
        return false;
    }
    return true;
}

} // namespace media::path
