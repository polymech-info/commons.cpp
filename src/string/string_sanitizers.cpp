#include "string_sanitizers.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace media::str_san {

namespace {

void trim_in_place(std::string &s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        s.clear();
        return;
    }
    const auto e = s.find_last_not_of(" \t\r\n");
    s = s.substr(b, e - b + 1);
}

bool ascii_iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ac = static_cast<unsigned char>(a[i]);
        unsigned char bc = static_cast<unsigned char>(b[i]);
        if (ac >= 'A' && ac <= 'Z') ac = static_cast<unsigned char>(ac - 'A' + 'a');
        if (bc >= 'A' && bc <= 'Z') bc = static_cast<unsigned char>(bc - 'A' + 'a');
        if (ac != bc) return false;
    }
    return true;
}

bool starts_with_ascii_ci(std::string_view s, size_t pos, std::string_view needle) {
    return pos <= s.size() && needle.size() <= s.size() - pos
        && ascii_iequal(s.substr(pos, needle.size()), needle);
}

std::string strip_utf8_bom(std::string_view raw) {
    if (raw.size() >= 3
        && static_cast<unsigned char>(raw[0]) == 0xEF
        && static_cast<unsigned char>(raw[1]) == 0xBB
        && static_cast<unsigned char>(raw[2]) == 0xBF)
        raw.remove_prefix(3);
    return std::string(raw);
}

std::string repair_invalid_utf8(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size();) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        if (c <= 0x7F) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        auto cont = [&](size_t off) -> bool {
            if (i + off >= raw.size()) return false;
            const unsigned char x = static_cast<unsigned char>(raw[i + off]);
            return (x & 0xC0) == 0x80;
        };
        if (c >= 0xC2 && c <= 0xDF && cont(1)) {
            out.append(raw.substr(i, 2));
            i += 2;
            continue;
        }
        if (c >= 0xE0 && c <= 0xEF && cont(1) && cont(2)) {
            const unsigned char c1 = static_cast<unsigned char>(raw[i + 1]);
            if ((c != 0xE0 || c1 >= 0xA0) && (c != 0xED || c1 <= 0x9F)) {
                out.append(raw.substr(i, 3));
                i += 3;
                continue;
            }
        }
        if (c >= 0xF0 && c <= 0xF4 && cont(1) && cont(2) && cont(3)) {
            const unsigned char c1 = static_cast<unsigned char>(raw[i + 1]);
            if ((c != 0xF0 || c1 >= 0x90) && (c != 0xF4 || c1 <= 0x8F)) {
                out.append(raw.substr(i, 4));
                i += 4;
                continue;
            }
        }
        // Replace invalid sequences before later filters decide whether to keep
        // non-ASCII. This preserves validity if callers only request repair.
        out += "\xEF\xBF\xBD";
        ++i;
    }
    return out;
}

std::string strip_non_ascii_except_text_controls(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (unsigned char c : raw) {
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7E))
            out.push_back(static_cast<char>(c));
    }
    return out;
}

std::string strip_html_comments(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size();) {
        if (i + 4 <= raw.size() && raw.substr(i, 4) == "<!--") {
            const size_t end = raw.find("-->", i + 4);
            if (end == std::string_view::npos)
                break;
            i = end + 3;
            continue;
        }
        out.push_back(raw[i++]);
    }
    return out;
}

bool is_dangerous_html_tag(std::string_view tag) {
    static constexpr std::string_view k_tags[] = {
        "script", "style", "iframe", "object", "embed", "svg", "math",
        "meta", "link", "base", "form", "input", "button", "textarea",
        "select", "option", "noscript",
    };
    return std::any_of(std::begin(k_tags), std::end(k_tags),
                       [&](std::string_view t) { return ascii_iequal(tag, t); });
}

std::string parse_tag_name(std::string_view raw, size_t lt_pos, bool& closing) {
    closing = false;
    size_t i = lt_pos + 1;
    if (i < raw.size() && raw[i] == '/') {
        closing = true;
        ++i;
    }
    while (i < raw.size() && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\r' || raw[i] == '\n'))
        ++i;
    const size_t start = i;
    while (i < raw.size()) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == ':') {
            ++i;
            continue;
        }
        break;
    }
    return std::string(raw.substr(start, i - start));
}

std::string strip_html_dangerous_elements(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size();) {
        const size_t lt = raw.find('<', i);
        if (lt == std::string_view::npos) {
            out.append(raw.substr(i));
            break;
        }
        out.append(raw.substr(i, lt - i));

        bool closing = false;
        const std::string tag = parse_tag_name(raw, lt, closing);
        if (tag.empty() || !is_dangerous_html_tag(tag)) {
            out.push_back(raw[lt]);
            i = lt + 1;
            continue;
        }

        const size_t tag_end = raw.find('>', lt + 1);
        if (tag_end == std::string_view::npos)
            break;
        if (closing) {
            i = tag_end + 1;
            continue;
        }

        const std::string close = "</" + tag + ">";
        size_t search = tag_end + 1;
        size_t close_pos = std::string_view::npos;
        while (search < raw.size()) {
            const size_t next_lt = raw.find('<', search);
            if (next_lt == std::string_view::npos) break;
            if (starts_with_ascii_ci(raw, next_lt, close)) {
                close_pos = next_lt;
                break;
            }
            search = next_lt + 1;
        }
        if (close_pos == std::string_view::npos) {
            i = tag_end + 1; // void-ish dangerous tag; strip opening element only
        } else {
            const size_t close_end = raw.find('>', close_pos + 2);
            i = (close_end == std::string_view::npos) ? raw.size() : close_end + 1;
        }
    }
    return out;
}

void append_utf8_codepoint(std::string& out, std::uint32_t cp)
{
    if (cp == 0)
        return; // PostgreSQL json/jsonb rejects NUL even when escaped as \u0000.
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool looks_like_utf16le(std::string_view bytes)
{
    const size_t sample = std::min<size_t>(bytes.size(), 4096);
    if (sample < 4)
        return false;
    size_t odd_nul = 0;
    size_t even_nul = 0;
    for (size_t i = 0; i < sample; ++i) {
        if (bytes[i] != '\0')
            continue;
        if ((i % 2) == 0)
            ++even_nul;
        else
            ++odd_nul;
    }
    return odd_nul > sample / 8 && odd_nul > even_nul * 4;
}

bool looks_like_utf16be(std::string_view bytes)
{
    const size_t sample = std::min<size_t>(bytes.size(), 4096);
    if (sample < 4)
        return false;
    size_t odd_nul = 0;
    size_t even_nul = 0;
    for (size_t i = 0; i < sample; ++i) {
        if (bytes[i] != '\0')
            continue;
        if ((i % 2) == 0)
            ++even_nul;
        else
            ++odd_nul;
    }
    return even_nul > sample / 8 && even_nul > odd_nul * 4;
}

std::string utf16_bytes_to_utf8(std::string_view bytes, bool little_endian, size_t offset)
{
    std::string out;
    out.reserve(bytes.size());
    for (size_t i = offset; i + 1 < bytes.size(); i += 2) {
        auto read_unit = [&](size_t pos) -> std::uint16_t {
            const auto a = static_cast<unsigned char>(bytes[pos]);
            const auto b = static_cast<unsigned char>(bytes[pos + 1]);
            return little_endian ? static_cast<std::uint16_t>(a | (b << 8))
                                 : static_cast<std::uint16_t>((a << 8) | b);
        };

        std::uint32_t cp = read_unit(i);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < bytes.size()) {
            const std::uint32_t lo = read_unit(i + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
                i += 2;
            }
        }
        append_utf8_codepoint(out, cp);
    }
    return out;
}

std::string strip_nul_bytes(std::string s)
{
    s.erase(std::remove(s.begin(), s.end(), '\0'), s.end());
    return s;
}

} // namespace

std::string clean_path(std::string_view raw) {
    std::string s(raw);
    for (char &c : s) {
        if (c == '\\')
            c = '/';
    }
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '/') {
            size_t j = i + 1;
            while (j < s.size() && s[j] == '/')
                ++j;
            if (j > i + 1) {
                s.erase(i + 1, j - (i + 1));
            } else
                ++i;
        } else
            ++i;
    }
    while (!s.empty() && s[0] == '/')
        s.erase(0, 1);
    while (!s.empty() && s.back() == '/')
        s.pop_back();
    return s;
}

std::vector<std::string> path_segments(std::string_view raw) {
    const std::string c = clean_path(raw);
    if (c.empty())
        return {};
    std::vector<std::string> out;
    size_t a = 0;
    for (size_t i = 0; i <= c.size(); ++i) {
        if (i == c.size() || c[i] == '/') {
            if (a < i)
                out.emplace_back(c, a, i - a);
            a = i + 1;
        }
    }
    return out;
}

std::string normalise_path(std::string_view raw) {
    const std::string c = clean_path(raw);
    if (c.empty())
        return "/";
    return "/" + c;
}

std::string clean_uuid(std::string_view raw, std::string &err) {
    err.clear();
    std::string id(raw);
    trim_in_place(id);
    for (char &c : id) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    static const std::regex k_uuid(
        R"(^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)",
        std::regex::icase);
    if (!std::regex_match(id, k_uuid)) {
        err = "Invalid UUID: '";
        err += id;
        err += "'";
        return {};
    }
    return id;
}

bool is_uuid(std::string_view raw) {
    std::string t(raw);
    trim_in_place(t);
    for (char &c : t) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    static const std::regex k_uuid(
        R"(^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)",
        std::regex::icase);
    return std::regex_match(t, k_uuid);
}

std::string clean_id(std::string_view raw, std::string &err) {
    err.clear();
    std::string t(raw);
    trim_in_place(t);
    for (char &c : t) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    if (t == k_anonymous_user_id) return std::string(k_anonymous_user_id);
    if (t == k_authenticated_user_id) return std::string(k_authenticated_user_id);
    return clean_uuid(t, err);
}

std::string clean_group_name(std::string_view raw, std::string &err) {
    err.clear();
    std::string t(raw);
    trim_in_place(t);
    for (char &c : t) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    if (t.empty()) {
        err = "Group name cannot be empty";
        return {};
    }
    if (t.find(':') != std::string::npos) {
        err = "Group name cannot contain ':': " + t;
        return {};
    }
    return t;
}

std::string clean_permission(std::string_view raw, std::string &err) {
    err.clear();
    std::string t(raw);
    trim_in_place(t);
    for (char &c : t) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    if (t.empty()) {
        err = "Permission name cannot be empty";
        return {};
    }
    return t;
}

std::vector<std::string> clean_permissions(const std::vector<std::string> &raw, std::string &err) {
    err.clear();
    std::vector<std::string> out;
    out.reserve(raw.size());
    for (const auto &s : raw) {
        std::string t = clean_permission(s, err);
        if (!err.empty()) return {};
        out.push_back(std::move(t));
    }
    return out;
}

std::string apply_text_sanitizer(std::string_view raw, TextSanitizer sanitizer) {
    switch (sanitizer) {
        case TextSanitizer::StripUtf8Bom:
            return strip_utf8_bom(raw);
        case TextSanitizer::RepairInvalidUtf8:
            return repair_invalid_utf8(raw);
        case TextSanitizer::StripNonAsciiExceptTextControls:
            return strip_non_ascii_except_text_controls(raw);
        case TextSanitizer::StripHtmlComments:
            return strip_html_comments(raw);
        case TextSanitizer::StripHtmlDangerousElements:
            return strip_html_dangerous_elements(raw);
    }
    return std::string(raw);
}

std::string apply_text_sanitizers(std::string_view raw, const TextSanitizer* sanitizers, std::size_t count) {
    std::string out(raw);
    for (std::size_t i = 0; i < count; ++i)
        out = apply_text_sanitizer(out, sanitizers[i]);
    return out;
}

std::size_t utf8_safe_prefix_len(std::string_view s, std::size_t max_bytes)
{
    if (max_bytes >= s.size())
        return s.size();
    std::size_t n = max_bytes;
    std::size_t start = n;
    while (start > 0 && (static_cast<unsigned char>(s[start]) & 0xC0) == 0x80)
        --start;
    if (start == n)
        return n;
    const unsigned char lead = static_cast<unsigned char>(s[start]);
    std::size_t need = 1;
    if (lead >= 0xC2 && lead <= 0xDF) need = 2;
    else if (lead >= 0xE0 && lead <= 0xEF) need = 3;
    else if (lead >= 0xF0 && lead <= 0xF4) need = 4;
    else return start;
    return (start + need <= n) ? n : start;
}

std::string utf8_safe_prefix(std::string_view s, std::size_t max_bytes)
{
    return std::string(s.substr(0, utf8_safe_prefix_len(s, max_bytes)));
}

std::size_t utf8_safe_suffix_len(std::string_view s, std::size_t max_bytes)
{
    if (s.empty() || max_bytes == 0)
        return 0;
    std::size_t start = s.size() > max_bytes ? s.size() - max_bytes : 0;
    while (start < s.size()
           && (static_cast<unsigned char>(s[start]) & 0xC0) == 0x80)
        ++start;
    if (start >= s.size())
        return 0;
    return s.size() - start;
}

std::string utf8_safe_suffix(std::string_view s, std::size_t max_bytes)
{
    const std::size_t n = utf8_safe_suffix_len(s, max_bytes);
    if (n == 0)
        return {};
    return std::string(s.substr(s.size() - n));
}

std::string utf8_safe_ellipsize(std::string_view s, std::size_t max_bytes,
                                std::string_view ellipsis)
{
    if (s.size() <= max_bytes)
        return std::string(s);
    const std::size_t reserve = ellipsis.size();
    const std::size_t budget = max_bytes > reserve ? max_bytes - reserve : 0;
    std::string out = utf8_safe_prefix(s, budget);
    out.append(ellipsis);
    return out;
}

std::string normalise_text_for_json_storage(std::string_view raw)
{
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF
        && static_cast<unsigned char>(raw[1]) == 0xFE) {
        return repair_invalid_utf8(utf16_bytes_to_utf8(raw, true, 2));
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFE
        && static_cast<unsigned char>(raw[1]) == 0xFF) {
        return repair_invalid_utf8(utf16_bytes_to_utf8(raw, false, 2));
    }
    if (looks_like_utf16le(raw))
        return repair_invalid_utf8(utf16_bytes_to_utf8(raw, true, 0));
    if (looks_like_utf16be(raw))
        return repair_invalid_utf8(utf16_bytes_to_utf8(raw, false, 0));

    return strip_nul_bytes(repair_invalid_utf8(strip_utf8_bom(raw)));
}

std::string assert_non_empty_str(std::string_view value, std::string_view label, std::string &err) {
    err.clear();
    for (const char c : value) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c != 0) return std::string(value);
    }
    err = std::string(label);
    err += " cannot be empty";
    return {};
}

static bool is_blank(std::string_view s) {
    for (const char c : s) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return false;
    }
    return true;
}

bool assert_non_empty_list(const std::vector<std::string> &values, std::string_view label, std::string &err) {
    err.clear();
    for (const auto &s : values) {
        if (s.empty() || is_blank(s)) {
            err = std::string(label);
            err += " cannot be empty";
            return false;
        }
    }
    return true;
}

} // namespace media::str_san
