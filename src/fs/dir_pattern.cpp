#include "fs/dir_pattern.hpp"

#include <cctype>
#include <vector>

namespace pm::filters {
namespace {

char fold(char c)
{
#if defined(_WIN32)
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
#else
    return c;
#endif
}

bool eq_char(char a, char b)
{
    return fold(a) == fold(b);
}

bool wild_segment(std::string_view pat, std::string_view text)
{
    std::size_t pi = 0;
    std::size_t ti = 0;
    std::size_t star_p = std::string_view::npos;
    std::size_t star_t = std::string_view::npos;
    while (ti < text.size()) {
        if (pi < pat.size() && pat[pi] == '\\' && pi + 1 < pat.size()) {
            if (eq_char(pat[pi + 1], text[ti])) {
                pi += 2;
                ++ti;
                continue;
            }
        } else if (pi < pat.size() && pat[pi] == '[') {
            const std::size_t end = pat.find(']', pi + 1);
            if (end != std::string_view::npos && end > pi + 1) {
                bool neg = false;
                std::size_t i = pi + 1;
                if (pat[i] == '!') {
                    neg = true;
                    ++i;
                }
                bool hit = false;
                while (i < end) {
                    if (i + 2 < end && pat[i + 1] == '-') {
                        const unsigned char lo = static_cast<unsigned char>(fold(pat[i]));
                        const unsigned char hi = static_cast<unsigned char>(fold(pat[i + 2]));
                        const unsigned char ch = static_cast<unsigned char>(fold(text[ti]));
                        if (ch >= lo && ch <= hi)
                            hit = true;
                        i += 3;
                    } else {
                        if (eq_char(pat[i], text[ti]))
                            hit = true;
                        ++i;
                    }
                }
                if (hit != neg) {
                    pi = end + 1;
                    ++ti;
                    continue;
                }
            }
        } else if (pi < pat.size() && (pat[pi] == '?' || eq_char(pat[pi], text[ti]))) {
            ++pi;
            ++ti;
            continue;
        }
        if (pi < pat.size() && pat[pi] == '*') {
            star_p = pi++;
            star_t = ti;
            continue;
        }
        if (star_p != std::string_view::npos) {
            pi = star_p + 1;
            ti = ++star_t;
            continue;
        }
        return false;
    }
    while (pi < pat.size() && pat[pi] == '*')
        ++pi;
    return pi == pat.size();
}

void split(std::string_view s, std::vector<std::string_view>& out)
{
    out.clear();
    std::size_t i = 0;
    while (i <= s.size()) {
        const std::size_t j = s.find('/', i);
        if (j == std::string_view::npos) {
            out.push_back(s.substr(i));
            break;
        }
        out.push_back(s.substr(i, j - i));
        i = j + 1;
    }
}

bool path_wild(
    const std::vector<std::string_view>& path,
    std::size_t pi,
    const std::vector<std::string_view>& pat,
    std::size_t ti)
{
    if (ti == pat.size())
        return pi == path.size();
    if (pat[ti] == "**") {
        if (ti + 1 == pat.size())
            return true;
        if (path_wild(path, pi, pat, ti + 1))
            return true;
        if (pi < path.size() && path_wild(path, pi + 1, pat, ti))
            return true;
        return false;
    }
    if (pi >= path.size() || !wild_segment(pat[ti], path[pi]))
        return false;
    return path_wild(path, pi + 1, pat, ti + 1);
}

bool path_matches(std::string_view pattern, std::string_view rel)
{
    std::vector<std::string_view> path;
    std::vector<std::string_view> pat;
    split(rel, path);
    split(pattern, pat);
    return path_wild(path, 0, pat, 0);
}

std::string_view parent_rel(std::string_view rel)
{
    const auto slash = rel.rfind('/');
    if (slash == std::string_view::npos)
        return {};
    return rel.substr(0, slash);
}

std::string_view basename_of(std::string_view rel)
{
    const auto slash = rel.rfind('/');
    if (slash == std::string_view::npos)
        return rel;
    return rel.substr(slash + 1);
}

bool pattern_hits(const PathPattern& pattern, std::string_view rel, bool is_dir)
{
    if (pattern.text.empty() || rel.empty())
        return false;
    if ((pattern.flags & PatternMustBeDir) != 0) {
        if ((pattern.flags & PatternNodir) != 0) {
            std::vector<std::string_view> parts;
            split(rel, parts);
            for (std::size_t i = 0; i < parts.size(); ++i) {
                if (!wild_segment(pattern.text, parts[i]))
                    continue;
                if (i + 1 < parts.size())
                    return true;
                return is_dir;
            }
            return false;
        }
        if (path_matches(pattern.text, rel))
            return is_dir;
        for (std::string_view up = parent_rel(rel); !up.empty(); up = parent_rel(up)) {
            if (path_matches(pattern.text, up))
                return true;
        }
        return false;
    }
    if ((pattern.flags & PatternNodir) != 0)
        return wild_segment(pattern.text, basename_of(rel));
    return path_matches(pattern.text, rel);
}

void trim_trailing_spaces(std::string& line)
{
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
        if (line.size() >= 2 && line[line.size() - 2] == '\\')
            break;
        line.pop_back();
    }
}

std::string unescape(std::string_view in)
{
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 1 < in.size()) {
            out.push_back(in[++i]);
            continue;
        }
        out.push_back(in[i]);
    }
    return out;
}

} // namespace

PatternList parse_gitignore(std::string_view text)
{
    if (text.size() >= 3
        && static_cast<unsigned char>(text[0]) == 0xEF
        && static_cast<unsigned char>(text[1]) == 0xBB
        && static_cast<unsigned char>(text[2]) == 0xBF) {
        text.remove_prefix(3);
    }
    PatternList list;
    int line_no = 0;
    std::size_t i = 0;
    while (i <= text.size()) {
        const std::size_t nl = text.find('\n', i);
        std::string_view raw = text.substr(
            i, nl == std::string_view::npos ? text.size() - i : nl - i);
        i = nl == std::string_view::npos ? text.size() + 1 : nl + 1;
        ++line_no;
        if (!raw.empty() && raw.back() == '\r')
            raw.remove_suffix(1);
        if (raw.empty() || raw.front() == '#')
            continue;
        std::string line(raw);
        trim_trailing_spaces(line);
        if (line.empty())
            continue;
        unsigned flags = 0;
        std::string_view body = line;
        if (body.front() == '!') {
            flags |= PatternNegative;
            body.remove_prefix(1);
        }
        std::string pattern = unescape(body);
        if (pattern.empty())
            continue;
        if (pattern.back() == '/') {
            flags |= PatternMustBeDir;
            pattern.pop_back();
        }
        if (pattern.empty())
            continue;
        const bool anchored = pattern.front() == '/';
        if (anchored)
            pattern.erase(pattern.begin());
        if (pattern.empty())
            continue;
        if (!anchored && pattern.find('/') == std::string::npos)
            flags |= PatternNodir;
        if (pattern.size() >= 2 && pattern.front() == '*' && pattern.find_first_of("?[") == std::string::npos) {
            bool only_suffix = true;
            for (std::size_t c = 1; c < pattern.size(); ++c) {
                if (pattern[c] == '*')
                    only_suffix = false;
            }
            if (only_suffix)
                flags |= PatternEndswith;
        }
        PathPattern row;
        row.text = std::move(pattern);
        row.flags = flags;
        row.line = line_no;
        list.patterns.push_back(std::move(row));
    }
    return list;
}

const PathPattern* last_match(const PatternList& list, std::string_view rel, bool is_dir)
{
    for (auto it = list.patterns.rbegin(); it != list.patterns.rend(); ++it) {
        if (pattern_hits(*it, rel, is_dir))
            return &*it;
    }
    return nullptr;
}

} // namespace pm::filters
