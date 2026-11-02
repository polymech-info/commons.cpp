#include "fs/glob_paths.hpp"

#include "output_path.hpp"
#include "fs/path_sanitizer.hpp"
#include "net/url_fetch.hpp"

#include <glob/glob.h>

#include <algorithm>
#include <cctype>
#include <regex>
#include <set>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace media {

namespace {

bool trailing_sep(const std::string &s) {
    return !s.empty() && (s.back() == '/' || s.back() == '\\');
}

static void trim_in_place(std::string &s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(0, 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
}

// ── Image extension sets ──────────────────────────────────────────────────────
// One set used by both is_supported_image_extension and
// path_leaf_looks_like_explicit_image_file (the latter only considers
// lossless/web formats, not RAW, so a separate trimmed set is kept).

const std::unordered_set<std::string> &web_image_exts() {
    static const std::unordered_set<std::string> k{
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".tiff", ".tif", ".jpe", ".jfif", ".avif", ".heic", ".jf",
    };
    return k;
}

const std::unordered_set<std::string> &all_image_exts() {
    static const std::unordered_set<std::string> k = [] {
        auto s = web_image_exts();
        for (const char *e : {".arw", ".cr2", ".cr3", ".nef", ".nrw", ".dng",
                               ".orf", ".rw2", ".raf", ".pef", ".srw", ".x3f",
                               ".3fr", ".mef", ".mrw"})
            s.insert(e);
        return s;
    }();
    return k;
}

void ext_to_lower_ascii(std::string &e) {
    for (char &c : e)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
}

bool is_supported_image_extension(const std::string &ext_with_dot) {
    std::string e = ext_with_dot;
    ext_to_lower_ascii(e);
    return all_image_exts().count(e) > 0;
}

bool path_leaf_looks_like_explicit_image_file(const fs::path &p) {
    std::string ext = p.extension().string();
    if (ext.empty()) return false;
    ext_to_lower_ascii(ext);
    return web_image_exts().count(ext) > 0;
}

// ── Brace expansion ───────────────────────────────────────────────────────────
// Expands the first {a,b,c} group in `raw` into one string per alternative.
// E.g. "foo/*.{cmd,exe}" → {"foo/*.cmd", "foo/*.exe"}.
// Only one brace group per call; call recursively for nested/multiple groups.

std::vector<std::string> expand_brace_glob_specs(const std::string &raw) {
    static const std::regex k_brace(R"(^(.*?)\{([^{}]*,[^{}]*)\}(.*)$)");
    std::smatch m;
    if (!std::regex_match(raw, m, k_brace))
        return {raw};

    const std::string prefix = m[1].str();
    const std::string inner  = m[2].str();
    const std::string suffix = m[3].str();

    static const std::regex k_comma(",");
    std::vector<std::string> parts;
    std::sregex_token_iterator it(inner.begin(), inner.end(), k_comma, -1), end;
    for (; it != end; ++it) {
        std::string token = it->str();
        trim_in_place(token);
        if (!token.empty())
            parts.push_back(prefix + token + suffix);
    }
    return parts.empty() ? std::vector<std::string>{raw} : parts;
}

} // anonymous namespace — closed early so expand_home_dir is in media:: scope

std::string expand_home_dir(std::string s) {
    if (s.empty() || s[0] != '~') return s;
    if (s.size() >= 2 && s[1] != '/' && s[1] != '\\') return s;

    std::string home;
#if defined(_WIN32)
    if (const char* h = std::getenv("USERPROFILE"); h && *h) {
        home = h;
    } else {
        const char* drv = std::getenv("HOMEDRIVE");
        const char* pth = std::getenv("HOMEPATH");
        if (drv && pth && *drv && *pth) home = std::string(drv) + pth;
    }
#else
    if (const char* h = std::getenv("HOME"); h && *h) home = h;
#endif
    if (home.empty()) return s;
    if (s.size() == 1) return home;
    return home + s.substr(1);
}

namespace {

void replace_all(std::string &s, const std::string &from, const std::string &to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.length(), to);
        pos += to.length();
    }
}

/** Apply `${SRC_*}` and `&{SRC_*}` using absolute input path or URL parts. */
fs::path resolve_dst_template(const std::string &input_spec, const std::string &tmpl) {
    std::string dir, stem, ext;
    if (is_http_url(input_spec)) {
        url_template_variables(input_spec, dir, stem, ext);
    } else {
        const fs::path input_abs = fs::absolute(path::path_from_utf8(input_spec));
        dir  = path::path_to_generic_utf8(input_abs.parent_path());
        stem = path::path_to_utf8(input_abs.stem());
        ext  = path::path_to_utf8(input_abs.extension());
    }

    std::string s = tmpl;
    replace_all(s, "${SRC_FILE_EXT}", ext);
    replace_all(s, "&{SRC_FILE_EXT}", ext);
    replace_all(s, "${SRC_NAME}",     stem);
    replace_all(s, "&{SRC_NAME}",     stem);
    replace_all(s, "${SRC_DIR}",      dir);
    replace_all(s, "&{SRC_DIR}",      dir);

    fs::path out = path::path_from_utf8(s);
    if (!out.is_absolute()) out = fs::absolute(out);
    return out.lexically_normal();
}

// ── Path-glob matching ────────────────────────────────────────────────────────

void split_path_segments(std::string_view s, std::vector<std::string_view> &out) {
    out.clear();
    std::size_t i = 0;
    while (i <= s.size()) {
        const std::size_t j = s.find('/', i);
        if (j == std::string_view::npos) { out.push_back(s.substr(i)); break; }
        out.push_back(s.substr(i, j - i));
        i = j + 1;
    }
}

void collapse_adjacent_double_stars(std::vector<std::string_view> &tok) {
    std::vector<std::string_view> collapsed;
    collapsed.reserve(tok.size());
    for (std::string_view t : tok) {
        if (t == "**" && !collapsed.empty() && collapsed.back() == "**") continue;
        collapsed.push_back(t);
    }
    tok.swap(collapsed);
}

bool segment_matches(std::string_view seg, std::string_view pat) {
    std::size_t si = 0, pi = 0;
    std::size_t star_si = std::string_view::npos, star_pi = std::string_view::npos;
    while (si < seg.size()) {
        if (pi < pat.size() && (pat[pi] == '?' || pat[pi] == seg[si])) { ++pi; ++si; continue; }
        if (pi < pat.size() && pat[pi] == '*') { star_pi = pi++; star_si = si; continue; }
        if (star_si != std::string_view::npos) { pi = star_pi + 1; si = ++star_si; continue; }
        return false;
    }
    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}

bool path_segments_match_glob(const std::vector<std::string_view> &path_segs, std::size_t pi,
                              const std::vector<std::string_view> &pat_segs, std::size_t ti) {
    if (ti == pat_segs.size()) return pi == path_segs.size();
    if (pat_segs[ti] == "**") {
        if (ti + 1 == pat_segs.size()) return true;
        if (path_segments_match_glob(path_segs, pi,     pat_segs, ti + 1)) return true;
        if (pi < path_segs.size() &&
            path_segments_match_glob(path_segs, pi + 1, pat_segs, ti))     return true;
        return false;
    }
    if (pi >= path_segs.size() || !segment_matches(path_segs[pi], pat_segs[ti])) return false;
    return path_segments_match_glob(path_segs, pi + 1, pat_segs, ti + 1);
}

void collect_images_recursive(const fs::path &dir, std::set<std::string> &out) {
    std::error_code ec;
    fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
    if (ec) return;
    const fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) break;
        std::error_code fe;
        if (!it->is_regular_file(fe) || fe) continue;
        const std::string ext = it->path().extension().string();
        if (!is_supported_image_extension(ext)) continue;
        fs::path canon = fs::weakly_canonical(it->path(), fe);
        if (fe) canon = fs::absolute(it->path());
        out.insert(path::path_to_generic_utf8(canon));
    }
}

bool ext_alt_ok(const std::string &token) {
    if (token.empty()) return false;
    for (unsigned char c : token) {
        if (c == '*' || c == '?' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' || c == '\\')
            return false;
    }
    return true;
}

std::string fold_ext(std::string e) {
#if defined(_WIN32)
    ext_to_lower_ascii(e);
#endif
    return e;
}

// One walk for brace-extension globs (e.g. dir/**/*.{png,jpg,webp}) instead of N glob walks.
bool try_expand_extension_brace_glob(const std::string &spec, std::vector<std::string> &out,
                                     std::string &err_out) {
    out.clear();
    const std::size_t close = spec.rfind('}');
    const std::size_t open  = spec.rfind('{');
    if (close != spec.size() - 1 || open == std::string::npos || open < 2)
        return false;
    if (spec[open - 1] != '.' || spec[open - 2] != '*')
        return false;

    std::unordered_set<std::string> exts;
    std::string inner = spec.substr(open + 1, close - open - 1);
    std::string token;
    auto flush = [&]() {
        trim_in_place(token);
        if (token.empty()) return true;
        if (!ext_alt_ok(token)) return false;
        if (token.front() != '.') token.insert(token.begin(), '.');
        if (token.find('.', 1) != std::string::npos) return false;
        exts.insert(fold_ext(std::move(token)));
        token.clear();
        return true;
    };
    for (char c : inner) {
        if (c == ',') {
            if (!flush()) return false;
        } else {
            token.push_back(c);
        }
    }
    if (!flush() || exts.size() < 2)
        return false;

    std::string star_prefix = spec.substr(0, open - 1); // includes trailing '*'
    for (char &c : star_prefix)
        if (c == '\\') c = '/';

    bool recursive = false;
    std::string root;
    if (star_prefix == "**/*") {
        recursive = true;
        root = ".";
    } else if (star_prefix == "*") {
        root = ".";
    } else if (star_prefix.size() >= 4 && star_prefix.compare(star_prefix.size() - 4, 4, "/**/*") == 0) {
        recursive = true;
        root = star_prefix.substr(0, star_prefix.size() - 4);
    } else if (star_prefix.size() >= 2 && star_prefix.compare(star_prefix.size() - 2, 2, "/*") == 0) {
        root = star_prefix.substr(0, star_prefix.size() - 2);
    } else {
        return false;
    }
    if (root.empty()) root = ".";
    if (has_glob_tokens(root)) return false;

    const fs::path dir = fs::absolute(path::path_from_utf8(root)).lexically_normal();
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec) {
        err_out = "glob matched no files: " + spec;
        return true;
    }

    std::set<std::string> collected;
    auto consider = [&](const fs::path &p) {
        std::error_code fe;
        if (!fs::is_regular_file(p, fe) || fe) return;
        if (!exts.count(fold_ext(p.extension().string()))) return;
        fs::path canon = fs::weakly_canonical(p, fe);
        if (fe) canon = fs::absolute(p);
        collected.insert(path::path_to_generic_utf8(canon));
    };

    if (recursive) {
        fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
        if (ec) {
            err_out = "glob matched no files: " + spec;
            return true;
        }
        const fs::recursive_directory_iterator end;
        for (; it != end; it.increment(ec)) {
            if (ec) break;
            consider(it->path());
        }
    } else {
        fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
        if (ec) {
            err_out = "glob matched no files: " + spec;
            return true;
        }
        const fs::directory_iterator end;
        for (; it != end; it.increment(ec)) {
            if (ec) break;
            consider(it->path());
        }
    }

    out.assign(collected.begin(), collected.end());
    if (out.empty()) err_out = "glob matched no files: " + spec;
    return true;
}

} // namespace

bool has_dst_template(const std::string &output_spec) {
    return output_spec.find("${SRC_") != std::string::npos
        || output_spec.find("&{SRC_") != std::string::npos;
}

bool has_glob_tokens(const std::string &path) {
    // *, ?, [] char classes, or a well-formed {a,b} brace group.
    static const std::regex k_glob_re(R"([*?\[\]]|\{[^{}]*,[^{}]*\})");
    return std::regex_search(path, k_glob_re);
}

bool path_matches_path_glob(std::string_view path_norm, std::string_view pattern_norm) {
    std::string pat;
    pat.reserve(pattern_norm.size());
    for (char c : pattern_norm) pat.push_back(c == '\\' ? '/' : c);
    std::string_view pv(pat);
    while (pv.size() >= 2 && pv[0] == '.' && pv[1] == '/') pv.remove_prefix(2);

    std::vector<std::string_view> path_segs, pat_segs;
    split_path_segments(path_norm, path_segs);
    split_path_segments(pv, pat_segs);
    collapse_adjacent_double_stars(pat_segs);
    if (pat_segs.empty()) return path_segs.empty();
    return path_segments_match_glob(path_segs, 0, pat_segs, 0);
}

std::vector<std::string> expand_input_paths(const std::string &input_spec, std::string &err_out) {
    err_out.clear();
    if (input_spec.empty()) { err_out = "input is empty"; return {}; }

    const std::string spec = expand_home_dir(input_spec);

    // `**/*.{png,jpg,webp}`: one directory walk, filter extensions (not N glob walks).
    {
        std::vector<std::string> fast;
        if (try_expand_extension_brace_glob(spec, fast, err_out))
            return fast;
    }

    // Brace expansion: {a,b,c} → recurse on each alternative, merge results.
    const std::vector<std::string> brace_specs = expand_brace_glob_specs(spec);
    if (brace_specs.size() > 1) {
        std::vector<std::string> out;
        std::unordered_set<std::string> seen;
        std::string first_err;
        for (const auto &one : brace_specs) {
            std::string one_err;
            for (const auto &p : expand_input_paths(one, one_err)) {
                if (seen.insert(p).second) out.push_back(p);
            }
            if (!one_err.empty() && first_err.empty()) first_err = one_err;
        }
        if (out.empty() && !first_err.empty()) err_out = first_err;
        std::sort(out.begin(), out.end());
        return out;
    }

    if (is_http_url(spec)) return {spec};

    // Windows Explorer multi-select: semicolon-separated absolute paths.
    if (spec.find(';') != std::string::npos && !has_glob_tokens(spec)) {
        std::vector<std::string> parts;
        std::string cur;
        for (char c : spec) {
            if (c == ';') { trim_in_place(cur); if (!cur.empty()) parts.push_back(std::move(cur)); cur.clear(); }
            else cur.push_back(c);
        }
        trim_in_place(cur);
        if (!cur.empty()) parts.push_back(std::move(cur));
        if (parts.size() < 2) { err_out = "invalid semicolon-separated input list"; return {}; }
        std::vector<std::string> out;
        out.reserve(parts.size());
        for (const auto &p : parts) {
            fs::path fp = path::path_from_utf8(p);
            std::error_code ec;
            if (!fs::is_regular_file(fp, ec) || ec) { err_out = "not a file: " + p; return {}; }
            fs::path canon = fs::weakly_canonical(fs::absolute(fp), ec);
            if (ec) canon = fs::absolute(fp);
            out.push_back(path::path_to_generic_utf8(canon));
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

    if (!has_glob_tokens(spec)) {
        fs::path p = fs::absolute(path::path_from_utf8(spec));
        std::error_code ec;
        if (fs::is_regular_file(p, ec) && !ec) {
            fs::path canon = fs::weakly_canonical(p, ec);
            if (ec) canon = p;
            return {path::path_to_generic_utf8(canon)};
        }
        err_out = "input file not found: " + path::path_to_generic_utf8(p);
        return {};
    }

    fs::path resolved = fs::absolute(path::path_from_utf8(spec)).lexically_normal();
    const std::string pat = path::path_to_utf8(resolved);

    std::vector<fs::path> matched;
    try {
        matched = (spec.find("**") != std::string::npos) ? glob::rglob(pat) : glob::glob(pat);
    } catch (const std::exception &e) {
        err_out = std::string("glob failed: ") + e.what();
        return {};
    }

    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    for (auto &p : matched) {
        std::error_code ec;
        if (!fs::is_regular_file(p, ec) || ec) continue;
        fs::path canon = fs::weakly_canonical(p, ec);
        if (ec) canon = p;
        const std::string key = path::path_to_generic_utf8(canon);
        if (seen.insert(key).second) out.push_back(key);
    }
    std::sort(out.begin(), out.end());
    if (out.empty()) err_out = "glob matched no files: " + input_spec;
    return out;
}

std::vector<std::string> expand_one_cli_src(const std::string &segment, std::string &err_out) {
    err_out.clear();
    std::string s = segment;
    trim_in_place(s);
    if (s.empty()) { err_out = "input is empty"; return {}; }
    s = expand_home_dir(s);
    if (is_http_url(s)) return {s};
    if (has_glob_tokens(s)) return expand_input_paths(s, err_out);

    fs::path p = path::path_from_utf8(s);
    std::error_code ec;
    if (fs::is_directory(p, ec)) {
        std::set<std::string> collected;
        collect_images_recursive(p, collected);
        if (collected.empty()) { err_out = "no image files in directory: " + s; return {}; }
        std::vector<std::string> out(collected.begin(), collected.end());
        std::sort(out.begin(), out.end());
        return out;
    }
    if (fs::is_regular_file(p, ec)) {
        fs::path canon = fs::weakly_canonical(fs::absolute(p), ec);
        if (ec) canon = fs::absolute(p);
        return {path::path_to_generic_utf8(canon)};
    }
    err_out = "not found: " + s;
    return {};
}

bool path_matches_gallery_glob(const fs::path &path, GalleryGlob glob) {
    switch (glob) {
    case GalleryGlob::IMAGES:
        return is_supported_image_extension(path.extension().string());
    }
    return false;
}

std::vector<std::pair<std::string, fs::path>> pair_resize_paths(const std::string &input_spec,
                                                                const std::string &output_spec,
                                                                std::string &err_out,
                                                                const std::string *implicit_format_cli,
                                                                const std::string *implicit_stem_suffix) {
    err_out.clear();
    if (output_spec.empty()) {
        if (!implicit_format_cli) { err_out = "output is empty"; return {}; }
        std::vector<std::string> inputs = expand_input_paths(input_spec, err_out);
        if (!err_out.empty()) return {};
        if (inputs.empty()) { err_out = "resize: no input files"; return {}; }
        const std::string empty_stem;
        const std::string &stem_ref = implicit_stem_suffix ? *implicit_stem_suffix : empty_stem;
        std::vector<std::pair<std::string, fs::path>> pairs;
        pairs.reserve(inputs.size());
        for (const auto &in : inputs) {
            std::string one_err;
            std::string out_str = default_output_path_for_one_input(in, *implicit_format_cli, one_err, stem_ref);
            if (!one_err.empty()) { err_out = one_err; return {}; }
            if (out_str.empty()) { err_out = "resize: could not derive default output for: " + in; return {}; }
            pairs.emplace_back(in, path::path_from_utf8(out_str));
        }
        return pairs;
    }

    std::vector<std::string> inputs = expand_input_paths(input_spec, err_out);
    if (inputs.empty()) return {};

    if (has_dst_template(output_spec)) {
        std::vector<std::pair<std::string, fs::path>> pairs;
        pairs.reserve(inputs.size());
        for (const auto &in : inputs)
            pairs.emplace_back(in, resolve_dst_template(in, output_spec));
        return pairs;
    }

    fs::path out_root = path::path_from_utf8(output_spec);
    std::error_code ec;

    if (inputs.size() == 1) {
        const std::string &in = inputs[0];
        bool out_is_dir = trailing_sep(output_spec);
        if (!out_is_dir) {
            if (fs::exists(out_root, ec)) {
                if (fs::is_directory(out_root, ec)) out_is_dir = true;
            } else {
                if (!path_leaf_looks_like_explicit_image_file(out_root)) out_is_dir = true;
            }
        }
        if (out_is_dir) {
            fs::path dir = fs::absolute(out_root);
            if (is_http_url(in)) return {{in, dir / url_suggested_filename(in)}};
            return {{in, dir / path::path_from_utf8(in).filename()}};
        }
        return {{in, fs::absolute(out_root)}};
    }

    if (fs::exists(out_root, ec) && fs::is_regular_file(out_root, ec)) {
        err_out = "multiple inputs require output to be a directory, not a file: " + output_spec;
        return {};
    }
    if (!trailing_sep(output_spec)) {
        if (fs::exists(out_root, ec)) {
            if (!fs::is_directory(out_root, ec)) {
                err_out = "multiple inputs: output must be a directory: " + output_spec;
                return {};
            }
        } else if (path_leaf_looks_like_explicit_image_file(out_root)) {
            err_out = "multiple inputs: output must be a directory, not a file path: " + output_spec;
            return {};
        }
    }

    fs::path dir = fs::absolute(out_root);
    std::vector<std::pair<std::string, fs::path>> pairs;
    pairs.reserve(inputs.size());
    for (const auto &in : inputs) {
        if (is_http_url(in)) {
            err_out = "URL input cannot be combined with multiple outputs in one batch: " + in;
            return {};
        }
        pairs.emplace_back(in, dir / path::path_from_utf8(in).filename());
    }
    return pairs;
}

} // namespace media
