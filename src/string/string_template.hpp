#pragma once

/**
 * String templating (choose by complexity):
 *
 * 1) **Trivial** — `resolve_dollar_brace` for `${name}` (names: `[A-Za-z0-9_]+` only) and
 *    `resolve_template` for `{{key}}` (both use a string map; header-only, no deps).
 *
 * 2) **Standard Mustache** (variables, sections, partials, HTML escape) — kainjow/Mustache
 *    @see `mustache_render.hpp` and `render_mustache_flat` (uses FetchContent’ed
 *    https://github.com/kainjow/Mustache).
 *
 * 3) **Logic, loops, filters, JSON** — use Inja (https://github.com/pantor/inja) with
 *    nlohmann::json; not vendored here.
 *
 * @see `glob_paths` / `output_path` for `${SRC_*}` / `&{SRC_*}` in destination paths;
 *      this module is a generic map lookup for prompts, config strings, etc.
 */

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace media::str_tpl {

struct TemplateOptions {
    /** If true, a key not in `vars` sets `err` and returns an empty string. */
    bool error_on_missing = true;
    /**
     * When `error_on_missing` is false: use this for unknown keys, or keep the
     * original `{{key}}` span if `use_empty_on_missing` is false.
     */
    bool   use_empty_on_missing = true;
    std::string missing_fallback;
};

namespace detail {

inline void trim_in_place(std::string_view &s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
}

} // namespace detail

/**
 * Replace `${name}` (identifier: letters, digits, underscore). No spaces inside braces.
 * Unknown keys: see `TemplateOptions` (same as `resolve_template`).
 */
inline std::string resolve_dollar_brace(std::string_view tmpl, const std::unordered_map<std::string, std::string> &vars,
                                        std::string &err, const TemplateOptions &opt = {}) {
    err.clear();
    std::string out;
    out.reserve(tmpl.size() + 32);
    std::size_t i = 0;
    while (i < tmpl.size()) {
        if (i + 1 < tmpl.size() && tmpl[i] == '$' && tmpl[i + 1] == '{') {
            const std::size_t key_start = i + 2;
            std::size_t       k         = key_start;
            while (k < tmpl.size()
                   && (std::isalnum(static_cast<unsigned char>(tmpl[k])) || tmpl[k] == '_'))
                ++k;
            if (k >= tmpl.size() || tmpl[k] != '}') {
                err = "string_template: unclosed `${`";
                return {};
            }
            std::string_view key(tmpl.data() + key_start, k - key_start);
            if (key.empty()) {
                err = "string_template: empty ${} key";
                return {};
            }
            const std::string   ks(key);
            const auto          it = vars.find(ks);
            if (it == vars.end()) {
                if (opt.error_on_missing) {
                    err = "string_template: missing variable: " + ks;
                    return {};
                }
                if (opt.use_empty_on_missing) {
                    if (!opt.missing_fallback.empty())
                        out += opt.missing_fallback;
                } else {
                    out += "${";
                    out += key;
                    out += "}";
                }
            } else
                out += it->second;
            i = k + 1;
            continue;
        }
        if (tmpl[i] == '\0') {
            err = "string_template: null byte in template";
            return {};
        }
        out += tmpl[i];
        ++i;
    }
    return out;
}

/**
 * Replace `{{key}}` segments using `vars`. Keys are trimmed; empty keys are an error.
 */
inline std::string resolve_template(std::string_view tmpl, const std::unordered_map<std::string, std::string> &vars,
                                    std::string &err, const TemplateOptions &opt = {}) {
    err.clear();
    std::string out;
    out.reserve(tmpl.size() + 32);
    std::size_t i = 0;
    while (i < tmpl.size()) {
        if (i + 1 < tmpl.size() && tmpl[i] == '{' && tmpl[i + 1] == '{') {
            const std::size_t key_start = i + 2;
            std::size_t       j         = key_start;
            while (j + 1 < tmpl.size() && (tmpl[j] != '}' || tmpl[j + 1] != '}')) {
                if (tmpl[j] == '\0') {
                    err = "string_template: null byte in template";
                    return {};
                }
                ++j;
            }
            if (j + 1 >= tmpl.size() || tmpl[j] != '}' || tmpl[j + 1] != '}') {
                err = "string_template: unclosed `{{`";
                return {};
            }
            std::string_view key(tmpl.data() + key_start, j - key_start);
            detail::trim_in_place(key);
            if (key.empty()) {
                err = "string_template: empty placeholder key";
                return {};
            }
            const std::string k(key);
            const auto        it = vars.find(k);
            if (it == vars.end()) {
                if (opt.error_on_missing) {
                    err = "string_template: missing variable: " + k;
                    return {};
                }
                if (opt.use_empty_on_missing) {
                    if (!opt.missing_fallback.empty())
                        out += opt.missing_fallback;
                } else {
                    out += "{{";
                    out += key;
                    out += "}}";
                }
            } else
                out += it->second;
            i = j + 2;
            continue;
        }
        if (tmpl[i] == '\0') {
            err = "string_template: null byte in template";
            return {};
        }
        out += tmpl[i];
        ++i;
    }
    return out;
}

} // namespace media::str_tpl
