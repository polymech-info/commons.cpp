#include "input_selection.hpp"

#include "fs/glob_paths.hpp"
#include "fs/path_sanitizer.hpp"
#include "net/url_fetch.hpp"

#include "logger/logger.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <unordered_set>

namespace fs = std::filesystem;

namespace media {

namespace {

void trim(std::string &s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(0, 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
}

} // namespace

void InputSelection::clear() { entries_.clear(); }

void InputSelection::add(Entry e) { entries_.push_back(std::move(e)); }

void InputSelection::add_from_cli_src_list(const std::vector<std::string> &src_args) {
    for (const auto &a : src_args)
        entries_.push_back(Entry{a, {}});
}

bool InputSelection::validate(std::string &err_out) const {
    err_out.clear();
    if (entries_.empty()) {
        err_out = "input_selection: no entries";
        return false;
    }
    for (const auto &e : entries_) {
        std::string s = e.spec;
        trim(s);
        if (s.empty()) {
            err_out = "input_selection: empty spec";
            return false;
        }
        if (!path::validate_path_spec_for_input_selection(s, err_out)) return false;
        if (!e.glob_under.empty()) {
            std::string gerr;
            (void)path::sanitize_subpath(e.glob_under, gerr);
            if (!gerr.empty()) {
                err_out = gerr;
                return false;
            }
        }
    }
    return true;
}

std::vector<std::string> InputSelection::resolve(std::string &err_out, bool log) const {
    err_out.clear();
    std::unordered_set<std::string> seen;
    std::vector<std::string> merged;

    for (const auto &e : entries_) {
        std::string spec = e.spec;
        trim(spec);
        if (spec.empty()) {
            err_out = "input_selection: empty spec";
            return {};
        }

        std::string effective;
        if (e.glob_under.empty()) {
            effective = spec;
        } else {
            if (is_http_url(spec)) {
                err_out = "input_selection: URL cannot be combined with glob_under";
                return {};
            }
            std::string gerr;
            const std::string g_san = path::sanitize_subpath(e.glob_under, gerr);
            if (!gerr.empty()) {
                err_out = gerr;
                return {};
            }
            fs::path base(spec);
            std::error_code ec;
            base = fs::absolute(base, ec);
            if (!fs::is_directory(base, ec)) {
                err_out = "input_selection: spec is not a directory: " + spec;
                return {};
            }
            fs::path pat = g_san.empty() ? base : (base / g_san);
            effective = media::path::path_to_utf8(pat.lexically_normal());
        }

        std::string one_err;
        std::vector<std::string> part = expand_one_cli_src(effective, one_err);
        if (!one_err.empty()) {
            err_out = one_err;
            return {};
        }
        if (part.empty()) {
            err_out = "input_selection: no files for: " + effective;
            return {};
        }
        if (log) {
            logger::info(std::string("input_selection: ") + effective + " -> " + std::to_string(part.size())
                         + " path(s)");
        }
        for (const auto &p : part) {
            if (seen.insert(p).second)
                merged.push_back(p);
        }
    }

    std::sort(merged.begin(), merged.end());
    return merged;
}

std::string InputSelection::to_expand_spec(const std::vector<std::string> &resolved, std::string &err_out) {
    err_out.clear();
    if (resolved.empty()) {
        err_out = "input_selection: no paths";
        return {};
    }
    if (resolved.size() == 1)
        return resolved[0];
    for (const auto &p : resolved) {
        if (is_http_url(p)) {
            err_out = "input_selection: multiple inputs cannot include a URL";
            return {};
        }
    }
    std::string s;
    for (const auto &p : resolved) {
        if (!s.empty())
            s += ';';
        s += p;
    }
    return s;
}

} // namespace media
