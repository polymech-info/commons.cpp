#include "output_path.hpp"

#include "fs/glob_paths.hpp"
#include "net/url_fetch.hpp"

#include <cctype>
#include <filesystem>
#include <string>
#include <vector>
#include "fs/path_sanitizer.hpp"

namespace fs = std::filesystem;

namespace media {

namespace {

void to_lower_ascii(std::string &s) {
    for (char &c : s) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
}

std::string ext_for_format(const std::string &fmt) {
    if (fmt.empty())
        return "";
    std::string f = fmt;
    to_lower_ascii(f);
    if (f == "jpeg")
        return "jpg";
    return f;
}

/** True if the whole filename is a Windows reserved device name (optional extension). */
bool is_windows_reserved_filename(const std::string &name) {
    std::string l = name;
    to_lower_ascii(l);
    const size_t dot = l.find('.');
    const std::string base = dot == std::string::npos ? l : l.substr(0, dot);
    if (base == "con" || base == "prn" || base == "aux" || base == "nul")
        return true;
    if (base.size() == 4) {
        if (base.compare(0, 3, "com") == 0) {
            const char d = base[3];
            return d >= '0' && d <= '9';
        }
        if (base.compare(0, 3, "lpt") == 0) {
            const char d = base[3];
            return d >= '0' && d <= '9';
        }
    }
    return false;
}

std::string utf8_truncate_255_bytes(std::string s) {
    if (s.size() <= 255)
        return s;
    size_t n = 255;
    while (n > 0 && (static_cast<unsigned char>(s[n - 1]) & 0xc0) == 0x80)
        --n;
    s.resize(n);
    return s;
}

std::string derive_basename_before_sanitize(const std::string &in, const std::string &format_cli,
                                            const std::string &stem_suffix) {
    const std::string ext_fmt = ext_for_format(format_cli);

    if (is_http_url(in)) {
        std::string fn = url_suggested_filename(in);
        fs::path bp = media::path::path_from_utf8(fn);
        std::string stem = media::path::path_to_utf8(bp.stem());
        std::string ext = media::path::path_to_utf8(bp.extension());
        if (!stem_suffix.empty())
            stem += stem_suffix;
        if (!format_cli.empty())
            return stem + "." + ext_fmt;
        if (ext.empty())
            return stem + ".jpg";
        if (stem_suffix.empty())
            return fn;
        return stem + ext;
    }

    fs::path p = media::path::path_from_utf8(in);
    std::string stem = media::path::path_to_utf8(p.stem());
    std::string ext = media::path::path_to_utf8(p.extension());
    if (!stem_suffix.empty())
        stem += stem_suffix;
    if (!format_cli.empty())
        return stem + "." + ext_fmt;
    if (stem_suffix.empty())
        return media::path::path_to_utf8(p.filename());
    return stem + ext;
}

} // namespace

std::string sanitize_filename(std::string input) {
    std::string out;
    out.reserve(input.size());

    for (size_t i = 0; i < input.size();) {
        const unsigned char uc = static_cast<unsigned char>(input[i]);
        if (uc < 0x20 || (uc >= 0x80 && uc <= 0x9f)) {
            ++i;
            continue;
        }
        if (uc < 0x80) {
            const char c = static_cast<char>(uc);
            if (c == '/' || c == '?' || c == '<' || c == '>' || c == '\\' || c == ':' || c == '*' ||
                c == '|' || c == '"') {
                ++i;
                continue;
            }
            out.push_back(c);
            ++i;
            continue;
        }
        size_t seq = 1;
        if ((uc & 0xe0) == 0xc0)
            seq = 2;
        else if ((uc & 0xf0) == 0xe0)
            seq = 3;
        else if ((uc & 0xf8) == 0xf0)
            seq = 4;
        if (i + seq > input.size())
            break;
        for (size_t j = 0; j < seq; ++j)
            out.push_back(input[i++]);
    }

    while (!out.empty() && (out.back() == ' ' || out.back() == '.'))
        out.pop_back();

    bool only_dots = !out.empty();
    for (char c : out) {
        if (c != '.') {
            only_dots = false;
            break;
        }
    }
    if (only_dots)
        return "";

    if (is_windows_reserved_filename(out))
        return "";

    return utf8_truncate_255_bytes(std::move(out));
}

std::string default_output_path_for_one_input(const std::string &resolved_input, const std::string &format_cli,
                                              std::string &err_out, const std::string &stem_suffix) {
    err_out.clear();
    std::string base = derive_basename_before_sanitize(resolved_input, format_cli, stem_suffix);
    std::string safe = sanitize_filename(base);
    if (safe.empty()) {
        const std::string ext = format_cli.empty() ? std::string("jpg") : ext_for_format(format_cli);
        safe = sanitize_filename(std::string("image.") + (ext.empty() ? "jpg" : ext));
        if (safe.empty())
            safe = "image.jpg";
    }

    std::error_code ec;
    fs::path out_dir;
    if (is_http_url(resolved_input)) {
        out_dir = fs::current_path(ec);
        if (ec) {
            err_out = "resize: cannot get current directory: " + ec.message();
            return {};
        }
    } else {
        out_dir = media::path::path_from_utf8(resolved_input).parent_path();
    }
    return media::path::path_to_utf8(
        (out_dir / media::path::path_from_utf8(safe)).lexically_normal());
}

std::string default_output_path_for_resize(const std::string &input_spec, const std::string &format_cli,
                                           std::string &err_out, const std::string &stem_suffix) {
    err_out.clear();
    std::string expand_err;
    std::vector<std::string> inputs = expand_input_paths(input_spec, expand_err);
    if (!expand_err.empty()) {
        err_out = expand_err;
        return {};
    }
    if (inputs.empty()) {
        err_out = "resize: no input files";
        return {};
    }
    if (inputs.size() > 1) {
        err_out.clear();
        return {};
    }

    return default_output_path_for_one_input(inputs[0], format_cli, err_out, stem_suffix);
}

} // namespace media
