#pragma once

#include <cctype>
#include <string>
#include <string_view>

namespace pm::core {

struct ResourceUri {
    std::string canonical;
    std::string scheme;
    std::string type;
    std::string name;
};

inline bool is_resource_uri_char(char c) noexcept {
    const unsigned char uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '-' || c == '_' || c == '.' || c == '/';
}

inline bool parse_resource_uri(std::string_view text, ResourceUri& out, std::string& err) {
    out = {};
    err.clear();

    constexpr std::string_view kPrefix = "pm://";
    if (text.substr(0, kPrefix.size()) != kPrefix) {
        err = "resource URI must start with pm://";
        return false;
    }

    const std::string_view rest = text.substr(kPrefix.size());
    const std::size_t slash = rest.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= rest.size()) {
        err = "resource URI must have shape pm://<type>/<name>";
        return false;
    }

    for (char c : rest) {
        if (!is_resource_uri_char(c)) {
            err = "resource URI contains an unsupported character";
            return false;
        }
    }

    out.scheme = "pm";
    out.type = std::string(rest.substr(0, slash));
    out.name = std::string(rest.substr(slash + 1));
    out.canonical = std::string(kPrefix) + out.type + "/" + out.name;
    return true;
}

inline bool is_valid_resource_uri(std::string_view text) {
    ResourceUri parsed;
    std::string err;
    return parse_resource_uri(text, parsed, err);
}

} // namespace pm::core
