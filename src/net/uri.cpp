#include "net/uri.hpp"
#include "net/url_fetch.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/url.hpp>

#include <algorithm>
#include <cctype>

namespace pm::uri {
namespace {

template <typename View>
std::string copy_view(const View& view) {
    return {view.data(), view.size()};
}

std::string lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string to_slashes(std::string value) {
    std::replace(value.begin(), value.end(), '\\', '/');
    return value;
}

bool is_windows_drive_path(std::string_view value) {
    return value.size() >= 2
        && std::isalpha(static_cast<unsigned char>(value[0]))
        && value[1] == ':';
}

// `//server/share/file` is a filesystem UNC path, not an RFC 3986 network-path
// reference. Boost.URL would split it into host + path and break grant matching.
bool is_unc_path(std::string_view value) {
    return value.size() >= 2
        && ((value[0] == '/' && value[1] == '/')
            || (value[0] == '\\' && value[1] == '\\'));
}

bool starts_with_scheme(std::string_view input, std::string_view scheme) {
    if (input.size() < scheme.size() + 1)
        return false;
    if (input[scheme.size()] != ':')
        return false;
    for (std::size_t i = 0; i < scheme.size(); ++i) {
        const char a = static_cast<char>(std::tolower(static_cast<unsigned char>(input[i])));
        const char b = static_cast<char>(std::tolower(static_cast<unsigned char>(scheme[i])));
        if (a != b)
            return false;
    }
    return true;
}

// Boost.URL rejects `file://C:/...` (drive letter looks like host:port). Security
// grants and consent scopes use that form on Windows, plus globs like
// `file://**` / `file://**.png`. When the RFC parser fails, treat everything
// after `file:` / `fs:` (minus leading slashes) as the path.
std::optional<ParsedUri> parse_file_uri_lenient(std::string_view input,
                                                const ParseOptions& options) {
    std::string_view rest;
    if (starts_with_scheme(input, "file"))
        rest = input.substr(5);
    else if (starts_with_scheme(input, "fs"))
        rest = input.substr(3);
    else
        return std::nullopt;
    if (options.require_authority_host)
        return std::nullopt;

    std::string path = to_slashes(std::string(rest));
    if (path.size() >= 2 && path[0] == '/' && path[1] == '/') {
        const auto slash = path.find('/', 2);
        const std::string auth = path.substr(2, slash == std::string::npos
            ? std::string::npos : slash - 2);
        if (options.reject_userinfo && auth.find('@') != std::string::npos)
            return std::nullopt;
        if (options.reject_percent_encoded_authority
            && auth.find('%') != std::string::npos)
            return std::nullopt;
    }
    while (!path.empty() && path.front() == '/')
        path.erase(path.begin());

    ParsedUri out;
    out.valid = true;
    out.scheme = "file";
    out.path = std::move(path);
    out.original = std::string(input);
    return out;
}

bool is_dec_digit(char c) {
    return c >= '0' && c <= '9';
}

bool is_hex_digit(char c) {
    return is_dec_digit(c) || (c >= 'a' && c <= 'f');
}

bool looks_like_obfuscated_numeric_host(std::string_view host) {
    if (host.empty() || !is_dec_digit(host.front())) return false;
    for (char c : host)
        if (!is_hex_digit(c) && c != '.' && c != 'x')
            return false;
    return true;
}

bool host_name_syntax_is_safe(std::string_view host) {
    if (host.empty() || host.front() == '.' || host.back() == '.') return false;
    for (char c : host)
        if (!((c >= 'a' && c <= 'z') || is_dec_digit(c) || c == '-' || c == '.'))
            return false;
    return true;
}

bool ipv4_is_private(const boost::asio::ip::address_v4& address) {
    const auto bytes = address.to_bytes();
    const unsigned a = bytes[0], b = bytes[1];
    return a == 127
        || a == 10
        || (a == 192 && b == 168)
        || (a == 172 && b >= 16 && b <= 31)
        || (a == 169 && b == 254)
        || a == 0
        || (a == 100 && b >= 64 && b <= 127);
}

bool ipv6_is_v4_mapped(const boost::asio::ip::address_v6::bytes_type& bytes) {
    for (std::size_t i = 0; i < 10; ++i)
        if (bytes[i] != 0)
            return false;
    return bytes[10] == 0xff && bytes[11] == 0xff;
}

boost::asio::ip::address_v4 mapped_v4(
    const boost::asio::ip::address_v6::bytes_type& bytes) {
    boost::asio::ip::address_v4::bytes_type v4{};
    std::copy_n(bytes.begin() + 12, 4, v4.begin());
    return boost::asio::ip::address_v4(v4);
}

} // namespace

std::optional<ParsedUri> parse_uri(std::string_view input, ParseOptions options) {
    if (input.empty())
        return std::nullopt;

    ParsedUri out;
    out.original = std::string(input);
    if (is_windows_drive_path(input) || is_unc_path(input)) {
        out.valid = true;
        out.path = to_slashes(std::string(input));
        return out;
    }

    // File / fs scopes before Boost: `file://C:/dir/**` is accepted by
    // parse_uri_reference (drive letter looks like host + empty port) and
    // then rejected by the empty-port check below. Handle them as a path.
    if (auto file = parse_file_uri_lenient(input, options))
        return file;

    bool wildcard_scheme = input.starts_with("*:");
    std::string parse_storage;
    std::string_view parse_input = input;
    if (wildcard_scheme) {
        parse_storage.assign(input);
        parse_storage[0] = 'x';
        parse_input = parse_storage;
    }

    const auto parsed = boost::urls::parse_uri_reference(parse_input);
    if (!parsed)
        return parse_file_uri_lenient(input, options);
    const boost::urls::url_view url = parsed.value();

    out.scheme = wildcard_scheme ? "*" : lower(url.scheme());
    if (out.scheme == "fs")
        out.scheme = "file";

    out.has_authority = url.has_authority();
    if (out.has_authority) {
        out.authority = copy_view(url.encoded_authority());
        if (options.reject_percent_encoded_authority
            && out.authority.find('%') != std::string::npos)
            return std::nullopt;
        if (url.has_userinfo()) {
            out.userinfo = copy_view(url.encoded_userinfo());
            if (options.reject_userinfo)
                return std::nullopt;
        }
        out.host = lower(copy_view(url.host()));
        out.bracketed_ipv6 = url.host_type() == boost::urls::host_type::ipv6;
        if (url.has_port()) {
            out.port = copy_view(url.port());
            if (out.port.empty())
                return std::nullopt;
        }
    }

    out.path = to_slashes(copy_view(url.encoded_path()));
    if (out.scheme == "file") {
        if (out.has_authority && !out.authority.empty())
            out.path = out.authority + out.path;
        while (!out.path.empty() && out.path.front() == '/')
            out.path.erase(out.path.begin());
        out.has_authority = false;
        out.bracketed_ipv6 = false;
        out.authority.clear();
        out.userinfo.clear();
        out.host.clear();
        out.port.clear();
    }
    if (url.has_query())
        out.query = copy_view(url.encoded_query());
    if (url.has_fragment())
        out.fragment = copy_view(url.encoded_fragment());
    if (options.require_authority_host && (!out.has_authority || out.host.empty()))
        return std::nullopt;

    out.valid = true;
    return out;
}

std::optional<ParsedUri> parse_uri_lenient(std::string_view input, ParseOptions options) {
    if (auto parsed = parse_uri(input, options))
        return parsed;
    if (input.find(' ') == std::string_view::npos)
        return std::nullopt;
    std::string encoded;
    encoded.reserve(input.size() + 8);
    for (const unsigned char c : input) {
        if (c == ' ')
            encoded += "%20";
        else
            encoded.push_back(static_cast<char>(c));
    }
    return parse_uri(encoded, options);
}

std::optional<ParsedUri> parse_http_uri(std::string_view input, ParseOptions options) {
    options.require_authority_host = true;
    auto uri = parse_uri(input, options);
    if (!uri || (uri->scheme != "http" && uri->scheme != "https"))
        return std::nullopt;
    return uri;
}

std::optional<std::string> percent_decode(std::string_view input, bool reject_encoded_percent) {
    const auto encoded = boost::urls::make_pct_string_view(input);
    if (!encoded)
        return std::nullopt;
    std::string decoded = encoded.value().decode();
    if (reject_encoded_percent && decoded.find('%') != std::string::npos)
        return std::nullopt;
    return decoded;
}

bool host_is_private_or_invalid(const ParsedUri& uri, std::string& reason) {
    reason.clear();
    if (uri.host.empty()) {
        reason = "empty host";
        return true;
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(uri.host, error);
    if (!error) {
        if (address.is_loopback()) {
            reason = "loopback address";
            return true;
        }
        if (address.is_unspecified()) {
            reason = "unspecified address";
            return true;
        }
        if (address.is_multicast()) {
            reason = "multicast address";
            return true;
        }
        if (address.is_v4()) {
            if (ipv4_is_private(address.to_v4())) {
                reason = "private ipv4";
                return true;
            }
            return false;
        }

        const auto bytes = address.to_v6().to_bytes();
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) {
            reason = "ipv6 link-local";
            return true;
        }
        if ((bytes[0] & 0xfe) == 0xfc) {
            reason = "ipv6 unique-local";
            return true;
        }
        if (ipv6_is_v4_mapped(bytes) && ipv4_is_private(mapped_v4(bytes))) {
            reason = "ipv4-mapped ipv6 private";
            return true;
        }
        return false;
    }

    if (uri.host == "localhost" || uri.host == "localhost.localdomain") {
        reason = "localhost";
        return true;
    }
    if (looks_like_obfuscated_numeric_host(uri.host)) {
        reason = "obfuscated numeric host";
        return true;
    }
    if (!host_name_syntax_is_safe(uri.host)) {
        reason = "invalid host syntax";
        return true;
    }
    return false;
}

} // namespace pm::uri

namespace media {

bool is_http_url(const std::string& s) {
    return pm::uri::parse_http_uri(s).has_value();
}

} // namespace media
