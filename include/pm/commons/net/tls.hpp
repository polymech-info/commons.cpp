#pragma once

// TLS helpers for outbound HTTPS. SPKI pins are 64 lowercase/uppercase hex
// digits (SHA-256 of the subjectPublicKeyInfo). Curl wants "sha256//" + base64.

#include <cstddef>
#include <string>
#include <string_view>

namespace pm::commons::net {

/// True when @p hex is exactly 64 hex digits.
[[nodiscard]] inline bool spki_hex_ok(std::string_view hex) noexcept
{
    if (hex.size() != 64)
        return false;
    for (unsigned char c : hex) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok)
            return false;
    }
    return true;
}

/// Format a 64-hex SPKI for CURLOPT_PINNEDPUBLICKEY (`sha256//…`).
/// Empty return + @p err set on failure.
[[nodiscard]] inline std::string spki_pin_curl(std::string_view hex, std::string& err)
{
    err.clear();
    if (!spki_hex_ok(hex)) {
        err = "the certificate pin is not valid";
        return {};
    }
    unsigned char raw[32];
    for (std::size_t i = 0; i < 32; ++i) {
        const auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            err = "the certificate pin is not valid";
            return {};
        }
        raw[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    b64.reserve(44);
    for (std::size_t i = 0; i < 32; i += 3) {
        const std::size_t left = 32 - i;
        unsigned value = static_cast<unsigned>(raw[i]) << 16;
        if (left > 1)
            value |= static_cast<unsigned>(raw[i + 1]) << 8;
        if (left > 2)
            value |= static_cast<unsigned>(raw[i + 2]);
        b64.push_back(alphabet[(value >> 18) & 63]);
        b64.push_back(alphabet[(value >> 12) & 63]);
        b64.push_back(left > 1 ? alphabet[(value >> 6) & 63] : '=');
        b64.push_back(left > 2 ? alphabet[value & 63] : '=');
    }
    return std::string("sha256//") + b64;
}

} // namespace pm::commons::net
