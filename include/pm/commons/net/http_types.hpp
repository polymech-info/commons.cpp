#pragma once

#include "pm/commons/net/cancellation.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace pm::commons::net {

struct Header {
    std::string name;
    std::string value;
};

/// Transport-level request. Protocol semantics (CMS paths, grants, retries)
/// belong in the caller — this layer does not auto-retry mutations.
struct Request {
    std::string method = "GET";
    std::string url;
    std::vector<Header> headers;
    std::string body;
    /// Sent as `Authorization: Bearer …` only when non-empty. Attached as an
    /// HTTP header after TLS completes; with @c spki_sha256_hex set, curl
    /// enforces the pin during handshake before any request bytes leave.
    std::string bearer;
    /// 64-hex SPKI. Empty = system CA verify. Non-empty requires `https://`,
    /// disables redirects, and pins the peer key (CA verify off for that call).
    std::string spki_sha256_hex;
    long timeout_ms = 60'000;
    long connect_timeout_ms = 30'000;
    /// Ignored when a pin is set (forced off).
    bool follow_redirects = true;
    long max_redirects = 5;
    /// 0 = unlimited. Enforced for buffered and file/stream downloads.
    std::uint64_t max_bytes = 0;
    CancelCheck cancel;
};

struct Response {
    /// Transport succeeded (curl OK). HTTP status may still be 4xx/5xx.
    bool ok = false;
    long status = 0;
    std::string body;
    std::string error;
    /// Stable machine code when useful: EINVAL, EPIN, EPROTO, ECANCEL, EIO, …
    std::string code;
};

using BodyChunk = std::function<bool(const char* data, std::size_t n)>;
/// Return false to abort before any body bytes are delivered.
using HeaderSink = std::function<bool(long status, const std::string& content_type,
                                      std::uint64_t content_length,
                                      const std::string& content_range)>;
using Progress = std::function<void(std::uint64_t done, std::uint64_t total)>;

struct StreamOptions {
    BodyChunk on_body;
    HeaderSink on_headers;
    Progress on_progress;
    /// Curl Range value without the `Range:` prefix, e.g. `bytes=0-1023`.
    std::string range;
};

struct FileOptions {
    Progress on_progress;
    std::uint64_t expected_size = 0;
};

} // namespace pm::commons::net
