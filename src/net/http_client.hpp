// http_client.hpp — structured HTTP(S) fetch with auth, proxy, caching, download-to-file.
//
// Wraps libcurl (already linked) behind a plain-value interface so xblox blocks
// and other call sites never touch raw CURL handles.
//
// Features
// ─────────
//   Auth      Bearer token / HTTP Basic / API-key header injection.
//   Proxy     Full-URL proxy with optional credentials.
//   SSL       verifyPeer / verifyHost flags; pass insecure:true to skip both.
//   downloadAs  Write response body directly to a file; result = saved path.
//   Cache     Disk cache keyed by URL; ETag/Last-Modified revalidation plus
//             TTL-based expiry. Thread-safe (global cache mutex).
//   Retry     Exponential back-off with jitter (base * 2^n + rand(0,base)),
//             capped at 30 s, skipping non-retriable curl/HTTP errors.
//   Session   Named persistent cookie jar (file on disk). Concurrent requests
//             to the same session ID are serialized via a per-session mutex.
//
// Usage inside a block handler:
//
//   #include "lib/net/http_client.hpp"
//
//   media::net::HttpRequest req;
//   req.url     = io.str("url");
//   req.method  = upper_ascii(io.str("method", "GET"));
//   req.auth    = media::net::parse_auth(io);   // helper below
//   req.cancel_check = [&]{ return io.runtime().cancel_requested &&
//                                  io.runtime().cancel_requested(io.runtime().user_data); };
//   auto r = media::net::http_fetch(req);
//   if (!r.ok) { io.error(...); return BlockResult::Error; }
//
#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace media::net {

// ── Authentication ────────────────────────────────────────────────────────────

enum class AuthKind {
    None,
    Bearer,   // Authorization: Bearer <token>
    Basic,    // Authorization: Basic base64(user:pass)
    ApiKey,   // <header>: <token>   (default header: X-Api-Key)
};

struct Auth {
    AuthKind    kind        = AuthKind::None;
    std::string token;          // bearer / api-key value
    std::string user;           // basic auth username
    std::string pass;           // basic auth password
    std::string header;         // api-key header name (default: "X-Api-Key")
};

// Parse AuthKind from a case-insensitive mode string ("bearer", "basic", "apikey", …)
AuthKind parse_auth_kind(const std::string& mode);

// ── Disk cache policy ────────────────────────────────────────────────────────

struct CachePolicy {
    bool        enabled         = false;
    std::string cache_dir;          // empty → default system cache dir / pixlwiz / net
    int64_t     ttl_ms          = 3'600'000;  // -1 = rely solely on server headers
    bool        force_revalidate = false;     // always send If-None-Match / If-Modified-Since
};

// Return the platform default cache directory for this feature
// (e.g. %LOCALAPPDATA%/pixlwiz/net on Windows).
std::string default_net_cache_dir();

// Return the platform default session directory
// (e.g. %LOCALAPPDATA%/pixlwiz/sessions on Windows).
std::string default_net_session_dir();

// ── Write callback helpers ────────────────────────────────────────────────────

// Progress/cancel callback type: returns true when the operation should abort.
using CancelCheck = std::function<bool()>;

// ── Request ──────────────────────────────────────────────────────────────────

struct HttpRequest {
    std::string url;
    std::string method          = "GET";
    std::string body;
    // Headers as a flat list of "Name: value" strings (already formatted).
    // Use append_json_headers() to add from a JSON value.
    std::vector<std::string> headers;

    Auth        auth;

    // Proxy
    std::string proxy;          // e.g. "http://proxy.corp:8080"
    std::string proxy_user;
    std::string proxy_pass;

    // SSL
    bool verify_peer            = true;
    bool verify_host            = true;

    // Redirects
    bool follow_redirects       = true;
    long max_redirects          = 5;

    // Timeouts
    long timeout_ms             = 30'000;
    long connect_timeout_ms     = 10'000;

    // Retry — exponential back-off: delay_ms * 2^attempt + rand(0, delay_ms)
    int  retries                = 2;
    int  retry_delay_ms         = 250;   // base delay; doubles each retry + jitter

    // Download-to-file
    // Non-empty → response body is written to this path; HttpResponse::saved_path
    // is set and ::body remains empty. Directories are created as needed.
    // "auto" → derive filename from Content-Disposition or URL basename, placed
    // in the system Downloads folder (or CWD if that fails).
    std::string download_as;

    // ── Structured body ───────────────────────────────────────────────────────
    // Explicit Content-Type injected as a header when non-empty and the caller
    // has not already included a Content-Type in `headers`.
    std::string content_type;
    // Multipart form parts — non-empty triggers curl_mime mode (ignores `body`).
    // Each entry uses one of two formats (same convention as curl -F):
    //   "name=value"        text field
    //   "name@/path/to/file"  file part (name may be empty: "@/path" uses filename)
    std::vector<std::string> body_parts;

    // ── Session / cookie jar ─────────────────────────────────────────────────
    // Non-empty → load/save cookies from a named jar file.
    // Concurrent requests with the same session_id are serialized (mutex).
    // The jar file is created on first use; subsequent requests merge new cookies.
    std::string session_id;
    // Directory where jar files are stored. Empty = system cache dir/pixlwiz/sessions.
    std::string session_dir;

    // ── Query-string parameters ───────────────────────────────────────────────
    // Applied on top of any query string already embedded in `url`.
    // Stored as a flat list of "name=raw-value" strings (values are NOT yet
    // percent-encoded here; the client encodes them before appending to the URL).
    std::vector<std::string> query_params;

    // Cache
    CachePolicy cache;

    // Cancel hook: called periodically during the transfer; return true to abort.
    CancelCheck cancel_check;
};

// ── Response ─────────────────────────────────────────────────────────────────

struct HttpResponse {
    bool   ok           = false;
    long   status_code  = 0;
    std::string body;               // raw (or decoded) response body
    std::string saved_path;         // set when download_as was used
    std::vector<std::string> response_headers;
    std::string effective_url;
    std::string error;
    int    attempts     = 0;
    bool   from_cache   = false;
};

// ── Main entry point ─────────────────────────────────────────────────────────

HttpResponse http_fetch(const HttpRequest& req);

// ── Header helpers ───────────────────────────────────────────────────────────

// Parse headers from a JSON value (object {"Name":"value"}, array of
// "Name: value" strings, or a JSON-encoded string of either) into an object
// suitable for MCP / structured consumers. Non-string values are stringified.
nlohmann::json parse_json_headers_object(const nlohmann::json& raw);

// Append headers from a JSON value (object {"Name":"value"} or array
// ["Name: value", ...] or a JSON-encoded string of either) into a flat list.
void append_json_headers(const void* json_ptr,   // const nlohmann::json*
                         std::vector<std::string>& out);

// Merge fetch-style auth fields into a headers object (same rules as apply_auth).
// Existing header keys are overwritten when auth supplies the same name.
void apply_auth_to_headers(const Auth& auth, nlohmann::json& headers);

// ── Content-Disposition ───────────────────────────────────────────────────────

// Parse the filename= token from a Content-Disposition response header line.
// Returns empty when not found or not parseable.
std::string content_disposition_filename(const std::vector<std::string>& response_headers);

// ── One-shot file download ───────────────────────────────────────────────────
//
// Single GET. No retries. Connect 4s, no total deadline (Stop / cancel_check
// aborts), abort if slower than 1 KB/s for 5s, abort on HTTP >= 400, cap the
// body at 2 GB. Refuses userinfo, loopback, private, and link-local hosts,
// and re-checks each redirect (at most 3). Proxy comes from `proxy` or
// http(s)_proxy / all_proxy. The
// file name is `filename` when `explicit_filename` is set, else the
// Content-Disposition filename, else the URL's last path segment, else
// `filename`. A name with no extension is probed (libmagic) and
// the sniffed extension is appended. media::path::sanitize_filename cleans the
// name; an existing file gets -2, -3, …. A failed or cancelled transfer
// deletes the partial file.

// received bytes, total bytes (0 when the server sent no length).
using DownloadProgressFn = std::function<void(std::uint64_t received, std::uint64_t total)>;

struct UrlDownloadRequest {
    std::string url;
    std::string directory;
    std::string filename;
    bool        explicit_filename = false;
    std::string proxy;
    std::string proxy_user;
    std::string proxy_pass;
    CancelCheck cancel_check;
    DownloadProgressFn on_progress;
};

struct UrlDownloadResult {
    bool        ok          = false;
    bool        cancelled   = false;
    long        status_code = 0;
    std::uint64_t bytes     = 0;
    std::string path;
    std::string content_type;
    std::string effective_url;
    std::string error;
};

UrlDownloadResult download_url_file(const UrlDownloadRequest& req);

} // namespace media::net
