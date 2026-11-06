// http_client.cpp — libcurl-based HTTP(S) fetch implementation.
//
// See http_client.hpp for the public interface and feature list.

#include "net/http_client.hpp"

#include "json/json_utils.hpp"
#include "fs/path_sanitizer.hpp"
#include "net/uri.hpp"
#include "media/probe.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <netdb.h>
#  include <sys/socket.h>
#endif

#include <nlohmann/json.hpp>
#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "string/string_utils.hpp"

#if defined(_WIN32)
#  include <windows.h>
#  include <shlobj.h>
#endif

namespace fs = std::filesystem;

namespace media::net {
namespace {

// ── One-time global init ───────────────────────────────────────────────────────
//
// curl_global_init is NOT thread-safe; call it exactly once before any easy
// handle is created. std::call_once guarantees this even if multiple threads
// first-call http_fetch concurrently.

static std::once_flag g_curl_init_flag;
static void ensure_curl_global_init()
{
    std::call_once(g_curl_init_flag, []() {
        curl_global_init(CURL_GLOBAL_ALL);
    });
}

// ── Thread-local reusable easy handle ────────────────────────────────────────
//
// curl_easy_reset() clears all options but keeps the internal connection pool
// (DNS cache, SSL sessions, TCP keep-alive sockets) alive for the lifetime of
// the handle. Because xblox runs blocks sequentially on one thread (or one
// Taskflow worker per background block), this gives us free SSL session reuse
// and TCP keepalive across consecutive fetch calls to the same host —
// eliminating the TLS handshake on all but the first request.
//
// curl_easy_init/cleanup per-attempt (the old approach) discards all of that.

struct ThreadLocalCurl {
    CURL* handle = nullptr;
    ThreadLocalCurl()
    {
        ensure_curl_global_init();
        handle = curl_easy_init();
    }
    ~ThreadLocalCurl()
    {
        if (handle) curl_easy_cleanup(handle);
    }
    // Reset all options, keep connection pool.
    CURL* get()
    {
        if (handle) curl_easy_reset(handle);
        return handle;
    }
};

thread_local ThreadLocalCurl tl_curl;

// ── Utilities ─────────────────────────────────────────────────────────────────


// FNV-1a 64-bit hash — used for cache key derivation.
uint64_t fnv1a_64(const std::string& s)
{
    uint64_t h = 14695981039346656037ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

std::string to_hex16(uint64_t v)
{
    char buf[17]{};
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
    return buf;
}

// ── Base-64 encoder (RFC 4648, no line breaks) ────────────────────────────────

static const char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& in)
{
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t b = static_cast<unsigned char>(in[i]) << 16;
        if (i + 1 < in.size()) b |= static_cast<unsigned char>(in[i + 1]) << 8;
        if (i + 2 < in.size()) b |= static_cast<unsigned char>(in[i + 2]);
        out += kB64Chars[(b >> 18) & 0x3f];
        out += kB64Chars[(b >> 12) & 0x3f];
        out += (i + 1 < in.size()) ? kB64Chars[(b >> 6) & 0x3f] : '=';
        out += (i + 2 < in.size()) ? kB64Chars[b & 0x3f] : '=';
    }
    return out;
}

// ── Curl callbacks ────────────────────────────────────────────────────────────

size_t cb_write_string(char* ptr, size_t size, size_t nmemb, void* ud)
{
    auto* out = static_cast<std::string*>(ud);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

size_t cb_write_file(char* ptr, size_t size, size_t nmemb, void* ud)
{
    auto* ofs = static_cast<std::ofstream*>(ud);
    ofs->write(ptr, static_cast<std::streamsize>(size * nmemb));
    return ofs->good() ? size * nmemb : 0;
}

size_t cb_header(char* ptr, size_t size, size_t nmemb, void* ud)
{
    auto* hdrs = static_cast<std::vector<std::string>*>(ud);
    std::string line(ptr, size * nmemb);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (!line.empty())
        hdrs->push_back(std::move(line));
    return size * nmemb;
}

struct ProgressData {
    const CancelCheck* cancel_check = nullptr;
};

int cb_progress(void* ud, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
    const auto* pd = static_cast<const ProgressData*>(ud);
    if (pd && pd->cancel_check && (*pd->cancel_check)())
        return 1;
    return 0;
}

// ── Auth header injection ─────────────────────────────────────────────────────

void merge_auth_into_headers(const Auth& auth, nlohmann::json& headers)
{
    if (auth.kind == AuthKind::None)
        return;
    if (!headers.is_object())
        headers = nlohmann::json::object();

    switch (auth.kind) {
    case AuthKind::Bearer:
        if (!auth.token.empty()) {
            const std::string token = auth.token.rfind("Bearer ", 0) == 0
                ? auth.token.substr(7) : auth.token;
            headers["Authorization"] = "Bearer " + token;
        }
        break;
    case AuthKind::Basic: {
        const std::string cred = base64_encode(auth.user + ":" + auth.pass);
        headers["Authorization"] = "Basic " + cred;
        break;
    }
    case AuthKind::ApiKey: {
        const std::string hdr = auth.header.empty() ? std::string("X-Api-Key") : auth.header;
        if (!auth.token.empty())
            headers[hdr] = auth.token;
        break;
    }
    default:
        break;
    }
}

curl_slist* apply_auth(const Auth& auth, curl_slist* list, CURL* /*curl*/)
{
    nlohmann::json merged = nlohmann::json::object();
    merge_auth_into_headers(auth, merged);
    if (!merged.is_object())
        return list;
    for (auto it = merged.begin(); it != merged.end(); ++it) {
        if (it.value().is_string())
            list = curl_slist_append(list, (it.key() + ": " + it.value().get<std::string>()).c_str());
    }
    return list;
}

// ── Percent-encoding (for form bodies) ───────────────────────────────────────

std::string percent_encode(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned>(c));
            out += buf;
        }
    }
    return out;
}

// ── Retry policy ──────────────────────────────────────────────────────────────

bool should_retry_status(long code)
{
    return code == 408 || code == 425 || code == 429 || code >= 500;
}

// Exponential back-off: base * 2^attempt + uniform(0, base), capped at 30 s.
int backoff_ms(int base, int attempt)
{
    static thread_local std::mt19937 rng{std::random_device{}()};
    const int multiplied = base * (1 << std::min(attempt, 10));
    const int jitter     = std::uniform_int_distribution<int>(0, base)(rng);
    return std::min(multiplied + jitter, 30'000);
}

// Cancellable sleep in 50 ms ticks.  Returns true if cancelled.
bool cancellable_sleep(int ms, const CancelCheck& cancel_check)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cancel_check && cancel_check())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

// ── Disk cache ────────────────────────────────────────────────────────────────

static std::mutex g_cache_mutex;

// ── Session / cookie-jar registry ─────────────────────────────────────────────
//
// Each named session gets its own std::mutex. Requests that share a session_id
// are serialized so they never read/write the cookie file concurrently.

static std::mutex g_session_registry_mtx;
static std::unordered_map<std::string, std::unique_ptr<std::mutex>> g_session_mutexes;

std::mutex& session_mutex(const std::string& id)
{
    std::lock_guard<std::mutex> lk(g_session_registry_mtx);
    auto& ptr = g_session_mutexes[id];
    if (!ptr) ptr = std::make_unique<std::mutex>();
    return *ptr;
}

struct CacheMeta {
    std::string etag;
    std::string last_modified;
    int64_t     expires_at_ms = 0;   // epoch ms; 0 = already expired
};

std::string cache_key(const std::string& url, const std::string& method)
{
    return to_hex16(fnv1a_64(method + "|" + url));
}

std::string resolved_cache_dir(const CachePolicy& policy)
{
    if (!policy.cache_dir.empty()) return policy.cache_dir;
    return default_net_cache_dir();
}

bool ensure_dir(const fs::path& p)
{
    std::error_code ec;
    fs::create_directories(p, ec);
    return !ec;
}

int64_t now_epoch_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

bool cache_load(const std::string& dir, const std::string& key,
                CacheMeta& meta, std::string& body)
{
    std::lock_guard<std::mutex> lk(g_cache_mutex);
    const fs::path meta_path = media::path::path_from_utf8(dir) / (key + ".meta");
    const fs::path body_path = media::path::path_from_utf8(dir) / (key + ".body");

    std::error_code ec;
    if (!fs::is_regular_file(meta_path, ec) || !fs::is_regular_file(body_path, ec))
        return false;

    try {
        std::ifstream mf(meta_path);
        if (!mf.is_open()) return false;
        const nlohmann::json j = nlohmann::json::parse(mf);
        meta.etag          = j.value("etag", std::string{});
        meta.last_modified = j.value("last_modified", std::string{});
        meta.expires_at_ms = j.value("expires_at_ms", int64_t{0});

        std::ifstream bf(body_path, std::ios::binary);
        if (!bf.is_open()) return false;
        body.assign(std::istreambuf_iterator<char>(bf), std::istreambuf_iterator<char>());
        return true;
    } catch (...) {
        return false;
    }
}

void cache_store(const std::string& dir, const std::string& key,
                 const CacheMeta& meta, const std::string& body)
{
    std::lock_guard<std::mutex> lk(g_cache_mutex);
    if (!ensure_dir(media::path::path_from_utf8(dir))) return;

    try {
        const nlohmann::json j = {
            {"etag",          meta.etag},
            {"last_modified", meta.last_modified},
            {"expires_at_ms", meta.expires_at_ms},
        };
        std::ofstream mf(media::path::path_from_utf8(dir) / (key + ".meta"));
        if (mf.is_open()) mf << j.dump();

        std::ofstream bf(media::path::path_from_utf8(dir) / (key + ".body"), std::ios::binary);
        if (bf.is_open()) bf.write(body.data(), static_cast<std::streamsize>(body.size()));
    } catch (...) {}
}

// Extract a header value (case-insensitive) from response header lines.
std::string find_header(const std::vector<std::string>& headers, const char* name)
{
    const std::string lname = media::strutil::lower_ascii(name);
    for (const auto& h : headers) {
        const auto colon = h.find(':');
        if (colon == std::string::npos) continue;
        if (media::strutil::lower_ascii(h.substr(0, colon)) == lname)
            return h.substr(colon + 2); // skip ": "
    }
    return {};
}

// ── Content-Disposition filename parsing ──────────────────────────────────────

} // namespace (anonymous)

std::string content_disposition_filename(const std::vector<std::string>& headers)
{
    const std::string cd = find_header(headers, "Content-Disposition");
    if (cd.empty()) return {};
    // Simple scan for filename= or filename*=UTF-8''
    const std::string lcd = media::strutil::lower_ascii(cd);
    for (const char* token : {"filename*=utf-8''", "filename=\"", "filename="}) {
        const std::string ltok(token);
        const auto pos = lcd.find(ltok);
        if (pos == std::string::npos) continue;
        std::string val = cd.substr(pos + ltok.size());
        // Strip trailing semicolon / whitespace / quotes
        if (!val.empty() && val.front() == '"') {
            val.erase(val.begin());
            const auto end = val.find('"');
            if (end != std::string::npos) val = val.substr(0, end);
        } else {
            const auto end = val.find_first_of(";\r\n ");
            if (end != std::string::npos) val = val.substr(0, end);
        }
        // Percent-decode for filename*
        if (std::string(token).find("utf-8") != std::string::npos) {
            std::string dec;
            for (size_t i = 0; i < val.size(); ++i) {
                if (val[i] == '%' && i + 2 < val.size()) {
                    const char hex[3] = {val[i+1], val[i+2], '\0'};
                    dec += static_cast<char>(std::strtol(hex, nullptr, 16));
                    i += 2;
                } else {
                    dec += val[i];
                }
            }
            val = std::move(dec);
        }
        if (!val.empty()) return val;
    }
    return {};
}

namespace {

// Derive the save path for download_as="auto": prefer Content-Disposition,
// then URL basename.
fs::path auto_download_path(const std::string& url,
                             const std::vector<std::string>& response_headers)
{
    // Try Content-Disposition filename
    std::string fname = content_disposition_filename(response_headers);
    if (fname.empty()) {
        // Derive from URL path (strip query string)
        std::string path = url;
        const auto q = path.find('?');
        if (q != std::string::npos) path = path.substr(0, q);
        fname = media::path::path_to_utf8(media::path::path_from_utf8(path).filename());
    }
    if (fname.empty()) fname = "download";

    // Place in system Downloads folder or CWD
    std::string base;
#if defined(_WIN32)
    PWSTR wpath = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_Downloads, KF_FLAG_DEFAULT, nullptr, &wpath)) && wpath) {
        // Convert wide to UTF-8
        const int n = ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1, nullptr, 0, nullptr, nullptr);
        if (n > 0) {
            std::string u(static_cast<size_t>(n - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1, u.data(), n, nullptr, nullptr);
            base = std::move(u);
        }
        ::CoTaskMemFree(wpath);
    }
#else
    {
        const char* home = std::getenv("HOME");
        if (home) base = media::path::path_to_utf8((media::path::path_from_utf8(home) / "Downloads"));
    }
#endif
    if (base.empty()) base = media::path::path_to_utf8(fs::current_path());
    return media::path::path_from_utf8(base) / fname;
}

// ── Single HTTP attempt ───────────────────────────────────────────────────────
//
// Returns true on success (ok=true in out), false otherwise.
// `body_sink` must be one of:
//   - a std::string* (body to memory)
//   - a std::ofstream* (body to file) combined with `body_to_file=true`

struct AttemptResult {
    CURLcode    curl_code   = CURLE_OK;
    long        status_code = 0;
    std::string effective_url;
    std::vector<std::string> resp_headers;
    std::string error;
};

struct RevalidationHints {
    std::string if_none_match;
    std::string if_modified_since;
};

AttemptResult run_attempt(const HttpRequest& req,
                          void* body_sink,
                          bool  body_to_file,
                          const RevalidationHints& reval,
                          const std::string& effective_url,
                          const std::string& cookie_jar_path)
{
    AttemptResult out;

    // Reuse the thread-local handle (reset clears options, keeps connection pool).
    CURL* curl = tl_curl.get();
    if (!curl) {
        out.error     = "curl handle unavailable";
        out.curl_code = CURLE_FAILED_INIT;
        return out;
    }

    curl_slist* hdrs = nullptr;
    for (const auto& h : req.headers)
        hdrs = curl_slist_append(hdrs, h.c_str());
    hdrs = apply_auth(req.auth, hdrs, curl);
    if (!reval.if_none_match.empty())
        hdrs = curl_slist_append(hdrs, ("If-None-Match: " + reval.if_none_match).c_str());
    if (!reval.if_modified_since.empty())
        hdrs = curl_slist_append(hdrs, ("If-Modified-Since: " + reval.if_modified_since).c_str());

    char errbuf[CURL_ERROR_SIZE] = {};
    ProgressData pd{ &req.cancel_check };

    // ── Cookie jar (session) ──────────────────────────────────────────────────
    if (!cookie_jar_path.empty()) {
        // CURLOPT_COOKIEFILE enables the cookie engine and loads existing cookies.
        // CURLOPT_COOKIEJAR saves cookies when the handle is closed or flushed.
        curl_easy_setopt(curl, CURLOPT_COOKIEFILE, cookie_jar_path.c_str());
        curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  cookie_jar_path.c_str());
    }

    // ── Core ─────────────────────────────────────────────────────────────────
    curl_easy_setopt(curl, CURLOPT_URL,               effective_url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,     req.method.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,        req.timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, req.connect_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,    req.follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,         req.max_redirects);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,    req.verify_peer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,    req.verify_host ? 2L : 0L);
#if defined(__ANDROID__)
    if (const char* ca = std::getenv("CURL_CA_BUNDLE"); ca && ca[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
#endif
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER,       errbuf);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS,        0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,  cb_progress);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA,      &pd);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,    cb_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA,        &out.resp_headers);

    // ── Speed / throughput ────────────────────────────────────────────────────
    // Disable SIGALRM-based timeouts — required for correctness in any
    // multi-threaded environment (Taskflow workers, background xblox blocks).
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,          1L);

    // Advertise all compiled-in encodings (gzip / deflate / br / zstd) and
    // let curl decompress transparently. Typically 60-80 % smaller on the wire
    // for JSON/text. Pass "" = all supported encodings.
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING,   "");

    // Prefer HTTP/2 on TLS connections (multiplexing, header compression).
    // Falls back to HTTP/1.1 automatically when the server doesn't support it.
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,      CURL_HTTP_VERSION_2TLS);

    // Stall detection: kill the transfer if throughput drops below 1 byte/sec
    // for 30 consecutive seconds. Prevents a silent hang from consuming the
    // full CURLOPT_TIMEOUT_MS budget (which could be 5 min for large files).
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,   1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,    30L);

    // TCP keepalive: send probes after 60 s idle, every 15 s.
    // Keeps the connection alive through NAT/firewall idle timeouts so that
    // consecutive requests to the same host don't need a new TCP handshake.
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE,     1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE,      60L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL,     15L);

    // Increase receive buffer to 256 KB (default: 16 KB).
    // Reduces the number of recv() syscalls on large bodies.
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE,        262144L);

    // ── Body sink ─────────────────────────────────────────────────────────────
    if (body_to_file) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_file);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     body_sink);
    } else {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_string);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     body_sink);
    }

    // ── Proxy ─────────────────────────────────────────────────────────────────
    if (!req.proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, req.proxy.c_str());
        if (!req.proxy_user.empty() || !req.proxy_pass.empty()) {
            const std::string cred = req.proxy_user + ":" + req.proxy_pass;
            curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, cred.c_str());
        }
    }

    // ── Content-Type injection ────────────────────────────────────────────────
    // Inject only if caller supplied content_type and no Content-Type is already
    // present in the explicit headers list.
    if (!req.content_type.empty()) {
        const std::string lct = media::strutil::lower_ascii(req.content_type);
        const bool already_set = [&]() {
            for (const auto& h : req.headers)
                if (media::strutil::lower_ascii(h).find("content-type:") == 0) return true;
            return false;
        }();
        if (!already_set)
            hdrs = curl_slist_append(hdrs, ("Content-Type: " + req.content_type).c_str());
    }

    // ── Request body ──────────────────────────────────────────────────────────
    curl_mime* mime = nullptr;

    if (!req.body_parts.empty()) {
        // ── Multipart ────────────────────────────────────────────────────────
        mime = curl_mime_init(curl);
        for (const auto& part : req.body_parts) {
            if (part.empty()) continue;
            curl_mimepart* mp = curl_mime_addpart(mime);
            const auto at  = part.find('@');
            const auto eq  = part.find('=');
            if (at != std::string::npos && (eq == std::string::npos || at < eq)) {
                // "name@/path/to/file" — or "@/path" (name = filename)
                std::string name  = part.substr(0, at);
                const std::string filepath = part.substr(at + 1);
                if (name.empty())
                    name = media::path::path_to_utf8(media::path::path_from_utf8(filepath).filename());
                curl_mime_name(mp, name.c_str());
                curl_mime_filedata(mp, filepath.c_str());
            } else if (eq != std::string::npos) {
                // "name=value" — text field
                const std::string name  = part.substr(0, eq);
                const std::string value = part.substr(eq + 1);
                curl_mime_name(mp, name.c_str());
                curl_mime_data(mp, value.c_str(), CURL_ZERO_TERMINATED);
            } else {
                // bare filepath — use filename as field name
                const std::string name = media::path::path_to_utf8(media::path::path_from_utf8(part).filename());
                curl_mime_name(mp, name.c_str());
                curl_mime_filedata(mp, part.c_str());
            }
        }
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    } else if (!req.body.empty()) {
        // ── Raw / JSON / form-encoded body ────────────────────────────────────
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    req.body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
    }

    if (hdrs)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    out.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status_code);

    // Flush cookies to the jar immediately (before the handle is reset on the
    // next call). Required because curl_easy_reset() clears cookie state.
    if (!cookie_jar_path.empty())
        curl_easy_setopt(curl, CURLOPT_COOKIELIST, "FLUSH");

    char* eff_url = nullptr;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &eff_url);
    out.effective_url = eff_url ? eff_url : effective_url;

    if (out.curl_code != CURLE_OK) {
        out.error = errbuf[0] != '\0' ? errbuf : curl_easy_strerror(out.curl_code);
        if (out.curl_code == CURLE_ABORTED_BY_CALLBACK)
            out.error = "network request cancelled";
    }

    // hdrs and mime are freed; the handle itself is NOT cleaned up — it returns
    // to the thread-local pool so its connection cache survives to the next call.
    if (mime) curl_mime_free(mime);
    if (hdrs) curl_slist_free_all(hdrs);
    return out;
}

} // namespace (anonymous)

// ── Public API ─────────────────────────────────────────────────────────────────

AuthKind parse_auth_kind(const std::string& mode)
{
    const std::string m = media::strutil::lower_ascii(mode);
    if (m == "bearer") return AuthKind::Bearer;
    if (m == "basic")  return AuthKind::Basic;
    if (m == "apikey" || m == "api_key" || m == "api-key" || m == "token")
        return AuthKind::ApiKey;
    return AuthKind::None;
}

void apply_auth_to_headers(const Auth& auth, nlohmann::json& headers)
{
    merge_auth_into_headers(auth, headers);
}

std::string default_net_cache_dir()
{
    std::string base;
#if defined(_WIN32)
    PWSTR wpath = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &wpath)) && wpath) {
        const int n = ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1, nullptr, 0, nullptr, nullptr);
        if (n > 0) {
            std::string u(static_cast<size_t>(n - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1, u.data(), n, nullptr, nullptr);
            base = std::move(u);
        }
        ::CoTaskMemFree(wpath);
    }
#elif defined(__APPLE__)
    {
        const char* home = std::getenv("HOME");
        if (home) base = media::path::path_to_utf8((media::path::path_from_utf8(home) / "Library" / "Caches"));
    }
#else
    {
        const char* xdg = std::getenv("XDG_CACHE_HOME");
        if (xdg && xdg[0]) {
            base = xdg;
        } else {
            const char* home = std::getenv("HOME");
            if (home) base = media::path::path_to_utf8((media::path::path_from_utf8(home) / ".cache"));
        }
    }
#endif
    if (base.empty()) base = media::path::path_to_utf8(fs::current_path());
    return media::path::path_to_utf8((media::path::path_from_utf8(base) / "tanit" / "net"));
}

std::string default_net_session_dir()
{
    std::string base;
#if defined(_WIN32)
    PWSTR wpath = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &wpath)) && wpath) {
        const int n = ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1, nullptr, 0, nullptr, nullptr);
        if (n > 0) {
            std::string u(static_cast<size_t>(n - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wpath, -1, u.data(), n, nullptr, nullptr);
            base = std::move(u);
        }
        ::CoTaskMemFree(wpath);
    }
#elif defined(__APPLE__)
    {
        const char* home = std::getenv("HOME");
        if (home) base = media::path::path_to_utf8((media::path::path_from_utf8(home) / "Library" / "Caches"));
    }
#else
    {
        const char* xdg = std::getenv("XDG_CACHE_HOME");
        if (xdg && xdg[0]) { base = xdg; }
        else {
            const char* home = std::getenv("HOME");
            if (home) base = media::path::path_to_utf8((media::path::path_from_utf8(home) / ".cache"));
        }
    }
#endif
    if (base.empty()) base = media::path::path_to_utf8(fs::current_path());
    return media::path::path_to_utf8((media::path::path_from_utf8(base) / "tanit" / "sessions"));
}

// ── Query-parameter URL builder ───────────────────────────────────────────────

// Returns a URL with the given query params appended (percent-encoded).
// Handles both a URL that already has a query string and one that doesn't.
std::string append_query_params(std::string url,
                                const std::vector<std::string>& params)
{
    if (params.empty()) return url;
    // Re-use the same percent_encode defined later in this TU, but declare
    // a local lambda to avoid forward-declaration churn.
    auto pct = [](const std::string& s) {
        std::string out;
        out.reserve(s.size() * 3);
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                out += static_cast<char>(c);
            else { char buf[4]; std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned>(c)); out += buf; }
        }
        return out;
    };
    std::string qs;
    for (const auto& p : params) {
        if (!qs.empty()) qs += '&';
        const auto eq = p.find('=');
        if (eq == std::string::npos) {
            qs += pct(p);
        } else {
            qs += pct(p.substr(0, eq)) + '=' + pct(p.substr(eq + 1));
        }
    }
    url += (url.find('?') == std::string::npos ? '?' : '&');
    url += qs;
    return url;
}

namespace {

std::string trim_ascii(std::string s)
{
    const auto l = s.find_first_not_of(" \t\r\n");
    if (l == std::string::npos)
        return {};
    const auto r = s.find_last_not_of(" \t\r\n");
    return s.substr(l, r - l + 1);
}

nlohmann::json parse_json_headers_value(nlohmann::json v)
{
    if (v.is_string()) {
        v = media::json::try_parse(v.get<std::string>());
        if (!media::json::parse_ok(v))
            return nlohmann::json::object();
    }

    nlohmann::json out = nlohmann::json::object();
    if (v.is_object()) {
        for (auto it = v.begin(); it != v.end(); ++it) {
            if (it.key().empty())
                continue;
            if (it.value().is_string())
                out[it.key()] = it.value().get<std::string>();
            else if (!it.value().is_null())
                out[it.key()] = it.value().dump();
        }
    } else if (v.is_array()) {
        for (const auto& item : v) {
            if (!item.is_string())
                continue;
            const std::string line = item.get<std::string>();
            const auto colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            const std::string name = trim_ascii(line.substr(0, colon));
            const std::string val  = trim_ascii(line.substr(colon + 1));
            if (!name.empty())
                out[name] = val;
        }
    }
    return out;
}

} // namespace

nlohmann::json parse_json_headers_object(const nlohmann::json& raw)
{
    return parse_json_headers_value(raw);
}

void append_json_headers(const void* json_ptr, std::vector<std::string>& out)
{
    if (!json_ptr) return;
    const auto& raw = *static_cast<const nlohmann::json*>(json_ptr);
    const nlohmann::json parsed = parse_json_headers_value(raw);
    if (!parsed.is_object())
        return;
    for (auto it = parsed.begin(); it != parsed.end(); ++it) {
        if (it.value().is_string())
            out.push_back(it.key() + ": " + it.value().get<std::string>());
    }
}

HttpResponse http_fetch(const HttpRequest& req)
{
    HttpResponse resp;
    const bool has_cache  = req.cache.enabled;
    const bool is_download = !req.download_as.empty();

    // ── Effective URL (query params appended) ─────────────────────────────────
    const std::string effective_url = append_query_params(req.url, req.query_params);

    // ── Session lock + cookie jar path ────────────────────────────────────────
    std::unique_lock<std::mutex> session_lock;
    std::string cookie_jar_path;
    if (!req.session_id.empty()) {
        // Acquire the per-session mutex — serializes all requests within a session.
        session_lock = std::unique_lock<std::mutex>(session_mutex(req.session_id));
        const std::string sess_dir = req.session_dir.empty()
            ? default_net_session_dir() : req.session_dir;
        std::error_code ec;
        fs::create_directories(media::path::path_from_utf8(sess_dir), ec);
        cookie_jar_path = media::path::path_to_utf8((media::path::path_from_utf8(sess_dir) / (req.session_id + ".cookies")));
    }

    // ── Cache lookup ──────────────────────────────────────────────────────────
    CacheMeta cached_meta;
    std::string cached_body;
    const std::string cdir = has_cache ? resolved_cache_dir(req.cache) : std::string{};
    const std::string ckey = has_cache ? cache_key(effective_url, req.method) : std::string{};

    RevalidationHints reval;
    bool cache_hit = false;

    if (has_cache && cache_load(cdir, ckey, cached_meta, cached_body)) {
        const int64_t now = now_epoch_ms();
        const bool expired = req.cache.ttl_ms == 0 ||
            (cached_meta.expires_at_ms > 0 && now > cached_meta.expires_at_ms);
        if (!expired && !req.cache.force_revalidate) {
            // Fresh hit — return immediately without touching the network.
            resp.ok               = true;
            resp.status_code      = 200;
            resp.body             = cached_body;
            resp.from_cache       = true;
            resp.effective_url    = effective_url;
            if (is_download) {
                // Copy to requested path.
                const fs::path dest = req.download_as == "auto"
                    ? auto_download_path(req.url, {})
                    : media::path::path_from_utf8(req.download_as);
                std::error_code ec;
                fs::create_directories(dest.parent_path(), ec);
                std::ofstream ofs(dest, std::ios::binary);
                if (ofs.is_open()) {
                    ofs.write(cached_body.data(), static_cast<std::streamsize>(cached_body.size()));
                    resp.saved_path = media::path::path_to_utf8(dest);
                    resp.body.clear();
                }
            }
            return resp;
        }
        // Stale but present — supply revalidation hints.
        reval.if_none_match      = cached_meta.etag;
        reval.if_modified_since  = cached_meta.last_modified;
        cache_hit = true;
    }

    // ── Retry loop ────────────────────────────────────────────────────────────
    for (int attempt = 0; attempt <= req.retries; ++attempt) {
        resp.attempts = attempt + 1;

        // Set up body sink (memory or file)
        std::string    mem_body;
        std::ofstream  file_sink;
        fs::path       dest_path;
        bool           body_to_file = false;

        if (is_download) {
            dest_path = (req.download_as == "auto")
                ? auto_download_path(req.url, {})
                : media::path::path_from_utf8(req.download_as);
            std::error_code ec;
            fs::create_directories(dest_path.parent_path(), ec);
            file_sink.open(dest_path, std::ios::binary | std::ios::trunc);
            body_to_file = file_sink.is_open();
            if (!body_to_file) {
                resp.error = "cannot open output file: " + media::path::path_to_utf8(dest_path);
                resp.ok    = false;
                return resp;
            }
        }

        void* sink_ptr = body_to_file
            ? static_cast<void*>(&file_sink)
            : static_cast<void*>(&mem_body);

        auto ar = run_attempt(req, sink_ptr, body_to_file, reval,
                              effective_url, cookie_jar_path);

        if (body_to_file) {
            file_sink.close();
        }

        resp.response_headers = std::move(ar.resp_headers);
        resp.effective_url    = ar.effective_url;

        // ── 304 Not Modified — reuse cached body ─────────────────────────────
        if (ar.curl_code == CURLE_OK && ar.status_code == 304 && cache_hit) {
            // Refresh expiry in the stored metadata.
            cached_meta.expires_at_ms = now_epoch_ms() +
                (req.cache.ttl_ms >= 0 ? req.cache.ttl_ms : 3'600'000);
            cache_store(cdir, ckey, cached_meta, cached_body);
            resp.ok            = true;
            resp.status_code   = 200;
            resp.body          = cached_body;
            resp.from_cache    = true;
            if (body_to_file) {
                // The file was (re-)opened; overwrite it with cached content.
                std::ofstream ofs(dest_path, std::ios::binary | std::ios::trunc);
                if (ofs.is_open()) {
                    ofs.write(cached_body.data(), static_cast<std::streamsize>(cached_body.size()));
                    resp.saved_path = media::path::path_to_utf8(dest_path);
                    resp.body.clear();
                }
            }
            return resp;
        }

        // ── Success ───────────────────────────────────────────────────────────
        if (ar.curl_code == CURLE_OK && ar.status_code < 400) {
            resp.ok          = true;
            resp.status_code = ar.status_code;

            if (body_to_file) {
                resp.saved_path = media::path::path_to_utf8(dest_path);
                resp.body.clear();
            } else {
                resp.body = std::move(mem_body);
            }

            // Store in cache
            if (has_cache) {
                const std::string& body_to_cache = body_to_file ? cached_body : resp.body;
                // For downloadAs+cache, read back from file
                std::string file_content;
                const std::string* to_store = &resp.body;
                if (body_to_file) {
                    std::ifstream ifs(dest_path, std::ios::binary);
                    if (ifs.is_open())
                        file_content.assign(std::istreambuf_iterator<char>(ifs),
                                            std::istreambuf_iterator<char>());
                    to_store = &file_content;
                }
                CacheMeta new_meta;
                new_meta.etag          = find_header(resp.response_headers, "ETag");
                new_meta.last_modified = find_header(resp.response_headers, "Last-Modified");
                new_meta.expires_at_ms = now_epoch_ms() +
                    (req.cache.ttl_ms >= 0 ? req.cache.ttl_ms : 3'600'000);
                cache_store(cdir, ckey, new_meta, *to_store);
            }
            return resp;
        }

        // ── Failure ───────────────────────────────────────────────────────────
        resp.ok          = false;
        resp.status_code = ar.status_code;
        resp.error       = ar.error.empty()
            ? (ar.status_code > 0 ? "HTTP " + std::to_string(ar.status_code) : "unknown error")
            : ar.error;

        // Clean up partial download file.
        if (body_to_file) {
            std::error_code ec;
            fs::remove(dest_path, ec);
        }

        const bool cancelled = ar.curl_code == CURLE_ABORTED_BY_CALLBACK;
        const bool can_retry = !cancelled && attempt < req.retries &&
                               (ar.curl_code != CURLE_OK || should_retry_status(ar.status_code));
        if (!can_retry) break;

        const int delay = backoff_ms(req.retry_delay_ms, attempt);
        if (req.cancel_check && cancellable_sleep(delay, req.cancel_check)) {
            resp.error = "network request cancelled";
            break;
        }
    }

    return resp;
}

namespace {

std::string env_proxy()
{
    static const char* k_keys[] = {
        "https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY",
    };
    for (const char* key : k_keys) {
        const char* value = std::getenv(key);
        if (value && value[0])
            return value;
    }
    return {};
}

std::string url_basename(const std::string& url)
{
    std::string path = url;
    const auto query = path.find('?');
    if (query != std::string::npos)
        path.erase(query);
    const auto hash = path.find('#');
    if (hash != std::string::npos)
        path.erase(hash);
    const auto scheme = path.find("://");
    if (scheme != std::string::npos) {
        const auto slash = path.find('/', scheme + 3);
        path = slash == std::string::npos ? std::string{} : path.substr(slash);
    }
    const auto slash = path.find_last_of('/');
    if (slash != std::string::npos)
        path = path.substr(slash + 1);
    return path;
}

bool http_url(const std::string& url)
{
    return url.rfind("https://", 0) == 0 || url.rfind("http://", 0) == 0;
}

std::string download_url_blocked(const std::string& url)
{
    pm::uri::ParseOptions opt;
    opt.reject_userinfo = true;
    const auto parsed = pm::uri::parse_http_uri(url, opt);
    if (!parsed || !parsed->valid)
        return "url must be http or https";
    std::string reason;
    if (pm::uri::host_is_private_or_invalid(*parsed, reason))
        return reason.empty() ? "private or invalid host" : "refusing " + reason;

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    const std::string port = parsed->port.empty()
        ? (parsed->scheme == "https" ? "443" : "80")
        : parsed->port;
    addrinfo* resolved = nullptr;
    if (getaddrinfo(parsed->host.c_str(), port.c_str(), &hints, &resolved) != 0)
        return "cannot resolve host";
    std::string blocked;
    for (addrinfo* it = resolved; it != nullptr; it = it->ai_next) {
        char numeric[NI_MAXHOST] = {};
        if (getnameinfo(it->ai_addr, static_cast<socklen_t>(it->ai_addrlen),
                        numeric, sizeof(numeric), nullptr, 0, NI_NUMERICHOST) != 0)
            continue;
        pm::uri::ParsedUri address = *parsed;
        address.host = numeric;
        std::string ip_reason;
        if (pm::uri::host_is_private_or_invalid(address, ip_reason)) {
            blocked = ip_reason.empty() ? "refusing private address" : "refusing " + ip_reason;
            break;
        }
    }
    freeaddrinfo(resolved);
    return blocked;
}

bool name_has_extension(const std::string& name)
{
    const auto slash = name.find_last_of("/\\");
    const std::string base = slash == std::string::npos ? name : name.substr(slash + 1);
    const auto dot = base.find_last_of('.');
    return dot != std::string::npos && dot > 0 && dot + 1 < base.size();
}

struct CappedFile {
    std::ofstream* ofs = nullptr;
    const CancelCheck* cancel = nullptr;
    std::uint64_t  bytes = 0;
    bool           overflow = false;
    bool           cancelled = false;
    static constexpr std::uint64_t k_cap = 2ull << 30;
};

struct DownloadXfer {
    const CancelCheck* cancel = nullptr;
    const DownloadProgressFn* progress = nullptr;
    std::chrono::steady_clock::time_point last{};
    bool cancelled = false;
};

int cb_download_xfer(void* ud, curl_off_t, curl_off_t, curl_off_t dltotal, curl_off_t dlnow)
{
    auto* x = static_cast<DownloadXfer*>(ud);
    if (!x)
        return 0;
    if (x->cancel && (*x->cancel)()) {
        x->cancelled = true;
        return 1;
    }
    if (x->progress && dlnow >= 0) {
        const auto now = std::chrono::steady_clock::now();
        if (x->last.time_since_epoch().count() == 0
            || now - x->last >= std::chrono::milliseconds(250)) {
            x->last = now;
            const auto total = dltotal > 0 ? static_cast<std::uint64_t>(dltotal) : 0ull;
            (*x->progress)(static_cast<std::uint64_t>(dlnow), total);
        }
    }
    return 0;
}

size_t cb_write_capped(char* ptr, size_t size, size_t nmemb, void* ud)
{
    auto* file = static_cast<CappedFile*>(ud);
    if (file->cancel && (*file->cancel)()) {
        file->cancelled = true;
        return 0;
    }
    const auto n = static_cast<std::uint64_t>(size) * static_cast<std::uint64_t>(nmemb);
    if (file->bytes + n > CappedFile::k_cap) {
        file->overflow = true;
        return 0;
    }
    file->ofs->write(ptr, static_cast<std::streamsize>(n));
    if (!file->ofs->good())
        return 0;
    file->bytes += n;
    return size * nmemb;
}

fs::path unique_download_path(const fs::path& dir, const std::string& name)
{
    const fs::path first = dir / media::path::path_from_utf8(name);
    std::error_code ec;
    if (!fs::exists(first, ec))
        return first;
    const fs::path parsed = media::path::path_from_utf8(name);
    const std::string stem = media::path::path_to_utf8(parsed.stem());
    const std::string ext = media::path::path_to_utf8(parsed.extension());
    for (int i = 2; i < 100; ++i) {
        const fs::path candidate = dir / media::path::path_from_utf8(stem + "-" + std::to_string(i) + ext);
        if (!fs::exists(candidate, ec))
            return candidate;
    }
    return {};
}

} // namespace

UrlDownloadResult download_url_file(const UrlDownloadRequest& req)
{
    UrlDownloadResult out;
    if (!http_url(req.url)) {
        out.error = "url must be http or https";
        return out;
    }
    if (req.directory.empty()) {
        out.error = "download directory is empty";
        return out;
    }

    const fs::path dir = media::path::path_from_utf8(req.directory);
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        out.error = "cannot create download directory";
        return out;
    }

    static std::atomic<std::uint64_t> seq{0};
    const fs::path temp = dir / media::path::path_from_utf8("dl-" + std::to_string(seq.fetch_add(1)) + ".part");
    std::ofstream ofs(temp, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        fs::remove(temp, ec);
        out.error = "cannot open temporary download file";
        return out;
    }

    auto discard = [&]() {
        ofs.close();
        std::error_code rm;
        fs::remove(temp, rm);
    };

    ensure_curl_global_init();
    CURL* curl = curl_easy_init();
    if (!curl) {
        discard();
        out.error = "curl_easy_init failed";
        return out;
    }

    std::vector<std::string> headers;
    CappedFile capped;
    capped.ofs = &ofs;
    capped.cancel = req.cancel_check ? &req.cancel_check : nullptr;
    DownloadXfer xfer;
    xfer.cancel = capped.cancel;
    xfer.progress = req.on_progress ? &req.on_progress : nullptr;
    char errbuf[CURL_ERROR_SIZE] = {};
    const std::string proxy = req.proxy.empty() ? env_proxy() : req.proxy;

    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 4000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(__ANDROID__)
    // NDK curl+mbedTLS has no system trust store; the host exports CURL_CA_BUNDLE.
    if (const char* ca = std::getenv("CURL_CA_BUNDLE"); ca && ca[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
#endif
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_capped);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &capped);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, cb_download_xfer);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &xfer);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, cb_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
#if defined(CURLOPT_PROTOCOLS_STR)
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
    if (!proxy.empty()) {
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());
        if (!req.proxy_user.empty() || !req.proxy_pass.empty()) {
            const std::string cred = req.proxy_user + ":" + req.proxy_pass;
            curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, cred.c_str());
        }
    }

    std::string current = req.url;
    CURLcode rc = CURLE_OK;
    long status = 0;
    char* effective = nullptr;
    char* content_type = nullptr;
    for (int hop = 0; hop < 4; ++hop) {
        if (const std::string why = download_url_blocked(current); !why.empty()) {
            curl_easy_cleanup(curl);
            discard();
            out.error = why;
            return out;
        }
        ofs.close();
        ofs.open(temp, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            curl_easy_cleanup(curl);
            discard();
            out.error = "cannot open temporary download file";
            return out;
        }
        capped.bytes = 0;
        capped.overflow = false;
        capped.cancelled = false;
        xfer.cancelled = false;
        headers.clear();
        errbuf[0] = '\0';
        curl_easy_setopt(curl, CURLOPT_URL, current.c_str());
        rc = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        char* next = nullptr;
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &next);
        if (rc == CURLE_OK && !capped.overflow && !capped.cancelled && !xfer.cancelled
            && status >= 300 && status < 400 && next && next[0] != '\0') {
            if (hop == 3) {
                curl_easy_cleanup(curl);
                discard();
                out.error = "too many redirects";
                return out;
            }
            current = next;
            continue;
        }
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective);
        curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
        break;
    }
    out.status_code = status;
    if (effective)
        out.effective_url = effective;
    if (content_type)
        out.content_type = content_type;
    ofs.close();
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || capped.overflow || capped.cancelled || xfer.cancelled || capped.bytes == 0) {
        const bool cancelled = capped.cancelled || xfer.cancelled || rc == CURLE_ABORTED_BY_CALLBACK;
        out.bytes = capped.bytes;
        discard();
        if (cancelled) {
            out.cancelled = true;
            out.error = "cancelled";
        } else if (capped.overflow)
            out.error = "download exceeded 2GB";
        else if (rc == CURLE_HTTP_RETURNED_ERROR)
            out.error = "HTTP " + std::to_string(status);
        else if (capped.bytes == 0 && rc == CURLE_OK)
            out.error = "empty response";
        else
            out.error = errbuf[0] ? errbuf : curl_easy_strerror(rc);
        return out;
    }

    const std::string from_url = url_basename(out.effective_url.empty() ? req.url : out.effective_url);
    std::string raw_name;
    if (req.explicit_filename && !req.filename.empty())
        raw_name = req.filename;
    if (raw_name.empty())
        raw_name = content_disposition_filename(headers);
    if (raw_name.empty())
        raw_name = from_url;
    if (raw_name.empty())
        raw_name = req.filename;
    std::string name = media::path::sanitize_filename(raw_name, "_");
    if (name.empty())
        name = "download";
    if (!name_has_extension(name)) {
        const media::probe::ProbeResult probed = media::probe::probe_file(temp);
        if (probed.ok && !probed.preferred_extension.empty()) {
            name += probed.preferred_extension;
            if (out.content_type.empty() || out.content_type == "application/octet-stream")
                out.content_type = probed.content_type;
        }
    }

    const fs::path final_path = unique_download_path(dir, name);
    if (final_path.empty()) {
        discard();
        out.error = "too many files with that name";
        return out;
    }
    fs::rename(temp, final_path, ec);
    if (ec) {
        discard();
        out.error = "cannot save download";
        return out;
    }
    out.ok = true;
    out.bytes = capped.bytes;
    out.path = media::path::path_to_utf8(final_path);
    if (req.on_progress)
        req.on_progress(capped.bytes, capped.bytes);
    return out;
}

} // namespace media::net
