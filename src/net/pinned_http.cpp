#include "pm/commons/net/http_client.hpp"
#include "pm/commons/net/tls.hpp"

#include <curl/curl.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string_view>
#include <utility>

namespace pm::commons::net {
namespace {

CURL* curl_easy_init_ca()
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return nullptr;
#if defined(__ANDROID__)
    const char* ca = std::getenv("CURL_CA_BUNDLE");
    if (!ca || !ca[0])
        ca = std::getenv("SSL_CERT_FILE");
    if (ca && ca[0])
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
#endif
    return curl;
}

size_t write_string(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

struct FileSink {
    FILE* fp = nullptr;
    std::uint64_t written = 0;
    std::uint64_t max_bytes = 0;
    Progress progress;
    std::uint64_t expected = 0;
    CancelCheck cancel;
    bool overflow = false;
    bool cancelled = false;
};

size_t write_file(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* sink = static_cast<FileSink*>(userdata);
    if (sink->cancel && sink->cancel()) {
        sink->cancelled = true;
        return 0;
    }
    const auto n = size * nmemb;
    if (sink->max_bytes && sink->written + n > sink->max_bytes) {
        sink->overflow = true;
        return 0;
    }
    if (std::fwrite(ptr, 1, n, sink->fp) != n)
        return 0;
    sink->written += n;
    if (sink->progress)
        sink->progress(sink->written, sink->expected);
    return n;
}

struct StreamSink {
    BodyChunk on_body;
    std::uint64_t written = 0;
    std::uint64_t max_bytes = 0;
    Progress progress;
    std::uint64_t expected = 0;
    CancelCheck cancel;
    bool overflow = false;
    bool cancelled = false;
    bool aborted = false;
};

size_t write_stream(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* sink = static_cast<StreamSink*>(userdata);
    if (sink->cancel && sink->cancel()) {
        sink->cancelled = true;
        return 0;
    }
    const auto n = size * nmemb;
    if (sink->max_bytes && sink->written + n > sink->max_bytes) {
        sink->overflow = true;
        return 0;
    }
    if (sink->on_body && !sink->on_body(ptr, n)) {
        sink->aborted = true;
        return 0;
    }
    sink->written += n;
    if (sink->progress)
        sink->progress(sink->written, sink->expected);
    return n;
}

struct HeaderState {
    long status = 0;
    std::string content_type;
    std::string content_range;
    std::uint64_t content_length = 0;
    HeaderSink sink;
    bool fired = false;
};

size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata)
{
    auto* st = static_cast<HeaderState*>(userdata);
    const auto n = size * nitems;
    std::string_view line(buffer, n);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.remove_suffix(1);
    if (line.empty()) {
        if (!st->fired && st->sink) {
            st->sink(st->status, st->content_type, st->content_length, st->content_range);
            st->fired = true;
        }
        return n;
    }
    if (line.size() >= 5 && (line[0] == 'H' || line[0] == 'h') && line.find("HTTP/") == 0) {
        const auto sp = line.find(' ');
        if (sp != std::string_view::npos) {
            long code = 0;
            for (std::size_t i = sp + 1; i < line.size() && line[i] >= '0' && line[i] <= '9'; ++i)
                code = code * 10 + (line[i] - '0');
            st->status = code;
        }
        return n;
    }
    const auto colon = line.find(':');
    if (colon == std::string_view::npos)
        return n;
    auto name = line.substr(0, colon);
    auto value = line.substr(colon + 1);
    while (!value.empty() && value.front() == ' ')
        value.remove_prefix(1);
    auto lower = [](std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s)
            out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
        return out;
    };
    const auto key = lower(name);
    if (key == "content-type")
        st->content_type.assign(value);
    else if (key == "content-range")
        st->content_range.assign(value);
    else if (key == "content-length") {
        std::uint64_t v = 0;
        for (unsigned char c : value) {
            if (c < '0' || c > '9')
                break;
            v = v * 10 + (c - '0');
        }
        st->content_length = v;
    }
    return n;
}

struct Prepared {
    std::string pin;
    std::string err;
    std::string code;
    bool ok = false;
};

Prepared prepare_pin(const Request& req)
{
    Prepared out;
    out.ok = true;
    if (req.spki_sha256_hex.empty())
        return out;
    if (req.url.rfind("https://", 0) != 0) {
        out.ok = false;
        out.code = "EPROTO";
        out.err = "the peer address is not https";
        return out;
    }
    out.pin = spki_pin_curl(req.spki_sha256_hex, out.err);
    if (out.pin.empty()) {
        out.ok = false;
        out.code = "EPIN";
        if (out.err.empty())
            out.err = "the certificate pin is not valid";
    }
    return out;
}

curl_slist* build_headers(const Request& req)
{
    curl_slist* hdr = nullptr;
    for (const auto& h : req.headers) {
        const std::string line = h.name + ": " + h.value;
        hdr = curl_slist_append(hdr, line.c_str());
    }
    // Bearer only when present — pin is enforced at TLS before these are sent.
    if (!req.bearer.empty()) {
        const std::string auth = "Authorization: Bearer " + req.bearer;
        hdr = curl_slist_append(hdr, auth.c_str());
    }
    return hdr;
}

void apply_common(CURL* curl, const Request& req, const std::string& pin, curl_slist* hdr)
{
    curl_easy_setopt(curl, CURLOPT_URL, req.url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, req.method.c_str());
    if (!req.body.empty() || req.method == "POST" || req.method == "PUT" || req.method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
    }
    const long timeout_s =
        req.timeout_ms <= 0 ? 0L : static_cast<long>((req.timeout_ms + 999) / 1000);
    const long connect_s =
        req.connect_timeout_ms <= 0 ? 0L : static_cast<long>((req.connect_timeout_ms + 999) / 1000);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_s);
    if (pin.empty()) {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, req.follow_redirects ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, req.max_redirects);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        // Pin replaces CA trust for this peer dial. No redirects (pin would not follow).
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin.c_str());
    }
}

Response fail(std::string code, std::string err)
{
    Response r;
    r.code = std::move(code);
    r.error = std::move(err);
    return r;
}

} // namespace

Response request(const Request& req)
{
    if (req.url.empty())
        return fail("EINVAL", "url is required");
    if (req.cancel && req.cancel())
        return fail("ECANCEL", "cancelled");

    const auto prep = prepare_pin(req);
    if (!prep.ok)
        return fail(prep.code, prep.err);

    CURL* curl = curl_easy_init_ca();
    if (!curl)
        return fail("EIO", "curl_easy_init failed");

    Response out;
    curl_slist* hdr = build_headers(req);
    apply_common(curl, req, prep.pin, hdr);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out.body);

    const CURLcode cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);

    if (req.max_bytes && out.body.size() > req.max_bytes) {
        out.body.clear();
        return fail("EFBIG", "response exceeds max_bytes");
    }
    if (cc != CURLE_OK) {
        out.code = "EIO";
        out.error = std::string("curl_easy_perform: ") + curl_easy_strerror(cc);
        return out;
    }
    out.ok = true;
    return out;
}

Response request_to_file(const Request& req, const std::filesystem::path& dest, FileOptions options)
{
    if (req.url.empty())
        return fail("EINVAL", "url is required");
    if (dest.empty())
        return fail("EINVAL", "dest is required");
    if (req.cancel && req.cancel())
        return fail("ECANCEL", "cancelled");

    const auto prep = prepare_pin(req);
    if (!prep.ok)
        return fail(prep.code, prep.err);

    std::error_code ec;
    if (dest.has_parent_path())
        std::filesystem::create_directories(dest.parent_path(), ec);

    FILE* fp = nullptr;
#if defined(_WIN32)
    if (_wfopen_s(&fp, dest.wstring().c_str(), L"wb") != 0 || !fp)
        return fail("EIO", "could not open destination");
#else
    fp = std::fopen(dest.string().c_str(), "wb");
    if (!fp)
        return fail("EIO", "could not open destination");
#endif

    FileSink sink;
    sink.fp = fp;
    sink.max_bytes = req.max_bytes;
    sink.progress = options.on_progress;
    sink.expected = options.expected_size;
    sink.cancel = req.cancel;

    CURL* curl = curl_easy_init_ca();
    if (!curl) {
        std::fclose(fp);
        return fail("EIO", "curl_easy_init failed");
    }

    Response out;
    curl_slist* hdr = build_headers(req);
    apply_common(curl, req, prep.pin, hdr);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);

    const CURLcode cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);
    std::fclose(fp);

    if (sink.cancelled)
        return fail("ECANCEL", "cancelled");
    if (sink.overflow) {
        std::error_code remove_ec;
        std::filesystem::remove(dest, remove_ec);
        return fail("EFBIG", "response exceeds max_bytes");
    }
    if (cc != CURLE_OK) {
        std::error_code remove_ec;
        std::filesystem::remove(dest, remove_ec);
        out.code = "EIO";
        out.error = std::string("curl_easy_perform: ") + curl_easy_strerror(cc);
        return out;
    }
    out.ok = true;
    out.body.clear();
    return out;
}

Response request_stream(const Request& req, StreamOptions options)
{
    if (req.url.empty())
        return fail("EINVAL", "url is required");
    if (!options.on_body)
        return fail("EINVAL", "on_body is required");
    if (req.cancel && req.cancel())
        return fail("ECANCEL", "cancelled");

    const auto prep = prepare_pin(req);
    if (!prep.ok)
        return fail(prep.code, prep.err);

    StreamSink sink;
    sink.on_body = std::move(options.on_body);
    sink.max_bytes = req.max_bytes;
    sink.progress = options.on_progress;
    sink.cancel = req.cancel;

    HeaderState headers;
    headers.sink = options.on_headers;

    CURL* curl = curl_easy_init_ca();
    if (!curl)
        return fail("EIO", "curl_easy_init failed");

    Response out;
    curl_slist* hdr = build_headers(req);
    if (!options.range.empty()) {
        const std::string range_hdr = "Range: " + options.range;
        hdr = curl_slist_append(hdr, range_hdr.c_str());
    }
    apply_common(curl, req, prep.pin, hdr);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_stream);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);

    const CURLcode cc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status);
    if (out.status == 0)
        out.status = headers.status;
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);

    if (sink.cancelled)
        return fail("ECANCEL", "cancelled");
    if (sink.overflow)
        return fail("EFBIG", "response exceeds max_bytes");
    if (sink.aborted)
        return fail("ECANCEL", "stream aborted");
    if (cc != CURLE_OK) {
        out.code = "EIO";
        out.error = std::string("curl_easy_perform: ") + curl_easy_strerror(cc);
        return out;
    }
    out.ok = true;
    return out;
}

} // namespace pm::commons::net
