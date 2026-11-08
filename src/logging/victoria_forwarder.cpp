#include "victoria_forwarder.hpp"

#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <cerrno>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include "string/string_utils.hpp"

namespace pm::logging {
namespace {

constexpr int k_probe_timeout_ms = 400;
constexpr int k_post_timeout_ms = 800;
constexpr std::size_t k_batch_size = 100;
constexpr std::size_t k_queue_limit = 4000;
constexpr std::size_t k_mirror_limit = 64;
constexpr std::size_t k_message_limit = 16 * 1024;
constexpr const char* k_insert_path =
    "/insert/jsonline?_stream_fields=source,device,build,session_id&_msg_field=message&_time_field=_time";

struct Endpoint {
    std::string host = "127.0.0.1";
    int port = 9428;
};

struct State {
    VictoriaForwarderConfig config;
    Endpoint endpoint;
    std::string source;
    std::string device;
    std::string build;
    std::string session_id;
    std::string pid;

    std::mutex queue_mu;
    std::condition_variable queue_cv;
    std::deque<std::string> queue;
    bool stop = false;
    bool posting = false;
    std::thread worker;

    ~State()
    {
        {
            std::lock_guard<std::mutex> lock(queue_mu);
            stop = true;
        }
        queue_cv.notify_all();
        if (worker.joinable())
            worker.join();
    }

    std::mutex mirror_mu;
    std::deque<std::string> mirrored;

    std::shared_ptr<spdlog::sinks::sink> sink;
    std::once_flag probe_once;
    std::atomic<bool> enabled{false};
};

State& state()
{
    static State s;
    return s;
}

void append_json_string(std::string& out, std::string_view text)
{
    out.push_back('"');
    for (unsigned char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", c);
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    out.push_back('"');
}

std::string iso_now()
{
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    const std::time_t sec = static_cast<std::time_t>(ms.count() / 1000);
    const int fraction = static_cast<int>(ms.count() % 1000);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &sec);
#else
    gmtime_r(&sec, &tm);
#endif
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, fraction);
    return buf;
}

std::string trimmed_copy(std::string_view text)
{
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' '))
        text.remove_suffix(1);
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.remove_prefix(1);
    if (text.size() > k_message_limit)
        text = text.substr(0, k_message_limit);
    return std::string(text);
}

std::string make_event(std::string_view level, std::string_view component, std::string_view message)
{
    State& s = state();
    std::string out;
    out.reserve(message.size() + 256);
    out += "{\"_time\":";
    append_json_string(out, iso_now());
    out += ",\"source\":";
    append_json_string(out, s.source);
    out += ",\"device\":";
    append_json_string(out, s.device);
    out += ",\"build\":";
    append_json_string(out, s.build);
    out += ",\"session_id\":";
    append_json_string(out, s.session_id);
    out += ",\"pid\":";
    append_json_string(out, s.pid);
    out += ",\"level\":";
    append_json_string(out, level);
    out += ",\"component\":";
    append_json_string(out, component.empty() ? std::string_view("process") : component);
    out += ",\"message\":";
    append_json_string(out, message);
    out += "}";
    return out;
}

void enqueue(std::string event)
{
    State& s = state();
    {
        std::lock_guard<std::mutex> lock(s.queue_mu);
        if (s.stop)
            return;
        if (s.queue.size() >= k_queue_limit)
            s.queue.pop_front();
        s.queue.push_back(std::move(event));
    }
    s.queue_cv.notify_one();
}

#if defined(_WIN32)
using Socket = SOCKET;
constexpr Socket k_invalid_socket = INVALID_SOCKET;
void close_socket(Socket s) { closesocket(s); }
int last_socket_error() { return WSAGetLastError(); }
constexpr int k_would_block = WSAEWOULDBLOCK;
constexpr int k_in_progress = WSAEWOULDBLOCK;
void set_nonblocking(Socket s, bool on)
{
    u_long mode = on ? 1UL : 0UL;
    ioctlsocket(s, FIONBIO, &mode);
}
void ensure_sockets()
{
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA data{};
        WSAStartup(MAKEWORD(2, 2), &data);
    });
}
#else
using Socket = int;
constexpr Socket k_invalid_socket = -1;
void close_socket(Socket s) { ::close(s); }
int last_socket_error() { return errno; }
constexpr int k_would_block = EWOULDBLOCK;
constexpr int k_in_progress = EINPROGRESS;
void set_nonblocking(Socket s, bool on)
{
    const int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0)
        return;
    fcntl(s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}
void ensure_sockets() {}
#endif

bool wait_socket(Socket s, bool write, int timeout_ms)
{
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#if defined(_WIN32)
    const int rc = select(0, write ? nullptr : &set, write ? &set : nullptr, nullptr, &tv);
#else
    const int rc = select(static_cast<int>(s) + 1, write ? nullptr : &set, write ? &set : nullptr, nullptr, &tv);
#endif
    return rc > 0;
}

bool connect_with_timeout(Socket s, const sockaddr* addr, socklen_t len, int timeout_ms)
{
    set_nonblocking(s, true);
    const int rc = connect(s, addr, len);
    if (rc != 0) {
        const int err = last_socket_error();
        if (err != k_would_block && err != k_in_progress)
            return false;
        if (!wait_socket(s, true, timeout_ms))
            return false;
        int so_error = 0;
#if defined(_WIN32)
        int so_len = sizeof so_error;
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &so_len) != 0 || so_error != 0)
            return false;
#else
        socklen_t so_len = sizeof so_error;
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0 || so_error != 0)
            return false;
#endif
    }
    set_nonblocking(s, false);
    return true;
}

int http_status(const Endpoint& endpoint, const std::string& request, int timeout_ms)
{
    ensure_sockets();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    const std::string port = std::to_string(endpoint.port);
    if (getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &result) != 0 || !result)
        return -1;

    Socket sock = k_invalid_socket;
    bool connected = false;
    for (addrinfo* it = result; it; it = it->ai_next) {
        sock = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (sock == k_invalid_socket)
            continue;
        if (connect_with_timeout(sock, it->ai_addr, static_cast<socklen_t>(it->ai_addrlen), timeout_ms)) {
            connected = true;
            break;
        }
        close_socket(sock);
        sock = k_invalid_socket;
    }
    freeaddrinfo(result);
    if (!connected)
        return -1;

#if defined(_WIN32)
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof timeout);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof timeout);
#else
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#endif

    std::size_t sent = 0;
    while (sent < request.size()) {
#if defined(_WIN32)
        const int n = send(sock, request.data() + sent, static_cast<int>(request.size() - sent), 0);
#else
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
        const ssize_t n = send(sock, request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
#endif
        if (n <= 0) {
            close_socket(sock);
            return -1;
        }
        sent += static_cast<std::size_t>(n);
    }

    std::string response;
    char buf[512];
    while (response.size() < 1024) {
#if defined(_WIN32)
        const int n = recv(sock, buf, sizeof buf, 0);
#else
        const ssize_t n = recv(sock, buf, sizeof buf, 0);
#endif
        if (n <= 0)
            break;
        response.append(buf, static_cast<std::size_t>(n));
        if (response.find("\r\n") != std::string::npos)
            break;
    }
    close_socket(sock);

    const auto http = response.find("HTTP/");
    const auto space = http == std::string::npos ? std::string::npos : response.find(' ', http);
    if (space == std::string::npos || space + 3 >= response.size())
        return -1;
    return std::atoi(response.c_str() + space + 1);
}

std::string http_request(const char* method, const char* path, std::string_view body)
{
    State& s = state();
    std::string req;
    req.reserve(body.size() + 256);
    req += method;
    req += ' ';
    req += path;
    req += " HTTP/1.1\r\nHost: ";
    req += s.endpoint.host;
    req += ':';
    req += std::to_string(s.endpoint.port);
    req += "\r\nConnection: close\r\n";
    if (!body.empty()) {
        req += "Content-Type: application/stream+json\r\nContent-Length: ";
        req += std::to_string(body.size());
        req += "\r\n";
    }
    req += "\r\n";
    req.append(body);
    return req;
}

bool parse_url(std::string text, Endpoint& out)
{
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.pop_back();
    if (text.rfind("http://", 0) != 0)
        return false;
    text.erase(0, 7);
    const auto slash = text.find('/');
    if (slash != std::string::npos)
        text.erase(slash);
    if (text.empty())
        return false;
    const auto colon = text.rfind(':');
    if (colon == std::string::npos) {
        out.host = text;
        out.port = 80;
        return true;
    }
    out.host = text.substr(0, colon);
    out.port = std::atoi(text.c_str() + colon + 1);
    return !out.host.empty() && out.port > 0 && out.port <= 65535;
}

std::string env_value(const std::string& name)
{
    if (name.empty())
        return {};
#if defined(_WIN32)
    char buf[1024];
    const DWORD n = GetEnvironmentVariableA(name.c_str(), buf, sizeof buf);
    if (n == 0 || n >= sizeof buf)
        return {};
    return std::string(buf, n);
#else
    const char* value = std::getenv(name.c_str());
    return (value && value[0]) ? std::string(value) : std::string{};
#endif
}

std::string env_url()
{
    const VictoriaForwarderConfig& cfg = state().config;
    const std::string value = env_value(cfg.env_var);
    if (!value.empty())
        return value;
    return cfg.default_url;
}

bool disabled_by_env(std::string_view value)
{
    std::string lower(value);
    lower = media::strutil::lower_ascii(std::move(lower));
    return lower == "0" || lower == "off" || lower == "false" || lower == "none";
}

std::string computer_name()
{
    char buf[256] = {};
#if defined(_WIN32)
    DWORD n = sizeof buf;
    if (GetComputerNameA(buf, &n) && n > 0)
        return std::string(buf, n);
#else
    if (gethostname(buf, sizeof buf - 1) == 0 && buf[0])
        return buf;
#endif
    return "unknown";
}

const char* level_name(spdlog::level::level_enum level)
{
    switch (level) {
    case spdlog::level::trace: return "trace";
    case spdlog::level::debug: return "debug";
    case spdlog::level::warn: return "warn";
    case spdlog::level::err: return "error";
    case spdlog::level::critical: return "fatal";
    case spdlog::level::info: return "info";
    default: return "info";
    }
}

void post_batch(const std::vector<std::string>& batch)
{
    std::string body;
    for (const std::string& line : batch) {
        body += line;
        body.push_back('\n');
    }
    const std::string request = http_request("POST", k_insert_path, body);
    (void)http_status(state().endpoint, request, k_post_timeout_ms);
}

void worker_main()
{
    State& s = state();
    std::vector<std::string> batch;
    for (;;) {
        {
            std::unique_lock<std::mutex> lock(s.queue_mu);
            s.queue_cv.wait_for(lock, std::chrono::milliseconds(250), [&] {
                return s.stop || !s.queue.empty();
            });
            if (s.queue.empty()) {
                if (s.stop)
                    break;
                continue;
            }
            const bool stopping = s.stop;
            const std::size_t limit = stopping ? k_queue_limit : k_batch_size;
            while (!s.queue.empty() && batch.size() < limit) {
                batch.push_back(std::move(s.queue.front()));
                s.queue.pop_front();
            }
            if (stopping)
                s.queue.clear();
            s.posting = true;
            if (stopping && batch.empty())
                break;
        }
        post_batch(batch);
        batch.clear();
        {
            std::lock_guard<std::mutex> lock(s.queue_mu);
            s.posting = false;
        }
        s.queue_cv.notify_all();
    }
}

bool probe()
{
    const std::string configured = env_url();
    if (disabled_by_env(configured))
        return false;
    Endpoint endpoint;
    if (!parse_url(configured, endpoint))
        return false;
    State& s = state();
    s.endpoint = endpoint;
    const int status = http_status(endpoint, http_request("GET", "/health", {}), k_probe_timeout_ms);
    return status >= 200 && status < 300;
}

void fill_identity()
{
    State& s = state();
    s.source = s.config.source;
    s.device = computer_name();
    s.build = s.config.build;
    const auto pid = static_cast<unsigned long>(
#if defined(_WIN32)
        GetCurrentProcessId()
#else
        getpid()
#endif
    );
    s.pid = std::to_string(pid);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    s.session_id = "p" + s.pid + "-" + std::to_string(ms);
}

template <typename Mutex>
class victoria_sink : public spdlog::sinks::base_sink<Mutex> {
protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        const std::string message = trimmed_copy(std::string_view(msg.payload.data(), msg.payload.size()));
        if (message.empty())
            return;
        const std::string component = trimmed_copy(std::string_view(msg.logger_name.data(), msg.logger_name.size()));
        enqueue(make_event(level_name(msg.level), component, message));
    }
    void flush_() override {}
};

void attach_sink()
{
    State& s = state();
    auto logger = spdlog::default_logger();
    if (!logger)
        return;
    if (!s.sink)
        s.sink = std::make_shared<victoria_sink<std::mutex>>();
    auto& sinks = logger->sinks();
    if (std::find(sinks.begin(), sinks.end(), s.sink) == sinks.end())
        sinks.push_back(s.sink);
}

} // namespace

void set_victoria_forwarder_config(VictoriaForwarderConfig config)
{
    state().config = std::move(config);
}

void install_victoria_forwarder()
{
    try {
        State& s = state();
        if (s.config.env_var.empty() && s.config.default_url.empty())
            return;
        std::call_once(s.probe_once, [&] {
            if (!probe())
                return;
            fill_identity();
            s.enabled.store(true, std::memory_order_release);
            s.worker = std::thread(worker_main);
        });
        if (!s.enabled.load(std::memory_order_acquire))
            return;
        attach_sink();
    } catch (...) {
    }
}

void flush_victoria_forwarder()
{
    State& s = state();
    if (!s.enabled.load(std::memory_order_acquire))
        return;
    {
        std::lock_guard<std::mutex> lock(s.queue_mu);
        s.stop = true;
    }
    s.queue_cv.notify_all();
    if (s.worker.joinable())
        s.worker.join();
    s.enabled.store(false, std::memory_order_release);
}

void remember_victoria_mirror(std::string_view formatted_line)
{
    if (!state().enabled.load(std::memory_order_acquire))
        return;
    std::string text = trimmed_copy(formatted_line);
    if (text.empty())
        return;
    State& s = state();
    std::lock_guard<std::mutex> lock(s.mirror_mu);
    s.mirrored.push_back(std::move(text));
    while (s.mirrored.size() > k_mirror_limit)
        s.mirrored.pop_front();
}

void forward_victoria_panel_line(std::string_view line)
{
    State& s = state();
    if (!s.enabled.load(std::memory_order_acquire))
        return;
    std::string text = trimmed_copy(line);
    if (text.empty())
        return;
    {
        std::lock_guard<std::mutex> lock(s.mirror_mu);
        const auto found = std::find(s.mirrored.begin(), s.mirrored.end(), text);
        if (found != s.mirrored.end()) {
            s.mirrored.erase(found);
            return;
        }
    }
    enqueue(make_event("info", "panel", text));
}

} // namespace pm::logging
