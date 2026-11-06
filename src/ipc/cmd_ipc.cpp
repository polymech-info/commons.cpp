// asio must come before any header that may pull in <windows.h>
#include <asio.hpp>
#include "fs/path_sanitizer.hpp"

#include "ipc/cmd_ipc.hpp"

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT

#include "logger/logger.h"

#include <picosha2.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace media::cmd_ipc {
namespace fs = std::filesystem;

namespace {

std::mutex g_shared_mu;
std::function<fs::path()> g_instances_dir;
std::vector<ActionHandler> g_shared_handlers;
std::function<void(InstanceDescriptor&)> g_shared_on_start;
std::function<void()> g_shared_on_shutdown;

} // namespace

void set_instances_dir_provider(std::function<fs::path()> fn)
{
    std::lock_guard<std::mutex> lk(g_shared_mu);
    g_instances_dir = std::move(fn);
}

void add_shared_handler(ActionHandler handler)
{
    std::lock_guard<std::mutex> lk(g_shared_mu);
    g_shared_handlers.push_back(std::move(handler));
}

void set_shared_on_start(std::function<void(InstanceDescriptor&)> fn)
{
    std::lock_guard<std::mutex> lk(g_shared_mu);
    g_shared_on_start = std::move(fn);
}

void set_shared_on_shutdown(std::function<void()> fn)
{
    std::lock_guard<std::mutex> lk(g_shared_mu);
    g_shared_on_shutdown = std::move(fn);
}

namespace {

// ── transport type selection ─────────────────────────────────────────────────
#if defined(_WIN32)
using ipc_acceptor = asio::ip::tcp::acceptor;
using ipc_socket   = asio::ip::tcp::socket;
constexpr const char* kTransport = "tcp";
#else
using ipc_acceptor = asio::local::stream_protocol::acceptor;
using ipc_socket   = asio::local::stream_protocol::socket;
constexpr const char* kTransport = "uds";
#endif

constexpr uint32_t kMaxFrameBytes = 16u << 20; // 16 MiB hard cap on any frame

// Handshake/auth tuning.
constexpr int      kAuthRecvTimeoutMs = 5000;  // server: max wait for a client's proof frame
constexpr size_t   kTokenBytes        = 32;    // per-instance secret size
constexpr size_t   kNonceBytes        = 16;    // per-connection challenge (128-bit)

// ── crypto helpers (no external deps: std RNG + vendored picosha2) ────────────
//
// Threat model (deliberately modest — see header): the goal is to stop
// *accidental* and *unrelated* local connections — e.g. browser pages or other
// apps probing 127.0.0.1, or stray processes that find the port — from driving
// the UI. A client must prove possession of the per-instance token, which lives
// only in the per-user-ACL'd descriptor file and in process memory. A determined
// attacker running as the *same* Windows user shares our trust boundary (can read
// the profile dir / our memory) and is explicitly out of scope; no localhost
// scheme defends that. verify_client_proof() is the single seam to later swap in
// stronger checks (peer-SID via ImpersonateNamedPipeClient, HMAC, etc.) without a
// protocol change.

// Fill `out` with cryptographically-non-deterministic bytes. std::random_device
// is backed by a CSPRNG on MSVC; swap for BCryptGenRandom here if ever needed.
void fill_random(uint8_t* out, size_t n)
{
    std::random_device rd;
    size_t i = 0;
    while (i < n) {
        const unsigned int r = rd();
        for (int b = 0; b < 4 && i < n; ++b, ++i)
            out[i] = static_cast<uint8_t>((r >> (b * 8)) & 0xFF);
    }
}

std::string to_hex(const uint8_t* data, size_t n)
{
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(k[(data[i] >> 4) & 0xF]);
        s.push_back(k[data[i] & 0xF]);
    }
    return s;
}

std::vector<uint8_t> from_hex(const std::string& hex)
{
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0)
        return out;
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return out; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string make_token()
{
    std::array<uint8_t, kTokenBytes> buf{};
    fill_random(buf.data(), buf.size());
    return to_hex(buf.data(), buf.size());
}

std::string make_nonce()
{
    std::array<uint8_t, kNonceBytes> buf{};
    fill_random(buf.data(), buf.size());
    return to_hex(buf.data(), buf.size());
}

// proof = SHA256( token_bytes || nonce_bytes ), hex-encoded.
std::string compute_proof(const std::string& token_hex, const std::string& nonce_hex)
{
    if (token_hex.empty() || nonce_hex.empty())
        return {};
    std::vector<uint8_t> msg = from_hex(token_hex);
    const std::vector<uint8_t> nb = from_hex(nonce_hex);
    if (msg.empty() || nb.empty())
        return {};
    msg.insert(msg.end(), nb.begin(), nb.end());
    std::vector<uint8_t> digest(picosha2::k_digest_size);
    picosha2::hash256(msg.begin(), msg.end(), digest.begin(), digest.end());
    return to_hex(digest.data(), digest.size());
}

// Constant-time-ish hex string compare (length-independent early-out avoided).
bool secure_equal(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
        return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

// THE auth seam. Today: prove possession of the per-instance token for this
// connection's fresh nonce. Replays are structurally impossible because every
// connection gets a unique server-generated nonce that is consumed when the
// connection closes; a captured (nonce, proof) pair never matches the next
// connection's nonce. Swap this body for peer-SID / HMAC / token-handle checks
// later without touching the wire protocol.
bool verify_client_proof(const std::string& token_hex,
                         const std::string& nonce_hex,
                         const std::string& proof_hex)
{
    if (token_hex.empty())
        return false;  // server has no token → refuse rather than allow-all
    const std::string expected = compute_proof(token_hex, nonce_hex);
    return !expected.empty() && secure_equal(expected, proof_hex);
}

// Best-effort recv timeout on an accepted/connected socket so a peer that
// connects but never speaks can't wedge the single-threaded accept loop.
void set_recv_timeout(ipc_socket& sock, int ms)
{
#if defined(_WIN32)
    const DWORD tv = static_cast<DWORD>(ms);
    ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv{};
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

// ── helpers ──────────────────────────────────────────────────────────────────
int64_t now_unix_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

#if defined(_WIN32)
int64_t current_pid() { return static_cast<int64_t>(::GetCurrentProcessId()); }

bool process_alive(int64_t pid)
{
    if (pid <= 0)
        return false;
    HANDLE h = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                             FALSE, static_cast<DWORD>(pid));
    if (!h)
        return false;
    DWORD code = STILL_ACTIVE;
    const BOOL ok = ::GetExitCodeProcess(h, &code);
    ::CloseHandle(h);
    return ok && code == STILL_ACTIVE;
}
#else
int64_t current_pid() { return static_cast<int64_t>(::getpid()); }

bool process_alive(int64_t pid)
{
    return pid > 0 && ::kill(static_cast<pid_t>(pid), 0) == 0;
}
#endif

// Filesystem-safe stem from pid (avoids colons on Windows)
std::string pid_stem(int64_t pid)
{
    return "pid_" + std::to_string(pid);
}

fs::path descriptor_path(int64_t pid)
{
    return instances_dir() / (pid_stem(pid) + ".json");
}

#if !defined(_WIN32)
fs::path socket_path(int64_t pid)
{
    return instances_dir() / (pid_stem(pid) + ".sock");
}
#endif

bool write_descriptor(const InstanceDescriptor& d, std::string& err)
{
    try {
        const fs::path final_path = descriptor_path(d.pid);
        const fs::path tmp_path   = media::path::path_to_utf8(final_path) + ".tmp";
        {
            std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
            if (!ofs) {
                err = "cannot open " + media::path::path_to_utf8(tmp_path);
                return false;
            }
            ofs << d.to_json().dump(2);
        }
        std::error_code ec;
        fs::rename(tmp_path, final_path, ec);
        if (ec) {
            fs::copy_file(tmp_path, final_path,
                          fs::copy_options::overwrite_existing, ec);
            fs::remove(tmp_path, ec);
        }
        return true;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

void remove_descriptor(int64_t pid)
{
    std::error_code ec;
    fs::remove(descriptor_path(pid), ec);
#if !defined(_WIN32)
    fs::remove(socket_path(pid), ec);
#endif
}

// ── framing: 4-byte LE length prefix + UTF-8 JSON ───────────────────────────
void write_frame(ipc_socket& sock, const std::string& json, asio::error_code& ec)
{
    const uint32_t len = static_cast<uint32_t>(json.size());
    asio::write(sock, asio::buffer(&len, 4), ec);
    if (ec)
        return;
    asio::write(sock, asio::buffer(json), ec);
}

bool read_frame(ipc_socket& sock, std::string& out, asio::error_code& ec)
{
    uint32_t len = 0;
    asio::read(sock, asio::buffer(&len, 4), ec);
    if (ec)
        return false;
    if (len == 0 || len > kMaxFrameBytes) {
        ec = asio::error::message_size;
        return false;
    }
    out.assign(len, '\0');
    asio::read(sock, asio::buffer(&out[0], len), ec);
    return !ec;
}

} // namespace

// ── InstanceDescriptor (de)serialization ─────────────────────────────────────
nlohmann::json InstanceDescriptor::to_json() const
{
    return nlohmann::json{
        {"id",            id},
        {"kind",          kind_str(kind)},
        {"pid",           pid},
        {"cwd",           cwd},
        {"endpoint",      endpoint},
        {"transport",     transport},
        {"startedUnixMs", started_unix_ms},
        {"label",         label},
        {"cmdline",       cmdline},
        {"commandId",     command_id},
        {"token",         token},
        {"settingsOwner", settings_owner},
        {"settingsEpoch", settings_epoch},
        {"settingsRevision", settings_revision},
    };
}

InstanceDescriptor InstanceDescriptor::from_json(const nlohmann::json& j)
{
    InstanceDescriptor d;
    d.id               = j.value("id",            std::string{});
    d.kind             = kind_from_str(j.value("kind", std::string{}));
    d.pid              = j.value("pid",            int64_t{0});
    d.cwd              = j.value("cwd",            std::string{});
    d.endpoint         = j.value("endpoint",       std::string{});
    d.transport        = j.value("transport",      std::string{});
    d.started_unix_ms  = j.value("startedUnixMs",  int64_t{0});
    d.label            = j.value("label",           std::string{});
    d.cmdline          = j.value("cmdline",          std::string{});
    d.command_id       = j.value("commandId",        std::string{});
    d.token            = j.value("token",           std::string{});
    d.settings_owner   = j.value("settingsOwner",   false);
    d.settings_epoch   = j.value("settingsEpoch",   std::uint64_t{0});
    d.settings_revision = j.value("settingsRevision", std::uint64_t{0});
    return d;
}

nlohmann::json InstanceRecord::to_json() const
{
    nlohmann::json j = descriptor.to_json();
    j["orphaned"] = orphaned;
    if (!orphan_reason.empty())
        j["orphanReason"] = orphan_reason;
    return j;
}

nlohmann::json PruneResult::to_json() const
{
    nlohmann::json removed_json = nlohmann::json::array();
    for (const auto& rec : removed)
        removed_json.push_back(rec.to_json());
    return nlohmann::json{
        {"scanned", scanned},
        {"removed", static_cast<int>(removed.size())},
        {"removedDescriptors", std::move(removed_json)},
        {"errors", errors},
    };
}

// ── instances_dir ─────────────────────────────────────────────────────────────
fs::path instances_dir()
{
    install_process_handlers();
    std::function<fs::path()> provider;
    {
        std::lock_guard<std::mutex> lk(g_shared_mu);
        provider = g_instances_dir;
    }
    if (!provider)
        return {};
    const fs::path dir = provider();
    if (dir.empty())
        return {};
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

// ── InstanceServer ────────────────────────────────────────────────────────────
struct InstanceServer::Impl {
    asio::io_context              io;
    std::unique_ptr<ipc_acceptor> acceptor;
    std::thread                   thread;
    std::atomic<bool>             running{false};
    std::atomic<bool>             started{false};  // set once by start(); guards descriptor cleanup

    InstanceDescriptor  descriptor;
    std::mutex          handler_mtx;
    ActionHandler       custom_handler;
    std::vector<ActionHandler> handlers;
    ExtraActionHandler  extra_action_handler;
    StopHook            stop_fn;
    // Set by the "stop" action; the stop hook is fired by handle_client AFTER
    // the stop_ack frame is flushed, so the requester always sees confirmation
    // before the owning process starts tearing itself (and this server) down.
    bool                pending_stop = false;

    nlohmann::json stamp(nlohmann::json reply, const nlohmann::json& req) const
    {
        if (!reply.is_object())
            return reply;
        const std::string id = req.value("id", std::string{});
        if (!id.empty() && !reply.contains("id"))
            reply["id"] = id;
        if (!reply.contains("pid"))
            reply["pid"] = descriptor.pid;
        if (!reply.contains("ts"))
            reply["ts"] = now_unix_ms();
        return reply;
    }

    // ping, status/info, stop, then shared handlers, then per-server handlers,
    // then the extra slot. A handler returns null JSON to decline.
    nlohmann::json dispatch(const nlohmann::json& req)
    {
        const std::string action = req.value("action", std::string{});
        const std::string id     = req.value("id",     std::string{});

        auto base = [&]() {
            nlohmann::json reply;
            if (!id.empty())
                reply["id"] = id;
            reply["pid"] = descriptor.pid;
            reply["ts"]  = now_unix_ms();
            return reply;
        };

        if (action == "ping") {
            nlohmann::json reply = base();
            reply["type"] = "pong";
            return reply;
        }
        if (action == "status" || action == "info") {
            nlohmann::json reply = base();
            reply["type"]     = "status";
            reply["instance"] = descriptor.to_json();
            return reply;
        }
        if (action == "stop") {
            nlohmann::json reply = base();
            reply["type"] = "stop_ack";
            running.store(false);
            pending_stop = true;
            return reply;
        }

        std::vector<ActionHandler> chain;
        ActionHandler extra;
        {
            std::lock_guard<std::mutex> lk(g_shared_mu);
            chain = g_shared_handlers;
        }
        {
            std::lock_guard<std::mutex> lk(handler_mtx);
            chain.insert(chain.end(), handlers.begin(), handlers.end());
            extra = extra_action_handler;
        }

        auto try_one = [&](const ActionHandler& handler) -> nlohmann::json {
            if (!handler)
                return nullptr;
            try {
                nlohmann::json reply = handler(req);
                if (reply.is_null())
                    return nullptr;
                return stamp(std::move(reply), req);
            } catch (const std::exception& e) {
                nlohmann::json reply = base();
                reply["type"]  = "error";
                reply["error"] = std::string("action handler failed: ") + e.what();
                return reply;
            } catch (...) {
                nlohmann::json reply = base();
                reply["type"]  = "error";
                reply["error"] = "action handler failed";
                return reply;
            }
        };

        for (const auto& handler : chain) {
            nlohmann::json reply = try_one(handler);
            if (!reply.is_null())
                return reply;
        }
        if (nlohmann::json reply = try_one(extra); !reply.is_null())
            return reply;

        nlohmann::json reply = base();
        reply["type"]  = "error";
        reply["error"] = "unknown action: " + action;
        return reply;
    }

    void handle_client(ipc_socket sock)
    {
        asio::error_code ec;

        // Bound how long a connected-but-silent peer can hold this (single)
        // accept thread. Realises the "challenge expires" intent and blocks a
        // trivial connect-and-stall DoS.
        set_recv_timeout(sock, kAuthRecvTimeoutMs);

        // ── Challenge ────────────────────────────────────────────────────────
        // Server speaks first: fresh per-connection 128-bit nonce. The client
        // must answer with proof = SHA256(token || nonce) on its first frame.
        const std::string nonce = make_nonce();
        {
            nlohmann::json chal;
            chal["type"]     = "challenge";
            chal["nonce"]    = nonce;
            chal["protocol"] = 1;
            write_frame(sock, chal.dump(), ec);
            if (ec) {
                logger::trace("[cmd_ipc] disconnect before challenge sent");
                return;
            }
        }
        logger::trace("[cmd_ipc] connect (challenge issued)");

        bool authed = false;
        for (;;) {
            std::string payload;
            if (!read_frame(sock, payload, ec))
                break;

            nlohmann::json req;
            try {
                req = nlohmann::json::parse(payload);
            } catch (...) {
                logger::warn("[cmd_ipc] protocol violation: malformed JSON frame — disconnecting");
                break;
            }

            // ── Authenticate (first frame only) ──────────────────────────────
            if (!authed) {
                const std::string proof = req.value("proof", std::string{});
                if (!verify_client_proof(descriptor.token, nonce, proof)) {
                    logger::warn("[cmd_ipc] auth failure — disconnecting client");
                    nlohmann::json r;
                    r["type"]  = "error";
                    r["error"] = "auth failed";
                    write_frame(sock, r.dump(), ec);
                    break;  // disconnect on failure
                }
                authed = true;
                logger::trace("[cmd_ipc] auth success");
            }

            nlohmann::json reply;
            {
                // Snapshot the override. dispatch() locks handler_mtx itself for the
                // per-server list, so this lock must not be held across the call.
                ActionHandler snap;
                {
                    std::lock_guard<std::mutex> lk(handler_mtx);
                    snap = custom_handler;
                }
                if (snap) {
                    reply = snap(req);
                } else {
                    reply = dispatch(req);
                }
            }

            write_frame(sock, reply.dump(), ec);
            if (ec)
                break;
            // stop action sets running=false; close connection after ack.
            if (!running.load()) {
                // Ack is flushed — now ask the owning process to terminate
                // (UI posts WM_CLOSE, etc.). The hook must be non-blocking; it
                // runs on this accept thread, which is about to exit.
                if (pending_stop) {
                    pending_stop = false;
                    StopHook stop_cb;
                    {
                        std::lock_guard<std::mutex> lk(handler_mtx);
                        stop_cb = stop_fn;
                    }
                    if (stop_cb)
                        stop_cb();
                }
                break;
            }
        }
        logger::trace("[cmd_ipc] disconnect");
    }

    void accept_loop()
    {
        while (running.load()) {
            ipc_socket       sock(io);
            asio::error_code ec;
            acceptor->accept(sock, ec);
            if (ec || !running.load())
                break;
            handle_client(std::move(sock));
            // stop action (from a client) sets running=false; break here to
            // exit cleanly after the connection closes.
            if (!running.load())
                break;
        }
    }
};

InstanceServer::InstanceServer() : impl_(std::make_unique<Impl>()) {}
InstanceServer::~InstanceServer() { shutdown(); }

void InstanceServer::set_handler(ActionHandler handler)
{
    std::lock_guard<std::mutex> lk(impl_->handler_mtx);
    impl_->custom_handler = std::move(handler);
}

void InstanceServer::add_handler(ActionHandler handler)
{
    std::lock_guard<std::mutex> lk(impl_->handler_mtx);
    impl_->handlers.push_back(std::move(handler));
}

void InstanceServer::set_stop_hook(StopHook fn)
{
    std::lock_guard<std::mutex> lk(impl_->handler_mtx);
    impl_->stop_fn = std::move(fn);
}

void InstanceServer::set_extra_action_handler(ExtraActionHandler handler)
{
    std::lock_guard<std::mutex> lk(impl_->handler_mtx);
    impl_->extra_action_handler = std::move(handler);
}

bool InstanceServer::start(ProcessKind kind, const std::string& cwd, std::string& err,
                           const std::string& label, const std::string& cmdline)
{
    if (impl_->running.load()) {
        err = "cmd_ipc: server already running";
        return false;
    }
    if (instances_dir().empty()) {
        err = "cmd_ipc: instances directory is not configured";
        return false;
    }

    // Sweep the instances dir on startup: every new instance reaps descriptors
    // whose owning process is dead (crash / SIGKILL left them behind). This is
    // the "next instance cleans up" path so stale files don't accumulate when
    // no one is actively calling list_instances(). Result is intentionally
    // discarded — list_instances() does the reaping as a side effect.
    (void)list_instances();

    InstanceDescriptor& d = impl_->descriptor;
    d.pid              = current_pid();
    d.id               = "pid:" + std::to_string(d.pid);
    d.kind             = kind;
    d.cwd              = cwd;
    d.transport        = kTransport;
    d.started_unix_ms  = now_unix_ms();
    d.label            = label;
    d.cmdline          = cmdline;
    d.token            = make_token();  // per-instance secret; never hardcoded

    // Launch surfaces (launcher popup / ribbon / shell ext) stamp the spawned
    // child with the originating commands.json id so cross-process UIs can map
    // this instance back to its tile. Inherited env var → free plumbing for
    // every host that activates cmd_ipc (CliActivityScope, xblox, …).
    if (const char* cid = std::getenv("PM_IMAGE_COMMAND_ID"); cid && *cid)
        d.command_id = cid;

    try {
#if defined(_WIN32)
        asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), 0);
        impl_->acceptor = std::make_unique<ipc_acceptor>(impl_->io);
        impl_->acceptor->open(ep.protocol());
        impl_->acceptor->set_option(asio::socket_base::reuse_address(true));
        impl_->acceptor->bind(ep);
        impl_->acceptor->listen();
        d.endpoint = std::to_string(impl_->acceptor->local_endpoint().port());
#else
        const fs::path sp = socket_path(d.pid);
        std::error_code fec;
        fs::remove(sp, fec);
        asio::local::stream_protocol::endpoint ep(media::path::path_to_utf8(sp));
        impl_->acceptor = std::make_unique<ipc_acceptor>(impl_->io, ep);
        d.endpoint = media::path::path_to_utf8(sp);
#endif
    } catch (const std::exception& e) {
        err = std::string("cmd_ipc: bind failed: ") + e.what();
        return false;
    }

    std::function<void(InstanceDescriptor&)> on_start;
    std::function<void()> on_shutdown;
    {
        std::lock_guard<std::mutex> lk(g_shared_mu);
        on_start = g_shared_on_start;
        on_shutdown = g_shared_on_shutdown;
    }
    if (on_start)
        on_start(d);

    if (!write_descriptor(d, err)) {
        if (on_shutdown)
            on_shutdown();
        impl_->acceptor.reset();
        return false;
    }

    impl_->running.store(true);
    impl_->started.store(true);
    impl_->thread = std::thread([this] { impl_->accept_loop(); });

    logger::trace(std::string("[cmd_ipc] server started pid=") + std::to_string(d.pid) +
                  " kind=" + kind_str(d.kind) + " endpoint=" + d.endpoint);
    return true;
}

void InstanceServer::shutdown()
{
    if (!impl_->started.load())
        return;

    std::function<void()> on_shutdown;
    {
        std::lock_guard<std::mutex> lk(g_shared_mu);
        on_shutdown = g_shared_on_shutdown;
    }
    if (on_shutdown)
        on_shutdown();

    logger::debug(std::string("[cmd_ipc] shutdown begin pid=") + std::to_string(impl_->descriptor.pid));
    impl_->running.store(false);

    std::error_code ec;
    if (impl_->acceptor) {
        // Synchronous accept() is not reliably interrupted by close() from
        // another thread on every Windows/ASIO backend. A loopback self-connect
        // wakes the accept loop so shutdown can join promptly.
        asio::error_code wake_ec;
        const auto ep = impl_->acceptor->local_endpoint(wake_ec);
        if (!wake_ec) {
            ipc_socket wake_sock(impl_->io);
            wake_sock.connect(ep, wake_ec);
            if (!wake_ec) {
                asio::error_code close_ec;
                wake_sock.shutdown(asio::socket_base::shutdown_both, close_ec);
                wake_sock.close(close_ec);
            }
        }
        impl_->acceptor->cancel(ec);
        impl_->acceptor->close(ec);
    }
    if (impl_->thread.joinable()) {
        logger::debug(std::string("[cmd_ipc] shutdown join begin pid=") + std::to_string(impl_->descriptor.pid));
        impl_->thread.join();
        logger::debug(std::string("[cmd_ipc] shutdown join end pid=") + std::to_string(impl_->descriptor.pid));
    }
    impl_->acceptor.reset();

    remove_descriptor(impl_->descriptor.pid);
    impl_->started.store(false);  // prevent double-shutdown
    logger::trace(std::string("[cmd_ipc] server stopped pid=") + std::to_string(impl_->descriptor.pid));
}

bool InstanceServer::is_running() const { return impl_->running.load(); }

const InstanceDescriptor& InstanceServer::descriptor() const
{
    return impl_->descriptor;
}

// ── list / find ───────────────────────────────────────────────────────────────
std::vector<InstanceRecord> list_instance_records(bool validate_ping,
                                                  int ping_timeout_ms)
{
    std::vector<InstanceRecord> out;
    const fs::path dir = instances_dir();
    if (dir.empty())
        return out;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec)
            break;
        if (entry.path().extension() != ".json")
            continue;
        try {
            std::ifstream ifs(entry.path(), std::ios::binary);
            if (!ifs)
                continue;
            std::ostringstream ss;
            ss << ifs.rdbuf();
            const auto j = nlohmann::json::parse(ss.str());
            auto d = InstanceDescriptor::from_json(j);
            InstanceRecord rec;
            rec.descriptor = std::move(d);
            if (!process_alive(rec.descriptor.pid)) {
                rec.orphaned = true;
                rec.orphan_reason = "pid not running";
            } else if (validate_ping) {
                nlohmann::json reply;
                std::string ping_err;
                if (!send_action(rec.descriptor, "ping", {}, reply, ping_err, ping_timeout_ms)) {
                    rec.orphaned = true;
                    rec.orphan_reason = ping_err.empty() ? "ping failed" : ping_err;
                }
            }
            out.push_back(std::move(rec));
        } catch (...) {
        }
    }
    return out;
}

std::vector<InstanceDescriptor> list_instances()
{
    std::vector<InstanceDescriptor> out;
    const fs::path dir = instances_dir();
    if (dir.empty())
        return out;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec)
            break;
        if (entry.path().extension() != ".json")
            continue;
        try {
            std::ifstream ifs(entry.path(), std::ios::binary);
            if (!ifs)
                continue;
            std::ostringstream ss;
            ss << ifs.rdbuf();
            const auto j = nlohmann::json::parse(ss.str());
            auto d = InstanceDescriptor::from_json(j);
            if (!process_alive(d.pid)) {
                std::error_code rep;
                fs::remove(entry.path(), rep);
#if !defined(_WIN32)
                fs::remove(socket_path(d.pid), rep);
#endif
                continue;
            }
            out.push_back(std::move(d));
        } catch (...) {
        }
    }
    return out;
}

PruneResult prune_instance_records(bool validate_ping, int ping_timeout_ms)
{
    PruneResult result;
    const auto records = list_instance_records(validate_ping, ping_timeout_ms);
    result.scanned = static_cast<int>(records.size());
    for (const auto& rec : records) {
        if (!rec.orphaned)
            continue;
        std::error_code ec;
        fs::remove(descriptor_path(rec.descriptor.pid), ec);
        if (ec) {
            result.errors.push_back(rec.descriptor.id + ": " + ec.message());
            continue;
        }
#if !defined(_WIN32)
        fs::remove(socket_path(rec.descriptor.pid), ec);
        if (ec)
            result.errors.push_back(rec.descriptor.id + " socket: " + ec.message());
#endif
        result.removed.push_back(rec);
    }
    return result;
}

bool find_instance(const std::string& key, InstanceDescriptor& out)
{
    // Support bare numeric pid ("1234") as well as "pid:1234"
    std::string normalised = key;
    if (!key.empty() && key.find(':') == std::string::npos) {
        bool all_digits = true;
        for (char c : key)
            if (c < '0' || c > '9') { all_digits = false; break; }
        if (all_digits)
            normalised = "pid:" + key;
    }

    for (auto& d : list_instances()) {
        if (d.id == normalised) {
            out = d;
            return true;
        }
    }
    return false;
}

// ── send_action ───────────────────────────────────────────────────────────────
bool send_action(const InstanceDescriptor& desc,
                 const std::string&        action,
                 const nlohmann::json&     extra,
                 nlohmann::json&           reply,
                 std::string&              err,
                 int                       timeout_ms)
{
    try {
        asio::io_context io;

#if defined(_WIN32)
        const uint16_t port = static_cast<uint16_t>(std::stoul(desc.endpoint));
        asio::ip::tcp::socket sock(io);
        sock.connect(
            asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
        sock.set_option(asio::ip::tcp::no_delay(true));
        // Simple blocking timeout via SO_RCVTIMEO / SO_SNDTIMEO
        if (timeout_ms > 0) {
            const DWORD tv = static_cast<DWORD>(timeout_ms);
            ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv));
            ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_SNDTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv));
        }
#else
        asio::local::stream_protocol::socket sock(io);
        sock.connect(asio::local::stream_protocol::endpoint(desc.endpoint));
        if (timeout_ms > 0) {
            struct timeval tv{};
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
#endif
        asio::error_code ec;

        // ── Read the server challenge and answer it ──────────────────────────
        // Server speaks first with {type:"challenge", nonce:…}. We prove
        // possession of the per-instance token (from the descriptor) by sending
        // proof = SHA256(token || nonce) on our first (and only) request frame.
        std::string chalRaw;
        if (!read_frame(sock, chalRaw, ec)) {
            err = "cmd_ipc handshake: " + ec.message();
            return false;
        }
        std::string nonce;
        try {
            const auto chal = nlohmann::json::parse(chalRaw);
            nonce = chal.value("nonce", std::string{});
        } catch (...) {
            err = "cmd_ipc handshake: malformed challenge";
            return false;
        }

        nlohmann::json req = extra;
        req["action"] = action;
        req["proof"]  = compute_proof(desc.token, nonce);
        const std::string payload = req.dump();

        write_frame(sock, payload, ec);
        if (ec) {
            err = "cmd_ipc send: " + ec.message();
            return false;
        }

        std::string raw;
        if (!read_frame(sock, raw, ec)) {
            err = "cmd_ipc recv: " + ec.message();
            return false;
        }

        reply = nlohmann::json::parse(raw);
        // Surface auth rejection as a transport failure so callers don't treat
        // an unauthenticated "error" reply as a normal response.
        if (reply.value("type", std::string{}) == "error" &&
            reply.value("error", std::string{}) == "auth failed") {
            err = "cmd_ipc: authentication rejected by peer";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        err = std::string("cmd_ipc: ") + e.what();
        return false;
    }
}

} // namespace media::cmd_ipc
#endif // FEATURE_COMMAND_IPC_NEXT
