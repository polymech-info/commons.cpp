// cmd_ipc — cross-process command IPC for discovering and controlling live
// pm-image (ui / cli / daemon / assistant) instances.
//
// Each pm-image process that activates this subsystem:
//   1. Writes a small JSON descriptor to the instances directory on startup.
//   2. Listens on a loopback socket for length-prefixed JSON frames.
//   3. Removes the descriptor on clean shutdown. list_instances() reaps dead
//      PIDs; list_instance_records() leaves them visible for diagnostics.
//
// Transport: loopback TCP on Windows, AF_UNIX stream socket elsewhere.
// Wire format: 4-byte little-endian length prefix + UTF-8 JSON body — the same
// framing that xblox_session uses, so the same test harness speaks this bus.
//
// Built-in actions (this module):
//   ping    → {type:"pong", pid:…, ts:…}
//   status  → {type:"status", pid:…, instance:…, ts:…}   ("info" is the same)
//   stop    → {type:"stop_ack", …} then the stop hook
//
// Every other verb is a host handler. add_handler / add_shared_handler return
// a null JSON value to decline. set_handler replaces the whole dispatch.
// Application handlers live in src/core/cmd_ipc_host.cpp.
//
// Compiled only when FEATURE_COMMAND_IPC_NEXT.
#pragma once
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace media::cmd_ipc {

// Process classification
enum class ProcessKind : uint8_t {
    Unknown   = 0,
    Ui        = 1,
    Cli       = 2,
    Xblox     = 3,
    Daemon    = 4,
    Assistant = 5,
    LlmAgent  = 6,
};

inline const char* kind_str(ProcessKind k) noexcept
{
    switch (k) {
        case ProcessKind::Ui:  return "ui";
        case ProcessKind::Cli: return "cli";
        case ProcessKind::Xblox: return "xblox";
        case ProcessKind::Daemon: return "daemon";
        case ProcessKind::Assistant: return "assistant";
        case ProcessKind::LlmAgent: return "llm-agent";
        default:               return "unknown";
    }
}

inline ProcessKind kind_from_str(const std::string& s) noexcept
{
    if (s == "ui")  return ProcessKind::Ui;
    if (s == "cli") return ProcessKind::Cli;
    if (s == "xblox") return ProcessKind::Xblox;
    if (s == "daemon") return ProcessKind::Daemon;
    if (s == "assistant") return ProcessKind::Assistant;
    if (s == "llm-agent") return ProcessKind::LlmAgent;
    return ProcessKind::Unknown;
}

// On-disk descriptor: what list_instances() returns and what clients connect
// against.  The id field is "pid:<decimal>" so it is globally sortable and
// unambiguous within a single machine.
struct InstanceDescriptor {
    std::string  id;                 // "pid:<n>"
    ProcessKind  kind = ProcessKind::Unknown;
    int64_t      pid  = 0;
    std::string  cwd;
    std::string  endpoint;           // TCP: "<port>"; UDS: abs .sock path
    std::string  transport;          // "tcp" | "uds"
    int64_t      started_unix_ms = 0;

    // Optional human label describing what this instance is doing, e.g. the CLI
    // subcommand currently running ("resize", "transform a.jpg"). Empty for
    // generic hosts (UI/daemon). Surfaced by run-ipc list/tree and the web panel.
    std::string  label;

    // Optional full command line that launched this instance (exe + args), for
    // CLI hosts. Lets run-ipc detail views show exactly what is running. Empty
    // when not supplied.
    std::string  cmdline;

    // Optional `commands.json` id of the custom command this instance is
    // running on behalf of (e.g. "custom.command-mq97rchy-5fcbf"). Populated
    // automatically by InstanceServer::start() from the PM_IMAGE_COMMAND_ID
    // environment variable, which launch surfaces (launcher popup, ribbon,
    // Explorer shell ext) stamp onto spawned children. Lets UI surfaces map a
    // live instance back to the tile/button that launched it — across
    // processes — without command-line heuristics.
    std::string  command_id;

    // Per-instance shared secret (hex of 32 random bytes), generated at start().
    // Used for the connection challenge-response: a client must prove possession
    // of this token to issue any action. It is stored ONLY in this descriptor
    // file, which lives under the per-user profile dir (OS ACL restricts it to
    // the current Windows user), and in the owning process's memory — never
    // hardcoded. See cmd_ipc.cpp for the handshake + threat model notes.
    std::string  token;

    // Settings-owner advertisement (docs/settings-next2.md). Cheap discovery of
    // the single writer; the named mutex is still the ownership primitive.
    bool         settings_owner = false;
    std::uint64_t settings_epoch = 0;
    std::uint64_t settings_revision = 0;

    nlohmann::json        to_json() const;
    static InstanceDescriptor from_json(const nlohmann::json& j);
};

// Discovery-time wrapper. The persisted descriptor remains unchanged; these
// fields are computed by list_instance_records().
struct InstanceRecord {
    InstanceDescriptor descriptor;
    bool               orphaned = false;
    std::string        orphan_reason;

    nlohmann::json to_json() const;
};

struct PruneResult {
    int scanned = 0;
    std::vector<InstanceRecord> removed;
    std::vector<std::string> errors;

    nlohmann::json to_json() const;
};

// Directory holding <pid>.json descriptors (and posix <pid>.sock files).
// The host supplies the path with set_instances_dir_provider. Empty until then.
std::filesystem::path instances_dir();

// Host layout. Called before any server starts. The function is invoked when
// the directory is needed, not at registration.
void set_instances_dir_provider(std::function<std::filesystem::path()> fn);

// Host TU (src/core/cmd_ipc_host.cpp). Idempotent. Wires the directory and the
// shared handlers. instances_dir() calls this.
void install_process_handlers();

// Process-wide handlers, tried after ping/status/stop and before the
// per-server list. A null JSON return declines. Installed once by the host.
using ActionHandler = std::function<nlohmann::json(const nlohmann::json& req)>;
void add_shared_handler(ActionHandler handler);

// Called with the descriptor before it is written, and at the start of shutdown
// (also when start() fails after the start hook ran).
void set_shared_on_start(std::function<void(InstanceDescriptor&)> fn);
void set_shared_on_shutdown(std::function<void()> fn);

// ── InstanceServer ──────────────────────────────────────────────────────────
//
// RAII command IPC server.  A live process holds exactly one of these.
// start() binds the loopback socket, writes the descriptor, and spawns an
// accept thread; shutdown()/dtor removes the descriptor, closes the socket,
// and joins the thread.
//
// Dispatch order when set_handler is empty:
//   ping, status/info, stop
//   shared handlers
//   handlers added with add_handler, in registration order
//   the extra slot (set_extra_action_handler, replaceable)
//   {type:"error", error:"unknown action: …"}
// set_handler replaces that chain. The start/shutdown hooks still run.
class InstanceServer {
public:
    InstanceServer();
    ~InstanceServer();
    InstanceServer(const InstanceServer&)            = delete;
    InstanceServer& operator=(const InstanceServer&) = delete;

    using ActionHandler = media::cmd_ipc::ActionHandler;

    // Full replacement for the action chain. Set before start().
    void set_handler(ActionHandler handler);

    // Append a verb handler. Null JSON means "not mine". Safe before or after start().
    void add_handler(ActionHandler handler);

    // Invoked after the stop ack is flushed. Non-blocking: it runs on the
    // accept thread. When unset, "stop" only tears down this server.
    using StopHook = std::function<void()>;
    void set_stop_hook(StopHook fn);

    // One replaceable slot, checked after add_handler. Null clears it.
    // Null JSON from the function declines, same as add_handler.
    using ExtraActionHandler = ActionHandler;
    void set_extra_action_handler(ExtraActionHandler handler);

    // `label` is an optional human description of the work this instance is
    // doing (e.g. a CLI subcommand name); `cmdline` is the optional full launch
    // command line. Both are stored in the descriptor and surfaced by discovery.
    // Defaulted empty so existing callers are unaffected.
    bool start(ProcessKind kind, const std::string& cwd, std::string& err,
               const std::string& label = {}, const std::string& cmdline = {});
    void shutdown();
    bool is_running() const;

    const InstanceDescriptor& descriptor() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ── Discovery helpers ────────────────────────────────────────────────────────

// Enumerate live instances; automatically reaps descriptors whose owning pid
// is no longer running.
std::vector<InstanceDescriptor> list_instances();

// Enumerate descriptor files without pruning. When validate_ping is true, live
// PIDs are also authenticated via ping; failed ping marks the row orphaned.
std::vector<InstanceRecord> list_instance_records(bool validate_ping = true,
                                                  int ping_timeout_ms = 500);

// Remove orphaned instance descriptors from the run-ipc registry. Uses the same
// validation as list_instance_records(); live descriptors are left untouched.
PruneResult prune_instance_records(bool validate_ping = true,
                                   int ping_timeout_ms = 500);

// Resolve an instance by exact id, or by numeric pid (e.g. "1234" → "pid:1234").
// Returns false when nothing matches.
bool find_instance(const std::string& key, InstanceDescriptor& out);

// ── Transport ────────────────────────────────────────────────────────────────

// Connect to a live instance and exchange one request/reply frame.  `extra` is
// merged into the outgoing {"action": action, ...} object.
// Returns false (fills err) on transport failure, timeout, or parse error.
bool send_action(const InstanceDescriptor& desc,
                 const std::string&        action,
                 const nlohmann::json&     extra,
                 nlohmann::json&           reply,
                 std::string&              err,
                 int                       timeout_ms = 3000);

} // namespace media::cmd_ipc
#endif // FEATURE_COMMAND_IPC_NEXT
