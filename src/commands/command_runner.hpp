#pragma once
//
// Shared process-spawning + lifecycle tracking with multi-sink event broadcasting.
//
// Every UI surface that launches `commands.json` entries goes through this single
// engine so pulsing / abort state stays in sync without duplicate bookkeeping:
//
//   • own-ribbon custom commands (`Mainfrm.cpp::launch_custom_external_command`)
//   • the in-app launcher fly-out (`showInLauncher: true` in `commands.json`)
//   • the assistant toolbar's BTN_LAUNCH popup
//   • the chat web bus when a chat message triggers a command
//
// Threading model: sinks fire on the runner's watcher thread. UI consumers must
// marshal back to their own message loop (typically via `PostMessageW(hwnd, …)`).
//
// Cancel model: prefer cooperative IPC stop + grace wait (`stop_by_command_id`)
// so MF Finalize can write the MP4 moov atom; hard `TerminateProcess` is the
// fallback when IPC is unavailable or the grace window expires.
//

#include "process/process_runner.hpp"  // media::process::ClosePolicy

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace media::cmd_run {

// ── Input ─────────────────────────────────────────────────────────────────────

struct RunOptions {
    /// Surface-local command id (e.g. `own_ribbon::kCustomRibbonCommandFirst + n`,
    /// or a launcher/assistant-bar button id). 0 if the run isn't tied to a UI button.
    /// Used by hosts to drive `is_running(cmdId)` and pulse animations.
    unsigned cmdId = 0;

    /// Stable `commands.json` `id` field, e.g. "custom.mic-start". Empty for transient
    /// or ad-hoc runs. Lets multiple surfaces (ribbon + launcher) share the same
    /// pulse state for the same logical command across different cmdId allocations.
    std::string commandId;

    /// Serialize runs sharing commandId. Default on; commands may explicitly
    /// opt into concurrent execution with runOptions.sequential=false.
    bool sequential = true;

    /// Either `executable + args`, OR a shell line (`externalShellMode = true`).
    /// Both empty → start() returns 0 and emits no events.
    std::wstring              executable;
    std::vector<std::wstring> args;
    bool                      externalShellMode = false;
    std::wstring              shellLine;
    /// Shell that runs `shellLine`: cmd | powershell | pwsh | bash | sh | zsh | fish.
    /// Empty → "pwsh" (historic default). Persisted as `externalCommand.interpreter`.
    std::string               shellInterpreter;

    /// Run the `run`-tool Deny validators against the fully expanded command
    /// (variables already substituted) right before spawning. Set for entries
    /// authored by the agent (`userData.createdBy == "create_command"`); a Deny
    /// hit refuses the spawn. Creation-time validation protects persistence,
    /// this protects the machine once `${…}` values are known.
    bool validateExpanded = false;

    /// Working directory; empty → inherit the caller's cwd.
    std::wstring cwd;

    /// Extra environment variables for the child (override inherited entries).
    /// Launch surfaces use this to stamp PM_IMAGE_COMMAND_ID so the spawned
    /// process's cmd_ipc descriptor carries the originating commands.json id.
    std::vector<std::pair<std::wstring, std::wstring>> extraEnv;

    /// Spawn under a visible new console window (`CREATE_NEW_CONSOLE`).
    /// Required for pm-image-cli "tray", "audio record", and similar foreground commands.
    bool newConsoleWindow = false;

    /// When `newConsoleWindow == true` and `externalShellMode == false`, the runner
    /// appends `--pause-on-exit` so the console stays open after the child exits
    /// unless this flag is set to true. Mirrors the existing
    /// `CustomRibbonCommand::closeOnExit` semantics in `Mainfrm.cpp`.
    bool closeOnExit = false;

    /// Lifetime relative to the launching surface (commands.json
    /// `runOptions.closePolicy`). `CloseWithOwner` → the spawned child dies when
    /// this process exits; `Persist` → it outlives us; `Default` → runner default
    /// (bind-to-parent). Applied by `media::process::run()`.
    media::process::ClosePolicy closePolicy = media::process::ClosePolicy::Default;
};

// ── Lifecycle events ──────────────────────────────────────────────────────────

enum class RunPhase {
    Started,   ///< process created, pid known
    Exited,    ///< process exited — exitCode populated
    Failed,    ///< CreateProcessW failed — error populated, pid == 0
    Cancelled, ///< user abort, or cancelled before the process started
};

struct RunEvent {
    RunPhase      phase    = RunPhase::Started;
    std::uint64_t runId    = 0;
    unsigned      cmdId    = 0;
    std::string   commandId;
    unsigned long pid      = 0;   ///< 0 for Failed
    unsigned long exitCode = 0;   ///< populated only for Exited
    std::string   error;          ///< populated only for Failed (Win32 error text)
};

using Sink = std::function<void(const RunEvent&)>;

/// Read-only description of a run currently owned by Runner. Queued sequential
/// runs have pid == 0; startedUnixMs is the reservation time for queued runs
/// and the launch-attempt time for spawned runs.
struct ActiveRunRow {
    std::uint64_t runId        = 0;
    unsigned      cmdId        = 0;
    std::string   commandId;
    unsigned long pid          = 0;
    std::int64_t  startedUnixMs = 0;
};

struct ActiveRunSnapshot {
    std::int64_t             capturedUnixMs = 0;
    std::vector<ActiveRunRow> rows;
};

// ── Runner ────────────────────────────────────────────────────────────────────

/// Singleton process-spawning + lifecycle tracker. All members are thread-safe.
///
/// Hosts subscribe at construction (`subscribe`) and detach at destruction
/// (`unsubscribe`). Each surface gets every event for every run; filter by
/// `cmdId` / `commandId` in your sink.
class Runner {
public:
    static Runner& instance() noexcept;

    /// Start a process. Returns the run id (non-zero on success, 0 on argument
    /// validation failure — empty executable AND empty shellLine).
    ///
    /// On Win32 spawn success the runner immediately emits a Started event to
    /// every sink synchronously on the calling thread, then a watcher thread
    /// waits on the process handle and emits Exited / Failed asynchronously.
    std::uint64_t start(const RunOptions& opt);

    /// Cancel a single active or queued run. Spawned runs are hard-terminated
    /// (`TerminateProcess(handle, 1)`); queued sequential runs are removed and
    /// emit Failed. Returns false if the run id is unknown or already exited.
    /// A spawned run's watcher still emits its single Exited event.
    bool cancel(std::uint64_t runId);

    /// Cancel every active run sharing the given cmdId / commandId. Returns
    /// the number of runs terminated.
    std::size_t cancel_by_cmd_id(unsigned cmdId);
    std::size_t cancel_by_command_id(const std::string& commandId);

    /// After a cooperative IPC stop: wait up to @p grace_ms for matching runs to
    /// exit on their own (so MF Finalize / xblox teardown can finish), then
    /// hard-terminate any survivors. Returns runs that were hard-killed.
    std::size_t stop_by_command_id(const std::string& commandId,
                                   unsigned grace_ms = 8000);

    /// Hard-terminate active runs that are bound to this process. `Persist`
    /// runs are left running. Call on host shutdown (e.g. the main window's
    /// WM_CLOSE). Returns the number of runs terminated.
    std::size_t cancel_all();

    /// Pulsing-state queries. Constant-time copies under a short lock — safe
    /// to call from per-frame paint code.
    bool is_running(unsigned cmdId) const;
    bool is_running(const std::string& commandId) const;
    std::size_t active_count() const;

    /// Snapshot of currently active run ids (for diagnostic dumps / cancel-all).
    std::vector<std::uint64_t> active_runs() const;

    /// Structured snapshot of active and queued runs. The returned value owns
    /// its strings and is safe to inspect after the runner lock is released.
    ActiveRunSnapshot active_snapshot() const;

    /// Child (`tanit-cli` / xblox) reported its own finish over cmd_ipc.
    /// Emits Exited with that result so the queue does not wait on a stale
    /// Windows exit code (job-kill / TerminateProcess after a clean return).
    void apply_reported_exit(const std::string& commandId, bool ok, int exit_code);

    /// Subscribe a sink. Returns a token; pass to `unsubscribe` to detach.
    /// Sinks fire on the runner's watcher threads — UI hosts must `PostMessage`
    /// to themselves rather than touch HWNDs from inside the callback.
    std::uint64_t subscribe(Sink sink);
    void          unsubscribe(std::uint64_t token);

private:
    Runner();
    ~Runner();
    Runner(const Runner&)            = delete;
    Runner& operator=(const Runner&) = delete;
};

/// When `opt.validateExpanded` is set, run the `run`-tool Deny validators on the
/// expanded command line. Returns the deny reason, or empty when allowed / not requested.
std::string validate_expanded_command(const RunOptions& opt);

/// True when a commands.json item's `userData` marks it as agent-authored
/// (`{"createdBy":"create_command"}`); such entries opt into `validateExpanded`.
bool user_data_marks_agent_authored(const std::string& userDataJson);

} // namespace media::cmd_run
