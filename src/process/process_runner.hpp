#pragma once
//
// ProcessRunner — unified process-spawning engine.
//
// Three modes:
//   Async    — fire-and-forget, detached watcher (ribbon/launcher/hotkeys).
//              Hidden-window runs pipe stdout/stderr and forward lines to the
//              host log (and on_output_chunk). New-console runs stay unpiped.
//   Sync     — block until exit, no pipes, poll loop with cancel (CLI dispatch)
//   Captured — block with piped stdout/stderr, timeout+cancel (LLM agent)
//
// All callers (command_runner, RunTool, pm_image_dispatch, xblox) delegate here.
//

#include "process/process_helpers.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace media::process {

// ═══════════════════════════════════════════════════════════════════════════════
// Options
// ═══════════════════════════════════════════════════════════════════════════════

enum class RunMode {
    Async,     // fire-and-forget — watcher thread emits on_exit
    Sync,      // block until exit — no IO capture
    Captured,  // block with piped stdout/stderr
};

/// Lifetime of the spawned child relative to *this* (launching) process.
/// Maps a `commands.json` `runOptions.closePolicy` value onto `bind_to_parent`:
///   - Default        → leave `bind_to_parent` as the caller set it (no override).
///   - Persist        → force `bind_to_parent = false`; the child outlives us.
///   - CloseWithOwner → force `bind_to_parent = true`; the child dies with us
///                      (kill-on-close Job Object). Owner-bound launches.
enum class ClosePolicy { Default = 0, Persist, CloseWithOwner };

/// Parse a `commands.json` `closePolicy` string. Unknown/empty → Default.
/// Accepts "persist" and "closeWithOwner" (also "close_with_owner").
ClosePolicy parse_close_policy(std::string_view value) noexcept;

struct RunOptions {
    // ── Command ──
    std::string              executable;   // executable path/name (UTF-8)
    std::vector<std::string> args;         // argv (UTF-8)
    std::string              cwd;          // working directory (UTF-8), empty = inherit

    // ── Shell wrapping ──
    bool        use_shell   = false;       // wrap command in a shell
    std::string shell_hint  = "auto";      // "auto", "cmd", "pwsh", "bash", "sh"
    std::string shell_command;             // raw shell command string (use instead of executable+args)

    // ── Mode ──
    RunMode mode = RunMode::Sync;

    // ── Timeout (Sync / Captured only) ──
    int timeout_ms = 0;                    // 0 = no timeout

    // ── Capture limits (Captured only) ──
    size_t capture_max_bytes = 128 * 1024;

    // ── Async-mode UI flags ──
    bool new_console_window = false;
    bool close_on_exit      = false;

    // ── Lifetime policy (commands.json runOptions.closePolicy) ──
    /// When not `Default`, overrides `bind_to_parent` in `run()`:
    /// `CloseWithOwner` → bind (die with launcher); `Persist` → detach (outlive).
    ClosePolicy close_policy = ClosePolicy::Default;

    // ── Lifetime binding ──
    /// When true (default), the spawned child is assigned to a process-wide
    /// kill-on-close Job Object so it dies when *this* process exits — even on a
    /// hard close or crash. This is what stops "work" spawns (agent run-tool
    /// shells, launcher/ribbon custom commands) from lingering as orphans after
    /// the UI window closes. Set to false for fire-and-forget launches that are
    /// meant to outlive us (e.g. a CLI dispatch that opens an external viewer and
    /// then exits, or spawning a new independent app window).
    bool bind_to_parent = true;

    /// When true (Captured mode), attach stdin to the OS null device instead of
    /// inheriting the parent handle. Needed for CLIs such as Codex that block
    /// when stdin looks like a pipe even if a prompt argument was supplied.
    bool redirect_stdin_null = false;

    // ── Environment ──
    bool augment_path = false;             // prepend exe-adjacent/bin to PATH
    /// Extra PATH folders, index 0 first. `run()` also prepends `ui.appPathDirectories`
    /// when `augment_path` or `use_shell` is set.
    std::vector<std::string> extra_path_prepends;
    /// Extra `key → value` environment variables for the child (overrides
    /// inherited entries of the same name). Used e.g. to stamp spawned custom
    /// commands with PM_IMAGE_COMMAND_ID so cmd_ipc descriptors can link back
    /// to the originating commands.json entry.
    std::vector<std::pair<std::string, std::string>> extra_env;

    // ── Callbacks ──
    using ChunkCb  = std::function<void(const std::string& stream, const std::string& chunk)>;
    using CancelCb = std::function<bool()>;  // returns true → cancel
    using ExitCb   = std::function<void(std::uint64_t run_id, unsigned long pid, int exit_code)>;

    ChunkCb  on_output_chunk;  // Captured + hidden Async — streaming stdout/stderr
    CancelCb on_cancel_check;  // Sync/Captured — polled periodically
    ExitCb   on_exit;          // Async mode — called from watcher thread

    // ── Tracking IDs (Async mode) ──
    unsigned    cmd_id     = 0;
    std::string command_id;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════════════════════════

struct RunResult {
    bool        ok         = false;
    int         exit_code  = -1;
    std::string error;

    // Captured mode only
    std::string stdout_text;
    std::string stderr_text;

    // Async mode tracking
    std::uint64_t  run_id = 0;
    unsigned long  pid    = 0;

    // Flags
    bool timed_out = false;
    bool cancelled = false;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Runner
// ═══════════════════════════════════════════════════════════════════════════════

/// Run a process according to the given options. Thread-safe for concurrent calls.
///
/// - Async: spawns + returns immediately; run_id and pid populated in result.
///   The watcher thread calls on_exit when the process ends. Hidden-window
///   children have stdout/stderr piped so the host can log what they emit.
/// - Sync: blocks until exit (or cancel). exit_code populated.
/// - Captured: blocks with piped IO. stdout_text/stderr_text populated.
RunResult run(const RunOptions& opts);

/// Kill the process that is currently executing in a Captured-mode `run()` call.
/// Safe to call from any thread; no-op if nothing is running.
void abort_captured_run();

#if defined(_WIN32)
/// Assign `process_handle` to the process-wide kill-on-close Job Object so the
/// child (and everything it spawns afterwards) is terminated when this process
/// exits — including a hard close or crash. The job is created lazily on first
/// use. Best-effort: returns false (and logs) if assignment fails, but never
/// throws. Used by the spawn engine for `bind_to_parent` runs and by other
/// direct `CreateProcessW` sites (e.g. the MCP stdio transport) that want the
/// same lifetime guarantee without routing through `run()`.
bool bind_process_to_lifetime_job(void* process_handle) noexcept;
#endif

} // namespace media::process

