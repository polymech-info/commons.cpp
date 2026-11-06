#pragma once
//
// Portable sequential-selection runner.
//
// Runs one custom command per item in a selection, one at a time, without
// imposing any argument convention on the wrapped command.  The caller
// supplies a `make_opts` factory that turns a resolved VariableContext into
// a cmd_run::RunOptions; this file owns only the sequencing loop.
//
// Two entry points:
//
//   run_selection_sync()   — blocking; for the CLI dispatcher and
//                            the context-menu short-lived process.
//                            Calls media::process::run(Sync/Async) directly.
//
//   run_selection_async()  — non-blocking; for the ribbon/launcher UI thread.
//                            Drives cmd_run::Runner; on_status fires on the
//                            Runner watcher thread — UI consumers must
//                            PostMessage back to the UI thread.
//
// Both share the same SelectionRunSpec so call sites differ only in which
// function they invoke.
//

#include "command_runner.hpp"
#include "command_variables.hpp"
#include "process/process_runner.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace media::commands {

// Status values reported via SelectionRunSpec::on_status.
enum class RunItemStatus {
    Running,
    Done,
    Failed,
    Cancelled,
    Skipped,   // item not started because a prior item failed and continue_on_failure==false
};

struct SelectionRunSpec {
    // Stable commands.json id — stamped as PM_IMAGE_COMMAND_ID env var.
    std::string commandId;

    // One context per item (from build_selection_contexts).
    // A single-element vector means aggregate / single-run — no fan-out.
    std::vector<VariableContext> items;

    // Produce RunOptions for one resolved context.  The lambda resolves
    // variables, chooses executable/args/cwd, and sets runInConsole /
    // newConsoleWindow.  Called once per item on the calling thread (sync)
    // or the scheduling thread (async).
    //
    // Return an empty RunOptions (executable empty, shellLine empty,
    // consoleCommandLine empty) to skip that item.
    struct RunItemOptions {
        // ── Ribbon / launcher path (async via cmd_run::Runner, wide strings) ──
        media::cmd_run::RunOptions runner;

        // ── CLI / context-menu sync path (UTF-8 strings, used directly) ──
        // When use_direct == true, run_selection_sync uses `direct` as-is and
        // ignores `runner`.  Avoids the UTF-8 → wide → UTF-8 round-trip that
        // would otherwise happen when going through cmd_run::RunOptions.
        media::process::RunOptions direct;
        bool use_direct = false;

        // ── Console path (internal WebView2 terminal) ──
        bool         runInConsole       = false;
        std::wstring consoleCommandLine; // built by custom_console_command_line()
        bool         closeOnExit        = false;
    };
    std::function<RunItemOptions(const VariableContext&)> make_opts;

    // Called after each item changes status.  May be null.
    //   idx    — 0-based item index
    //   status — new state
    //   runId  — cmd_run::Runner run id when status==Running (async path only);
    //            0 for the sync path, console path, and all non-Running statuses.
    // sync variant: called on the calling thread.
    // async variant: called on the Runner watcher thread — must PostMessage for UI.
    std::function<void(std::size_t idx, RunItemStatus status, std::uint64_t runId)> on_status;

    // Console launch hook — only relevant when make_opts returns runInConsole=true.
    // Accepted console work must invoke completion with the PTY exit code; accepting
    // input is not completion. The async path registers command_control lifecycle
    // around accept/complete (Runner never sees the PTY child). If launch_console
    // is null/rejected, the item is failed (no silent Runner fallback).
    using ConsoleCompletion = std::function<void(int)>;
    std::function<bool(const std::wstring&, bool, ConsoleCompletion)> launch_console;

    // Serialize async batches sharing commandId. Commands opt out explicitly;
    // an absent commands.json runOptions.sequential value defaults to true.
    bool sequential = true;

    // Keep going after a failed item (exit code != 0)?  Default true.
    bool continue_on_failure = true;

    /// Optional UI / cancel key (same idea as VFS Job::batch). When non-zero,
    /// cancel_selection_batch stops the chain and marks remaining items Cancelled.
    std::uint64_t batchId = 0;
};

// ── Sync variant (CLI dispatcher, context-menu short-lived process) ───────────
//
// Runs items in order on the calling thread using media::process::run(Sync).
// Blocks until all items complete.  Returns the last non-zero exit code, or 0.
//
// cancel_check: polled between items (and by the underlying Sync runner while
// a child is running).  Pass `[] { return media::cli::cancel_requested(); }`
// from the CLI path.  May be null.
//
int run_selection_sync(
    const SelectionRunSpec&            spec,
    std::function<bool()>              cancel_check = nullptr);

// ── Async variant (ribbon / launcher — must NOT be called on the UI thread) ───
//
// Starts item[0] via cmd_run::Runner, then chains: when item[i] fires
// Exited/Failed the Runner watcher thread starts item[i+1].
// Returns immediately after starting item[0].
//
// on_status fires on the Runner watcher thread.  UI call sites must
// PostMessage (or equivalent) from inside the callback.
//
void run_selection_async(const SelectionRunSpec& spec);

/// Cancel an in-flight async selection batch (stops chaining; cancels the
/// current Runner child). No-op when batchId is 0 or unknown.
void cancel_selection_batch(std::uint64_t batchId);

/// Hold chaining after the current item finishes (does not kill the live child).
void pause_selection_batch(std::uint64_t batchId);
/// Resume a paused selection batch (starts the next Queued item if idle).
void resume_selection_batch(std::uint64_t batchId);
[[nodiscard]] bool is_selection_batch_paused(std::uint64_t batchId);

} // namespace media::commands
