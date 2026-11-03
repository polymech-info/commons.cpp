#pragma once
// installer/events.hpp — execution control: progress events, run options,
// results.  Everything the engine reports serializes to JSON so the CLI
// (--json), the web UI, and the run journal share one shape.

#include <nlohmann/json.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pm::installer {

// ── Error classification ──────────────────────────────────────────────────────
// transient  — retryable once the environment changes (network back, disk
//              freed, auth renewed).  Resume runs re-attempt these.
// permanent  — manifest or content problem; retrying cannot help.

enum class ErrorClass { None, Transient, Permanent };

const char* error_class_token(ErrorClass c) noexcept;

// ── Abort signals (cancellation / timeout) ────────────────────────────────────

enum class AbortReason { None, Cancelled, TimedOut };

// ── Per-package result ────────────────────────────────────────────────────────

struct PackageResult {
    std::string id;
    std::string verb;
    bool        ok = true;
    std::string error;
    ErrorClass  error_class = ErrorClass::None;
    // Non-empty when the package did not run: "constraints" | "masked" |
    // "journal" (already done in a previous run) | "aborted".
    std::string skip_reason;
    int         files_copied  = 0;
    int         files_skipped = 0;   // existing files left in place / filtered out
    std::uint64_t bytes_written = 0;
    std::int64_t  duration_ms   = 0;

    // Absolute paths a verb actually produced this run (copy/vfs_pull).  Fed to
    // after-hook verbs as VerbContext::input_files.  Empty on dry-run.
    std::vector<std::string> written_files;

    // shell verb — populated when verb == "shell"
    int         exit_code  = 0;
    std::string stdout_text;
    std::string stderr_text;
    bool        timed_out  = false;
    bool        cancelled  = false;

    nlohmann::json to_json() const;
};

// ── Manifest result ───────────────────────────────────────────────────────────

struct ManifestResult {
    bool                       ok = true;
    bool                       cancelled = false;
    bool                       timed_out = false;
    std::vector<PackageResult> packages;
    int                        total_copied  = 0;
    int                        total_skipped = 0;

    nlohmann::json to_json() const;
};

// ── Progress events ───────────────────────────────────────────────────────────
// All callbacks are optional (default no-op).  The engine invokes them on the
// calling thread.

struct InstallEvents {
    std::function<void(const std::string& pkg_id, const std::string& verb)> on_package_start;
    std::function<void(const std::string& pkg_id, const std::string& rel_path)> on_file;
    std::function<void(const PackageResult&)> on_package_done;
};

// ── Run options ───────────────────────────────────────────────────────────────

struct RunOptions {
    bool dry_run = false;

    // Resume a previous run: packages recorded as done in the journal are
    // skipped; failed-transient ones are retried.  Requires journal_dir.
    bool resume = false;

    // Directory for run-journal sidecars (<manifest-hash>.json/.jsonl).
    // Empty = journaling disabled.
    std::string journal_dir;

    // Wall-clock budget for the whole manifest run; 0 = unlimited.
    std::int64_t timeout_ms = 0;

    // Cooperative cancellation; may be null.
    const std::atomic<bool>* cancel = nullptr;

    // Runtime verb masking: when non-empty, only verbs matching one of these
    // globs may execute (e.g. {"copy", "vfs_*"}).
    std::vector<std::string> verb_allow_globs;

    // Service API override for vfs_pull / vfs_push verbs.
    std::string service_server_url;
    std::string service_bearer;

    // Retry packages recorded as failed(permanent) in the journal.
    bool force = false;
};

} // namespace pm::installer
