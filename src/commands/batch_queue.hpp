#pragma once
// Batch queue control — pause / resume / cancel for file-batch workers.
// In-memory only.  Persistence (sessions.json) lives in win/settings_store.
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace media {

// ── BatchControl ──────────────────────────────────────────────────────────────
// Thread-safe pause/cancel gate shared between the UI thread and a worker.
// Workers call check_pause() between items.  The UI thread calls pause(),
// resume(), or request_cancel() from ribbon command handlers.
//
// Lifetime: created by CMainFrame::OnRun*, captured by value (shared_ptr)
// into the worker lambda, and also held by CMainFrame for the UI-side API.
struct BatchControl {
    std::atomic<bool>       cancel{false};
    std::atomic<bool>       paused{false};
    std::mutex              pause_mtx;
    std::condition_variable pause_cv;

    // ── Worker-side ──────────────────────────────────────────────────────────
    /// Block here until resumed or cancelled.  No-op when not paused.
    /// Must be called between items, never inside libvips or a curl call.
    void check_pause();

    // ── UI-thread-side ───────────────────────────────────────────────────────
    void pause();           ///< Enter paused state.
    void resume();          ///< Leave paused state; unblocks check_pause().
    void request_cancel();  ///< Set cancel + unblock check_pause().
};

// ── BatchItemStatus ───────────────────────────────────────────────────────────
enum class BatchItemStatus { Pending, Done, Error };

// ── BatchItem ─────────────────────────────────────────────────────────────────
struct BatchItem {
    std::string     path;
    std::string     sha256;   ///< Hex SHA-256 of first 64 KB (change detection on resume).
    BatchItemStatus status  = BatchItemStatus::Pending;
    std::string     error;    ///< Non-empty when status == Error.
};

// ── BatchState ────────────────────────────────────────────────────────────────
// Owned by CMainFrame (m_currentSession).  Updated in-place by worker threads
// via the shared BatchStateAccess mutex.  Serialized only on explicit user Save.
struct BatchState {
    std::string            session_id;  ///< UUID generated at batch start.
    std::string            op;          ///< "resize"|"compress"|"meta"|"transform"|"find"
    nlohmann::json         options;     ///< Full op-opts blob; apply_*_from_json reuses on resume.
    std::vector<BatchItem> items;
    std::string            created_at;  ///< ISO-8601 UTC.
    std::string            updated_at;

    int count_done()    const;
    int count_error()   const;
    int count_pending() const;
    bool empty() const { return items.empty(); }
};

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Return a change-detection fingerprint for @p path (file size + mtime,
/// hex-encoded).  Named "sha256_fast" for API stability; the implementation
/// uses std::filesystem metadata — no external deps, no crypto.
/// Returns empty string on I/O failure.
std::string file_sha256_fast(const std::string& path);

/// Generate a random session UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
std::string new_session_id();

/// ISO-8601 UTC timestamp string for "now" (e.g. "2026-04-20T12:34:56Z").
std::string utc_now_iso8601();

} // namespace media
