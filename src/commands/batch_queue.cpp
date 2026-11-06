#include "batch_queue.hpp"
#include "fs/path_sanitizer.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <system_error>

namespace media {

// ── BatchControl ──────────────────────────────────────────────────────────────

void BatchControl::check_pause()
{
    if (!paused.load(std::memory_order_acquire))
        return;
    std::unique_lock<std::mutex> lk(pause_mtx);
    pause_cv.wait(lk, [this] {
        return !paused.load(std::memory_order_relaxed)
            || cancel.load(std::memory_order_relaxed);
    });
}

void BatchControl::pause()
{
    paused.store(true, std::memory_order_release);
}

void BatchControl::resume()
{
    paused.store(false, std::memory_order_release);
    pause_cv.notify_all();
}

void BatchControl::request_cancel()
{
    cancel.store(true, std::memory_order_release);
    paused.store(false, std::memory_order_release);
    pause_cv.notify_all();
}

// ── BatchState helpers ────────────────────────────────────────────────────────

int BatchState::count_done() const
{
    int n = 0;
    for (const auto& it : items)
        if (it.status == BatchItemStatus::Done) ++n;
    return n;
}

int BatchState::count_error() const
{
    int n = 0;
    for (const auto& it : items)
        if (it.status == BatchItemStatus::Error) ++n;
    return n;
}

int BatchState::count_pending() const
{
    int n = 0;
    for (const auto& it : items)
        if (it.status == BatchItemStatus::Pending) ++n;
    return n;
}

// ── File fingerprint (size + mtime, no external deps) ────────────────────────
// Named "sha256_fast" for API compatibility, but uses filesystem metadata as a
// fast, portable change-detection fingerprint.  Sufficient for session resume:
// if a file's size or mtime differs from the saved value the item is flagged.

std::string file_sha256_fast(const std::string& path)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path file = media::path::path_from_utf8(path);
    const auto sz    = fs::file_size(file, ec);
    if (ec) return {};
    const auto mtime = fs::last_write_time(file, ec);
    if (ec) return {};
    // Apple libc++: duration::count() can be __int128 — no ostream overload; use fixed-width.
    const auto count = static_cast<std::uint64_t>(mtime.time_since_epoch().count());
    std::ostringstream ss;
    ss << std::hex << static_cast<std::uintmax_t>(sz) << ":" << count;
    return ss.str();
}

// ── UUID ──────────────────────────────────────────────────────────────────────

std::string new_session_id()
{
    std::random_device rd;
    std::mt19937_64    gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    const uint64_t a = dis(gen);
    const uint64_t b = dis(gen);

    auto hex = [](uint64_t v, int digits) -> std::string {
        std::ostringstream ss;
        ss << std::hex << std::setw(digits) << std::setfill('0') << v;
        return ss.str().substr(0, digits);
    };

    return hex(a >> 32,           8) + "-"
         + hex((a >> 16) & 0xFFFF, 4) + "-"
         + hex(a & 0xFFFF,         4) + "-"
         + hex(b >> 48,            4) + "-"
         + hex(b & 0x0000FFFFFFFFFFFFULL, 12);
}

// ── ISO-8601 UTC timestamp ────────────────────────────────────────────────────

std::string utc_now_iso8601()
{
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto t   = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_MSC_VER)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // namespace media
