#include "fs/file_watcher.hpp"

#include <atomic>
#include <mutex>
#include <thread>
#include <utility>

#if !defined(_WIN32)
#  error "file_watcher_win32.cpp is the ReadDirectoryChangesW backend"
#endif

// Win32 headers must live at global scope (not inside `namespace media`), or the
// API declarations get nested and `::CreateEventW` / `::CloseHandle` / … fail to
// resolve in the global namespace.
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>

namespace media {

namespace fs = std::filesystem;

// A generated 8.3 short name is at most 12 chars (8 + '.' + 3) and carries a
// tilde (e.g. "IMG_12~1.JPG"). ReadDirectoryChangesW reports whatever name the
// filesystem operation used, so short names can leak through on volumes with
// 8.3 generation enabled and would never match the long-name entries our
// consumers build from directory enumeration.
static bool looks_like_8dot3(const std::wstring& leaf)
{
    return !leaf.empty() && leaf.size() <= 12 && leaf.find(L'~') != std::wstring::npos;
}

// Recover the long-path form for an entry that still exists on disk. Returns
// `full` unchanged when expansion is unnecessary or fails (e.g. the file is
// already gone — true for removals/old-rename names, which we don't expand).
static fs::path expand_short_name(const fs::path& full)
{
    wchar_t buf[MAX_PATH];
    const DWORD n = ::GetLongPathNameW(full.c_str(), buf, static_cast<DWORD>(_countof(buf)));
    if (n > 0 && n < static_cast<DWORD>(_countof(buf)))
        return fs::path(std::wstring(buf, n));
    return full;
}

struct FileWatcher::Impl {
    explicit Impl(ChangeCallback cb) : cb_(std::move(cb))
    {
        // Manual-reset so the worker stays signalled until we explicitly reset
        // it between watches; created once for the watcher's lifetime.
        stop_event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    ~Impl()
    {
        if (stop_event_)
            ::CloseHandle(stop_event_);
    }

    // Open the directory and spin up the worker. Caller holds no lock.
    bool Start(const fs::path& folder, bool recursive)
    {
        if (!stop_event_)
            return false;

        HANDLE dir = ::CreateFileW(
            folder.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr);
        if (dir == INVALID_HANDLE_VALUE)
            return false;

        ::ResetEvent(stop_event_);
        running_.store(true, std::memory_order_release);
        try {
            // The worker takes ownership of `dir` (closes it on exit).
            thread_ = std::thread(&Impl::Run, this, dir, folder, recursive);
        } catch (...) {
            running_.store(false, std::memory_order_release);
            ::CloseHandle(dir);
            return false;
        }
        return true;
    }

    void Stop()
    {
        if (stop_event_)
            ::SetEvent(stop_event_);
        if (thread_.joinable())
            thread_.join();
        running_.store(false, std::memory_order_release);
        if (stop_event_)
            ::ResetEvent(stop_event_);
    }

    // Worker thread. Owns `dir`.
    void Run(HANDLE dir, fs::path folder, bool recursive)
    {
        // 64 KB is the documented max that works across local + network volumes.
        // operator new gives storage aligned for any scalar, so the DWORD-aligned
        // FILE_NOTIFY_INFORMATION reinterpretation below is safe.
        std::vector<BYTE> buffer(64 * 1024);

        HANDLE io_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr); // manual reset
        if (!io_event) {
            ::CloseHandle(dir);
            return;
        }

        const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME
                           | FILE_NOTIFY_CHANGE_DIR_NAME
                           | FILE_NOTIFY_CHANGE_LAST_WRITE
                           | FILE_NOTIFY_CHANGE_SIZE;

        for (;;) {
            OVERLAPPED ov{};
            ov.hEvent = io_event;
            ::ResetEvent(io_event);

            DWORD queued = 0;
            const BOOL ok = ::ReadDirectoryChangesW(
                dir, buffer.data(), static_cast<DWORD>(buffer.size()),
                recursive ? TRUE : FALSE, filter, &queued, &ov, nullptr);
            if (!ok)
                break; // handle invalid (folder deleted/renamed) — stop quietly

            HANDLE waits[2] = { stop_event_, io_event };
            const DWORD wr = ::WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wr == WAIT_OBJECT_0) {
                // Stop requested: cancel the pending read and drain it so the
                // OVERLAPPED/buffer are no longer referenced before we return.
                ::CancelIo(dir);
                DWORD ignored = 0;
                ::GetOverlappedResult(dir, &ov, &ignored, TRUE);
                break;
            }
            if (wr != WAIT_OBJECT_0 + 1)
                break; // wait failed

            DWORD transferred = 0;
            if (!::GetOverlappedResult(dir, &ov, &transferred, FALSE))
                break;

            if (transferred == 0) {
                // The kernel signalled completion but returned no bytes: too many
                // changes to fit the buffer. Individual events were lost; ask the
                // consumer to re-enumerate.
                if (cb_ && running_.load(std::memory_order_acquire)) {
                    std::vector<FileChange> overflow;
                    overflow.push_back({ FileChangeKind::OverflowRescan, {} });
                    cb_(std::move(overflow));
                }
                continue;
            }

            std::vector<FileChange> changes;
            const BYTE* cursor = buffer.data();
            for (;;) {
                const auto* fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(cursor);
                // FileName is NOT null-terminated; length is in bytes.
                std::wstring name(fni->FileName, fni->FileNameLength / sizeof(wchar_t));

                FileChangeKind kind = FileChangeKind::Modified;
                bool keep = true;
                switch (fni->Action) {
                    case FILE_ACTION_ADDED:            kind = FileChangeKind::Added;      break;
                    case FILE_ACTION_REMOVED:          kind = FileChangeKind::Removed;    break;
                    case FILE_ACTION_MODIFIED:         kind = FileChangeKind::Modified;   break;
                    case FILE_ACTION_RENAMED_OLD_NAME: kind = FileChangeKind::RenamedOld; break;
                    case FILE_ACTION_RENAMED_NEW_NAME: kind = FileChangeKind::RenamedNew; break;
                    default:                           keep = false;                      break;
                }
                if (keep && !name.empty()) {
                    fs::path full = folder / name;
                    // Only expand for actions whose target still exists; removals
                    // and old-rename names are gone, so GetLongPathNameW can't help.
                    const bool exists_now = (kind == FileChangeKind::Added
                                          || kind == FileChangeKind::Modified
                                          || kind == FileChangeKind::RenamedNew);
                    if (exists_now && looks_like_8dot3(std::filesystem::path(name).filename().wstring()))
                        full = expand_short_name(full);
                    changes.push_back({ kind, std::move(full) });
                }

                if (fni->NextEntryOffset == 0)
                    break;
                cursor += fni->NextEntryOffset;
            }

            if (!changes.empty() && cb_ && running_.load(std::memory_order_acquire))
                cb_(std::move(changes));
        }

        ::CloseHandle(io_event);
        ::CloseHandle(dir);

        // Reflect self-termination (folder deleted/renamed, or a failed read) so
        // IsWatching() doesn't keep reporting a watcher whose thread has exited.
        // Stop() also clears this after join(); the duplicate store is harmless.
        running_.store(false, std::memory_order_release);
    }

    ChangeCallback     cb_;
    HANDLE             stop_event_ = nullptr;
    std::thread        thread_;
    std::atomic_bool   running_{false};

    mutable std::mutex mtx_;     // guards folder_/recursive_
    fs::path           folder_;
    bool               recursive_ = false;
};

FileWatcher::FileWatcher(ChangeCallback on_change)
    : impl_(std::make_unique<Impl>(std::move(on_change)))
{
}

FileWatcher::~FileWatcher()
{
    if (impl_)
        impl_->Stop();
}

bool FileWatcher::Watch(const fs::path& folder, bool recursive)
{
    {
        std::lock_guard<std::mutex> lk(impl_->mtx_);
        if (impl_->running_.load(std::memory_order_acquire)
            && impl_->folder_ == folder
            && impl_->recursive_ == recursive)
            return true; // already watching exactly this — cheap no-op
    }

    Stop();

    std::error_code ec;
    if (!fs::is_directory(folder, ec) || ec)
        return false;

    if (!impl_->Start(folder, recursive))
        return false;

    std::lock_guard<std::mutex> lk(impl_->mtx_);
    impl_->folder_    = folder;
    impl_->recursive_ = recursive;
    return true;
}

void FileWatcher::Stop()
{
    impl_->Stop();
    std::lock_guard<std::mutex> lk(impl_->mtx_);
    impl_->folder_.clear();
}

bool FileWatcher::IsWatching() const noexcept
{
    return impl_->running_.load(std::memory_order_acquire);
}

fs::path FileWatcher::WatchedFolder() const
{
    std::lock_guard<std::mutex> lk(impl_->mtx_);
    return impl_->folder_;
}

} // namespace media
