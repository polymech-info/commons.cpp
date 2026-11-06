#pragma once
//
// Cross-platform single-directory change watcher.
//
//   * Win32  : backed by ReadDirectoryChangesW (overlapped I/O on a worker thread).
//   * macOS  : not yet implemented — Watch() returns false, no events (TODO: FSEvents).
//   * Linux  : not yet implemented — Watch() returns false, no events (TODO: inotify).
//
// Threading contract: the change callback fires on an internal background thread.
// Marshal to your UI thread (e.g. ::PostMessage with a heap-allocated batch) before
// touching UI state. The callback is never invoked after Stop()/destruction returns.
//
#include <filesystem>
#include <functional>
#include <memory>
#include <vector>

namespace media {

enum class FileChangeKind {
    Added,          // a child file/dir appeared
    Removed,        // a child file/dir was deleted
    Modified,       // a child's contents / size / last-write changed
    RenamedOld,     // the source name of a rename (treat like Removed)
    RenamedNew,     // the destination name of a rename (treat like Added)
    OverflowRescan, // the change buffer overflowed; individual events were lost —
                    // the consumer should re-enumerate the folder. `path` is empty.
};

struct FileChange {
    FileChangeKind        kind;
    std::filesystem::path path;   // absolute path of the affected child (empty for OverflowRescan)
};

/// Watches one directory for child create/delete/rename/modify events.
///
/// Owns a single background watch at a time; calling Watch() with a new folder
/// transparently stops the previous one. Re-pointing to the folder that is already
/// being watched is a cheap no-op.
class FileWatcher {
public:
    /// Receives a non-empty batch of changes (moved in). Invoked on a worker thread.
    using ChangeCallback = std::function<void(std::vector<FileChange>)>;

    explicit FileWatcher(ChangeCallback on_change);
    ~FileWatcher();

    FileWatcher(const FileWatcher&)            = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;
    FileWatcher(FileWatcher&&)                 = delete;
    FileWatcher& operator=(FileWatcher&&)      = delete;

    /// Begin (or re-point) watching @p folder. Stops any active watch first.
    /// @param recursive  watch the whole subtree (default: this folder only).
    /// @return true if the watch is now active for @p folder; false if @p folder
    ///         is not a directory, could not be opened, or the platform is unsupported.
    bool Watch(const std::filesystem::path& folder, bool recursive = false);

    /// Stop the active watch and join the worker thread. Safe to call repeatedly.
    void Stop();

    bool                  IsWatching() const noexcept;
    std::filesystem::path WatchedFolder() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace media
