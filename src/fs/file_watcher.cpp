#include "fs/file_watcher.hpp"

#include <mutex>
#include <utility>

#if defined(_WIN32)
#  error "file_watcher.cpp is the non-Windows stub; Windows builds file_watcher_win32.cpp"
#endif

namespace media {

// FSEvents (macOS) and inotify (Linux) are not implemented. Watch() reports that.
struct FileWatcher::Impl {
    explicit Impl(ChangeCallback cb) : cb_(std::move(cb)) {}
    ChangeCallback        cb_;
    mutable std::mutex    mtx_;
    std::filesystem::path folder_;
};

FileWatcher::FileWatcher(ChangeCallback on_change)
    : impl_(std::make_unique<Impl>(std::move(on_change)))
{
}

FileWatcher::~FileWatcher() = default;

bool FileWatcher::Watch(const std::filesystem::path&, bool)
{
    return false;
}

void FileWatcher::Stop() {}

bool FileWatcher::IsWatching() const noexcept
{
    return false;
}

std::filesystem::path FileWatcher::WatchedFolder() const
{
    std::lock_guard<std::mutex> lk(impl_->mtx_);
    return impl_->folder_;
}

} // namespace media
