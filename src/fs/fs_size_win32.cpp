#include "fs_size_win32.hpp"

#if defined(_WIN32)

#include "fs/path_sanitizer.hpp"

#include <chrono>
#include <cwchar>
#include <optional>
#include <utility>

namespace media {
namespace {

constexpr size_t kMaxExtendedPathLength = 32767;

bool HasExtendedPrefix(const std::wstring& path) noexcept
{
    return path.rfind(L"\\\\?\\", 0) == 0;
}

bool IsFindEnumerationComplete(DWORD error) noexcept
{
    return error == ERROR_NO_MORE_FILES
        || error == ERROR_OPERATION_ABORTED;
}

void CancelThreadIo(HANDLE threadHandle) noexcept
{
    if (!threadHandle || threadHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    const DWORD threadId = GetThreadId(threadHandle);
    if (threadId == 0) {
        return;
    }

    HANDLE cancelHandle =
        OpenThread(THREAD_TERMINATE, FALSE, threadId);
    if (!cancelHandle) {
        return;
    }

    CancelSynchronousIo(cancelHandle);
    CloseHandle(cancelHandle);
}

} // namespace

std::wstring ToExtendedWin32Path(std::wstring path)
{
    if (path.empty() || HasExtendedPrefix(path)) {
        return path;
    }

    if (path.rfind(L"\\\\", 0) == 0 && path.size() > 2 && path[2] != L'?') {
        return L"\\\\?\\UNC\\" + path.substr(2);
    }

    if (path.size() >= 2 && path[1] == L':') {
        if (path.size() == 2 || path[2] != L'\\') {
            path.insert(2, 1, L'\\');
        }
        return L"\\\\?\\" + path;
    }

    return path;
}

std::wstring FromExtendedWin32Path(const std::wstring& path)
{
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        return L"\\\\" + path.substr(8);
    }
    if (HasExtendedPrefix(path)) {
        return path.substr(4);
    }
    return path;
}

std::wstring CurrentFolderSizeScan::NormalizeRootPath(std::wstring path)
{
    path = RemoveTrailingSeparators(std::move(path));
    if (path.empty()) {
        return path;
    }

    path = path::normalize_local_path_w(path, true);
    if (path.empty()) {
        return path;
    }

    if (!HasExtendedPrefix(path)) {
        std::wstring buffer(32768, L'\0');
        const DWORD length = GetFullPathNameW(
            path.c_str(),
            static_cast<DWORD>(buffer.size()),
            buffer.data(),
            nullptr);
        if (length > 0 && length < buffer.size()) {
            path.assign(buffer.data(), length);
        }
    }

    return ToExtendedWin32Path(std::move(path));
}

bool CurrentFolderSizeScan::TryJoinPath(
    const std::wstring& parent,
    const wchar_t* child,
    std::wstring& outPath)
{
    if (!path::is_safe_path_component_w(child)) {
        return false;
    }

    outPath = JoinPath(parent, child);
    return outPath.size() <= kMaxExtendedPathLength;
}

bool CurrentFolderSizeScan::TryOpenFind(
    const std::wstring& directoryPath,
    HANDLE& outHandle,
    WIN32_FIND_DATAW& data)
{
    outHandle = INVALID_HANDLE_VALUE;

    const std::wstring extendedDirectory =
        HasExtendedPrefix(directoryPath)
        ? directoryPath
        : ToExtendedWin32Path(directoryPath);
    const std::wstring pattern = JoinPath(extendedDirectory, L"*");

    outHandle = FindFirstFileExW(
        pattern.c_str(),
        FindExInfoBasic,
        &data,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH);
    return outHandle != INVALID_HANDLE_VALUE;
}

unsigned ChooseWorkerCount(StorageType type) noexcept
{
    switch (type) {
    case StorageType::Rotational:
        return 1;
    case StorageType::Network:
        return 2;
    case StorageType::Ssd:
        return 4;
    default:
        return 2;
    }
}

StorageType DetectStorageType(const std::wstring& rootPath) noexcept
{
    const std::wstring path = FromExtendedWin32Path(rootPath);
    if (path.size() < 2) {
        return StorageType::Unknown;
    }

    std::wstring root = path.substr(0, 2);
    if (root[1] != L':') {
        if (path.rfind(L"\\\\", 0) == 0) {
            return StorageType::Network;
        }
        return StorageType::Unknown;
    }
    root.push_back(L'\\');

    switch (::GetDriveTypeW(root.c_str())) {
    case DRIVE_REMOTE:
        return StorageType::Network;
    case DRIVE_REMOVABLE:
    case DRIVE_CDROM:
        return StorageType::Rotational;
    case DRIVE_FIXED:
        return StorageType::Ssd;
    default:
        return StorageType::Unknown;
    }
}

CurrentFolderSizeScan::ChildResult::ChildResult(
    std::wstring childName,
    std::wstring childPath)
    : name(std::move(childName)),
      path(std::move(childPath))
{
}

CurrentFolderSizeScan::~CurrentFolderSizeScan()
{
    JoinThreads();
}

uint64_t CurrentFolderSizeScan::FileSize(
    const WIN32_FIND_DATAW& data) noexcept
{
    return (static_cast<uint64_t>(data.nFileSizeHigh) << 32)
        | static_cast<uint64_t>(data.nFileSizeLow);
}

std::wstring CurrentFolderSizeScan::JoinPath(
    const std::wstring& parent,
    const wchar_t* child)
{
    std::wstring result;
    result.reserve(parent.size() + 1 + wcslen(child));
    result.append(parent);
    if (!result.empty()
        && result.back() != L'\\'
        && result.back() != L'/') {
        result.push_back(L'\\');
    }
    result.append(child);
    return result;
}

std::wstring CurrentFolderSizeScan::RemoveTrailingSeparators(
    std::wstring path)
{
    while (path.size() > 3
        && (path.back() == L'\\' || path.back() == L'/')) {
        path.pop_back();
    }
    return path;
}

void CurrentFolderSizeScan::RequestStopUnlocked()
{
    if (bootstrapThread_.joinable()) {
        bootstrapThread_.request_stop();
    }
    for (auto& worker : workers_) {
        worker.request_stop();
    }
    if (progressThread_.joinable()) {
        progressThread_.request_stop();
    }
}

void CurrentFolderSizeScan::CollectCancelHandlesUnlocked(
    std::vector<HANDLE>& handles)
{
    auto collect = [&handles](std::jthread& thread) {
        if (!thread.joinable()) {
            return;
        }
        handles.push_back(
            static_cast<HANDLE>(thread.native_handle()));
    };

    collect(bootstrapThread_);
    for (auto& worker : workers_) {
        collect(worker);
    }
    collect(progressThread_);
}

void CurrentFolderSizeScan::JoinThreads()
{
    Cancel();

    // Joining can block on FindNextFile; callers must not do this on the UI
    // thread (CustomFileView destroys the scan on a background thread).
    bootstrapThread_ = {};
    workers_.clear();
    progressThread_ = {};

    {
        std::scoped_lock lock(mutex_);
        queue_.clear();
        outstandingTasks_.store(0, std::memory_order_relaxed);
        callback_ = nullptr;
    }

    running_.store(false, std::memory_order_release);
}

bool CurrentFolderSizeScan::Start(
    std::wstring rootPath,
    unsigned workerCount,
    ProgressCallback callback)
{
    JoinThreads();

    if (workerCount == 0) {
        workerCount = 1;
    }

    rootPath = NormalizeRootPath(std::move(rootPath));
    if (rootPath.empty()) {
        return false;
    }

    {
        std::scoped_lock lock(mutex_);
        rootPath_ = std::move(rootPath);
        callback_ = std::move(callback);
        workerCount_ = workerCount;
        queue_.clear();
        results_.clear();
        outstandingTasks_.store(0, std::memory_order_relaxed);
        cancelled_.store(false, std::memory_order_relaxed);
        running_.store(true, std::memory_order_release);
    }

    // Child-folder enumeration + worker spawn stay off the caller thread.
    bootstrapThread_ = std::jthread([this](std::stop_token stopToken) {
        BootstrapMain(stopToken);
    });
    return true;
}

void CurrentFolderSizeScan::Cancel()
{
    cancelled_.store(true, std::memory_order_release);

    std::vector<HANDLE> handles;
    {
        std::scoped_lock lock(mutex_);
        callback_ = nullptr;
        RequestStopUnlocked();
        CollectCancelHandlesUnlocked(handles);
    }

    queueCv_.notify_all();

    for (HANDLE handle : handles) {
        CancelThreadIo(handle);
    }
}

void CurrentFolderSizeScan::BootstrapMain(std::stop_token stopToken)
{
    if (stopToken.stop_requested()
        || cancelled_.load(std::memory_order_acquire)) {
        running_.store(false, std::memory_order_release);
        return;
    }

    if (!EnumerateCurrentFolder()) {
        running_.store(false, std::memory_order_release);
        PublishProgress();
        return;
    }

    if (stopToken.stop_requested()
        || cancelled_.load(std::memory_order_acquire)) {
        running_.store(false, std::memory_order_release);
        return;
    }

    const unsigned workerCount = workerCount_;
    {
        std::scoped_lock lock(mutex_);
        if (cancelled_.load(std::memory_order_acquire)
            || stopToken.stop_requested()) {
            running_.store(false, std::memory_order_release);
            return;
        }

        workers_.reserve(workerCount);
        for (unsigned index = 0; index < workerCount; ++index) {
            workers_.emplace_back(
                [this](std::stop_token workerStop) {
                    WorkerMain(workerStop);
                });
        }

        progressThread_ = std::jthread(
            [this](std::stop_token progressStop) {
                ProgressMain(progressStop);
            });
    }

    if (outstandingTasks_.load(std::memory_order_acquire) == 0) {
        MarkAllComplete();
        running_.store(false, std::memory_order_release);
    }

    queueCv_.notify_all();
}

bool CurrentFolderSizeScan::IsRunning() const noexcept
{
    return running_.load(std::memory_order_acquire);
}

std::vector<CurrentFolderSizeScan::Snapshot>
CurrentFolderSizeScan::GetSnapshot() const
{
    std::vector<Snapshot> snapshot;

    std::scoped_lock lock(mutex_);
    snapshot.reserve(results_.size());

    for (size_t index = 0; index < results_.size(); ++index) {
        const auto& result = results_[index];
        snapshot.push_back({
            .index = index,
            .name = result->name,
            .path = result->path,
            .logicalBytes =
                result->logicalBytes.load(std::memory_order_relaxed),
            .fileCount =
                result->fileCount.load(std::memory_order_relaxed),
            .directoryCount =
                result->directoryCount.load(std::memory_order_relaxed),
            .inaccessibleCount =
                result->inaccessibleCount.load(
                    std::memory_order_relaxed),
            .complete =
                result->complete.load(std::memory_order_acquire),
        });
    }

    return snapshot;
}

bool CurrentFolderSizeScan::EnumerateCurrentFolder()
{
    WIN32_FIND_DATAW data{};
    HANDLE rawHandle = INVALID_HANDLE_VALUE;
    if (!TryOpenFind(rootPath_, rawHandle, data)) {
        return false;
    }

    struct FindHandle
    {
        HANDLE value{INVALID_HANDLE_VALUE};

        ~FindHandle()
        {
            if (value != INVALID_HANDLE_VALUE) {
                FindClose(value);
            }
        }
    } handle{rawHandle};

    do {
        if (cancelled_.load(std::memory_order_acquire)) {
            return false;
        }

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            continue;
        }

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            continue;
        }

        std::wstring childPathExtended;
        if (!TryJoinPath(rootPath_, data.cFileName, childPathExtended)) {
            continue;
        }

        const std::wstring childPath =
            FromExtendedWin32Path(childPathExtended);

        ChildResult* aggregate = nullptr;
        {
            std::scoped_lock lock(mutex_);
            results_.push_back(std::make_unique<ChildResult>(
                data.cFileName,
                childPath));
            aggregate = results_.back().get();
            queue_.push_back({
                .path = std::move(childPathExtended),
                .aggregate = aggregate,
            });
        }

        outstandingTasks_.fetch_add(1, std::memory_order_relaxed);
    } while (FindNextFileW(handle.value, &data));

    return IsFindEnumerationComplete(GetLastError());
}

void CurrentFolderSizeScan::WorkerMain(std::stop_token stopToken)
{
    while (!stopToken.stop_requested()) {
        std::optional<DirectoryTask> task;

        {
            std::unique_lock lock(mutex_);

            queueCv_.wait(
                lock,
                stopToken,
                [this] {
                    return !queue_.empty()
                        || outstandingTasks_.load(
                               std::memory_order_acquire)
                            == 0;
                });

            if (stopToken.stop_requested()) {
                return;
            }

            if (queue_.empty()) {
                if (outstandingTasks_.load(
                        std::memory_order_acquire)
                    == 0) {
                    return;
                }
                continue;
            }

            task = std::move(queue_.front());
            queue_.pop_front();
        }

        ScanDirectory(*task, stopToken);

        const uint64_t remaining =
            outstandingTasks_.fetch_sub(
                1,
                std::memory_order_acq_rel)
            - 1;

        if (remaining == 0) {
            MarkAllComplete();
            running_.store(false, std::memory_order_release);
        }

        queueCv_.notify_all();
    }
}

void CurrentFolderSizeScan::ScanDirectory(
    const DirectoryTask& task,
    std::stop_token stopToken)
{
    if (stopToken.stop_requested() || !task.aggregate) {
        return;
    }

    WIN32_FIND_DATAW data{};
    HANDLE rawHandle = INVALID_HANDLE_VALUE;
    if (!TryOpenFind(task.path, rawHandle, data)) {
        task.aggregate->inaccessibleCount.fetch_add(
            1,
            std::memory_order_relaxed);
        return;
    }

    struct FindHandle
    {
        HANDLE value{INVALID_HANDLE_VALUE};

        ~FindHandle()
        {
            if (value != INVALID_HANDLE_VALUE) {
                FindClose(value);
            }
        }
    } handle{rawHandle};

    ChildResult& result = *task.aggregate;

    do {
        if (stopToken.stop_requested()
            || cancelled_.load(std::memory_order_acquire)) {
            return;
        }

        const DWORD attributes = data.dwFileAttributes;

        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                continue;
            }

            result.directoryCount.fetch_add(
                1,
                std::memory_order_relaxed);

            std::wstring childPathExtended;
            if (!TryJoinPath(task.path, data.cFileName, childPathExtended)) {
                result.inaccessibleCount.fetch_add(
                    1,
                    std::memory_order_relaxed);
                continue;
            }

            DirectoryTask childTask{
                .path = std::move(childPathExtended),
                .aggregate = task.aggregate,
            };

            outstandingTasks_.fetch_add(1, std::memory_order_relaxed);

            {
                std::scoped_lock lock(mutex_);
                queue_.push_back(std::move(childTask));
            }

            queueCv_.notify_one();
        } else {
            result.logicalBytes.fetch_add(
                FileSize(data),
                std::memory_order_relaxed);
            result.fileCount.fetch_add(1, std::memory_order_relaxed);
        }
    } while (FindNextFileW(handle.value, &data));

    const DWORD error = GetLastError();
    if (!IsFindEnumerationComplete(error)) {
        result.inaccessibleCount.fetch_add(
            1,
            std::memory_order_relaxed);
    }
}

void CurrentFolderSizeScan::ProgressMain(std::stop_token stopToken)
{
    using namespace std::chrono_literals;

    while (!stopToken.stop_requested()) {
        std::this_thread::sleep_for(150ms);

        if (stopToken.stop_requested()) {
            break;
        }

        PublishProgress();

        if (!running_.load(std::memory_order_acquire)) {
            break;
        }
    }

    PublishProgress();
}

void CurrentFolderSizeScan::PublishProgress()
{
    if (cancelled_.load(std::memory_order_acquire)) {
        return;
    }

    ProgressCallback callback;
    {
        std::scoped_lock lock(mutex_);
        callback = callback_;
    }

    if (callback) {
        callback(GetSnapshot());
    }
}

void CurrentFolderSizeScan::MarkAllComplete()
{
    std::scoped_lock lock(mutex_);

    const bool complete =
        !cancelled_.load(std::memory_order_acquire);

    for (auto& result : results_) {
        result->complete.store(complete, std::memory_order_release);
    }
}

} // namespace media

#endif // _WIN32
