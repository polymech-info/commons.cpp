#pragma once
//
// Win32 folder-size scanner for direct child directories of one folder.
// One scan session per current folder; each visible child folder gets its own
// aggregate bucket. See docs/foldersize.md.
//
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace media {

struct FolderSizeResult
{
    uint64_t logicalBytes{};
    uint64_t fileCount{};
    uint64_t directoryCount{};
    uint64_t inaccessibleCount{};
    bool complete{};
};

enum class StorageType
{
    Unknown,
    Rotational,
    Ssd,
    Network,
};

[[nodiscard]] unsigned ChooseWorkerCount(StorageType type) noexcept;
[[nodiscard]] StorageType DetectStorageType(
    const std::wstring& rootPath) noexcept;
[[nodiscard]] std::wstring ToExtendedWin32Path(std::wstring path);
[[nodiscard]] std::wstring FromExtendedWin32Path(
    const std::wstring& path);

class CurrentFolderSizeScan
{
public:
    struct ChildResult
    {
        std::wstring name;
        std::wstring path;

        std::atomic_uint64_t logicalBytes{0};
        std::atomic_uint64_t fileCount{0};
        std::atomic_uint64_t directoryCount{0};
        std::atomic_uint64_t inaccessibleCount{0};
        std::atomic_bool complete{false};

        ChildResult() = default;
        ChildResult(std::wstring childName, std::wstring childPath);
        ChildResult(const ChildResult&) = delete;
        ChildResult& operator=(const ChildResult&) = delete;
    };

    struct Snapshot
    {
        size_t index{};
        std::wstring name;
        std::wstring path;

        uint64_t logicalBytes{};
        uint64_t fileCount{};
        uint64_t directoryCount{};
        uint64_t inaccessibleCount{};
        bool complete{};
    };

    using ProgressCallback =
        std::function<void(std::vector<Snapshot>)>;

    CurrentFolderSizeScan() = default;
    ~CurrentFolderSizeScan();

    CurrentFolderSizeScan(const CurrentFolderSizeScan&) = delete;
    CurrentFolderSizeScan& operator=(const CurrentFolderSizeScan&) = delete;

    /// Starts enumeration + recursive sizing on background threads. Safe to call
    /// from the UI thread (returns before FindFirst/FindNext work begins).
    bool Start(
        std::wstring rootPath,
        unsigned workerCount,
        ProgressCallback callback);
    /// Requests stop and cancels blocking I/O; does not join worker threads.
    /// Destroy the scan (destructor) off the UI thread to wait for completion.
    void Cancel();

    [[nodiscard]] bool IsRunning() const noexcept;
    [[nodiscard]] std::vector<Snapshot> GetSnapshot() const;

    struct DirectoryTask
    {
        std::wstring path;
        ChildResult* aggregate{};
    };

private:
    [[nodiscard]] static uint64_t FileSize(
        const WIN32_FIND_DATAW& data) noexcept;
    [[nodiscard]] static std::wstring JoinPath(
        const std::wstring& parent,
        const wchar_t* child);
    [[nodiscard]] static std::wstring RemoveTrailingSeparators(
        std::wstring path);
    [[nodiscard]] static std::wstring NormalizeRootPath(
        std::wstring path);
    [[nodiscard]] static bool TryJoinPath(
        const std::wstring& parent,
        const wchar_t* child,
        std::wstring& outPath);
    [[nodiscard]] static bool TryOpenFind(
        const std::wstring& directoryPath,
        HANDLE& outHandle,
        WIN32_FIND_DATAW& data);

    void JoinThreads();
    void RequestStopUnlocked();
    void CollectCancelHandlesUnlocked(std::vector<HANDLE>& handles);
    bool EnumerateCurrentFolder();
    void BootstrapMain(std::stop_token stopToken);
    void WorkerMain(std::stop_token stopToken);
    void ScanDirectory(
        const DirectoryTask& task,
        std::stop_token stopToken);
    void ProgressMain(std::stop_token stopToken);
    void PublishProgress();
    void MarkAllComplete();

    mutable std::mutex mutex_;
    std::condition_variable_any queueCv_;

    std::wstring rootPath_;
    ProgressCallback callback_;
    unsigned workerCount_{1};

    std::deque<DirectoryTask> queue_;
    std::vector<std::unique_ptr<ChildResult>> results_;

    std::jthread bootstrapThread_;
    std::vector<std::jthread> workers_;
    std::jthread progressThread_;

    std::atomic_uint64_t outstandingTasks_{0};
    std::atomic_bool cancelled_{false};
    std::atomic_bool running_{false};
};

} // namespace media

#endif // _WIN32
