#pragma once
// installer/fs/fs_ops.hpp — low-level file primitives shared by verbs.
// Portable std::filesystem baseline; Windows specifics (long paths, ACL-aware
// overwrites) get a fs_ops_win32.cpp split behind these same signatures.

#include "installer/events.hpp"
#include "installer/manifest.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pm::installer::fs_ops {

struct CopyTreeOptions {
    std::string source_dir;   // must exist; walked recursively
    std::string target_dir;   // created as needed
    std::string pattern;      // filename glob include-filter (resolve.hpp semantics)
    std::vector<std::string> exclude; // glob patterns for relative paths to skip
    OnExist     on_exist = OnExist::Skip;
    bool        dry_run  = false;
    /// When true (default), skip `.git` / `.svn` / `.hg` (FilterSpec::skip_vcs).
    bool        skip_vcs = true;

    // Called before each file copy with the source-relative path.
    std::function<void(const std::string& rel_path)> on_file;
    // Cooperative abort probe checked between files (may be null).
    std::function<AbortReason()> should_abort;
};

struct CopyStats {
    int           files_copied  = 0;
    int           files_skipped = 0;
    std::uint64_t bytes_written = 0;
    AbortReason   aborted = AbortReason::None;
    // Absolute destination paths written this run (empty on dry-run).
    std::vector<std::string> written_files;
};

struct CopyFilesOptions {
    std::vector<std::string> source_files; // absolute paths
    std::string rel_base;                    // stripped when building target rel paths
    std::string target_dir;
    std::string pattern;                     // optional include-filter on source-relative path
    std::vector<std::string> exclude;        // glob patterns for relative paths to skip
    OnExist     on_exist = OnExist::Skip;
    bool        dry_run  = false;
    bool        skip_vcs = true;

    std::function<void(const std::string& rel_path)> on_file;
    std::function<AbortReason()> should_abort;
};

// Recursively copy `source_dir` into `target_dir` via the same walk/filter
// stack as CLI `cp` (`collect_copy_at` + `.gitignore` mask + include/exclude),
// then apply installer `on_exist`. Contents merge into `target_dir` (no extra
// source-folder leaf). VCS dirs are skipped in that shared walk.
// On failure returns false and fills err/err_class.
// An abort (stats.aborted != None) also returns false with a matching error.
bool copy_tree(const CopyTreeOptions& opts, CopyStats& stats,
               std::string& err, ErrorClass& err_class);

// Copy an explicit file list into `target_dir`, preserving paths relative to
// `rel_base`. Same FilterSpec defaults as copy_tree / CLI `cp`.
bool copy_files(const CopyFilesOptions& opts, CopyStats& stats,
                std::string& err, ErrorClass& err_class);

// Write bytes to `path` via a same-directory temp file + atomic rename, so a
// crash mid-write never leaves a truncated destination.
bool write_file_atomic(const std::string& path, const void* data, size_t size,
                       std::string& err);

// Read a whole file into `out`.  Returns false and sets err on failure.
bool read_file(const std::string& path, std::string& out, std::string& err);

} // namespace pm::installer::fs_ops
