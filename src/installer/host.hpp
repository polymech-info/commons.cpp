#pragma once

// Host-owned installer facts. Variable expansion, the VFS walker, CMS
// pull/push, the shell runner, and the OAuth bearer stay on the host.

#include "installer/variables.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace pm::installer::host {

using ResolveVariablesFn = std::function<std::string(const std::string& raw,
                                                     const VariableMap& vars,
                                                     std::string* err)>;
using ApplySourceFileFn = std::function<void(VariableMap& vars,
                                             const std::string& source_file,
                                             const std::string& cwd,
                                             const std::string& rel_base)>;
using MakeBundleFn = std::function<VariableMap(const std::string& install_root,
                                               std::string* err)>;
using CmsBaseFn = std::function<std::string(const std::string& configured)>;
using ReadBearerFn = std::function<bool(std::string& bearer, std::string& err)>;

void set_resolve_variables(ResolveVariablesFn fn);
void set_apply_source_file_variables(ApplySourceFileFn fn);
void set_make_bundle_variables(MakeBundleFn fn);
void set_resolve_cms_base(CmsBaseFn fn);
void set_read_access_token(ReadBearerFn fn);

std::string resolve_variables(const std::string& raw, const VariableMap& vars, std::string* err);
void apply_source_file_variables(VariableMap& vars,
                                 const std::string& source_file,
                                 const std::string& cwd,
                                 const std::string& rel_base);
VariableMap make_bundle_variables(const std::string& install_root, std::string* err);
std::string resolve_cms_base(const std::string& configured);
bool read_access_token(std::string& bearer, std::string& err);

struct DestInfo {
    bool ok = false;
    bool exists = false;
    std::int64_t mtime = 0;
};

struct CopyFilter {
    std::vector<std::string> include;
    std::vector<std::string> exclude;
    bool skip_vcs = true;
};

struct CollectFault {
    bool not_found = false;
    std::string src;
    std::string detail;
};

struct CopyNode {
    std::string src;
    std::string dest;
    bool is_dir = false;
};

struct CollectResult {
    std::vector<CopyNode> nodes;
    std::vector<CollectFault> faults;
    std::string err;
};

struct DirResult {
    bool ok = false;
    std::string err;
};

struct CopyFileResult {
    bool ok = false;
    bool cancelled = false;
    std::string err;
    std::uint64_t bytes = 0;
};

struct CopyOps {
    std::function<DestInfo(std::string_view)> dest_stat;
    std::function<std::string(std::string_view)> leaf_name;
    std::function<bool(std::string_view, bool, const CopyFilter&)> filter_accepts;
    std::function<CollectResult(std::string_view, std::string_view, const CopyFilter&)> collect_copy_at;
    std::function<DirResult(std::string_view)> ensure_dir;
    std::function<CopyFileResult(std::string_view, std::string_view, std::function<bool()>)> copy_file;
};

void set_copy_ops(CopyOps ops);
DestInfo dest_stat(std::string_view path);
std::string leaf_name(std::string_view path);
bool filter_accepts(std::string_view path, bool is_dir, const CopyFilter& filter);
CollectResult collect_copy_at(std::string_view src, std::string_view dest, const CopyFilter& filter);
DirResult ensure_dir(std::string_view path);
CopyFileResult copy_file(std::string_view src, std::string_view dest, std::function<bool()> cancel);

struct VfsProgress {
    std::uint64_t bytes_done = 0;
    std::uint64_t bytes_total = 0;
    double bytes_per_sec = 0.0;
};

struct VfsPullRequest {
    std::string remote_path;
    std::string local_root;
    std::string mount;
    std::string pattern;
    std::string remote_glob;
    bool dry_run = false;
    bool empty_list_root_is_error = false;
    std::string bearer_token;
    bool endpoint_read = false;
    bool resume = true;
    int retries = 3;
    bool skip_existing = true;
    bool overwrite = false;
    bool fail_if_exists = false;
    std::function<bool()> cancel_check;
    std::function<void(const std::string& remote, const std::string& local)> on_file;
    std::function<void(std::string_view line)> log;
    std::function<void(const VfsProgress&)> on_progress;
};

struct VfsPulledFile {
    bool ok = false;
    bool skipped = false;
    std::string local_path;
};

struct VfsPullResult {
    bool ok = false;
    std::string err;
    int files_ok = 0;
    int files_skipped = 0;
    std::uint64_t bytes_written = 0;
    std::vector<VfsPulledFile> files;
};

struct VfsUploadResult {
    bool ok = false;
    std::string err;
};

using PullVfsFn = std::function<VfsPullResult(const std::string& base, VfsPullRequest req)>;
using UploadVfsFn = std::function<VfsUploadResult(const std::string& base,
                                                  const std::string& bearer,
                                                  const std::string& local_file,
                                                  const std::string& mount,
                                                  const std::string& remote_path)>;

void set_pull_vfs(PullVfsFn fn);
void set_upload_vfs(UploadVfsFn fn);
VfsPullResult pull_vfs(const std::string& base, VfsPullRequest req);
VfsUploadResult upload_vfs(const std::string& base,
                           const std::string& bearer,
                           const std::string& local_file,
                           const std::string& mount,
                           const std::string& remote_path);

struct ShellRun {
    bool ok = false;
    std::string error;
    std::string stdout_text;
    std::string stderr_text;
    int exit_code = 1;
    bool timed_out = false;
    bool cancelled = false;
};

using RunShellFn = std::function<ShellRun(const std::string& command,
                                          const std::string& shell,
                                          int timeout_ms,
                                          const std::string& cwd)>;

void set_run_shell(RunShellFn fn);
ShellRun run_shell(const std::string& command,
                   const std::string& shell,
                   int timeout_ms,
                   const std::string& cwd);

} // namespace pm::installer::host
