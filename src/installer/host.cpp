#include "installer/host.hpp"

namespace pm::installer::host {
namespace {

ResolveVariablesFn g_resolve;
ApplySourceFileFn g_apply_source;
MakeBundleFn g_bundle;
CmsBaseFn g_cms_base;
ReadBearerFn g_bearer;
CopyOps g_copy;
PullVfsFn g_pull;
UploadVfsFn g_upload;
RunShellFn g_shell;

} // namespace

void set_resolve_variables(ResolveVariablesFn fn) { g_resolve = std::move(fn); }
void set_apply_source_file_variables(ApplySourceFileFn fn) { g_apply_source = std::move(fn); }
void set_make_bundle_variables(MakeBundleFn fn) { g_bundle = std::move(fn); }
void set_resolve_cms_base(CmsBaseFn fn) { g_cms_base = std::move(fn); }
void set_read_access_token(ReadBearerFn fn) { g_bearer = std::move(fn); }

std::string resolve_variables(const std::string& raw, const VariableMap& vars, std::string* err)
{
    if (!g_resolve) {
        if (err)
            *err = "variable expansion is not installed";
        return {};
    }
    return g_resolve(raw, vars, err);
}

void apply_source_file_variables(VariableMap& vars,
                                 const std::string& source_file,
                                 const std::string& cwd,
                                 const std::string& rel_base)
{
    if (g_apply_source)
        g_apply_source(vars, source_file, cwd, rel_base);
}

VariableMap make_bundle_variables(const std::string& install_root, std::string* err)
{
    if (!g_bundle) {
        if (err)
            *err = "bundle variable map is not installed";
        return {};
    }
    return g_bundle(install_root, err);
}

std::string resolve_cms_base(const std::string& configured)
{
    if (!g_cms_base)
        return configured;
    return g_cms_base(configured);
}

bool read_access_token(std::string& bearer, std::string& err)
{
    if (!g_bearer) {
        err = "oauth token store is not installed";
        return false;
    }
    return g_bearer(bearer, err);
}

void set_copy_ops(CopyOps ops) { g_copy = std::move(ops); }

DestInfo dest_stat(std::string_view path)
{
    if (!g_copy.dest_stat)
        return {};
    return g_copy.dest_stat(path);
}

std::string leaf_name(std::string_view path)
{
    if (!g_copy.leaf_name)
        return {};
    return g_copy.leaf_name(path);
}

bool filter_accepts(std::string_view path, bool is_dir, const CopyFilter& filter)
{
    if (!g_copy.filter_accepts)
        return false;
    return g_copy.filter_accepts(path, is_dir, filter);
}

CollectResult collect_copy_at(std::string_view src, std::string_view dest, const CopyFilter& filter)
{
    if (!g_copy.collect_copy_at) {
        CollectResult missing;
        missing.err = "vfs copy is not installed";
        return missing;
    }
    return g_copy.collect_copy_at(src, dest, filter);
}

DirResult ensure_dir(std::string_view path)
{
    if (!g_copy.ensure_dir) {
        DirResult missing;
        missing.err = "vfs copy is not installed";
        return missing;
    }
    return g_copy.ensure_dir(path);
}

CopyFileResult copy_file(std::string_view src, std::string_view dest, std::function<bool()> cancel)
{
    if (!g_copy.copy_file) {
        CopyFileResult missing;
        missing.err = "vfs copy is not installed";
        return missing;
    }
    return g_copy.copy_file(src, dest, std::move(cancel));
}

void set_pull_vfs(PullVfsFn fn) { g_pull = std::move(fn); }
void set_upload_vfs(UploadVfsFn fn) { g_upload = std::move(fn); }

VfsPullResult pull_vfs(const std::string& base, VfsPullRequest req)
{
    if (!g_pull) {
        VfsPullResult missing;
        missing.err = "vfs pull is not installed";
        return missing;
    }
    return g_pull(base, std::move(req));
}

VfsUploadResult upload_vfs(const std::string& base,
                           const std::string& bearer,
                           const std::string& local_file,
                           const std::string& mount,
                           const std::string& remote_path)
{
    if (!g_upload) {
        VfsUploadResult missing;
        missing.err = "vfs upload is not installed";
        return missing;
    }
    return g_upload(base, bearer, local_file, mount, remote_path);
}

void set_run_shell(RunShellFn fn) { g_shell = std::move(fn); }

ShellRun run_shell(const std::string& command,
                   const std::string& shell,
                   int timeout_ms,
                   const std::string& cwd)
{
    if (!g_shell) {
        ShellRun missing;
        missing.error = "shell runner is not installed";
        return missing;
    }
    return g_shell(command, shell, timeout_ms, cwd);
}

} // namespace pm::installer::host
