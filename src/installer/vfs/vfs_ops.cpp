#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS

#include "installer/vfs/vfs_ops.hpp"

#include "installer/host.hpp"
#include "installer/resolve.hpp"

#include "logging/pm_log.hpp"

#include <algorithm>
#include <filesystem>
#include <sstream>

namespace pm::installer::vfs_ops {

namespace fs = std::filesystem;
namespace host = pm::installer::host;

namespace {

std::string clean_remote(std::string p)
{
    while (!p.empty() && (p.front() == '/' || p.front() == '\\'))
        p.erase(p.begin());
    while (!p.empty() && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    for (char& c : p)
        if (c == '\\')
            c = '/';
    return p;
}

std::string strip_slashes(std::string p)
{
    for (char& c : p)
        if (c == '\\')
            c = '/';
    while (!p.empty() && p.front() == '/')
        p.erase(p.begin());
    while (!p.empty() && p.back() == '/')
        p.pop_back();
    return p;
}

void map_on_exist(OnExist on_exist, host::VfsPullRequest& opts)
{
    switch (on_exist) {
    case OnExist::Overwrite:
        opts.skip_existing = false;
        opts.overwrite     = true;
        opts.fail_if_exists = false;
        break;
    case OnExist::Error:
        opts.skip_existing  = false;
        opts.overwrite      = false;
        opts.fail_if_exists = true;
        break;
    case OnExist::UpdateIfNewer:
    case OnExist::Skip:
    default:
        opts.skip_existing  = true;
        opts.overwrite      = false;
        opts.fail_if_exists = false;
        break;
    }
}

std::string trim_trailing_slash(std::string s)
{
    while (!s.empty() && (s.back() == '/' || s.back() == '\\'))
        s.pop_back();
    return s;
}

} // namespace

bool resolve_service(const VerbContext& ctx, std::string& base, std::string& bearer, std::string& err,
                     const bool require_auth)
{
    err.clear();
    base = ctx.vfs_server.empty() ? ctx.service_server_url : ctx.vfs_server;
    base = trim_trailing_slash(base);
    if (base.empty()) {
        err = "DEFAULT_VFS_SERVER not configured (installer --config JSON)";
        return false;
    }
    bearer = ctx.service_bearer;
    if (bearer.empty()) {
        std::string aerr;
        host::read_access_token(bearer, aerr);
        if (require_auth && bearer.empty()) {
            err = "auth_required: " + (aerr.empty() ? "missing bearer token" : aerr);
            return false;
        }
    }
    return true;
}

bool pull_to_local(const VerbContext& ctx, PackageResult& result)
{
    if (!ctx.package) {
        result.ok          = false;
        result.error       = "internal: missing package context";
        result.error_class = ErrorClass::Permanent;
        return false;
    }

    std::string base, bearer, err;
    if (!resolve_service(ctx, base, bearer, err, false)) {
        result.ok          = false;
        result.error       = err;
        result.error_class = ErrorClass::Permanent;
        return false;
    }

    const std::string mount = ctx.vfs_mount.empty()
        ? (ctx.package->source.mount.empty() ? "home" : ctx.package->source.mount)
        : ctx.vfs_mount;
    const std::string remote_pattern = clean_remote(ctx.source_path);
    const std::string list_root      = ctx.source_globbed ? clean_remote(glob_path_prefix(remote_pattern))
                                                          : remote_pattern;

    std::error_code ec;
    if (!ctx.dry_run)
        fs::create_directories(fs::path(ctx.target_path), ec);

    const char* log_prefix = ctx.package->verb == "copy" ? "copy(vfs)" : "vfs_pull";
    const PackageVfsDownload& vd = ctx.package->vfs_download;
    const bool show_progress     = vd.progress_set ? vd.progress : true;

    host::VfsPullRequest popts;
    popts.remote_path              = list_root;
    popts.local_root               = ctx.target_path;
    popts.mount                    = mount;
    popts.pattern                  = ctx.package->source.pattern;
    popts.remote_glob              = ctx.source_globbed ? strip_slashes(remote_pattern) : std::string{};
    popts.dry_run                  = ctx.dry_run;
    popts.empty_list_root_is_error = true;
    popts.bearer_token             = bearer;
    popts.endpoint_read            = vd.endpoint_set && vd.endpoint == "read";
    popts.resume                   = vd.resume_set ? vd.resume : true;
    popts.retries                  = vd.retries_set ? std::max(0, vd.retries) : 3;
    map_on_exist(ctx.package->on_exist, popts);

    if (ctx.should_abort) {
        popts.cancel_check = [&ctx] {
            return ctx.should_abort && ctx.should_abort() != AbortReason::None;
        };
    }

    const std::string pkg_id = ctx.package->id;
    popts.on_file = [&](const std::string& remote, const std::string& local) {
        pm::log::trace_lazy("installer", [&] {
            return std::string(log_prefix) + ": " + remote + " -> " + local;
        });
        if (ctx.events && ctx.events->on_file)
            ctx.events->on_file(pkg_id, fs::path(local).filename().string());
    };

    popts.log = [log_prefix](std::string_view line) {
        pm::log::debug("installer", std::string(log_prefix) + " " + std::string(line));
    };

    if (show_progress) {
        popts.on_progress = [log_prefix](const host::VfsProgress& p) {
            std::ostringstream oss;
            oss << "progress bytes=" << p.bytes_done;
            if (p.bytes_total > 0)
                oss << "/" << p.bytes_total;
            if (p.bytes_per_sec > 0.0)
                oss << " rate=" << static_cast<long long>(p.bytes_per_sec) << " B/s";
            pm::log::info("installer", std::string(log_prefix) + " " + oss.str());
        };
    }

    const host::VfsPullResult pull = host::pull_vfs(base, std::move(popts));
    result.files_skipped = pull.files_skipped;
    result.bytes_written = pull.bytes_written;

    for (const auto& f : pull.files) {
        if (f.ok && !f.skipped)
            result.written_files.push_back(f.local_path);
    }

    if (!pull.ok) {
        result.ok          = false;
        result.error       = pull.err.empty() ? "vfs pull failed" : pull.err;
        result.error_class = pull.err.find("cancelled") != std::string::npos ? ErrorClass::Transient
                                                                             : ErrorClass::Transient;
        if (pull.err.find("already exists") != std::string::npos)
            result.error_class = ErrorClass::Permanent;
        result.files_copied = pull.files_ok;
        return false;
    }

    result.files_copied = pull.files_ok;
    result.ok           = true;
    return true;
}

} // namespace pm::installer::vfs_ops

#endif
