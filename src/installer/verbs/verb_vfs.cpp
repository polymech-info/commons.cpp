#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS

#include "installer/verb.hpp"
#include "installer/fs/fs_ops.hpp"
#include "installer/resolve.hpp"
#include "installer/vfs/vfs_ops.hpp"
#include "installer/verbs/register_verbs.hpp"

#include "installer/host.hpp"
#include "logging/pm_log.hpp"

#include <algorithm>
#include <filesystem>

namespace pm::installer {

namespace fs = std::filesystem;

namespace {

std::string join_remote(const std::string& dir, const std::string& name)
{
    if (dir.empty())
        return name;
    std::string out = dir;
    if (out.back() != '/' && out.back() != '\\')
        out.push_back('/');
    out += name;
    return out;
}

std::string clean_remote(std::string p)
{
    while (!p.empty() && (p.front() == '/' || p.front() == '\\'))
        p.erase(p.begin());
    while (!p.empty() && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    return p;
}

class VfsPullVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "vfs_pull"; }

    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        if (!ctx.package) {
            result.ok          = false;
            result.error       = "internal: missing package context";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        if (ctx.package->source.kind != SourceKind::VfsRemote) {
            result.ok          = false;
            result.error       = "vfs_pull requires source.kind vfs-remote";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        std::error_code ec;
        if (!ctx.dry_run)
            fs::create_directories(fs::path(ctx.target_path), ec);

        if (!vfs_ops::pull_to_local(ctx, result))
            result.ok = false;
    }
};

class VfsPushVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "vfs_push"; }

    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        if (!ctx.package) {
            result.ok          = false;
            result.error       = "internal: missing package context";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        if (ctx.package->target.kind != TargetKind::VfsRemote) {
            result.ok          = false;
            result.error       = "vfs_push requires target.kind vfs-remote";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        std::string base, bearer, err;
        if (!vfs_ops::resolve_service(ctx, base, bearer, err, true)) {
            result.ok          = false;
            result.error       = err;
            result.error_class = err.find("auth_required") != std::string::npos
                ? ErrorClass::Transient : ErrorClass::Permanent;
            return;
        }

        const std::string mount = ctx.package->target.mount.empty() ? "home" : ctx.package->target.mount;
        const std::string remote_dir = clean_remote(ctx.target_path);

        auto push_one = [&](const fs::path& local_path, const std::string& rel_s) -> bool {
            if (!matches_path_pattern(rel_s, ctx.package->source.pattern)) {
                ++result.files_skipped;
                return true;
            }
            std::string rel_remote = rel_s;
            std::replace(rel_remote.begin(), rel_remote.end(), '\\', '/');
            const std::string remote_path = join_remote(remote_dir, rel_remote);
            pm::log::trace_lazy("installer", [&]{
                return "vfs_push: " + local_path.string() + " -> " + mount + ":" + remote_path;
            });
            if (ctx.events && ctx.events->on_file)
                ctx.events->on_file(ctx.package->id, rel_s);
            if (ctx.dry_run) {
                ++result.files_copied;
                return true;
            }
            const host::VfsUploadResult ur
                = host::upload_vfs(base, bearer, local_path.string(), mount, remote_path);
            if (!ur.ok) {
                result.ok          = false;
                result.error       = ur.err.empty() ? "vfs upload failed" : ur.err;
                result.error_class = ErrorClass::Transient;
                return false;
            }
            ++result.files_copied;
            return true;
        };

        if (!ctx.source_files.empty()) {
            const fs::path base_path(ctx.source_rel_base.empty() ? ctx.source_path : ctx.source_rel_base);
            for (const auto& file_s : ctx.source_files) {
                if (ctx.should_abort && ctx.should_abort() != AbortReason::None) {
                    result.ok          = false;
                    result.error       = "cancelled";
                    result.error_class = ErrorClass::Transient;
                    return;
                }
                const fs::path local(file_s);
                std::error_code ec;
                fs::path rel = fs::relative(local, base_path, ec);
                if (ec || rel.empty()) {
                    ec.clear();
                    rel = local.filename();
                }
                if (!push_one(local, rel.generic_string()))
                    return;
            }
            return;
        }

        std::error_code ec;
        const fs::path src_root(ctx.source_path);
        if (!fs::exists(src_root, ec) || ec) {
            result.ok          = false;
            result.error       = "source path not found: " + ctx.source_path;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        if (fs::is_regular_file(src_root, ec) && !ec) {
            if (!push_one(src_root, src_root.filename().string()))
                return;
            return;
        }

        for (fs::recursive_directory_iterator it(src_root, ec), end; !ec && it != end; it.increment(ec)) {
            if (ctx.should_abort && ctx.should_abort() != AbortReason::None) {
                result.ok          = false;
                result.error       = "cancelled";
                result.error_class = ErrorClass::Transient;
                return;
            }
            if (!it->is_regular_file(ec) || ec) {
                ec.clear();
                continue;
            }
            fs::path rel = fs::relative(it->path(), src_root, ec);
            if (ec || rel.empty()) {
                ec.clear();
                rel = it->path().filename();
            }
            if (!push_one(it->path(), rel.generic_string()))
                return;
        }
        if (ec) {
            result.ok          = false;
            result.error       = "directory walk failed: " + ec.message();
            result.error_class = ErrorClass::Permanent;
        }
    }
};

} // namespace

void register_vfs_verbs(VerbRegistry& reg)
{
    reg.register_verb(std::make_unique<VfsPullVerb>());
    reg.register_verb(std::make_unique<VfsPushVerb>());
}

} // namespace pm::installer

#endif // FEATURE_INSTALLER_VFS
