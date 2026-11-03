#include "installer/verb.hpp"
#include "installer/verb_registry.hpp"
#include "installer/fs/fs_ops.hpp"
#include "installer/resolve.hpp"
#include "logging/pm_log.hpp"

#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS
#include "installer/vfs/vfs_ops.hpp"
#endif

#include <filesystem>
#include <iostream>

namespace pm::installer {

namespace {

class CopyVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "copy"; }

    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        if (!ctx.package) {
            result.ok          = false;
            result.error       = "internal: missing package context";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        if (ctx.package->type.find(":zip") != std::string::npos) {
            result.ok          = false;
            result.error       = "zip packages require verb extract (FEATURE_INSTALLER_EXTRACT)";
            result.error_class = ErrorClass::Permanent;
            return;
        }

#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS
        if (ctx.source_is_vfs) {
            namespace fs = std::filesystem;
            std::error_code ec;
            const fs::path staging = fs::temp_directory_path(ec)
                / ("pm-installer-vfs-" + ctx.package->id);
            if (!ctx.dry_run && ec) {
                result.ok          = false;
                result.error       = "staging dir failed: " + ec.message();
                result.error_class = ErrorClass::Permanent;
                return;
            }

            VerbContext pull_ctx = ctx;
            pull_ctx.target_path = staging.string();

            PackageResult pull_result;
            pull_result.id   = result.id;
            pull_result.verb = result.verb;
            if (!vfs_ops::pull_to_local(pull_ctx, pull_result)) {
                result = pull_result;
                return;
            }

            if (ctx.dry_run) {
                result.files_copied  = pull_result.files_copied;
                result.files_skipped = pull_result.files_skipped;
                result.bytes_written = pull_result.bytes_written;
                return;
            }

            std::string err;
            ErrorClass err_class = ErrorClass::None;
            fs_ops::CopyStats stats;
            const auto on_file = [&](const std::string& rel) {
                pm::log::trace_lazy("installer", [&]{ return "copy: " + rel; });
                if (ctx.events && ctx.events->on_file)
                    ctx.events->on_file(ctx.package->id, rel);
            };

            fs_ops::CopyTreeOptions copts;
            copts.source_dir   = staging.string();
            copts.target_dir   = ctx.target_path;
            copts.pattern      = ctx.package->source.pattern;
            copts.exclude      = ctx.package->source.exclude;
            copts.on_exist     = ctx.package->on_exist;
            copts.dry_run      = ctx.dry_run;
            copts.on_file      = on_file;
            copts.should_abort = ctx.should_abort;

            const bool copy_ok = fs_ops::copy_tree(copts, stats, err, err_class);

            if (!ctx.dry_run)
                fs::remove_all(staging, ec);

            if (!copy_ok) {
                result.ok            = false;
                result.error         = err;
                result.error_class   = err_class;
                result.files_copied  = stats.files_copied;
                result.files_skipped = pull_result.files_skipped + stats.files_skipped;
                result.bytes_written = stats.bytes_written;
                return;
            }

            result.files_copied  = stats.files_copied;
            result.files_skipped = pull_result.files_skipped + stats.files_skipped;
            result.bytes_written = stats.bytes_written;
            result.written_files = std::move(stats.written_files);
            return;
        }
#else
        if (ctx.source_is_vfs) {
            result.ok          = false;
            result.error       = "vfs:// sources require FEATURE_INSTALLER_VFS build";
            result.error_class = ErrorClass::Permanent;
            return;
        }
#endif

        std::string err;
        ErrorClass  err_class = ErrorClass::None;
        fs_ops::CopyStats stats;

        if (ctx.package->clear && !ctx.dry_run) {
            namespace fs = std::filesystem;
            std::error_code ec;
            fs::remove_all(fs::path(ctx.target_path), ec);
        }

        if (ctx.source_globbed && ctx.source_files.empty()) {
            result.ok = true;
            return;
        }

        const auto on_file = [&](const std::string& rel) {
            pm::log::trace_lazy("installer", [&]{ return "copy: " + rel; });
            if (ctx.events && ctx.events->on_file)
                ctx.events->on_file(ctx.package->id, rel);
        };

        if (!ctx.source_files.empty()) {
            fs_ops::CopyFilesOptions copts;
            copts.source_files = ctx.source_files;
            copts.rel_base     = ctx.source_rel_base;
            copts.target_dir   = ctx.target_path;
            copts.pattern      = ctx.package->source.pattern;
            copts.exclude      = ctx.package->source.exclude;
            copts.on_exist     = ctx.package->on_exist;
            copts.dry_run      = ctx.dry_run;
            copts.on_file      = on_file;
            copts.should_abort = ctx.should_abort;
            if (!fs_ops::copy_files(copts, stats, err, err_class)) {
                result.ok            = false;
                result.error         = err;
                result.error_class   = err_class;
                result.files_copied  = stats.files_copied;
                result.files_skipped = stats.files_skipped;
                result.bytes_written = stats.bytes_written;
                return;
            }
        } else {
            namespace fs = std::filesystem;
            std::error_code ec;
            const fs::path src(ctx.source_path);
            if (!fs::exists(src, ec) || ec) {
                result.ok          = false;
                result.error       = "source path not found: " + ctx.source_path;
                result.error_class = ErrorClass::Permanent;
                return;
            }

            if (fs::is_regular_file(src, ec) && !ec) {
                fs_ops::CopyFilesOptions copts;
                copts.source_files = { fs::absolute(src, ec).string() };
                copts.rel_base     = fs::absolute(src, ec).parent_path().string();
                copts.target_dir   = ctx.target_path;
                copts.pattern      = ctx.package->source.pattern;
                copts.exclude      = ctx.package->source.exclude;
                copts.on_exist     = ctx.package->on_exist;
                copts.dry_run      = ctx.dry_run;
                copts.on_file      = on_file;
                copts.should_abort = ctx.should_abort;
                if (!fs_ops::copy_files(copts, stats, err, err_class)) {
                    result.ok            = false;
                    result.error         = err;
                    result.error_class   = err_class;
                    result.files_copied  = stats.files_copied;
                    result.files_skipped = stats.files_skipped;
                    result.bytes_written = stats.bytes_written;
                    return;
                }
            } else {
                fs_ops::CopyTreeOptions copts;
                copts.source_dir   = ctx.source_path;
                copts.target_dir   = ctx.target_path;
                copts.pattern      = ctx.package->source.pattern;
                copts.exclude      = ctx.package->source.exclude;
                copts.on_exist     = ctx.package->on_exist;
                copts.dry_run      = ctx.dry_run;
                copts.on_file      = on_file;
                copts.should_abort = ctx.should_abort;
                if (!fs_ops::copy_tree(copts, stats, err, err_class)) {
                    result.ok            = false;
                    result.error         = err;
                    result.error_class   = err_class;
                    result.files_copied  = stats.files_copied;
                    result.files_skipped = stats.files_skipped;
                    result.bytes_written = stats.bytes_written;
                    return;
                }
            }
        }

        result.files_copied  = stats.files_copied;
        result.files_skipped = stats.files_skipped;
        result.bytes_written = stats.bytes_written;
        result.written_files = std::move(stats.written_files);
    }
};

} // namespace

void register_copy_verb(VerbRegistry& reg)
{
    reg.register_verb(std::make_unique<CopyVerb>());
}

} // namespace pm::installer

