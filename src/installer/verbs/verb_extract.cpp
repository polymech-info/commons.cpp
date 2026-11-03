#if defined(FEATURE_INSTALLER_EXTRACT) && FEATURE_INSTALLER_EXTRACT

#include "installer/verb.hpp"
#include "installer/verbs/register_verbs.hpp"

#include "fs/zip_store.hpp"
#include "logging/pm_log.hpp"

#include <filesystem>

namespace pm::installer {

namespace {

class ExtractVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "extract"; }

    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        if (!ctx.package) {
            result.ok          = false;
            result.error       = "internal: missing package context";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        namespace fs = std::filesystem;
        const fs::path source = ctx.source_path;
        const fs::path target = ctx.target_path;

        std::error_code ec;
        if (!fs::is_regular_file(source, ec)) {
            result.ok          = false;
            result.error       = "extract: source is not a regular file: " + source.string();
            result.error_class = ErrorClass::Permanent;
            return;
        }

        pm::log::info_lazy("installer", [&]{
            return std::string("extract: ") + source.string() + " -> " + target.string();
        });

        if (ctx.package->clear && !ctx.dry_run) {
            fs::remove_all(target, ec);
            ec.clear();
        }

        if (ctx.dry_run)
            return;

        std::string err;
        if (!media::zip_store::extract_stored_zip(source, target, err)) {
            result.ok          = false;
            result.error       = err.empty() ? "extract failed" : err;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        std::uint64_t bytes = 0;
        for (fs::recursive_directory_iterator it(target, fs::directory_options::skip_permission_denied, ec), end;
             it != end; it.increment(ec)) {
            if (ec)
                break;
            if (ctx.should_abort && ctx.should_abort() != AbortReason::None) {
                result.ok          = false;
                result.error       = "cancelled";
                result.error_class = ErrorClass::Transient;
                return;
            }
            if (!it->is_regular_file(ec)) {
                ec.clear();
                continue;
            }
            const fs::path abs = it->path();
            const fs::path rel = fs::relative(abs, target, ec);
            if (ec || rel.empty()) {
                ec.clear();
                continue;
            }
            const std::string rel_u8 = rel.generic_string();
            if (ctx.events && ctx.events->on_file)
                ctx.events->on_file(ctx.package->id, rel_u8);
            pm::log::trace_lazy("installer", [&]{ return "extract: " + rel_u8; });
            result.written_files.push_back(abs.string());
            ++result.files_copied;
            bytes += static_cast<std::uint64_t>(it->file_size(ec));
            ec.clear();
        }
        result.bytes_written = bytes;
    }
};

} // namespace

void register_extract_verb(VerbRegistry& reg)
{
    reg.register_verb(std::make_unique<ExtractVerb>());
}

} // namespace pm::installer

#endif
