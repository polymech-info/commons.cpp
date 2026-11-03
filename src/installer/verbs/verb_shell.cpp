#if defined(FEATURE_INSTALLER_SHELL) && FEATURE_INSTALLER_SHELL

#include "installer/verb.hpp"
#include "installer/resolve.hpp"
#include "installer/verbs/register_verbs.hpp"

#include "installer/host.hpp"
#include "logging/pm_log.hpp"

namespace pm::installer {

namespace {

class ShellVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "shell"; }

    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        if (!ctx.package) {
            result.ok          = false;
            result.error       = "internal: missing package context";
            result.error_class = ErrorClass::Permanent;
            return;
        }
        if (!ctx.vars) {
            result.ok          = false;
            result.error       = "internal: missing variable map";
            result.error_class = ErrorClass::Permanent;
            return;
        }

        PackageShell action;
        std::string resolve_err;
        if (!resolve_shell_action(*ctx.package, *ctx.vars, action, &resolve_err)) {
            result.ok          = false;
            result.error       = resolve_err.empty() ? "shell: resolve failed" : resolve_err;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        pm::log::info_lazy("installer", [&]{
            return "shell: " + action.command
                 + (action.cwd.empty() ? "" : " (cwd=" + action.cwd + ")");
        });

        if (ctx.dry_run)
            return;

        const auto run = host::run_shell(
            action.command,
            action.shell.empty() ? "auto" : action.shell,
            action.timeout_ms,
            action.cwd);

        result.stdout_text = run.stdout_text;
        result.stderr_text = run.stderr_text;
        result.exit_code   = run.exit_code;
        result.timed_out   = run.timed_out;
        result.cancelled   = run.cancelled;

        if (run.ok && result.exit_code == 0)
            return;

        result.ok = false;
        if (!run.error.empty())
            result.error = run.error;
        else if (result.timed_out)
            result.error = "timeout";
        else if (result.cancelled)
            result.error = "cancelled";
        else
            result.error = "shell command failed";

        if (result.error.find("blocked") != std::string::npos
            || result.error.find("deny") != std::string::npos)
            result.error_class = ErrorClass::Permanent;
        else if (result.timed_out || result.cancelled)
            result.error_class = ErrorClass::Transient;
        else
            result.error_class = ErrorClass::Permanent;
    }
};

} // namespace

void register_shell_verb(VerbRegistry& reg)
{
    reg.register_verb(std::make_unique<ShellVerb>());
}

} // namespace pm::installer

#endif // FEATURE_INSTALLER_SHELL
