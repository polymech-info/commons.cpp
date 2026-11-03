#include "installer/engine.hpp"
#include "installer/journal/journal.hpp"
#include "installer/manifest.hpp"
#include "installer/resolve.hpp"
#include "installer/verb_registry.hpp"
#include "installer/verb.hpp"
#include "logging/pm_log.hpp"
#include <chrono>
#include <functional>
#include <unordered_set>

namespace pm::installer {

namespace {

using Clock = std::chrono::steady_clock;

struct DependencyState {
    std::unordered_set<std::string> stack;
    std::unordered_set<std::string> completed;
};

AbortReason check_abort(const RunOptions& opts, Clock::time_point started)
{
    if (opts.cancel && opts.cancel->load(std::memory_order_relaxed))
        return AbortReason::Cancelled;
    if (opts.timeout_ms > 0) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
        if (elapsed >= opts.timeout_ms)
            return AbortReason::TimedOut;
    }
    return AbortReason::None;
}

PackageJournalStatus result_status(const PackageResult& pr)
{
    if (pr.skip_reason == "parked")
        return PackageJournalStatus::Parked;
    if (pr.ok)
        return PackageJournalStatus::Done;
    if (pr.error_class == ErrorClass::Transient)
        return PackageJournalStatus::FailedTransient;
    return PackageJournalStatus::FailedPermanent;
}

void update_journal_pkg(JournalState& journal, const Package& pkg, const PackageResult& pr)
{
    const int attempts = journal.packages.value(pkg.id, nlohmann::json::object()).value("attempts", 0) + 1;
    journal.packages[pkg.id] = {
        {"status", journal_status_token(result_status(pr))},
        {"verb", effective_verb(pkg)},
        {"attempts", attempts},
        {"files_copied", pr.files_copied},
        {"files_skipped", pr.files_skipped},
        {"error", pr.error},
        {"error_class", error_class_token(pr.error_class)},
    };
}

ManifestResult execute_manifest_impl(const Manifest&                     manifest,
                                     const VariableMap& vars,
                                     RunOptions                          options,
                                     InstallEvents                       events,
                                     DependencyState&                    deps);

bool run_manifest_dependency(const std::string&                  dep_path,
                             const VariableMap& vars,
                             RunOptions                          options,
                             InstallEvents                       events,
                             DependencyState&                    deps,
                             std::string&                        err)
{
    if (deps.completed.count(dep_path))
        return true;

    if (deps.stack.count(dep_path)) {
        err = "dependency cycle detected: " + dep_path;
        return false;
    }

    deps.stack.insert(dep_path);

    std::string load_err;
    const auto dep_manifest = load_manifest(dep_path, &load_err);
    if (!dep_manifest) {
        deps.stack.erase(dep_path);
        err = load_err.empty() ? ("cannot load dependency manifest: " + dep_path) : load_err;
        return false;
    }

    const ManifestResult sub = execute_manifest_impl(*dep_manifest, vars, options, events, deps);
    deps.stack.erase(dep_path);

    if (!sub.ok) {
        err = "dependency manifest failed: " + dep_path;
        return false;
    }

    deps.completed.insert(dep_path);
    return true;
}

bool ensure_package_dependencies(const Package&                      pkg,
                                 const Manifest&                     parent_manifest,
                                 const VariableMap& vars,
                                 RunOptions                          options,
                                 InstallEvents                       events,
                                 DependencyState&                    deps,
                                 std::string&                        err)
{
    for (const auto& raw : pkg.dependencies_) {
        const std::string dep_path =
            resolve_manifest_dependency_path(raw, parent_manifest.manifest_path, vars, &err);
        if (dep_path.empty())
            return false;



        pm::log::trace_lazy("installer", [&]{
            return "dep: [" + pkg.id + "] " + raw + " -> " + dep_path;
        });



        if (!run_manifest_dependency(dep_path, vars, options, events, deps, err)) {
            if (err.find("dependency manifest failed") == std::string::npos
                && err.find("dependency cycle") == std::string::npos)
                err = "dependency [" + raw + "]: " + err;
            return false;
        }
    }
    return true;
}



// Run a package's before/after verb hooks in order.  Each hook is dispatched
// through the verb registry (so runtime/policy masks apply): a masked hook is
// skipped with a log note, an unknown or failing hook fails the parent package.
// `input_files` is the parent verb's produced set (empty for before hooks);
// `rel_base` is the parent target path so hook verbs can derive ${SRC_REL}.

bool run_verb_hooks(const std::vector<Package>&         hooks,
                    VerbRegistry&                       registry,
                    const std::vector<std::string>&     input_files,
                    const std::string&                  rel_base,
                    const VariableMap& vars,
                    const RunOptions&                   options,
                    InstallEvents&                      events,
                    const std::function<AbortReason()>& abort_probe,
                    std::string&                        err)
{
    for (const auto& hook : hooks) {
        const std::string hv = effective_verb(hook);
        if (!registry.is_allowed(hv, options.verb_allow_globs)) {

            pm::log::info_lazy("installer", [&]{
                return "skip hook [" + hv + "] — verb masked";
            });

            continue;
        }
        IVerb* verb = registry.find(hv);
        if (!verb) {
            err = "hook verb_unknown: " + hv;
            return false;
        }
        VerbContext hctx;
        hctx.package            = &hook;
        hctx.vars               = &vars;
        hctx.input_files        = input_files;
        hctx.source_rel_base    = rel_base;
        hctx.dry_run            = options.dry_run;
        hctx.events             = &events;
        hctx.should_abort       = abort_probe;
        hctx.service_server_url = options.service_server_url;
        hctx.service_bearer     = options.service_bearer;

        PackageResult hr;
        hr.id   = hook.id.empty() ? ("hook:" + hv) : hook.id;
        hr.verb = hv;
        verb->execute(hctx, hr);
        if (!hr.ok) {
            err = hr.error.empty() ? ("hook [" + hv + "] failed") : hr.error;
            return false;
        }
    }
    return true;
}

ManifestResult execute_manifest_impl(const Manifest&                     manifest,
                                     const VariableMap& vars,
                                     RunOptions                          options,
                                     InstallEvents                       events,
                                     DependencyState&                    deps)
{
    register_builtin_verbs();
    auto& registry = VerbRegistry::instance();

    ManifestResult result;
    const Clock::time_point started = Clock::now();
    if (options.dry_run)
        pm::log::info_lazy("installer", []{ return "dry-run mode — no files will be written"; });
    const std::string manifest_hash = manifest_content_hash(manifest);
    std::optional<JournalState> journal;
    if (!options.journal_dir.empty()) {
        journal = load_journal(options.journal_dir, manifest_hash);
        if (!journal) {
            JournalState fresh;
            fresh.manifest_hash = manifest_hash;
            fresh.manifest_path = manifest.manifest_path;
            journal = std::move(fresh);
        }
    }
    // Run manifest-level dependencies before any packages.
    for (const auto& raw_dep : manifest.dependencies_) {
        std::string dep_err;
        const std::string dep_path = resolve_manifest_dependency_path(
            raw_dep, manifest.manifest_path, vars, &dep_err);

        if (dep_path.empty() || !run_manifest_dependency(dep_path, vars, options, events, deps, dep_err)) {
            result.ok = false;
            PackageResult dep_pr;
            dep_pr.id          = raw_dep;
            dep_pr.ok          = false;
            dep_pr.error       = dep_err.empty() ? ("dependency failed: " + raw_dep) : dep_err;
            dep_pr.error_class = ErrorClass::Permanent;
            result.packages.push_back(std::move(dep_pr));
            return result;
        }
    }

    for (const auto& pkg : manifest.packages) {
        PackageResult pr;
        pr.id   = pkg.id;
        pr.verb = effective_verb(pkg);

        const auto t0 = Clock::now();

        if (const AbortReason ar = check_abort(options, started); ar != AbortReason::None) {
            result.ok        = false;
            result.cancelled = ar == AbortReason::Cancelled;
            result.timed_out = ar == AbortReason::TimedOut;
            pr.ok            = false;
            pr.error         = ar == AbortReason::TimedOut ? "timeout" : "cancelled";
            pr.error_class   = ErrorClass::Transient;
            pr.duration_ms   = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
            result.packages.push_back(std::move(pr));
            break;
        }

        if (journal && options.resume) {
            const std::string st = journal->packages.value(pkg.id, nlohmann::json::object()).value("status", "");
            if (journal_should_skip(status_from_token(st), true, options.force)) {
                pr.skip_reason = "journal";
                pr.duration_ms = 0;

                pm::log::info_lazy("installer", [&]{
                    return "skip [" + pkg.id + "] — already done in journal";
                });

                result.packages.push_back(std::move(pr));
                continue;
            }
        }

        if (!pkg.dependencies_.empty()) {
            std::string dep_err;
            if (!ensure_package_dependencies(pkg, manifest, vars, options, events, deps, dep_err)) {
                pr.ok          = false;
                pr.error       = dep_err.empty() ? "dependency failed" : dep_err;
                pr.error_class = ErrorClass::Permanent;
                pr.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
                result.ok      = false;
                result.packages.push_back(std::move(pr));
                continue;
            }
        }

        if (!constraints_satisfied(pkg.constraints)) {
            pr.skip_reason = "constraints";

            pm::log::info_lazy("installer", [&]{
                return "skip [" + pkg.id + "] — constraints not satisfied on " + std::string(current_os_token());
            });

            result.packages.push_back(std::move(pr));
            continue;
        }

        if (!registry.is_allowed(pr.verb, options.verb_allow_globs)) {
            pr.ok          = false;
            pr.error       = "verb_disabled";
            pr.error_class = ErrorClass::Permanent;
            pr.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
            result.ok      = false;
            result.packages.push_back(std::move(pr));
            continue;
        }

        IVerb* verb = registry.find(pr.verb);
        if (!verb) {
            pr.ok          = false;
            pr.error       = "verb_unknown";
            pr.error_class = ErrorClass::Permanent;
            pr.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
            result.ok      = false;
            result.packages.push_back(std::move(pr));
            continue;
        }

        std::string src_err, tgt_err;
        std::string src_path;
        std::string tgt_path;
        
        ResolvedSource src;
        const bool is_shell = (pr.verb == "shell");
        if (!is_shell) {
            if (!resolve_source(pkg, vars, src, &src_err)) {
                pr.ok          = false;
                pr.error       = "source: " + (src_err.empty() ? "resolve failed" : src_err);
                pr.error_class = ErrorClass::Permanent;
                pr.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
                result.ok      = false;
                result.packages.push_back(std::move(pr));
                continue;
            }
            src_path = src.path;
            tgt_path = resolve_target_path(pkg, vars, &tgt_err);
            if (tgt_path.empty()) {
                pr.ok          = false;
                pr.error       = "target: " + (tgt_err.empty() ? "empty path" : tgt_err);
                pr.error_class = ErrorClass::Permanent;
                pr.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
                result.ok      = false;
                result.packages.push_back(std::move(pr));
                continue;
            }
        }

        if (is_shell)
            pm::log::info_lazy("installer", [&]{ return "[" + pkg.id + "] shell"; });
        else
            pm::log::info_lazy("installer", [&]{
                return "[" + pkg.id + "] " + pr.verb + " " + src_path + " -> " + tgt_path;
            });

        if (events.on_package_start)
            events.on_package_start(pkg.id, pr.verb);

        if (journal) {
            journal->packages[pkg.id] = {
                {"status", journal_status_token(PackageJournalStatus::Running)},
                {"verb", pr.verb},
                {"attempts", journal->packages.value(pkg.id, nlohmann::json::object()).value("attempts", 0)},
            };
            std::string jerr;
            save_journal(options.journal_dir, *journal, jerr);
            append_journal_event(options.journal_dir, manifest_hash,
                                 {{"event", "pkg_start"}, {"id", pkg.id}, {"verb", pr.verb}});
        }

        VerbContext vctx;
        vctx.package            = &pkg;
        vctx.source_path        = src_path;
        vctx.target_path        = tgt_path;
        vctx.source_files       = std::move(src.files);
        vctx.source_rel_base    = std::move(src.rel_base);
        vctx.source_globbed     = src.globbed;
        vctx.source_is_vfs      = src.is_vfs;
        vctx.vfs_server         = src.vfs_server;
        vctx.vfs_mount          = src.vfs_mount;
        vctx.vars               = &vars;
        vctx.dry_run            = options.dry_run;
        vctx.events             = &events;
        vctx.service_server_url = options.service_server_url;
        vctx.service_bearer     = options.service_bearer;
        vctx.should_abort       = [&]() { return check_abort(options, started); };

        const auto abort_probe = vctx.should_abort;

        bool before_ok = true;
        if (!pkg.before_.empty()) {
            std::string hook_err;
            if (!run_verb_hooks(pkg.before_, registry, {}, src_path, vars, options, events, abort_probe, hook_err)) {
                pr.ok          = false;
                pr.error       = "before hook: " + (hook_err.empty() ? "failed" : hook_err);
                pr.error_class = ErrorClass::Permanent;
                before_ok      = false;
            }
        }

        if (before_ok) {
            verb->execute(vctx, pr);

            if (pr.ok && !pkg.after_.empty()) {
                std::string hook_err;
                if (!run_verb_hooks(pkg.after_, registry, pr.written_files, tgt_path, vars, options, events, abort_probe, hook_err)) {
                    pr.ok          = false;
                    pr.error       = "after hook: " + (hook_err.empty() ? "failed" : hook_err);
                    pr.error_class = ErrorClass::Permanent;
                }
            }
        }

        pr.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();



        if (!pr.ok && pkg.optional && pr.error.find("source path not found") != std::string::npos) {
            pm::log::info("installer", "[" + pr.id + "] skipped (optional source missing)");
            pr.ok = true;
            pr.error.clear();
        }

        if (!pr.ok) {
            result.ok = false;
            pm::log::error_lazy("installer", [&]{
                return "[" + pr.id + "] FAILED: " + pr.error;
            });
        }

        result.total_copied  += pr.files_copied;
        result.total_skipped += pr.files_skipped;
        result.packages.push_back(pr);

        if (events.on_package_done)
            events.on_package_done(pr);

        if (journal) {
            update_journal_pkg(*journal, pkg, pr);
            std::string jerr;
            save_journal(options.journal_dir, *journal, jerr);
            append_journal_event(options.journal_dir, manifest_hash,
                                 {{"event", pr.ok ? "pkg_done" : "pkg_failed"},
                                  {"id", pkg.id},
                                  {"error", pr.error},
                                  {"status", journal_status_token(result_status(pr))}});
        }
    }



    pm::log::info_lazy("installer", [&]{
        return "done — copied " + std::to_string(result.total_copied)
             + ", skipped " + std::to_string(result.total_skipped);
    });
    return result;
}

} // namespace

ManifestResult execute_manifest(const Manifest&                     manifest,
                                const VariableMap& vars,
                                RunOptions                          options,
                                InstallEvents                       events)
{
    DependencyState deps;
    return execute_manifest_impl(manifest, vars, options, events, deps);
}

} // namespace pm::installer
