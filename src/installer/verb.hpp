#pragma once
// installer/verb.hpp — the verb seam.  Each action the installer can take
// (copy, vfs_pull, vfs_push, extract, verify, sign, …) is an IVerb
// implementation living in its own TU under src/installer/verbs/, so verbs
// can be masked per build (CMake feature), per machine (GPO), and per run
// (--verbs globs) independently.

#include "installer/events.hpp"
#include "installer/manifest.hpp"
#include "installer/variables.hpp"

#include <functional>
#include <string>
#include <vector>

namespace pm::installer {

// Everything a verb needs to execute one package.  Paths arrive pre-resolved
// (variables expanded); verbs never resolve brand or OS paths themselves.
struct VerbContext {
    const Package* package = nullptr;
    // Resolved by resolve_source / resolve_target_path.  For VFS-remote
    // ends these hold the remote path / remote dir prefix (mount is on the
    // package source/target).
    std::string source_path;
    std::string target_path;
    // When source.path was a glob pattern, absolute local files + rel_base for
    // target layout (empty => walk source_path as a directory tree).
    std::vector<std::string> source_files;
    std::string              source_rel_base;
    bool                     source_globbed = false;

    // Files handed to a hook verb (before/after) by the engine: the parent
    // verb's produced set (PackageResult::written_files).  Hook verbs operate
    // over these, filtered by the hook's mask, resolving options per file
    // relative to source_rel_base.  Empty for a top-level verb.
    std::vector<std::string> input_files;

    const VariableMap* vars = nullptr;

    bool dry_run = false;

    // Progress sink (never null; engine passes a no-op default).
    const InstallEvents* events = nullptr;

    // Cooperative abort probe — verbs must call this between files and stop
    // when it returns anything but AbortReason::None.
    std::function<AbortReason()> should_abort;

    // Service/VFS auth (optional; vfs verbs read oauth when bearer is empty).
    std::string service_server_url;
    std::string service_bearer;

    // Populated when source.path is a vfs:// URL (per-URL host override).
    std::string vfs_server;
    std::string vfs_mount;
    bool        source_is_vfs = false;
};

class IVerb {
public:
    virtual ~IVerb() = default;

    // Canonical verb name used in manifests, masks, and GPO keys.
    virtual const char* name() const noexcept = 0;

    // Execute one package.  Fill `result` (files_copied, error,
    // error_class, …); `result.id/verb/duration_ms` are managed by the engine.
    virtual void execute(const VerbContext& ctx, PackageResult& result) = 0;
};

} // namespace pm::installer
