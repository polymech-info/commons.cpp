#pragma once
// installer/runtime.hpp — run any bundle manifest from inside the app.
//
// The CLI `installer --bundle` path stays in pm_image_cmd_installer.cpp.
// This entry fills the same variable map and service session the service
// commands use (CMS base + optional bearer), then calls execute_manifest.
// Shipped manifests live in <exe>/manifests/ (the install folder, not roaming).

#include "installer/events.hpp"
#include "installer/manifest.hpp"
#include "installer/variables.hpp"

#include <string>

namespace pm::installer {

struct ManifestRunRequest {
    /// Manifest JSON path. Relative paths resolve against install_root.
    std::string path;

    /// Empty = directory of the running executable (${INSTALL_ROOT}).
    std::string install_root;

    RunOptions options;

    /// Merged after the standard bundle map. These win.
    VariableMap variables;

    /// When true, a missing file, load error, or package failure is recorded
    /// on the result and does not throw. Manifest-level `forgiving: true`
    /// has the same effect.
    bool forgiving = false;

    /// <0: use the manifest `ttl` field. 0: always run. >0: skip window in seconds.
    std::int64_t ttl_sec = -1;
};

struct ManifestRunResult {
    bool ran = false;
    bool skipped_ttl = false;
    bool skipped_missing = false;
    std::string error;
    ManifestResult manifest;
};

/// Load and execute one manifest. Never throws.
/// A fresh TTL stamp (under ${CONFIG_DIR}/cache/manifest-ttl/) skips the run.
/// The stamp is written only after a successful execute.
ManifestRunResult run_manifest(const ManifestRunRequest& req) noexcept;

} // namespace pm::installer
