#pragma once
//
// pm::security — Sandbox configuration presets.
//
// Named presets encapsulate the right combination of flags, capabilities,
// and standard path grants for common sidecar/MCP tool categories.
//
// Usage:
//   SandboxPresetContext ctx;
//   ctx.binDir     = "/path/to/dist/win-x64/bin";
//   ctx.distDir    = "/path/to/dist/win-x64";            // self preset
//   ctx.roamingDir = "%APPDATA%/PolyMech/pm-image";       // self preset
//   ctx.cwd        = "/path/to/workspace";
//   ctx.cacheDir   = std::filesystem::temp_directory_path().string();
//
//   SandboxSpawnOptions opts;
//   bool ok = resolve_preset("offline", ctx, opts);
//   opts.run  = ctx.binDir + "/ruff.exe";
//   opts.args = {"--version"};
//   backend.spawn(opts);
//
// Individual flags/paths added after resolve_preset() take precedence;
// the preset only fills in defaults (it never overwrites non-empty fields).
//
// For the "self" preset, ctx.capsOverride replaces the default full-capability
// set when non-empty. This lets callers restrict the self sandbox to a subset
// of capabilities without losing the other self-preset grants.
//
// Built-in preset names:
//   offline  — linters/formatters: no network, exec+rw on bin+cwd
//   fetch    — package managers: internetClient, scratch+cache
//   run      — general code: no network default, scratch, exec+rw on bin+cwd
//   strict   — untrusted MCP servers: LPAC + no network + no sub-spawn + no Win32k
//   self     — the app itself inside AC: all network caps, dist+bin+roaming+userPaths
//

#include "security/backends/SandboxBackend.hpp"
#include <string>
#include <vector>

namespace pm::security {

struct SandboxPresetContext {
    // ── Common ────────────────────────────────────────────────────────────────
    std::string binDir;    // absolute path to sidecar binary dir (dist/win-x64/bin)
    std::string cwd;       // working directory for the sandboxed process
    std::string cacheDir;  // writable cache dir for package downloads ($TEMP by default)

    // ── self preset ───────────────────────────────────────────────────────────
    std::string distDir;    // app install dir (dist/win-x64): exec+read grant for all DLLs
    std::string roamingDir; // settings profile dir (%APPDATA%\PolyMech\pm-image): read-write grant
    std::vector<std::string> userPaths;   // user-defined additional paths, granted read-write
    std::vector<std::string> capsOverride; // if non-empty: replaces self preset's default caps
                                           // (default: internetClient + internetClientServer
                                           //           + privatenetworkClientServer)
};

// Resolve a named preset into a SandboxSpawnOptions baseline.
// Preset fills in flags and standard paths; caller overlays run/args/moniker afterwards.
// Returns false when the name is not a known built-in preset.
bool resolve_preset(const std::string& name,
                    const SandboxPresetContext& ctx,
                    SandboxSpawnOptions& out);

// Canonical preset name constants.
constexpr const char* k_preset_offline = "offline";
constexpr const char* k_preset_fetch   = "fetch";
constexpr const char* k_preset_run     = "run";
constexpr const char* k_preset_strict  = "strict";
constexpr const char* k_preset_self    = "self";

} // namespace pm::security
