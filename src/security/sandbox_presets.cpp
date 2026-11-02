//
// pm::security — Sandbox configuration presets.
//
// See sandbox_presets.hpp for design intent and usage.
//

#include "security/sandbox_presets.hpp"

namespace pm::security {

namespace {

// Helper: append a path grant if the path string is non-empty.
// Presets grant dirs whose pre-existing files must be readable/executable
// (bin/dist DLLs, sources, caches), so they default to ImmediateFiles.
void add_path(SandboxSpawnOptions& opts,
              const std::string& path,
              const std::string& access,
              GrantPropagation propagation = GrantPropagation::ImmediateFiles,
              bool deleteOnRevoke = false) {
    if (!path.empty())
        opts.paths.push_back({path, access, propagation, deleteOnRevoke});
}

// Default capability set for the "self" preset: full network stack.
// Covers outbound internet, local listen sockets, and LAN/VPN access.
// Mirrors what a native (non-sandboxed) app expects from the OS network layer.
const std::vector<std::string> k_self_default_caps = {
    "internetClient",           // outbound TCP/UDP to internet addresses
    "internetClientServer",     // server: bind a port for internet-facing connections
    "privatenetworkClientServer", // LAN / VPN: local network access
};

} // namespace

bool resolve_preset(const std::string& name,
                    const SandboxPresetContext& ctx,
                    SandboxSpawnOptions& out) {
    out = {};

    // ── offline ───────────────────────────────────────────────────────────────
    // Linters, formatters, static analysis (ruff, ty, mypy, eslint):
    //   • No network: the tool must not phone home. No capabilities granted.
    //   • Child processes ALLOWED: tools like ruff use combase.dll / netapi32.dll
    //     during runtime init which internally may create sub-processes; blocking
    //     that is too aggressive here. Use strict if sub-spawn must be prevented.
    //   • bin/ exec grant: load the binary and its imported DLLs.
    //   • cwd read-write: tool reads sources and may write fix patches in-place.
    if (name == k_preset_offline) {
        add_path(out, ctx.binDir, "exec");
        add_path(out, ctx.cwd,    "read-write");
        return true;
    }

    // ── fetch ─────────────────────────────────────────────────────────────────
    // Package managers on first run (uvx, uv pip install, npm install, pip):
    //   • internetClient: outbound TCP to registries (PyPI, npm, …).
    //   • Child processes allowed: package managers sub-spawn compilers/scripts.
    //   • scratch dir: isolated writable temp for partial downloads; deleted on exit.
    //   • cache dir read-write: share the OS-level package cache across runs.
    //   • cwd read-write: write lock-files, venvs, node_modules.
    if (name == k_preset_fetch) {
        out.capabilities.push_back("internetClient");
        out.createScratchDir = true;
        add_path(out, ctx.binDir,   "exec");
        add_path(out, ctx.cwd,      "read-write");
        add_path(out, ctx.cacheDir, "read-write");
        return true;
    }

    // ── run ───────────────────────────────────────────────────────────────────
    // General code execution (node scripts, Python, shell):
    //   • No network by default: caller adds "internetClient" if the script needs it.
    //   • Child processes allowed: scripts commonly sub-spawn utilities.
    //   • scratch dir: isolated temp; deleted after exit.
    //   • cwd read-write: script can write output files in the workspace.
    if (name == k_preset_run) {
        out.createScratchDir = true;
        add_path(out, ctx.binDir, "exec");
        add_path(out, ctx.cwd,    "read-write");
        return true;
    }

    // ── strict ────────────────────────────────────────────────────────────────
    // Untrusted third-party MCP servers or high-risk tools:
    //   • LPAC: Less-Privileged AppContainer for maximum kernel-level isolation.
    //   • No network: must be explicitly opted in per-tool via capabilities.
    //   • No child processes: prevents spawning less-contained sub-processes.
    //   • Win32k lockdown: no GUI calls; reduces kernel attack surface.
    //   • bin/ exec only: cwd is NOT pre-granted; caller must add explicit scopes.
    if (name == k_preset_strict) {
        out.lpac           = true;
        out.noChildProcess = true;
        out.noWin32k       = true;
        add_path(out, ctx.binDir, "exec");
        // cwd intentionally omitted: strict mode requires explicit path grants
        return true;
    }

    // ── self ──────────────────────────────────────────────────────────────────
    // The app's own binary running inside an AppContainer — e.g. a sandboxed
    // sidecar of pm-image itself or a full pm-image worker process:
    //
    //   • Capabilities: full network stack by default.
    //       ctx.capsOverride replaces the default set when non-empty, so callers
    //       can restrict to a subset (e.g. internetClient only) without losing
    //       the other preset grants.
    //   • distDir exec: grants read + execute on the whole dist directory so all
    //       DLLs (libvips, llama, ggml, …) can be loaded from their install path.
    //   • binDir exec: sidecar executables (uv, ruff, node, …).
    //   • roamingDir read-write: settings profile (%APPDATA%\PolyMech\pm-image),
    //       sessions, grants, layout — everything the app needs to read/write.
    //   • scratch dir: isolated temp for any ephemeral output.
    //   • userPaths read-write: caller-supplied workspace / data directories.
    if (name == k_preset_self) {
        // Capabilities: caller-override or full default set
        const auto& caps = ctx.capsOverride.empty() ? k_self_default_caps : ctx.capsOverride;
        for (const auto& c : caps)
            out.capabilities.push_back(c);

        out.createScratchDir = true;

        // Grant the full install directory so all bundled DLLs are loadable.
        add_path(out, ctx.distDir,    "exec");
        // Grant the bin directory separately (same or child dir — idempotent if same).
        if (!ctx.binDir.empty() && ctx.binDir != ctx.distDir)
            add_path(out, ctx.binDir, "exec");
        // Settings profile: the sandboxed binary must read/write its own config.
        add_path(out, ctx.roamingDir, "read-write");
        // User-defined paths (workspaces, model dirs, export targets, …).
        for (const auto& p : ctx.userPaths)
            add_path(out, p, "read-write");

        return true;
    }

    return false;
}

} // namespace pm::security
