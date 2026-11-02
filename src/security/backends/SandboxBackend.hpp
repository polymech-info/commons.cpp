#pragma once
//
// pm::security — SandboxBackend: pluggable process-isolation interface.
//
// The gateway's DecisionKind::Sandbox verdict means "execute inside an isolated
// process."  Which isolation technology is used (AppContainer, WSL2, Docker, …)
// is determined by a SandboxBackend registered at startup.  The gateway and
// orchestration layers never see Win32/platform types — only this portable API.
//
// Design reference: docs/security/security.md § "Sandbox backends"
// Implementation: src/security/backends/win/SandboxAppContainer.hpp/.cpp
//

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pm::security {

// Live stdout/stderr delivery during spawn(). stream is "stdout" | "stderr".
using SandboxOutputHook = std::function<void(const std::string& stream,
                                             const std::string& chunk)>;
// Polled cooperatively while the child runs; return true to request a stop.
using SandboxCancelCheck = std::function<bool()>;

// ── Data types ────────────────────────────────────────────────────────────────

// How far a directory grant's ACE propagates. Inheritable ACEs cause the OS to
// re-propagate inherited security to existing children when the ACE is added —
// cost is O(entries) and stalls on large trees (workspace roots / node_modules).
//   NodeOnly       : inheritable ACE written to this node only (no propagation).
//                    O(1). List / traverse / create, and new children inherit
//                    write (e.g. `dir *.md > dir.md`). Existing files stay
//                    unreadable by the container.
//   ImmediateFiles : inheritable to immediate children (NO_PROPAGATE). Container
//                    can read pre-existing files in the folder. Cost O(direct kids).
//   Recursive      : fully inheritable down the whole subtree. Rare, explicit,
//                    slow/dangerous on big trees.
enum class GrantPropagation {
    NodeOnly,
    ImmediateFiles,
    Recursive,
};

struct SandboxPathGrant {
    std::string path;
    std::string access;       // "read" | "write" | "read-write" | "exec"
    // Default is the safe/fast mode: auto-grants (e.g. the run tool's cwd) must
    // never trigger subtree ACL propagation. Explicit shared-folder grants opt
    // into ImmediateFiles when they need to expose existing files.
    GrantPropagation propagation = GrantPropagation::NodeOnly;
    bool deleteOnRevoke = false;  // physically remove the directory after its ACE is revoked
};

struct SandboxPathGrantResult {
    std::string path;
    std::string access;
    bool        ok    = false;
    std::string error;
};

struct SandboxSpawnOptions {
    std::string              moniker;          // isolation domain name
    bool                     lpac           = false;  // Win32: Less-Privileged AppContainer
    bool                     noWin32k       = false;  // Win32: Win32k syscall lockdown
    bool                     noChildProcess = false;  // Win32: prevent the child from spawning sub-processes
                                                      //   (PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY /
                                                      //    PROCESS_CREATION_CHILD_PROCESS_RESTRICTED)
    bool                     retain         = false;  // keep profile/container after exit
    uint32_t                 timeoutMs   = 10000;
    std::string              run;                   // executable path/name
    std::vector<std::string> args;                  // argv (joined after run)
    std::string              cwd;                   // current directory for child
    std::vector<std::string> capabilities;          // optional capability tokens
    std::vector<SandboxPathGrant> paths;            // grant before spawn, revoke after exit

    // When true, the backend creates a unique scratch directory under %TEMP% (Win32) or
    // $TMPDIR before launch, grants it read-write to the container, and deletes it after
    // the process exits. The created path is reported in SandboxResult::scratchDir.
    bool createScratchDir = false;

    // When true (default), attempt to inject pm-sb-shim.dll into the sandboxed
    // process before resuming its main thread.  The shim patches
    // GetVolumeInformationW / GetDiskFreeSpaceExW in the EXE's IAT so that
    // shell commands like `dir`, `vol`, `tree` do not fail with
    // "Access is denied." from volume-device queries that AppContainer blocks.
    // Silently skipped when the shim DLL is not found next to the host binary.
    bool injectVolumeShim = true;

    // Lifecycle hooks (optional). When set, the backend streams output live and
    // polls for cancellation while the child runs, instead of only returning at
    // exit. Mirrors core/process_runner.hpp's RunOptions contract.
    SandboxOutputHook        onOutputChunk;         // live stdout/stderr chunks
    SandboxCancelCheck       onCancelCheck;         // cooperative stop signal
};

struct SandboxResult {
    bool        ok            = false;
    bool        launched      = false;
    bool        timedOut      = false;
    bool        cancelled     = false;   // stopped via onCancelCheck or abort
    int         exitCode      = -1;
    uint32_t    pid           = 0;
    std::string error;
    std::string stdoutText;
    std::string stderrText;
    std::string containerSid;   // platform identity string (S-1-15-2-... on Win32)
    bool        profileCreated = false;
    std::string scratchDir;     // auto-created temp scratch dir (when createScratchDir=true)
    std::vector<SandboxPathGrantResult> grantedPaths;
    std::vector<SandboxPathGrantResult> revokedPaths;
};

// ── Abstract interface ────────────────────────────────────────────────────────

class SandboxBackend {
public:
    virtual ~SandboxBackend() = default;

    // Spawn an isolated process: grant paths, launch, wait, revoke paths.
    // Caller may set opts.retain=true to keep the profile across calls.
    virtual SandboxResult spawn(const SandboxSpawnOptions& opts) = 0;

    // Grant / revoke file-system access for a named isolation domain.
    // access:  "read" | "write" | "read-write" | "exec"
    // Returns false on platform error (check error logs for details).
    virtual bool grantPath(const std::string& moniker,
                           const std::string& path,
                           const std::string& access) = 0;
    virtual bool revokePath(const std::string& moniker,
                            const std::string& path) = 0;

    // Return true if the path's ACL already grants access to the container.
    virtual bool checkAccess(const std::string& moniker,
                             const std::string& path) = 0;

    // Ensure the isolation profile exists and return its identity string.
    // On Win32 this is the AppContainer SID (S-1-15-2-...).
    // Creates the profile if it does not exist yet.
    virtual std::string containerSid(const std::string& moniker) = 0;

    // Delete the isolation profile (container / namespace / image).
    virtual bool deleteProfile(const std::string& moniker) = 0;

    // Short identifier surfaced in logs and PolicyDecision.sandboxBackend.
    virtual std::string name() const = 0;
};

} // namespace pm::security
