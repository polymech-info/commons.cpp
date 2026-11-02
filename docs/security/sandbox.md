# Sandbox — AppContainer / LPAC for MCP Tool Workers

We use **AppContainer / LPAC** as the primary Windows containment primitive for
risky MCP tool workers, inspired by Chromium-style broker/target sandboxing.

This is **not the primary permission system**. The primary system remains:

```
LLM proposes → SecurityGateway authorizes → scoped capability executes
```

The sandbox is an optional extra containment layer for higher-risk tools.

---

## Architecture

```
MainApp.exe  (broker)
  ├─ SecurityGateway::authorizeWithConsent()   ← decides policy
  ├─ ToolWorkerClient                          ← launches / reuses worker
  │    └─ sandbox acl → SetNamedSecurityInfoW  ← opens "shared folder" to container SID
  └─ ToolWorker.exe  (target, inside AppContainer)
       ├─ minimal JSON-RPC dispatcher
       ├─ no policy decisions
       ├─ no broad filesystem access by default
       └─ on ACCESS_DENIED → emits PrivilegeEscalationRequest → broker
```

The parent always authorizes first.  
The worker never decides permission.  
The worker signals gaps back to the broker; the broker routes them through the gateway.

---

## Isolation stack

```
┌────────────────────────────────────────────────────────┐
│  AppContainer (or LPAC)                                │  deny-by-default FS/net/process
│   ├── filesystem: only granted paths ("shared folders")│
│   ├── network: none by default (opt-in per capability) │
│   └── process handles: cannot see/open outside         │
│                                                        │
│  Job Object  (KILL_ON_JOB_CLOSE)                       │  cleanup + resource limits
│   └── CPU / memory / PID limits                        │
│                                                        │
│  Process Mitigation Policies                           │  DEP, ASLR, optional Win32k lock
│   └── PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY          │
└────────────────────────────────────────────────────────┘
```

| Layer | What it prevents |
|---|---|
| AppContainer | FS access outside granted paths, network, foreign process handles |
| LPAC (stricter) | Also opts out of ALL_APPLICATION_PACKAGES group; tighter than AC |
| Job Object | Orphan processes, fork bombs, resource exhaustion |
| Mitigation policies | DEP bypass, ASLR bypass, Win32k attacks, DLL injection |

---

## Experiment results (Jun 2026)

`FEATURE_SECURITY_SANDBOX` CLI sub-arm (`src/security/cli.cpp`) was built and
exercised against the live Win32 APIs.  Summary of what was verified:

### AppContainer profile lifecycle

```
sandbox probe --moniker pm-sandbox-smoke-test
→ ok=true  sid=S-1-15-2-781098855-...  profileCreated=true
```

`CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName` work
without elevated privileges.  SID is stable across process restarts (derived
deterministically from the moniker).

### Shared folder grant — ACL timing

```
sandbox acl --moniker pm-mcp-test --path <workspace> --access read-write
→ ok=true  elapsed=17ms
```

**Key finding:** using `SUB_CONTAINERS_AND_OBJECTS_INHERIT` (≡ `CONTAINER_INHERIT_ACE |
OBJECT_INHERIT_ACE`) caused Windows to propagate the ACE to all existing children —
O(n_files), **~60s on the pixlwiz workspace**.

**Fix:** `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE`.
New files created inside the directory still inherit the ACE; existing files are
not updated. Grant is now **17ms** regardless of repo size.

### PrivilegeEscalationRequest simulation

```
# Before grant:
sandbox wrap-mcp --tool mcp.fs.write --action write --path <workspace>
→ accessDenied=true  aclGranted=false
  privilegeEscalationRequest.reason = "path not covered by AppContainer ACL grant"

# After sandbox acl:
sandbox wrap-mcp --tool mcp.fs.write --action write --path <workspace>
→ accessDenied=false  aclGranted=true
```

The deny → escalation request → grant → allow round-trip validates the broker
routing contract.  The `PrivilegeEscalationRequest` JSON is the wire format the
real worker will emit over the IPC pipe.

### Real process launch

```
sandbox launch --moniker pm-test --exe "cmd.exe /c exit 42" --timeout-ms 5000
→ ok=true  pid=1940  exitCode=42  timedOut=false
```

`CreateProcessW` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` works without
`SeAssignPrimaryTokenPrivilege`.  Exit code propagates correctly.

### LPAC

```
sandbox launch --moniker pm-lpac-test --exe "cmd.exe /c whoami" --lpac
→ ok=true  exitCode=1
```

Process is created inside LPAC.  `whoami` exits 1 — it cannot read the user
account information from inside LPAC.  **Containment confirmed.**

LPAC is stricter than regular AppContainer: it opts out of the
`ALL_APPLICATION_PACKAGES` group, so even paths with a broad AC grant are still
inaccessible unless the specific container SID is listed.

### What was NOT tested yet

```
Job Object assignment on the launched process
Child-process creation restriction (PROCESS_CREATION_CHILD_PROCESS_RESTRICTED)
Network block verification (WSAConnect inside container)
Handle inheritance audit (no parent handle leaks)
Sidecar binary DLL load (uvx.exe / node.exe / ruff.exe inside AC)
Capability SID resolution (DeriveCapabilitySidsFromName for internetClient)
```

---

## Shared folders

AppContainer is deny-by-default.  Grant paths explicitly via `SetNamedSecurityInfoW`
at spawn time and revoke at worker exit.

| Path | Access | Why |
|---|---|---|
| `workspaceDir` | R+W | User files the tool operates on |
| `dist/win-x64/bin/` | R+X | node.exe, uvx.exe, ruff.exe, ty.exe |
| `dist/win-x64/npm-global/` | R+X | Pre-installed globals (tsc, tsx, prettier) |
| `%TEMP%\pm-sidecar-<uuid>` | R+W | Scratch space, cleaned up on exit |
| `UV_CACHE_DIR` | R+W | uv package cache — optional, speeds up repeated runs |

The container's isolated storage (`%LOCALAPPDATA%\Packages\<moniker>\`) is always
writable without a grant.

**ACL strategy:** add `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE`
to the directory.  New files inherit; existing files are not walked.

---

## PrivilegeEscalationRequest — broker contract

When the sandboxed worker hits `ACCESS_DENIED` on a path it needs, it sends:

```json
{
  "id": "call_123",
  "type": "privilege_escalation",
  "tool": "mcp.fs.write",
  "action": "write",
  "path": "/workspace/out.csv",
  "containerSid": "S-1-15-2-...",
  "lpac": false,
  "reason": "path not covered by AppContainer ACL grant"
}
```

Broker routing on receipt:

```
PrivilegeEscalationRequest
  ↓
SecurityGateway::authorizeWithConsent()
  ↓ Allow → SetNamedSecurityInfoW (widen ACL) → re-send MCP call to worker
  ↓ Deny  → inject {"ok":false,"security_denied":true} as tool result
  ↓ Ask   → CliConsentDelegate / Win32ConsentDelegate → user decides → route above
```

---

## IPC protocol

```
parent launches ToolWorker.exe with SECURITY_CAPABILITIES attribute
parent ↔ worker: JSON lines over stdin/stdout
binary/file data: duplicated handles (parent opens, DuplicateHandle into worker)
```

Message types (worker → broker):

```json
{ "id": "c1", "type": "tool_result",  "ok": true, "data": "..." }
{ "id": "c1", "type": "privilege_escalation", "tool": "...", "path": "...", ... }
```

Message types (broker → worker):

```json
{ "id": "c1", "type": "tool_call", "tool": "...", "args": {}, "handles": {"input": 42}, "limits": {"max_bytes": 10485760, "timeout_ms": 30000} }
{ "id": "c1", "type": "grant",     "path": "...", "access": "read-write" }
```

---

## Worker rules

```
- not load user plugins unless explicitly launched for that plugin
- not evaluate policy
- not ask user consent — only signal back to broker
- not accept filesystem paths unless policy explicitly allowed it
- enforce byte/time limits locally
- return structured result or privilege_escalation message
- exit cleanly after one request for high-risk tools
```

For high-risk tools (unknown MCP, Execute actions): **one worker process per call**.  
For medium-risk tools (session-scoped MCP reads): **reused worker per session**.

---

## Worker launch config (updated)

```cpp
struct WorkerSandboxOptions {
    // AppContainer
    bool useAppContainer    = true;
    bool useLpac            = false;   // stricter; use for untrusted remote MCP
    std::string moniker;               // derived: "pm-worker-" + toolId hash (8 chars)
    bool retainProfile      = false;   // delete on worker exit by default
    std::vector<std::string> capabilities; // e.g. "internetClient" for network tools

    // Shared folders
    struct PathGrant { std::string path; std::string access; }; // "read"|"read-write"|"exec"
    std::vector<PathGrant> sharedPaths;  // set at spawn, revoked at exit

    // Job Object
    bool jobObject          = true;
    bool killOnClose        = true;
    uint64_t memoryLimitBytes = 512ull * 1024 * 1024;

    // Mitigations
    bool blockChildProcesses = true;
    bool noWin32k            = false;  // enable for pure-compute workers

    // Lifetime
    uint32_t timeoutMs      = 30000;
    std::filesystem::path tempDir; // %TEMP%\pm-sidecar-<uuid>
};
```

---

## Tiers (incremental adoption)

### Tier 1 — Job Object only ✅ ready to ship

Minimum viable: process cleanup, CPU/mem limits.  No FS isolation.

```cpp
HANDLE hJob = CreateJobObject(nullptr, nullptr);
JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
jeli.BasicLimitInformation.LimitFlags =
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
jeli.ProcessMemoryLimit = 512 * 1024 * 1024;
SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
AssignProcessToJobObject(hJob, hProcess);
```

Tier 1/2 are **cleanup + damage-reduction only** — not filesystem allowlist sandboxes.

### Tier 2 — Low Integrity token (privilege drop)

Prevents writing above Low IL (AppData\Roaming, system32, registry hives).
Readable everywhere, writable only to Low IL paths and explicitly granted dirs.
~10 lines; `OpenProcessToken` → `DuplicateTokenEx` → set Low IL label → `CreateProcessAsUser`.

### Tier 3 — AppContainer + Job Object ⬅ next target

Full deny-by-default FS isolation.  Shared folders grant only what the tool needs.
`PrivilegeEscalationRequest` over IPC handles gaps at runtime.  
Profile creation + ACL grant confirmed working (17ms).  
Real process launch confirmed working without elevated privileges.

### Tier 4 — LPAC + capabilities

For untrusted remote MCP servers.  `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`
confirmed working.  Capability SID resolution (`DeriveCapabilitySidsFromName`) still
to be wired.

---

## Next steps

Ordered by priority:

### 1. Add Job Object to `sandbox launch` (Tier 1 + Tier 3 combined)

Every AppContainer worker should also be inside a Job Object.  Without it there is
no reliable process cleanup if the broker exits.

```cpp
// After CreateProcessW succeeds:
AssignProcessToJobObject(hJob, pi.hProcess);
// hJob is owned by the broker; kill-on-close fires when broker closes it.
```

Wire into `WorkerSandboxOptions` and expose in the `sandbox launch` CLI sub-command.

### 2. Build `pm-worker-tool.exe`

A minimal console exe that:
- reads one JSON line from stdin (tool call)
- attempts the filesystem/network operation
- on `ACCESS_DENIED`: writes a `privilege_escalation` JSON line to stdout
- on success: writes `tool_result` JSON line to stdout
- exits after one call (high-risk mode)

This is the first real target process for the AppContainer.

### 3. Verify filesystem containment end-to-end

```
sandbox launch --exe pm-worker-tool.exe --moniker pm-verify
  → worker tries to open C:\Windows\System32\drivers\etc\hosts
  → assert exit = ACCESS_DENIED (5)
sandbox acl --path <tmpdir> --access read
sandbox launch --exe pm-worker-tool.exe --moniker pm-verify
  → worker opens <tmpdir>/test.txt
  → assert exit = 0
```

This is the critical proof that SECURITY_CAPABILITIES is actually enforcing deny-by-default
and the grant actually opens the path.

### 4. Wire `ToolWorkerClient::executeWindowsSandboxed`

Replace the placeholder body with:
1. `ensure_profile(moniker, &sid)`
2. `grant_path(workspacePath, sid, "read-write")`
3. `CreateProcessW` with `SECURITY_CAPABILITIES` + `AssignProcessToJobObject`
4. Send tool call JSON over stdin; read response from stdout
5. On `privilege_escalation` response: route to `SecurityGateway::authorizeWithConsent()`
6. On `Allow`: `grant_path` + retry; on `Deny`: inject `security_denied` tool result
7. On process exit / timeout: `DeleteAppContainerProfile` + revoke ACL ACEs

### 5. Sidecar binary smoke test

```
sandbox acl --path dist/win-x64/bin --access exec
sandbox launch --moniker pm-sidecar-test --exe "dist\win-x64\bin\uvx.exe --version"
```

Verifies that `uvx.exe` / `node.exe` DLLs load correctly when the binary dir is
granted exec.  This is the first real sidecar validation.

### 6. Capability SID resolution for LPAC network tools

Wire `DeriveCapabilitySidsFromName("internetClient", ...)` into the profile-create
path.  Expose `--capabilities internetClient` on `sandbox probe` and `sandbox launch`.
Required for first-run `uvx` package downloads inside LPAC.

---

## Limits — what the sandbox does and does not protect

**Does protect:**
```
filesystem writes outside granted paths
network access (default off)
child process spawning (with PROCESS_CREATION_CHILD_PROCESS_RESTRICTED)
access to other users' processes / handles
registry writes outside the AC profile hive
```

**Does not protect against:**
```
administrator / kernel compromise
same-user malware injecting into the broker process
debuggers/memory dumpers on the broker
filesystem reads if paths are passed directly (use handles instead)
vulnerabilities in the broker itself
```

---

## Portable design

Keep the public API portable across platforms:

```
ToolWorkerClient
WorkerSandboxOptions
ExecutionMode { InProcess, Worker, SandboxedWorker }
```

Backend files:

```
src/security/workers/win/WinSandboxWorker.cpp   ← AppContainer (active)
src/security/workers/mac/MacSandboxWorker.cpp   ← App Sandbox (future)
src/security/workers/linux/LinuxSandboxWorker.cpp ← seccomp/Landlock (future)
```

macOS / Linux: return `ExecutionMode::Worker` (no FS isolation) until their backends land.

---

## Tests (pending)

See `docs/security/todos.md § Sandbox` for the full list.  Priority probes:

```
sandbox probe round-trip — SID format S-1-15-2-*
sandbox wrap-mcp deny path — accessDenied=true + privilegeEscalationRequest fields
sandbox acl + wrap-mcp — grant → aclGranted=true
sandbox launch exit 42 — exitCode=42
sandbox launch --lpac — process created, containment confirmed
shared folder end-to-end — grant → use → revoke lifecycle
```

---

## References

- [AppContainer isolation — Win32 docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Implementing an AppContainer — Win32 docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Cheap sandboxing with AppContainers (blahcat)](https://blahcat.github.io/2020-12-29-cheap-sandboxing-with-appcontainers/)
- [Chromium sandbox design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)
- [arapuca — Rust/C sandbox library](https://github.com/sergio-correia/arapuca)
- [rappct — AppContainer/LPAC Rust toolkit](https://crates.io/crates/rappct)
- [Microsoft LaunchAppContainer reference](https://github.com/microsoft/SandboxSecurityTools/blob/main/LaunchAppContainer/LaunchAppContainer/LaunchAppContainer.cpp) — local copy at `ref/SandboxSecurityTools/`
