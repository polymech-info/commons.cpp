# Software protection todos

Scope: protect the shipped `tanit` / `tanit-cli.exe` product, bundled
sidecars, MCP workers, app UI paths, agent tools, secrets, license checks, and
user data.

Priority rule: reduce what a compromised process can do before trying to detect
or frustrate a debugger. Anti-debug and anti-reversing checks are telemetry and
tamper signals only; they are not a security boundary.

> **Status:** `FEATURE_ANTI_HACKING` is implemented, live in `tanit.exe`, and
> fully tested (141/141). Startup scan runs at ~1 ms before the first window
> appears — output confirmed in production logs. See
> **§ Anti-hack module** at the end of this document for full reference.
>
> | Area | State |
> |---|---|
> | `anti_hack.hpp/.cpp` — debugger, hooks, modules, memory | ✅ shipped |
> | `FEATURE_ANTI_HACKING` wired into CMake / all 3 targets | ✅ shipped |
> | `tanit.exe` startup scan → `pm-image.log` (stderr channel) | ✅ live |
> | `pm-image-security antihack` CLI + `test-antihack.mjs` (141/141) | ✅ tested |
> | Antihack lines in `pm-image.log` file (file-mirror channel) | ⬜ next |
> | Re-scan on slow background timer | ⬜ next |
> | Capability downgrade / action on signals | ⬜ next |
> | Trial/license hardening using antihack signals (P2) | ⬜ next |
> | Secure storage, signing pipeline, SecurityGateway surfaces, sandboxing | ⬜ planned |

Relevant code / build areas:

- `src/cli/pm_image_register_cli.cpp` - CLI flags, UI launch path, MCP bind,
  custom commands.
- `src/core/library_utils.cpp` - explicit DLL loading helpers.
- `src/core/stdio_child_runner.hpp` / `.cpp` - tool / sidecar process launch.
- `src/security/*` - `SecurityGateway`, policy, grants, audit, AppContainer.
- `src/win/assistant/uia_spy.*`, `src/win/inspect.cpp`,
  `src/win/session_replay/*` - UIAutomation client / inspection surfaces.
- `src/win/trial_protection.cpp` - license / trial checks.
- `CMakeLists.txt` - feature flags, target sources, link options, third-party
  libraries.

---

## P0 - real security controls

These reduce attack impact and must be implemented before optional anti-debug
work.

### P0.1 DLL search hardening

- [ ] **Set safe process DLL search policy at process entry.** Use:

  ```cpp
  SetDefaultDllDirectories(
      LOAD_LIBRARY_SEARCH_SYSTEM32 |
      LOAD_LIBRARY_SEARCH_USER_DIRS);
  SetDllDirectoryW(L"");
  AddDllDirectory(installBinDir.c_str());
  ```

  `LOAD_LIBRARY_SEARCH_SYSTEM32` alone is too strict for app-local DLLs. The
  intended policy is: system DLLs from `System32`; app/vendor DLLs only from
  registered install directories; never current working directory or `%PATH%`.

- [x] **Ensure `--cwd` never changes DLL resolution.** `--cwd` is for resource and
  path resolution, not loader state. Set DLL search policy before honoring `--cwd`
  or any UI launch path. => CWD affects only data

- [ ] **Change explicit loads to verified absolute paths.** `library_utils::load`
  should load from an absolute install path only after verification:

  ```txt
  realpath under install/bin
  sha256 matches binary manifest
  Authenticode signature valid
  signer is allowlisted
  ```

  Then call:

  ```cpp
  LoadLibraryExW(absPath.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
      LOAD_LIBRARY_SEARCH_SYSTEM32);
  ```

- [ ] **Ban fallback to default OS search for third-party DLL names.** Loading
  `"onnxruntime.dll"` or `"opencv_world*.dll"` by name is not allowed in release
  builds. Fallback may stay in dev builds behind `FEATURE_DEV_DLL_SEARCH`.

- [ ] **Add import-table CI audit.** Run `dumpbin /IMPORTS` or `llvm-readobj`
  post-build and fail release builds if unexpected third-party DLLs appear as
  implicit imports of `tanit-cli.exe`. Third-party DLLs should be delay-loaded
  or loaded through the verified manifest path.

### P0.2 Sign and manifest every shipped binary

- [ ] **Sign every executable binary shipped in the product.** This includes:

  ```txt
  .exe
  .dll
  .node
  .pyd
  .msi / .msix
  helper tools
  sidecars
  bundled MCP server binaries
  bundled node.exe / python.exe if redistributed
  ```

- [ ] **Treat self-compiled third-party binaries as our binaries.** Examples:

  ```txt
  opencv_world.dll
  onnxruntime.dll
  libsodium.dll
  llama.dll
  ggml-cuda.dll
  toolworker.exe
  node.exe if redistributed
  python.exe if redistributed
  ```

  Build from verified source / release hashes, sign with the PolyMech publisher
  certificate, timestamp the signature, and record the final binary in the
  manifest.

- [ ] **Do not rewrite vendor-signed binaries.** If a vendor DLL is shipped
  untouched, keep the vendor signature and verify vendor signer + hash. If we
  rebuild, patch, strip, repackage, or otherwise modify it, sign it ourselves and
  treat it as part of our supply chain.

- [ ] **Create a binary manifest consumed at runtime.** Example:

  ```json
  {
    "path": "bin/onnxruntime.dll",
    "sha256": "...",
    "signer": "Plastic Hub / PolyMech",
    "original_project": "onnxruntime",
    "version": "1.x"
  }
  ```

- [ ] **Add runtime bundle verification before trust-sensitive use.** Validate
  path, SHA-256, Authenticode chain, timestamp, signer allowlist, and manifest
  entry before loading DLLs, starting sidecars, granting tool identities, or using
  built-in MCP/tool bundles.

- [ ] **Use the right certificates per environment.**

  ```txt
  dev: self-signed cert trusted locally only
  release: OV code-signing cert minimum
  optional: EV cert for stronger SmartScreen reputation path
  required: timestamp every release signature
  ```

  Signing is not a sandbox and does not make third-party code safe. It provides
  tamper evidence, publisher identity, SmartScreen reputation, runtime
  allowlisting, and stable tool/bundle identity binding.

### P0.3 CLI, UI, and resource policy

- [ ] **Change `--mcp-bind` default to `127.0.0.1`.** Current all-interface bind
  semantics are too risky for a local agent surface. LAN exposure must require
  explicit `--mcp-bind 0.0.0.0` plus policy approval.

- [ ] **Route `--system-prompt @path` through ResourceVFS.** Do not load arbitrary
  filesystem paths directly into prompts. Allowed prompt resources should be
  content-addressed, under trusted roots, policy-classified, and logged as
  resource URIs.

- [ ] **Move scripts, prompts, templates, and built-in tool specs into
  ResourceVFS.** No raw filesystem prompt/template loading in release paths.
  ResourceVFS should support:

  ```txt
  signed immutable built-in bundles
  content-addressed resources
  user/workspace override roots
  policy-gated overrides
  resource trust classification
  hash-bound audit events
  ```

- [ ] **Policy-gate `--commands` and custom `shellLine`.** Custom commands with
  `externalCommand` / `shellLine` must go through `SecurityGateway`, not direct
  CLI execution. Require an explicit user/workspace grant for shell execution.

- [ ] **Reject unsafe `--config-dir` values.** For release builds, reject config
  directories that are world-writable, inside temp/downloads, symlinked outside
  trusted roots, or owned by another user. Log `config_dir_rejected_total`.

- [~] **Remove plain hidden maintenance commands from retail builds.** `godmod`
  is removed and the stale registry bypass flag is no longer honored. `purgetrial`
  is now a dev/test-only command behind `FEATURE_COMMAND_TEST` and still removes
  stale trial/bypass state for local testing. If a support-only path is required
  later, require a signed challenge token bound to machine fingerprint, build
  channel, expiry, and support case ID.

### P0.4 SecurityGateway as the boundary

- [ ] **All tool calls enter through `SecurityGateway`.** That includes local file
  tools, command tools, MCP calls, app commands, custom commands, and UI-injected
  actions. No direct execution path should bypass classify -> authorize -> grant
  -> execute.

- [ ] **Add an MCP broker / proxy.** The app should not connect arbitrary MCP tools
  directly to the agent process. Route MCP through a broker that:

  ```txt
  verifies MCP binary identity
  maps tools to stable tool IDs
  classifies requested resources
  enforces per-tool grants
  records tool_hash and bundle_hash
  blocks permission escalation without consent
  ```

- [ ] **Bind grants to tool identity and content hash.** A grant for `tool_id=A`
  with `tool_hash=X` must not be reusable after the tool binary/script changes to
  hash `Y`. Invalidate on bundle update, policy update, signer change, or resource
  trust downgrade.

- [ ] **No arbitrary shell without an explicit grant.** Shell execution should
  carry command intent, working directory, environment diff, network/file access
  class, timeout, and sandbox mode in the authorization request.

### P0.5 UIAutomation policy gateway

UIAutomation is useful for accessibility and automation, but weak as a security
signal. Treat it like another tool/resource surface: policy-gate sensitive access,
audit it, and redact sensitive controls. Do not rely on "automation detection" as
a boundary.

- [ ] **Introduce `UIAutomationGateway`.** Route provider requests and app-owned
  automation actions through the same policy model as tools:

  ```txt
  QueryTree
  ReadProperty
  Invoke
  SetValue
  Expand
  Focus
  ElementFromPoint
  ```

  Each request should classify the target element, action, process/session, and
  sensitivity before returning provider data or executing an action.

- [ ] **Add profile-level `AutomationMode`.**

  ```cpp
  enum class AutomationMode {
      Disabled,
      Accessibility,
      Trusted,
      Full,
  };
  ```

  Suggested defaults:

  ```txt
  End user: Accessibility
  Developer: Full
  OEM / locked-down: Disabled or Accessibility
  ```

  `Disabled` may return `0` for `WM_GETOBJECT` or avoid exposing providers, but
  must be opt-in because it breaks Narrator, screen readers, WinAppDriver, Power
  Automate, and accessibility tools.

- [ ] **Wrap every UIA provider entry point.** If the app implements
  `IRawElementProviderSimple`, `IRawElementProviderFragment`, or
  `IRawElementProviderFragmentRoot`, log and policy-check:

  ```txt
  GetPatternProvider()
  GetPropertyValue()
  Navigate()
  GetRuntimeId()
  ElementFromPoint()
  GetFocus()
  ```

  Provider calls know exactly which automation objects are queried; this is more
  useful than generic process detection.

- [ ] **Handle `WM_GETOBJECT` as telemetry, not authorization.** Count requests,
  measure request rate, record window/control identity, and try to capture caller
  hints where Windows exposes them. High `WM_GETOBJECT` frequency means the UI is
  likely being inspected, but it does not prove malicious activity.

- [ ] **Redact sensitive controls by default.** For API keys, passwords, license
  data, grant dialogs, security settings, tokens, recovery codes, and provider
  secrets, expose safe metadata only:

  ```txt
  IsPassword = TRUE
  Value = ""
  Name = ""
  ```

  Or return `UIA_E_ELEMENTNOTAVAILABLE` for controls that should not be
  automation-visible under the active profile.

- [ ] **Separate accessibility reads from automation actions.** Screen-reader
  compatible read-only properties may be allowed in `Accessibility` mode. `Invoke`,
  `SetValue`, privileged focus changes, grant approval, export, delete, and shell
  actions require `Trusted` or `Full` plus an explicit policy grant.

- [ ] **Classify known UIA clients only as hints.** `inspect.exe`,
  Accessibility Insights, Narrator, WinAppDriver, Power Automate, and
  `UIAutomationCore` can sometimes be inferred from COM/RPC, window ownership,
  parent process, or activation context. Never use process name alone to allow a
  sensitive action.

- [ ] **Gate our own UIA inspection tools.** Existing UIA client paths such as
  `src/win/assistant/uia_spy.*`, `src/win/inspect.cpp`, assistant app inspection,
  and session replay should also enter `SecurityGateway`. Reading another app's UI
  tree can expose secrets, so it needs profile policy, user consent, and audit.

### P0.6 Sandboxed sidecars for risky work

- [ ] **Run MCP servers and risky tools in a sidecar process.** The primary UI/agent
  process should broker access; it should not host untrusted code or tool plugins
  in-process.

- [ ] **Use Job Object containment for all child processes.** Set process count,
  memory, CPU, kill-on-job-close, UI restrictions where practical, and timeout
  limits. Log `sandbox_killed_total` on enforcement.

- [ ] **Use AppContainer / LPAC for tool workers where viable.** Start with MCP and
  shell/tool workers. Grant filesystem access by explicit ACL to the AppContainer
  SID, not by inheriting the user's full token. Prefer LPAC for tools that do not
  need broad Windows app package access.

- [ ] **Use process mitigation policies on sidecars.** Apply where compatible:

  ```txt
  ProcessDynamicCodePolicy
  ProcessSignaturePolicy
  ProcessChildProcessPolicy
  ProcessExtensionPointDisablePolicy
  ProcessImageLoadPolicy
  ```

  Test compatibility per sidecar; do not silently weaken policies without an
  audit event.

### P0.7 Audit logging that survives common tampering

- [ ] **Do not rely on ETW as the only audit channel.** ETW can be blinded by
  in-process patching of `EtwEventWrite` (as shown in the
  [UnhookingDLL reference](https://github.com/ProcessusT/UnhookingDLL/blob/main/UnhookingDLL.cpp)).
  Always write security events to a signed local audit log or out-of-process log
  service in addition to optional ETW.

- [ ] **Hash-chain audit records.** Each record should include previous record hash,
  current record hash, monotonic counter, process/session ID, and policy version.
  This gives tamper evidence even when the process is compromised after startup.

- [ ] **Flush deny/escalation events synchronously.** Do not buffer high-risk audit
  events only in memory.

---

## P1 - tamper evidence and build hardening

These improve detection and incident analysis. They should not decide core access
control by themselves.

### P1.1 Build mitigations

- [ ] **Enable Control Flow Guard in MSVC release builds.**

  ```cmake
  target_compile_options(${MEDIA_TARGET_PM_IMAGE} PRIVATE /guard:cf)
  target_link_options(${MEDIA_TARGET_PM_IMAGE} PRIVATE /GUARD:CF)
  ```

- [ ] **Enable CET shadow stack compatibility where toolchain and target OS allow.**

  ```cmake
  target_link_options(${MEDIA_TARGET_PM_IMAGE} PRIVATE /CETCOMPAT)
  ```

- [ ] **Strip public release debug metadata.** Do not ship PDBs beside public
  binaries. Use private symbol server access for crash reporting. Consider
  `/PDBALTPATH:NONE` and verify the final `IMAGE_DEBUG_DIRECTORY`.

- [ ] **Enable reproducible release builds where practical.** Record compiler,
  linker, source revision, dependency versions, hashes, signature metadata, and
  manifest hash in the release artifact.

### P1.2 Module and memory tamper evidence

- [~] **Snapshot loaded modules at startup.** Record path, realpath, base address,
  size, signer, SHA-256, and manifest match for each loaded module. Recheck at
  security-sensitive gates and long-running daemon intervals. *(Partial:
  `antihack::scan_modules()` snapshots loaded modules via Toolhelp and flags
  user-writable/transient load paths — **live in `tanit.exe`** since Jun 2026,
  confirmed 116 modules at startup. Signer / SHA-256 / manifest match still TODO
  — requires the binary manifest from P0.2.)*

- [ ] **Verify security-critical modules against the binary manifest.** At minimum:
  `tanit-cli.exe`, `pm-media`, `libsodium`, `onnxruntime`, `opencv`, `llama`,
  `ggml`, MCP sidecars, and any DLL used by license / crypto code.

- [ ] **Treat unexpected module changes as a capability downgrade signal.** A new
  unsigned module inside the process should revoke high-risk capabilities, flush an
  audit event, and require user restart. Avoid false positives by allowlisting known
  Windows accessibility / IME / GPU overlay modules separately.

- [~] **Keep ntdll checks as tamper telemetry only.** It is fine to compare selected
  ntdll exports or `.text` hashes for diagnostics, especially to detect the
  [UnhookingDLL](https://github.com/ProcessusT/UnhookingDLL/blob/main/UnhookingDLL.cpp)
  pattern, but do not assume "clean ntdll stubs are suspicious." Clean stubs are
  normal on many systems. Only mismatches from our own baseline or unexpected
  changes during runtime are useful signals. *(Implemented as telemetry:
  `antihack::scan_dll_hooks()` checks the entry prologue of sensitive
  ntdll/kernel32/kernelbase exports — incl. `EtwEventWrite` — for inline-hook
  trampoline shapes and reports them as signals, never as a hard block.)*

- [ ] **Do not use `PAGE_GUARD` on ntdll `.text` as a default protection.** It is
  fragile and may conflict with EDR, debuggers, profilers, and system behavior.
  Keep it only behind `FEATURE_ANTITAMPER_EXPERIMENTAL` for lab builds.

### P1.3 Tool and bundle integrity

- [ ] **Signed immutable built-in bundles.** Built-in prompts, tools, MCP schemas,
  policies, and templates should be signed and content-addressed. A grant should
  record the bundle hash it was created against.

- [ ] **Policy-gated user/workspace overrides.** Overrides are useful for dev, but
  they should be classified as less trusted than built-ins and require policy
  approval for shell, network, or secret access.

- [ ] **Manifest drift test.** CI should fail if a binary in the shipped package is
  missing from the manifest, unsigned, signed by an unexpected signer, or has a hash
  that does not match the manifest.

---

## P2 - optional anti-debug / anti-reversing

These are noisy, bypassable, and can break legitimate user tools. Keep them out of
core security decisions. They may be useful as retail-only telemetry or as a speed
bump around trial/license checks.

- [x] **Gate all anti-debug checks behind a feature flag.** Implemented under
  `FEATURE_ANTI_HACKING` (default ON). The default security posture (gateway,
  policy, grants) does **not** depend on these checks — `antihack::run()` only
  produces signals; nothing terminates or corrupts state.

- [x] **Optional debugger telemetry.** Implemented in `antihack::scan_debugger()`
  as risk signals only:

  ```txt
  IsDebuggerPresent                              → debugger.is_debugger_present
  CheckRemoteDebuggerPresent                     → debugger.remote_present
  PEB.BeingDebugged                              → debugger.peb_being_debugged
  PEB.NtGlobalFlag (debug-heap bits)             → debugger.peb_nt_global_flag
  NtQueryInformationProcess(ProcessDebugPort)    → debugger.nt_debug_port
  NtQueryInformationProcess(DebugObjectHandle)   → debugger.nt_debug_object
  NtQueryInformationProcess(ProcessDebugFlags)   → debugger.nt_debug_flags
  thread debug registers Dr0-Dr3                 → debugger.hardware_breakpoints
  ```

  Timing-delta heuristics are intentionally not implemented (too noisy). No
  signal terminates or corrupts user state.

- [ ] **Optional anti-reversing for license code.** If a retail license gate needs
  obfuscation, prefer commercial or build-time obfuscation around only that narrow
  component. Do not spread opaque predicates or exception tricks throughout the app.

- [ ] **Remove or protect sensitive string literals.** Support-only commands,
  license paths, and policy bypass terms should not appear as obvious strings in
  release binaries. The stronger fix is to remove support-only paths from retail
  builds, not to rely only on string obfuscation.

- [ ] **Use attacker tools only in test harnesses.** Detours, PolyHook2, Frida,
  pe-sieve, al-khaser, ScyllaHide, and the UnhookingDLL sample are useful for
  validating telemetry and hardening assumptions. They should not become required
  runtime dependencies of the production app.

---

## App-level security measurements

Add counters and structured events so security controls can be tested, monitored,
and regression-checked.

### Counters

```txt
tool_call_total
tool_call_denied_total
tool_call_asked_total
tool_call_allowed_total
grant_created_total
grant_reused_total
grant_expired_total
grant_revoked_total
sandbox_launch_total
sandbox_launch_failed_total
sandbox_timeout_total
sandbox_killed_total
mcp_permission_escalation_total
resource_policy_violation_total
prompt_resource_rejected_total
config_dir_rejected_total
unsigned_bundle_rejected_total
binary_manifest_mismatch_total
authenticode_rejected_total
dll_load_rejected_total
unexpected_module_total
uia_wm_getobject_total
uia_provider_query_total
uia_read_allowed_total
uia_read_redacted_total
uia_action_denied_total
uia_action_allowed_total
uia_sensitive_element_rejected_total
uia_client_suspected_total
```

### Required event fields

```txt
session_id
profile
tool_id
actor
resource_uri
resource_trust
decision
risk
grant_id
policy_version
tool_hash
bundle_hash
binary_path
binary_hash
binary_signer
sandbox_mode
sidecar_pid
automation_mode
uia_action
uia_pattern
uia_property
uia_element_id
uia_element_role
uia_element_sensitivity
uia_client_hint
uia_request_rate
```

### Acceptance tests

- [ ] `--mcp-bind` defaults to `127.0.0.1`; `0.0.0.0` requires explicit policy.
- [ ] `--system-prompt @outside_workspace` is rejected through ResourceVFS policy.
- [ ] `--commands attacker.json` with `shellLine` requires a shell grant and is
  denied by default.
- [ ] Unsigned or hash-mismatched `onnxruntime.dll` is rejected before load.
- [ ] Self-compiled third-party DLLs are signed by PolyMech and present in the
  binary manifest.
- [ ] Vendor-signed untouched DLLs validate against vendor signer + manifest hash.
- [ ] MCP sidecar launch without a manifest entry is rejected.
- [ ] Sandbox timeout kills the worker and increments `sandbox_killed_total`.
- [ ] A changed tool bundle invalidates old grants bound to the previous hash.
- [ ] ETW-disabled environment still produces signed local audit records.
- [ ] `WM_GETOBJECT` requests increment `uia_wm_getobject_total` and produce
  telemetry without blocking accessibility by default.
- [ ] Sensitive controls expose `IsPassword = TRUE` and redacted `Name` / `Value`
  in `Accessibility` mode.
- [ ] UIA `Invoke` / `SetValue` on grant dialogs, security settings, API keys, or
  license controls is denied without a `Trusted` / `Full` automation grant.
- [ ] Our own `uia_spy` / inspect paths require SecurityGateway authorization
  before reading another process's automation tree.

---

## Anti-hack module (`FEATURE_ANTI_HACKING`)

The first runtime tamper-telemetry module. **Default ON.** Windows produces real
signals; every other platform (and `FEATURE_ANTI_HACKING=0`) compiles to clean
no-op stubs.

> These are *signals, not a boundary.* `run()` returns evidence; the caller
> decides what to do (log, downgrade capabilities, warn the user). Nothing here
> terminates the process or corrupts state — consistent with the priority rule
> at the top of this document.

### Code

```
src/security/anti_hack.hpp          ← Signal / Severity / Category / ScanOptions / Report + API
src/security/anti_hack.cpp          ← Windows backend + portable clean stubs
src/win/ui_next/launch_ui_next.cpp  ← pm_run_startup_antihack_scan() called in run_pm_image_ui()
```

Compiled into `pm-media`, so both `pm-image(.exe)` and `pm-image-security.exe`
share one implementation. Flag wiring lives in `CMakeLists.txt`
(`option(FEATURE_ANTI_HACKING …)`, source append, compile definitions on
`pm-media`, `tanit`, `tanit-cli`, `pm-image-security`) and
`CMakePresets.json` (`vendor.pm.features` + `cacheVariables`).

### Scans

| Scan | Function | Signals (selected) | Severity |
|---|---|---|---|
| Debugger | `scan_debugger()` | `debugger.is_debugger_present`, `…remote_present`, `…peb_being_debugged`, `…peb_nt_global_flag`, `…nt_debug_port`, `…nt_debug_object`, `…nt_debug_flags`, `…hardware_breakpoints` | High / Medium |
| DLL hooks | `scan_dll_hooks()` | `dll_hook.inline` (locus = `module!export`) on sensitive ntdll/kernel32/kernelbase/amsi exports incl. `EtwEventWrite` | High (ntdll syscall stubs) / Medium |
| Modules | `scan_modules()` | `module.suspicious_path` (temp/downloads/public/recycle), `module.count` (Info snapshot) | Medium / Info |
| Memory | `scan_memory()` | `memory.rwx_region` (writable+executable), `memory.private_exec` (non-image executable), `memory.summary` (Info) | High / Low / Info |

Inline-hook detection classifies the export entry prologue against the classic
trampoline shapes installed by Detours/EasyHook/MinHook/EDR/cheat engines:
`jmp rel32`, `jmp rel8`, `jmp [mem]`, `push imm32; ret`, `mov rax,imm64; jmp rax`,
`mov eax,imm32; jmp`. Note: legitimate EDR/AV products inline-hook the same
exports, so a `dll_hook.inline` signal is evidence to audit, not proof of attack.

### Test CLI

```
pm-image-security antihack scan        # all scans, aggregated
pm-image-security antihack debugger    # debugger signals only
pm-image-security antihack hooks [--module ntdll.dll]
pm-image-security antihack modules
pm-image-security antihack memory [--self-test-rwx]
```

Each emits one JSON report:

```jsonc
{
  "ok": true,
  "available": true,            // false on non-Windows / flag OFF
  "anyDetected": false,
  "detectedCount": 0,
  "maxSeverity": "info",
  "modulesTotal": 30,
  "counters": { "debugger": 0, "dll_hook": 0, "module": 0, "memory": 0 },
  "signals": [ { "category": "memory", "name": "memory.rwx_region",
                 "detected": true, "severity": "high",
                 "detail": "…", "locus": "0x…" } ]
}
```

`--self-test-rwx` leaks one `PAGE_EXECUTE_READWRITE` page before scanning so the
memory detector has a deterministic positive — used by the test harness to prove
the scanner actually fires.

### Tests

```
tests/orchestrator/test-antihack.mjs
npm run test:antihack          # expects a pre-built binary
npm run test:antihack:build    # builds pm-image-security first
node tests/orchestrator/test-antihack.mjs --only selftest
```

Suites (selectable via `--only`): `scan`, `debugger`, `hooks`, `modules`,
`memory`, `selftest`. Structural suites assert the report shape and that a clean
standalone run is not falsely flagged (no debugger; counters consistent with
`detectedCount`); the `selftest` suite asserts the injected RWX page is detected
at High severity.

### Live in `tanit.exe`

`antihack::run()` is called at GUI startup in `run_pm_image_ui()`
(`src/win/ui_next/launch_ui_next.cpp`) — right after the log sink installs,
before the first window is created. Memory scan is intentionally skipped at
startup; WebView2/V8/ONNX/llama JIT engines legitimately allocate executable
pages and would produce constant noise.

```
[info]    [antihack] startup scan: modules=116 detected=1 maxSeverity=medium
[warning] [antihack] dll_hook.inline (medium) @ kernel32.dll!CreateFileW — inline hook prologue (jmp [mem])
[trace]   [startup]  9 ms  after antihack startup scan
```

Output goes to the spdlog stderr channel. The `pm-image.log` file-mirror
channel (`append_pm_image_log_file_line_wide`) is a separate sink and does not
yet capture these lines — see **Next steps** below.

### Next steps

| Task | Note |
|---|---|
| Mirror antihack lines to `pm-image.log` | Call `append_pm_image_log_file_line_wide` alongside `logger::*` in the scan helper |
| Re-scan on slow background timer | e.g. every 5 min; diff against startup baseline; log only changes |
| Capability downgrade on signal change | Hook `Report` into a security state observer; downgrade on new High signal |
| Trial/license: reject if debugger attached at check time | Use `scan_debugger()` inline in `trial_enforce_or_exit` as a risk signal (item 4) |
| Signer / SHA-256 module verification | Depends on P0.2 binary manifest — blocked until manifest exists |
| `memory.private_exec` allowlisting | V8/ONNX/llama JIT pages need an image-name allowlist before memory scan can run in-process |
