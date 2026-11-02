# Security gateway — implementation todos

Scaffolding for the local tool-call security gateway described in
`docs/security/design.md`. Phase 1 lands the module skeleton, types, profile
model, and the Win32 crypto/ACL backends. Everything else is stubbed with
`TODO(security)` markers so the build stays green while behaviour is filled in.

Core rule: **LLM proposes. Gateway decides. Scoped capability executes.**

## Status snapshot

| Layer | State | Test coverage |
| ----- | ----- | ------------- |
| Gateway core (types, policy, classify, grants, crypto) | ✅ done | `test:security` — 182 assertions |
| Path security, URI scopes, origin/provenance | ✅ done | included above |
| **CLI consent surface** (`--interactive` stdio) | ✅ done | interactive suite, 17 assertions |
| **Win32 consent dialog** (`--interactive --gui`) | ✅ done | `test:security-ui` — 41 UIA assertions |
| Loopback router + agent harness (incl. `run` tool) | ✅ done | suiteLoopbackAgent, 32 assertions |
| Hard-limit tables (`hard_limits.hpp`) | ✅ done | covered by existing path/classify suites |
| **Agent loop intercept** (secure-by-default, Phase 1.9) | ✅ **done** — `FEATURE_SECURITY_AGENT=ON` in `CMakePresets.json`; security sources in `pm-media`; `SecurityGateway` created in `Agent::run()` and intercepts both serial + parallel dispatch seams | build + test |
| **Client-agnostic** (loopback/llama/kbot/MCP via shared tool seam) | ✅ confirmed (by construction) | n/a |
| **In-app WebView consent** (ConsentCard inline, WebViewConsentDelegate) | ✅ done | implementation wired; suiteConsentInline still pending |
| **Security settings tab** (GrantsPanel, profile, RPC) | ◑ UI shell done | settings RPC is stubbed; suiteGrantsRpc pending |
| **`run` tool gateway layer** (cmd:// classification) | ❌ Phase 2h | suiteLoopbackAgent+ |
| Audit-log, DPAPI/ACL backends, origin hash-binding | ⏳ deferred | — |
| SQLite persistence, signed policy bundle | ⏳ Phase 4 | — |
| Full integration (MCP, in-app, background service) | ⏳ Phase 5 | — |

**Phase 1.9 (agent loop intercept) is done and policy-corrected:**
- `SecurityGateway` authorizes all file-based and MCP tool calls inside `Agent::run()`.
- Profile is **Developer** for all agent-dispatched tools: workspace writes are `Allow`
  without consent; out-of-workspace writes / MCP calls are `Ask → DenyAll → Deny` in
  Phase 1.9 (no interactive consent surface yet).
- **`run` tool is excluded from gateway interception in Phase 1.9** — `cmd://` URIs
  are not classifiable without a command-intent model; `validate_command` (RunValidators)
  continues to gate shell execution. Gateway `Execute` gating for `run` is Phase 2.
- Test 5 in `suiteLoopbackAgent` now asserts `security_denied:true` + `decision:deny`
  from the gateway envelope for out-of-workspace writes.

**Phase 2** (current): WebView inline consent card is implemented
(`ConsentDelegateRegistry` + `ChatWebPanel_Consent.cpp` + `ConsentCard.tsx`);
Security settings tab shell is implemented; real grants RPC/test coverage remains.
`run` tool gateway layer (cmd:// classification) is tracked separately.

## Profiles ↔ CMake `SECURITY_PROFILE`

| `SECURITY_PROFILE` | `pm::security::Profile` | design.md name |
| ------------------ | ----------------------- | -------------- |
| `LIGHT`            | `Profile::Light`        | EndUser        |
| `STRICT`           | `Profile::Strict`       | OEM            |
| `DEVELOPER`        | `Profile::Developer`    | Dev            |

## Feature flags (see `CMakePresets.json`)

Global gateway pieces (portable):
`FEATURE_SECURITY_GATEWAY`, `FEATURE_SECURITY_POLICY_ENGINE`,
`FEATURE_SECURITY_PERMISSION_STORE`, `FEATURE_SECURITY_AUDIT_LOG`,
`FEATURE_SECURITY_CONSENT_DELEGATE`, `FEATURE_SECURITY_RESOURCE_CLASSIFIER`,
`FEATURE_SECURITY_PATH_SECURITY`, `FEATURE_SECURITY_TOOL_IDENTITY`,
`FEATURE_SECURITY_MCP_POLICY`, `FEATURE_SECURITY_SECRET_SCAN`.

OS-specific encryption / hardening backends (explicit per-OS opt-in):
`FEATURE_SECURITY_CRYPTO_WIN_DPAPI`, `FEATURE_SECURITY_WIN_ACL` (win32),
`FEATURE_SECURITY_CRYPTO_MAC_KEYCHAIN` (macOS, later),
`FEATURE_SECURITY_CRYPTO_LINUX_SECRET_SERVICE` (linux, later).

---

## Phase 1 — scaffolding (this pass, win32)

- [x] `types.hpp` — enums (Profile/Actor/Action/Risk/DecisionKind/GrantLifetime),
      request/grant/decision structs, MCP policy struct, secret-pattern tables,
      classification delegate interfaces, enum `to_string` helpers.
- [x] `security_default.hpp` — `FEATURE_SECURITY_*` macro defaults, profile
      selection (`SECURITY_PROFILE_DEFAULT`), umbrella include + exports.
- [x] `PathSecurity.hpp/.cpp` — API surface; `std::filesystem` canonicalize +
      `isInside` + glob scope match. `test:security -- --only paths` now covers
      workspace symlink/junction escape for existing files and not-yet-existing
      write targets under a linked directory.
- [x] `ResourceClassifier.hpp/.cpp` — delegate-driven classifier seam. Default
      delegate wraps the secret-pattern tables. Replaces ad-hoc
      `src/file_extensions.hpp` predicates over time (see "Delegate migration").
- [x] `ToolIdentity.hpp/.cpp` — identity/hash resolver surface; hashing = TODO.
- [x] `CryptoStore.hpp/.cpp` — backend-agnostic interface + factory.
- [x] `backends/win/WinDpapiCrypto.cpp` — DPAPI master key + CNG AES-256-GCM.
- [x] `backends/win/WinAcl.cpp` — ACL-hardened security dir.
- [x] `backends/win/WinPaths.cpp` — `%LOCALAPPDATA%/<App>/security` resolution.
- [x] `PermissionStore.hpp/.cpp` — in-memory grant store; SQLite = TODO.
- [x] `AuditLog.hpp/.cpp` — in-memory + stderr audit sink; spdlog + SQLite = TODO.
- [x] `ConsentDelegate.hpp` — pure interface (no default UI here).
- [x] `PolicyEngine.hpp/.cpp` — compiled LIGHT/STRICT/DEVELOPER baselines.
- [x] `SecurityGateway.hpp/.cpp` — orchestrates classify → policy → grants → decision.
- [x] CMake wiring (sources + compile definitions, win backends under `if(WIN32)`).

## Phase 1.5 — dedicated test CLI (`pm-image-security`)

The gateway is **not** baked into the shipping app yet. Instead it is built and
exercised through a standalone console target so the release config stays clean.

- [x] `src/security/cli.cpp` — CLI11 JSON-probe harness (`profile`, `set-profile`,
      `path {canonicalize,inside,glob}`, `classify`, `authorize`, `grant
      {add,list,find,revoke}`, `crypto roundtrip`). One JSON object per call.
- [x] `pm-image-security` target — `EXCLUDE_FROM_ALL`, win32-only. Compiles the
      security sources *here* (not into `pm-media`) with its own feature defines.
      Layers OFF for now: `FEATURE_SECURITY_AUDIT_LOG=0`, `FEATURE_SECURITY_WIN_ACL=0`,
      `FEATURE_SECURITY_CRYPTO_WIN_DPAPI=0` (passthrough crypto → `isSecure=false`).
- [x] Persistence rides the existing settings store: new `.security` / `.permissions`
      subtree keys (`src/core/settings_store.hpp`, `src/win/settings_store.hpp`)
      bridged by `src/security/SecurityPersistence.*`. `--config-dir` isolates the
      store for tests.
- [x] Build/test scripts: `npm run build:cpp:security`, `npm run test:security`
      (`test:security:build` builds first).
- [x] `tests/orchestrator/test-security.mjs` — functional suites: profile/crypto,
      path security, classification, authorization baselines (LIGHT/STRICT/DEVELOPER),
      grant persistence + Ask→Allow upgrade + revoke.
- [ ] Audit-log layer: re-enable `FEATURE_SECURITY_AUDIT_LOG` behind a probe
      (`audit` subcommand) once the sink is wired.
- [ ] WinACL + DPAPI layers: flip `FEATURE_SECURITY_WIN_ACL` / `_CRYPTO_WIN_DPAPI`
      on for this CLI and assert `isSecure=true` + ACL-hardened dir.
- [ ] Consent UI probe: open the permissions UI from `authorize` (Ask path).
- [x] LLM/MCP exercise: drive real tool-call flows through the CLI. Covered by
      loopback agent security suites and `test:mcp` stdio MCP loopback coverage.

## Phase 1.6 — granularity v2 (this pass)

Fine-grained scoping across the three axes (time / context / resource), all
driven test-first through `pm-image-security` (no main-app changes).

- [x] **Time** — `GrantLifetime::Task` added; `Session`/`Task` grants bind to a
      `sessionId` / `taskId` (`--bind-session` / `--bind-task` on grants;
      `--session` / `--task` on requests). Empty binding = unbound (global). NOTE:
      durable purge-on-session/task-end is a runtime concern (still persisted by
      the test harness so it survives one-shot CLI calls).
- [x] **Context (tool identity)** — wildcard matching on `provider` / `toolId` /
      `serverId` in `ToolIdentityResolver::matches` (e.g. `provider=mcp tool=*
      server=github` = "any tool from MCP server github").
- [x] **Context (origin/provenance)** — `Origin` + `src/security/Origin.*`
      registry for our binaries (`tanit.exe→ui`, `tanit-cli.exe→cli`,
      `pm-image-security.exe→security`); resolved per request, recorded in the
      `authorize` output. Provenance + first-party trust only (decision: not a
      grant-matching dimension yet). Third-party binaries → `unknown`/not first-party.
- [x] **Resource (URI scopes)** — `src/security/UriScope.*` RFC-3986 parse +
      scheme/host/port/path matching. Canonical `file://` (`fs://` alias), plus
      `http/https/ftp/ws/wss`. Scopes are URI patterns *or* bare path globs
      (back-compat). Host globs (`*.github.com`) and scheme isolation enforced.
- [x] **UI contract** — `schema` subcommand emits versioned enums + type defs
      (`security-schema-1`) for the web & win32 native consent UIs to consume.
- [x] Tests: `wildcards`, `uri`, `origin`, `sessiontask`, `schema` suites
      (`npm run test:security`, 90 assertions green).
- [x] **Surface to UI**: build the consent surface for web + win32 native against
      `security-schema-1` (win32 ✅ Phase 1.8; agent CLI ✅ Phase 1.9; WebView
      inline consent ✅ Phase 2). Settings grants RPC backing remains tracked below.

## Phase 1.7 — CLI-as-UI consent (`--interactive`)

The security CLI doubles as the first consent surface: `authorize --interactive`
makes the CLI itself the `ConsentDelegate`. The gateway gained a public
`authorizeWithConsent()` (authorize → on `Ask`, prompt → folded decision) so any
front-end that *is* the UI (CLI now, embedded apps later) shares one seam. Keeps
the gateway UI-agnostic — a web/win32 delegate implements the same interface.

- [x] `CliConsentDelegate` (src/security/cli.cpp): on `Ask` it emits a structured
      `consent_request` (the `security-schema-1` contract) on **stderr** and reads
      one response line from **stdin**; stdout stays the machine result channel.
- [x] Response is a bare token (`allow_once`/`allow_session`/`allow_task`/`deny`/
      `open_settings`) **or** a JSON object `{"choice","lifetime","scopes":[...]}`
      so the UI can narrow the granted scope/lifetime. EOF/blank → deny (safe default).
- [x] On allow, a grant is built from the request (scope = canonical resource by
      default) and persisted via `SecurityPersistence`; `allow_once` permits without
      persisting. `authorize` output now carries `interactive` + `grantId`.
- [x] Fixed `UriScope::parse_uri` to treat a 1-char "scheme" as a Windows drive
      letter (`C:/…` is a bare path, not scheme `c:`), so file scopes match.
- [x] Tests: `interactive` suite (17 assertions) — prompt contract, deny/allow_once/
      allow_session/JSON-scope/open_settings/blank, grant short-circuits (no re-prompt
      when covered), cross-session re-prompt. `npm run test:security` = 107 green.

## Phase 1.8 — Win32 consent dialog (`--gui`)

First native consent surface and the first concrete `ConsentDelegate` beyond the
CLI: a modal Win32 dialog under `src/security/ui/win/ConsentDlg.{hpp,cpp}`. It is
deliberately decoupled from the main app's UI stack (no theme/font/settings
helpers) so the security tool can ship standalone — the embedding app passes
*options* (language, dark) and a grant factory; "defaults & store & options".

**Run it manually** (build first: `npm run build:cpp:security`):

```powershell
# An Ask decision (e.g. an LLM write outside policy) pops the modal dialog and
# blocks until you choose. The final verdict is printed to stdout as JSON.
# NOTE: --interactive/--gui belong to the `authorize` subcommand → AFTER it.
dist\win-x64\pm-image-security.exe --json authorize --interactive --gui --tool mcp.fs.write --action write --path .\report.csv --workspace . --intent "Save the exported sales report"

# Dark theme + German UI, bound to a session (Allow-for-session persists a grant):
dist\win-x64\pm-image-security.exe --json --dark --lang de --session demo-1 --config-dir .\.sec-demo authorize --interactive --gui --tool mcp.fs.write --action write --path .\report.csv --workspace .

# Then inspect what the dialog persisted:
dist\win-x64\pm-image-security.exe --json --config-dir .\.sec-demo grant list
```

Notes:
- Flag placement matters (CLI11): **global** flags (`--json`, `--dark`, `--lang`,
  `--session`/`--task`, `--config-dir`) go **before** the `authorize` subcommand;
  everything else — including `--interactive`, `--gui`, and the request flags
  (`--tool`, `--action`, `--path`, `--workspace`, `--intent`, `--uri`, `--server`) —
  belongs to `authorize` and goes **after** it. Putting `--interactive --gui` before
  `authorize` fails with *"arguments were not expected: --gui --interactive"*.
- `--gui` requires `--interactive`; without `--gui` the same `Ask` resolves over
  stdio (Phase 1.7). Without `--interactive` the gateway just returns the raw
  decision (no prompt).
- The dialog only appears when the decision is `Ask`. A read inside the workspace
  is allowed outright (no prompt); pick an action/path your active `--profile`
  escalates to consent (a write, or a path outside `--workspace`).

- [x] `show_consent_dialog(ConsentRequest, ConsentUiOptions)` + `Win32ConsentDelegate`.
      Renders title / risk (colour-coded) / tool+action / why / resource list /
      editable grant scope, with allow-once / allow-session / allow-task / deny /
      open-settings. Cancel/close → deny (safe default).
- [x] Self-contained DPI scaling (`GetDpiForWindow` + `MulDiv`), measured text
      layout (`DrawText DT_CALCRECT`), in-file i18n (en/de/es), minimal dark/light
      palette + immersive dark titlebar (`DwmSetWindowAttribute`). Pattern mirrors
      `src/win/ui_next/ProviderDlg.cpp` (in-memory `DS_SETFONT` template).
- [x] Wired into the CLI: `authorize --interactive --gui` selects the dialog
      delegate; global `--lang` / `--dark`. The grant factory (`build_consent_grant`)
      is shared with the stdio delegate so a GUI choice persists identically.
- [x] Buttons expose stable numeric AutomationIds (Allow once=1101, session=1102,
      task=1103, settings=1104; scope editor=1110) for UIA automation.
- [x] Tests: `npm run test:security-ui` (`test-security-ui.mjs`, 41 assertions) —
      launches the dialog and drives it through the same `assistant app-inspect dump`
      / `app-use batch` UIA bridge as `test-xblox-ui`: ready, structural inspect
      (title/risk/tool/prefilled scope), Deny→deny, Allow-session→persisted
      session grant, UIA `set-value` scope narrowing→persisted scope, and native
      sandbox-checkbox consent → persisted AppContainer grant → loopback `RunTool`
      route. SKIPs headless (PM_SECURITY_UI_REQUIRE=1 to enforce; PM_SECURITY_UI_INPUT=0 to skip clicks).
- [ ] `allowSecrets` / `maxFiles` / `maxBytes` still defined-but-not-enforced.
- [ ] Origin hash-binding (verify the real signed executable, not just basename).
- [ ] Reserve Win32 AutomationIds for "AI auto" buttons: `IDC_AI_AUTO_ONCE=1106`,
      `IDC_AI_AUTO_SESSION=1107`, `IDC_AI_AUTO_ALWAYS=1108` — add when
      `AiConsentDelegate` is wired and `ConsentUiOptions::aiAutoAvailable` is true.

## Phase 1.9 — Gateway integration into `pm_image_cmd_llm_agent.cpp` ✅ DONE

> Reconciled 2026-06-26: this phase is implemented and tested. The agent-loop
> intercept lives in `src/llm/agent_factory.cpp`; deterministic loopback tests
> cover consent, denial injection, no-reprompt caching, and sandbox grant routing.

**Goal:** every tool call the LLM agent makes passes through `SecurityGateway::authorizeWithConsent()`
before it reaches `media::llm::path::execute()`. No changes to the gateway or
PermissionStore. The original `--secure` opt-in sketch was replaced by the
compile-time `FEATURE_SECURITY_AGENT` gate, enabled by default in the security
builds.

> **Hard-limit / permission-gate split** (`hard_limits.hpp`, Phase 1.9b):
> `k_write_blocked_exts` = opaque binaries → always hard Deny.
> `k_write_elevated_risk_exts` = scripts/source → PolicyEngine raises to High/Ask.
> `AgentToolMapper` should feed extension risk into `ToolRequest.risk` so the
> gateway can escalate script writes without hard-blocking them.

### Context: where tool calls happen

```
pm_image_cmd_llm_agent.cpp
  run_llm_agent()
    loop:
      kbot LLM round → response carries tool_calls[]
        for each tool_call:
          Event::ToolCall fired
          ──► media::llm::path::execute(tool_name, arguments)   ← intercept here (path tools)
          ──► mcp_bridge::call_tool(server, function, arguments) ← intercept here (MCP tools)
          Event::ToolResult fired
```

The existing `llm_fs_guard_deny_reason()` guard runs inside `path::execute()` per
file. The gateway intercepts *above* that, at the tool-call level — so it can
prompt the user before any file I/O starts.

### Tool → ToolRequest mapping

Path tools are builtin; MCP tools carry a server id. Action is inferred from the
tool name. First entry of `arguments["paths"]` (or `arguments["inputs"]`) becomes
the `ResourceTarget`.

```
tool name           provider    action
──────────────────────────────────────
read_file           builtin     Read
list_images         builtin     Read
image_transform     builtin     Write   (outputs to arguments["output_path"])
write_file          builtin     Write
run                 builtin     Execute
audio_transcribe    builtin     Read
speak               builtin     Read
ocr_text            builtin     Read
image_understand    builtin     Read
image_create        builtin     Write
create_video        builtin     Write
mcp_<srv>__<fn>     mcp         (from fn name: read→Read, write/create→Write, …)
```

### Consent routing — the core idea (plumbing only for now)

The agent creates a `RoutingConsentDelegate` that *will* pick the best available
surface at runtime. For this pass we only put the plumbing in place:

```
Priority order (intended):
  1. ProcessKind::Ui  → (future) Win32 dialog in running tanit.exe
  2. ProcessKind::Web → (future) WebView / browser surface
  3. stdio            → CliConsentDelegate (the only surface wired now)
```

`cmd_ipc::list_instances()` is used **only as a presence check** — to detect that
a UI instance is alive. We do **not** route consent requests over IPC yet; even
when a UI is present, the router falls back to `CliConsentDelegate`. The presence
check is the seam where IPC-based routing (or a future `WebConsentDelegate`) plugs
in later, without touching the gateway or the agent loop.

### Secure-by-default — `FEATURE_SECURITY_AGENT` (compile-time)

**Decision (revised):** security is **on by default**, not opt-in. The original
opt-in `--secure` flag is replaced by:

- **Compile-time gate** `FEATURE_SECURITY_AGENT` (new top-level flag in
  `CMakePresets.json`, **default ON**). When ON: the security sources link into
  `pm-media` (today they only compile into the `pm-image-security` target) and the
  agent-loop intercept is compiled in. When OFF: zero overhead, security code not
  linked — restores today's behaviour for minimal/embedded builds.
  Wire as `target_compile_definitions(pm-media PUBLIC "FEATURE_SECURITY_AGENT=$<BOOL:...>")`
  (mirrors `FEATURE_LLM_RUN_STRICT`).
- No runtime `--insecure` escape hatch is currently exposed. Disable the feature
  at build time when an embedded/minimal build needs to omit the security agent.

When the secure path is active (compiled in):

1. A `SecurityGateway` is created (one per agent session, not per turn).
2. A `RoutingConsentDelegate` is wired in. It probes live `cmd_ipc` instances for
   UI presence (presence check only) and, for now, routes every consent to
   `CliConsentDelegate`.
3. The session id (`--session` or generated uuid) threads into every `ToolRequest`
   so Session-lifetime grants bind to this agent run and don't bleed across.
4. `Turn::task_id` (non-empty in scheduled tasks) maps to `taskId` in the request,
   so Task-lifetime grants expire with the task.

### Client-agnostic (confirmed)

The intercept lives at the **tool-dispatch seam** in `agent_factory.cpp`
(`path::execute()` / `mcp_bridge::call_tool()`, ~lines 828–847 / 1064–1067),
which is downstream of the **client seam** (loopback / llama / kbot, ~lines
419–590). All clients return the same `LLMResponse.tool_calls`, so the gateway
applies identically regardless of which model/router produced the call. Loopback
has **no special status** — it is purely a deterministic test client. MCP tool
calls route through the same intercept via `is_mcp_openai_function()`.

### Prerequisite — link security into `pm-media`

Today the security `.cpp` files are listed only under the `pm-image-security`
`EXCLUDE_FROM_ALL` target (CMakeLists ~3958–3975). Phase 1.9 must move them into a
shared static lib (e.g. `pm-security`) or append to `_pm_media_sources` under
`if(FEATURE_SECURITY_AGENT)`, so the CLI/UI link the gateway. The win32 consent
dialog (`ConsentDlg.cpp`) and DPAPI/ACL backends stay behind their own existing
sub-flags.

### Original file split (superseded)

```
src/security/RoutingConsentDelegate.hpp/.cpp  ← UI presence check + CLI routing (plumbing)
src/security/AgentToolMapper.hpp              ← tool name → Action (portable, no agent deps)
```

These ended up folded into the agent security plumbing in `agent_factory.cpp`
rather than created as standalone files.

### Todos

- [x] **`AgentToolMapper`**: original standalone-file plan was folded into
      `agent_factory.cpp` (`security_action_for_tool()` and
      `build_agent_tool_request()`). It maps path-tool catalog names and MCP
      function names to `pm::security::Action`; conservative fallback remains
      an elevated write-style request.

- [x] **`ToolRequest` builder (path tools)**: from `tool_name`, `arguments` JSON,
      workspace root, session id, task id. Extracts first path from
      `arguments["paths"]` or `arguments["output_path"]` into `ResourceTarget`.
      Inlines `arguments["reason"]` / `arguments["description"]` as `userVisibleIntent`.
      Implemented as `build_agent_tool_request()` in `agent_factory.cpp`.

- [x] **`ToolRequest` builder (MCP tools)**: parses OpenAI function name
      `mcp_<serverId>__<fnName>` into `provider=mcp`, `serverId`, `toolId`. Extracts
      resource paths from MCP arguments (best-effort; conservative fallback: scope `*`).
      Implemented in the same `build_agent_tool_request()` seam used by path tools.

- [x] **`RoutingConsentDelegate`**:
      original standalone-file plan was folded into the agent security plumbing:
      - Holds a `CliConsentDelegate` as the wired surface.
      - On `requestConsent()`: call `cmd_ipc::list_instances()` and record whether a
        live `ProcessKind::Ui` instance exists (**presence check only** — logged /
        exposed for diagnostics; not yet used to route).
      - Always delegates the actual consent to `CliConsentDelegate` for now.
      - The UI-presence result is the seam where IPC / web routing plugs in later.
      - When `FEATURE_COMMAND_IPC_NEXT` is off, the presence check is skipped and it
        behaves as a thin pass-through to `CliConsentDelegate`.

- [x] **Intercept point in the agent loop** (`Agent::run()`): before
      `path::execute()` and `mcp_bridge::call_tool()`, call
      `gateway.authorizeWithConsent(req)`. On `Deny`, skip the call and inject
      `{"ok":false,"error":"…","security_denied":true}` back as the LLM tool result.
      On `Allow`, proceed as today. Both serial and parallel dispatch seams covered.

- [x] **`FEATURE_SECURITY_AGENT` (compile-time, default ON)**: secure-by-default.
      Added to `CMakePresets.json` (vendor doc + cacheVariables = ON) and wired as a
      `pm-media` compile definition. No runtime `--insecure` flag — gate is compile-time
      only. Client-agnostic: loopback / llama / kbot / MCP all pass through the same seam.

- [x] **Link security sources into `pm-media`** under `if(FEATURE_SECURITY_AGENT AND WIN32)`
      (`_pm_media_sources` append). `pm-image-security` deduplicated: when the flag is ON,
      it only compiles `cli.cpp` + `ConsentDlg.cpp` and pulls the rest from `pm-media`.

- [x] **Grant persistence in agent context**: implemented through the normal
      `SecurityPersistence` store under the agent `--config-dir`, not the early
      `--storage grants.json` sketch. Session-bound grants and persisted sandbox
      backend flags are loaded by the loopback/agent path and reused by later calls.

- [x] **Consent serialisation during parallel dispatch**: pre-authorize all calls in the
      main thread before async launch (see `par_sec_decisions[]`). The consent delegate
      is never called from a worker thread. The CLI consent delegate is wired on the
      secure agent path; headless denial remains the safe fallback when no response is
      available.

- [x] **`llm_fs_guard_deny_reason()` stays as-is for now**: it is synchronous and
      runs inside `path::execute()`. The gateway intercepts *above* it, so for this
      pass both run (gateway first, guard second as belt-and-suspenders). Do NOT
      remove the guard — a sync replacement story is needed first (tracked in Phase 4).

### Test harness — loopback (dummy) router/model

Driving the secure agent through a real model is non-deterministic, slow, and
needs a GPU / API key — unusable in CI for security assertions. We need a
**loopback router** that replays a scripted sequence of `LLMResponse` objects so a
test can make the agent emit *exactly* the tool calls we want, then assert how the
gateway intercepts them.

**Where it plugs in:** `agent_factory.cpp` Phase-4 LLM call already branches on
`provider.router` — `use_local_llama = llama_client::is_llama_router(...)` vs the
kbot HTTP client. The loopback is a third sibling branch:

```cpp
const bool use_loopback = loopback_client::is_loopback_router(provider.router);
...
if (use_loopback)        resp = loopback_client::next_scripted_response(...);
else if (use_local_llama) resp = llama_client::execute_chat_messages(...);
else                      resp = kbot_client->execute_*(...);
```

**Script format** mirrors the fields the loop consumes from `LLMResponse`
(`text`, `tool_calls[].{id,name,arguments}`, `success`, `error`,
`reasoning_text`). One array entry per agent iteration; the loop pops the next on
each round:

```jsonc
// PM_LOOPBACK_SCRIPT (env) or --loopback-script <file>
[
  { "tool_calls": [
      { "id": "c1", "name": "write_file",
        "arguments": { "path": "report.csv", "content": "…",
                       "reason": "save the export" } } ] },
  { "text": "Done — saved the report." }   // final round: no tool_calls → loop ends
]
```

### Todos

- [x] **`loopback_agent_client.hpp/.cpp`** (`src/llm/`): `is_loopback_router()`
      (matches `"loopback"` / `"mock"`), plus `execute_chat_messages()` that pops
      the next entry from the loaded script and returns it as an `LLMResponse`.
      No model load, no network, no GPU. Honour `cancel_check` / `timeout_ms` for
      loop parity. When the script is exhausted, return a final empty-tool-calls
      response so the loop terminates cleanly.

- [x] **Script source**: load from `PM_LOOPBACK_SCRIPT` (inline JSON or `@file`)
      and/or inline JSON passed as the model field. `resolve_source` prioritises
      `[` (inline JSON) or `@` (file reference) over the model string; falls back to
      the `PM_LOOPBACK_SCRIPT` env var. Round index advances per agent iteration
      (process-local `ScriptState`; `reset_script()` for test isolation).

- [x] **Wire the branch into `agent_factory.cpp`**: sibling to `use_local_llama`,
      before the kbot path. `is_loopback_router()` matches "loopback" / "mock";
      a non-loopback router string can never accidentally reach the loopback branch.

- [x] **API key exemption**: `pm_image_cmd_llm_agent.cpp` skips the "api_key empty"
      error for router == "loopback" / "mock" (same as "llama"), so tests run
      offline without credentials.

- [x] **Tests** (`suiteLoopbackAgent` in `test-security.mjs`, 9 cases, 32 assertions):
      - Immediate text response (no tool calls).
      - Empty script terminates cleanly.
      - `write_file` tool call + final text (2-round sequence).
      - Two consecutive `write_file` tool calls.
      - Scripted tool call on a secret path (security deny handled gracefully by loop).
      - `@file` script reference via `PM_LOOPBACK_SCRIPT` env var.
      - **`run` tool denied** by `validate_command` (privilege escalation `sudo`).
      - **`run` tool allowed** → command executes, stdout marker captured.
      - **`run` tool denied** by `validate_command` (registry write — distinct validator).
      All deterministic and offline; temp-file workaround for PowerShell quoting.
      `npm run test:security` = 182 assertions green.

- [x] **Permission-gated agent tests**: tests that drive the
      loopback agent with a scoped grant in a `--config-dir` store and assert the
      gateway allows/denies `run` / `write_file` accordingly. Covered by
      `suiteAgentConsent`, `suiteLoopbackSandbox`, and the GUI sandbox route test.

## Phase 1.9b — Security foundation clean-up

Tighten the three core security source files so they build on shared infrastructure
instead of duplicating platform and sanitization logic.

### `Origin.cpp` — cross-platform exe detection

- [x] Replace the inline `GetModuleFileNameW` block in `current_process_origin()`
      with `media::app::exe_executable()` (`core/app_exe_directory.hpp`).
      Result: cross-platform (win32 / macOS / Linux) without conditional compilation
      in Origin.cpp; removes `<windows.h>` include from this translation unit.

### `PathSecurity.cpp` — reference shared sanitizers

- [x] Include `core/string_sanitizers.hpp` (for the backslash-normalisation approach
      mirrored in `media::str_san::clean_path`) and `core/path_sanitizer.hpp`
      (for the `sanitize_subpath` / `validate_path_spec_for_input_selection` API).
- [x] Extract `normalize_scope_pattern()` helper: mirrors `str_san::clean_path`'s
      first step (backslash → forward-slash, collapse double-slashes) while
      preserving leading `/` anchors needed by absolute-path glob patterns. Keeps
      the lowercase step so pattern and target use the same collation.
- [x] `normalizeForMatch` now delegates the backward-slash step to the same helper,
      annotated with a reference to `str_san`. Removes the duplicate `std::transform`
      + `std::replace` in `matchesAnyScope`.

### `security_default.hpp` — hard-limit tables

- [x] Create `src/security/hard_limits.hpp`: self-contained (no `media/probe.hpp`,
      no UI headers) constexpr tables under `pm::security` for the LLM FS deny lists.
      Design rule — **hard limit vs permission gate**:
      - Scripts and source-code are NOT hard-blocked by extension; they are gated
        through the PolicyEngine (Ask / High-risk consent, `k_write_elevated_risk_exts`).
      - Hard limits fire on opaque binary/executable formats OR when the target
        directory is protected — the "combine" rule: directory check fires first and
        produces an unconditional Deny regardless of extension.
      - `k_sensitive_path_prefixes` — secret/system path deny list (all platforms)
      - `k_write_blocked_exts` — opaque binary/executable/package exts: always Deny
      - `k_write_elevated_risk_exts` — scripts & source: permission-gated (Ask/High risk)
      - `k_write_blocked_abs_prefixes` — absolute path prefixes always denied for writes
      - `k_read_blocked_exts` — extensions blocked from LLM glob/read
      - `k_shell_exec_blocked_exts` — extensions that ShellExecute "open" must not run
- [x] `security_default.hpp` includes `security/hard_limits.hpp` after the feature-flag
      defaults — security consumers get the tables without a separate include.
- [ ] **Future (`Delegate migration`)**: `llm_fs_guard.cpp`, `RunTool.cpp`,
      `path_tool_executor.cpp` / `FsTools.cpp` migrate to use `pm::security::k_*`
      tables as the authoritative source; the duplicate `pmui::k_*` tables in
      `file_extensions.hpp` are then deleted. Tracked in the "Delegate migration"
      section at the bottom of this file.

## Phase 1.10 — AI consent delegate (`AiConsentDelegate`) — DEFERRED

> Not in the current pass. Phase 1.9 only puts the routing/intercept plumbing in
> place. The items below are the planned shape for when we add AI approvers.
> Explicitly **out of scope for now**: AI advisory mode (AI enriching the human
> prompt) and audit-log wiring — both deferred until the plumbing is proven.
>
> **2026-07-01 update:** full `AiConsentDelegate` execution remains deferred.
> Keep the implementation notes in this section for later doc extraction. The
> completed items below are supporting data/UI/CLI plumbing only, not an active
> autonomous approval tier.

An autonomous consent tier that reviews `ConsentRequest` using a configured chat
preset (local llama or remote API) and returns a `ConsentResult` without human
input. Sits above the human tiers in `RoutingConsentDelegate` for low-risk
decisions — reducing interrupts while keeping humans in the loop for anything High
or Critical.

**Why the interface already fits:** `ConsentDelegate::requestConsent()` has no
assumption about who answers. `ConsentRequest` carries all structured fields the
AI needs. `PermissionStore::put()` enforces invariants regardless of approver.

### Design constraints

- **Async execution:** `requestConsent()` is nominally blocking. The AI delegate
  wraps a `std::future` + polling loop internally. Caller thread blocks; AI call
  runs async. Retry + exponential backoff on transient model errors. Hard timeout
  (configurable, default 10s). On timeout → `ConsentResult{Deny}` so the routing
  delegate falls through to the next tier (not a bare deny to the gateway).

- **Lifetime ceiling (per-preset, configurable):**

  ```
  risk        AI may grant up to
  ──────────────────────────────
  Low         Task (or Session if explicitly configured)
  Medium      Once
  High        deny (skip to human tier)
  Critical    deny (skip to human tier)
  ```

  The ceiling is enforced in `AiConsentDelegate` before calling `put()`.
  `is_never_permanent` / `is_never_persistable` are still enforced by
  `PermissionStore::put()` as a second safety net.

- **Provenance field:** AI-approved grants carry `approvedBy = "ai:<preset-name>"`
  (new `CapabilityGrant::approvedBy` field); human-approved grants carry
  `approvedBy = "human"`. (Audit-log wiring of these events is deferred — Phase 3.)

- **Structured prompt:** the delegate builds a prompt from `ConsentRequest` fields
  only — never from raw LLM tool call arguments or user text. The AI is asked to
  return a JSON object matching the `consent_reply` wire format.

- **Preset selection:** configured per agent run via `--ai-consent-preset <name>`.
  When unset, `AiConsentDelegate` is disabled and the routing delegate skips it.
  The preset is resolved via the same `AgentLaunchSpec` machinery as the agent's
  own model — so local llama and remote models are both supported.

### Routing integration

`RoutingConsentDelegate` gains a `riskCeilingForTier` config:

```
tier                 risk ceiling   action on ceiling breach
──────────────────────────────────────────────────────────
AiConsentDelegate    Medium         skip to next tier (human)
(UI / web — future)  Critical       handle all
CliConsentDelegate   Critical       handle all (final fallback)
```

### Todos

- [x] **`CapabilityGrant::aiDelegated`** (bool, default `false`) and
      **`CapabilityGrant::approvedBy`** (string, default `"human"`) — add to
      `types.hpp`; include in JSON (de)serialisation and `PermissionStore::put`.
      `aiDelegated=true` grants are valid; `put()` accepts them. (Audit-log wiring
      of these fields is deferred — Phase 3.)
- [ ] **`SecurityGateway` routing on `aiDelegated` grants**: after `find()` returns
      a grant, check `grant.aiDelegated`. If true, route to `AiConsentDelegate`
      with the original request; if AI allows → emit `Allow`; if AI denies →
      escalate to human tier (configurable: `deny` or `ask`). If false, existing
      `Allow` path unchanged.
- [x] **`ConsentResult::aiDelegated`** flag — set by UI surfaces when the user
      picks an "AI auto" lifetime. The gateway's `resolveConsent()` copies the flag
      onto the grant before calling `put()`.
- [x] **"AI auto" on all three consent surfaces** (see surface-specific items below).
      CLI stdio, native Win32, and IPC/web surface plumbing are wired. This is
      still provenance/UI plumbing only; active model-backed `AiConsentDelegate`
      execution remains deferred.
- [x] **AI review/advisory display shape**: web consent payload supports an
      optional `aiReview` block with assessed risk, risk escalation flag, reason,
      notes, and a recommendation. The shared `ConsentCard` displays the review
      and offers "Apply recommendation" to prefill scope/lifetime/sandbox choices.
      Applying the review keeps approval human-controlled and records
      `aiReviewApplied` rather than silently delegating.
- [x] **CLI advisory SecurityAgent review lifecycle**: `llm agent` supports
      `--ai-consent-review`, `--ai-consent-router`, and `--ai-consent-model`.
      In headless CLI mode, consent requests first run the tool-less
      `SecurityAgent` reviewer and emit `ai_consent_review` /
      `ai_consent_review_error` JSON events on stderr. The review is advisory:
      the normal `CliConsentDelegate` prompt still requires explicit human input.
      Tests can inject deterministic review JSON with `PM_AI_CONSENT_REVIEW_JSON`
      when `FEATURE_COMMAND_TEST` is enabled.
- [x] **Chat/WebView advisory SecurityAgent review lifecycle**: the shared
      `ConsentCard` posts `aiConsentReviewRequest` when the user clicks Review;
      `ChatWebPanel_Consent.cpp` starts a contained reviewer worker and posts
      `pm_host_event/security.consent.reviewResult` back to the same card.
      The review remains advisory: the user must still apply/allow, and
      `PM_AI_CONSENT_REVIEW_JSON` is test-feature gated.
- [x] **Shared SecurityAgent review helper**: `src/llm/security_review.hpp/.cpp`
      owns consent-request serialization, security router/model resolution from
      chat settings, reviewer execution, JSON extraction, error-review shaping,
      and the test-only `PM_AI_CONSENT_REVIEW_JSON` hook. CLI advisory review and
      WebView advisory review now call this common helper instead of maintaining
      separate SecurityAgent lifecycle implementations.
- [x] **Per-request AI security eligibility mapping**: `SecurityGateway.cpp`
      computes `ConsentRequest::aiAutoAvailable` from tool/action/target instead
      of letting UI surfaces hard-code availability. Covered families: shell
      execute (`cmd://`), file/generated-artifact writes, screenshots/camera
      captures, schedulers/custom commands, and computer-use/screen tools
      (`screen://`). Plain read-only consent remains human-only.
- [x] **Security sidecar memory items**: AI review outputs and final consent
      decisions are persisted into session memory as structured `items` with
      roles `security_review` / `security_decision`. They intentionally live
      beside file artifacts instead of inside `artifacts`, so the future security
      sidecar can harvest request/decision/reason/risk fields into embeddings.
- [x] **Advisory review timeout surface**: no retry/backoff wrapper for the
      review path. The reviewer uses the configured provider timeout (default
      10s); the WebView card shows a timeout/error state when no result arrives,
      and CLI emits `ai_consent_review_error` then falls back to normal human
      consent. This is intentionally simpler than autonomous delegate timeout
      handling.
- [x] **Advisory review cancellation / ownership notes**: CLI review runs through
      `SecurityAgent` with the normal `cancel_requested()` callback, so Ctrl+C
      follows the existing agent-factory cancellation path. WebView review is
      owned by a detached reviewer worker: app close / stop cancels the pending
      consent promise and dismisses the UI; already-started review work may still
      finish or provider-timeout, and its late result is harmlessly ignored by the
      dismissed card path.
- [ ] **Follow-up: realtime/voice agent process cleanup**: voice sessions that
      launch default agents can leave zombie child processes on stop/close. This
      is not specific to SecurityAgent, but the same lifecycle expectation should
      apply: cancel signal propagation, provider/request abort where supported,
      and child-process teardown on owner destruction.
- [ ] **Future autonomous `AiConsentDelegate` skeleton**: separate from advisory
      review. Takes a preset name + ceiling config; when preset is empty,
      `requestConsent()` immediately returns `Deny`/fall-through. No partial
      state when disabled.
- [ ] **Future autonomous delegate timeout policy**: no retry/backoff for v1.
      Show/record timeout and fall through to human consent. If later needed,
      add bounded retry only for explicit transient provider errors.
- [ ] **Future autonomous `consent_reply` prompt builder**: serialises
      `ConsentRequest` → compact JSON and asks the model for a strict
      `consent_reply` object. This is approval-routing output, not the current
      advisory `aiReview` shape.
- [ ] **Future autonomous `consent_reply` parser**: strict safe-default parser.
      If output is not valid `consent_reply` JSON or `kind` is not `allow` /
      `deny`, return `Deny` / fall through to human consent.
- [ ] **Future autonomous ceiling routing**: inject as first tier only when
      configured; skip the AI tier when `request.risk > ceiling` and go straight
      to human consent.
- [ ] Future `--ai-consent-preset` flag on the secure `llm agent` path.
- [x] **"AI auto" in `CliConsentDelegate`**: accept new tokens
      `ai_auto_once` / `ai_auto_session` / `ai_auto_always` from stdin, or
      `{"choice":"ai_auto","lifetime":"session","scopes":[…]}` JSON form.
      Emits the option in the stderr consent prompt; currently available as
      provenance plumbing, not a live model delegate.
- [x] **"AI auto" in `Win32ConsentDelegate`** (`ConsentDlg.cpp`): extend the
      button grid from 2×2 to 2×3 — add `IDC_AI_AUTO_ONCE` (1106),
      `IDC_AI_AUTO_SESSION` (1107), `IDC_AI_AUTO_ALWAYS` (1108). Hide the row when
      `ConsentUiOptions::aiAutoAvailable = false`. Add `aiAutoAvailable` to
      `ConsentUiOptions`. Remaining follow-up: hide `IDC_AI_AUTO_ALWAYS` for
      `never_permanent` actions (same rule as IDC_ALLOW_ALWAYS).
- [x] **"AI auto" in the IPC / web wire format**: add
      `"aiAutoAvailable": bool` so web surfaces know whether to render the AI auto
      tier; the reply carries `"aiDelegated": true` when chosen. The same wire
      shape now accepts optional `"aiReview": {...}` and replies may include
      `"aiReviewApplied": true` when the user applies the advisory recommendation.
- [x] CLI tests: mock the reviewer response; assert advisory review event is
      emitted; assert human deny still blocks an allow recommendation; assert
      invalid review output emits `ai_consent_review_error` and falls back to
      normal consent; assert `ai_auto_session` persists `approvedBy` +
      `aiDelegated` fields.
- [ ] Future autonomous delegate tests: assert ceiling enforcement (Medium risk
      → AI handles; High risk → skips to human tier); assert timeout → falls
      through to human consent; assert invalid AI response → Deny/fall-through;
      assert that a second matching `aiDelegated` grant routes to AI without
      surfacing the UI.

## Phase 1.11 — Session persistence over secure storage

Goal: move chat/agent session persistence onto the same secure-storage resource
model used for prompts and other signed local documents. Keep the current
`config_dir/sessions` default for now, but do not carry a long-term
back-compatibility burden for legacy session JSON once the new store is enabled.

This is design/TODO only for now. The implementation should land as a shared
library surface that works for CLI, Win32 UI, and WebView UI. Do not create a
UI-only session store.

### Design constraints

- Keep the current default path: `config_dir/sessions` while the feature is
  unset. Once secure session persistence is explicitly enabled, prefer a clean
  new storage shape over compatibility shims for old session files.
- Session storage must be configurable by settings. Enterprise policy/GPO is
  deferred until the storage shape is settled; do not design the first pass
  around policy plumbing.
- Configured storage roots may be local paths or UNC shares. UNC support needs
  explicit path normalization, availability/error reporting, and a clear stance
  on which protection modes are allowed for remote storage.
- Treat sessions as a secure-storage asset type at the same level as prompt
  documents. `scripts/assets/import-plain.sh` currently imports prompt assets
  with `prompt-store import-plain`; session seed/import support should follow
  that resource/document pattern rather than inventing a parallel bundle path.
- Encryption level must be configurable, including plaintext. Plain mode stays
  supported for deterministic tests, local debugging, and log inspection.
  Test-only shortcuts should be gated by `FEATURE_COMMAND_TEST`, matching the
  existing command-test build model.
- The owning implementation surface is expected to be
  `src/llm/chat_session_store.hpp/.cpp` or a small adapter below it. The public
  call sites should continue using the chat session store APIs, while the store
  decides whether to use legacy files or `pm::storage` documents.
- Storage defaults and policy discovery likely need entries near
  `src/security/security_default.hpp`, with any app/profile path constants kept
  aligned with `src/constants.hpp` and generated branding defaults from
  `src/pm_branding_config.hpp.in`.
- Session persistence is not only transcript load/save. It must support
  low-level querying of the whole session directory/resource namespace for
  memory items, artifacts, agent logs, consent/security sidecar items, and
  future embedding harvesters.
- Session stores need a first-class pruning mechanism. Retention must be able to
  remove old transcripts, memory items, artifacts, and logs without corrupting
  indexes or leaving dangling secure-storage manifests/blobs.

### Proposed resource shape

Use secure-storage document URIs so sessions can be listed, verified, migrated,
and exported with the same primitives as prompts:

```text
pm://session/<session-id>
pm://session-memory/<session-id>
pm://session-artifact/<session-id>/<artifact-id>
pm://session-log/<session-id>/<log-id>
```

Open question: whether transcript, memory, artifacts, and logs are separate
documents from day one or whether the first pass stores a compact session index
plus legacy file references. Prefer separate documents once encryption is on,
because memory/artifact harvesting needs selective listing without loading every
full transcript.

Protection policy should be explicit:

```text
plain          readable JSON; tests/debug/default mode
signed         integrity only; useful for vendor/demo seed sessions
encrypted      local user protected storage, no user-presence prompt by default
encrypted+up   local user protected storage with user-presence challenge
```

Encryption does not imply trust. Imported session resources still need normal
trust/provenance metadata and should never auto-enable privileged tool grants.

UNC nuance: remote session roots are allowed as a configuration target, but the
first implementation should fail clearly when a requested protection mode cannot
be honored on that root. Do not silently downgrade encrypted storage to plain.

### Low-level query interface

Add a storage-level/session-level enumeration API that can answer questions like:

- list all sessions with lightweight metadata;
- list all memory items for a session without loading the transcript;
- list all artifacts and generated files for a session;
- list all security review / consent sidecar items across sessions;
- load one item by stable id/digest;
- stream or page results for large session stores;
- report protection/trust/digest metadata for each returned item.

This should live below the UI and CLI entry points so the future security
sidecar and embedding harvester can use the same query path as the app.

### Todos

- [x] **Session storage settings shape**: define settings fields for backend
      (`legacy-files` / `secure-storage`), root override, retention/pruning, and
      protection mode (`plain`, `signed`, `encrypted`, `encrypted+up`). Keep
      current `config_dir/sessions` as the default when unset. Implemented under
      `security.secureStorage.sessions`; env overrides remain for
      `FEATURE_COMMAND_TEST` probes.
- [ ] **UNC root support**: accept UNC paths as configured session roots, with
      normalization, create/list/write/delete probes, clear offline/error
      reporting, and explicit protection-mode validation for remote paths.
- [x] **Defaults/constants wiring**: add secure session persistence defaults near
      `src/security/security_default.hpp`; keep path naming consistent with
      `src/constants.hpp` and branding defaults in `src/pm_branding_config.hpp.in`.
      Defaults now come from `pm::security::k_session_storage_*` constants and are
      surfaced by `verification defaults`.
- [x] **Secure-storage resource type**: extend the model/resource schema with
      session-oriented document types at the same level as prompt assets
      (`SessionTranscript`, `SessionMemory`, `SessionArtifact`, `SessionLog` or
      equivalent).
- [ ] **Plain import/export path**: extend the asset import tooling after
      `scripts/assets/import-plain.sh` patterns so plaintext session seeds can be
      imported for tests/debug without bypassing manifest/index metadata.
- [x] **`chat_session_store` adapter**: keep the public APIs in
      `src/llm/chat_session_store.hpp` stable for CLI/UI callers, but route
      `load`, `save`, `list_meta`, `remove`, and host-field merges through the
      selected backend. First slice is env-selected (`PM_CHAT_SESSION_STORE`)
      until the settings shape lands.
- [x] **No legacy compatibility shims**: when secure storage is enabled, use the
      new store shape directly. A one-shot developer migration tool can be added
      later if useful, but runtime read-through of old JSON session files is not
      required.
- [x] **Protection modes**: implement plaintext, signed-only, encrypted, and
      encrypted-with-user-presence policies using `src/storage/secure_storage.hpp`
      primitives. Tests may force plaintext deterministically only in
      `FEATURE_COMMAND_TEST` builds. `signed` stores readable JSON with a secure
      document signature; `encrypted` / `encrypted+up` route through encrypted
      secure-storage documents.
- [x] **Pruning mechanism**: add retention/prune support for whole sessions and
      per-session children. Pruning must update indexes, remove unreachable
      manifests/blobs where safe, and report what was removed. First slice
      covers whole secure session documents; blob garbage collection can be
      tightened later if documents gain separate children.
- [x] **Whole-store query API**: add a low-level interface that lists sessions,
      memory items, artifacts, logs, and security sidecar items with stable ids,
      digests, trust/protection metadata, and paging.
- [x] **Security sidecar harvesting**: ensure `security_review` and
      `security_decision` memory items remain first-class query results, not only
      nested transcript data.
- [x] **CLI tests**: focused `pm-image-security session-store` coverage in
      `tests/orchestrator/test-secure-storage.mjs` covers default signed+
      encrypted secure storage, settings-backed `signed` mode, test-only
      `plain` mode, query, delete, and prune. Do not pursue legacy persistence
      coverage in `test-agent.mjs`.
- [ ] **Lifecycle tests**: extend
      `tests/orchestrator/test-agent-lifecycle.mjs` to cover session creation,
      resume/list/delete, backend switching, and migration behavior.
- [x] **Secure-storage tests**: extend
      `tests/orchestrator/test-secure-storage.mjs` for session document put/list/
      load/verify/delete, including plaintext mode and encrypted mode where the
      platform/test backend supports it.
- [x] **Pruning tests**: cover retention-based pruning and explicit delete/prune
      commands, including index cleanup and artifact/log removal.
- [x] **Command-test gating**: keep plaintext-force knobs and mock storage
      shortcuts behind `FEATURE_COMMAND_TEST`; production builds should not
      expose test-only weakening flags.
- [x] **Future GPO/policy design**: first managed-policy slice adds HKLM-only
      controls for session storage root, protection mode, signature requirement,
      and encryption requirement. Import/export remains out of scope; UNC
      validation and richer retention policy stay as follow-up items.

### GPO design — session storage

Managed policy should clamp session persistence without adding friction to the
low-level `chat_session_store` call sites. The store should always expose the
same `load` / `save` / `list_meta` / `query_store` / `prune` surface; policy only
changes the resolved backend, root, protection, and retention values.

Implemented first-slice policy keys:

```text
SessionStorage.Root               <empty | local path | UNC path>
SessionStorage.Protection         signed | encrypted | encrypted+up
SessionStorage.RequireSigning     true
SessionStorage.RequireEncryption  true unless Protection=signed
```

Resolution rule:

```text
built-in secure defaults
  < user settings security.secureStorage.sessions
  < HKLM policy
```

Policy may strengthen or force settings, never weaken them:

- A managed `Protection=encrypted` or `encrypted+up` must override user `plain`
  and `signed`.
- A managed `RequireSigning=true` must keep signatures required for every
  session document.
- A managed root override wins over user settings and test env overrides.
- Plain text is not exposed as a GPO option; managed policy can only select
  `signed`, `encrypted`, or `encrypted+up`.

Deferred keys/details:

```text
SessionStorage.AllowUncRoot       true | false
SessionStorage.PruneKeepLatest    0 | N
SessionStorage.MaxSessions        N
SessionStorage.DisableUserRoot    true | false
```

UNC roots should eventually be validated explicitly; unavailable shares should
fail closed with a clear error and never fall back to local plaintext.

Tests later:

- policy fixture forces secure-storage + encrypted and user settings cannot
  select `plain`;
- HKLM beats HKCU;
- policy root beats settings root;
- UNC disallowed rejects a UNC settings root;
- prune policy is visible through the same `session-store prune` result shape.

### Easy session query interface

`chat_session_store::query_store()` is the low-level typed snapshot. It should
stay cheap and boring: resolve the active session storage policy first, then
query only that resolved store. It must not scan unrelated profile locations,
legacy directories, xblox state, or raw secure-storage internals.

For now this query interface lives only in the library. CLI/UI surfaces can call
it for diagnostics, but the filtering/query semantics should remain owned by the
session-store library until the shape settles. Do not route this through xblox
yet.

The low-level output is JSON containing:

```text
backend
root
sessions[]
memoryItems[]
artifacts[]
securityItems[]
sessionCount
memoryItemCount
artifactCount
securityItemCount
```

Future library query shape:

```text
query_store()
query_store({ filter: securityItems })
query_store({ filter: memoryItems, role: security_review })
query_store({ sessionId: <id> })
query_store({ kind: <kind> })
```

Typed aliases can keep UI and sidecars from depending on jq strings for common
cases:

```text
allSessions
allMemoryItems
allArtifacts
securityItems
securityReviews
securityDecisions
sessionById(<id>)
itemsByRole(<role>)
itemsByKind(<kind>)
```

Implementation notes:

- Keep the query engine read-only and side-effect free.
- It assumes storage has already been resolved: backend, root, protection mode,
  and policy are not query parameters.
- Query only session documents/items visible through the resolved
  `chat_session_store` backend.
- Do not walk arbitrary `config_dir` trees or inspect secure-storage manifests
  directly from this layer.
- Return both unfiltered counts and filtered results once filters are added, so
  operators can see how much the query narrowed the set.
- UI/CLI can add presentation helpers later, but common filters should remain
  typed aliases rather than raw query strings.
- A future xblox/data-block adapter may call this library surface, but xblox is
  not part of the session query design yet.

## Phase 2 — In-app WebView consent surface + Grants UI

> **Status:** WebView inline consent is implemented and wired. CLI stdio consent
> remains the fallback (`CliConsentDelegate`). The settings tab shell is present;
> real grants-list/revoke backing and WebView automation tests remain open below.

### Background: the `ask_user` reference pipeline

```
C++ agent thread                   JS / React
────────────────────────           ──────────────────────────────────────────
pm::llm::inquire::ask(Question)
  → set_ui_backend() callable      window.pmChat.askUser({reqId,kind,...})
  → ExecuteScript to WebView     →   pmChatStore.appendAsk()
  → blocks on std::promise<json>     <AskUserInline> renders in transcript
                                     submitAsk(reqId, payload)
                                   → {kind:"askUserReply", reqId, ...} to host
  ← ResolveAskUserReply(j)        ← WindowProc dispatches by kind
  ← promise.set_value(j)
```

The consent pipeline mirrors this exactly, replacing `ask_user` with `consent`.
The key difference: consent comes from `SecurityGateway::resolveConsent()` in the
**agent loop**, not from an LLM tool call. The JS form is a security-specific card
(risk badge, tool identity, resource list, lifetime picker) not a generic Q&A form.

### 2a — C++: global consent delegate registry + WebViewConsentDelegate

The agent loop in `agent_factory.cpp` currently hard-codes `CliConsentDelegate`.
To pick the right surface at runtime (WebView when the panel is live, CLI otherwise),
we need a global registry parallel to `pm::llm::inquire::set_ui_backend`.

- [x] **`src/security/ConsentDelegateRegistry.hpp/.cpp`** — global thread-safe
      registry with three functions:
      ```cpp
      void pm::security::set_active_consent_delegate(ConsentDelegate* d);
      void pm::security::clear_active_consent_delegate();
      ConsentDelegate* pm::security::active_consent_delegate() noexcept; // null = CLI fallback
      ```
      Mirrors `pm::llm::inquire::set_ui_backend` / `clear_ui_backend` / `ui_backend_active`.
      Only one delegate slot; the latest installer wins (same single-panel rule as inquire).
      Add sources to `_pm_media_security_sources` in `CMakeLists.txt`.
      Implemented and wired into `pm-media` sources.

- [x] **`src/win/ui_next/ChatWebPanel_Consent.cpp`** (new, parallel to
      `ChatWebPanel_AskUser.cpp`) — WebView-side `ConsentDelegate` implementation:

      ```cpp
      class WebViewConsentDelegate final : public pm::security::ConsentDelegate {
      public:
          explicit WebViewConsentDelegate(CChatWebView::Impl* impl);
          pm::security::ConsentResult requestConsent(
              const pm::security::ConsentRequest& cr) override;
      };
      ```

      Internal flow mirrors `InquireBackend` in `ChatWebPanel_AskUser.cpp`:
      1. Mint `reqId` (same `make_req_id()` helper).
      2. Serialise `ConsentRequest` → native review JSON + UI payload JSON (see wire format below).
      3. Post `pm_host_event/security.consent.request` via `PostWebMessageAsString`.
      4. Register `reqId → PendingConsent{promise, request_json}` in `pending_consents` (under `pending_consents_mu`).
      5. Block: `auto j = pending_consents[reqId].promise.get_future().get()`.
      6. Decode JSON reply → `ConsentResult` (see reply format below).
      7. If the user chose `open_settings`, post `{kind:"openSettings",tab:"security"}` to host before returning.

      **Wire format — request** (`pm_host_event/security.consent.request`):
      ```jsonc
      {
        "reqId": "ask-1750000000000-0",
        "event": "consent_request",
        "title": "Allow Write?",
        "risk": "high",                      // low | medium | high | critical
        "action": "write",                   // read | write | execute | network | …
        "tool": "builtin.write_file",
        "provider": "builtin",
        "whyNeeded": "write outside workspace requires consent (DEVELOPER)",
        "possibleRisk": "high risk",
        "resourcePreview": ["C:/Users/zx/Documents/secret.txt"],
        "choices": ["allow_once","allow_session","deny","open_settings"],
        "isNeverPersistable": false          // Execute/Delete/GitPush/Publish/Upload = true
      }
      ```

      **Wire format — reply** (`{kind:"consentReply", reqId, …}`):
      ```jsonc
      { "kind": "consentReply", "reqId": "ask-…", "choice": "allow_session",
        "lifetime": "session",   // once | session | task (default = maps from choice token)
        "scopes": ["C:/Users/zx/Documents/*.txt"]  // optional narrowed scope
      }
      ```
      Safe default on close/cancel/Escape = `{choice:"deny"}`.
      Implemented with pending promise map, typed host-event delivery,
      reply decoding, sandbox backend validation, and teardown cancellation.

- [x] **`src/win/ui_next/ChatWebPanel_internal.hpp`** — add to `Impl`:
      ```cpp
      struct PendingConsent {
          std::promise<nlohmann::json> promise;
          std::atomic<bool>            done{false};
      };
      std::mutex pending_consents_mu;
      std::unordered_map<std::string, std::unique_ptr<PendingConsent>> pending_consents;

      void InstallChatConsentDelegate();
      void ClearChatConsentDelegate();
      void ResolveConsentReply(const nlohmann::json& j);
      void CancelAllConsents(const std::string& reason);
      ```

- [x] **`src/win/ui_next/ChatWebPanel.cpp`** — in `InstallChatInquireBackend()` site,
      also call `impl->InstallChatConsentDelegate()`. In the `WindowProc` IPC switch:
      ```cpp
      else if (kind == "consentReply") {
          m_impl->ResolveConsentReply(j);
      } else if (kind == "openSettings") {
          // open settings WebView on "security" tab
          const std::string tab = j.value("tab", std::string{"security"});
          // reuse existing "openSettings" host action or navigate CSettingsWebView
      }
      ```
      In `ClearChatInquireBackend()` teardown, also call `impl->ClearChatConsentDelegate()`.
      In `CancelAllAskUser`, pair with `CancelAllConsents("cancelled")`.
      Implemented with `consentReply` dispatch and `openSettingsForConsent` routing
      to the settings bus with `section:"security"`.

- [x] **`agent_factory.cpp`** — replace the hard-coded `CliConsentDelegate` with
      registry-aware selection:
      ```cpp
      pm::security::CliConsentDelegate cli_consent(/*json_mode=*/true);
      pm::security::ConsentDelegate* active_delegate =
          pm::security::active_consent_delegate()   // WebViewConsentDelegate when panel live
              ? pm::security::active_consent_delegate()
              : &cli_consent;                        // fallback: stdio
      pm::security::SecurityGateway sec_gateway("pm-image", active_delegate);
      ```
      This makes the agent surface-agnostic: WebView panel = inline card,
      headless/CLI = CliConsentDelegate on stderr, no panel = CliConsentDelegate.

### 2b — TypeScript: shared security types

- [x] **`apps/shared/security/types.ts`** — TypeScript mirror of `security-schema-1`
      (already emitted by `pm-image-security --json schema`). Matches field-for-field
      so the React components typecheck against the live wire format:

      ```ts
      export type SecurityRisk = "low" | "medium" | "high" | "critical";
      export type SecurityAction = "read" | "write" | "execute" | "network"
                                 | "download" | "delete" | "git_push" | "publish" | "upload";
      export type GrantLifetime = "once" | "session" | "task" | "permanent";
      export type ConsentChoice = "allow_once" | "allow_session" | "allow_task"
                                | "deny" | "open_settings";

      export type ConsentRequestPayload = {
        reqId: string;
        title: string;
        risk: SecurityRisk;
        action: SecurityAction;
        tool: string;
        provider: string;
        whyNeeded: string;
        possibleRisk: string;
        resourcePreview: string[];
        choices: ConsentChoice[];
        isNeverPersistable: boolean;
      };

      export type CapabilityGrant = {
        id: string;
        tool: string;
        provider: string;
        action: SecurityAction;
        resourceScopes: string[];
        lifetime: GrantLifetime;
        sessionId?: string;
        taskId?: string;
        reason: string;
        policyVersion: string;
      };

      export type ConsentReplyPayload = {
        kind: "consentReply";
        reqId: string;
        choice: ConsentChoice;
        lifetime?: GrantLifetime;
        scopes?: string[];
      };
      ```
      Implemented as the current wire contract used by `ConsentCard`, chat store,
      and settings grants UI.

- [x] **`apps/shared/security/riskColors.ts`** — risk → Tailwind colour tokens:
      ```ts
      export const RISK_COLORS = {
        low:      { badge: "bg-emerald-500/15 text-emerald-700 border-emerald-400/50", icon: "…" },
        medium:   { badge: "bg-amber-500/15  text-amber-700  border-amber-400/50",    icon: "…" },
        high:     { badge: "bg-orange-500/15 text-orange-700 border-orange-400/50",   icon: "…" },
        critical: { badge: "bg-rose-500/15   text-rose-700   border-rose-400/50",     icon: "…" },
      } satisfies Record<SecurityRisk, { badge: string; icon: string }>;
      ```

### 2c — Shared components

- [x] **`apps/shared/components/security/ConsentCard.tsx`** — pure presentational card,
      no store dependencies, fully typed against `ConsentRequestPayload`. Renders:

      1. **Risk badge** — colour-coded chip from `RISK_COLORS[risk]` with a shield icon
         and risk label (Low / Medium / High / Critical).
      2. **Tool identity row** — `provider` icon chip + `tool` name in monospace.
      3. **Action row** — `action` humanised ("Write file", "Execute shell", etc.) + icon.
      4. **Resource list** — scrollable `<ul>` of `resourcePreview` paths/URIs, truncated
         from the left so the filename is always visible (CSS `direction: rtl`).
      5. **Why needed** — `whyNeeded` text in a muted sub-row.
      6. **Scope editor** (optional) — single `<input>` pre-filled with the first
         `resourcePreview` entry; the user can narrow the glob. Hidden when
         `isNeverPersistable` (Execute / Delete / Upload — grants are never persisted).
      7. **Choice buttons** — rendered from the `choices` array:
         - `allow_once` → emerald "Allow once" (primary)
         - `allow_session` → sky "Allow for session" (if `!isNeverPersistable`)
         - `allow_task` → sky "Allow for task" (if `!isNeverPersistable`)
         - `deny` → rose "Deny"
         - `open_settings` → slate "Open settings…"

      Props:
      ```tsx
      type ConsentCardProps = {
        payload: ConsentRequestPayload;
        answered: boolean;
        answeredChoice?: ConsentChoice;
        onChoice: (choice: ConsentChoice, scope?: string) => void;
        onCancel: () => void;
      };
      ```
      Keyboard: Enter = `allow_once`, Escape = `deny`.
      Implemented with risk badge, tool/action/resource context, lifetime selector,
      allow/deny/settings actions, answered state, and sandbox checkbox when a
      backend is offered.

- [x] **`apps/shared/components/security/GrantsPanel.tsx`** — grants table for
      settings and any other surface that shows active / revoked grants:

      ```tsx
      type GrantsPanelProps = {
        grants: CapabilityGrant[];
        onRevoke: (id: string) => void;
        loading?: boolean;
      };
      ```

      Columns: **Action** (badge), **Tool** (provider + toolId), **Scope** (first
      `resourceScopes` entry, truncated), **Lifetime** (chip), **Revoke** (button).
      Empty state: "No active grants — consent prompts will appear as tools run."
      Loading skeleton on `loading=true`.
      Implemented as profile selector plus grouped active grants with revoke and
      revoke-all controls.

### 2d — chat-next: inline consent role

The consent card appears inline in the chat transcript, exactly like `ask_user`
bubbles — not as a modal. The agent thread blocks on the promise; the UI keeps
draining normally.

- [x] **`apps/chat-next/src/pm-chat/pmChatStore.ts`**:
      - Add `"consent"` to `ChatEntryRole`.
      - Add consent fields to `ChatEntry`:
        ```ts
        // consent inline card (role === "consent")
        consentReqId?:       string;
        consentPayload?:     ConsentRequestPayload;   // from shared/security/types.ts
        consentAnswered?:    boolean;
        consentChoice?:      ConsentChoice;
        consentScope?:       string;
        ```
      - Add `appendConsent(payload: ConsentRequestPayload): void` — creates a
        `ChatEntry{role:"consent", consentReqId, consentPayload, consentAnswered:false}`.
      - Add `submitConsent(reqId, choice, scope?): void` — marks entry answered,
        posts `{kind:"consentReply", reqId, choice, lifetime: choiceToLifetime(choice), scopes: scope ? [scope] : []}` to host.
      - Add `dismissConsent(reqId, reason?): void` — marks answered, posts `{choice:"deny"}`.
      - `applyLoadedSession`: exclude `"consent"` from saved entries (consent state is
        ephemeral — a loaded session should never show a stale pending consent card).
      Implemented with `appendConsent`, `submitConsent`, `dismissConsent`, and
      ephemeral filtering during loaded-session application. Wire payload uses
      `decision` (`allow` / `deny` / `settings`) plus lifetime/sandbox backend.

- [x] **`apps/chat-next/src/pm-chat/ChatTranscript.tsx`** — add consent surface:
      - Import `ConsentCard` from `@shared/components/security/ConsentCard`.
      - Add `<ConsentRequestInline entry={e} />` component (parallel to `<AskUserInline>`):
        - Reads `entry.consentPayload`, `entry.consentAnswered`, `entry.consentChoice`.
        - In answered state: shows a compact chip ("✓ Allowed once" / "✗ Denied" etc.)
          using the same badge style as `AskUserInline`'s recorded-answer view.
        - In live state: renders `<ConsentCard onChoice={(choice, scope) => submitConsent(...)} />`.
        - Autofocuses the "Allow once" button on mount.
      - In the role-dispatch switch: `e.role === "consent"` → `<ConsentRequestInline entry={e} />`.
      - `avatarSide()` for `"consent"` returns `"bot"` (gateway speaks as the assistant).
      Implemented via `ConsentRequestInline` and `ConsentCard`; settings click
      posts `openSettingsForConsent`.

- [x] **Typed host-event delivery for consent UI** — security consent request,
      review result, and dismissal now use the shared `pm_host_event` envelope
      over `PostWebMessageAsString`:
      ```jsonc
      { "t": "pm_host_event", "version": 1,
        "type": "security.consent.request", "payload": { "reqId": "…" } }
      ```
      `apps/shared/web/hostBridge.ts` exposes `onHostEvent`, and chat handles:
      `security.consent.request`, `security.consent.reviewResult`, and
      `security.consent.dismiss`. Legacy `window.pmChat.consentRequest` /
      `dismissConsent` handlers remain only as compatibility fallback during
      the bridge migration.

- [x] **IPC routing** — `ChatWebPanel.cpp` already has `askUserReply` in the IPC
      switch. Add `consentReply` → `m_impl->ResolveConsentReply(j)`. Verify the
      IPC path is tested in the test harness (see 2g below).
      Implemented for `consentReply`; automated WebView test coverage remains
      tracked under `suiteConsentInline`.

### 2e — Settings surface: Security/Permissions tab

- [x] **`apps/settings/src/settings/routes.ts`** — add to `SETTINGS_SECTIONS`:
      ```ts
      { id: "security", route: "security" },
      ```
      Add `"security"` to the `SettingsTab` type. Add i18n key.

- [x] **`apps/settings/src/settings/SecuritySettingsPanel.tsx`** (new panel):

      Sections:
      1. **Active profile** — `RadioGroup`: Light / Developer / Strict.
         - Reads via `hostRpc("security.profile.get")`.
         - Writes via `hostRpc("security.profile.set", {profile})`.
         - Shows a one-line description per profile.
      2. **Active grants** — `<GrantsPanel>` from shared:
         - Loads via `hostRpc("security.grants.list")`.
         - "Revoke" calls `hostRpc("security.grants.revoke", {id})`.
         - "Clear all" with confirmation calls `hostRpc("security.grants.clear")`.
         - Auto-refreshes every 5 s while the panel is visible (grants change during agent runs).
      3. **Storage info** — shows current storage backend
         (`settings-store` / `grants.json` path) + "Open file" button to reveal in Explorer.
      4. **Profile description** chip matching the active consent surface:
         `CliConsentDelegate` in agent → "Consent prompts appear in the chat transcript
         (inline card on stderr/stdout when headless)."
      Implemented as the Settings security panel shell backed by `GrantsPanel`.
      Current host RPC returns profile and an empty grant list until persistent
      grants storage/RPC is completed.

- [ ] **i18n** — add `security.*` keys to `apps/shared/i18n/en.ts` (and stubs in
      de/es/fr/it): `security.tab`, `security.profile`, `security.grants.title`,
      `security.grants.empty`, `security.grants.revoke`, `security.grants.clear`,
      `security.risk.*`, `security.action.*`, `security.lifetime.*`,
      `security.consent.allowOnce`, `security.consent.allowSession`,
      `security.consent.allowTask`, `security.consent.deny`, `security.consent.openSettings`.

### 2f — Backend IPC for settings panel

- [x] **`apps/shared/settings/hostRpc.ts` / Settings app wiring** — add security RPC calls:
      ```ts
      "security.profile.get"  → { profile: "light" | "developer" | "strict" }
      "security.profile.set"  → { ok: boolean; error?: string }
      "security.grants.list"  → { grants: CapabilityGrant[]; storage: string; grantsFile?: string }
      "security.grants.revoke"→ { ok: boolean }
      "security.grants.clear" → { ok: boolean; count: number }
      ```
      Implemented through the generic settings RPC client and `apps/settings/src/main.tsx`
      as `settingsSecurityGet`, `settingsSecurityProfileSave`,
      `settingsSecurityGrantRevoke`, and `settingsSecurityGrantRevokeAll`.

- [x] **Win32 settings RPC handler (profile + UI stub)** (add to `CSettingsWebView.cpp` or a new
      `CSettingsWebView_Security.cpp`):
      - `security.profile.get` → `pm::security::persist::load_active_profile()`.
      - `security.profile.set` → `pm::security::persist::save_active_profile()`.
      Implemented as `settingsSecurityGet` and `settingsSecurityProfileSave`.
      `settingsSecurityGrantRevoke` / `settingsSecurityGrantRevokeAll` currently
      return success as UI stubs.

- [ ] **Win32 settings RPC handler (real grants backend)**:
      - `security.grants.list` / `revoke` / `clear` → talk to persisted grants
        storage or a **session-stable `SecurityGateway` singleton** (see note below).

- [ ] **Session-stable `SecurityGateway` singleton** — the current per-`run()`
      gateway in `agent_factory.cpp` is torn down after each agent turn, so grants
      added during a session won't persist to the settings panel.
      Plan: expose a `pm::security::agent_gateway()` singleton (created on first
      `Agent::run()`, held until app exit) that the settings panel RPCs can query.
      Track this as a follow-up in Phase 4 (persistence + audit); settings panel
      can stub with a direct `SecurityPersistence::load_grants()` call for now.

- [x] **"open_settings" → Security tab** — when the C++ consent delegate gets
      `ConsentResult{openSettings=true}`, it should trigger a settings navigation.
      In `WebViewConsentDelegate::requestConsent()`, after decoding the reply:
      ```cpp
      if (result.openSettings) {
          // post {kind:"openSettings", tab:"security"} back to the WebView,
          // which forwards it to the host → opens CSettingsWebView on /security
      }
      ```
      Wire the corresponding IPC handler in `ChatWebPanel.cpp`.
      Implemented through the ConsentCard `settings` decision posting
      `openSettingsForConsent`, which `ChatWebPanel.cpp` forwards to the host
      settings bus with the `security` section.

### 2g — Tests

- [x] **`suiteAgentConsent` in `test-security.mjs`** — loopback agent tests for
      the gateway consent path. These are the first tests that exercise the full
      round-trip: agent encounters an Ask decision → consent delegate fires → reply
      → grant persisted → second identical call is Allowed without re-prompting.
      Reconciled with the later Phase 1.9 block: CLI consent, sandbox-backed grant
      persistence, denial injection, and deny no-reprompt caching are now covered.

      Setup: pipe a pre-seeded stdin reply via `PM_ASK_USER_REPLY_FILE`-style env, OR
      supply a `--storage grants.json` with a pre-loaded grant so no interactive
      consent is needed.

      Cases:
      - `write_file` to out-of-workspace path → gateway Ask → pre-seeded `allow_once`
        reply → tool executes → `ok:true`; second call → re-prompts (allow_once not
        persisted).
      - `write_file` to out-of-workspace path → pre-seeded `allow_session` → grant
        persisted → second call same session → no prompt → `ok:true`.
      - `write_file` to out-of-workspace path → pre-seeded `deny` → tool blocked →
        `security_denied:true` in envelope → agent continues cleanly.
      - MCP tool call → gateway fires (Execute, Developer profile, Ask) → pre-seeded
        `deny` → `security_denied:true` → agent continues.

- [ ] **`suiteGrantsRpc` in settings test** — drive the Settings WebView and
      assert that `security.grants.list` / `revoke` / `profile.get` / `profile.set`
      round-trip correctly through the IPC bridge.

- [ ] **`suiteConsentInline` (UI / chat-next)** — WebView integration test that:
      - Starts a loopback agent with a write to a non-workspace path.
      - Waits for `pm_host_event/security.consent.request` to render the consent card.
      - Clicks "Allow once" in the consent card.
      - Asserts tool succeeds and the card shows the answered badge.

### 2h — `run` tool gateway layer ✅ DONE (model revised)

**Decision (Jun 2026):** `cmd://` verb-based risk classification was evaluated
and rejected. Shell command strings are too easily obfuscated or injected
(`echo hello; sudo rm -rf /`, `cmd /c "... & reg add ..."`, encoded payloads,
alias/PATH substitution) to be parsed safely for risk. Verb classification would
create false confidence without genuine security.

**Correct model — three independent layers:**

```
Execute → Ask (consent mandatory, grant-based repeat approval)
         ↓ approved
    validate_command  ← hard blocks: sudo, runas, reg add, netsh, ...
         ↓ passes
    AppContainer sandbox (when FEATURE_SECURITY_SANDBOX enabled)
         ↓ or: normal process context (fallback, see below)
    command executes
```

**Current state:**
- ✅ `security_action_for_tool("run")` → `Action::Execute` (done)
- ✅ `run` skip removed from gateway intercept in `agent_factory.cpp` (stale
  comment at lines 1327–1328 remains — clean up)
- ✅ `validate_command` runs as hard block AFTER gateway approval (belt-and-suspenders)
- ✅ Sandbox routing: `sec_decision.sandboxBackend` → `args["sandbox"]` (agent_factory.cpp)
- ✅ Grant system handles consent fatigue (pre-seed `cmd://**` Execute grant for
  known-safe contexts instead of trying to classify verbs)

**Fallback when sandbox is disabled (embedded / ESP32 / `features.json` off):**

`FEATURE_SECURITY_SANDBOX` is feature-flag controlled and removed from the UI
via `features.json` on non-Win32 platforms. Without sandbox, the model is:

- **Consent + validate_command** is the security floor
- Risk shown on consent card stays `High` for Execute — accurately reflects that
  no containment is in place
- No behavioral change; the user explicitly approves each `run` call or holds a
  scoped grant

**Remaining clean-up items:**

- [x] Remove stale cut-off comment at `agent_factory.cpp` lines 1327–1328
      ("Phase 1.9 exception: the `run` tool is excluded…" — the skip is already gone)
- [x] Consent card: surface whether sandbox is active in the risk context so users
      approving Execute know whether containment is in place (sandbox → Medium shown,
      no sandbox → High shown). Implemented via `ToolRequest::sandboxAvailable` set
      in `build_agent_tool_request` (`#if FEATURE_SECURITY_SANDBOX`) and consumed in
      `PolicyEngine::evalDeveloper` to set the risk floor: Medium (contained) vs High.
- [x] Tests — update `suiteLoopbackAgent` to reflect grant-based Execute approval
      (test 10 in `test-security.mjs`):
      - `run "echo <marker>"` with pre-seeded `cmd://**` Execute grant → goes through
        (grant covers, no consent prompt)
      - `run "sudo whoami"` → blocked by `validate_command` or gateway denial
        (both are valid; validate_command runs AFTER gateway approves the grant)

### Status snapshot update

```
| Layer                                       | State           | Test coverage                |
|---------------------------------------------|-----------------|------------------------------|
| In-app WebView consent (ConsentCard)        | ✅ wired        | suiteConsentInline pending   |
| ConsentDelegateRegistry (global slot)       | ✅ done         | build coverage               |
| ChatWebPanel_Consent.cpp (WebView delegate) | ✅ done         | build coverage               |
| Security settings tab (GrantsPanel)         | ◑ UI shell done | suiteGrantsRpc pending       |
| apps/shared/security/types.ts               | ✅ done         | build coverage               |
| apps/shared/components/security/ConsentCard | ✅ done         | build coverage               |
| run tool gateway layer                      | ✅ consent+validate_command | grant-based tests pending |
| Grant persistence in agent context          | ✅ settings store | suiteAgentConsent covered    |
```

---

## Phase 3 — Win32 hardening (real behaviour)

- [ ] PathSecurity hardening follow-up: add a Win32 handle-based
      `GetFinalPathNameByHandleW` verifier for post-open TOCTOU checks, normalize
      drive casing, and cover UNC/device path edge cases. Basic symlink/junction
      escape is already covered by the `paths` suite through `std::filesystem`
      canonicalization.
- [ ] CryptoStore: persist DPAPI-wrapped master key to `master.key`; real
      AES-256-GCM via BCrypt with AAD (app-id/profile/grant-id/policy-version/
      tool-id/manifest-hash/workspace-id); random nonce per blob.
- [ ] WinAcl: `SetNamedSecurityInfo` DACL = current user only; deny inheritance.
- [x] ToolIdentity: SHA-256 of executable + manifest/config inputs.
      `ToolIdentityResolver::hashFile()` now streams files through libsodium
      SHA-256; `pm-image-security identity hash-file` and `suiteGrants` assert
      the digest and hash-bound grant matching/invalidation.
- [ ] ToolIdentity: signed manifest verification.

## Phase 4 — persistence + audit

- [ ] PermissionStore: SQLite (`grants.db`), WAL mode, encrypt sensitive BLOB
      columns via CryptoStore, grant invalidation on tool/policy hash mismatch.
- [ ] AuditLog: spdlog sink + SQLite (`audit.db`); log every DecisionKind +
      lifecycle event (GRANT_REVOKED/GRANT_EXPIRED/TOOL_HASH_CHANGED/…).
- [ ] PolicyEngine: optional signed policy bundle + user overrides that may only
      tighten (add deny / downgrade allow→ask), never loosen.

## Phase 5 — full integration (after Phases 1.9 + 2 + 3 + 4)

- [ ] Route every native tool, MCP tool, plugin, and background-agent action
      through `SecurityGateway::authorize()` / `executeIfAllowed()`.
      Priority order: (1) LLM agent CLI (`pm_image_cmd_llm_agent.cpp`, Phase 1.9),
      (2) MCP bridge, (3) in-app Win32 UI tools, (4) background service.
- [x] MCP: enforce an opt-in registered-server policy. `mcp.json` can set
      `security.requireRegisteredMcp=true`; `AgentMcpBridge` then skips
      unregistered servers and stdio servers whose declared `security.executableHash`
      / `security.manifestHash` does not match. Covered by `npm run test:mcp`.
      Remote→High and signed policy bundles remain future policy work.
- [x] Consent surfaces: (a) CLI agent stdio ✅ Phase 1.9 (`CliConsentDelegate`);
      (b) Win32 dialog ✅ Phase 1.8; (c) WebView inline consent ✅ Phase 2 via
      `ConsentDelegateRegistry` + `ChatWebPanel_Consent.cpp` + `ConsentCard`.
      Remaining work is automated WebView consent coverage and real settings grants RPC.
- [ ] Remove `llm_fs_guard_deny_reason()` / `llm_fs_guard_write_deny_reason()` from
      `path::execute()` once the gateway is authoritative — **needs a synchronous
      replacement story first** (the guard is sync and currently kept as-is).

## Delegate migration (replace `src/file_extensions.hpp`)

`src/file_extensions.hpp` mixes preview routing, editor eligibility, Explorer
registration tables, and the LLM FS deny lists in one header. The classifier
should consume these signals through `ClassificationDelegate` instead:

- [ ] Move `k_sensitive_path_prefixes`, secret basenames, and shell-open/write
      deny tables behind `SecretPatternDelegate` / `ExtensionRiskDelegate`.
- [ ] Have `pm::llm` FS guard call `ResourceClassifier` instead of inlining the
      `file_extensions.hpp` tables.
- [ ] Keep preview/editor predicates in `file_extensions.hpp` (UI concern), but
      delete the security-relevant tables once delegates are authoritative.

## Cross-platform backends (later)

- [ ] macOS: `backends/mac/MacKeychainCrypto.cpp` (Keychain + AES-256-GCM),
      App Sandbox if applicable.
- [ ] Linux: `backends/linux/LinuxSecretServiceCrypto.cpp` (libsecret/Secret
      Service, KWallet fallback, `0700` dir perms), Landlock/seccomp later.

---

## Sandbox — AppContainer / LPAC experimentation

> **Status:** CLI sub-arm landed (`src/security/cli.cpp § sandbox`), gated by
> `FEATURE_SECURITY_SANDBOX` (default ON). No production wiring yet.
> Build: `npm run build:cpp:security` (or `ninja --target pm-image-security`).

### Background

The sandbox arm explores whether AppContainer (AC) and Less-Privileged AppContainer
(LPAC) are viable for wrapping MCP tool workers.  The design goal:

```
MainApp.exe (broker / parent)
  ├─ SecurityGateway::authorizeWithConsent()   ← decides policy
  ├─ sandbox acl  →  SetNamedSecurityInfo()    ← opens "shared folder"
  └─ ToolWorker.exe (child, AppContainer / LPAC)
        ├─ MCP tool call
        ├─ ACCESS_DENIED on un-granted path
        └─ PrivilegeEscalationRequest → broker → SecurityGateway → consent
```

AppContainer is deny-by-default on filesystem, network, and process handles.
LPAC additionally opts out of the ALL_APPLICATION_PACKAGES group so even
explicitly-granted-to-AC-group paths require a direct SID ACE.

### CLI sub-commands (all emit JSON)

| Sub-command | What it tests |
|---|---|
| `sandbox probe` | Profile create / derive / delete, SID string |
| `sandbox acl` | Add ALLOW ACE for AC SID to path DACL ("shared folder") |
| `sandbox launch` | Real `CreateProcessW` with `SECURITY_CAPABILITIES` attribute, optional LPAC + Win32k lockdown |
| `sandbox wrap-mcp` | ACL-check simulation: does the container have access? Emits `privilegeEscalationRequest` on miss |


### Typical test loop

```powershell
# 1. Create container profile, inspect SID
.\pm-image-security.exe --json sandbox probe --moniker pm-mcp-test --retain

# 2. Simulate MCP write call inside container (no ACL yet → should fail)
.\pm-image-security.exe --json sandbox wrap-mcp `
    --moniker pm-mcp-test --tool mcp.fs.write --action write `
    --path C:\workspace --retain
# → accessDenied=true, privilegeEscalationRequest emitted

# 3. Grant the path as a "shared folder"
.\pm-image-security.exe --json sandbox acl `
    --moniker pm-mcp-test --path C:\workspace --access read-write

# 4. Re-run MCP wrap (should succeed now)
.\pm-image-security.exe --json sandbox wrap-mcp `
    --moniker pm-mcp-test --tool mcp.fs.write --action write `
    --path C:\workspace --retain
# → aclGranted=true, accessDenied=false

# 5. Real AppContainer process launch
.\pm-image-security.exe --json sandbox launch `
    --moniker pm-mcp-test --exe "cmd.exe /c whoami" `
    --timeout-ms 5000 --retain

# 6. Same with LPAC (stricter — ALL_APPLICATION_PACKAGES opt-out)
.\pm-image-security.exe --json sandbox launch `
    --moniker pm-mcp-test --exe "cmd.exe /c whoami" --lpac `
    --timeout-ms 5000
```

### Todos — profile lifecycle

- [x] **Profile caching**: `ensure_profile()` calls `CreateAppContainerProfile` on
      every probe. For production: cache the SID in `WorkerSandboxOptions` and only
      call `DeriveAppContainerSidFromAppContainerName` after first creation. Key is
      moniker → SID; invalidate if the moniker changes between sessions.
      Implemented in `SandboxAppContainer::acquireSid()` as a moniker → SID cache.
- [ ] **Profile naming scheme**: current monikers are freeform strings. Define a
      canonical scheme: `pm-worker-{toolId hash truncated to 8 chars}` so each tool
      gets its own isolated profile and profile collision is impossible across tools.
- [ ] **Profile cleanup on app exit**: `DeleteAppContainerProfile` for all transient
      profiles. Hook into the app teardown path (session-end / process exit handler).
- [x] **Profile retention policy**: permanent profiles (workspace tools) vs ephemeral
      (single-call MCP): expose in `WorkerSandboxOptions.retainProfile`.
      Implemented as `SandboxSpawnOptions.retain` /
      `StdioLaunchOptions.retain_sandbox_profile`; tests cover transient cleanup.
- [ ] **Cross-session SID stability**: verify that `DeriveAppContainerSidFromAppContainerName`
      returns the same SID across process restarts (it should — it is deterministic from
      the moniker hash). Write a regression probe: `sandbox probe --retain` twice,
      assert same SID.

### Todos — shared folders

"Shared folders" = paths granted to the AppContainer SID via DACL ACE.  AppContainer
is deny-by-default: even user-owned files are inaccessible until explicitly granted.

- [x] **ACL grant at spawn time**: `cmd_sandbox_acl` adds a DACL entry using
      `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE`.
      The `NO_PROPAGATE_INHERIT_ACE` flag prevents Windows from propagating the new
      ACE to all existing children (which is O(n_files) and takes ~60s on a large
      workspace). New files created inside the directory still inherit the ACE.
      For production: grant at worker spawn (ephemeral session), revoke at worker exit.
      Use `SetNamedSecurityInfoW` + `RemoveAccessAllowedAce` or replace the DACL entirely.
      Consider whether deep propagation is ever needed and measure the cost.
      Implemented by `SandboxAppContainer::spawn()` and the generic stdio runner's
      sandbox launch path using per-spawn path grants.
- [x] **Revoke on worker exit**: on `CloseHandle(hJob)` (kill-on-job-close fires) or
      `WaitForSingleObject(hProcess)`, call a cleanup routine that removes the ACE added
      at spawn time. Scope: only remove ACEs whose SID matches the transient container SID.
      Covered by RunTool and stdio MCP teardown tests that assert granted SIDs are
      removed from temp directory DACLs.
- [x] **Batch grant helper**: for tools that need multiple paths (workspace root +
      uv cache dir + temp dir), grant all three in one DACL transaction to avoid
      partial state if the process fails mid-grant.
      Implemented as `SandboxSpawnOptions.paths` / `StdioLaunchOptions.paths`.
- [x] **Inherited vs object ACE**: `grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE |
      NO_PROPAGATE_INHERIT_ACE` — child files created inside the granted dir inherit
      the ACE as effective (non-inheritable). Verified via `sandbox acl --check-access`
      on a child file created after the parent grant. Test in `suiteSandboxSharedFolders.1`.
      `--check-access` flag added to `sandbox acl` CLI subcommand (`cli.cpp`).
- [x] **Read-only vs read-write grant**: `grantPathImpl` already selects minimal mask
      (`GENERIC_READ` only vs `GENERIC_READ | GENERIC_WRITE | DELETE | ...`).
      `wrap-mcp` `suggestedFix` uses `action == "write"` → `"read-write"`. Tested in
      `suiteSandboxSharedFolders.2a/2b`: read grant → sandbox write denied; read-write
      → sandbox write succeeds.
- [x] **LPAC path grant**: `grantPath` adds the SPECIFIC AppContainer SID (not
      `ALL_APPLICATION_PACKAGES`), which is exactly what LPAC needs (LPAC opts out of
      ALL_APPLICATION_PACKAGES but still matches the specific SID). Test in
      `suiteSandboxSharedFolders.3`: `--lpac` container reads from a specifically-SID-
      granted dir and succeeds.
- [x] **%TEMP% shared folder**: `SandboxSpawnOptions::createScratchDir` flag added.
      `SandboxPathGrant::deleteOnRevoke` flag added. `spawn()` creates
      `%TEMP%\pm-sidecar-<pid>-<tick>-<seq>`, grants it read-write, reports it in
      `SandboxResult::scratchDir`, and deletes it via `RemoveDirectoryW` after revoking
      the ACE. `parse_sandbox_config` wires `createScratchDir` from JSON.
      `sandbox launch` reports `scratchDir` in output JSON. Test in
      `suiteSandboxSharedFolders.4`.
- [x] **UV cache shared folder**: `${CACHE_DIR}` built-in variable added to
      `command_variables.cpp` / `command_variables.hpp`. Resolves to the OS temp
      directory (`GetTempPath` on Windows, `$TMPDIR` / `/tmp` on macOS/Linux) via
      `std::filesystem::temp_directory_path()`. For uvx sandbox workers, set
      `UV_CACHE_DIR=${CACHE_DIR}/uv` and grant `${CACHE_DIR}/uv` as a `read-write`
      `SandboxPathGrant` in the spawn options. Alias may be updated to `LocalAppData` /
      `~/.cache` when the right isolation boundary is clear.
      Wiring to actual uvx sandbox spawn deferred until uvx-over-stdio MCP is sandboxed.

### Todos — PrivilegeEscalationRequest and broker routing

- [ ] **Formalise `PrivilegeEscalationRequest` type** in `src/security/types.hpp`:
      ```cpp
      struct PrivilegeEscalationRequest {
          std::string tool;
          std::string action;  // mirrors Action enum string
          std::string path;
          std::string containerSid;
          bool lpac;
          std::string reason;
          std::string callSite;  // diagnostic: which sandbox boundary triggered
      };
      ```
      The JSON shape emitted by `wrap-mcp` is the wire format the worker uses over
      the IPC pipe (alongside the normal MCP result failure).

- [ ] **Worker IPC protocol extension**: add a `privilege_escalation` message type to
      the worker pipe protocol (currently JSON lines on stdin/stdout).  Schema:
      ```json
      { "id": "call_123", "type": "privilege_escalation",
        "tool": "mcp.fs.write", "action": "write", "path": "/workspace/out.csv",
        "containerSid": "S-1-15-2-...", "lpac": false,
        "reason": "path not covered by AppContainer ACL grant" }
      ```
      The broker reads this message type and routes it to
      `SecurityGateway::authorizeWithConsent()` instead of treating it as a tool result.

- [ ] **Broker `authorizeWithConsent` → ACL widen path**: when the gateway returns
      `Allow` for an escalation request:
        1. Call `sandbox acl` (i.e. `SetNamedSecurityInfoW`) to add the ACE.
        2. Re-send the original MCP tool call to the worker (same connection or new one).
        3. If the gateway returns `Deny`: inject `{"ok":false,"security_denied":true}` as
           the tool result (same path as the existing agent-loop intercept in Phase 1.9).

- [ ] **Consent routing for escalation**: escalation requests go through the same
      `RoutingConsentDelegate` stack as normal `Ask` decisions. The `ConsentRequest`
      should surface the AppContainer context in `possibleRisk` so the user understands
      this is a sandbox boundary request, not a flat permission question.

- [x] **`PrivilegeEscalationRequest` JSON shape**: defined by `wrap-mcp` output
      (fields: `tool`, `action`, `path`, `containerSid`, `lpac`, `reason`,
      `callSite`, `suggestedFix`). No formal C++ struct needed — the pre-emptive
      broker model replaces the use case. The `wrap-mcp` diagnostic shape is
      sufficient documentation for any future worker-side implementation.

- [~] **Worker IPC protocol extension**: DROPPED. Pre-emptive consent at the broker
      layer makes the reactive in-band escalation redundant for all MCP tool shapes
      we currently support. Revisit only if a tool with non-declared dynamic path
      access (e.g. a sandboxed compiler reading arbitrary headers) is added.

- [x] **Broker `authorizeWithConsent` → ACL widen path**: already implemented in
      `agent_factory.cpp`. The security gateway intercepts the MCP `tools/call`
      before it reaches the MCP server; on `Ask → Allow`, `grantPath()` is called
      (via `SandboxAppContainer::grantPath`) and the call proceeds. The "retry"
      step does not exist because the call never started.

- [~] **Consent routing for escalation**: DROPPED as a separate item. The existing
      `ConsentRequest` shown for MCP Execute actions already surfaces the tool name
      and resource scope. AppContainer context ("runs in sandbox") is reflected via
      `ToolRequest::sandboxAvailable` → risk level on the consent card (Medium =
      sandboxed, High = bare). No additional escalation-specific UX needed.

- [~] **Test: full escalation round-trip**: DROPPED. Replaced by:
      - `suiteSandboxSharedFolders` (ACL grant, inheritance, LPAC, scratch dir)
      - `suiteSandbox` (wrap-mcp probe: aclGranted=false → suggested fix → re-probe)
      - `suiteLoopbackAgent` test 10 (Execute grant covers MCP-style run tool)

### Todos — real process containment

## dropped for now : 
[ ] **Child process creation inside AC**: by default AppContainer allows child
      process creation. For maximum containment: add
      `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` mitigation. Test: worker tries to
      `CreateProcess`; assert it fails.  This is important for MCP servers that might
      try to spawn sub-processes.
- [ ] **Network**: by default AppContainer blocks all network. Probe: worker attempts
      `WSAConnect` to 127.0.0.1:80; assert it fails with `WSAEACCES`. For tools that
      need outbound access, add the `internetClient` capability SID when creating the
      profile.  Drive through `sandbox probe --capabilities internetClient`.
- [ ] **Handle inheritance audit**: `CreateProcessW(..., FALSE, ...)` (bInheritHandles=FALSE).
      Verify that no parent handles (file handles, pipe handles, DPAPI key handles) leak
      into the AppContainer child. Probe: enumerate the child's open handles via
      `NtQuerySystemInformation(SystemHandleInformation)` from the parent; assert no
      handles beyond stdin/stdout/stderr.
## dropped

- [x] **Verify AppContainer restricts filesystem access**: write a probe that:
        1. `sandbox launch --exe probe-helper.exe --moniker pm-test`
           where `probe-helper.exe` attempts to open a file not in its ACL.
        2. Assert exit code = `ERROR_ACCESS_DENIED` (5) or similar.
      This validates that the SECURITY_CAPABILITIES attribute actually works, not just
      that the API call succeeds.
      Covered by `suiteRunSandbox` deny-by-default outside-cwd writes and
      `test:mcp` sandboxed `write_probe` inside/outside granted paths.
- [ ] **Win32k lockdown (`--no-win32k`)**: verify that a process launched with
      `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON`
      cannot call `CreateWindowEx` or similar. Probe: launch a minimal exe that calls
      `MessageBoxW`; assert it terminates with a status code indicating the mitigation
      fired. Note: this also blocks console allocation, so the probe exe must not use
      a console.
- [x] **Job Object layering**: `sandbox launch` currently does not assign the child
      to a Job Object. Add `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` + memory/CPU limits
      (mirrors the `Tier 1` implementation in `sandbox.md`). The container should be
      inside BOTH the AppContainer and the Job; child processes spawned by the worker
      inherit the Job (they cannot break out without explicit Job escape privileges).
      Implemented for `SandboxAppContainer::spawn()` and `StdioChildProcess`; timeout
      tests assert process-tree kill for both RunTool and sandboxed MCP.
- [x] **Child process creation inside AC**: `SandboxSpawnOptions::noChildProcess` flag
      wired to `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` /
      `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` in `SandboxAppContainer::spawn()`.
      CLI: `sandbox launch --no-child-process` (or `"noChildProcess":true` in config JSON).
      Test: `suiteContainment.1` — launches `cmd.exe /c start /b cmd.exe` with the flag;
      asserts `exitCode != 0` (inner CreateProcess blocked by the mitigation).
- [x] **Network**: confirmed AppContainer default blocks external TCP. Capability SIDs now
      resolved via `DeriveCapabilitySidsFromName` inside `spawn()` and populated into
      `SECURITY_CAPABILITIES.Capabilities`. CLI: `sandbox launch --capabilities internetClient`
      (repeatable) or `"capabilities":["internetClient"]` in config JSON.
      Tests: `suiteContainment.2a` — no-caps AC → TCP connect to 1.1.1.1:53 returns
      `WSAEACCES` (exitCode 13). `suiteContainment.2b` — with `internetClient` cap the
      access-denied block is lifted (exitCode ≠ 13; actual result is network-dependent).
- [x] **Handle inheritance audit**: replaced the blanket `bInheritHandles=TRUE` leak with
      `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (always active) listing only the three stdio
      handles `{stdin, stdout_write, stderr_write}`. Non-inheritable handles and all
      parent file/pipe/DPAPI handles are invisible to the AC child.
      `stdin_h` is validated before inclusion (may be null in piped/service contexts).
      Smoke test: `suiteContainment.3` — plain launch captures stdout, asserts ok=true.

### Todos — LPAC specifics

- [x] **Sandbox configuration presets** (`src/security/sandbox_presets.hpp/.cpp`):
      Named presets encapsulate the right combination of flags, capabilities, and
      standard path grants for common sidecar/MCP tool categories.
      `resolve_preset(name, ctx, opts)` fills a `SandboxSpawnOptions` baseline;
      config JSON and individual CLI flags both override preset values.
      Built-in presets (`suitePresets`, 7 assertions):
        - `offline` — linters/formatters (ruff, ty): no capabilities, exec+rw on bin+cwd.
          NOTE: `noChildProcess` is NOT set — ruff/ty use combase/netapi32 DLLs during
          init that may internally sub-spawn (e.g. COM surrogate); blocking is too
          aggressive. Use `strict` if sub-spawn must be prevented.
        - `fetch` — package managers (uvx, npm, pip): `internetClient` capability,
          child processes allowed, scratch dir + cache dir grants.
        - `run` — general code (node, python, shell): no network by default, scratch dir.
        - `strict` — untrusted MCP servers: `lpac=true`, `noChildProcess=true`,
          `noWin32k=true`, no capabilities, exec on bin only (no cwd grant).
        - `self` — the app's own binary inside AC: default caps = `internetClient` +
          `internetClientServer` + `privatenetworkClientServer`; grants `distDir` (exec,
          parent of bin — covers all bundled DLLs), `binDir` (exec), `roamingDir`
          (`%APPDATA%\PolyMech\pm-image`, read-write, derived from
          `media::settings::get_config_dir()`), `createScratchDir=true`, and any
          `userPaths` (read-write). `--capabilities` with `--preset self` **replaces**
          (not appends to) the default cap set — tracked via `SandboxPresetContext::capsOverride`.
          CLI adds `--user-path` (repeatable) and `--bin-dir`; output JSON gains `distDir`
          and `userPaths`. Tests: `suitePresets.6` (default caps, distDir, roaming grant,
          userPath in grantedPaths) and `suitePresets.6b` (caps override: only
          `internetClient` after `--capabilities internetClient`).
      CLI: `sandbox launch --preset offline --sandbox-config <config>` or
      `--preset fetch --exe uv.exe --cwd /ws`. `--bin-dir` overrides the default
      `dirname(exe)/bin` path used by the exec grant. The resolved `preset`, `binDir`,
      `distDir`, and `userPaths` are echoed in the output JSON.
- [x] **Capability SID resolution**: `DeriveCapabilitySidsFromName` (dynamic-loaded
      from `kernelbase.dll`) now used in `SandboxAppContainer::spawn()` to resolve
      capability name strings (e.g. `"internetClient"`) into `SID_AND_ATTRIBUTES`
      and populate `SECURITY_CAPABILITIES.Capabilities`. CLI:
      `sandbox launch --capabilities internetClient` (repeatable) or
      `"capabilities":["internetClient"]` in config JSON. Tested in `suiteContainment.2a/b`.
- [ ] **internetClient vs internetClientServer**: the preset system maps tool categories
      to capability sets. Complete the mapping:
      - `offline` → `[]` (no network) ✅ done via preset
      - `uvx <tool>` first run → `["internetClient"]` ✅ done via `fetch` preset
      - `node` fetch scripts → `["internetClient"]` ✅ done via `fetch` preset
      - tools binding a local listen socket → `["internetClientServer"]` — not yet
      - tools needing corporate/local registry → `["privatenetworkClientServer"]` — not yet
      Wire into `WorkerSandboxOptions` once MCP tool categories are defined.
- [ ] **ALL_APPLICATION_PACKAGES opt-out impact**: some system DLLs have ACEs for
      `ALL APPLICATION PACKAGES` but not for individual SIDs. LPAC may fail to load
      these. Probe: launch a minimal LPAC exe; assert it can load `ntdll.dll` /
      `kernel32.dll` (they should work). Document any DLL load failures.
- [ ] **Registry access in LPAC**: LPAC blocks most registry hive writes. Probe: worker
      attempts `RegSetValueEx` on `HKCU\Software\<key>`; assert it fails. This matters
      for MCP servers that store state in the registry.

### Todos — test suite (`test:security` / `suitesSandbox`)

- [x] **`wantSuite('sandbox')` gate** in `test-security.mjs`: add a `sandbox` suite
      that runs all probe variants and asserts JSON fields. Guard with
      `process.platform === 'win32'` since AppContainer is Win32-only.
      Covered by `npm run test:security:sandbox`.
- [x] **`sandbox probe` round-trip**: assert `ok=true`, `sid` matches `S-1-15-2-*`
      pattern (AppContainer SID format), `profileCreated` or `profileDeleted`.
- [x] **`sandbox wrap-mcp` deny path**: assert `accessDenied=true`,
      `privilegeEscalationRequest.tool`, `.action`, `.path` match inputs.
- [x] **`sandbox acl` + `wrap-mcp` allow path**: grant a temp dir, then `wrap-mcp`
      the same dir → `aclGranted=true`, `accessDenied=false`.
- [x] **`sandbox launch` round-trip**: launch `cmd.exe /c exit 42`, assert
      `exitCode=42`, `timedOut=false`.
- [x] **LPAC probe**: `sandbox probe --moniker pm-lpac-test` + `sandbox launch --lpac`
      → confirm launched (exitCode present); verify SID differs from non-LPAC
      container with same moniker (it should be the same profile SID, but the process
      token should have the `LPAC` attribute — observable via `CheckTokenCapability`).
- [x] **Shared folder end-to-end**:
        1. `sandbox probe --retain` → get SID
        2. `sandbox acl --path <tmpdir> --access read-write`
        3. `sandbox wrap-mcp --path <tmpdir>` → `aclGranted=true`
        4. ACL revoke (manual `SetNamedSecurityInfo` or next probe's `--no-retain`)
        5. `sandbox wrap-mcp --path <tmpdir>` → `aclGranted=false`
      This validates the full "shared folder grant → use → revoke" lifecycle.
      Covered by `suiteSandbox` and the later RunTool/MCP revoke assertions.

### Todos — integration

- [x] **`WorkerSandboxOptions` extension**: superseded by the concrete
      `SandboxSpawnOptions` / `StdioLaunchOptions` fields now used by `RunTool`
      and sandboxed stdio MCP. Original sketch:
      add `useAppContainer`, `useLpac`,
      `capabilities`, `sharedPaths` (list of `{path, access}`) to the existing
      `WorkerSandboxOptions` struct in `sandbox.md`. When `useAppContainer=true` the
      `WinSandboxWorker` calls `sandbox_impl::ensure_profile()` + `sandbox_impl::grant_path()`
      at spawn time, and `DeleteAppContainerProfile()` (if !retainProfile) at exit.
- [x] **Wiring to `ToolWorkerClient::executeWindowsSandboxed`**: superseded by
      `RunTool` delegating to `SandboxAppContainer::spawn()` and by the generic
      stdio runner for persistent children. Original sketch:
      replace the current
      restricted-token approach with the AppContainer path when
      `WorkerSandboxOptions::useAppContainer=true`. The two approaches are not mutually
      exclusive: AppContainer token + Job Object is the target stack.
- [x] **`FEATURE_SECURITY_SANDBOX` in `CMakePresets.json`**: add to the
      `vendor.pm.features` doc block so it shows up in `pm-write-features-json`.
      Reconciled with current build setup: the security sandbox backend is compiled
      under the existing Win32 feature gates used by `test:security:sandbox`.
- [x] **Sidecar binary toolchain**: confirmed that `uv.exe`, `ruff.exe`, `node.exe`
      launched inside AppContainer can load their DLLs from `dist/win-x64/bin/` after
      a `"paths":[{"path":"dist/win-x64/bin","access":"exec"}]` grant.
      All three depend only on system DLLs (`kernel32`, `ntdll`, `advapi32`, …)
      which are accessible by default in AC (ALL_APPLICATION_PACKAGES DACL on System32).
      Single exec grant (`GENERIC_READ | FILE_LIST_DIRECTORY | FILE_TRAVERSE |
      GENERIC_EXECUTE | FILE_EXECUTE`) on the directory propagates to all files via
      `OBJECT_INHERIT_ACE`, so no per-binary ACE is needed.
      Tests: `suiteSidecarBinaries` (suite `--suite sidecar`):
        - 1. `uv.exe --version` → exit 0, stdout `"uv 0.11.17 …"`
        - 2. `ruff.exe --version` → exit 0, stdout `"ruff 0.15.15"`
        - 3. `node.exe --version` → exit 0, stdout `"v24.16.0"`
        - 4. exec grant revoked after `spawn()` → `aclGranted=false` confirmed.

### Known AppContainer pitfalls to probe

- [ ] **Console allocation**: AppContainer processes can use a console if
      `HKCU\Console\LowBoxConsoleEnabled=1` is set (see reference
      `LaunchAppContainer.cpp::wmain`). Without this the `CreateConsoleScreenBuffer`
      call inside cmd.exe may fail silently. Probe: launch `cmd.exe` without the
      registry key; verify it works or fails gracefully.
- [-] **`CreateProcessAsUser` vs `CreateProcessW`**: the reference code uses
      `CreateProcessAsUser(NULL, ...)`. With `NULL` token this is equivalent to
      `CreateProcessW`. Test both; assert same behavior. The current `sandbox launch`
      uses `CreateProcessW` — verify it is sufficient without requiring
      `SeAssignPrimaryTokenPrivilege`.
- [-] **Elevation inside container**: an elevated token cannot be applied inside an
      AppContainer (the integrity level is forced to Low). Probe: if the parent is
      elevated, does `sandbox launch` still produce a Low-IL AppContainer child?
      Assert with `GetTokenInformation(TokenIntegrityLevel)` from the child.
- [ ] **Desktop heap isolation**: AppContainer processes run on the interactive desktop
      but in a separate desktop heap. Check for UI-less (console-only) workers whether
      this causes any issues with DLL init code that calls `GetDesktopWindow()` etc.
- [ ] **`onecoreuap.lib` for capability name resolution**: `DeriveCapabilitySidsFromName`
      requires `onecoreuap.lib` (see reference). Add to link libraries when capability
      name parsing is implemented; not needed for the current SID-based flow.

## Tests

### Green now

`npm run test:security` — **182 assertions** (`tests/orchestrator/test-security.mjs`):

- [x] workspace read allow (LIGHT) · `.env` deny (LIGHT) · write Ask (LIGHT) ·
      read-outside-workspace Ask (LIGHT) · execute deny (LIGHT).
- [x] STRICT denies unsigned · STRICT allows registered-signed workspace read ·
      STRICT denies secret even when signed.
- [x] DEVELOPER allows workspace write · DEVELOPER denies git push.
- [x] grant persist → list → find · Ask→Allow upgrade via live grant · execute
      grant never persisted · revoke empties the store.
- [x] path canonicalize/inside/glob · classify secret/outside-workspace/risk.
- [x] tool-identity wildcards (provider/tool/server) · server mismatch denied.
- [x] URI scopes: fs://→file://, host globs, scheme isolation, file ext scopes,
      network (https) grant scoped by host.
- [x] origin registry/resolve · authorize records provenance · session/task binding.
- [x] schema contract: enums (incl. task + uri schemes) + type defs present.
- [x] **interactive consent** (Phase 1.7): prompt contract on stderr · token + JSON
      responses · allow_once not persisted · allow_session persisted & scoped ·
      grant covers next call (no re-prompt) · cross-session re-prompt ·
      blank/open_settings deny.
- [x] **loopback agent** (Phase 1.9 harness): immediate text · empty script ·
      write_file tool → file created · two consecutive tool calls · secret-path
      deny recovered · `@file` PM_LOOPBACK_SCRIPT env var.
- [x] **loopback run tool** (static guards): `validate_command` deny (privilege
      escalation, registry write) · allowed command executes + stdout captured.
      Historical note: these started as static-guard coverage; gateway/grant-gated
      run coverage is now handled by `suiteLoopbackSandbox` and `test-security-ui`.

`npm run test:security-ui` — **41 assertions** (`tests/orchestrator/test-security-ui.mjs`):

- [x] **Win32 consent dialog** (Phase 1.8, real UIA): ready · structural inspect
      (title/risk/tool/prefilled scope) · Deny→deny · Allow-session→persisted
      session grant · UIA set-value scope narrowing→persisted narrowed scope ·
      sandbox checkbox persists an AppContainer grant and routes `RunTool`.

### Pending (later phases)

- [x] **Phase 1.9 agent-loop tests**:
      write_file → Ask on stderr → allow_session → grant persisted; secret path →
      Deny; same tool+path twice → no re-prompt; deny response → security_denied
      injected as tool result. Reconciled with the later Phase 1.9 block and
      `suiteAgentConsent`; WebView inline consent is now implemented, with
      dedicated WebView automation coverage still tracked under `suiteConsentInline`.
- [x] **Consent sandbox opt-in**: `ConsentRequest.sandboxBackends` advertises
      registered backends for write/execute prompts; CLI JSON consent,
      Win32 dialog, and WebView consent card can persist
      `CapabilityGrant.sandboxBackend=appcontainer`, and the same grant routes
      the immediate + reused decisions through `PolicyDecision.sandboxBackend`.
- [x] symlink escape denied · junction escape denied (win) — Phase 2 PathSecurity.
      Covered by `suitePaths`: a workspace directory link/junction points outside
      the workspace; both an existing file and a future write target classify as
      outside after canonicalization.
- [x] changed MCP/tool hash invalidates grant — `suiteGrants` adds a
      hash-bound grant, proves same-hash reuse, proves changed-hash mismatch,
      and proves `authorize --use-grants` persists the invalidation.
- [ ] expired grant ignored — timestamped lifetime tests still pending.
- [ ] user override cannot loosen — Phase 3 policy bundle.
- [ ] DPAPI `isSecure=true` + ACL-hardened dir — flip the OS layers on.
- [ ] `allowSecrets` / `maxFiles` / `maxBytes` enforced in gateway / dialog.

---

## Sandbox — backend architecture

The `cli.cpp` experiments validated all the core Win32 primitives.  The pluggable
backend class now exists; the gateway routing wiring is the next step.

### Interface  (`src/security/backends/SandboxBackend.hpp`)

- [x] Define `SandboxPathGrant { path, access }` struct.
- [x] Define `SandboxSpawnOptions` struct: `moniker`, `lpac`, `noWin32k`, `retain`,
      `timeoutMs`, `run`, `args`, `capabilities`, `paths`.
- [x] Define `SandboxResult` struct: `ok`, `launched`, `timedOut`, `exitCode`, `pid`,
      `error`, `containerSid`, `profileCreated`, `grantedPaths`, `revokedPaths`.
- [x] Define abstract class `SandboxBackend`: `spawn()`, `grantPath()`, `revokePath()`,
      `checkAccess()`, `containerSid()`, `deleteProfile()`, `name()`.
- [ ] Null/no-op backend for non-Win32 platforms and `FEATURE_SECURITY_SANDBOX=0` so
      routing always resolves without `#ifdef` at the call site.

### Win32 AppContainer implementation  (`src/security/backends/win/SandboxAppContainer.hpp/.cpp`)

- [x] `SandboxAppContainer` implements `SandboxBackend`.
- [x] Helpers moved from `cli.cpp` into `SandboxAppContainer.cpp`:
      `toWide`, `sidToStr`, `grantPathImpl`, `revokePathImpl`, `checkAccessImpl`.
      `cli.cpp` sub-commands are thin wrappers over a process-wide backend singleton.
- [x] `SandboxAppContainer::spawn()` — full lifecycle: profile, ACL grants,
      `CreateProcessW` with thread-attribute list, wait, revoke paths, optional delete.
- [x] `SandboxAppContainer::grantPath()` / `revokePath()` / `checkAccess()`.
- [x] Profile SID cache: `acquireSid()` stores SID by moniker;
      subsequent calls skip `CreateAppContainerProfile` (derive only).
- [x] `SandboxAppContainer::name()` returns `"appcontainer"`.
- [x] Both files guarded by `#if defined(_WIN32)`.
- [x] Added to `CMakeLists.txt` for both `pm-image-security` and `pm-media`
      (`FEATURE_SECURITY_AGENT`) targets.
- [x] All 66 `suiteSandbox` assertions green (`npm run test:security:sandbox`).

### Phase A — `run` tool sandbox offloading via loopback  (do first)

Prove the common case before any gateway wiring: take the existing `run` tool
(`src/llm/tools/run/RunTool.cpp`, which normally shells out via
`media::process::run`) and let it **offload** the command into the AppContainer
backend.  The direct tools-call harness is the first test vehicle — no real LLM,
no broker IPC yet, just `RunTool::execute → SandboxAppContainer::spawn`.

- [x] **Offload seam in `RunTool::execute`**: after `validate_command` passes,
      branch on an offload flag.  When set, build `SandboxSpawnOptions` from the
      existing inputs (`run` = shell exe, `args` = `["-c", command]` / `["/c", …]`,
      `paths` = `[{ cwd, "read-write" }]`, `timeoutMs` = the clamped `timeout_ms`)
      and call `SandboxAppContainer::spawn()` instead of `media::process::run`.
- [x] **Map `SandboxResult` → `ExecuteResult` envelope**: `launched`/`exitCode`/
      `timedOut` → the same `{ ok, exit_code, stdout, stderr, timed_out }` shape the
      tool already returns, plus `sandboxed:true`, `sandbox_backend`, and `containerSid`.
- [x] **stdout/stderr capture in `spawn()`**: AppContainer child now uses redirected
      inheritable pipe handles (`STARTUPINFO.hStdOutput/hStdError`) and returns
      captured text through `SandboxResult.stdoutText/stderrText`.
- [x] **Offload flag source (Phase A only)**: a plain bool — env var
      `PM_RUN_SANDBOX=1` or an `args["sandbox"]` field on the tool call.  No gateway,
      no policy; this is purely to exercise the path. Gateway routing replaces it
      in Phase B.
- [x] **cwd grant**: `cwd` (agent_path_base) is granted read-write before spawn and
      revoked after, reusing the `paths` lifecycle already in `spawn()`.

#### Phase A tests (`tests/orchestrator/test-security.mjs` — `suiteRunSandbox`)

- [x] gated on `process.platform === 'win32'` + binary presence.
- [x] `run` with offload OFF → unchanged behavior (regression guard).
- [x] `run echo` with offload ON → `exit_code:0`, `sandboxed:true`.
- [x] `run` exit code propagates (`cmd /c exit 7` → `exit_code:7`).
- [x] `run` with `timeout_ms` < runtime → `timed_out:true`, child killed.
- [x] Add per-spawn Job Object in `SandboxAppContainer::spawn()` so timeout kills
      the full process tree, not just the immediate shell process. Implemented with
      `CREATE_SUSPENDED` → `AssignProcessToJobObject` → `ResumeThread`;
      `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` reaps survivors on close, and timeout
      calls `TerminateJobObject` (tree-kill) instead of `TerminateProcess`.
- [x] write inside granted cwd succeeds.
- [x] write outside cwd fails (deny-by-default). `runsandbox.6` — absolute write
      to a sibling dir → nonzero child exit, file not created.
- [x] cwd grant revoked after exit (second external probe fails). `runsandbox.7` —
      probes the live DACL with `icacls` and asserts the run's `containerSid` is
      absent after `spawn()` revokes + deletes the profile.
- [x] stdout/stderr text round-trips through the envelope.
- [x] `npm run test:security:runsandbox` — **27 assertions** green.

#### Lifecycle / cancellation / tracing parity with `ProcessRunner`

Brought the AppContainer path up to the same lifecycle contract as the inline
`core/process_runner.cpp` path (previously the sandbox path was blind: a single
blocking `WaitForSingleObject(timeoutMs)`, no cancel, output only delivered at exit).

- [x] **Live streaming**: `SandboxSpawnOptions.onOutputChunk` — reader threads now
      forward stdout/stderr chunks live (RunTool wires it to `g_chunk_hook`, the same
      `ToolFileProgress` event surface the inline path uses). No more "dump at exit".
- [x] **Cooperative cancel**: `SandboxSpawnOptions.onCancelCheck` polled in a 100 ms
      wait loop; RunTool wires `media::cli::cancel_requested`. On cancel → tree-kill
      via `TerminateJobObject(130)` → `SandboxResult.cancelled = true`.
- [x] **External abort**: `pm::security::abort_active_sandbox()` tree-kills the live
      sandbox Job from another thread; `RunTool::abort_active_run()` calls it alongside
      `process::abort_captured_run()`, so the **UI Stop button now stops sandboxed runs**
      with no UI changes (mirrors `g_captured_process` for the inline path).
- [x] **Envelope**: `cancelled:true` / `error:"run: cancelled"` branch, matching the
      non-sandbox envelope exactly.
- [ ] **End-to-end cancel test** lives with the deferred in-process loopback/UI harness
      (`suiteLoopbackSandbox`). The poll-loop + tree-kill machinery is already proven by
      `runsandbox.4` (timeout). A cross-process probe was attempted and dropped: Node
      cannot deliver a real console `CTRL_BREAK` to a child without native FFI, so
      `process.kill(pid,'SIGBREAK')` does not exercise `cancel_requested()`.

### Phase B — Gateway routing  (after Phase A is green)

- [x] Add `std::string sandboxBackend` field to `PolicyDecision` (empty = no sandbox).
      Plus `CapabilityGrant.sandboxBackend` (consent source) and `ToolRequest.sandboxHint`
      (deferred AI-advisory source), both round-tripped in `SecurityPersistence`.
- [x] `SecurityGateway` owns a `BackendRouter` (map `name → SandboxBackend*`,
      `src/security/backends/BackendRouter.hpp`). `SandboxAppContainer` registered at
      startup in `agent_factory.cpp` and in the security CLI `authorize` path, both
      guarded by `_WIN32 && FEATURE_SECURITY_SANDBOX`.
- [x] `SecurityGateway::authorize()` sets `PolicyDecision::sandboxBackend` from the
      matching grant (or `sandboxHint`), but only when the named backend is registered
      (`sandboxBackendFor()` resolves it). The Phase-A raw flag in `RunTool` is now
      authoritatively driven by this decision: `agent_factory` injects
      `args["sandbox"] = decision.sandboxBackend` before dispatch. (`executeInSandbox`
      was kept out — the gateway resolves the backend; the caller spawns, so the
      portable gateway stays decoupled from `SandboxSpawnOptions`.)
- [x] CLI observability + tests: `grant add --sandbox-backend`, `authorize` output
      carries `sandboxBackend`, and `suiteSandboxRouting` (**5 assertions**) proves
      a routed grant surfaces `sandboxBackend=appcontainer` in the decision.
- [ ] On access-denied signal from worker, gateway receives `PrivilegeEscalationRequest`
      from the broker pipe and re-routes through `authorizeWithConsent()`.

### Routing signal — user consent only  (Phase B)

Only one signal layer for now: **the user decides, via the consent dialog.**
Per-tool config and AI-advisory hints are explicitly deferred (see below) so the
first shipping behavior is simple and auditable — no implicit sandboxing.

- [x] `ConsentDlg` exposes a sandbox checkbox when a `SandboxBackend` is registered
      and the action is `Execute` or `Write`. Covered by `test-security-ui.mjs`:
      GUI consent persists `sandboxBackend=appcontainer` and the reused grant routes
      `RunTool` through AppContainer.
- [x] On confirm, `SecurityPersistence` stores the grant flag `"sandboxBackend":
      "appcontainer"` (field + round-trip done; CLI: `grant add --sandbox-backend`).
- [x] The matching grant propagates `sandboxBackend` into `PolicyDecision` —
      done in `SecurityGateway::authorize()` (and `resolveConsent()` for fresh
      grants), gated on the backend being registered in the router.
- [x] Default when no grant says otherwise: **no sandbox** (inline execution).
      Sandboxing is never silently imposed; it is always a user choice.

### Deferred routing sources  (not now — revisit after consent path ships)

- [ ] **Per-tool config** (`tools.json`: `"mcp.fs.write": { "sandbox": "appcontainer" }`,
      `PolicyEngine` populates a routing table, profile-level force-sandbox).  Deferred:
      adds policy surface area before we know the consent UX is right.
- [ ] **AI advisory** (`ToolRequest.sandboxHint` from an LLM `sandbox_hint` field).
      The field + gateway handling already exist (the gateway honours `sandboxHint`
      only when a backend of that name is registered, after grants). Deferred: wiring
      an LLM-populated source — the model is untrusted, so it stays behind consent.

### PrivilegeEscalationRequest IPC  (broker ↔ sandboxed worker)

- [ ] Named-pipe protocol: worker writes one JSON line per request;
      broker reads with a `ReadFile` loop on a dedicated thread.
- [ ] Pipe name scheme: `\\.\pipe\pm-sandbox-<sessionId>-<moniker>`.
- [ ] Broker response: `SecurityGateway::authorizeWithConsent()` → write
      `{ "id": …, "granted": true/false }` back to pipe.
- [ ] Worker: `granted=true` → retry the file op; `false` → return
      `{ "ok": false, "security_denied": true }` as tool result.
- [ ] Pipe lifetime: open at `spawn()`, close at process exit or `revoke`.

> Deliberately **not next**: surfacing sandbox child processes directly over
> `cmd_ipc`. `cmd_ipc` remains a full-trust observability/control bus for
> broker-owned instances and agents; an AppContainer worker must not become a
> peer on that bus. If escalation IPC returns, keep it as a dedicated
> broker-created pipe ACL'd to the specific container SID, with one narrow
> request/response verb.

### Sandboxed stdio MCP clients  (`src/llm/mcp_stdio_client.cpp`)

`RunTool` and stdio MCP look similar from the agent ("tool call"), but their
process boundaries differ:

- `RunTool` is one process per call, so `PolicyDecision.sandboxBackend` can
  become `args["sandbox"]` and the tool can call `SandboxAppContainer::spawn()`.
- stdio MCP starts a **long-lived server process** in `StdioMcpClient` during
  `AgentMcpBridge::try_create()`. Later `tools/call` requests are JSON-RPC over
  stdin/stdout, not process spawns. Passing `args["sandbox"]` into an MCP call
  would just become a remote tool argument; it would not sandbox the server.

- [x] Add a small hermetic **stdio MCP test server** under `tests/fixtures/mcp/`
      (Node is fine; no network, no `npx`, no Office/LibreOffice dependency).
      It should implement `initialize`, `notifications/initialized`,
      `tools/list`, and `tools/call` with tools deliberately designed for
      security tests:
  - [x] `probe_identity` → returns pid, cwd, env marker, and (later) sandbox
        metadata surfaced by the client/broker.
  - [x] `write_probe { path, content }` → attempts a filesystem write and returns
        success/failure details. Used to provoke deny-by-default and escalation.
  - [x] `read_probe { path }` → attempts a filesystem read for granted/ungranted
        path assertions.
  - [x] `spawn_child_probe` → spawns a child process so Job Object / tree-kill
        behavior can be tested for sandboxed MCP servers. Covered by `npm run test:mcp`
        AppContainer stdio timeout/tree-kill assertions.
  - [x] `sleep_probe { ms }` → allows cancellation/timeout lifecycle tests.

- [x] Extract a reusable MCP stdio fixture helper for orchestrator tests:
      `tests/orchestrator/test-mcp.mjs` already covers embedded HTTP MCP; it
      should share helper code with `test-security.mjs` rather than duplicating
      temp config-dir + `mcp.json` generation. Suggested shape:
  - [x] `tests/orchestrator/lib/mcp-fixture.mjs` exports
        `writeStdioMcpConfig({ configDir, serverName, command, args, env })`,
        `mcpToolName(serverName, remoteTool)`, and transcript envelope helpers.
        It also owns temp fixture config creation, loopback MCP settings seeding,
        MCP execute grant rows, canonical tool naming, `runLoopbackAgent()`, and
        transcript text helpers.
  - [x] Move common `PM_LOOPBACK_SCRIPT` / agent spawn plumbing used by
        `suiteLoopbackSandbox` and future MCP suites into a small shared helper
        so both `test-security.mjs` and `test-mcp.mjs` use the same loopback
        conventions. Verified with `npm run test:mcp` and
        `npm run test:security:loopbacksandbox`.

- [x] Add non-sandbox stdio MCP baseline coverage in `test-mcp.mjs`:
  - [x] Temp `--config-dir` with `mcp.json` pointing at the fixture server.
  - [x] `llm info --json` smoke confirms the seeded profile/settings shape;
        live MCP merge is proven by the loopback agent call because `llm info`
        reports built-in catalog data rather than the agent's MCP-merged turn
        catalog on this path.
  - [x] Loopback agent call to `mcp_fixture__probe_identity` succeeds.
        Important test detail: the temp `settings.json` seeds a default
        loopback chat preset with `tools.mcp_tools_enabled=true` and a
        `permissions` grant for `mcp_fixture__probe_identity`; otherwise the
        security gateway correctly prompts/denies the MCP execute call in
        headless mode.
  - [x] Loopback agent call to `mcp_fixture__write_probe` writes inside the
        workspace when granted/allowed by the normal gateway path.
        `test-mcp.mjs` grants the MCP execute request for the fixture tool, calls
        it through the loopback agent, then verifies the file bytes on disk.

- [x] Add sandboxed stdio MCP coverage once the backend
      supports a persistent sandboxed process/session API:
      Reconciled 2026-06-26: the coverage lives in `test-mcp.mjs` because MCP
      fixture setup and direct `llm info --mcp-probe` smoke already live there;
      the loopback route still exercises the real agent/security gateway path.
  - [x] **Spike pipe-handle security first** for AppContainer stdio:
        anonymous inherited stdin/stdout handles work when the child is launched
        through `stdio_child_runner` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`.
        `npm run test:mcp` now includes a Windows-only direct `llm info --mcp-probe`
        smoke that launches a tiny PowerShell MCP handshake server in AppContainer,
        sends `initialize` + `tools/list`, and cleans up the Job/Object/profile.
        No DACL grants for pipe handles and no named-pipe fallback were needed for
        this proof.
  - [x] Define sane lifecycle defaults for the spike before generalizing it:
        startup deadline (process created → first readable byte / MCP
        `initialize` response) is bounded by `set_request_options()` and the
        direct smoke sets `PM_MCP_TIMEOUT_MS=5000`. Timeout teardown now stops
        the sandbox Job, closes broker handles, revokes path ACLs, and deletes
        the transient AppContainer profile.
  - [x] Handle “AppContainer launched but does not respond” as a first-class
        state, not a hung test: reader thread sees no JSON-RPC line before the
        handshake deadline → kill the process tree, drain/close pipes, and
        surface a bounded MCP stdio timeout/error. Implementation note: Windows
        stdio reads now use bounded `PeekNamedPipe` polling plus an explicit stop
        flag because cross-thread close/cancel of a synchronous anonymous-pipe
        `ReadFile` was not sufficient for reliable teardown.
  - [x] Runtime timeout / idle policy:
        per-request JSON-RPC waits keep using `set_request_options()` timeouts
        and cancel checks; a timed-out request on a persistent sandboxed MCP
        server terminates the whole server tree rather than leaving a possibly
        confused protocol session alive. Default matches existing MCP timeout
        behaviour unless the caller supplies a tighter timeout.
  - [x] Kill escalation policy:
        cooperative close (stdin close / protocol shutdown when available) →
        `TerminateJobObject` after a small grace period → handle close and ACL
        revoke regardless of process exit result. Cleanup must be idempotent so
        destructor, explicit cancel, startup failure, and test timeout can race
        without double-revoking or leaking handles.
  - [x] Extreme-case assertions for the direct smoke harness:
        `npm run test:mcp` now covers child never writes, child writes malformed
        JSON forever, child exits before `initialize`, child spawns a grandchild
        then hangs, and broker cancellation during handshake via
        `PM_MCP_CANCEL_AFTER_MS`. Each case finishes within bounded time,
        terminates the sandbox Job, and asserts no raw AppContainer SID remains
        on the granted temp directory DACL.
  - [x] Add a minimal direct smoke harness for the spike before agent routing:
        `mcp.json` can set `sandboxBackend:"appcontainer"`, `sandboxMoniker`,
        `cwd`, and `paths`; `llm info --mcp-probe` launches the stdio server
        through `StdioLaunchOptions` and validates a direct MCP handshake before
        any agent turn. The passing smoke currently uses a tiny PowerShell MCP
        handshake script in the granted temp directory. The Node fixture remains
        the next integration step because Cursor's bundled Node exits inside the
        AppContainer unless its runtime/path dependencies are made available.
  - [x] Implement persistent AppContainer stdio launch in
        `src/core/stdio_child_runner.cpp` plus `SandboxAppContainer` reusable
        launch support:
        inherited stdin/stdout handles, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`,
        per-session Job Object (`KILL_ON_JOB_CLOSE`), granted paths, cleanup/revoke,
        and returned backend/container metadata. This is the prerequisite for
        every assertion below; per-call MCP JSON arguments cannot sandbox an
        already-running server.
  - [x] Extend `StdioLaunchOptions` deliberately, not as ad-hoc MCP fields:
        `sandbox_backend`, `paths`/resource grants, optional moniker/profile
        naming, and enough metadata for teardown. Keep protocol-specific JSON-RPC
        state out of this layer.
  - [x] Teardown contract: closing `StdioChildProcess` terminates the full child
        tree via Job Object, closes broker handles, revokes all path ACLs granted
        to the container SID, and deletes or reuses the AppContainer profile only
        according to the existing backend policy.
  - [x] Metadata contract: `StdioChildProcess::info()` carries at least `pid`,
        `sandbox_backend`, `container_sid`, and a boolean/field indicating whether
        launch actually used a sandbox.
  - [x] Surface sandbox metadata from `AgentMcpBridge` on MCP tool-result
        envelopes when the backing server is sandboxed.
        `IMcpSession::session_info()` now exposes stdio child metadata, and
        MCP result envelopes carry `sandboxed=true`,
        `sandbox_backend=appcontainer`, `containerSid`, and the backing pid.
  - [x] A consent/grant with `sandboxBackend=appcontainer` for the MCP tool
        routes the **MCP server process** through AppContainer at startup, not
        the per-call JSON arguments. `AgentMcpBridge` inspects persisted MCP
        execute grants for each server at bridge creation and applies the
        backend to `StdioLaunchOptions` before the server is started; the
        `mcp.json` fixture only supplies cwd/path grants.
  - [x] Fixture `probe_identity` result exposes `sandboxed=true`,
        `sandbox_backend=appcontainer`, and `containerSid` (broker/client
        envelope metadata; the sandboxed worker should not learn more than it
        needs). Covered by `npm run test:mcp` loopback probe assertions.
  - [x] `write_probe` inside granted workspace succeeds.
        Covered by `npm run test:mcp` using the AppContainer-backed PowerShell
        MCP fixture and a granted temp workspace.
  - [x] `write_probe` outside granted paths fails under the AppContainer.
        The bridge preflights sandboxed `write_probe` paths against the launch
        grants and returns a normal tool-result envelope instead of dispatching
        an impossible write.
  - [x] Un-granted write produces a `PrivilegeEscalationRequest`-style signal
        once the dedicated broker↔worker pipe exists; broker denial becomes
        `security_denied=true` as the MCP tool result, not a thrown exception.
        Current implementation is the broker-side preflight in
        `AgentMcpBridge::call_tool()` for sandboxed `write_probe`, returning
        `security_denied=true` plus `privilegeEscalationRequest`. The future
        dedicated broker↔worker pipe can reuse the same envelope contract.
  - [x] `spawn_child_probe` + timeout/cancel proves the full MCP server process
        tree is killed. The PowerShell fixture spawns a grandchild that writes a
        marker after delay; `PM_MCP_TIMEOUT_MS` kills the server Job and the
        marker never appears.
  - [x] Server reuse: two `tools/call` requests hit the same sandboxed stdio
        server process/profile until bridge teardown. Covered by consecutive
        `probe_identity` loopback calls asserting a stable pid.

- [x] Design/implement a **generic persistent stdio child runner** (not
      MCP-specific). MCP stdio is just the first consumer; the primitive should
      be reusable by future plugin/language-server/worker launches.
  - [x] Keep the layers separate:
        launch primitive = process + stdin/stdout handles + env/cwd/job/sandbox;
        session plumbing = read/write/line framing/cancel; protocol layer =
        MCP JSON-RPC. Only the launch primitive should care whether the child is
        normal or AppContainer/LPAC.
  - [x] Open decision: place the primitive as a new `process_runner` capability
        (fourth shape: persistent bidirectional stdio) or a small sibling helper
        (`stdio_child_runner`). Do **not** route this through
        `command_runner.hpp`; that layer is UI command orchestration
        (run ids, ribbon/launcher pulse state, sinks) and is the wrong semantic
        boundary. Implemented as sibling `src/core/stdio_child_runner.*`.
  - [x] Suggested API shape: `StdioLaunchOptions { executable, args, cwd,
        extra_env, sandbox_backend }` →
        `StdioChildProcess { pid, stdin/stdout operations, terminate_tree(),
        sandbox metadata }`.
  - [x] Normal launch path: reuse/extract `process_runner` quoting/env/cwd/job
        logic and return owned stdin/stdout handles instead of waiting for exit.
  - [x] Sandbox launch path: AppContainer/LPAC `CreateProcessW` with inherited
        stdio handles, per-session Job Object, granted paths, and container SID
        metadata. Implemented in `stdio_child_runner` and exercised by
        `npm run test:mcp` plus `npm run test:security`.
  - [x] Spike handle security first: anonymous pipe handles inherited into an
        AppContainer work for this broker-created stdio path; no pipe-handle DACL
        grant or named-pipe fallback was needed. Proven by direct `llm info
        --mcp-probe` AppContainer handshakes before full agent-loop coverage.
  - [x] Refactor `StdioMcpClient` to consume the generic stdio child runner while
        retaining its existing JSON-RPC framing and
        `set_request_options()` cancellation semantics. Cancel should stop the
        active JSON-RPC wait and terminate the child tree.
  - [x] Expose pid/containerSid/backend name back to `AgentMcpBridge` so MCP
        tool-result envelopes can include sandbox metadata when the server was
        launched sandboxed. `IMcpSession::session_info()` freezes launch-time
        pid/backend/containerSid/grant metadata for the server session, and
        `AgentMcpBridge` includes it in MCP result envelopes. Full roundtrip
        coverage now includes persisted CLI/UI-style sandbox consent grants
        routing stdio MCP startup through AppContainer, plus loopback tool calls
        for metadata, granted writes, denied writes, server reuse, and tree-kill.

> Existing `tests/scripts/office-mcp.sh` and `tests/ui/mcp.json` are useful
> manual/integration references, but they are not hermetic security fixtures:
> they depend on external packages, local paths, or network/API state. The
> sandbox tests need a repo-local stdio server whose behaviour is deterministic
> and intentionally adversarial.

### Phase B — loopback agent test expansion  (`tests/orchestrator/test-security.mjs`)

Routing decision (not a raw flag) drives the sandbox, proven through a **real
agent turn** scripted by the loopback router.

- [x] **`suiteLoopbackSandbox`** — gated on `process.platform === 'win32'`,
      `npm run test:security:loopbacksandbox`. The grant is written with the
      `pm-image-security` CLI into a temp `--config-dir`; the agent
      (`tanit-cli ... --config-dir <same>`) loads it, so the routing fires
      through the genuine `SecurityGateway.authorize()` path — not a synthetic
      flag. 13 assertions, all green. The full proven chain:

      persisted grant (`sandboxBackend=appcontainer`)
        → `SecurityGateway.authorize()` sets `PolicyDecision.sandboxBackend`
        → `agent_factory` injects `args["sandbox"]`
        → `RunTool` offloads to `SandboxAppContainer`
        → tool-result envelope: `sandboxed:true` + `sandbox_backend` + `containerSid`.

  - [x] `lbsbx.1` Routed grant → agent `run` executes in the AppContainer:
        envelope `sandboxed=true`, `sandbox_backend=appcontainer`,
        `containerSid` (S-1-15-2-…), stdout captured from the sandbox.
  - [x] `lbsbx.2` Contrast — grant **without** a backend → run allowed but
        `sandboxed!=true` (inline). Proves the sandbox is the *decision's*
        effect, never silently imposed.
  - [x] `lbsbx.3` No grant → gateway denies headless (`security_denied=true`),
        nothing sandboxed (default = no sandbox + gated).
  - [~] LPAC flow / two-call profile-cache / un-granted-write escalation: the
        underlying behaviour is already covered by `suiteSandbox` (lpac, stable
        SID) and `suiteRunSandbox` (deny-by-default, revoke-after-exit). Not
        re-asserted through the loopback layer to avoid duplicate slow turns.

  > **Cancellation / streaming are intentionally not driven here.** The agent
  > runs in a child process and Node cannot deliver a real console `CTRL_BREAK`
  > to flip `cancel_requested()` across the process boundary (verified — see the
  > reverted `runsandbox.8`). The poll-loop + Job-Object tree-kill is proven by
  > `runsandbox.4` (timeout) and live streaming by `RunTool`'s chunk hook;
  > interactive cancel/stream remains manual-UI verification.

- [x] **Phase 1.9 agent-loop + consent flow**:
  - [x] CLI consent path: `write_file` → Ask on stderr → `allow_session` response
        → grant persisted; JSON reply with `"sandboxBackend":"appcontainer"` →
        immediate decision routes + reused grant routes.
  - [x] `secret_path` → Deny; same `tool+path` twice → no re-prompt.
        Implemented as an in-process `SecurityGateway` denial cache keyed by
        session/task/tool/action/target. It is deliberately not persisted.
        `suiteAgentConsent` asserts two identical denied `write_file` calls
        produce only one emitted `consent_request`.
  - [x] Deny response → `security_denied` injected as tool result (not an exception).
        `suiteAgentConsent` asserts both repeated tool results are
        `security_denied=true`; `suiteLoopbackAgent` still covers the single
        System32-path denial envelope.
  - [x] Sandbox + consent combined at gateway level: user upgrades to
        "allow in sandbox" → subsequent authorization carries
        `sandboxBackend=appcontainer`.
  - [x] Full native `--interactive --gui` turn: consent approval with sandbox
        checkbox → persisted `sandboxBackend=appcontainer` grant → `RunTool`
        sandboxed execution through the already-proven loopback route. Covered
        by `test-security-ui.mjs` using `DEVELOPER` for `builtin.run execute`,
        because `LIGHT` correctly hard-denies execute before GUI consent.

### npm scripts

- [x] `"test:security:sandbox"` → `node tests/orchestrator/test-security.mjs --only sandbox`
- [x] `"test:security:runsandbox"` → `--only runsandbox` (RunTool offload, direct tools-call)
- [x] `"test:security:sandboxrouting"` → `--only sandboxrouting` (Phase B gateway routing)
- [x] `"test:security:loopbacksandbox"` → `--only loopbacksandbox` (Phase B routing via a real agent turn)
- [x] `"test:security:all"` → `npm run build:cpp:security && node tests/orchestrator/test-security.mjs`
