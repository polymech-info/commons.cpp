# Command Scheduler Next

Implementation plan for daemon-owned custom-command triggers, scheduling,
cross-process lifecycle, and Settings UI.

This scheduler executes entries from the custom command document. It is not the
LLM `AgentScheduler`, and it is not `AppTaskManager`.

## Current status

**Engine, host, and shared Schedule card are in tree.** Next real hole is
stale claim/lease/child reconcile at startup. Parked: extracted Run options
editor, DayPicker localization, Settings RPC wiring on the native side,
cron/DST, and Linux/macOS daemon hosts.

Shipped:

| Piece | Location |
|---|---|
| `FEATURE_SCHEDULER` default ON | `CMakeLists.txt`, `CMakePresets.json` |
| Compile defs on GUI + CLI | `FEATURE_SCHEDULER=$<BOOL:...>` |
| Constructible `SchedulerEngine` | `src/tasks/scheduler_engine.*` |
| Atomic file store | `src/tasks/scheduler_store.*` → `media::runtime_settings::scheduler_state_path()` (`<config_dir>/run-ipc/scheduler/state.json`) |
| Command-document compile | `once`, `interval`, `daily`, `weekly`, `monthly` (UTC) |
| Router + file leases | `src/tasks/scheduler_router.*`, `scheduler_lease.*` |
| Win32/POSIX leader lock | `scheduler_platform_win32.cpp` / `_posix.cpp` (no Windows types in headers) |
| CLI verbs | `compile/next/tick/run-now/reload/notify/status/pause/resume/paths/lock/serve` (status payloads include command label, action summary, XBlox path/context) |
| Isolated smoke harness | `tests/scheduler/test-scheduler-smoke.mjs` |
| Cooperative claim | `src/tasks/scheduler_claim.*` → `media::runtime_settings::scheduler_claim_path()` (`claim.json`) |
| UI scheduler host | `CMainFrame` prio 100; daemon/`scheduler serve` prio 10; one OS lock |
| App commands | `schedulerstart` / `schedulerstop` / `schedulerpause` |
| Interval catch-up | one collapsed due slot per wake; no missed-slot backlog |
| Shared Schedule card | `apps/shared/components/customCommands/schedule/` |
| npm scripts | `test:scheduler`, `test:scheduler:build` |
| Web feature helper | `apps/shared/settings/featurePolicy.ts` → `isSchedulerEnabled()` |

Seeding for tests and CLI:

- `--commands <file>` overrides the command document (same flag as
  `test-commands.mjs`).
- `--config-dir <dir>` isolates `get_config_dir()` and scheduler state.
- Use both. Do not write the developer's real profile.

```text
tanit-cli --config-dir <tmp> --commands <tmp>/commands.json scheduler compile
tanit-cli --config-dir <tmp> --commands <tmp>/commands.json scheduler next --now 2026-08-22T12:00:00Z
tanit-cli --config-dir <tmp> --commands <tmp>/commands.json scheduler tick --now 2026-08-22T12:00:00Z
```

`--now` / `--namespace` / `--count` are subcommand options (`scheduler next --now …`).
Parent-only flags are ignored by CLI11 after the subcommand name.

Also shipped: `tick --execute` / `run-now --execute` for `externalCommand` and
`cliCommand` / XBlox (spawn `tanit-cli`, expand `${TANIT_SHARED}` and other
command variables)
targets (lineage env: `PM_IMAGE_COMMAND_ID`, `PM_IMAGE_TRIGGER_KIND`,
`PM_IMAGE_SCHEDULE_ID`, `PM_IMAGE_OCCURRENCE_ID`); overlap skip in one tick;
persisted pause/resume (CLI also IPCs the live leader; tick save cannot clear
`paused`); `scheduler serve [--execute] [--seconds N]` foreground host that
stays up as a follower when it cannot hold the lock, IPC Daemon, file-watch/mtime
poll, stderr progress (found schedules + due/execute lines), and Ctrl+C /
`cancel_requested()` exit; UI process `SchedulerHost` (priority 100) that
cooperatively takes the lock so `appCommand` schedules can run;
portable
`get_daemon_json_path()` + `effective_command_document_path()`; daemon
execute-on-tick (async), command-document watch, leader lock, `set_stop_hook`,
and IPC `scheduler_pause` / `scheduler_resume` / `scheduler_run_now`.

Not shipped yet: stale claim/lease/child reconcile at startup, cron
execution, DST/clock-change, extracted shared Run options editor, DayPicker
locale/dir tests, native Settings scheduler RPC handlers, process-tree stop /
`Cancelled`, Linux/macOS daemon hosts.

## Scope and ownership

There are three separate scheduling domains:

| Domain | Owner | Purpose |
|---|---|---|
| Command scheduler | Instance-based scheduler core hosted by the UI process (preferred leader) or daemon/`scheduler serve` | Global hotkeys and time-based execution of custom commands/pipelines |
| App tasks | UI process / `AppTaskManager` | One-shot `at_boot` and `when_idle` UI lifecycle work |
| LLM scheduler | Agent host / `AgentScheduler` | Scheduled agent turns with task memory |

`AppTaskManager` may act as a trigger adapter for a custom command configured
for `at_boot` or `when_idle`, but it must delegate execution to the shared
custom-command executor. It does not own scheduled runs, recurrence, IPC, or
cancellation.

For global hotkeys and time schedules:

1. The daemon owns the trigger.
2. The daemon's `cmd_run::Runner` owns the spawned process.
3. A pm-image worker may additionally own cooperative shutdown.
4. `command_control` discovers and controls the owner through `cmd_ipc`.

The daemon must not fire-and-forget `tanit-cli <custom-id>`. That leaves the
daemon without authoritative lifecycle state after the dispatcher exits.

## Self-contained, composable scheduler core

The scheduler implementation itself is **not a singleton**. Do not add
`Scheduler::instance()`, process-global mutable schedule state, static worker
threads, or hidden access to `config_dir()`, IPC, `Runner`, wall-clock time or
the command store.

`SchedulerEngine` is an ordinary constructible object with injected
dependencies:

```text
SchedulerEngine
  <- Clock
  <- ScheduleStateStore
  <- OccurrenceSink
  <- engine namespace / instance options
```

The core:

- accepts an immutable set of compiled schedule definitions;
- calculates/reconciles due occurrences;
- persists recurrence state through the injected store;
- emits normalized `TriggerOccurrence` values through the sink;
- can be instantiated more than once in one process for independent profiles,
  pipelines, previews and tests;
- owns no process runner, IPC server, file watcher, tray, hotkey, config path or
  leader lock.

The daemon is a host adapter. It resolves `config_dir()`, loads commands,
watches files, acquires scheduler leadership, supplies persistent state, routes
occurrences and owns execution/lifecycle integration. A different pipeline host
may construct the same engine with a different store and sink.

### Leader is not a code singleton

Only one host may be the authoritative dispatcher for a given:

```text
(effective config directory, scheduler namespace)
```

This is a cross-process single-writer/leadership rule enforced by an external
OS-held lock. It is not a restriction on constructing scheduler objects.
Non-leaders may create read-only engines for preview/status, but may not commit
runtime state or emit dispatchable occurrences.

Leadership must be an explicit capability passed by the host. On leadership
loss, the host disables new emission immediately. Existing runs remain owned by
their execution owner and follow the documented shutdown/handoff policy.

Priority only decides who may hold the existing lock. The lock cannot be
stolen; a higher-priority host writes `claim.json` and the current leader
yields on its 250 ms `step()`:

```text
UI (100)  >  daemon / scheduler serve (10)  >  inspect CLI (never claims)
```

Same priority: first holder wins. A follower retries the lock every tick and
does not emit. App commands dispatch only when the UI leader has set the
router hook; daemon/serve still skip them. Missed app ticks are not replayed.

Likewise, `runOptions.singleton` is an optional execution policy for a command.
It does not make the scheduler, trigger, pipeline or daemon class a singleton.

### Trigger and pipeline contract

Time scheduling is one trigger source among others:

```text
schedule/interval/hotkey/app/IPC trigger
  -> TriggerOccurrence
  -> TriggerRouter or pipeline
  -> conditions/transforms
  -> shared command execution planner
  -> optional command lease
  -> execution owner
```

A direct command schedule is shorthand for a small pipeline:

```text
interval schedule -> execute custom command
```

The same interval trigger may instead feed a larger pipeline:

```text
interval schedule -> check prior result/state -> transform inputs
                  -> execute command -> publish downstream event
```

The scheduler does not execute the command and does not wait/sleep inside a
command process to implement intervals. It emits an occurrence at each planned
boundary; the router/pipeline decides what that occurrence activates. Pipeline
completion time must not shift interval cadence.

Every occurrence carries:

- `triggerId` and trigger kind;
- immutable `scheduleId` where applicable;
- `plannedAt`;
- stable `occurrenceId`, derived from scheduler namespace + schedule ID +
  planned occurrence identity;
- `correlationId` and optional `causationId`;
- command/pipeline target reference;
- immutable definition generation/hash;
- retry/attempt number without changing occurrence identity.

The occurrence ID is the deduplication boundary across daemon restart,
leadership handoff and pipeline retry. Trigger chains also carry a bounded hop
count so a command that edits/fires its own trigger cannot create an
uncontrolled recursive loop.

Scheduling a pipeline and scheduling a command use the same engine. The target
is typed (`command` or `pipeline`) and the host resolves it. The scheduler core
must not depend on either target implementation.

For v1, `commands[].triggers.schedules[]` remains the convenient persisted
authoring form and implicitly targets its parent command. Compilation converts
it to a generic scheduled-target definition before it reaches
`SchedulerEngine`. A pipeline document can compile the same trigger schema with
an explicit pipeline target. Do not encode “parent custom command” assumptions
inside recurrence calculation or state storage.

### Native source placement

Keep the native scheduler implementation in `src/tasks/`. It is task/trigger
infrastructure, not a CLI implementation and not Windows UI code.

Landed:

```text
src/tasks/
  scheduler_types.hpp
  scheduler_engine.hpp
  scheduler_engine.cpp
  scheduler_store.hpp
  scheduler_store.cpp
src/cli/
  pm_image_cmd_scheduler.hpp
  pm_image_cmd_scheduler.cpp
```

Still to add:

```text
src/tasks/
  scheduler_router.hpp
  scheduler_router.cpp
  scheduler_host.hpp
  scheduler_host.cpp
  scheduler_platform.hpp
  scheduler_platform_win32.cpp
  scheduler_platform_posix.cpp
```

Split further only when a responsibility becomes large; do not create one file
per schedule kind. Recurrence calculation remains portable in
`scheduler_engine.cpp`. Public native scheduler types live in `pm::tasks`,
matching the existing task modules.

Any Win32-specific behavior must live in a matching `_win32.cpp` translation
unit, including named mutex/events, Windows session identity, Job Object or
handle semantics, service/tray wake integration and Win32 path/file quirks.
Portable headers must not expose `HANDLE`, `HWND`, `DWORD` or include
`windows.h`.

Use `_posix.cpp`, `_linux.cpp` or `_macos.cpp` counterparts where behavior is
not portable. The build selects exactly one implementation of the narrow
`scheduler_platform.hpp` interface. Avoid broad `_WIN32` branches in
`scheduler_engine.cpp`, `scheduler_store.cpp` and `scheduler_router.cpp`.

`src/cli/pm_image_cmd_daemon.cpp` remains a thin executable composition root:
parse CLI options, construct the `src/tasks` host and connect shutdown. It must
not accumulate recurrence, persistence, routing, locking or platform scheduler
logic.

### Build and web feature gate

Gate the complete scheduler capability behind:

```cmake
option(FEATURE_SCHEDULER
    "Task scheduler engine, scheduled command/pipeline triggers and scheduler UI"
    ON)
```

`FEATURE_SCHEDULER` defaults to `ON` and is already in `CMakeLists.txt` plus
the `CMakePresets.json` feature descriptions and base cache variables:

```json
"FEATURE_SCHEDULER": "ON"
```

Individual SKU presets may explicitly set it to `OFF`. Do not infer it from
`FEATURE_DAEMON`: the self-contained scheduler engine may be embedded in another
task/pipeline host when the standalone daemon is disabled. Daemon-owned
scheduling is available only when both capabilities are built:

```text
FEATURE_SCHEDULER && FEATURE_DAEMON
```

When `FEATURE_SCHEDULER=OFF`:

- Do not compile/link scheduler engine, store, router, platform or daemon
  scheduler-host translation units.
- Do not acquire scheduler leadership, create scheduler state/lease
  directories, watch schedule definitions or dispatch timed occurrences.
- Scheduler-specific CLI and IPC actions are absent or return a structured
  `feature_disabled` result; they must never appear to succeed as no-ops.
- Existing `triggers.schedules` JSON must remain round-trippable. A build with
  the feature disabled must not erase schedule definitions when editing other
  command fields.
- Existing non-scheduler daemon features such as global hotkeys remain governed
  by `FEATURE_DAEMON`.

Pass `FEATURE_SCHEDULER=$<BOOL:${FEATURE_SCHEDULER}>` to every native target
that compiles scheduler call sites, including the GUI host, CLI/daemon host and
the task library target. Keep feature-off branches at composition/API
boundaries rather than scattering preprocessor checks through recurrence code.

#### `APP_FEATURES` exposure

The existing CMake feature-manifest writer collects every `FEATURE_*` cache
variable, so defining the option exports `FEATURE_SCHEDULER` into
`dist/shared/features.json` (or the SKU-specific feature manifest).

`CWebView.cpp` injects the manifest as immutable `window.APP_FEATURES` before
the web bundle runs. `CWebViewManager.cpp` remains the native authority for
scheduler RPC registration/dispatch:

- compile/register scheduler RPC handlers only when `FEATURE_SCHEDULER` is on;
- otherwise return structured `feature_disabled` for a stale page/request;
- never trust the JavaScript feature check as authorization or proof of native
  capability.

Shared helper is in `apps/shared/settings/featurePolicy.ts`:

```ts
export function isSchedulerEnabled(
  features: AppFeatureMap = readAppFeatures(),
): boolean {
  return isAppFeatureEnabled(features, "FEATURE_SCHEDULER", false);
}
```

All shared scheduler entry points, Schedule cards, status/actions and
scheduler-specific validation use this helper. The Settings host must not
reimplement the check. Use a conservative `false` fallback when the key is
missing so an old/native host cannot expose controls for RPC methods it does not
support.

Feature gating controls availability, not data ownership. Keep schedule fields
in shared schemas and serializers even when the editor is hidden, so toggling
the build feature off and back on is lossless.

## Required invariants

- Exactly one leader may emit/commit occurrences for a given effective
  `config_dir()` and scheduler namespace. Scheduler objects themselves are not
  singletons.
- Every run has one execution owner, a stable command UUID, a dispatch
  `commandId`, an immutable `scheduleId` when scheduled, and a stable
  owner-local `runId`.
- Every daemon-owned run is discoverable and stoppable from another process.
- `Started`, `Exited`, `Failed`, and `Cancelled` are emitted once per run.
- Command-level running state is reference-counted. One parallel run exiting
  must not mark the command idle while another run is active.
- Scheduled definitions are user configuration. Runtime state and leases are
  stored separately.
- A failed command-document reload never replaces the last valid snapshot.
- A daemon restart never blindly replays every occurrence missed while it was
  offline.
- `runOptions.singleton` is enforced across processes, not merely inside one
  `Runner`.
- The effective config directory is resolved before singleton locks, IPC paths,
  command paths, or schedule paths are created.

## Proposed command schema

Triggers are siblings of `runOptions`: triggers describe *when*; run options
describe *how*.

```json
{
  "id": "custom.command-nightly-index",
  "cliCommand": "search",
  "args": ["index", "--src", "D:/Photos"],
  "runOptions": {
    "sequential": true,
    "singleton": true,
    "closePolicy": "closeWithOwner",
    "showInQueue": true,
    "logging": {
      "level": "info",
      "file": {
        "path": "${CONFIG_DIR}/logs/commands/${COMMAND_ID}/${INVOCATION_ID}.log",
        "mode": "unique",
        "streams": "combined"
      }
    },
    "environment": {
      "inherit": true,
      "variables": [
        {
          "name": "PM_JOB_KIND",
          "source": "literal",
          "value": "nightly-index"
        }
      ]
    }
  },
  "triggers": {
    "globalHotkey": {
      "enabled": false,
      "accelerator": "Ctrl+Alt+F8"
    },
    "schedules": [
      {
        "id": "schedule.weekday-nightly-index",
        "enabled": true,
        "kind": "weekly",
        "time": "02:00",
        "weekdays": [1, 2, 3, 4, 5],
        "timezone": "local",
        "missedPolicy": "runOnce",
        "overlapPolicy": "skip",
        "runOptionsMode": "replace",
        "runOptions": {
          "sequential": true,
          "singleton": true,
          "newShellWindow": false,
          "runInConsole": false,
          "closeOnExit": false,
          "closePolicy": "closeWithOwner",
          "showInQueue": true,
          "logging": {
            "level": "debug",
            "file": {
              "path": "${CONFIG_DIR}/logs/scheduler/${SCHEDULE_ID}/${INVOCATION_ID}.log",
              "mode": "unique",
              "streams": "combined"
            }
          },
          "environment": {
            "inherit": true,
            "variables": [
              {
                "name": "PM_JOB_TRIGGER",
                "source": "literal",
                "value": "weekday"
              }
            ]
          }
        }
      }
    ],
    "appTask": {
      "runWhen": []
    }
  }
}
```

### Execution policy

`sequential` and `singleton` are not aliases:

- `sequential: true`: queue same-command runs owned by the same process.
- `singleton: true`: prohibit overlapping runs of this command across all
  pm-image processes using the same config directory.
- `overlapPolicy: "skip"`: discard a scheduled occurrence while another run is
  active.
- `overlapPolicy: "queueOne"`: retain at most one pending occurrence.
- `overlapPolicy: "replace"`: cooperatively stop the current run, wait for the
  grace period, then start the replacement.

Defaults:

- `singleton`: `false` for compatibility.
- Scheduled commands: recommend `singleton: true` and `overlapPolicy: "skip"`.
- Toggle commands: a trigger stops the active command instead of starting a
  second run.
- Never allow an unbounded backlog of missed or overlapping schedule ticks.

### Per-trigger run-options override

Every executable trigger may override the complete command-level `runOptions`
object. Do not support only a scheduler-specific subset.

- `runOptionsMode: "inherit"` (default): use the command-level `runOptions`.
- `runOptionsMode: "replace"`: the trigger's `runOptions` is the complete
  effective object. It does not merge field-by-field with the command-level
  object.
- When switching from inherit to replace, the Settings UI clones the currently
  resolved command-level options into the trigger so enabling an override does
  not unexpectedly reset behavior.
- When switching back to inherit, preserve the trigger override in draft UI
  state until save, but omit it from persisted JSON after confirmation.
- Validation, dispatch, singleton leasing, ownership and cancellation always
  use the fully resolved effective run options for that trigger invocation.
- The override schema must track the shared `runOptions` type. New run-option
  fields automatically become available to trigger overrides rather than
  requiring scheduler-specific plumbing.

This replacement rule avoids ambiguous three-way behavior between an omitted
field, an inherited field and an explicit reset-to-default. Import/export and
remote command packs must preserve both `runOptionsMode` and the complete
override object.

### Logging and seeded environment

Logging and environment seeding are part of `runOptions`, so command defaults
and complete per-trigger replacements use exactly the same schema and editor.

#### Logging layers

Keep three concerns distinct:

1. **Daemon audit log:** scheduler decisions, claims, ownership, lifecycle and
   errors. Always uses the application logging system and cannot be redirected
   or disabled by an individual command.
2. **Internal CLI log level:** `logging.level` maps to the pm-image CLI global
   `--log-level` option when the planned action is a `cliCommand`.
3. **Child stdout/stderr log file:** `logging.file` redirects process output for
   CLI and external commands.

`logging.level` accepts the existing levels:

```text
trace | debug | info | warn | error | critical | off
```

For an arbitrary external executable, log level has no universal meaning. Do
not invent a `--log-level` argument. The environment editor may explicitly set
an application-specific variable when needed.

`logging.file`:

- `path`: variable-aware path resolved at invocation time.
- `mode`: `unique` (recommended), `append`, or `truncate`.
- `streams`: `combined`, `stdout`, or `stderr`. A future split mode may expose
  separate stdout/stderr paths.
- `createDirectories`: defaults true.

Relative paths resolve beneath `<config_dir>/logs`; explicit absolute paths are
allowed for locally authored commands but may fail under a service account that
lacks access. Imported/remote absolute paths and `append`/`truncate` targets
remain disabled until local review because they can overwrite user files.
Automatic retention manages only files beneath an approved log root; an
arbitrary external path is user-managed.

Add invocation variables before resolving run options:

- `${COMMAND_ID}`
- `${COMMAND_UUID}`
- `${SCHEDULE_ID}`
- `${INVOCATION_ID}`
- `${RUN_ID}` (only where resolution occurs after Runner allocation)
- `${TRIGGER_KIND}`
- `${TIMESTAMP_UTC}`

Normal config/path variables such as `${CONFIG_DIR}` remain available too.

`unique` mode must guarantee a collision-free filename even if the template
does not contain `${INVOCATION_ID}`. It may add an invocation suffix. Concurrent
commands must never truncate each other's logs.

Implement stdout/stderr file logging as process-handle redirection in
`ProcessRunner`, not by constructing shell redirection strings. This preserves
argv-mode safety and works for descendants inheriting the handles. Open files
before spawn, report open/create failures as launch failures, and close owner
handles after process completion.

Combined-stream ordering is best-effort because stdout and stderr writes from
different handles/processes are not globally ordered. Document this rather
than promising byte-perfect interleaving.

The scheduler runtime row records the resolved non-secret log path. `run-ipc
info`, Settings status and queue surfaces may expose/open that file. Never put
secret environment values into a log path.

Retention:

- `unique` files require configurable retention by maximum age/count/total
  bytes.
- Cleanup runs outside the command watcher and never follows symlinks outside
  the configured log root.
- `append` can grow without bound, so the UI must warn unless rotation/retention
  is configured.
- High-frequency one-second schedules must not force one permanent file per
  invocation by default. Offer an append-per-schedule preset with rotation.

Legacy compatibility:

- Existing top-level `logLevel` remains readable.
- Normalize it into effective `runOptions.logging.level`.
- New saves write the canonical run-options field after migration.
- If both exist, the nested canonical value wins and validation reports the
  legacy conflict.

#### Environment schema

`environment.inherit` controls whether the child receives the daemon's ambient
environment:

- `true` (default): copy the host environment, then apply configured entries
  and required internal lineage variables.
- `false`: start from a documented minimal platform environment, then apply
  configured entries and required lineage variables. Preserve OS essentials
  needed for process creation and profile/temp resolution.

Environment rows preserve order in the UI but resolve to one key/value map:

```json
{
  "name": "OUTPUT_FORMAT",
  "enabled": true,
  "source": "literal",
  "value": "json"
}
```

Supported sources:

- `literal`: persisted non-secret value, with command-variable expansion.
- `host`: copy a named variable from the daemon environment at invocation time,
  optionally under another target name.
- `secretRef`: resolve a reference from secure storage at invocation time. The
  secret value is never written to commands JSON, scheduler state, IPC
  descriptors, reports or logs.

Validation:

- Reject empty names, `=`, NUL and platform-invalid names/values.
- Treat names case-insensitively on Windows and case-sensitively on POSIX.
- Duplicate effective names are an error rather than last-write-wins.
- Reserve scheduler-owned lineage/control variables such as
  `PM_IMAGE_COMMAND_ID`, `PM_IMAGE_OWNER_INSTANCE_ID`,
  `PM_IMAGE_OWNER_RUN_ID`, `PM_IMAGE_TRIGGER_KIND` and future documented
  `PM_IMAGE_*` control names. User rows cannot override them.
- Warn and require explicit local confirmation for process-loader and
  interpreter-control variables such as `PATH`, `PATHEXT`, `LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PYTHONPATH` and shell startup
  variables.
- Imported/remote command packs may declare non-secret environment rows, but
  they remain disabled until locally reviewed. Secret references are never
  accepted from a remote pack as already authorized.

Resolve environment values only after the command snapshot and trigger
run-options override are fixed for the invocation. An environment/config reload
must not mutate an already-running process.

Long-lived daemon caveat: `source:"host"` reads the daemon's startup
environment, which may differ from an interactive terminal and may become
stale. Prefer explicit literals/secret references for deterministic schedules.
The Settings UI must preview the source and whether a host variable is currently
available without revealing its value.

### Schedule identity and multiplicity

- `triggers.schedules` is an array. A command may have zero, one or multiple
  independent schedules.
- Every schedule has an immutable, globally unique `id`. Runtime state,
  deduplication, edit operations and event logs are keyed by this `scheduleId`,
  never by array index.
- Persisted scheduler ownership uses the command's immutable `uuid`.
  `commandId` remains the human-visible/CLI dispatch identity.
- A command must have a backfilled UUID and unique command ID before a schedule
  can be enabled.
- Renaming `commandId` preserves schedules through command UUID. Duplicate
  command IDs are a validation error and prevent schedule activation.
- Deleting a command retires its schedule IDs and runtime rows after active
  runs finish; recreating a command with the old display ID does not inherit
  the retired state.

### Initial schedule kinds

- `once`: one local/UTC timestamp.
- `interval`: monotonic interval measured in whole seconds from the last
  planned occurrence. `intervalSeconds` supports values from `1` upward; this
  explicitly includes sub-minute schedules.
- `daily`: local wall-clock time.
- `weekly`: weekdays plus local wall-clock time.
- `monthly`: day-of-month plus local wall-clock time.
- `cron`: advanced five-field cron expression with an explicit dialect.

The UI should author structured schedule kinds first. Cron is an advanced
input/export format, not the primary editor. Standard five-field cron cannot
represent intervals below one minute, so second-based intervals remain native
daemon schedules and must be marked non-exportable to standard cron.

## Config and persistence layout

All paths derive from `media::settings::get_config_dir()`.

```text
<config_dir>/
  daemon.json                         daemon host configuration
  commands.json or secure document   custom-command definitions
  run-ipc/
    instances/                        existing process descriptors
    scheduler/
      state.json                      scheduler runtime state
      daemon.lock                     Unix lock target / diagnostic metadata
      command-leases/
        <command-id-hash>.json        singleton diagnostics and ownership
```

On Windows with secure storage, the active command document is
`pm://config/commands.json`; `get_command_json_path()` is only the
legacy/plaintext import-export path. The daemon must always load commands with
`load_command_json_utf8()` and must watch the effective command-document
revision path, not assume `<config_dir>/commands.json`.

Persist only runtime data in `run-ipc/scheduler/state.json`, for example:

```json
{
  "version": 1,
  "generation": 18,
  "schedules": {
    "schedule.weekday-nightly-index": {
      "commandUuid": "6d37c6c0-...",
      "commandId": "custom.command-nightly-index",
      "definitionHash": "...",
      "lastPlannedAt": 0,
      "lastStartedAt": 0,
      "lastFinishedAt": 0,
      "nextRunAt": 0,
      "lastResult": "none",
      "runCount": 0
    }
  }
}
```

Use write-to-temporary-file plus atomic replace, following `cmd_ipc.cpp`.
Definitions remain in the command document; runtime writes must never rewrite
the command document.

## Command-document change notification

Notification must have a push path and a recovery path.

### Primary push path

After `settingsCustomCommandsSave` successfully calls
`save_command_json_utf8()`:

1. Increment or compute a command-document generation/hash.
2. Discover the daemon through `cmd_ipc`.
3. Send `reload_commands` with the generation/hash.
4. Treat “daemon not running” as non-fatal; the next daemon start loads the
   saved document.

Do not reuse `set_settings_persist_observer`: it currently reports persistence
failures and is not a successful-save notification bus.

### Watch/recovery path

- Expose a public settings-store function returning the effective command
  watch target. On secure Windows profiles this is the command document
  `.doc.meta`; elsewhere it is the real command JSON path.
- Extend `FileWatcher` with Linux `inotify` and macOS FSEvents/kqueue support.
- Until those backends exist, use a low-frequency generation/mtime poll so
  Linux and macOS cannot miss updates.
- Watch `daemon.json` separately.
- Debounce replace/write event bursts.
- On overflow, dropped event, watcher failure, or directory replacement,
  perform a full reload and re-arm the watcher.

### Transactional reload

1. Read bytes through `load_command_json_utf8()`.
2. Parse and validate into a new immutable snapshot.
3. Compile schedule definitions and execution plans.
4. Compare the definition hash to the active snapshot.
5. Atomically swap only on success.
6. Recompute future times for changed schedules.
7. Keep active runs attached to the definition snapshot with which they
   started.
8. Disable removed schedules but do not silently kill an active run unless the
   user explicitly requests stop.

## IPC and lifecycle work

The current `InstanceServer::set_runner_hooks()` exposes only numeric run IDs.
That is insufficient because a daemon hosts many command IDs while its single
process descriptor has an empty `command_id`.

### Extend daemon host state

Add structured hosted runs:

```json
{
  "action": "command_runs"
}
```

```json
{
  "type": "command_runs",
  "runs": [
    {
      "runId": 42,
      "commandId": "custom.command-nightly-index",
      "pid": 1234,
      "trigger": "schedule",
      "state": "running",
      "startedAt": 1787407200000
    }
  ]
}
```

Add targeted host control:

```json
{
  "action": "command_stop",
  "commandId": "custom.command-nightly-index",
  "graceMs": 8000
}
```

Keep IPC `stop` process-scoped: it means “shut down the daemon.” Wire the
daemon's existing stop event/loop to `InstanceServer::set_stop_hook()`.

### Cheap discovery

Extend the daemon descriptor with an atomically refreshed summary:

```json
{
  "activeCommands": {
    "custom.command-nightly-index": {
      "count": 1,
      "runIds": [42]
    }
  }
}
```

`command_control::is_command_running()` may use this summary without issuing
synchronous IPC requests from paint/input paths. `command_runs` is the
authoritative detail query.

### Worker lineage

Stamp daemon children with:

- `PM_IMAGE_COMMAND_ID`
- `PM_IMAGE_OWNER_INSTANCE_ID`
- `PM_IMAGE_OWNER_RUN_ID`
- `PM_IMAGE_TRIGGER_KIND`

When a pm-image worker creates its own IPC descriptor, copy those fields into
the descriptor. This allows command control to distinguish a standalone worker
from a worker already owned by the daemon and prevents duplicate stop routing.

### Stop sequence

1. Resolve host-owned runs for the command ID.
2. Request cooperative stop from matching child IPC instances.
3. Wait the configured grace period.
4. Ask the owning `Runner` to terminate remaining process trees.
5. Release the singleton lease only after the owner observes final exit.
6. Persist the result and next occurrence.
7. Emit the final lifecycle event.

### Cross-process lifecycle fanout

- Subscribe the daemon to its local `Runner`.
- Maintain per-command active counts and update `activeCommands`.
- Send `command_event` to live UI/assistant IPC hosts on `0 -> 1` and `1 -> 0`
  transitions.
- UI hosts translate the event into local `command_control` notifications and
  WebView fanout.
- A newly started UI reads the daemon snapshot so events missed while it was
  closed are recovered.
- Include owner instance ID, run ID, and monotonically increasing event
  sequence for deduplication.

## Singleton daemon

Schedule leadership scope is `(canonical effective config directory, user
identity, machine)`, across interactive sessions. A console login and an RDP
login using the same profile must not both execute the same schedule.

Tray/global-hotkey presence is session-scoped. This creates two distinct roles:

- **Scheduler leader:** exactly one per profile on the machine.
- **Session agent:** at most one tray/hotkey host per interactive session.

The initial implementation may run both roles in one process, but it must hold
both independent locks. A daemon that acquires only the session-agent lock may
serve tray/hotkeys and forward scheduler control to the elected leader; it must
not evaluate schedules. A later split into separate executables must preserve
the same IPC contract.

The current constant Windows mutex prevents duplicate processes but does not
model different config profiles or multiple sessions. Keep a session-scoped
name containing the session and profile hash for tray/hotkey ownership:

```text
Local\PolyMech_<app-id>_session-agent_<session-id>_<config-dir-hash>
```

Use an OS-held lock file under `run-ipc/scheduler` as the cross-session
scheduler-leader authority on every platform, including Windows.

### Windows

- Resolve and canonicalize `config_dir` before creating the mutex.
- Keep the session-agent named mutex held for the tray/hotkey lifetime.
- Acquire and hold an exclusive lock on the profile scheduler lock file for
  cross-session leadership; a `Local\` mutex alone is insufficient.
- Treat `ERROR_ALREADY_EXISTS` as a live-owner check, not permission to start.
- Use the existing named stop event with the same profile hash.
- Handle an abandoned mutex by validating/pruning the old run-ipc descriptor
  before taking ownership.

### Linux and macOS

- Open `<config_dir>/run-ipc/scheduler/daemon.lock`.
- Acquire an exclusive non-blocking OS lock (`flock`/`fcntl`).
- Hold the file descriptor for the process lifetime; a JSON file existing by
  itself is not proof of ownership.
- Put PID, process start identity, instance ID, profile hash, and start time in
  the file for diagnostics.
- Use `cmd_ipc` for graceful stop/status. Signals are fallback shutdown only.

### Start race

1. Resolve effective config directory.
2. Acquire the session-agent lock when tray/hotkeys are requested.
3. Attempt the cross-session scheduler-leader lock.
4. If leadership is held elsewhere, stay up as a follower: accept IPC, poll
the command document, retry the lock every 250 ms, and yield if a live
higher-priority `claim.json` appears. Never start a second emitting loop.
5. Prune only demonstrably dead descriptors/state.
6. Start `InstanceServer`.
7. Load the command snapshot and scheduler state if leader.
8. Start watchers and the scheduler loop if leader.
9. Advertise role and readiness.

Never use “descriptor file does not exist” as the singleton test. Two processes
can both observe absence. The OS lock is authoritative; run-ipc is discovery
and diagnostics.

## Singleton commands

`Runner::sequential` is process-local and cannot enforce
`runOptions.singleton` across daemon, UI, assistant, and CLI processes.

Add a cross-platform `CommandLease`:

- Lease key: hash of immutable command UUID; placement under the effective
  config directory scopes it to the profile. `commandId` is stored as
  diagnostic/dispatch metadata, not lease identity.
- Acquire before spawning.
- Hold an OS lock handle for the full run lifetime.
- Allocate an invocation UUID before lease acquisition; `Runner` does not
  provide `runId` until start. Store command UUID/ID, schedule ID, invocation
  UUID, owner instance ID, eventual owner run ID/PID, process start identity,
  trigger, and acquisition time for diagnostics.
- On contention, validate the owning process through run-ipc before reporting
  it active.
- Release only after final process exit.
- OS lock release handles owner crashes; stale JSON metadata is cleaned on the
  next acquisition.

Owner-bound lifetime is required for daemon-owned singleton commands in v1.
Allowing a non-IPC external process to outlive its daemon would release the
lease while work was still running and permit a duplicate. A future durable
worker handoff may relax this.

All launch surfaces must use the same lease service. Enforcing singleton only
inside the daemon is insufficient because a ribbon or CLI launch can race the
scheduled tick.

## Shared command execution

Extract command planning currently embedded in CLI/ribbon paths into a portable
module:

```text
command ID + VariableContext + trigger metadata
  -> CustomCommandExecutionPlan
  -> SelectionRunSpec / Runner RunOptions
```

The planner must:

- Load through the settings-store command API.
- Resolve `cliCommand`, `externalCommand`, source selection, variables, cwd,
  log level, close policy, sequential and singleton settings.
- Produce sync options for CLI/Explorer and async options for UI/daemon.
- Stamp command and owner lineage.
- Avoid the daemon -> custom-command dispatcher -> leaf double spawn.

Scheduled runs have no ambient Explorer selection. Commands requiring
`${CURRENT_FILE}` or `${CURRENT_SELECTION}` must provide fixed
`source.files`/`source.folders`, runtime parameters, or fail validation before
the schedule is enabled.

Execution support:

| Command kind | Daemon behavior |
|---|---|
| `cliCommand` | Execute through shared planner and daemon Runner |
| `externalCommand` | Execute through shared planner and daemon Runner |
| `appCommand` | Send `app_cmd` to a live UI; apply unavailable-host policy |
| `ribbonCommand` | Require/reroute to a live UI; never emulate UI state in daemon |
| URL/path | Use portable platform-open service |
| XBlox | Execute its CLI plan and preserve command lifecycle |

## Cross-platform daemon

Keep `pm_image_cmd_daemon.cpp` as the thin composition root and place its
scheduler/trigger implementation under `src/tasks/`:

- Platform-neutral task host: configuration, command snapshots, scheduler,
  leases, Runner ownership and cmd-ipc actions.
- `_win32.cpp` backend: tray icon, `RegisterHotKey`, named mutex/event and
  autorun.
- `_linux.cpp`/`_posix.cpp` backend: foreground/service loop, lock file,
  signals, inotify and systemd user-service integration.
- `_macos.cpp`/`_posix.cpp` backend: foreground/agent loop, lock file, signals,
  watcher and launchd agent integration.

The first Linux/macOS milestone only needs scheduled command execution and
IPC. Global OS hotkeys and tray UI are independent platform capabilities and
must not block the scheduler.

Add portable settings APIs:

- `get_daemon_json_path()` to `core/settings_store.hpp/.cpp`.
- Public effective command watch/revision API.
- Identical `--config-dir` handling before daemon initialization.

Autostart targets:

- Windows: current Run registration initially; evaluate per-user registration
  instead of requiring HKLM elevation.
- Linux: generated/installed `systemd --user` service where available, with a
  documented foreground fallback.
- macOS: per-user LaunchAgent plist, with a documented foreground fallback.

## Scheduling engine

- Keep each `SchedulerEngine` instance's state behind that instance's mutex or
  scheduler thread. Engines share no scheduler mutex/thread/static state.
- Use `condition_variable`/platform wake primitive; do not busy-poll.
- Wait until the exact next deadline; do not implement interval schedules as a
  one-minute or one-second polling scan.
- Support `intervalSeconds >= 1`. Compute the next occurrence from the planned
  cadence rather than completion time so process duration does not introduce
  cumulative drift.
- Apply overlap and misfire policy when a run lasts longer than its
  second-based interval; never build an unbounded per-second backlog.
- Use UTC system time for persisted instants.
- Use a monotonic clock for waiting so wall-clock changes do not corrupt sleeps.
- Recalculate wall-clock schedules after timezone/DST/system clock changes.
- Wake immediately on config reload, run completion, stop, and manual run-now.
- Limit dispatches per wake to prevent a catch-up storm.
- Persist state after a claim/start/result transition, not on every idle tick.

### Misfire defaults

- `skip`: advance to the first future occurrence.
- `runOnce`: run one collapsed occurrence, then advance.
- `catchUp`: optional advanced mode with a strict maximum count.
- Default desktop behavior: `runOnce`.

For DST:

- Nonexistent local time: run at the next valid local instant.
- Repeated local time: run once unless explicitly configured otherwise.

Crash semantics must be documented as at-most-once or at-least-once. Exact-once
execution is not possible for arbitrary external processes. For v1, persist a
dispatch claim before spawn, record the spawned PID immediately, and prefer
at-most-once recovery over silently duplicating destructive work.

## Shared web UI

All scheduler frontend code belongs in `apps/shared`. The Settings app is only
an integration host: it supplies the RPC client, feature flags and current
command value, then renders the shared component.

Do not add scheduler schemas, recurrence helpers, date/time pickers, timezone
pickers, run-options override fields, preview logic or scheduler translations
under `apps/settings/src`.

Proposed placement:

```text
apps/shared/
  customCommands/
    types.ts                              shared persisted command types
    schedule/
      schema.ts                           validation and defaults
      effectiveRunOptions.ts              inherit/replace resolution
      display.ts                          locale-aware display helpers
  components/
    customCommands/
      runOptions/
        RunOptionsEditor.tsx              extracted complete editor
        LoggingOptionsEditor.tsx
        EnvironmentVariablesEditor.tsx
      schedule/
        ScheduleCard.tsx
        ScheduleKindFields.tsx
        ScheduleDateTimePicker.tsx
        ScheduleTimeZonePicker.tsx
        ScheduleRunOptionsOverride.tsx
        SchedulePreview.tsx
  components/ui/
    calendar.tsx                          single shared DayPicker wrapper
  settings/
    schedulerClient.ts                    typed Settings/daemon RPC client
  i18n/
    types.ts                              scheduler translation keys
    en.json / de.json / ...               translated strings
```

`apps/settings/src/settings/customCommands/CommandEditor.tsx` should only
insert the shared `ScheduleCard` and pass the existing command update callback.
`CommandParameterDialog.tsx` should render the same shared card or a compact
mode of it. No second implementation is permitted.

Add a collapsible **Schedule** card next to **Run options** in
`CommandEditor.tsx`; mirror essential controls in
`CommandParameterDialog.tsx`.

Controls:

- Enabled.
- Once / Interval / Daily / Weekly / Monthly / Custom cron.
- Date/time, interval value and unit (seconds/minutes/hours), weekdays,
  day-of-month.
- Timezone.
- Human-readable summary.
- Next five occurrences.
- Missed-run policy.
- Overlap policy.
- “Only one instance” (`runOptions.singleton`).
- Run options: **Use command options** or **Override for this schedule**. The
  override exposes the complete Run options editor, not a reduced scheduler
  variant.
- Host availability warning for app/ribbon commands.
- Validation warning when selection variables have no fixed source.
- Run now, stop, last result, next run, and owner process.
- Advanced export: cron line; Windows Task Scheduler XML can be added later.

Saving:

1. Validate locally.
2. Save the complete command document.
3. Notify daemon with the new generation/hash.
4. Display daemon acknowledgement/rejection separately from save success.
5. If daemon is offline, show “Saved; starts when daemon runs.”

### Calendar and date-time picker design

Radix does not provide a calendar/date-picker primitive. Compose the picker
from the existing Radix primitives and the existing DayPicker wrapper:

```text
Radix Popover
  Date trigger button
  Popover content
    Calendar (React DayPicker)
    Time fields
    Timezone summary
    Cancel / Apply
```

The repository already has:

- Radix `Popover`, `Dialog`, `Select`, `Label`, and related form primitives.
- `apps/shared/components/ui/calendar.tsx`, backed by `react-day-picker`.
- Additional copied calendar wrappers in individual apps.

Before implementation:

- Consolidate scheduler use on the shared calendar instead of creating another
  app-local copy.
- Remove scheduler imports from app-local copied Calendar wrappers. Any
  compatibility shim must only re-export
  `apps/shared/components/ui/calendar.tsx`.
- Make `react-day-picker` a direct dependency of the package that owns/builds
  the shared calendar. Do not rely on an accidental transitive dependency.
- Verify the installed DayPicker major version before applying current
  examples; the checked-in wrapper uses an older class-name/component API.
- Keep Radix responsible for popover focus, portal, dismissal and collision
  behavior. Keep DayPicker responsible for the calendar grid and date keyboard
  navigation.

#### Picker layout

- The closed trigger shows a localized medium date, for example
  `22 Aug 2026`, never a hard-coded numeric pattern.
- The accessible trigger name includes the full selected date:
  “Change date, Saturday, 22 August 2026”.
- Opening focuses the selected date. If empty, focus today.
- Selecting a day updates a draft value. **Apply** commits date and time
  together; **Cancel** restores the previous value.
- Preserve typed time values when navigating between months.
- Include a **Today** shortcut only when today is valid for the selected
  schedule kind.
- Use month/year dropdowns for distant dates; previous/next arrows alone are
  inefficient for one-time schedules years away.
- Show one month in the settings card. Do not use a two-month range picker for
  a single scheduled instant.
- On narrow surfaces, use the same content in a Radix `Dialog` rather than
  allowing a popover to clip or overflow. Desktop uses `Popover`.
- Avoid nesting another modal inside `CommandParameterDialog`; use an anchored
  popover there unless viewport constraints require the dialog variant.

Time is edited separately from the calendar:

- Use labeled numeric hour, minute and optional second fields, or a localized
  native time input only after verifying WebView2 behavior in all supported
  locales.
- Show seconds for `once` schedules and wherever precision requires them.
- Interval schedules use a number plus unit selector
  (seconds/minutes/hours), not the calendar picker.
- Detect the locale's preferred 12/24-hour cycle for presentation. Persist
  canonical 24-hour `HH:mm:ss`.
- Validate incomplete and nonexistent local times inline before Apply.

#### Schedule-kind-specific controls

- **Once:** date picker, time including seconds, timezone.
- **Interval:** positive integer and seconds/minutes/hours unit. Show the
  normalized interval and the next occurrence.
- **Daily:** time and timezone; no calendar grid.
- **Weekly:** localized weekday toggle group in locale week order, then time
  and timezone.
- **Monthly:** choose either day-of-month or ordinal weekday
  (“last Friday”), then time and timezone. A calendar may illustrate the
  choice but must not be the only editor.
- **Cron:** raw expression, dialect label, validation, human summary and next
  occurrences. Do not force cron through the calendar UI.

#### Trigger run-options editor

- Default to a compact read-only summary of the inherited command run options.
- **Override for this schedule** expands the same shared editor used by the
  command's Run options card.
- Extract the current Run options controls from the Settings-only
  `CommandEditor.tsx` and `CommandParameterDialog.tsx` into
  `apps/shared/components/customCommands/runOptions/RunOptionsEditor.tsx`.
- Initialize the override from the currently resolved command options.
- Clearly label that later edits to command-level run options do not affect a
  replacement override.
- Include every supported field: sequential, singleton, internal console,
  external shell window, close on exit, close policy, queue visibility,
  logging, environment and future additions.
- Apply host capability validation to the effective override. For example,
  `runInConsole` is invalid for a daemon-owned schedule unless execution is
  explicitly delegated to a live UI console host.
- Show the effective owner/lifetime consequence next to `closePolicy`; do not
  allow an untracked persistent singleton worker.

#### Logging and environment UI

Both editors live inside the shared `RunOptionsEditor` and therefore appear for
command-level options and schedule replacement overrides.

Logging:

- Log level select using existing localized level labels.
- **Write process output to file** toggle.
- Variable-aware path field with file/folder picker and variable builder.
- Stream selector (combined/stdout/stderr).
- File mode selector (unique/append/truncate).
- Retention controls when unique/append is selected.
- Resolved-path preview using a synthetic invocation ID; never create the file
  while editing.
- Inline warning when a one-second interval would generate one unique file per
  run.

Environment:

- Editable rows with Enabled, Name, Source and Value/Reference.
- Add, remove, duplicate and reorder rows.
- Source selector: Literal, Host variable, Secret reference.
- Variable builder is available for literal values.
- Secret reference picker shows the reference name only. It never loads secret
  plaintext into JavaScript.
- Host source shows Available/Missing without showing the inherited value.
- Reserved/dangerous names show blocking errors or explicit warnings inline.
- Duplicate effective names are highlighted before save, including
  case-insensitive duplicates on Windows.
- **Inherit host environment** defaults on. Turning it off shows the documented
  minimal inherited variables.
- A collapsed summary shows variable names and sources, never values marked
  secret.
- Command JSON preview/export redacts secret metadata beyond the stable
  reference identifier.

The Settings host may provide path picking and secure-reference listing through
typed RPC props, but all rendering, validation and editing logic remains in
`apps/shared`.

### Localization contract

Calendar localization is broader than translating button labels.

- Extend the shared i18n context to expose a qualified BCP 47 locale
  (`en-US`, `de-DE`, `fr-FR`, etc.) and text direction alongside the
  translation object. `useT()` alone does not currently expose locale identity.
- Map that locale to the matching DayPicker/date-fns locale and pass
  `locale`, `lang`, and `dir` into the shared Calendar.
- Derive month names, weekday names, date order, first day of week, week
  numbering, numerals and hour cycle from locale/CLDR data. Do not infer these
  from translated strings.
- Use `Intl.DateTimeFormat` for trigger text, summaries and preview rows.
  Never concatenate translated month/day fragments or hard-code
  `MM/DD/YYYY`.
- Keep all scheduler-owned labels, ARIA labels, validation messages, relative
  phrases and policy descriptions in the `apps/shared/i18n` catalog. Do not add
  scheduler-only translation modules under the Settings app.
- Make weekday selection semantic (`1` = Monday through `7` = Sunday in stored
  data) while rendering in locale-specific first-day order.
- Render navigation icons directionally in RTL and set `dir="rtl"` on both
  Radix content and DayPicker.
- Support localized numerals in display. Parse/persist canonical ASCII numeric
  values at the form boundary.
- The initial implementation may use Gregorian scheduling semantics with
  localized presentation. If non-Gregorian authoring (Hijri, Persian,
  Buddhist, etc.) is added, it must be an explicit calendar-system field with
  conversion tests; do not silently display one calendar and schedule another.

The current settings translations cover English, German, French, Spanish and
Italian, all LTR. Still implement the direction contract now so adding an RTL
locale does not require replacing the picker.

### Timezone presentation

- Store IANA timezone IDs, not translated names or fixed offsets.
- Offer “Local time” as a resolved value, for example
  `Local time (Europe/Berlin)`, plus `UTC`.
- The timezone selector should be searchable. A long IANA list does not fit a
  basic Radix Select; compose Radix `Popover` with the existing command/list
  pattern when the full zone catalog is exposed.
- Display a localized zone name together with the stable IANA ID where
  available. The ID remains visible enough to disambiguate duplicate names.
- When changing timezone, explicitly choose between preserving the wall-clock
  fields and preserving the instant. For schedule editing, default to
  preserving wall-clock intent and immediately refresh the occurrence preview.
- Surface DST effects in the preview, including skipped and repeated local
  times.

### Accessibility and keyboard behavior

The picker must follow the WAI-ARIA date-picker dialog/grid behavior:

- Only one day in the calendar grid participates in the tab sequence.
- Arrow keys move by day/week.
- Home/End move to the start/end of the displayed week.
- Page Up/Page Down move by month.
- Shift+Page Up/Page Down move by year.
- Enter/Space select.
- Escape closes without committing and returns focus to the trigger.
- Month/year changes are announced through a polite live region.
- The selected day, today, disabled days and out-of-month days must not rely on
  color alone.
- Focus rings must remain visible in light and dark themes.
- Calendar cells need at least a 36px target in the dense desktop layout and a
  44px target in the narrow/dialog layout.

Do not override DayPicker keyboard behavior unless tests demonstrate a gap.
Radix controls the surrounding focus boundary; DayPicker controls roving focus
inside the grid.

### Calendar UI states to test

- Empty value, valid value and invalid typed value.
- Today, past date and far-future date.
- Month/year boundary and leap day.
- Locale changes while the picker is open.
- Sunday-first and Monday-first locales.
- 12-hour and 24-hour locales.
- Long translated month/button labels.
- RTL navigation and focus order.
- Browser timezone differing from schedule timezone.
- DST gap and repeated hour.
- Keyboard-only and screen-reader operation.
- Popover collision near every settings-panel edge.
- Calendar inside the command parameter dialog.

### UI references

- [shadcn/Radix date-picker composition](https://ui.shadcn.com/docs/components/radix/date-picker)
- [shadcn Calendar and localization](https://ui.shadcn.com/docs/components/radix/calendar)
- [React DayPicker localization](https://daypicker.dev/localization/changing-locale)
- [React DayPicker timezone handling](https://daypicker.dev/localization/setting-time-zone)
- [WAI-ARIA date-picker dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/examples/datepicker-dialog/)
- [Unicode CLDR date/time model](https://www.unicode.org/reports/tr35/tr35-73/tr35.html)

## Implementation TODOs

### Phase 1 — Shared paths and daemon shell

- [x] Add default-on `FEATURE_SCHEDULER` to `CMakeLists.txt` and
  `CMakePresets.json` feature descriptions/default cache variables.
- [x] Export `FEATURE_SCHEDULER` compile definitions to every scheduler
  consumer and conditionally add all scheduler source files.
- [x] Keep `FEATURE_SCHEDULER` independent from `FEATURE_DAEMON`; require both
  only for daemon-owned timed dispatch.
- [x] Add cross-platform `get_daemon_json_path()`.
- [x] Ensure CLI `--config-dir` is applied before daemon path resolution.
- [x] Create the scheduler engine/store under `src/tasks/`; keep the CLI daemon
  file as composition only.
- [x] Split platform-neutral task host from Windows tray/hotkeys
  (`SchedulerHost` + `scheduler serve`; daemon remains the Win32 tray composition).
- [x] Move Win32-only scheduler/host behavior into `_win32.cpp` translation
  units behind portable interfaces.
- [x] Keep Windows types and `windows.h` out of scheduler public headers.
- [x] Implement profile/session-scoped Windows session-agent mutex/event names
  plus a cross-session scheduler-leader lock.
- [x] Implement Linux/macOS OS-held singleton locks (POSIX file lock).
- [x] Wire daemon process shutdown through `cmd_ipc::set_stop_hook()`.
- [ ] Start schedule-only daemon hosts on Linux and macOS.

### Phase 2 — IPC ownership model

- [ ] Compile/register scheduler IPC and WebView RPC handlers only with
  `FEATURE_SCHEDULER`; return structured `feature_disabled` to stale clients.
- [ ] Extend IPC descriptors with `activeCommands`.
- [x] Add `reload_commands`, `scheduler_status`, `scheduler_pause`,
  `scheduler_resume`, and `scheduler_run_now` actions. `command_runs` /
  `command_stop` are still pending.
- [ ] Add worker owner/trigger lineage fields.
- [ ] Update `command_control` to query/stop host-owned commands.
- [ ] Preserve process-level `stop` semantics.
- [ ] Add lifecycle sequence numbers and UI snapshot reconciliation.
- [ ] Wire daemon Runner events to descriptor updates and UI notifications.
- [ ] Add explicit `Cancelled` lifecycle/result classification; do not infer it
  from a generic non-zero process exit.

### Phase 3 — Shared planner and leases

- [ ] Extract `CustomCommandExecutionPlan` from CLI/ribbon-specific code.
- [x] Support daemon execution of CLI, external and XBlox command plans.
- [x] Implement `CommandLease` with Windows and POSIX backends.
- [ ] Parse and honor `runOptions.singleton` on every launch surface.
- [ ] Resolve per-trigger `runOptionsMode` and complete replacement overrides
  before planning, leasing or dispatch.
- [ ] Normalize legacy top-level `logLevel` into
  `runOptions.logging.level`.
- [ ] Add direct stdout/stderr file-handle redirection to `ProcessRunner`.
- [ ] Resolve and validate environment sources while preserving reserved
  scheduler lineage variables.
- [ ] Add secure-storage reference resolution without putting secret values in
  persisted plans, IPC or logs.
- [ ] Define unavailable-UI behavior for app/ribbon commands.
- [ ] Make daemon-owned v1 runs owner-bound by default.

### Phase 4 — Scheduler store and engine

- [x] Define/version trigger schema and runtime-state schema (v1 state.json).
- [x] Implement `SchedulerEngine` as a constructible library with injected
  clock, state store, occurrence sink and namespace; prohibit hidden globals
  and singleton access.
- [x] Define the shared `TriggerOccurrence` envelope and stable occurrence IDs.
  Correlation IDs ship; causation/hop-count fields exist but are unused.
- [x] Keep leadership as an engine option (`Leader` / `ReadOnly`); UI/daemon
  hosts take one OS leader lock and yield via `claim.json`.
- [x] Route typed command/pipeline targets through a shared trigger router;
  never call `Runner` directly from the scheduler core. External, CLI and
  XBlox plans dispatch; app commands need a UI hook.
- [x] Implement atomic scheduler-state load/save under `run-ipc/scheduler`.
- [x] Parse `once`, `interval` (`intervalSeconds >= 1`), `daily`, `weekly`,
  and `monthly` (UTC wall clock). Cron is next.
- [x] Implement next-occurrence preview through CLI `scheduler next --json`.
  Shared web preview still needs Settings RPC or a portable library binding.
- [x] Implement same-tick overlap skip and interval misfire collapse (latest
  due slot only). DST and clock-change remain.
- [ ] Reconcile stale claims, leases and child descriptors at startup.
- [x] Add CLI `scheduler run-now --schedule` plus `pause` / `resume`.

### Phase 5 — Reload notification

- [x] Expose effective command revision/watch path from settings storage
  (`effective_command_document_path()`, `command_cache_watch_path()`,
  `scheduler paths`).
- [x] Send `reload_commands` after successful Settings command save
  (`save_commands_document` → `notify_command_document_changed`).
- [x] Watch effective command document (Win32 FileWatcher + mtime poll).
  `daemon.json` watch is still pending.
- [ ] Implement Linux watcher backend.
- [ ] Implement macOS watcher backend.
- [x] Keep polling fallback for watcher failure/unsupported filesystems.
- [x] Implement parse/validate/atomic-snapshot reload (failed reload keeps
  the last valid snapshot).
- [ ] Test secure-document replacement and plaintext replacement.

### Phase 6 — Shared web UI

- [x] Keep every scheduler frontend module under `apps/shared`; Settings may
  contain integration calls/imports only.
- [x] Add shared `isSchedulerEnabled()` using
  `APP_FEATURES.FEATURE_SCHEDULER` with a conservative false fallback.
- [x] Hide scheduler UI/actions when disabled while preserving schedule fields
  during unrelated command edits.
- [x] Extend `apps/shared/customCommands/types.ts`.
- [x] Add shared Schedule card and `apps/shared/i18n` strings.
- [ ] Extract the complete shared `RunOptionsEditor` from Settings-only forms.
- [ ] Add shared logging path/mode/retention controls.
- [ ] Add shared environment row editor for literal, host and secret-reference
  sources.
- [ ] Add typed Settings RPC adapters for file picking, host-variable
  availability and secret-reference listing.
- [ ] Expose BCP 47 locale and text direction from shared i18n context.
- [ ] Consolidate on the shared DayPicker Calendar and declare its dependency
  directly.
- [ ] Add locale, direction, first-day-of-week, numerals and timezone support
  to the shared Calendar wrapper.
- [ ] Build responsive Radix Popover/Dialog date-time picker composition.
- [ ] Add accessible calendar-grid keyboard and focus tests.
- [x] Add natural-language summary and next-run preview.
- [x] Add singleton, overlap and missed-run controls.
- [ ] Reuse the complete Run options editor for per-trigger replacement
  overrides; do not duplicate a partial field list.
- [ ] Add runtime status and stop/run-now actions through Settings RPC.
- [x] Put the typed scheduler RPC client in `apps/shared/settings`.
- [x] Add command-source and unavailable-host validation.
- [ ] Add cron and Task Scheduler export only after native scheduling works.

### Phase 7 — Autostart and service integration

- [ ] Review Windows HKLM Run elevation; prefer per-user ownership if possible.
- [ ] Add systemd user-service install/uninstall/status commands.
- [ ] Add macOS LaunchAgent install/uninstall/status commands.
- [ ] Keep foreground mode on every platform for diagnostics and tests.
- [ ] Ensure register/manual-start races converge on one scheduler leader per
  config/namespace while permitted session agents may coexist.

### Phase 8 — Tests and observability

- [ ] Add configure/compile coverage for `FEATURE_SCHEDULER=ON` and `OFF`, with
  `FEATURE_DAEMON` independently on and off.
- [ ] Assert generated `features.json` contains the effective
  `FEATURE_SCHEDULER` boolean.
- [ ] Unit-test shared UI gating for true, false and missing `APP_FEATURES`
  values.
- [ ] Feature-off round-trip test: edit another command field and prove stored
  schedules are preserved byte-equivalently at the schema level.
- [ ] Verify feature-off CLI/IPC/RPC calls return `feature_disabled` and create
  no scheduler state, locks or child processes.
- [x] Add `tests/scheduler/test-scheduler-smoke.mjs` (compile/next/tick/isolation).
- [x] Add `npm run test:scheduler` / `test:scheduler:build`.
- [ ] Expand into `tests/scheduler/test-scheduler-next.mjs` for daemon/IPC stages.
- [ ] Unit-test schedule parsing, next occurrence, DST and misfires.
- [ ] Test 1-second and other sub-minute intervals without timing drift or
  unbounded overlap queues.
- [ ] Unit-test atomic reload preserving the last valid snapshot.
- [ ] Race-test two daemon starts for the same profile.
- [ ] Verify separate config profiles may run separate daemons.
- [ ] Race-test manual UI launch against a due singleton schedule.
- [ ] Race-test reload/remove while a command is starting or stopping.
- [ ] Crash daemon between claim, spawn, PID persistence and lifecycle publish.
- [ ] Verify cooperative stop, grace timeout and process-tree hard kill.
- [ ] Verify descriptor/event deduplication with parallel same-command runs.
- [ ] Verify sleep/resume and clock/timezone changes.
- [ ] Test Linux/macOS service restart and stale lock metadata.
- [ ] Extend `run-ipc info/tree` with hosted runs and scheduler state.
- [ ] Log trigger, schedule ID, command ID, owner instance, run ID and result.

## CLI-first synthetic scheduler test suite

The first integration suite must exercise synthetic commands through
`tanit-cli`, without starting the main UI and without reading or writing the
developer's real profile.

Use `tests/orchestrator/test-ipc-next.mjs` as the harness reference:

- Node `spawn`/`spawnSync` with watchdog timeouts.
- `createAssert` from `test-commons.js`.
- polling with bounded `waitFor`, never fixed sleeps as the assertion.
- structured suites/steps and `tests/test-report-last.md`.
- accumulated report support through `test-report-accumulate.mjs`.
- cleanup in `finally`, followed by run-ipc prune.
- platform-neutral executable resolution through `cliExePath`.

Use `tests/orchestrator/test-commands.mjs` as the synthetic-command reference:

- write an isolated command document;
- execute commands by stable custom command ID through the CLI;
- assert deterministic file side effects instead of inherited/captured stdout;
- use `process.execPath` as the portable synthetic external executable;
- validate argv, cwd, environment and variable expansion before involving the
  scheduler.

### Proposed files

```text
tests/scheduler/
  test-scheduler-smoke.mjs            landed — engine/CLI smoke
  test-scheduler-next.mjs             next — daemon/IPC/lifecycle stages
  fixtures/
    scheduler-command.mjs
package.json
  "test:scheduler": "node tests/scheduler/test-scheduler-smoke.mjs"
  "test:scheduler:build": "… rebuild tanit-cli, then smoke …"
  "test:scheduler-next": "node tests/scheduler/test-scheduler-next.mjs"
```

The synthetic worker accepts explicit modes:

```text
node scheduler-command.mjs record     --events <ndjson> --token <id>
node scheduler-command.mjs sleep      --events <ndjson> --token <id> --ms 3000
node scheduler-command.mjs fail       --events <ndjson> --token <id> --code 17
node scheduler-command.mjs child-tree --events <ndjson> --token <id>
node scheduler-command.mjs env        --out <json> ...
```

Each invocation writes machine-readable events containing:

```json
{
  "event": "started",
  "token": "unique-test-token",
  "pid": 1234,
  "parentPid": 1200,
  "argv": [],
  "cwd": "...",
  "startedAt": 1787407200000
}
```

Completion, signal/cancel observation and child-process creation use separate
event rows. Every row includes a unique per-test token so parallel tests never
mistake another process for their fixture.

### Isolation contract

For every test run:

1. Create `mkdtemp()` work and config directories.
2. Pass `--config-dir <temp-config>` to every pm-image CLI process.
3. Pass `--commands <temp-commands.json>` until the secure command-store
   fixture path is explicitly under test.
4. Set an isolated cwd and output/event paths inside the temp directory.
5. Assert the daemon descriptor, scheduler state and leases are all below the
   temporary config directory.
6. Use unique command UUIDs, command IDs, schedule IDs and event tokens.
7. Stop the daemon through authenticated IPC.
8. Hard-kill only as a cleanup fallback.
9. Wait for children to exit, prune stale descriptors, then remove temp files.
10. Keep artifacts only when `PM_KEEP_SCHEDULER_TMP=1`.

The suite must abort rather than continue if any resolved path points at the
normal user config directory.

### Required CLI/control surface

The suite needs stable JSON commands rather than scraping human output:

```text
tanit-cli --config-dir <dir> --commands <file> daemon run
tanit-cli --config-dir <dir> daemon status --json
tanit-cli --config-dir <dir> daemon schedule list --json
tanit-cli --config-dir <dir> daemon schedule run-now <schedule-id> --json
tanit-cli --config-dir <dir> daemon schedule pause <schedule-id> --json
tanit-cli --config-dir <dir> daemon schedule resume <schedule-id> --json
tanit-cli --config-dir <dir> daemon reload --json
tanit-cli --config-dir <dir> daemon stop --json
```

Equivalent authenticated `run-ipc send` actions are acceptable internally, but
the daemon CLI should provide the stable user/test facade. Every accepted
mutation reply includes daemon instance ID, applied command generation,
schedule ID and resulting state.

Add deterministic pure evaluation commands or C++ unit-test hooks for calendar
math:

```text
tanit-cli daemon schedule next --spec <json-file> --after <ISO-8601> --count 5 --json
```

Do not add a production command that changes the daemon's wall clock. The
scheduler core instead receives an injectable Clock in unit tests. Real-time
orchestrator tests cover only short intervals and process lifecycle.

### Test stages

#### Stage A - synthetic command preflight

Run each fixture directly:

```text
tanit-cli --commands <fixture> custom.scheduler-record
tanit-cli --commands <fixture> custom.scheduler-sleep
tanit-cli --commands <fixture> custom.scheduler-fail
```

Assert:

- expected start/finish side effects;
- argv, environment, cwd and source variables;
- non-zero exit behavior;
- inherited command `runOptions`;
- complete trigger `runOptionsMode: "replace"` resolution through a
  run-now invocation.

No scheduler timing assertion is valid until this stage passes.

#### Stage B - daemon discovery and command load

- Start a foreground, no-tray daemon against the isolated profile.
- Wait for `kind:"daemon"` in `run-ipc list --json`.
- Assert role (`schedulerLeader` and optional `sessionAgent`), profile hash,
  config path, command generation and readiness.
- Assert `scheduler_status`, empty hosted runs and compiled synthetic
  schedules.
- Start a second daemon for the same profile and prove it does not become a
  second scheduler leader.
- Start another daemon with a different config directory and prove it may
  become that profile's leader.

#### Stage C - run-now lifecycle

- Trigger one synthetic schedule through CLI.
- Observe `activeCommands` and `command_runs` while the worker sleeps.
- Match command UUID, command ID, schedule ID, owner instance, invocation ID,
  run ID and PID.
- Assert Started event precedes the worker's started side effect.
- Wait for exit and assert the hosted run disappears.
- Assert persisted result, timestamps and run count.
- Verify command-level active state remains true until the final parallel run
  exits.

#### Stage D - second intervals

- Run a one-second interval long enough to collect several occurrences.
- Assert occurrence count with platform-appropriate timing tolerance.
- Measure planned timestamps separately from actual start timestamps.
- Assert planned cadence does not drift with worker duration.
- Run a worker longer than its interval and prove:
  - `skip` creates no backlog;
  - `queueOne` retains at most one pending invocation;
  - `replace` stops the previous invocation before replacement;
  - `singleton` never overlaps PIDs.
- Assert the daemon remains responsive to IPC during rapid ticks.
- Record scheduler state write count and verify it is bounded.
- Route the same interval fixture through a synthetic multi-stage pipeline and
  assert one stable occurrence/correlation identity reaches every stage.
- Assert slow pipeline completion does not shift the next planned interval.

#### Stage E - reload

- Add a schedule, save/replace the synthetic command document and send
  `reload_commands`.
- Assert the acknowledged generation is actually active.
- Change an interval and verify only future planned occurrences use it.
- Remove a schedule while its command runs; assert no new start and no implicit
  kill of the active run.
- Write malformed JSON and assert the last valid snapshot remains active.
- Race push notification with file-watch notification and assert one applied
  generation.
- Rename command ID while preserving command UUID and assert schedule/runtime
  continuity.
- Introduce duplicate command IDs and assert schedule activation is rejected.
- Import/install a remote command pack containing enabled triggers and assert
  schedules/global hotkeys remain disabled until explicit local activation.

#### Stage F - singleton races

- Launch the same singleton synthetic command concurrently from:
  - scheduled run-now requests;
  - direct custom-command CLI dispatch;
  - multiple daemon IPC clients.
- Synchronize requests with a barrier rather than relying on timing luck.
- Assert exactly one lease winner and zero overlapping worker intervals.
- Verify losers return structured `already_running`, `skipped` or `queued`
  outcomes according to policy.
- Kill the lease owner, then prove a new invocation can acquire the lease after
  process identity validation.
- Test PID-reuse defenses with mismatched recorded process-start identity.

#### Stage G - cancellation and process trees

- Stop by schedule ID, command ID and run ID.
- Verify cooperative stop is attempted before hard termination.
- Verify grace timeout is bounded.
- Use `child-tree` mode and assert descendants do not survive.
- Assert the terminal result is `Cancelled`, not generic `Exited`/`Failed`.
- Race stop against spawn, normal exit and daemon shutdown.
- Repeat stop/cancel requests and assert idempotent replies.
- Ensure lease release occurs after observed final exit.

This requires extending `Runner::RunPhase`/result data with an explicit
Cancelled classification; the current Started/Exited/Failed set cannot satisfy
the scheduler lifecycle contract.

#### Stage H - persistence and recovery

- Restart the daemon and verify next occurrence/run count restoration.
- Kill it at fault-injection points:
  - after dispatch claim;
  - after process spawn;
  - after PID persistence;
  - before/after lifecycle publication;
  - before/after lease release.
- Assert recovery follows the documented at-most-once policy.
- Verify a past one-time schedule and each missed-run policy.
- Verify stale state for deleted commands/schedules is retired.
- Verify repeated restarts do not increment run counts or replay completed
  one-time schedules.

Fault injection must be a test-only hook guarded by build/test configuration or
an explicitly test-scoped environment variable accepted only with an isolated
config directory.

#### Stage I - IPC concurrency and security

Mirror the stress approach in `test-ipc-next.mjs`:

- parallel `status`, `command_runs`, `run-now`, `pause`, `resume`, `reload`,
  `command_stop` and process `stop`;
- no hangs or handler mutex re-entry deadlocks;
- stop under request load;
- authenticated challenge-response for new scheduler actions;
- replayed/invalid proof rejection;
- path/permission checks on scheduler state, lock and lease files;
- symlink/reparse-point rejection where applicable.

#### Stage J - deterministic calendar cases

Use the injected Clock/unit layer, not wall-clock sleeps:

- construct multiple scheduler engines in one process with separate clocks,
  stores, sinks and namespaces and prove complete state isolation;
- construct two engines over the same fixture in read-only/leader modes and
  prove only the explicit leader emits dispatchable occurrences;
- leap day and month-end;
- one-time timestamp already in the past;
- Sunday-first/Monday-first display versus stored ISO weekdays;
- DST nonexistent and repeated local times;
- timezone changes and IANA aliases;
- system clock rollback/forward;
- suspend/resume misfire collapse;
- interval restart anchoring;
- multiple schedules on one command;
- retry colliding with the next planned occurrence;
- `maxRuns`/end boundary if those fields are added.

The same expected occurrence fixtures must drive the daemon implementation and
the shared web preview contract. Do not maintain separate hand-authored JS and
C++ expectations.

#### Stage K - logging and environment

Extend the synthetic fixture with modes that print distinct markers to stdout
and stderr and write the selected environment to a JSON side-effect file.

Assert:

- direct CLI preflight and scheduled execution receive identical effective
  literal environment values;
- inherited, non-inherited, host-source and missing-host-source behavior;
- Windows case-insensitive and POSIX case-sensitive duplicate validation;
- reserved `PM_IMAGE_*` values cannot be spoofed, while the real command,
  owner, trigger and run lineage reaches the child;
- schedule replacement run options fully replace command logging/environment;
- variable expansion uses the fixed invocation snapshot;
- stdout-only, stderr-only and combined redirection;
- unique paths never collide under concurrent and one-second runs;
- append does not truncate and truncate has explicit deterministic semantics;
- unwritable/invalid paths fail launch with a structured error and no leaked
  lease;
- daemon restart, reload and cancellation close file handles;
- retention never deletes outside the configured root or follows a
  symlink/reparse point;
- `logging.level` reaches internal CLI commands but adds no invented argument
  to external executables;
- secret values are absent from commands JSON, scheduler state, IPC replies,
  daemon logs, worker logs, reports and failure artifacts.

Use a test-only fake secret resolver. Tests must never depend on a developer's
real credential store.

### Cross-platform expectations

- Core CLI, schedule, ownership, IPC and external Node fixture suites run on
  Windows, Linux and macOS.
- Tray/global-hotkey suites are separately capability-gated.
- Windows process-tree assertions account for Job Objects.
- POSIX assertions account for process groups and signals.
- Timing tolerance is declared per platform and reported, never silently
  widened after failures.
- A skipped capability is reported as skipped with a reason; it is not counted
  as passed.
- Add a Windows multi-session/RDP integration job where infrastructure permits:
  two session agents may exist, but only one scheduler leader may execute the
  shared profile's synthetic schedule.

### Test metrics and failure artifacts

Report at least:

- planned versus actual start latency;
- cadence drift;
- active/queued maximums;
- scheduler state writes;
- IPC request latency and hangs;
- graceful versus hard cancellations;
- leaked processes/descriptors/leases;
- command generation applied;
- daemon role/leader transitions;
- output log path/count/bytes and retention actions.

On failure retain:

- synthetic command document;
- scheduler state;
- daemon/worker stdout and stderr;
- NDJSON event log;
- run-ipc descriptors;
- lease metadata;
- exact CLI argv and platform information.

## Race checklist

Before implementation is considered complete:

- [ ] Scheduler instances have no shared mutable process-global state.
- [ ] A non-leader/read-only scheduler instance cannot emit or commit an
  occurrence.
- [x] Leadership handoff cannot dispatch the same stable occurrence twice.
- [ ] Trigger/pipeline cycles stop at the configured hop limit and report the
  causation chain.
- [ ] Two daemons cannot both pass startup ownership.
- [ ] A daemon descriptor is never treated as an ownership lock.
- [ ] Two processes cannot acquire the same command singleton lease.
- [ ] A stale lease cannot block forever after owner death.
- [x] A daemon crash cannot cause an unbounded catch-up replay.
- [ ] A reload cannot expose a partially parsed command snapshot.
- [ ] A removed command cannot be newly dispatched from an old due queue.
- [ ] Stop during spawn either prevents spawn or immediately owns and stops it.
- [ ] Stop acknowledgement is not treated as proof of process exit.
- [ ] Final exit and lease release are idempotent.
- [ ] Parallel runs do not emit command-level idle before the last run exits.
- [ ] Watcher overflow and atomic file replacement cause a full reload.
- [ ] UI save notification and file-watch notification deduplicate by generation.
- [ ] Daemon shutdown cancels owner-bound children before releasing ownership.
- [ ] A persistent child cannot silently outlive a singleton lease.
- [ ] Concurrent invocations cannot truncate or claim the same unique log file.
- [ ] A reload cannot change the resolved environment of an in-flight run.
- [ ] User environment rows cannot overwrite scheduler lineage/control values.
- [ ] Log retention cannot escape its root through traversal, symlinks or
  reparse points.

## Deferred decisions

- Whether command schedules and LLM schedules eventually share one UI. Their
  execution stores and ownership remain separate for this implementation.
- Whether cron export/import preserves the structured schedule exactly.
- Whether Windows autostart migrates from Run to Task Scheduler.
- Whether Linux/macOS global hotkeys and tray UI ship with the first scheduler
  milestone.
- Whether a durable worker handoff permits daemon-owned runs to survive daemon
  shutdown.
