# Settings Next2

Scope: multi-process settings store coordination on Windows. Chat presets and provider schema live in [settings-next.md](settings-next.md). This document is the store, IPC, persistence, and race-test spec.

**v1 is implemented.** `FEATURE_COMMAND_IPC_NEXT` (on in the usual CLI/UI presets) claims a single settings owner when `InstanceServer` starts. File-change notification remains the safety net. Plan B (short commit mutex) is reserved, unused.

Code:

- `src/win/settings_store.cpp` / `src/win/settings_store.hpp` — owner, debounce persist, mutex, watcher, intercept, verbs
- `src/core/settings_store.cpp` / `src/core/settings_store.hpp` — non-Windows stubs (`settings ipc owner is Windows-only`)
- `src/core/cmd_ipc.cpp` / `src/core/cmd_ipc.hpp` — descriptor fields, `settings_*` dispatch, claim/stop around bind
- `src/cli/pm_image_register_test.cpp` / `src/cli/pm_image_cli_state.hpp` — probes
- `tests/orchestrator/test-core.mjs` — `suiteSettings`
- `package.json` — `test:core:settings` → `node tests/orchestrator/test-core.mjs --only settings`

`test:settings` (`test-media.mjs --settings-only`) is the old media API-key suite. Leave it. Store races go under `test:core:settings`.

## Problem

Each Tanit process has its own settings cache behind `g_settings_load_mutex` in `src/win/settings_store.cpp`. That mutex serializes threads inside one process. It does not serialize processes.

Without an owner, saves go `mutate_settings_root` → audit → pretty JSON dump → full-document encrypt/sign/index (`put_document`) or atomic temp-file + `MoveFileExW`. Two processes can each load the same document, mutate different keys, and the slower encrypt/write replaces the whole blob.

The dangerous sequence with file notifications alone:

```text
Instance A cache = revision 10
Instance B cache = revision 10

A changes appearance
B changes provider

A debounce expires
  -> writes revision 11

B has not processed watcher yet
B debounce expires
  -> writes its revision-10-derived document
  -> A's change disappears
```

A watcher tells B after something happened. It does not serialize mutation ownership.

`src/core/command_finish.cpp` already special-cases this class of bug: CLI skips artifact persistence when a UI instance is listening, because a CLI disk write races the UI cache. That workaround does not generalize.

Encryption of the whole settings document is the expensive part. Avoiding redundant writers matters. `src/core/cmd_ipc.cpp` is the cross-instance bus (loopback TCP, length-prefixed JSON, per-process `InstanceServer`, `list_instances()` + `send_action`). Discovery is peer-to-peer, not a broker.

## Decision

v1 is a **single IPC settings owner** and **one disk writer**. IPC is the primary coordination channel. File-change notification is a safety net for edits outside the IPC consistency domain.

The reason to pay owner complexity is coalescing:

```text
A changes something
B changes something 80 ms later
C changes something 120 ms later

              ↓

one canonical in-memory document
one 750 ms debounce (override with TANIT_SETTINGS_DEBOUNCE_MS; 0 is allowed)
one encryption
one disk commit
```

instead of three encrypted writes from three processes.

### Plan B (documented, unused in v1)

A short-lived commit mutex is simpler and may be enough later:

```text
all instances may write
  -> reload latest disk if revision changed
  -> merge this instance's pending semantic ops into latest
  -> acquire Local\PolyMech.Tanit.SettingsCommit.<profile>
  -> recheck revision, merge again if needed
  -> encrypt + atomic replace
  -> unlock
  -> IPC settings_changed (notification, not ownership)
```

The lock is held only for the physical commit, not process lifetime. Hung process only stalls others if it dies inside that tiny section; Windows then abandons the mutex. No election, no epoch takeover, no split-brain owner.

IPC would shrink to cache invalidation. `ReadDirectoryChangesW` remains the external-edit net. Disk `_meta.revision` detects stale cache.

| Model | Advantage | Cost |
|---|---|---|
| Permanent IPC owner (v1, shipped) | best coalescing, one encryptor | complex lifetime/failure semantics |
| Short commit mutex (Plan B) | much simpler and robust | potentially more encrypted writes |

Reserve the Plan B mutex name `Local\PolyMech.Tanit.SettingsCommit.<config-dir-hash>`. Do not acquire it in v1.

Tests decide whether to switch. See [Fallback trigger](#fallback-trigger).

### Non-negotiable in either model

```text
acquire lock / owner apply
    -> load current authoritative state
    -> apply this instance's pending semantic changes
    -> write
```

never:

```text
prepare full document from stale cache
    -> lock
    -> write prepared document
```

That distinction is everything. A client's `base_revision` is advisory (conflict policy), never a license to write a stale prepared blob.

## Rules

1. IPC is the primary path. File notification is fallback for old Tanit, CLI import, `--no-ipc` probes, manual replace, crash around ownership change, another utility, IPC bugs, roaming/config sync.
2. A hung owner causes delayed cross-instance synchronization, not a second writer. Temporary stale settings are vastly better than two processes encrypting/replacing the same document concurrently.
3. Reads stay local. `get_setting`, `load_subtree`, provider lookup, theme lookup never IPC.
4. Mutations are semantic. Never send a whole settings document as the normal write. `replace_root` exists for import-class ops; do not use it for MRU/history.
5. Never let settings correctness depend on another instance responding synchronously. UI applies optimistically, then sends IPC. v1 client timeout is the `send_action` deadline (1 s on `settings_mutate`); missing ACK keeps the local cache and does **not** become writer.
6. Ownership is a named kernel mutex held for process lifetime. Heartbeat is diagnostic only. Heartbeat never grants ownership. Only `WAIT_ABANDONED` (dead owner) permits takeover.
7. `g_settings_load_mutex` stays in-process cache protection. It is not cross-process serialization.
8. Encrypt/write stays off the cmd_ipc accept thread (persist worker). v1 still **applies in memory and broadcasts on the accept thread** — see [v1 shortcuts](#v1-shortcuts).

## Architecture

```text
Instance A ─┐
Instance B ─┼── IPC mutations ──> Settings owner
Instance C ─┘                       |
                                    +-- canonical JSON in memory
                                    +-- merge mutations
                                    +-- one debounce (persist thread)
                                    +-- encrypt/write once
                                    |
                                    +-- broadcast revision + changed keys
```

| Concern | Primary | Fallback |
|---|---|---|
| coordination | IPC | |
| serialization | named mutex + IPC owner | |
| cache update | IPC broadcast | |
| debounce | owner persist thread | |
| encryption | owner only | |
| disk write | owner only | immediate persist if no `InstanceServer` |
| external edit | | `ReadDirectoryChangesW` |
| missed IPC | | `ReadDirectoryChangesW` |
| owner crash | named mutex `WAIT_ABANDONED` | disk reload on claim |
| startup | disk load + `settings_snapshot` | |

```text
named mutex     = ownership / death detection
heartbeat       = hang detection (pull, not a push loop)
IPC             = normal mutations + broadcasts
local cache     = survive owner stalls (optimistic; no durable retry journal yet)
file watcher    = external-change / recovery detector
epoch + revision = split-brain / identity of a revision
mutation IDs    = safe retries (string guid, last 256)
```

### v1 shortcuts

Shipped behavior that is thinner than the original worker-queue sketch:

- **Accept thread applies in memory.** `cmd_ipc` `accept_loop` is sequential (`handle_client` one at a time). `settings_mutate` / `settings_changed` / `settings_snapshot` run there: parse, apply to canonical JSON, ACK, fan-out. Encrypt is `settings_ipc_persist_thread_main`. A `TANIT_SETTINGS_HANG_IPC` owner occupies that accept thread, so later `settings_status` / snapshot to the same owner stall. Hung tests must not wait on owner IPC after hang; they only assert the second process did not steal the mutex.
- **Broadcast is on the accept thread** (500 ms `send_action` per peer) before the mutate ACK returns. Fine for a handful of instances; not a dedicated owner worker.
- **No durable client mutation queue.** `g_settings_ipc_pending` is an in-flight counter. Timeout keeps optimistic local state; reconnect does not replay a journal.
- **`persist_now` does not re-read disk `_meta` for epoch mismatch.** Split-brain stop-and-reload is still a follow-on. Watcher reload + new epoch on mutex takeover cover the tested paths.
- **Heartbeat is pull** (`settings_heartbeat`), not an owner push loop.
- **`settings_persisted` is not shipped.** `settings_flush` blocks in `persist_now` and ACKs `level=persisted`.
- Visited / palette MRU / bookmarks / xblox do not have dedicated IPC ops. They hitchhike `save_subtree` → `set_many` when those APIs go through `commit_audited_root`.

## Components

### Local cache

Each process keeps:

- `SettingsRootSnapshot` (`shared_ptr<const nlohmann::json>`)
- owner epoch + revision (`g_settings_ipc_epoch`, `g_settings_ipc_revision`)

Reads hit this cache. IPC is mutation, synchronization, ownership, and broadcast only.

After ownership changes, revision `42` from the old owner and `42` from the new owner are not identical. Compare `(epoch, revision)` as a pair.

### Semantic mutations

Reuse existing store verbs. IPC `op` strings:

| Op | Wire | Notes |
|---|---|---|
| `set` | `key` + `value` | replace one top-level key |
| `set_many` | `fields` | what `save_subtree` / `commit_audited_root` send |
| `merge` | `key` + object `value` | shallow merge into an object |
| `delete` | `key` | remove a top-level key (`_meta` refused) |
| `append_history` | object `value` | MRU prepend + URL dedupe, not whole-array replace |
| `replace_root` | object `value` | import-class; not the normal UI write |

Conflict policy:

- different keys/subtrees → merge (`set_many` fields into canonical root)
- same scalar key → last **accepted** mutation wins
- list-like structures → semantic operation, not whole-array replacement
- `base_epoch` / `base_revision` are sent on client mutate and are advisory in v1 (not a reject)

### Owner mutex

Name:

```text
Local\PolyMech.Tanit.SettingsOwner.<config-dir-hash>
```

FNV-1a hash of `get_config_dir()` UTF-8 so `--config-dir` tests isolate from the roaming profile and from each other.

On `InstanceServer::start()` → `settings_ipc_on_server_start`:

1. Try `WaitForSingleObject` timeout 0 on the mutex.
2. `WAIT_OBJECT_0` or `WAIT_ABANDONED` → become owner (new epoch; `WAIT_ABANDONED` is takeover).
3. Else try `settings_ipc_connect_owner` (`run-ipc/settings-owner.json` then `list_instances()` `settings_owner`, then `settings_snapshot`).
4. If neither claim nor connect: process stays **not active**. `commit_audited_root` falls through to immediate persist (lone CLI without a live owner still writes). A mutate probe that starts IPC typically self-claims.

Owner:

- loads disk into canonical JSON
- starts persist thread (debounce + encrypt + atomic commit)
- starts `FileWatcher` on the backing directory
- publishes `settings_owner=true` plus epoch/revision on its cmd_ipc descriptor
- writes `{config_dir}/run-ipc/settings-owner.json` `{pid,id,epoch,revision,endpoint}`

Other processes with a live owner: snapshot, then `settings_mutate` / intercept `save_subtree`.

If owner dies, Windows releases the mutex (`WAIT_ABANDONED`). Another instance becomes owner, reloads disk, new epoch.

A hung-but-alive process still owns the mutex. Another instance must **not** start writing the file just because IPC timed out.

```text
A is frozen for 5 seconds
B decides A is dead
B starts writing
A wakes up
A still thinks it's owner
=> split brain
```

Only process death (`WAIT_ABANDONED`) permits automatic ownership transfer.

For hung-but-alive: clients keep local optimistic state, disk remains single-writer, retry later. Do not claim the mutex.

### Persist thread

Not the UI thread. Not encrypt-on-accept.

```text
IPC accept thread
  -> apply op to canonical JSON
  -> bump revision, stamp _meta
  -> ACK Accepted
  -> broadcast settings_changed
  -> schedule persist (reset debounce, or FlushNow)

persist thread
  -> wait until due / flush / stop
  -> optional TANIT_SETTINGS_PERSIST_DELAY_MS sleep
  -> encrypt + commit_settings_utf8_unlocked
  -> persistSeq++
```

Default debounce is **750 ms**. `TANIT_SETTINGS_DEBOUNCE_MS=0` persists as soon as the worker runs (still after ACK). Negative values fall back to 750.

`FlushNow` when the commit context contains `ui_close`, equals `save_settings_utf8`, or contains `import`, or the mutate payload `durability` is `flush_now`. Owner shutdown always `persist_now`.

### Persistence metadata

Every committed document carries:

```json
{
  "_meta": {
    "writer_epoch": 13435156547383,
    "revision": 1842,
    "writer_pid": 1234
  }
}
```

`writer_epoch` is `GetSystemTimeAsFileTime` / 10000 at claim time (ms-ish counter, not a GUID).

### File watcher

Reuse `src/core/file_watcher.hpp` (`ReadDirectoryChangesW`). Watch the **directory**, not an open handle to `settings.json`. Commits are temp-file + replace, so file identity can change. Secure storage updates `.doc` / `.doc.meta` / `.doc.sig` / `doc-index.json` on a logical commit.

Watch parent of `settings_profile_meta_path()` (secure) or `settings.json` (plain). Ignore events for 1500 ms after own persist.

```text
ReadDirectoryChangesW
        ↓
relevant settings backing file changed
        ↓
disk (epoch, revision) already ours?
   yes → ignore
   no  → owner reloads document
         bumps revision, stamps _meta
         broadcasts settings_reloaded (includes root)
```

Covers old Tanit that does not participate in IPC, `--no-ipc` mutate, CLI import, manual replacement, crash/restart around ownership change, another utility, IPC bug, roaming/config synchronization.

## Protocol

Wire: existing cmd_ipc (4-byte LE length + UTF-8 JSON). `default_handle` routes any `action` prefix `settings_` to `media::settings::settings_ipc_handle` so UI, CLI, daemon, and test probes all speak them without `Mainfrm::set_extra_action_handler`.

On `InstanceServer::start()` (after bind + descriptor write): `settings_ipc_on_server_start(desc)`. On stop or failed descriptor write: `settings_ipc_on_server_stop()`.

Short-lived CLI: if an owner exists, mutate via IPC. If not, claim mutex for process lifetime and `FlushNow` on owner exit. Do not churn ownership every `tanit-cli` invocation when a UI/daemon is already owner.

`CliActivityScope` does not publish IPC for `test core` today. Test probes start `InstanceServer` themselves (`ProcessKind::Cli`, label `test-core-settings`). Product UI (`StartCommandIpcServer`) and capture-worthy CLI already start a server; owner claim runs at that start.

### Mutation payload

```json
{
  "action": "settings_mutate",
  "guid": "11111111-0000000000000001-00000001",
  "base_epoch": 0,
  "base_revision": 0,
  "op": "set_many",
  "fields": { "probe_theme": "dark" },
  "durability": "debounced"
}
```

`guid` empty → not idempotent (always apply). Same non-empty `guid` twice → one apply, same revision. Owner keeps a 256-entry ring.

Client intercept (`settings_ipc_try_commit` when not owner) generates `pid-tick-seq` unless `TANIT_SETTINGS_MUTATE_GUID` is set. Probe `--guid` sets that env (Win32 `SetEnvironmentVariableA` + `_putenv_s`). Hook readers must use `GetEnvironmentVariableA`, not CRT `getenv` — the CRT copy is frozen at startup.

### ACK

```json
{
  "type": "settings_ack",
  "guid": "...",
  "level": "accepted",
  "epoch": 1,
  "revision": 2
}
```

`settings_flush` uses `level: persisted`. Owner acknowledges mutate from memory. It does not encrypt before mutate ACK.

```text
IPC mutation
→ canonical root updated
→ settings_changed broadcast
→ ACK immediately

debounce later (default 750 ms)
→ encrypted persistence
```

| Change | Durability |
|---|---|
| window position / theme / MRU | Debounced |
| `save_settings_utf8` / import / `ui_close` | FlushNow |
| process-exit-as-owner | FlushNow |
| probe `--wait-persisted` | `settings_flush` after mutate |

### Verbs

| action | who | purpose |
|---|---|---|
| `settings_snapshot` | client → owner | fetch `root` + `{epoch,revision}` at connect |
| `settings_mutate` | client → owner | one semantic mutation; ACK `{guid,epoch,revision,level}` |
| `settings_changed` | owner → peers | `{epoch,revision,keys,op,fields}` — apply to local cache, no disk wait |
| `settings_reloaded` | owner → peers | external/disk reload; payload includes `root` |
| `settings_heartbeat` | client → owner | `{epoch,revision,monotonic_ms}` — liveness only |
| `settings_flush` | client → owner | `FlushNow`; ACK after persist |
| `settings_status` | client → owner | `{owner,pid,epoch,revision,pending,persistSeq,lastKeys,lastCommitMeta}` |

Descriptor extras: `settingsOwner` / `settingsEpoch` / `settingsRevision` in instance JSON (`settings_owner` in C++). Pointer file: `{config_dir}/run-ipc/settings-owner.json`.

## Client write path

```text
local UI / save_subtree
    ↓
audit + optimistic local cache
    ↓
if owner: apply + schedule persist + broadcast
if peer:  settings_mutate (1 s send_action)
if inactive: immediate disk persist (legacy path)
```

If mutate ACK times out: log, **keep local**, do not become writer.

On connect: `settings_snapshot` replaces local cache. There is no queued-op replay in v1. Semantic hitchhiking (`set_many` of changed keys) is what `save_subtree` sends, not a whole-tree replace.

Example: owner has `appearance.theme = dark`. Disconnected B locally changed `providers.openai.model = gpt-x`. B reconnects with a snapshot first (gets dark), then a later `SET providers.openai.model` is the safe form. `replace_root` of B's stale cache would overwrite A's theme — probes must not do that.

## Owner apply path

1. `settings_ipc_guid_seen` — duplicate → ACK current epoch/revision, no bump, no persist, no broadcast
2. apply op to canonical JSON
3. bump in-memory `revision`, stamp `_meta`
4. ACK `Accepted`
5. fan-out `settings_changed`
6. reset persist debounce (or FlushNow)
7. persist thread: one encrypt + one disk commit (`persistSeq++`)

Crash window (accepted in memory, ACK sent, process dies before encrypt): ordinary UI settings may revert one debounce interval. Accepted for v1.

## Peer cache install (broadcast-before-disk)

`settings_changed` lands on every peer while the owner may still be inside its debounce window — disk does not have the new value yet. `settings_ipc_install_cache` therefore keeps the in-process cache self-consistent: it installs the received root **and** sets `g_settings_cache_sp` + captures the current disk mtime. Without that, a peer that never disk-loaded (empty `sp`) fails `settings_cache_is_stale_for_path` and reloads the **old** disk document over the just-applied IPC root. With it: cache stays fresh until the owner actually commits (mtime then differs → next read reloads disk, which by then has the new value).

The General settings form submits `config_directory_path` on every OK save. `save_config_dir_registry_value` must treat an unchanged empty or resolved path as a no-op. Invalidating the settings cache for an unchanged path would make the following General-field save reload the old disk revision during the owner debounce, discarding the just-installed appearance/language root before live apply and persistence.

## Settings UI reopen (hideOnClose refetch)

The settings window uses `hideOnClose` — reopening goes through the `CWebViewManager::ShowOrFocus` reuse branch and the SPA never remounts, so its mount-time `settingsGeneralGet` does not re-run and the general tab (theme / language / use_native_editor) showed the values from the previous visit. Fix:

- Reuse branch: if `hideOnClose` **and** the HWND was hidden before activation (genuine reopen, not a re-show of a visible window), post `{"t":"cweb_shown"}` to the page.
- Settings SPA (`useSettingsHostMessageBridge.onShown` in `apps/settings/src/main.tsx`) calls `reloadGeneral()` on that message — refetching from the last local (IPC-invalidated) cache via `settingsGeneralGet` / `load_appearance`, which read the peer cache above.

Already-visible re-shows skip the message so unsaved form edits are never clobbered. The native peer chrome (ApplyAppearance, ribbon language) still follows on that instance's own settings interaction; broadcasting a native appearance re-apply on `settings_changed` remains a follow-on below.

**Journal (`settings.pending`) is phase 2.** Append tiny records, ACK durable, debounce, encrypt canonical document, atomically replace, truncate journal. Exclude secret-bearing mutations from a plaintext journal, or encrypt each journal record independently (still cheaper than rewriting the whole document).

## Failure modes

| Case | Behavior |
|---|---|
| owner process dead | mutex abandoned; next claimant reloads disk, new epoch |
| owner alive but hung / accept thread deadlocked | no second writer; clients keep local; do not query that owner |
| client sends mutation, never gets ACK | keep local; retry with same guid is safe if the client still has it |
| owner applies in memory, crashes before disk flush | v1 loss of debounce window; journal later |
| two instances both think they are owner | mutex should prevent; leftover pointer file is ignored if pid/id do not match `list_instances` |
| IPC reconnect after stall | snapshot, then new semantic ops; no automatic journal replay |
| external file change while owner healthy | watcher reload + `settings_reloaded` |
| process never started `InstanceServer` | `NotActive` → immediate persist (lone writer) |

## Implementation map

- `src/win/settings_store.cpp` — mutex, claim/connect, persist thread, watcher, `commit_audited_root` / `save_settings_utf8` intercept, GUID ring, env hooks via `GetEnvironmentVariableA`, `settings_ipc_handle`. `g_settings_load_mutex` stays in-process.
- `src/core/cmd_ipc.cpp` — `settings_*` prefix in `default_handle`; `settings_ipc_on_server_start/stop` after bind / on shutdown.
- `src/core/settings_store.cpp` — stubs when not Windows.
- `src/win/web/CWebViewManager.cpp` — `ShowOrFocus` reuse branch posts `cweb_shown` on genuine hideOnClose reopen.
- `apps/shared/settings/hostRpc.ts` + `apps/settings/src/main.tsx` — `onShown` hook → `reloadGeneral()` on `cweb_shown` (rebuilt via `npm run build:settings-bundle`).
- `src/cli/pm_image_register_test.cpp` — probes below. Env from CLI flags also `_putenv_s` so CRT getenv would see them; store code still reads Win32.
- `tests/orchestrator/test-core.mjs` — `runCore` / `spawnCore` pass `--config-dir` and extra env.
- `CMakeLists.txt` — no extra TU. `FEATURE_COMMAND_IPC_NEXT` required for IPC scenarios. `FEATURE_COMMAND_TEST` compiles the probe TU into `tanit-cli`.

There is no CTest registration. Integration tests are npm → Node orchestrator → `tanit-cli`.

## Test plan

`npm run test:core:settings`. Pattern: Node orchestrator + isolated `--config-dir` + `tanit-cli test core … --json`.

```text
exe --config-dir <tmp> --log-level off test core --json …
```

Windows only for IPC/mutex/watcher scenarios. Skip with a clear reason if `settings-status` reports `ipcNext` false.

Keep the existing path-handle probe (`settings`).

### Test-only hooks

Env / probe flags, not product API. Owner process must see them in the **Win32** environment (`GetEnvironmentVariableA`). Node `env` on `spawn` is visible from process start; CLI flags applied mid-run need `SetEnvironmentVariableA` (and `_putenv_s` for CRT).

| hook | purpose |
|---|---|
| `TANIT_SETTINGS_PERSIST_DELAY_MS` | sleep at start of owner `persist_now` (simulates encrypt) |
| `TANIT_SETTINGS_ACK_DELAY_MS` | `Sleep` before mutate ACK |
| `TANIT_SETTINGS_HANG_IPC=1` | owner loops in `settings_mutate` until stop; holds mutex; occupies accept thread |
| `TANIT_SETTINGS_DEBOUNCE_MS` | debounce ms; `0` allowed |
| `TANIT_SETTINGS_MUTATE_GUID` | force client mutate guid (`--guid` on the probe) |

Status snapshot: `{owner, pid, ownerPid, epoch, revision, pending, persistSeq, lastKeys, lastCommitMeta, ipcNext}`. Non-owner `settings-status` probe copies `persistSeq` from the owner's `settings_status` IPC (local `persistSeq` is always 0 on a client).

Do not assert on wall-clock encrypt time except as delay injection. Assert invariants: single writer pid, no lost distinct-key edits, broadcasts beat disk, hung ≠ takeover.

Each mutate probe is a **new process**. Spacing at the orchestrator is not spacing at the owner. `debounce-coalesce` uses a long debounce (1500 ms) covering three sequential CLI mutates in one window, then asserts `persistSeq === 1`. `broadcast-before-disk` samples owner `persistSeq` immediately after ACK, before waiting on the peer, so a 2 s persist delay still reads `0`.

### Probes in `pm_image_register_test.cpp`

1. `settings` — existing path handles (keep).
2. `settings-roundtrip` — single process, isolated dir: `save_subtree` / `merge_subtree_object` / reload. Baseline without needing a held owner.
3. `settings-owner --hold [--hang-ipc] [--persist-delay-ms] [--timeout-ms]` — claim mutex, start IPC, print snapshot JSON, sleep until timeout. Orchestrator's long-lived owner. Prints JSON then flushes before hold so Node can attach.
4. `settings-mutate --op set\|merge\|append-history --key --value [--guid] [--wait-persisted] [--no-ipc]` — `save_subtree` / merge / `settings_mutate` append-history. `--no-ipc` is the foreign writer (no `InstanceServer`). `--wait-persisted` sends `settings_flush`.
5. `settings-wait-changed --min-revision --timeout-ms` — poll local revision (updated by `settings_changed`) until min or timeout.
6. `settings-status` — local snapshot; if not owner, query live owner `settings_status` for `persistSeq` / `ownerPid`.

### Orchestrator scenarios

Isolated `freshCfg(work, id)` per scenario. `withOwner` spawns `settings-owner --hold`, waits for `ready`, runs the body, kills the child.

| id | what it proves |
|---|---|
| path / apostrophe / roundtrip | existing JSON-safe handles + single-process save/load |
| `cli-with-owner` | mutate goes IPC (`owner=false`); owner cache has the key |
| `cli-without-owner` | single mutate process with IPC self-claims; `FlushNow` on exit |
| `lost-update-prevented` | theme + provider overlapping a 2 s persist delay → both keys; same `ownerPid` |
| `debounce-coalesce` | three mutates in one debounce window → `persistSeq === 1`, last scalar wins |
| `broadcast-before-disk` | long-lived peer `settings-wait-changed` gets revision **and** `probe_theme` from `settings_changed` while persist delay still running (`persistSeq === 0`). A fresh `settings-status` process is not a peer — it snapshots the owner. |
| `owner-write-peer-cache` | owner `save_subtree` (same intercept as `save_appearance`) after a peer is connected → peer local cache has the new key. UI `settingsGeneralGet` / `load_appearance` read that cache; they do not invalidate-and-reload disk. |
| `hung-owner-no-split-brain` | `--hang-ipc`; mutator `owner===false` and different pid (do not IPC-status the hung owner) |
| `dead-owner-takeover` | kill owner; successor `owner=true`, new `epoch`, `--wait-persisted` `persistSeq>=1` |
| `idempotent-retry` | same `--guid` twice → revision stays, first value kept |
| `semantic-history` | two `append-history` items → both URLs present |
| `external-replace` | `--no-ipc` write while owner held; waiter sees reload (`theme=foreign`) |

`npm run test:core:settings` last green: **50 passed, 0 failed** (Windows, `FEATURE_COMMAND_IPC_NEXT` on).

### Fallback trigger

Keep the owner if these stay true under injected persist delay.

Consider switching to Plan B (short commit mutex + rebase) if:

- `hung-owner-no-split-brain` / `dead-owner-takeover` are flaky or expensive to keep correct
- persist delay under realistic encrypt time does not produce overlapping writers worth coalescing (`debounce-coalesce` rarely fires in real UI)
- owner election itself causes lost updates (tests fail for coordination, not merge logic)

If we fall back, keep the same semantic ops, IPC `settings_changed` broadcast, watcher, `_meta.revision`, and `lost-update-prevented` / `semantic-history` tests. Only ownership and coalescing change. The rebase-on-latest rule remains in either model.

## Follow-ons

- Journal (`settings.pending`) for durable ACK without full re-encrypt per mutation
- Enqueue off the accept thread (tiny parse → owner queue) so hang/encrypt cannot stall ping/status
- Disk `_meta` epoch check before commit; stop + reload on mismatch
- Selective `FlushNow` / persisted ACK for secrets, license, auth (`settings_persisted`)
- Dedicated ops for visited MRU, palette recent, bookmarks, xblox if hitchhiking `set_many` is too coarse
- UI appearance / provider apply on `settings_changed` (WebView/post to UI thread; not in the IPC handler)
- Possible switch to Plan B if tests say coalescing is not worth owner lifetime
- Non-Windows: cmd_ipc is UDS there; owner mutex and `ReadDirectoryChangesW` stay Windows-first; stubs return errors
