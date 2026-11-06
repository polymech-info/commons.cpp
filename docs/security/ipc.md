# Command IPC

Cross-process bus for live Tanit instances: UI, CLI, daemon, assistant, xBlox, llm-agent. One process publishes a descriptor and a loopback socket. Other processes discover it and send one action per connection.

`FEATURE_COMMAND_IPC_NEXT` compiles the bus. `tanit-security` forces that flag off.

## Where the code sits

| Piece | File | Role |
|---|---|---|
| Transport, discovery, handshake | `src/ipc/cmd_ipc.hpp`, `src/ipc/cmd_ipc.cpp` | Generic. No settings, models, or UI commands. |
| Host handlers | `src/core/cmd_ipc_host.cpp` | Directory, settings owner, models, agents, run/cancel, app commands. |
| Shim | `src/core/cmd_ipc.hpp` | Includes both headers so existing callers keep compiling. |
| Settings verbs | `src/settings/win/settings_store.cpp` | `settings_ipc_handle` and the owner mutex. The host registers them. |

`src/ipc/cmd_ipc.cpp` is not in `pm-commons-lib`. The host image compiles it, because that target has standalone Asio and the feature flag. `pm-media` gets `ASIO_STANDALONE` when the flag is on.

## Flow

1. The first call to `instances_dir()` runs `install_process_handlers()` once. That points the directory at `get_config_dir()/run-ipc/instances` and registers the shared handlers.
2. `InstanceServer::start` reaps dead descriptors, binds `127.0.0.1` on an ephemeral port (or a Unix socket), fills the descriptor, then runs the shared start hook.
3. On Windows the start hook claims or follows the settings owner and writes `settingsOwner` / `settingsEpoch` / `settingsRevision` onto the descriptor before it hits disk.
4. The accept thread speaks first: `{type:"challenge", nonce, protocol:1}`. The client answers with `proof = SHA256(token || nonce)` on its request frame. The token is 32 random bytes, stored only in the descriptor file under the user profile and in the server process. A failed proof closes the socket.
5. Dispatch, when `set_handler` is empty: `ping`, `status`/`info`, `stop`, then shared handlers, then `add_handler` in registration order, then the extra slot. A handler returns null JSON to decline. Missing `pid`, `ts`, and `id` are filled in.
6. `stop` flushes `{type:"stop_ack"}` and then runs the stop hook on the accept thread. The hook must not block. With no hook, only this server shuts down.
7. `shutdown` runs the shared shutdown hook (settings owner flush and release), wakes the accept thread, joins it, and deletes the descriptor.

`set_handler` replaces steps 5's chain. xBlox does that and handles `ping`, `status`, `artifacts`, `loaded_models`, and `stop` itself. The start and shutdown hooks still run, so that process still joins the settings owner.

## Wire

4-byte little-endian length, then a UTF-8 JSON body. Frames are capped at 16 MiB. `send_action` connects, reads the challenge, sends one request, reads one reply. An `auth failed` reply is a transport error.

The descriptor JSON is one `<pid>.json` file: `id` (`pid:<n>`), `kind`, `pid`, `cwd`, `endpoint` (port or socket path), `transport` (`tcp` or `uds`), `startedUnixMs`, `label`, `cmdline`, `commandId` (from `PM_IMAGE_COMMAND_ID`), `token`, and the three settings fields.

`list_instances` drops descriptors whose pid is dead. `list_instance_records` keeps them and can mark a live pid orphaned when `ping` fails. `prune_instance_records` deletes those rows.

## Host setup

Call `add_handler` for a verb this process owns. Return null to ignore the request. `set_extra_action_handler` is the same idea as one replaceable slot, so a long-lived CLI can attach and later clear a verb after `start`. `set_stop_hook` is how UI, daemon, scheduler, and CLI map `stop` onto close or cancel.

Shared handlers, installed once for every server in the process:

| Action | Handler |
|---|---|
| `loaded_models`, `stop_model` | In-process llama, VLM, ONNX, whisper, VibeVoice, embed, embedded MCP. |
| `agents` | On-disk agent registry. |
| `settings_*` | `media::settings::settings_ipc_handle`. Windows only. |

Per server, from the UI:

| Action | Installed by |
|---|---|
| `run_ids`, `cancel` | `install_run_handlers` |
| `app_cmd`, `app_cmds` | `install_app_cmd_exec`, `install_app_cmd_list` |
| `chat`, `command_run`, `dock_debug`, `command_finished`, artifact rows, scheduler | `set_extra_action_handler` on the UI, daemon, or scheduler |

A new verb is another lambda. It does not go in `src/ipc/cmd_ipc.cpp`.

## Features

| Flag | Effect |
|---|---|
| `FEATURE_COMMAND_IPC_NEXT` | Compiles the bus and the `run-ipc` CLI. |
| `FEATURE_SECURE_STORAGE` | Settings owner watches the secure document directory instead of the profile root. |
| `FEATURE_LLAMA`, `FEATURE_ONNX`, `FEATURE_WHISPER`, `FEATURE_VIBEVOICE`, `FEATURE_COMMAND_LLAMA_INFERENCE` | Which rows `loaded_models` can report. |
| `FEATURE_SCHEDULER` | Daemon and scheduler extra handler. |

`npm run test:core:settings` drives the settings verbs through `tanit-cli` (`settings-owner`, `settings-mutate`, `settings-wait-changed`).
