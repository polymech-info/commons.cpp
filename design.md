# Follow-ups

The contract is README.md. This list is the order to take next.

`media::zip_store` lives in `src/fs/zip_store.cpp`. Settings archive and the installer extract verb include `fs/zip_store.hpp`. `pm-media` links `pm-commons-lib`; it does not compile a second copy.

1. Tanit compiles `packages/commons.cpp/src` straight into `pm-media` (security compiles `src/path/path.cpp` only). `pm-commons-lib` stays the standalone test library. Next, drop the host copies once each package file is the original body: `src/string_utils.cpp`, `src/utilities/uuid_generator.cpp`, and `src/fs/filters`. Leave `src/core/uri.cpp` (Boost) and the PATH half of `src/core/app_resolver.cpp` until those dependencies move with the file. `packages/vfs.cpp/src/commons` still has its own path copy.
2. Pass `process::which` a PATHEXT list from the host on Windows. The registry, App Paths, Start Menu, and package-family scan stay in `app_resolver.cpp`.
3. Scheduler claims already take a process-alive hook. The host should pass its existing liveness check when it links the library. Do not pull a process snapshot into this package.
4. Task handlers (`settings_prewarm`, manifests, index cleanup, ipc prune) stay in `src/tasks`. This package only owns the stable id table.
5. Optional nlohmann slice for `async_iterator` and task-option JSON. jq stays a host dependency. Do not put it in the default static library.
6. HTTP fetch (`http_client`, `url_fetch`) belongs in a later net package. It needs sockets and curl, which this library does not link.
7. `packages/ipc` can adopt `pm::commons::ipc` for the frame and keep its own transport. `src/ipc/ipc_serve.cpp` stays a host server.
8. CLI11 schema helpers and a process runner (spawn, not `which`) once a caller needs them. Parent options stay on the executable, not in the library.
9. `src/types.h` `NH_Parameter` stays in the host. Only `Uuid64` moved.
10. Magic-byte sniff is the portable probe. libmagic and `magic.mgc` stay with the host file tool.

## Settings

`packages/commons.cpp/src/settings` owns the store. Encryption, the config-dir override, the `--settings` read-path override, registry config dir, portable profile, Windows profile, typed readers, chat JSON, and the ZIP archive move with it. The host passes a configuration: storage kind, and the layout (`config_dir`, and any path it wants to pin). Dialogs stay in the app and call this store.

The file profile is the default implementation of one interface. A database adapter is a second implementation of that same interface, written when a caller needs it. Subtree callbacks in `pm::commons::host` and the per-package directory lambdas are the glue this cut removes.

What moves, as one module:

| Piece | Where today |
|---|---|
| Windows profile, PME1, DPAPI key wrap, overrides | `src/win/settings_store.cpp`, `src/win/settings_store.hpp` |
| Non-Windows profile | `src/core/settings_store.cpp`, `src/core/settings_store.hpp` |
| Portable file | `src/core/settings_portable.cpp` |
| Typed readers | `src/core/settings_runtime.cpp`, `src/core/settings_runtime.hpp` |
| Shapes | `src/core/settings_types.hpp` |
| Chat JSON | `src/core/chat_settings_schema.cpp` |
| Zip backup | `src/core/settings_archive.cpp` |
| Xblox stand-in | `packages/xblox/cli/standalone_host.cpp` |

Audio, video, search, and xblox read the store. They stop taking a `config_dir` lambda from `video_host.cpp`, `audio_record_host.cpp`, `search_host.cpp`, and `commons_host.cpp`.

Settings goes first. Auth and `packages/llm.cpp` both need the profile, and neither exists as a store the host can pass.

`src/lib/pm_zitadel_oauth.cpp` and `src/lib/provider_oauth.cpp` call `media::settings::get_config_dir()`, then `pm::storage` under that directory. `merge_provider_credentials` calls them back for the tanit token and for `auth_mode` `oauth` / `auto`. Pulling auth out first leaves it asking the host store for a path. The login and refresh flow stays in the app. The token files and the credential merge move with the typed document, once `settings::Store` is the profile.

`packages/llm.cpp` is a README. The live callers are `src/llm` and the xblox resolvers in `block_provider.hpp`. A package created before the handle would grow the same stubs as `standalone_host.cpp`. It waits until cut 3, then takes `settings::Store&`.

Cuts, in order. Each one leaves `tanit-cli` on the new store before the next starts.

1. **Interface plus the default file store.** `settings::Store` is load, save, subtree, layout, config-dir override, settings-path override, export, and profile-key reset. The current encrypted profile is `settings::FileStore`. Tanit and `tanit-cli` construct that store from the host configuration and pass the reference. Delete the host copies of the store in the same cut, including the xblox stand-in.
2. **Typed document.** Readers, shapes, chat schema, and the ZIP archive become methods on that store. Call sites in `src/` use the reference the process already holds.
3. **Package handles.** Audio, video, search, and xblox take `settings::Store&` from the host. Drop their directory and subtree hooks.

On the radar, after those three: `packages/image.cpp` and `packages/llm.cpp` take the same `settings::Store&` from the host. They do not open the profile and they do not grow a settings module. `image.cpp` still calls `media::settings` from its security CLI. That call becomes the handle.

Check each cut with the CLI suites already in `package.json`. Both run `dist/win-x64/tanit-cli.exe` (`PM_IMAGE_CLI` overrides the path).

- `npm run test:core:settings` — `tests/orchestrator/test-core.mjs --only settings`. Probes `settings`, `settings-roundtrip`, `settings-status`, `settings-owner`, `settings-mutate`, `settings-wait-changed`.
- `npm run test:settings` — `tests/orchestrator/test-media.mjs --settings-only`. Provider and chat keys resolve through the store.

### Xblox

A block field wins. An empty field is read from the store. Keys are never a block field. `packages/xblox/cli/standalone_host.cpp` stubs these reads, so a standalone `pm-xblox` returns no devices, no presets, and empty credentials.

| Op | Call today | Empty block field |
|---|---|---|
| Audio in/out | `audio_blocks.cpp` `resolve_audio_input` / `resolve_audio_output` | `custom.audio_video_devices` |
| Camera, mux mic | `video_core_blocks.cpp` `resolve_video_capture`, `resolve_audio_input` | same device record; unplugged camera falls back to the OS default |
| Speak | `audio_blocks.cpp` `effective_tts_provider` | `chat.tts_provider` |
| LLM / STT / TTS | `block_provider.hpp` `resolve_llm`, `resolve_stt`, `resolve_tts` | router, model, voice from chat settings; `merge_provider_credentials` fills `providers[name].api_key` and `base_url` |
| Video generate | `video_blocks.cpp` `videoCreate` | `merge_provider_credentials` for the block provider |
| Image generate | `image_blocks.cpp` `apply_image_ai_defaults` | default chat preset, then `merge_provider_credentials` |
| OCR | `ocr_blocks.cpp` `apply_ocr_settings_defaults` | `chat.ocr_provider` or `chat.image_recognition_provider`, then `ocr_model` |

After cut 3 the host passes `settings::Store&` into the xblox session. Those functions call `store.audio_video_devices()`, `store.chat_provider()`, and `store.merge_provider_credentials(...)`. The standalone CLI constructs the same `FileStore` from its `--config-dir` and drops the stubs in `standalone_host.cpp`. A database adapter satisfies the same three calls.

### Also in this cut

These are the store, not callers. They were outside the table above.

| Piece | Where | Why it moves |
|---|---|---|
| Default profile root | `src/core/app_storage.cpp` (`pm::appdata`) | `get_config_dir` picks MSIX `LocalState` / `LocalCache` or `%APPDATA%`. Registry and `--config-dir` sit on top of this. |
| Models-dir and install-dir check | `src/ui_defaults.hpp` `effective_models_dir`, `is_under_install_dir` | The store calls these two. The rest of that header stays UI. |
| Android readers | `src/core/settings_runtime_android.cpp`, `src/core/settings_chat_presets_android.cpp` | Same typed document, second body. |
| Batch sessions file | `sessions.json` IO inside `src/win/settings_store.cpp` | `src/core/batch_queue.hpp` is the in-memory queue. The file lives in the store. |
| Profile backup | `src/core/pmbackup.cpp` | Cloud `.pmbackup` on top of `settings_archive`. |
| Settings owner | `settings_ipc_*` in `settings/win/settings_store.cpp` | The bus is `ipc/cmd_ipc.cpp`. The host handler list in `src/core/cmd_ipc_host.cpp` forwards `settings_*`. `test:core:settings` drives these verbs. |
| Credential files | `src/lib/provider_oauth.cpp`, `src/lib/pm_zitadel_oauth.cpp` | `merge_provider_credentials` reads `oauth-tokens.json` and `zitadel-oauth.json` through `pm::storage`, then can write the tanit key back. A JSON-only reader leaves those providers empty. |
| Policy temp dir | `pm::policy::policy_temp_dir` in `settings_runtime.cpp` | One override. The host pins `temp` in the layout. The store does not include `policy/app_policy.hpp`. |

`pm::storage` (`packages/commons.cpp/src/storage`) is already the encrypted document backend (`settings.json.doc`, `commands.json`). The profile code moves onto that. PME1 and `.settings-key.dat` stay the legacy file format inside `FileStore`.

`src/win/settings_empty_override_dlg.cpp` is a dialog the store compiles in. It stays in the app. The store reports an empty override. The dialog asks the user.

### Callers

These read the store and stay where they are. They take `settings::Store&` the same way xblox does.

- `src/core`: `command_variables.cpp` (variables subtree, `MODELS_DIR`, `TEMP_DIR`), `local_model_catalog.cpp`, `hotkeys.cpp` (command-document watch path), `web_command_host.cpp`, `launcher_commands.cpp`, the provider model CLIs (`openai`, `openrouter`, `replicate`, `pixlwiz`), `transform.cpp`, `meta.cpp`, `resize.cpp`, `app_image_provider.cpp`.
- `src/lib`: `KompressScorer`, `EmbedInference`, and `VectorStore` only need `models` and `embedding_models` from the layout. The models stay in the LLM package.
- `src/llm` (`chat_session_store`, `mcp_config`, `change_store`) already uses `pm::storage`. They need the layout, not a second settings module.
