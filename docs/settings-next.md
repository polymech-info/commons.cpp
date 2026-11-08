# Settings Next

Scope: CLI and settings app provider/model settings. We keep the current chat preset interface and make it the foundation for workflows.

## Decision

Do not introduce a new model-target abstraction and do not split model selection into another settings subtree.

The user-facing unit remains a chat preset:

- `router` / `model`
- `planner_router` / `planner_model`
- `realtime_router` / `realtime_model` / `realtime_voice`
- `image_provider` / `image_model`
- `image_recognition_provider` / `image_recognition_model`
- `video_provider` / `video_model`
- `stt_provider` / `stt_model`
- `tts_provider` / `tts_model` / `tts_voice_id`
- optional tools policy
- optional skills policy
- `isDefault` / `is_default`

This shape is easy for users to understand and already appears in `s1.json`. A preset like `quick` is effectively a workflow profile: one selection in the UI can choose text LLM, realtime voice, image/video models, audio providers, tools, and skills together.

We keep one preset marked as the default for chat sessions and CLI runs that do not specify a preset.

## Source Of Truth

Settings store is the only source of truth, unless the user passes explicit CLI overrides.

No hidden fallback chains:

- Do not infer runtime model selection from first provider row.
- Do not infer runtime model selection from provider API key presence.
- Do not infer runtime model selection from `providers[*].default_model`.
- Do not use top-level legacy `active_provider`.
- Do not silently pick OpenRouter, Replicate, Google, or any built-in model if settings are missing.

If a command needs a model and no preset/settings/CLI override provides one, fail clearly and tell the user where to set it.

Provider rows remain credentials and endpoint configuration:

- `api_key`
- `base_url`
- OAuth/token related state
- optional catalog/display hints

Runtime model choice remains in `chat` and chat presets.

## Current Shape

Canonical native type:

- `src/core/settings_types.hpp`
- `media::settings_types::ChatProviderSettings`

Preset persistence:

- `settings.json["custom"]["settings_chat_presets"]`
- `src/core/settings_runtime.cpp`
- `media::runtime_settings::ChatProviderPreset`

Settings app shared TS type:

- `apps/shared/providers/settings.ts`
- `ChatSettings`
- `ChatPreset`

Windows settings web host:

- `src/win/ui_next/CSettingsWebView.cpp`
- `settingsChatGet`
- `settingsChatSave`
- `settingsChatPresetsGet`
- `settingsChatPresetsSave`

CLI and info paths:

- `src/cli/pm_image_cmd_llm_agent.cpp`
- `src/cli/pm_image_cmd_llm_info.cpp`
- `src/cli/pm_image_cli_helpers.cpp`
- `src/cli/pm_image_cli_state.hpp`

Local model commands:

- `src/cli/pm_image_cmd_llama.cpp`
- `src/cli/pm_image_cmd_video_detect.cpp`
- whisper path in `src/cli/pm_image_cmd_llm_agent.cpp`

## Fragmentation Found

Manual sync is the main problem.

The same chat field list is copied across:

- `src/win/settings_store.cpp`
- `src/core/settings_runtime.cpp`
- `src/win/ui_next/CSettingsWebView.cpp`
- `apps/shared/providers/settings.ts`
- `src/cli/pm_image_cmd_llm_info.cpp`

This causes drift. Examples already exist:

- C++ parses fields that some save/RPC paths do not consistently write.
- TS and C++ defaults can diverge.
- `llm info`, agent launch, image CLI defaults, and compact context have separate default-preset selection logic.
- Settings UI and `llm info models` duplicate provider model catalog special cases.

Agent preset use is also incomplete:

- Text agent routing uses the selected preset.
- Some image/vision/video tool default helpers still read top-level `settings.json["chat"]`.
- That means `llm agent --preset quick` can use preset text routing while tools still use global image/video settings unless tool arguments override them.

## Local Models

We still want users to choose from locally available models:

- runtime config directory: `config_dir/models`
- development fallback: `dist/models`
- user-selected absolute paths

This should not create new model-profile abstractions. Local models should appear as selectable models for the existing preset slots.

Examples:

- `stt_provider = "whisper"` and `stt_model = "base.en"` can resolve to `config_dir/models/whisper/base.en.*` or `dist/models/...`.
- `video_provider = "onnx"` and `video_model = "yolo11n"` can resolve to a local ONNX model plus a saved parameter schema.
- `image_recognition_provider = "llama"` and `image_recognition_model = "paddleocr-vl"` can resolve to GGUF + mmproj settings.
- `router = "custom"` / `model = "<model-id>"` can remain a normal OpenAI-compatible router/model pair, using `providers.custom.base_url` plus the model string. No new client is needed for this path.

The model id shown in the preset should remain a friendly id. The local path and runtime knobs are metadata attached to that model id, not a replacement for router/model selection.

## Model Parameters

Replicate already points at the larger problem: models often have their own input schema.

This is not only a settings problem. The same model parameter schema must be usable from:

- settings app
- custom commands
- XBlox
- CLI
- path tools / chat tools

Replicate has some of the basics in place: model catalog, collections, schemas, and provider-specific UI. The next step is to generalize the idea without tying it only to Replicate.

Target concept:

- A selected model can expose a parameter schema.
- The schema belongs to the model catalog entry or local model manifest.
- A preset may store default parameter values for that model slot.
- Commands/XBlox/CLI can override those values per invocation.

Parameter resolution order:

1. explicit command / XBlox / CLI / tool input
2. selected preset model defaults
3. settings-store model defaults
4. schema defaults
5. fail if required input is still missing

This is not a hidden provider/model fallback. It is parameter resolution after the model has already been selected.

## Next Todos

### 1. Eliminate Manual Sync

Create one schema definition for chat settings and presets.

The generated/derived outputs should include:

- C++ parse/serialize helpers for `ChatProviderSettings`
- C++ parse/serialize helpers for `ChatProviderPreset`
- TypeScript `ChatSettings` and `ChatPreset`
- RPC payload types for settings app
- JSON schema for import/export validation
- maybe CLI `llm info` serialization helpers

Immediate cleanup:

- Move chat JSON conversion out of `settings_store.cpp`, `settings_runtime.cpp`, and `CSettingsWebView.cpp` into one shared helper.
- Make settings app RPC use that helper for `settingsChatGet` / `settingsChatSave`.
- Make preset load/save and `llm info` use the same serializer.
- Keep snake_case JSON as the persisted shape; accept camelCase only where needed for compatibility.

### 2. Single Source Of Truth

Settings store is authoritative.

Only explicit CLI flags override it.

Required cleanup:

- Centralize default preset selection once: `is_default` / `isDefault`, then name/id `Default`, then lone preset only if we intentionally keep that behavior.
- Make `llm agent`, `llm info`, image CLI defaults, compact context, and tool defaults call the same resolver.
- Remove duplicated fallback logic from command helpers.
- Ensure agent path tools use the selected preset snapshot, not top-level global `chat`, when a preset was selected.
- Ensure `providers[*].default_model` is never used as runtime model selection.

### 3. Local Model Discovery

Add a shared model discovery service for local/built-in models.

Search locations:

- `config_dir/models`
- `dist/models` for development and packaged defaults
- optional user-added model directories

Model manifests should allow:

- friendly id
- display name
- runtime: `onnx`, `llama.cpp`, `whisper.cpp`, etc.
- path(s): model, mmproj, tokenizer, labels, yaml
- compatible preset slot(s): text, planner, image, vision, video, stt, tts
- parameter schema
- default parameter values

Settings UI should list these models alongside hosted catalogs for the existing preset slots.

### 4. Model Parameter Schemas

Generalize Replicate-style schemas.

Surfaces that must consume the same schema:

- settings app: configure default values
- custom commands: expose fields in command editor and generated forms
- XBlox: block params generated from schema
- CLI: `--param key=value` or generated command options where practical
- chat tools: validate and merge tool arguments

The schema system should not care whether the model is hosted or local.

Examples:

- Replicate video/image model input schema
- ONNX detection: execution provider, input size, task, labels, confidence threshold
- llama.cpp VLM: model, mmproj, context, GPU layers, prompt template
- whisper.cpp: model size/id/path, language, translation flag, VAD/silence defaults

### 5. Workflow Integration

Treat chat presets as workflow-ready profiles.

Near-term workflow mapping:

- workflow chooses a preset id
- preset provides router/model selections, media model selections, tools, skills
- workflow step can override model parameters explicitly

Do not create a separate workflow model-selection config. Workflows should reference presets and then override only what they need.

## Invariants

- Chat presets stay the main user-facing model/profile selector.
- Router/model selection remains flat and readable.
- One preset can be default for chat sessions.
- Settings store is the source of truth.
- CLI overrides are explicit and local to that command invocation.
- No new hidden fallback policy.
- Provider rows are credentials/endpoints, not model profiles.
- Local model metadata augments selectable models; it does not replace preset router/model fields.
- Model parameter schemas are shared across settings, commands, XBlox, CLI, and tools.
