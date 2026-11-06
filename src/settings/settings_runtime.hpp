#pragma once

#include "settings/settings_types.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace media::runtime_settings {

using ProviderEntry = media::settings_types::ProviderEntry;
using ProviderMap = media::settings_types::ProviderMap;
using ChatProviderSettings = media::settings_types::ChatProviderSettings;
using AudioVideoDeviceSettings = media::settings_types::AudioVideoDeviceSettings;
using VoiceCommandSettings = media::settings_types::VoiceCommandSettings;
using DeviceAbsentPolicy = media::settings_types::DeviceAbsentPolicy;

struct BookmarkItem {
    std::string kind;
    std::string node_kind;
    std::string path;
    std::string label;
    bool searchable = true;
    bool share = false;
};

struct VisitedFileEntry {
    std::string path;
    std::string visited_at;
    std::string workbench;
};

struct GlobalToolSettings {
    std::vector<std::string> disabled_path_tools;
    bool mcp_tools_enabled = true;
    std::vector<std::string> disabled_mcp_servers;
    /// Per-tool MCP disable list — OpenAI function names, e.g. "mcp_server__tool_name".
    /// When set on a preset, overrides the turn's disabled_mcp_tools for that preset.
    std::vector<std::string> disabled_mcp_tools;
};

struct AgentSkillsSettings {
    bool enabled = true;
    bool roaming_enabled = true;
    bool workspace_enabled = true;
    std::vector<std::string> pinned;
    std::vector<std::string> disabled;
};

/// Hybrid memory recall profile + inject richness (custom.agent_memory).
struct AgentMemorySettings {
    /// off | lexical | hybrid | shadow
    std::string recall_profile = "hybrid";
    /// concise | balanced | rich
    std::string richness = "balanced";
    /// Dense latency budget in ms (0 = disabled / never mark over-budget).
    std::int64_t dense_budget_ms = 150;
};

struct ChatProviderPreset {
    std::string id;
    std::string name;
    ChatProviderSettings chat;
    bool has_tools = false;
    GlobalToolSettings tools;
    bool has_skills = false;
    AgentSkillsSettings skills;
    /// When true, this preset is selected by `pm-image-cli llm agent` when no `--preset` flag is
    /// passed. At most one preset in the saved list should have `is_default == true`; the settings
    /// UI and `save_chat_provider_preset()` enforce that invariant on write.
    bool is_default = false;
    /// Agent backend: `native` (default) | `claude-code` | `codex`.
    /// Stored on each `custom.settings_chat_presets[]` entry; exposed via
    /// `settingsChatPresetsGet` / `settingsChatPresetsSave`.
    std::string runner = "native";
    /// Expose the embedded Tanit MCP server to external runners.
    /// Missing values in older presets default to enabled.
    bool add_tanit_mcp_server = true;
    /// Read `Agent.md` / `AGENTS.md` from the current folder and inject it.
    /// Missing values default to enabled.
    bool load_agent_md = true;
    /// Consent surface for this preset. Empty = default cards / auto.
    /// `yolo` / `auto-allow` = allow every Ask with a session grant
    /// (same as CLI `--consent-ui yolo`). `auto-deny` = deny every Ask.
    std::string consent_ui;
    /// Android chat source for this preset. Empty or `phone` uses the phone.
    /// `lan` uses the paired Tanit LAN server. Desktop leaves it empty.
    std::string connection;
};

bool load_chat_provider(ChatProviderSettings& out, std::string& err);
bool save_chat_provider(const ChatProviderSettings& in, std::string& err);
bool load_chat_provider_presets(std::vector<ChatProviderPreset>& out, std::string& err);
bool find_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out, std::string& err);
bool resolve_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out, std::string& err);
bool save_chat_provider_preset(ChatProviderPreset preset, bool& changed, std::string& err);
/// Active preset id in `custom.selected_chat_preset_id` (Android + portable).
bool load_selected_chat_preset_id(std::string& out, std::string& err);
bool save_selected_chat_preset_id(const std::string& id, std::string& err);
/// Resolve preset → write `settings.json["chat"]` + selected id (survives APK updates in profile).
bool apply_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out, std::string& err);
bool load_providers(ProviderMap& out, std::string& err);
bool load_command_json_utf8(std::string& out_json, std::string& err);
bool save_command_json_utf8(const std::string& utf8_json, std::string& err);
/// Serialised load → mutate → atomic save of the command document (see
/// media::settings::update_command_json_utf8). Use this for any read-modify-write.
bool update_command_json_utf8(const std::function<bool(std::string& utf8_json, std::string& err)>& mutate,
                              std::string& err);
void set_command_json_path_override(const std::string& path);
/** Effective commands document: `--commands` override, else settings command path. */
std::filesystem::path effective_command_document_path();

/** File whose parent directory should be watched for command-document saves
 *  (secure-storage `.doc.meta` when FEATURE_SECURE_STORAGE, else commands.json). */
std::filesystem::path effective_command_watch_path();

/// Apply an explicit `--config-dir` or, when empty, auto-select install `../roaming` when the user
/// roaming profile has no settings yet.
void apply_cli_config_dir_override(const std::string& explicit_config_dir);

/// Per-process default directory for logs and run artifacts.
/// Shape: <config_dir>/sessions/session-MM-DD-HH-MM-SS.
/// The path is created on first use and remains stable for the process.
std::filesystem::path default_logging_dir();
void set_default_logging_dir_override(const std::filesystem::path& dir);

/// Scheduler runtime files under <config_dir>/run-ipc/scheduler/.
/// No-arg overloads use @ref media::settings::get_config_dir.
std::filesystem::path scheduler_dir();
std::filesystem::path scheduler_dir(const std::filesystem::path& config_dir);
std::filesystem::path scheduler_state_path();
std::filesystem::path scheduler_state_path(const std::filesystem::path& config_dir);
std::filesystem::path scheduler_leader_lock_path();
std::filesystem::path scheduler_leader_lock_path(const std::filesystem::path& config_dir);
std::filesystem::path scheduler_claim_path();
std::filesystem::path scheduler_claim_path(const std::filesystem::path& config_dir);
std::filesystem::path scheduler_command_lease_path(std::string_view command_id);
std::filesystem::path scheduler_command_lease_path(const std::filesystem::path& config_dir,
                                                   std::string_view command_id);

/// Admin-forced or profile temp root (@ref media::settings::get_temp_dir).
std::filesystem::path effective_temp_dir();

/// True when the user passed an explicit global @c --cwd on the command line (not the default @c ".").
void set_cli_cwd_explicit(bool explicit_cwd);
bool cli_cwd_explicit();

/// Base directory for implicit tool-generated outputs (image_create, prompt-only video, …).
/// Uses process cwd only when @ref cli_cwd_explicit; otherwise @ref effective_temp_dir.
std::filesystem::path implicit_tool_output_base();

/// Fill API key / base URL from `providers[provider]`. Provider/model selection must already be
/// explicit from chat settings or command/tool overrides; provider rows are credential rows only.
void merge_provider_credentials(const std::string& provider,
                                bool dry_run,
                                std::string& api_key,
                                std::string& base_url);

/// Write `api_key` into `providers["tanit"]["api_key"]` in settings.json (and clear it when
/// `api_key` is empty). No-op on platforms where settings save is not implemented. Never fatal —
/// Option B (zitadel-oauth.json fallback in merge_provider_credentials) remains the authoritative
/// source; this only keeps ProviderDlg in sync.
void update_tanit_api_key(const std::string& api_key, std::string& err);

/// Append one published CMS item to settings.json["custom"]["cms"]["history"].
bool append_cms_history_entry(const nlohmann::json& entry, std::string& err, size_t max_entries = 200);

bool load_global_tool_settings(GlobalToolSettings& out, std::string& err);
bool save_global_tool_settings(const GlobalToolSettings& in, std::string& err);
bool load_agent_skills_settings(AgentSkillsSettings& out, std::string& err);
bool save_agent_skills_settings(const AgentSkillsSettings& in, std::string& err);
bool load_agent_memory_settings(AgentMemorySettings& out, std::string& err);
bool save_agent_memory_settings(const AgentMemorySettings& in, std::string& err);

/// Load / save the user's preferred audio + video device overrides.
/// Stored under settings.json["custom"]["audio_video_devices"].
/// Empty string device fields mean "use the OS/system default".
bool load_audio_video_device_settings(AudioVideoDeviceSettings& out, std::string& err);
bool save_audio_video_device_settings(const AudioVideoDeviceSettings& in, std::string& err);
bool load_voice_command_settings(VoiceCommandSettings& out, std::string& err);
bool save_voice_command_settings(const VoiceCommandSettings& in, std::string& err);

/// Global workbench preference: play finish/error/selected notification sounds.
/// Stored under settings.json["workbench"]["sound_notifications_enabled"] (default false).
bool load_sound_notifications_enabled(bool& out, std::string& err);
bool save_sound_notifications_enabled(bool enabled, std::string& err);

bool load_bookmarks(std::vector<BookmarkItem>& out, std::string& err);
bool save_bookmarks(const std::vector<BookmarkItem>& in, std::string& err);
bool load_visited_files(std::vector<VisitedFileEntry>& out, std::string& err);
bool save_visited_files(const std::vector<VisitedFileEntry>& in, std::string& err);
bool load_command_palette_recent(std::vector<std::string>& out, std::string& err);
bool save_command_palette_recent(const std::vector<std::string>& ids, std::string& err);
/// Move @p commandId to the front of the palette MRU list (cap @p max_entries).
bool touch_command_palette_recent(const std::string& commandId,
                                  std::string& err,
                                  std::size_t max_entries = 5);

/// Load persisted xblox artifact MRU (`settings.json["xblox_artifacts"]`).
bool load_xblox_artifacts(nlohmann::json& out, std::string& err);

/// Prepend harvested run rows; dedupe by path (case-insensitive), cap @p max_entries.
bool append_xblox_artifact_entries(const nlohmann::json& entries,
                                   std::string& err,
                                   std::size_t max_entries = 30);

/// Resolve the effective capture device name to open:
///   1. If `cli_override` is non-empty → use it (CLI flag wins).
///   2. Else if `settings_device` is non-empty → use it (user preference).
///   3. Else → return "" (caller opens the system default).
/// When `absent_policy == fail` and the resolved name is non-empty but the
/// device is not found by the subsystem, callers should propagate the error
/// instead of silently falling back to the default.
std::string resolve_audio_input_device(const std::string& cli_override,
                                       const AudioVideoDeviceSettings& avs);
std::string resolve_audio_output_device(const std::string& cli_override,
                                        const AudioVideoDeviceSettings& avs);
std::string resolve_video_capture_device(const std::string& cli_override,
                                         const AudioVideoDeviceSettings& avs);

struct ChatLaunchOverrides {
    bool        has_api_mode = false;
    std::string api_mode;
    bool        has_system_prompt = false;
    bool        system_prompt_is_null = false;
    std::string system_prompt;
    bool        no_tools = false;
    bool        no_mcp_tools = false;
    bool        no_skills = false;
    /// UI launch `--consent-ui` (empty | auto-allow | yolo | auto-deny | …).
    std::string consent_ui;
};

void set_chat_launch_overrides(const ChatLaunchOverrides& overrides);
ChatLaunchOverrides chat_launch_overrides();

/// Native Coin/OCCT 3D viewer (`FEATURE_3D_NATIVE_VIEWER`).
/// Off when the feature is not compiled. Otherwise on unless
/// settings.json appearance.use_native_3d_viewer is false.
bool native_3d_viewer_enabled();

/// Global settings win: merges persistent tool policy from settings.json into per-turn values.
void apply_global_tool_policy_to_values(std::vector<std::string>& disabled_path_tools,
                                        bool& mcp_tools_enabled,
                                        std::vector<std::string>& disabled_mcp_servers,
                                        std::string& err);

} // namespace media::runtime_settings
