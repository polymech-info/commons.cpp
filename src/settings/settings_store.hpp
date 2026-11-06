#pragma once

#if defined(_WIN32)
#include "win/settings_store.hpp"
#else

#include "export/polymech_export.h"
#include "settings/settings_types.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace media {
namespace cmd_ipc {
struct InstanceDescriptor;
}
}

namespace media::settings {

using ProviderEntry = media::settings_types::ProviderEntry;
using ProviderMap = media::settings_types::ProviderMap;
using ChatProviderSettings = media::settings_types::ChatProviderSettings;

POLYMECH_API std::filesystem::path get_config_dir();
/** Branded default profile root (portable: XDG-style path). */
std::filesystem::path default_branded_config_dir();
inline std::filesystem::path read_config_dir_registry_value() { return {}; }
inline bool save_config_dir_registry_value(const std::filesystem::path&, std::string&) { return true; }
inline std::string config_dir_source_u8() { return "default"; }
inline bool config_dir_settings_locked() { return false; }
void set_config_dir_override(const std::filesystem::path& dir);
void maybe_auto_set_config_dir_from_exe_roaming();
/** Default local model cache: @ref get_config_dir() / "models". */
POLYMECH_API std::filesystem::path get_models_dir();
/** App-scoped scratch directory: @ref get_config_dir() / "temp". */
std::filesystem::path get_temp_dir();
/** App log directory: @ref get_config_dir() / "logs". */
std::filesystem::path get_logs_dir();
/** First existing shipped model root (`exe/shared/models`, `exe/models`, `exe/../models`). */
std::filesystem::path get_embedding_models_dir();
/** User Desktop directory, or empty if unknown. */
std::filesystem::path get_user_desktop_dir();
std::filesystem::path get_settings_json_path();
// Legacy/plaintext import-export path. Active commands use pm://config/commands.json.
std::filesystem::path get_command_json_path();
/** Daemon host config: get_config_dir() / "daemon.json". */
std::filesystem::path get_daemon_json_path();
/** Path whose parent directory should be watched for command-document changes. */
std::filesystem::path command_cache_watch_path();
std::filesystem::path get_settings_effective_read_path();
bool has_settings_read_path_override();
void set_settings_read_path_override(const std::filesystem::path& absolute_path);
void clear_settings_read_path_override();

bool load_settings_utf8(std::string& out_json, std::string& err_out);
using SettingsRootSnapshot = std::shared_ptr<const nlohmann::json>;
bool load_settings_root(SettingsRootSnapshot& out_root, std::string& err_out);
bool save_settings_utf8(const std::string& utf8_json, std::string& err_out);
bool load_command_json_utf8(std::string& out_json, std::string& err_out);
bool save_command_json_utf8(const std::string& utf8_json, std::string& err_out);
/** Serialised load → mutate → atomic save of the command document. `mutate`
 *  receives the current UTF-8 text (empty when the file does not exist) and
 *  replaces it in place; returning false aborts without touching the file. */
bool update_command_json_utf8(const std::function<bool(std::string& utf8_json, std::string& err)>& mutate,
                              std::string& err_out);
/** Mutex guarding read-modify-write cycles on the command document. */
std::mutex& command_document_mutex();

bool export_settings_file(const std::filesystem::path& path, bool encrypted, std::string& err_out);
bool import_settings_file(const std::filesystem::path& path, std::string& err_out);

struct SettingsSubtreeKeys {
    static constexpr const char* custom = "custom";
    static constexpr const char* history = "history";
    static constexpr const char* explorer_presets = "explorer_presets";
    static constexpr const char* bookmarks = "bookmarks";
    static constexpr const char* visited_files = "visited_files";
    /**
     * Command palette MRU (most recently executed command ids, newest first).
     * Schema: `{ "version": 1, "items": [ "togglechat", "custom.command-…", … ] }`
     */
    static constexpr const char* command_palette_recent = "command_palette_recent";
    static constexpr const char* xblox_artifacts = "xblox_artifacts";
    static constexpr const char* chat_web = "chat_web";
    /** Security gateway state (active profile, policy version) — see src/security/SecurityPersistence.*. */
    static constexpr const char* security = "security";
    /** Persisted capability grants for the security gateway (JSON array). */
    static constexpr const char* permissions = "permissions";
};

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

POLYMECH_API bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err);
using SettingsRootMutator = std::function<bool(nlohmann::json& root, std::string& err)>;
bool mutate_settings_root(const char* context, const SettingsRootMutator& mutator, std::string& err);
bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err);
bool merge_subtree_object(const std::string& key, const nlohmann::json& fields, std::string& err);

bool load_providers(ProviderMap& out, std::string& err);
bool save_providers(const ProviderMap& providers, std::string& err);
bool load_chat_provider(ChatProviderSettings& out, std::string& err);
bool save_chat_provider(const ChatProviderSettings& s, std::string& err);
bool load_bookmarks(std::vector<BookmarkItem>& out, std::string& err);
bool save_bookmarks(const std::vector<BookmarkItem>& items, std::string& err);
bool load_visited_files(std::vector<VisitedFileEntry>& out, std::string& err);
bool save_visited_files(const std::vector<VisitedFileEntry>& items, std::string& err);
bool load_command_palette_recent(std::vector<std::string>& out, std::string& err);
bool save_command_palette_recent(const std::vector<std::string>& ids, std::string& err);
inline constexpr std::size_t k_xblox_artifacts_max_entries = 30;
bool load_xblox_artifacts(nlohmann::json& out, std::string& err);
bool save_xblox_artifacts(const nlohmann::json& doc, std::string& err);
bool append_xblox_artifact_entries(const nlohmann::json& entries,
                                   std::string& err,
                                   std::size_t max_entries = k_xblox_artifacts_max_entries);

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
void settings_ipc_on_server_start(::media::cmd_ipc::InstanceDescriptor& desc);
void settings_ipc_on_server_stop();
nlohmann::json settings_ipc_handle(const nlohmann::json& req);
nlohmann::json settings_ipc_status_json();
#endif

} // namespace media::settings

#endif
