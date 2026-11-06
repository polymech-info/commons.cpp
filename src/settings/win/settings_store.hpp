#pragma once

#include "win/LayoutStore.hpp"
#include "export/polymech_export.h"
#include "settings/settings_portable.hpp"

#include <Windows.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace media {
namespace cmd_ipc {
struct InstanceDescriptor;
}
}

namespace media::settings {

using WindowLayout = media::layout::WindowLayout;
using WorkbenchWindowDefaults = media::layout::WorkbenchWindowDefaults;

/** %APPDATA%\\<vendor>\\<app-id> (branded default; directory not created). */
std::filesystem::path default_branded_config_dir();

/** HKCU @c Software\\<vendor>\\<app-id>\\ConfigDirectory override, or empty to use @ref default_branded_config_dir. */
std::filesystem::path read_config_dir_registry_value();

/**
 * Persist @p dir to HKCU (empty clears). Built-in command variables such as
 * @c ${KNOWNFOLDER:Roaming_App_Data}, @c ${ENV:APPDATA}, and branding variables
 * are expanded before validation and persistence. Self-references are rejected.
 * Applies the resolved absolute path to the current process when non-empty.
 */
bool save_config_dir_registry_value(const std::filesystem::path& dir, std::string& err);

/** @c "cli" | @c "bundled" | @c "registry" | @c "default" — how @ref get_config_dir resolved this process. */
std::string config_dir_source_u8();

/** True when UI must not edit config dir (CLI @c --config-dir or bundled roaming bootstrap). */
bool config_dir_settings_locked();

/** %APPDATA%\\<vendor>\\<app-id> (created if missing). */
POLYMECH_API std::filesystem::path get_config_dir();

/** Default local model cache: @ref get_config_dir() / "models" (directory created if missing). */
POLYMECH_API std::filesystem::path get_models_dir();

/** App-scoped scratch directory: @ref get_config_dir() / "temp" (directory created if missing). */
std::filesystem::path get_temp_dir();

/** App log directory: @ref get_config_dir() / "logs" (directory created if missing). */
std::filesystem::path get_logs_dir();

/**
 * First existing shipped model root: @c exe/shared/models (Store), @c exe/models,
 * then @c exe/../models (desktop). Empty when none exist; never created.
 * Probe together with @ref get_models_dir() when resolving embedding GGUF files.
 * @ref get_models_dir remains the writable extra-model cache under the profile.
 */
std::filesystem::path get_embedding_models_dir();

/** Current-user Desktop (FOLDERID_Desktop), or empty if unknown. */
std::filesystem::path get_user_desktop_dir();

/** Override the process profile/config root (settings, caches, MCP, skills, web state). */
void set_config_dir_override(const std::filesystem::path& dir);

/**
 * When no `--config-dir` / read override is active and the user roaming profile has no settings yet,
 * use the install-bundled `../roaming` directory (see @ref media::app::exe_bundled_roaming_directory).
 */
void maybe_auto_set_config_dir_from_exe_roaming();

/**
 * Encrypted settings file: get_config_dir() / "settings.json" (binary PME1 blob or legacy UTF-8 JSON).
 * When the user roaming profile is empty and install `../roaming` has settings, @ref get_config_dir
 * auto-selects that bundled directory (same effect as `--config-dir`).
 */
std::filesystem::path get_settings_json_path();

/**
 * Legacy/plaintext import-export path for the user-authored ribbon/app command file.
 * The active command config is stored as the secure document pm://config/commands.json.
 */
std::filesystem::path get_command_json_path();

/**
 * Global shortcut daemon config: get_config_dir() / "daemon.json".
 */
std::filesystem::path get_daemon_json_path();

/** Path whose parent directory should be watched for command-document changes. */
std::filesystem::path command_cache_watch_path();

/**
 * Path @ref load_settings_utf8 / subtree saves use: @c --settings override, cwd shadow,
 * secure profile meta (@c FEATURE_SECURE_STORAGE), or roaming @c settings.json.
 */
std::filesystem::path get_settings_effective_read_path();

/** True after @ref set_settings_read_path_override (e.g. @c pm-image --settings=…). */
bool has_settings_read_path_override();

/**
 * Use @p absolute_path as the only source for @ref load_settings_utf8 in this process (read-through).
 * Does not copy into the profile store. Cleared on process exit.
 */
void set_settings_read_path_override(const std::filesystem::path& absolute_path);

/** Remove a prior @ref set_settings_read_path_override (tests / rare tooling). */
void clear_settings_read_path_override();

/**
 * Append one UTF-8 line to @ref get_logs_dir() / @c k_iexecute_log_basename (same file as the IExecute DLL).
 * Prefixes wall time and `[pm-image]` so Explorer shell and the main EXE can be correlated.
 */
void append_explorer_shell_correlation_log_utf8(const std::string& line);

/**
 * Load UTF-8 JSON string from @ref get_settings_effective_read_path (PME1 or plaintext JSON).
 * If no override is active and the profile file is missing, first imports a `settings.json` next to
 * tanit.exe into the profile store. Supports:
 * - libsodium secretbox file (magic PME1 + nonce + ciphertext)
 * - legacy plaintext JSON (trimmed first char '{')
 */
bool load_settings_utf8(std::string& out_json, std::string& err_out);

using SettingsRootSnapshot = std::shared_ptr<const nlohmann::json>;

/**
 * Load the immutable parsed settings root.
 * The document is read and parsed lazily, then shared by all accessors until the
 * effective settings path or file mtime changes. Persist operations replace the snapshot.
 */
bool load_settings_root(SettingsRootSnapshot& out_root, std::string& err_out);

/**
 * Load UTF-8 commands JSON from the secure command-config document.
 * Missing document is success with an empty string. Plain files are import/export
 * artifacts only; use the secure-storage import path to make them active.
 */
bool load_command_json_utf8(std::string& out_json, std::string& err_out);

/**
 * Save UTF-8 commands JSON as the encrypted, signed secure command-config document.
 */
bool save_command_json_utf8(const std::string& utf8_json, std::string& err_out);

/**
 * Serialised load → mutate → save of the command document. `mutate` receives the
 * current UTF-8 text (empty when no document exists) and replaces it in place;
 * returning false aborts without touching storage.
 */
bool update_command_json_utf8(const std::function<bool(std::string& utf8_json, std::string& err)>& mutate,
                              std::string& err_out);
/// Mutex guarding read-modify-write cycles on the command document.
std::mutex& command_document_mutex();

/// Optional: on cache *miss* only, with a short reason (see `SettingsLoadLabelScope`).
void set_settings_load_tracing(void (*fn)(const char* reason));
void clear_settings_load_tracing();

/// Optional: invoked when settings persist fails (secure storage put/sign, JSON parse abort, etc.).
/// @p context is a short label (e.g. @c "save_subtree/custom", @c "merge_subtree_object/ui").
void set_settings_persist_observer(void (*fn)(const char* context, const char* detail));
void clear_settings_persist_observer();

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
/** Claim the settings-owner mutex or connect to the live owner. Called from cmd_ipc server start. */
void settings_ipc_on_server_start(::media::cmd_ipc::InstanceDescriptor& desc);
/** Flush + release ownership. Called from cmd_ipc server stop. */
void settings_ipc_on_server_stop();
/** Built-in cmd_ipc settings_* verbs. Runs on the accept thread: parse/apply in memory only. */
nlohmann::json settings_ipc_handle(const nlohmann::json& req);
/** Test/diagnostics snapshot: owner, pid, epoch, revision, pending, persistSeq. */
nlohmann::json settings_ipc_status_json();
#endif

/// RAII: next nested `load_settings_utf8` cache miss is attributed to @p reason in the trace.
class SettingsLoadLabelScope {
public:
    explicit SettingsLoadLabelScope(const char* reason);
    ~SettingsLoadLabelScope();
    SettingsLoadLabelScope(const SettingsLoadLabelScope&)            = delete;
    SettingsLoadLabelScope& operator=(const SettingsLoadLabelScope&) = delete;

private:
    bool pushed_ = false;
};

/**
 * Save UTF-8 JSON (always written as encrypted PME1 blob; 32-byte key in .settings-key.dat protected via DPAPI).
 */
bool save_settings_utf8(const std::string& utf8_json, std::string& err_out);

/**
 * Export all settings to a file. If @p encrypted is true, writes the same PME1 binary format as settings.json
 * (portable only to machines that can read the same DPAPI-protected key file — typically same Windows user profile).
 * If false, writes UTF-8 JSON (contains API keys — handle carefully).
 * Merges missing @c workbench.main.chrome boolean keys (@c show_menu, @c show_status_bar, @c show_ribbon_strip) and
 * missing @c workbench.main.window_defaults @c width / @c height (1280×860) so the export documents preset sizing;
 * does not change the on-disk app settings store.
 */
bool export_settings_file(const std::filesystem::path& path, bool encrypted, std::string& err_out);

/**
 * Replace the local profile encryption key, rewrite every encrypted user-local
 * document that still decrypts (a digest mismatch still counts), then load
 * each one back and require the stored digest to match. The previous key is
 * restored when a rewrite or the check fails.
 */
bool reset_profile_encryption_key(int& rewritten, std::string& err_out);

/**
 * Import settings from a file (PME1 blob or plaintext UTF-8 JSON) and persist to the live settings store.
 */
bool import_settings_file(const std::filesystem::path& path, std::string& err_out);

// ---------------------------------------------------------------------------
// Extensible settings interface (API keys, custom JSON, history, …)
// ---------------------------------------------------------------------------
// The root document is `settings.json` (encrypted PME1).  Top-level keys
// already used by this app include: `providers`, `window`,
// `appearance`, `chat`, `explorer_presets`, `chat_web`.  For app-specific or UI state that does not warrant a
// dedicated struct, use the reserved subtrees in @ref SettingsSubtreeKeys and
// @c load_subtree / @c save_subtree (or @c merge_subtree_object for partial
// updates to an object).  @c load_history_data / @c load_custom_data are
// thin aliases with stable key names.  @ref SettingsApiKeys groups API key
// read/write for discoverability; it forwards to the functions below.
// ---------------------------------------------------------------------------

/** String literals for `settings.json` top-level keys reserved for extensions. */
struct SettingsSubtreeKeys {
    static constexpr const char* custom  = "custom";
    static constexpr const char* history = "history";
    /**
     * Windows Explorer context-menu presets (transform / resize / meta / future ops).
     * Authoritative copy lives only in the encrypted store — `register_explorer` and any
     * `pm-image … --preset <id>` helper read via @ref load_explorer_presets.
     */
    static constexpr const char* explorer_presets = "explorer_presets";
    /**
     * User bookmarks across surfaces (FileTree, viewers, future nodes), schema:
     * `{ "version": 1, "items": [ { "kind", "node_kind"?, "path", "label"?, "searchable"?, "share"? } ] }`
     * `searchable` defaults to true. Folder rows with it off stay in the places menu
     * and are left out of chat/search roots. `share` defaults to false. A folder
     * with it on is a named mount on `vfs://desktop`.
     */
    static constexpr const char* bookmarks = "bookmarks";
    /**
     * Recently viewed files from the centre viewer navigation pipeline.
     * Schema: `{ "version": 1, "items": [ { "path", "visited_at", "workbench" } ] }`
     */
    static constexpr const char* visited_files = "visited_files";
    /**
     * Centre in-app browser navigation history (newest first, max 1000).
     * Schema: `{ "version": 1, "items": [ { "url", "title"?, "visited_at" } ] }`
     */
    static constexpr const char* browser_history = "browser_history";
    /**
     * Command palette MRU (most recently executed command ids, newest first).
     * Schema: `{ "version": 1, "items": [ "togglechat", "custom.command-…", … ] }`
     */
    static constexpr const char* command_palette_recent = "command_palette_recent";
    /**
     * MRU of file paths produced by xblox runs (CLI or GUI-hosted).
     * Schema: `{ "version": 1, "items": [ { "path", "pathKind", "block", "src", "ts", … } ] }`
     */
    static constexpr const char* xblox_artifacts = "xblox_artifacts";
    /** WebView2 chat UI: prompt history, quick actions, panel toggles, active_session_id (transcripts live in secure session docs). */
    static constexpr const char* chat_web = "chat_web";
    /**
     * Local tool-call security gateway state (docs/security/design.md): active profile, policy
     * version, workspace trust, seededDefaultGrantIds (ids of compiled default grants already
     * offered — so a user revoke is not re-inserted), and other non-grant settings.
     */
    static constexpr const char* security = "security";
    /**
     * Persisted capability grants for the security gateway (scoped CapabilityGrant records).
     * Phase-1 store: plain JSON array under this key in the encrypted settings.json (later moves
     * to a dedicated SQLite grants.db, see FEATURE_SECURITY_PERMISSION_STORE).
     */
    static constexpr const char* permissions = "permissions";
    /**
     * Native SciTE/Scintilla editor prefs (`FEATURE_NATIVE_TEXT_EDITOR`).
     * Schema: `{ "font_face", "font_size_pt", "magnification", "wrap" }`.
     * Feature toggle stays on `appearance.use_native_editor`.
     */
    static constexpr const char* scite = "scite";
    /**
     * Copy / move / delete filter profile reused by the file-panel dialogs.
     * Schema: `{ respect_ignores, gitignore, npmignore, dockerignore, dotignore,
     * rules: [ { enabled, include, pattern } ] }`.
     */
    static constexpr const char* transfer_filters = "transfer_filters";
    /**
     * Named include/exclude presets for the file-panel copy dialog.
     * Schema: `{ active, items: [ { name, respect_ignores, gitignore, npmignore,
     * dockerignore, dotignore, rules: [ { enabled, include, pattern } ] } ] }`.
     */
    static constexpr const char* transfer_filter_presets = "transfer_filter_presets";
    /**
     * Copy / move / delete options reused by the file-panel dialogs.
     * Schema: `{ wait_for_others, skip_errors, limit_speed, speed_mb_s,
     * preserve_attributes, preserve_times, preserve_archive_encrypted }`.
     */
    static constexpr const char* transfer_options = "transfer_options";
};

/**
 * Load `settings.json["chat_web"]` (object or null). Empty / missing returns true with @p out = {}.
 * May include `sessions` (array of full session objects) written by the Win32 WebView host.
 */
bool load_chat_web(nlohmann::json& out, std::string& err);

/**
 * Replace `settings.json["chat_web"]` with @p doc; other top-level keys preserved.
 * The WebView host merges `sessions` when the UI posts `chatWebState` without that key.
 */
bool save_chat_web(const nlohmann::json& doc, std::string& err);

/**
 * One user-defined shell / Explorer action. `op` selects the dispatcher branch
 * (e.g. `transform`, `resize`, `meta`); `args` holds op-specific options (see product docs).
 */
struct ExplorerPreset {
    std::string     id;    ///< Stable id for registry / CLI (ASCII recommended).
    std::string     label; ///< Shown in Explorer (MUIVerb).
    std::string     op;    ///< Operation id (e.g. transform, resize, meta).
    nlohmann::json  args = nlohmann::json::object();
};

/**
 * One user bookmark entry. `kind` reserves cross-surface bookmark families:
 * - `node` + `node_kind` `folder`|`vfs`|`mtp`|`ssh`|`ftp` — FileTree folder bookmarks
 * - `url` — centre browser URL bookmarks (`path` = absolute URL)
 */
struct BookmarkItem {
    std::string kind;      ///< Entry discriminator (`node` or `url`).
    std::string node_kind; ///< For `kind=="node"`: folder | vfs | mtp | ssh | ftp.
    std::string path;      ///< UTF-8 filesystem path or remote URI.
    std::string label;     ///< Optional display label override.
    /// Folder bookmarks included in chat/search roots. Missing JSON means on.
    bool searchable = true;
    /// Local folder served as `vfs://desktop/<name>`. Missing JSON means off.
    bool share = false;
};

/** One visited-viewer file entry (deduped by path in memory). */
struct VisitedFileEntry {
    std::string path;       ///< UTF-8 filesystem path (navigation).
    std::string visited_at; ///< ISO8601 UTC timestamp.
    std::string workbench;  ///< "main" | "chat" | "viewer" (or custom slot id).
    std::string stored;     ///< Portable `${…}` expression, filled when the file is visited.
};

/** One centre-browser history row (deduped by url, newest first, cap 1000). */
struct BrowserHistoryEntry {
    std::string url;        ///< UTF-8 absolute URL.
    std::string title;      ///< Optional page title when known.
    std::string visited_at; ///< ISO8601 UTC timestamp.
};

inline constexpr size_t kBrowserHistoryMaxItems = 1000;

/**
 * Load `settings.json[explorer_presets]`. Document shape:
 *   `{ "version": 1, "items": [ { "id", "label", "op", "args"?: {…} } ] }`
 * Missing or invalid document yields an empty @p out and success (first run).
 */
bool load_explorer_presets(std::vector<ExplorerPreset>& out, std::string& err);

/**
 * Replace the `explorer_presets` subtree; all other `settings.json` keys preserved.
 */
bool save_explorer_presets(const std::vector<ExplorerPreset>& items, std::string& err);

/**
 * Load `settings.json[bookmarks]` (`version:1`, `items[]`). Missing or invalid documents
 * return success with an empty vector.
 */
bool load_bookmarks(std::vector<BookmarkItem>& out, std::string& err);

/**
 * Replace the full bookmarks subtree while preserving all other settings keys.
 */
bool save_bookmarks(const std::vector<BookmarkItem>& items, std::string& err);

inline constexpr std::size_t kVisitedFilesMax = 50;

/** Load `settings.json[visited_files]` (`version:1`, `items[]`). */
bool load_visited_files(std::vector<VisitedFileEntry>& out, std::string& err);

/** Replace the full `visited_files` subtree while preserving all other settings keys. */
bool save_visited_files(const std::vector<VisitedFileEntry>& items, std::string& err);

/** Load `settings.json[browser_history]` (`version:1`, `items[]`). */
bool load_browser_history(std::vector<BrowserHistoryEntry>& out, std::string& err);

/** Replace the full `browser_history` subtree while preserving all other settings keys. */
bool save_browser_history(const std::vector<BrowserHistoryEntry>& items, std::string& err);

/** Load `settings.json[command_palette_recent]` (`version:1`, `items[]` of command ids). */
bool load_command_palette_recent(std::vector<std::string>& out, std::string& err);

/** Replace the full `command_palette_recent` subtree while preserving all other settings keys. */
bool save_command_palette_recent(const std::vector<std::string>& ids, std::string& err);

/** Newest-first MRU of xblox artifact paths kept in `settings.json`. */
inline constexpr std::size_t k_xblox_artifacts_max_entries = 30;

/** Load `settings.json["xblox_artifacts"]` (`version:1`, `items[]`). */
bool load_xblox_artifacts(nlohmann::json& out, std::string& err);

/** Replace the full `xblox_artifacts` subtree while preserving all other settings keys. */
bool save_xblox_artifacts(const nlohmann::json& doc, std::string& err);

/** Prepend harvested run rows; dedupe by path (case-insensitive), cap @p max_entries. */
bool append_xblox_artifact_entries(const nlohmann::json& entries,
                                   std::string& err,
                                   std::size_t max_entries = k_xblox_artifacts_max_entries);

/**
 * Read one top-level value from `settings.json`.
 * If @p key is missing, @p out is JSON `null` (and the function still returns true).
 */
POLYMECH_API bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err);

/**
 * Replace the top-level @p key and persist.  All other top-level keys are kept.
 */
bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err);

using SettingsRootMutator = std::function<bool(nlohmann::json& root, std::string& err)>;

/** Load settings root, run @p mutator, persist — all under one mutex scope.
 *  Logs every flush (context, thread, changed keys). Restores guarded keys
 *  (`providers`, `bookmarks`, …) when a write would empty or type-corrupt them
 *  unless @p context is an explicit save of that key. */
bool mutate_settings_root(const char* context, const SettingsRootMutator& mutator, std::string& err,
                           const char* touched_key = nullptr);

/** Coalesce mutate_settings_root calls on this thread into one profile commit.
 *  UI thread only. A background settings write during the batch is overwritten. */
void begin_settings_commit_batch(const char* context);
bool end_settings_commit_batch();

/**
 * Shallow-merge @p fields into the JSON object at @p key.
 * If the existing value is not an object, it is replaced by an object built from @p fields.
 * @p fields must be a JSON object.
 */
bool merge_subtree_object(const std::string& key, const nlohmann::json& fields, std::string& err);

bool load_custom_data(nlohmann::json& out, std::string& err);
bool save_custom_data(const nlohmann::json& value, std::string& err);
bool load_history_data(nlohmann::json& out, std::string& err);
bool save_history_data(const nlohmann::json& value, std::string& err);

/// Load `settings.json["agent_variables"]` — a flat object `{ "varId": value }`.
/// Returns an empty object when the key is absent (not an error).
bool load_agent_variables(nlohmann::json& out, std::string& err);

/// Merge `values` into `settings.json["agent_variables"]`.
/// `values` is a flat object `{ "varId": value }` produced by @ref all_variables().
bool save_agent_variables(const nlohmann::json& values, std::string& err);

// ---------------------------------------------------------------------------
// Provider key management (stored under "providers" key in settings.json)
// ---------------------------------------------------------------------------

/** Per-provider configuration stored in settings.json. */
using ProviderEntry = media::settings_types::ProviderEntry;
using ProviderMap = media::settings_types::ProviderMap;

/**
 * Known provider names and their default base URLs.
 * Order matches the UI display order.
 */
struct ProviderDefaults {
    const char* name;
    const char* display_name;
    const char* base_url;
    std::vector<const char*> models;
};

/** Static list of supported providers. */
const ProviderDefaults* known_providers(int* count_out);

/**
 * Load provider entries from settings.json.
 * Missing providers are returned with empty api_key and provider defaults for base_url.
 */
bool load_providers(ProviderMap& out, std::string& err);

/**
 * Save provider entries to settings.json.
 * Non-provider keys in the JSON (e.g. prompt_presets) are preserved.
 * Legacy active_provider key is removed on save (no longer used per design).
 */
bool save_providers(const ProviderMap& providers, std::string& err);

/**
 * Convenience: load the active provider's API key.
 * Returns empty string on failure or if no key is configured.
 */
std::string get_active_api_key(std::string& provider_name_out);

/**
 * Active image provider entry (API key, base_url, default_model) from the same store as @c get_active_api_key.
 * @return false if settings could not be loaded.
 */
bool get_active_image_provider(ProviderEntry& out, std::string& provider_name_out);

/**
 * Google / Gemini API key for image transform, meta, and find (LLM mode).
 * Stored under settings.json["providers"]["google"]["api_key"] (same as AI Provider Settings).
 * Used when IMAGE_TRANSFORM_GOOGLE_API_KEY is unset (e.g. Explorer-launched UI where cwd has no .env).
 */
std::string get_google_provider_api_key();

// ---------------------------------------------------------------------------
// Window placement persistence (settings.json)
// ---------------------------------------------------------------------------
// Dock topology (parent, style, size, floating rect) is stored as
// `workbench.main.win32_dock` (legacy: top-level `win32_dock` still read, then
// removed on next save; migration from HKCU\…\Dock Settings unchanged).
// Window placement + panel flags live in `workbench.main.window` (legacy:
// top-level `window` still read, then removed on save).
// ---------------------------------------------------------------------------

/**
 * True when the stored preference is to skip synchronous `LoadDockContainers` inside
 * `LoadDockLayout` and apply it from the main frame after first show instead.
 * Respects `WindowLayout::defer_dock_containers` (see `load_window_layout`). Default is true
 * before any load; not used in non-UI / non-pm-image builds.
 */
bool defer_dock_container_load();

/**
 * Load window layout from settings.json.
 * @param workbench_slot  Key under `workbench` (e.g. from the active workbench’s @c workbenchSettingsId()).
 *                        Legacy top-level `window` is read only when @p workbench_slot is `main`.
 * On first run / missing data, returns default-initialised struct (err stays empty).
 * `has_placement` is set only when `normal_rect` exists and has a sane non-degenerate size (partial
 * `window` objects no longer imply placement).
 */
bool load_window_layout(WindowLayout& out, std::string& err, const char* workbench_slot = "main");

/**
 * Persist window layout to settings.json, preserving all other keys.
 * Writes `workbench.<workbench_slot>.window` and, when @p workbench_slot is `main`, drops legacy top-level `window`.
 */
bool save_window_layout(const WindowLayout& layout, std::string& err, const char* workbench_slot = "main");

/** Sets `filetree_show_shell_frames` for that workbench’s `window` object. */
bool set_filetree_show_shell_frames(bool show, std::string& err, const char* workbench_slot = "main");

/** Sets `filetree_filter_mask` for that workbench's `window` object (e.g. "*.jpg;*.png"). */
bool set_filetree_filter_mask(const std::string& mask, std::string& err, const char* workbench_slot = "main");

/** Sets `filetree_glob_select_history` (Numpad+ select masks, newest first). */
bool set_filetree_glob_select_history(const std::vector<std::string>& history, std::string& err,
                                      const char* workbench_slot = "main");

/**
 * Optional frame “chrome” under `workbench.<slot>.chrome` (ReBar main menu, Win32++ status bar,
 * own-ribbon strip). Omitted keys: menu off, status/ribbon on. Overrides Win32++ registry frame
 * defaults (see CMainFrame::Create after LoadRegistrySettings).
 */
struct WorkbenchChromeSettings {
    bool show_main_menu   = false;
    bool show_status_bar  = true;
    /// Own-ribbon builds only (`FEATURE_USE_OWN_RIBBON`); ignored when the Windows UIRibbon build is used.
    bool show_ribbon_strip = true;
    /// Own-ribbon only: when true the strip uses small command icons. Toggled at runtime via
    /// the ribbon right-click context menu and persisted
    /// under `workbench.<slot>.chrome.ribbon_small_icons_only`.
    bool ribbon_small_icons_only = false;
    /// Own-ribbon only: global command-caption visibility. Individual icon-only commands remain
    /// icon-only. Persisted under `workbench.<slot>.chrome.ribbon_show_labels`.
    bool ribbon_show_labels = true;
    /// Own-ribbon only: group-name captions under each command cluster. Persisted under
    /// `workbench.<slot>.chrome.ribbon_show_groups`.
    bool ribbon_show_groups = true;
    /// When true, the workbench skips restoring saved panel layout on start and calls ResetLayout
    /// instead, ensuring a clean default state every session.
    bool always_restore = false;
    /// When true, showing a panel grows the frame instead of stealing space from the centre view.
    /// Breakpoint collapse is skipped while this is on. Persisted under
    /// `workbench.<slot>.chrome.auto_grow`. Default on.
    bool auto_grow = true;
};

/**
 * Fills @p out from @c workbench[workbench_slot].chrome. Missing @c workbench, slot, or @c chrome
 * uses slot defaults: menu off; @c main/@c viewer → status/ribbon on; @c chat → menu/status off with own-ribbon on.
 */
bool load_workbench_chrome(WorkbenchChromeSettings& out, std::string& err, const char* workbench_slot = "main");

/// Updates `workbench.<slot>.chrome.ribbon_small_icons_only` while preserving the other chrome
/// keys (`show_menu`, `show_status_bar`, `show_ribbon_strip`). Used by the own-ribbon right-click
/// context menu to persist the user's icon-size preference per workbench.
bool set_workbench_chrome_ribbon_small_icons_only(bool small_only, std::string& err, const char* workbench_slot = "main");
bool set_workbench_chrome_ribbon_show_labels(bool show, std::string& err, const char* workbench_slot = "main");
bool set_workbench_chrome_ribbon_show_groups(bool show, std::string& err, const char* workbench_slot = "main");

/// Updates `workbench.<slot>.chrome.show_ribbon_strip` while preserving the other chrome keys.
/// Driven by both the View → Ribbon menu toggle and the own-ribbon right-click "Hide ribbon"
/// command so both surfaces persist the change for the active workbench.
bool set_workbench_chrome_show_ribbon_strip(bool show, std::string& err, const char* workbench_slot = "main");

/// Updates `workbench.<slot>.chrome.auto_grow` while preserving the other chrome keys.
bool set_workbench_chrome_auto_grow(bool enabled, std::string& err, const char* workbench_slot = "main");

/// Writes the `workbench.<slot>.chrome` keys at once, including ribbon icon, label, and group options.
/// Preserves all other keys in the slot. Used by the Settings WebView workbench panel.
bool save_workbench_chrome(const WorkbenchChromeSettings& chrome, std::string& err, const char* workbench_slot = "main");

/**
 * Per-workbench panel-visibility defaults stored under
 * @c workbench.<slot>.panel_defaults.  These are the values applied when the
 * user chooses Reset Layout; they replace the previously hard-coded panel
 * visibility values in each workbench's @c ResetLayout() implementation.
 *
 * Slot defaults (used when the key is absent in settings.json):
 *   main   → filetree=true,  queue=true,  log=true,  chat=false, centre_view="file_viewer"
 *   chat   → filetree=true,  queue=false, log=false, chat=false, centre_view="chat"
 *            (Preview ribbon toggle moves chat to dock + file preview in centre)
 *   viewer → filetree=false, queue=false, log=false, chat=false, centre_view="file_viewer"
 *
 * centre_view: "file_viewer" | "chat"
 *   Selects the IAppMode (and thus the centre SetView) independently of the
 *   layout slot.  "chat" → CChatAppMode.  Everything else → CMainAppMode or
 *   CViewerAppMode depending on the slot.
 */
struct WorkbenchPanelDefaults {
    bool        filetree    = true;
    bool        queue       = true;
    bool        log         = true;
    bool        chat        = false;
    std::string centre_view;  ///< empty = slot default ("file_viewer" for main/viewer, "chat" for chat slot)
};

/**
 * Fills @p out from @c workbench[workbench_slot].panel_defaults.
 * Missing keys fall back to slot-specific built-in defaults (see struct doc).
 */
bool load_workbench_panel_defaults(WorkbenchPanelDefaults& out, std::string& err, const char* workbench_slot = "main");

/** Writes all panel_defaults keys for @p workbench_slot. */
bool save_workbench_panel_defaults(const WorkbenchPanelDefaults& d, std::string& err, const char* workbench_slot = "main");

/**
 * Returns the effective centre_view string for @p slot.
 * If @p pd.centre_view is non-empty it is returned as-is; otherwise @c "file_viewer".
 */
inline std::string effective_centre_view(const WorkbenchPanelDefaults& pd, const char* slot)
{
    (void)slot;
    if (!pd.centre_view.empty()) return pd.centre_view;
    return "file_viewer";
}

/**
 * Reads @c settings.json @c ["ui"]["workbench"]. @c "main" (default), @c "chat", or @c "viewer". Unknown / missing / invalid → @c "main".
 * If @ref set_ui_workbench_id_cli_override was set (e.g. @c --ui-preset=chat), that value is returned once and takes precedence.
 */
bool load_settings_ui_workbench_id(std::string& out, std::string& err);

/**
 * Disk-only @c ui.workbench (no CLI override, no @c --ui-reset clamp). Use for Settings UI
 * "default workbench" so a one-shot @c --ui-preset cannot masquerade as the saved default.
 */
bool load_persisted_settings_ui_workbench_id(std::string& out, std::string& err);

/**
 * Same resolution as @ref load_settings_ui_workbench_id (CLI override if set, else JSON) but never consumes the
 * CLI one-shot. Use before @c CMainFrame construction (e.g. splash monitor) so @ref load_settings_ui_workbench_id
 * in the frame ctor still sees the override.
 */
bool peek_settings_ui_workbench_id(std::string& out, std::string& err);

/** One-shot: next @ref load_settings_ui_workbench_id returns @p id (@c "main", @c "chat", or @c "viewer") and clears. Pass @c nullptr or @c "" to clear without consuming. */
void set_ui_workbench_id_cli_override(const char* id);

/** Persist @p id (@c "main", @c "chat", or @c "viewer") to @c settings.json @c ["ui"]["workbench"]. */
bool save_settings_ui_workbench_id(const std::string& id, std::string& err);

/**
 * CLI --app: override viewer kind for the next file opened in viewer workbench.
 * Used to force a specific viewer app regardless of file extension (reserved).
 * Pass @c nullptr or @c "" to clear.
 */
void set_ui_viewer_app_cli_override(const char* app);

/**
 * Peek the current viewer app CLI override without consuming it.
 * Returns @c true if an override is set (output in @p out).
 */
bool peek_ui_viewer_app_cli_override(std::string& out) noexcept;

/**
 * When @c true (e.g. @c pm-image --ui-reset): for this process only, ignore persisted workbench UI in
 * settings.json — @ref load_window_layout, @ref load_win32_dock_doc, @ref load_workbench_chrome, and file-backed
 * @c ui.workbench (unless @c --ui-preset is set) use built-in defaults for @c main, @c chat, and @c viewer. Other keys (providers, paths, …) still load from disk.
 */
void set_ui_reset_session(bool active) noexcept;
bool ui_reset_session() noexcept;

/**
 * Per-workbench preset for the main window outer size (pixels) when the @c workbench @c window subtree
 * is **absent** (first run / no saved placement). Used by @ref load_window_layout; centered on the primary
 * work area, clamped to the monitor. JSON path: @c workbench.<id>.window_defaults.
 * If @c width / @c height are missing, zero, or invalid, the apply step is skipped.
 * Typical values: 1280×860.
 */
/**
 * Reads @c workbench[workbench_slot].window_defaults from settings.json.
 * Missing object or non-numeric @c width / @c height leaves @p out with zeros (and returns true, empty @p err).
 */
bool load_workbench_window_defaults(WorkbenchWindowDefaults& out, std::string& err, const char* workbench_slot = "main");

// ---------------------------------------------------------------------------
// Appearance (theme + UI font size) — stored under "appearance" in settings.json
// ---------------------------------------------------------------------------

enum class Theme {
    System = 0,   // follow Windows AppsUseLightTheme registry
    Light  = 1,
    Dark   = 2,
};

/**
 * Visual appearance preferences.  Persisted under settings.json["appearance"]
 * alongside provider keys / window layout / prompt presets.
 */
struct AppearanceSettings {
    Theme theme              = Theme::System;
    /**
     * Settings UI step 0..4 (clamped to [0, 8] on write). Step 2 is
     * "Standard (System size)" and applies the system message font as-is;
     * each step is ±1 pt from that baseline. See `pmui::ui_font_applied_extra_pt`.
     */
    int   font_size_extra_pt = 2;
    /**
     * Display language for Win32 resources (ribbon / fallback menu). One of:
     * `en`, `es`, `de`, `it`, `fr`. Applied via `SetThreadUILanguage` at startup;
     * changing it typically requires a restart to refresh cached ribbon UI.
     */
    std::string display_language = "en";
    /**
     * Prefer the native SciTE/Scintilla editor (FEATURE_NATIVE_TEXT_EDITOR)
     * over the WebView text viewer when both are available. Default on;
     * host routing is still scaffolding.
     */
    bool use_native_editor = true;
    /**
     * Prefer libmpv HWND playback (FEATURE_MPV_PLAYER) over the WebView2
     * `<video>` viewer when the plugin + libmpv-2.dll are available.
     */
    bool use_mpv_player = true;
    /**
     * Prefer the Coin/OCCT HWND viewer (FEATURE_3D_NATIVE_VIEWER) over the
     * WebView 3D viewer when the 3D plugin is available.
     */
    bool use_native_3d_viewer = true;
    /**
     * Native Coin viewer object tree. Default on; the 3D toolbar toggle
     * persists this across files and restarts.
     */
    bool show_3d_object_tree = true;
    /**
     * Native mpv OSC: start playback on open. Same default as viewer-next
     * `pm-viewer-media-autoplay` (localStorage; native cannot read that).
     */
    bool media_autoplay = true;
    /**
     * Native mpv OSC: at EOF open the next folder video. Same default as
     * viewer-next `pm-viewer-media-autoplay-next` (off).
     */
    bool media_autoplay_next = false;
};

/// Load appearance settings (returns defaults on first run).
bool load_appearance(AppearanceSettings& out, std::string& err);

/// Persist appearance settings, preserving every other key in settings.json.
bool save_appearance(const AppearanceSettings& a, std::string& err);

// ---------------------------------------------------------------------------
// Transfer filters — stored under "transfer_filters" in settings.json
// ---------------------------------------------------------------------------

struct TransferFilterRule {
    bool enabled = true;
    bool include = false;
    std::string pattern;
};

struct TransferFilterSettings {
    bool respect_ignores = true;
    bool gitignore = true;
    bool npmignore = false;
    bool dockerignore = false;
    bool dotignore = false;
    /// Skip `.git` / `.svn` / `.hg` (default). Maps to FilterSpec::skip_vcs.
    bool skip_vcs = true;
    std::vector<TransferFilterRule> rules;
};

bool load_transfer_filters(TransferFilterSettings& out, std::string& err);
bool save_transfer_filters(const TransferFilterSettings& filters, std::string& err);

struct TransferFilterPreset {
    std::string name;
    TransferFilterSettings filters;
};

struct TransferFilterPresetLibrary {
    std::string active;
    std::vector<TransferFilterPreset> items;
};

bool load_transfer_filter_presets(TransferFilterPresetLibrary& out, std::string& err);
bool save_transfer_filter_presets(const TransferFilterPresetLibrary& library, std::string& err);

struct TransferOptionSettings {
    bool wait_for_others = false;
    bool skip_errors = false;
    bool limit_speed = false;
    int speed_mb_s = 1;
    bool preserve_attributes = false;
    bool preserve_times = false;
    bool preserve_archive_encrypted = false;
};

bool load_transfer_options(TransferOptionSettings& out, std::string& err);
bool save_transfer_options(const TransferOptionSettings& options, std::string& err);

// ---------------------------------------------------------------------------
// SciTE / native editor — stored under "scite" in settings.json
// ---------------------------------------------------------------------------

/**
 * Native editor (SciTE/Scintilla) preferences. Persisted under
 * settings.json["scite"]. Routing on/off remains `appearance.use_native_editor`.
 */
struct SciteSettings {
    /// Face name passed to SCI_STYLESETFONT (ASCII / UTF-8 for Scintilla).
    std::string font_face = "Consolas";
    /**
     * Base style size in points (SCI_STYLESETSIZE). Default 13 ≈ previous 10pt
     * plus three Ctrl+/- zoom steps. Clamped to [8, 36].
     */
    int font_size_pt = 13;
    /**
     * SciTE `magnification` / SCI_SETZOOM (points relative to style size).
     * Updated when the user zooms in the editor. Clamped to [-10, 20].
     */
    int magnification = 0;
    /// Soft wrap; default off for code (wrap hurts scroll performance).
    bool wrap = false;
};

bool load_scite(SciteSettings& out, std::string& err);
bool save_scite(const SciteSettings& s, std::string& err);
/// Persist only magnification (zoom) without rewriting other scite keys.
bool set_scite_magnification(int magnification, std::string& err);

// ---------------------------------------------------------------------------
// Chat provider — `settings.json["chat"]` (in-app agent)
// ---------------------------------------------------------------------------
// Chat *presets* live under `settings.json["custom"]["settings_chat_presets"]`
// (array). Each preset object shape (settings API: settingsChatPresetsGet/Save):
//
//   {
//     "id": "chat-preset-…",
//     "name": "Default",
//     "runner": "native",          // native | claude-code | codex
//     "add_tanit_mcp_server": true, // external runners; default true when omitted
//     "load_agent_md": true,        // inject Agent.md from the current folder; default true when omitted
//     "is_default": true,          // optional; at most one preset
//     "chat": { … ChatProviderSettings … },
//     "tools": { … GlobalToolSettings … },   // optional
//     "skills": { … AgentSkillsSettings … }  // optional
//   }
//
// `runner` defaults to `native` when absent. Unknown values normalize to `native`
// on read/write via @ref media::settings_schema::normalize_chat_preset_runner.
//
// Three different concerns share the top-level `chat` object; do not conflate them:
//   1) Text (LLM) chat — `router` / `model` (and `timeout_ms`, `max_iterations`) for
//      OpenAI-compatible chat completions (kbot::LLMClient). **API keys are not
//      persisted in `settings.json["chat"]`** — they live under `settings.json["providers"][…]`.
//      `chat.base_url` is allowed for router=`custom` (per preset). Other routers still
//      take their URL from `providers[router]`. At runtime, `resolve_agent_launch` applies
//      the preset URL first, then merges provider credentials for empty fields.
//   2) Image *creation* tools — `image_provider` / `image_model` default which
//      backend (e.g. google, replicate) `image_create`-style tool calls use.
//   2b) Image *recognition* / vision (`image_recognition_provider` / `image_recognition_model`):
//      separate defaults for models used when describing or analyzing images (e.g. vision
//      APIs). Same provider id space as (2). Edited in ChatProviderDlg; persisted here.
//   2c) Video generation (`video_provider` / `video_model`) — defaults for the `create_video`
//      path tool. Same provider id space as (2).
//   3) Replicate (image) — when a row’s provider is "replicate", ChatProviderDlg shows
//      collection + refresh + model (ReplicateSelectorController).
//
// Persisted under settings.json["chat"] beside (but not overlapping) `providers`.
using ChatProviderSettings = media::settings_types::ChatProviderSettings;

/// Load chat-provider settings (returns defaults on first run).
bool load_chat_provider(ChatProviderSettings& out, std::string& err);

/// Persist chat-provider settings, preserving every other key in settings.json.
bool save_chat_provider(const ChatProviderSettings& s, std::string& err);

/**
 * Grouped access to image `providers` and in-app `chat` settings (LLM API keys
 * are under `providers`, not the `chat` object).
 * Thin wrappers for discoverability; see @c load_providers, etc.
 */
struct SettingsApiKeys {
    static std::string image_google() { return get_google_provider_api_key(); }
    static bool image_providers_load(ProviderMap& out, std::string& err) { return media::settings::load_providers(out, err); }
    static bool image_providers_save(const ProviderMap& m, std::string& err) { return media::settings::save_providers(m, err); }
    static bool chat_load(ChatProviderSettings& out, std::string& err) { return media::settings::load_chat_provider(out, err); }
    static bool chat_save(const ChatProviderSettings& s, std::string& err) { return media::settings::save_chat_provider(s, err); }
};

// ---------------------------------------------------------------------------
// Batch sessions — pause / resume / cancel state
// ---------------------------------------------------------------------------
// Stored in a separate sessions.json next to settings.json so large session
// payloads (thousands of paths) never inflate the main settings load/save cycle.
//
// Format: plain UTF-8 JSON array under the top-level "sessions" key.
//   { "sessions": [ { session_id, op, options, items:[...], created_at, updated_at } ] }
//
// Session encryption is not implemented. Loads and saves always use sessions.json.
// Do not route them through the settings profile.
// ---------------------------------------------------------------------------

/// Path: <get_config_dir()> / "sessions.json"
std::filesystem::path get_sessions_json_path();

struct SessionItem {
    std::string path;
    std::string sha256;
    std::string status;  ///< "pending" | "done" | "error"
    std::string error;   ///< Non-empty when status == "error"
};

struct PersistedSession {
    std::string              session_id;
    std::string              op;        ///< "resize"|"compress"|"meta"|"transform"|"find"
    nlohmann::json           options;   ///< Full op-opts blob for apply_*_from_json
    std::vector<SessionItem> items;
    std::string              created_at;
    std::string              updated_at;
};

/// Load all sessions from sessions.json.  Returns empty vector when the file
/// does not exist or is empty.  Errors are reported via @p err.
bool load_sessions(std::vector<PersistedSession>& out, std::string& err);

/// Upsert one session (matched by session_id).
/// Creates sessions.json when absent.  Preserves all other sessions.
bool save_session(const PersistedSession& s, std::string& err);

/// Remove the session with the given id.  No-op when not found.
bool delete_session(const std::string& session_id, std::string& err);

/// Convenience: load_sessions, optionally filter by op name (empty = all).
std::vector<PersistedSession> list_sessions(const std::string& op_filter = "");

} // namespace media::settings
