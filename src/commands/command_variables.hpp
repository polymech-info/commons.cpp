#pragma once

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace media::commands {

struct BrowserTabVariable {
    std::string url;
    std::string title;
};

struct VariableContext {
    std::string cwd;
    std::string source_file;
    std::vector<std::string> selection_paths;

    // Taskbar / launcher app-chip target. Decimal HWND as text so it survives
    // argv / xblox `${CURRENT_HWND}` and `screen:0:hwnd=${CURRENT_HWND}`.
    std::string current_hwnd;
    std::string current_pid;
    std::string current_wintitle;
    std::string current_process;

    // ── Installer / bundle context ─────────────────────────────────────────
    // When set, populates ${INSTALL_ROOT} and ${INSTALL_BIN} in the variable
    // map.  Set this from the --root CLI flag before calling make_variable_map
    // so that bundle manifests and seed-data paths resolve correctly.
    std::string install_root;

    // Optional JSON file of variable overrides (installer --config).  Parsed and
    // merged after make_variable_map via apply_variable_overrides().
    std::string variable_config_path;

    // Last voice utterance (CLI `--VOICE_*` / explicit caller). Empty fields fall
    // back to set_last_voice_utterance() then inherited PM_VOICE_* env.
    std::string voice_wake;
    std::string voice_command;
    std::string voice_full;

    // Centre browser tabs (real pages only) and the newest history URL.
    // Empty fields stay literal `${CURRENT_URL}` / `${BROWSER_TAB_N}`.
    std::string current_url;
    std::string current_url_title;
    std::string last_url;
    std::vector<BrowserTabVariable> browser_tabs;
};

using VariableMap = std::unordered_map<std::string, std::string>;

// Host entries. Called after the default map (date, paths, selection, known
// folders, voice). A contributor may add or replace keys.
using VariableContributor = std::function<void(VariableMap& vars, const VariableContext& context)>;
void add_variable_contributor(VariableContributor fn);

// Extra rows for command_variable_palette_json. push(name, group, description).
using PalettePush = std::function<void(const char* name, const char* group, const char* description)>;
using PaletteContributor = std::function<void(const PalettePush& push)>;
void add_palette_contributor(PaletteContributor fn);

// Runs the palette contributors. command_variable_palette.cpp calls this.
void apply_palette_contributors(const PalettePush& push);

// Defined by the host (src/core/command_variables_host.cpp). Idempotent.
void install_host_variables();

// OS known-folder lookup used by ${KNOWNFOLDER:name} and by host variable contributors.
std::string os_known_folder(const std::string& name);

/// Snapshot of the last matched voice trigger in this process.
struct VoiceUtterance {
    std::string wake;     ///< ${VOICE_WAKE} — matched wake prefix (empty if none)
    std::string command;  ///< ${VOICE_COMMAND} — text after the wake phrase
    std::string full;     ///< ${VOICE_FULL} — raw transcript (wake + command)
};

inline constexpr const char* kVoiceWakeEnv    = "PM_VOICE_WAKE";
inline constexpr const char* kVoiceCommandEnv = "PM_VOICE_COMMAND";
inline constexpr const char* kVoiceFullEnv    = "PM_VOICE_FULL";

void set_last_voice_utterance(VoiceUtterance utterance);
VoiceUtterance last_voice_utterance();

/// Insert VOICE_WAKE / VOICE_COMMAND / VOICE_FULL when the matching field is
/// non-empty, so unset tokens stay literal `${VOICE_COMMAND}`.
void apply_voice_variables(VariableMap& vars, const VoiceUtterance& utterance);

/// Stamp PM_VOICE_* onto a child extra-env list from last_voice_utterance().
void append_voice_utterance_env(std::vector<std::pair<std::string, std::string>>& extra_env);

// Build the standard variable map from `context`.
//
// Built-in variables always populated:
//   ${YYYY} ${MM} ${DD} ${HH} ${mm} ${SS}  — local datetime components
//   ${CWD}                                  — current working directory
//   ${PATH_SEP}                             — OS path separator (/ or \)
//   ${PATH_LIST_SEP}                        — path-list separator (; or :)
//   ${TANIT_ROOT} / ${tanit}               — directory containing the app exe
//   ${CACHE_DIR}                            — OS temp directory (GetTempPath /
//                                             $TMPDIR / /tmp).
//   ${OS_LANG}                              — OS/system default locale (BCP-47, e.g. en-US)
//   ${USER_LANG}                            — user UI / preferred language (BCP-47)
//   ${APP_LANG}                             — Tanit display language (en|es|de|it|fr)
//
// Source-file variables (when context.source_file is set):
//   ${CURRENT_FILE} ${CURRENT_FILE_NAME} ${CURRENT_PATH} ${SRC_NAME} …
//   (${SRC_REL} is added per file by apply_source_file_variables when a rel_base
//    is supplied — e.g. by the installer sign/encrypt verbs)
//
// Multi-file selection (when context.selection_paths is non-empty). Index is
// 0-based and follows the same order as the ${CURRENT_SELECTION} list. An
// out-of-range index stays literal. Path helpers compose on each slot:
//   ${CURRENT_SELECTION} ${CURRENT_SELECTION_COUNT}
//   ${CURRENT_SELECTION_0} ${CURRENT_SELECTION_1} …
//   ${PATH_DIR:CURRENT_SELECTION_0} ${PATH_NAME:CURRENT_SELECTION_1} …
//
// Target window (when context.current_hwnd is set):
//   ${CURRENT_HWND} ${CURRENT_PID} ${CURRENT_WINTITLE} ${CURRENT_PROCESS}
//   ${CURRENT_SCREEN_SPEC}  — `screen:0:hwnd=<CURRENT_HWND>` for xblox capture/record
//
// Centre browser (when the GUI host filled the tab / history fields):
//   ${CURRENT_URL} ${CURRENT_URL_TITLE} ${LAST_URL}
//   ${BROWSER_TAB_COUNT} ${BROWSER_TAB_0} ${BROWSER_TAB_TITLE_0} …
//
// Voice utterance (last trigger in this process, CLI overrides, or PM_VOICE_* env):
//   ${VOICE_WAKE} ${VOICE_COMMAND} ${VOICE_FULL}
//
// Branding variables (always populated from pm::brand constants):
//   ${APP_ID}       — technical app slug (e.g. "tanit")
//   ${APP_DISPLAY}  — human-readable product name (e.g. "Tanit")
//   ${APP_VENDOR}   — vendor name (e.g. "PolyMech")
//   ${APP_EXE}      — full path to the running executable
//
// Brand-qualified data directories (OS-specific, brand-subdir appended):
//   ${APP_DATA}          — roaming config dir   (%APPDATA%\Vendor\App / XDG_CONFIG_HOME/… / ~/Library/Preferences/…)
//   ${APP_LOCAL_DATA}    — local (non-roaming)  (%LOCALAPPDATA%\Vendor\App / ~/.local/share/Vendor/App)
//   ${APP_PROGRAM_DATA}  — machine-wide data    (%PROGRAMDATA%\Vendor\App / /var/lib/Vendor/App)
//
// OS install / package locations (short-form; same as ${KNOWNFOLDER:NAME}):
//   ${PROGRAM_FILES}        ${PROGRAM_FILES_X86}    ${PROGRAM_DATA}
//   ${START_MENU}           ${START_MENU_COMMON}
//   ${PROGRAMS}             ${PROGRAMS_COMMON}
//   ${STARTUP}              ${STARTUP_COMMON}
//   ${FONTS}                ${SYSTEM_DIR}           ${WINDOWS_DIR}
//   ${PUBLIC}               ${PUBLIC_DESKTOP}
//   ${SEND_TO}              ${RECENT}
//
// VFS logical roots (derived from brand data dirs):
//   ${VFS_PUBLIC_DIR}   — machine-wide public VFS root  (${APP_PROGRAM_DATA}/vfs/public)
//   ${VFS_USER_DIR}     — per-user private VFS root     (${APP_DATA}/vfs/user)
//   ${CONFIG_DIR}       — roaming profile root (@ref media::settings::get_config_dir)
//   ${MODELS_DIR}       — local model cache (@ref media::settings::get_models_dir)
//   ${TANIT_SHARED}     — shipped shared assets (dist/shared / package shared/)
//   ${TANIT_SCRIPTS}     — xblox scripts: dist/shared/xblox, or <config-dir>/scripts (Store)
//   ${TEMP_DIR}         — app-scoped temp (@ref media::runtime_settings::effective_temp_dir)
//   ${MCP_CONFIG}       — Claude-normalized MCP export: ${TEMP_DIR}/claude-mcp-config.json
//   ${DEFAULT_FOLDER}   — default work folder (@ref media::ui_defaults::safe_default_folder)
//   ${DEFAULT_MODEL_VFS_MOUNT} — public VFS mount for shipped model assets (default: models)
//
// Install context (when context.install_root is set):
//   ${INSTALL_ROOT}  — bundle/zip root directory
//   ${INSTALL_BIN}   — ${INSTALL_ROOT}/bin if it exists, else ${INSTALL_ROOT}
//
// Installer --config overrides (not pre-populated from environment):
//   ${DEFAULT_VFS_SERVER} — CMS base URL for vfs:// copy sources and vfs_pull/push
//                           (e.g. "https://tanit.polymech.info")
// On-demand prefix handlers (not pre-populated, resolved at lookup time):
//   ${KNOWNFOLDER:name}  — OS known-folder by canonical name
//   ${ENV:name}          — environment variable
//   ${USER:name}         — user-defined variable from settings store
//   ${PATH_DIR:var}  ${PATH_NAME:var}  ${PATH_EXT:var}  ${PATH_BASE:var}  ${PATH_ABS:var}
VariableMap make_variable_map(const VariableContext& context);

// Layer the first-class per-file source variables onto `vars` for a single file:
//   ${SRC_FILE} ${SRC_DIR} ${SRC_NAME} ${SRC_FILE_EXT} ${SRC_EXT}
//   ${CURRENT_FILE} ${CURRENT_FILE_NAME} ${CURRENT_PATH}
// When `rel_base` is non-empty, also sets ${SRC_REL} = `source_file` relative to
// `rel_base` (generic/forward-slash form; falls back to the bare filename when the
// file is not under rel_base).  Shared by make_variable_map and by verbs that
// resolve options per file (installer sign/encrypt), so the vocabulary stays one.
void apply_source_file_variables(VariableMap&       vars,
                                 const std::string& source_file,
                                 const std::string& cwd      = {},
                                 const std::string& rel_base = {});

// Maximum passes for deep variable expansion (override values referencing other
// overrides, or values that embed ${..} templates).  Mirrors xblox ParamResolve::Deep.
inline constexpr int kMaxDeepVariablePasses = 5;

// Re-expand ${..} tokens up to `max_passes` times.  Single pass = resolve_variables.
std::string deep_resolve_variables(std::string_view value,
                                   const VariableMap& vars,
                                   std::string* err = nullptr,
                                   int max_passes = kMaxDeepVariablePasses);

// Load variable overrides from a JSON file.  Accepts either a flat object of
// string values, or { "variables": { "NAME": "value", ... } }.
std::optional<VariableMap> load_variable_overrides(const std::string& path,
                                                   std::string* err = nullptr);

// Parse the same shape as load_variable_overrides from an in-memory JSON value.
std::optional<VariableMap> parse_variable_overrides(const nlohmann::json& j,
                                                    std::string* err = nullptr);

// Merge `overrides` into `vars` (overrides win).  Each override value is
// deep-resolved against the evolving map so entries like
//   "SKILLS": "${APP_DATA}/skills", "APP_DATA": "${INSTALL_ROOT}/profile"
// compose in declaration order across passes.
bool apply_variable_overrides(VariableMap& vars,
                              const VariableMap& overrides,
                              std::string* err = nullptr,
                              int max_passes = kMaxDeepVariablePasses);

// Build the variable map for installer/bundle runs: make_variable_map + optional
// --config overrides from context.variable_config_path.
VariableMap make_bundle_variable_map(const VariableContext& context,
                                     std::string* err = nullptr);

// Expand ${VAR} tokens in an installer filesystem path (--bundle, --config,
// --journal-dir, manifest dependencies), then normalize to an absolute path.
std::string resolve_installer_path(std::string_view path,
                                     const VariableMap& vars,
                                     std::string* err = nullptr);

// User-defined variable from settings store `variables` subtree (${USER:name} / bare ${name}).
std::optional<std::string> user_variable_value(const std::string& name);

// `quiet` suppresses the unresolved-key warnings — for callers that re-resolve
// a string the central param pipeline already resolved (and warned about) once.
std::string resolve_variables(std::string_view value,
                              const VariableMap& vars,
                              std::string* err = nullptr,
                              bool quiet = false);

// Expand built-in/map variables without consulting the settings store for
// user-defined values. This is safe while the settings store itself is resolving
// its config directory (and therefore may already hold its load mutex).
std::string resolve_builtin_variables(std::string_view value,
                                      const VariableMap& vars = {},
                                      std::string* err = nullptr,
                                      bool quiet = false);

void resolve_custom_command_item_variables(nlohmann::json& item,
                                           const VariableContext& context,
                                           std::string* err = nullptr);

/// Same as resolve_custom_command_item_variables, but merges `extra_vars` into the
/// map first (xblox execution context: PREVIOUS, storeAs names, document vars).
/// String fields are deep-resolved so values that themselves embed `${…}`
/// (e.g. context.dst = "${KNOWNFOLDER:Desktop}/out.png") expand fully.
void resolve_custom_command_item_variables(nlohmann::json& item,
                                           const VariableContext& context,
                                           const VariableMap& extra_vars,
                                           std::string* err = nullptr);

// Selection policy shared by the CLI dispatcher and the ribbon/launcher so both
// surfaces fan a multi-file selection out the same way.
//
//   perItem   → run the wrapped command once per selected path; per-item vars
//               (${CURRENT_FILE}, ${SRC_NAME}, …) bind to that single path.
//   aggregate → run once; ${CURRENT_SELECTION} carries the whole list and
//               ${CURRENT_SELECTION_N} binds each path (path helpers compose).
//
// `mode` is the raw `source.selectionMode` string from commands.json.
bool selection_mode_is_per_item(std::string_view mode);

// Expand `base` into the contexts to actually execute against:
//   per_item && base has a selection → one context per selected path
//   otherwise                         → { base } unchanged (aggregate)
std::vector<VariableContext> build_selection_contexts(const VariableContext& base,
                                                      bool per_item);

// CLI custom-command extras: `--arg-NAME value`, bare `--CURRENT_FILE path`, etc.
struct ParsedCustomCliExtras {
    VariableMap              overrides;
    std::vector<std::string> passthrough;
};

// Split `extra_args` into variable overrides (not forwarded) and passthrough argv.
// Skips selection carriers (`--src`, `-s`, `--input`, `-i`) like passthrough_custom_args.
ParsedCustomCliExtras parse_custom_command_cli_extras(const std::vector<std::string>& extra_args);

// Apply CLI override map onto `ctx` when selection/source fields are still empty.
// Path-like override values are normalized to absolute paths in place.
void enrich_context_from_cli_overrides(VariableContext& ctx, VariableMap& overrides);

// Web/catalog JSON for JS variable pickers ({ name, group, description }[]).
// Implemented in command_variable_palette.cpp; surfaced via web_command_host.
nlohmann::json command_variable_palette_json();

/// When `path` lies under a known variable / KNOWNFOLDER root, return a
/// `${TOKEN}/relative` stored form; otherwise return a normalized absolute path.
std::string path_to_stored_expression(std::string_view path,
                                      const VariableContext& context = {});

/// Expand `${KNOWNFOLDER:…}` / `${ENV:…}` in a stored settings string.
/// Text with no `${` is returned unchanged.
std::string expand_stored_text(std::string_view text);

/// Persist a filesystem path, or a `file://` scope (glob suffix kept).
/// Other schemes (`https://`, `mcp://`, `cmd://`, `vfs://`) stay literal.
std::string stored_scope_expression(std::string_view scope);

} // namespace media::commands
