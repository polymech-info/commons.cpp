#pragma once
//
// Common command-finish sink: sound + Windows UI notification + optional TTS.
//
// Every launch path that can complete a `commands.json` entry should end here
// so ribbon, launcher, global hotkeys (daemon / no UI), and in-process xblox
// share one policy. Commands emit output paths with `emit_run_artifact`; the
// CLI process finish hook and xblox both drain that bag into this sink.
//

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace media::commands {

struct CommandFinishEvent {
    std::string command_id;
    std::string label;        ///< commands.json `label` (utf-8)
    std::string description;  ///< tooltip / description (utf-8)
    /// CLI11 parsed path, e.g. `audio tts` / `pdf render`.
    std::string cli_path;
    /// Last CLI11 token, e.g. `tts`.
    std::string cli_stem;
    /// Spoken / toast line (artifact messages, or a composed summary).
    std::string message;
    /// Exact TTS announcement. Composed to "Label finished" when empty.
    std::string tts_text;
    bool        ok         = true;
    int         exit_code  = 0;
    std::string error;
    /// Output paths from the xblox ledger and/or `emit_run_artifact`.
    std::vector<std::string> artifact_paths;
    /// Total produced files (including collapsed / not listed in `artifact_paths`).
    std::size_t artifact_count = 0;
    bool play_sound = false;
    bool notify_ui  = false;
    bool notify_tts = false;
    /// Open the last output with the OS default handler.
    bool open_file = false;
    /// Open the last output in a Tanit viewer. Spawns a window until five UI
    /// instances are already listening, then opens in one of those instead.
    bool open_in_new_instance = false;
};

struct FinishNotifyPrefs {
    bool        play_sound = false;
    bool        notify_ui  = false;
    bool        notify_tts = false;
    bool        open_file = false;
    bool        open_in_new_instance = false;
    std::string label;
    std::string description;
};

struct RunArtifactRecord {
    std::string path;
    std::string source;   ///< family tag (`audio`, `xblox`, …)
    std::string cli;      ///< CLI11 path (`audio tts`)
    std::string stem;     ///< last CLI11 token (`tts`)
    std::string message;  ///< human line for toast / TTS / statusbar
};

/// After CLI11 parse: remember `audio tts` / leaf description for this process.
void remember_cli_invocation(std::string path, std::string stem, std::string description = {});

RunArtifactRecord current_cli_invocation();

/// Session overlay from the parameter dialog (this-run), then catalog `runOptions`.
void remember_session_notify(const std::string& command_id,
                             bool play_sound, bool notify_ui, bool notify_tts = false,
                             bool open_file = false, bool open_in_new_instance = false);

/// Overlay (if any) over `commands.json` `runOptions.notifyOnFinish` / `notifyUi` / `notifyTts`
/// / `openFile` / `openInNewInstance`.
FinishNotifyPrefs resolve_finish_notify(const std::string& command_id);

/// `PM_IMAGE_NOTIFY_*` / `PM_IMAGE_OPEN_*` when the parent already resolved prefs.
bool finish_notify_from_env(FinishNotifyPrefs& out);

/// Stamp `PM_IMAGE_NOTIFY_*` / `PM_IMAGE_OPEN_*` (`0`/`1`) after resolve.
void stamp_notify_env_utf8(std::vector<std::pair<std::string, std::string>>& extra_env,
                           const FinishNotifyPrefs& prefs);

/// Play finish/error wav, show a Windows toast (balloon fallback), and/or speak.
void notify_command_finished(const CommandFinishEvent& ev);

/// Sound / toast / TTS only (no IPC, no once-per-process guard). The UI host
/// calls this when a CLI child delegated finish effects over `command_finished`.
void play_finish_effects(const CommandFinishEvent& ev);

/// Resolve prefs for @p command_id (env, then overlay/catalog) and notify when any flag is on.
void maybe_notify_command_finished(const CommandFinishEvent& ev);

/// `files[].path` from an xblox `ArtifactLedger::snapshot()` (or a raw array).
std::vector<std::string> artifact_paths_from_snapshot(const nlohmann::json& snapshot);

/// Record a generated file or http(s) URL for this process. Live-notifies UI
/// instances over cmd_ipc (same `xblox_artifact` verb as the ledger) and
/// persists to the recent-outputs MRU. CLI path/stem are inferred from CLI11
/// when omitted. Bulk runs (`cp` of thousands of files) collapse to the dest
/// folder after a few siblings, and live/persist/toast are capped.
/// Drained into the finish toast by `notify_cli_process_finished` /
/// `maybe_notify_command_finished`.
void emit_run_artifact(std::string path, std::string source = {}, std::string message = {});

/// `http://` / `https://` artifact (service page/post/file URLs, stream URLs).
bool artifact_path_is_http_url(std::string_view path);

/// Snapshot of paths emitted this process (deduped, insertion order).
std::vector<std::string> snapshot_run_artifacts();

/// Snapshot of full artifact rows (path + cli + message).
std::vector<RunArtifactRecord> snapshot_run_artifact_records();

/// Once-per-process finish notify for `tanit-cli` (uses env + catalog + bag).
/// No-op when `maybe_notify_command_finished` already ran (xblox).
void notify_cli_process_finished(int exit_code);

/// Process exit that should show as Done, not Failed.
/// `0` is success; `130` is the xblox/SIGINT user-stop convention.
bool command_exit_succeeded(int exit_code);

/// Parent watcher of `tanit-cli` / xblox: the child already logged success, then
/// Windows often reports `1` (TerminateProcess / job close) or `-1` during
/// teardown. NTSTATUS crashes still fail.
bool command_child_process_succeeded(int exit_code);

/// Finish toast / queue / ribbon: success, user-stop, or a generic fail after
/// outputs were already written (recorder finalize + kill, cancel-as-Fatal).
bool command_finish_succeeded(bool reported_ok, int exit_code, std::size_t artifact_count);

/// One ledger shape for CLI `emit_run_artifact` and xblox harvest rows
/// (`path`, `label`, `src`/`block`, `op`, `ts`, `pathKind`). Empty if no path.
nlohmann::json normalize_output_artifact_row(nlohmann::json row);

} // namespace media::commands
