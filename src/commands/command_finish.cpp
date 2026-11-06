#include "command_finish.hpp"
#include "fs/path_sanitizer.hpp"
#include "command_finish_i18n.hpp"

#include "audio/notifications.hpp"
#include "constants.hpp"
#include "process/app_exe_directory.hpp"
#include "commands/command_variables.hpp"
#include "settings/settings_runtime.hpp"
#include "net/uri.hpp"
#include "logging/pm_log.hpp"

#if defined(FEATURE_STT) && FEATURE_STT
#  include "core/audio.hpp"
#  include "audio/tts/elevenlabs_tts.hpp"
#  include "audio/tts/proxy_tts.hpp"
#  include "blocks/block_provider.hpp"
#endif

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
#  include "core/cmd_ipc.hpp"
#endif

#if defined(_WIN32)
#  include "win/desktop_notification.hpp"
#endif

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include "string/string_utils.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <objbase.h>
#  include <shellapi.h>
#endif

namespace media::commands {

bool artifact_path_is_http_url(std::string_view path)
{
    return path.size() >= 7
        && (path.rfind("http://", 0) == 0 || path.rfind("https://", 0) == 0);
}

namespace {

struct Overlay {
    bool play_sound = false;
    bool notify_ui  = false;
    bool notify_tts = false;
    bool open_file = false;
    bool open_in_new_instance = false;
};

std::mutex g_overlay_mu;
std::unordered_map<std::string, Overlay> g_overlay;

std::mutex g_cli_mu;
RunArtifactRecord g_cli;

std::mutex g_artifacts_mu;
std::vector<RunArtifactRecord> g_artifacts;
std::unordered_set<std::string> g_artifact_keys;
std::size_t g_artifact_total = 0;
std::size_t g_live_sent = 0;
std::size_t g_persist_sent = 0;
std::int64_t g_live_window_start_ms = 0;
int g_live_window_count = 0;
std::unordered_map<std::string, std::size_t> g_parent_counts;
std::unordered_set<std::string> g_collapsed_parents;
std::unordered_map<std::string, std::size_t> g_collapse_row;
std::atomic<bool> g_finish_notified{false};

constexpr std::size_t kBagCap = 32;
constexpr std::size_t kLiveCap = 8;
constexpr std::size_t kPersistCap = 12;
constexpr std::size_t kCollapseAfter = 8;
constexpr std::size_t kToastPaths = 5;
constexpr std::int64_t kLiveWindowMs = 1000;
constexpr int kLiveBurstMax = 8;

std::int64_t now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void notify_ui_artifact(const nlohmann::json& entry);
bool notify_ui_command_finished(const CommandFinishEvent& ev, bool request_effects);

std::string file_leaf(const std::string& path)
{
    if (path.empty())
        return {};
    if (artifact_path_is_http_url(path)) {
        std::string p = path;
        if (const auto qpos = p.find('?'); qpos != std::string::npos) {
            std::string query = p.substr(qpos + 1);
            if (const auto hash = query.find('#'); hash != std::string::npos)
                query.resize(hash);
            const std::string key = "file=";
            std::size_t pos = 0;
            while (pos < query.size()) {
                const auto amp = query.find('&', pos);
                const std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
                if (part.size() > key.size() && part.compare(0, key.size(), key) == 0) {
                    std::string name = part.substr(key.size());
                    if (!name.empty())
                        return name;
                }
                if (amp == std::string::npos)
                    break;
                pos = amp + 1;
            }
        }
        if (const auto q = p.find_first_of("?#"); q != std::string::npos)
            p.resize(q);
        while (!p.empty() && (p.back() == '/' || p.back() == '\\'))
            p.pop_back();
        const auto slash = p.find_last_of("/\\");
        std::string leaf = slash == std::string::npos ? p : p.substr(slash + 1);
        if (leaf.empty() || leaf == "http:" || leaf == "https:") {
            if (const auto uri = pm::uri::parse_http_uri(path); uri && !uri->host.empty())
                return uri->host;
            return path;
        }
        return leaf;
    }
    try {
        namespace fs = std::filesystem;
        return media::path::path_to_utf8(media::path::path_from_utf8(path).filename());
    } catch (...) {
        return path;
    }
}

RunArtifactRecord cli_invocation_unlocked()
{
    return g_cli;
}

std::string default_artifact_message(const std::string& path, const RunArtifactRecord& inv)
{
    const std::string name = file_leaf(path);
    // `inv.message` is CLI11 get_description() — help prose, not a toast line.
    if (!inv.cli.empty())
        return inv.cli + (name.empty() ? std::string{} : (" → " + name));
    return name;
}

std::string compose_finish_message(const CommandFinishEvent& ev)
{
    if (!ev.message.empty())
        return ev.message;
    const auto& tr = command_finish_i18n::current();
    std::string text;
    if (ev.ok) {
        text = ev.label.empty() ? (ev.cli_path.empty() ? tr.command_finished : ev.cli_path + tr.finished_suffix)
                                : ev.label + tr.finished_suffix;
        if (!ev.cli_path.empty() && ev.label != ev.cli_path) {
            text += ". ";
            text += ev.cli_path;
        }
        std::size_t n = 0;
        for (const auto& path : ev.artifact_paths) {
            const std::string name = file_leaf(path);
            if (name.empty())
                continue;
            text += (n == 0) ? ". " : ", ";
            text += name;
            if (++n == 3)
                break;
        }
        const std::size_t total = ev.artifact_count > 0 ? ev.artifact_count : ev.artifact_paths.size();
        if (total > n) {
            text += " +";
            text += std::to_string(total - n);
            text += tr.more_suffix;
        }
    } else {
        text = ev.label.empty() ? tr.command_failed : ev.label + tr.failed_suffix;
        if (!ev.error.empty()) {
            text += ". ";
            text += ev.error;
        } else if (ev.exit_code != 0) {
            text += ". ";
            text += tr.exit_prefix;
            text += std::to_string(ev.exit_code);
        }
    }
    return text;
}

constexpr std::size_t kSpeechCap = 180;

std::string clamp_speech(std::string text, std::size_t cap)
{
    if (text.size() <= cap)
        return text;
    std::size_t cut = text.rfind(' ', cap);
    if (cut == std::string::npos || cut < cap / 2)
        cut = cap;
    text.resize(cut);
    while (!text.empty() && (text.back() == ' ' || text.back() == '.' || text.back() == ','))
        text.pop_back();
    if (!text.empty())
        text += "…";
    return text;
}

/// Short spoken line only. Never the CLI help paragraph or artifact essays.
std::string compose_finish_speech(const CommandFinishEvent& ev)
{
    std::string text;
    const auto& tr = command_finish_i18n::current();
    if (ev.ok) {
        if (!ev.label.empty())
            text = ev.label + tr.finished_suffix;
        else if (!ev.cli_stem.empty())
            text = ev.cli_stem + tr.finished_suffix;
        else if (!ev.cli_path.empty())
            text = ev.cli_path + tr.finished_suffix;
        else
            text = tr.command_finished;
    } else {
        text = ev.label.empty() ? tr.command_failed : ev.label + tr.failed_suffix;
        if (!ev.error.empty()) {
            text += ". ";
            text += clamp_speech(ev.error, 80);
        }
    }
    return clamp_speech(std::move(text), kSpeechCap);
}

#if defined(FEATURE_STT) && FEATURE_STT && defined(_WIN32)
struct FinishTtsComMtaGuard {
    bool owned = false;
    FinishTtsComMtaGuard()
    {
        const HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        owned = (hr == S_OK || hr == S_FALSE);
    }
    ~FinishTtsComMtaGuard()
    {
        if (owned)
            ::CoUninitialize();
    }
};
#endif

void play_finish_tts_bytes(const std::vector<uint8_t>& audio)
{
#if defined(FEATURE_STT) && FEATURE_STT
    std::exception_ptr ep;
    std::thread t([&] {
#if defined(_WIN32)
        FinishTtsComMtaGuard com;
#endif
        try {
            pm::audio::AudioOutput out;
            media::runtime_settings::AudioVideoDeviceSettings avs;
            std::string avs_err;
            media::runtime_settings::load_audio_video_device_settings(avs, avs_err);
            const std::string device = media::runtime_settings::resolve_audio_output_device(
                {}, avs);
            if (!device.empty())
                out.set_device_name(device);
            out.play_sync(audio.data(), audio.size());
        } catch (...) {
            ep = std::current_exception();
        }
    });
    t.join();
    if (ep)
        std::rethrow_exception(ep);
#else
    (void)audio;
#endif
}

// Re-entrant finish paths (runner + IPC host, or several UI listeners) can
// play the same open / utterance a few seconds apart. Remember recent keys
// so the second call is a no-op.
constexpr auto kEffectDedupeTtl = std::chrono::seconds(10);

bool effect_recently_done(const std::string& key)
{
    if (key.empty())
        return false;
    static std::mutex mu;
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> seen;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mu);
    for (auto it = seen.begin(); it != seen.end(); ) {
        if (now - it->second >= kEffectDedupeTtl)
            it = seen.erase(it);
        else
            ++it;
    }
    const auto it = seen.find(key);
    if (it != seen.end())
        return true;
    seen.emplace(key, now);
    return false;
}

std::string effect_path_key(std::string path)
{
    for (char& ch : path) {
        if (ch == '\\')
            ch = '/';
#if defined(_WIN32)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
#endif
    }
    return path;
}

bool finish_tts_already_spoken(const std::string& text)
{
    if (text.empty())
        return true;
    if (!effect_recently_done("tts\n" + text))
        return false;
    logger::trace("[command-finish] tts skip duplicate text=\"" + text + "\"");
    return true;
}

void speak_finish_message(const std::string& text)
{
    logger::trace("[command-finish] tts text=\"" + text + "\" chars="
        + std::to_string(text.size()));
#if defined(FEATURE_STT) && FEATURE_STT
    if (text.empty()) {
        logger::warn("[command-finish] tts: empty message");
        return;
    }
    try {
        // Same defaults as `audio tts` / xblox `audioSpeak` with empty overrides:
        // App Settings → Chat → Voice & Audio provider / model / voice.
        const auto tts = media::xblox::bp::resolve_tts({});
        if (!tts.error.empty()) {
            logger::warn("[command-finish] tts resolve: " + tts.error);
            return;
        }
        logger::trace("[command-finish] tts provider=" + tts.provider
            + " model=" + (tts.model.empty() ? std::string("(default)") : tts.model)
            + " voice=" + (tts.voice.empty() ? std::string("(default)") : tts.voice));

        std::vector<uint8_t> audio_bytes;
        if (tts.provider == "elevenlabs") {
            pm::tts::ElevenLabsTTSConfig cfg;
            cfg.api_key = tts.api_key;
            if (!tts.voice.empty())
                cfg.voice_id = tts.voice;
            if (!tts.model.empty())
                cfg.model_id = tts.model;
            audio_bytes = pm::tts::elevenlabs_tts_synthesize(text, cfg);
        } else if (tts.provider == "vibevoice" || tts.provider == "moss") {
            logger::warn("[command-finish] tts: local engine '" + tts.provider
                + "' is not used for finish notify; set Chat TTS to tanit or elevenlabs");
            return;
        } else {
            audio_bytes = pm::tts::proxy_tts_synthesize(
                text, tts.base_url, tts.api_key, tts.model, tts.voice);
        }
        if (audio_bytes.empty()) {
            logger::warn("[command-finish] tts: provider returned no audio bytes");
            return;
        }
        play_finish_tts_bytes(audio_bytes);
        logger::info("[command-finish] tts ok chars=" + std::to_string(text.size())
            + " bytes=" + std::to_string(audio_bytes.size())
            + " provider=" + tts.provider);
    } catch (const std::exception& e) {
        logger::warn(std::string("[command-finish] tts: ") + e.what());
    } catch (...) {
        logger::warn("[command-finish] tts: unknown error");
    }
#else
    logger::info("[command-finish] tts (unavailable): " + text);
#endif
}

std::string artifact_key(std::string path)
{
    while (!path.empty() && (path.back() == '\\' || path.back() == '/'))
        path.pop_back();
    path = media::strutil::lower_ascii(std::move(path));
    return path;
}

std::string normalize_artifact_path(std::string path)
{
    if (path.empty())
        return {};
    if (artifact_path_is_http_url(path))
        return path;
    try {
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path p = media::path::path_from_utf8(path);
        const fs::path abs = fs::absolute(p, ec);
        if (ec)
            return path;
        const fs::path canon = fs::weakly_canonical(abs, ec);
        const fs::path use = ec ? abs : canon;
        return media::path::path_to_utf8(use);
    } catch (...) {
        return path;
    }
}

std::string parent_dir_of(const std::string& path)
{
    if (path.empty() || artifact_path_is_http_url(path))
        return {};
    try {
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path p = media::path::path_from_utf8(path);
        if (fs::is_directory(p, ec))
            return path;
        const fs::path parent = p.parent_path();
        if (parent.empty())
            return {};
        return normalize_artifact_path(media::path::path_to_utf8(parent));
    } catch (...) {
        return {};
    }
}

bool path_under_parent(const std::string& path, const std::string& parent_key)
{
    if (parent_key.empty())
        return false;
    const std::string key = artifact_key(path);
    if (key == parent_key)
        return true;
    if (key.size() <= parent_key.size())
        return false;
    if (key.compare(0, parent_key.size(), parent_key) != 0)
        return false;
    const char next = key[parent_key.size()];
    return next == '\\' || next == '/';
}

std::int64_t system_now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string infer_artifact_path_kind(const std::string& path)
{
    if (artifact_path_is_http_url(path))
        return "url";
    const std::string name = file_leaf(path);
    const auto dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 >= name.size())
        return "file_path";
    std::string ext = name.substr(dot + 1);
    ext = media::strutil::lower_ascii(std::move(ext));
    if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "webp"
        || ext == "gif" || ext == "bmp" || ext == "tif" || ext == "tiff"
        || ext == "avif" || ext == "heic" || ext == "heif")
        return "image_path";
    if (ext == "mp4" || ext == "webm" || ext == "mkv" || ext == "mov" || ext == "avi")
        return "video_path";
    if (ext == "wav" || ext == "mp3" || ext == "flac" || ext == "ogg" || ext == "m4a")
        return "audio_path";
    return "file_path";
}

std::string json_row_string(const nlohmann::json& o, const char* key)
{
    if (o.contains(key) && o[key].is_string())
        return o[key].get<std::string>();
    return {};
}

nlohmann::json normalize_row_unlocked(nlohmann::json row)
{
    if (!row.is_object() || !row.contains("path") || !row["path"].is_string())
        return {};
    const std::string path = row["path"].get<std::string>();
    if (path.empty())
        return {};
    if (json_row_string(row, "label").empty())
        row["label"] = file_leaf(path);
    const std::string cli = json_row_string(row, "cli");
    const std::string stem = json_row_string(row, "stem");
    const std::string source = json_row_string(row, "source");
    if (json_row_string(row, "src").empty()) {
        const std::string src = !cli.empty() ? cli : (!source.empty() ? source : stem);
        if (!src.empty())
            row["src"] = src;
    }
    if (json_row_string(row, "block").empty()) {
        const std::string block = !stem.empty() ? stem : (!cli.empty() ? cli : source);
        if (!block.empty())
            row["block"] = block;
    }
    if (!row.contains("op") || !row["op"].is_string() || row["op"].get<std::string>().empty())
        row["op"] = "write";
    if (!row.contains("ts") || !row["ts"].is_number())
        row["ts"] = system_now_ms();
    if (json_row_string(row, "pathKind").empty())
        row["pathKind"] = infer_artifact_path_kind(path);
    return row;
}

nlohmann::json artifact_row_json(const RunArtifactRecord& rec, const std::string& label)
{
    return normalize_row_unlocked({
        {"path", rec.path},
        {"source", rec.source},
        {"cli", rec.cli},
        {"stem", rec.stem},
        {"message", rec.message},
        {"label", label},
    });
}

bool ui_host_is_listening()
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind == media::cmd_ipc::ProcessKind::Ui)
            return true;
    }
#endif
    return false;
}

void persist_artifact_row(const nlohmann::json& row)
{
    // When a UI is up it persists the IPC row into its settings cache.
    // Writing from the CLI here races that cache and can drop sibling rows.
    if (ui_host_is_listening())
        return;
    std::string persist_err;
    if (!media::runtime_settings::append_xblox_artifact_entries(
            nlohmann::json::array({row}), persist_err) && !persist_err.empty())
        logger::warn("[command-finish] artifact persist failed: " + persist_err);
}

bool allow_live_notify_locked()
{
    const std::int64_t now = now_ms();
    if (g_live_window_start_ms == 0 || now - g_live_window_start_ms >= kLiveWindowMs) {
        g_live_window_start_ms = now;
        g_live_window_count = 0;
    }
    if (g_live_sent >= kLiveCap || g_live_window_count >= kLiveBurstMax)
        return false;
    ++g_live_sent;
    ++g_live_window_count;
    return true;
}

void fanout_artifact(const RunArtifactRecord& rec, const std::string& label, bool live, bool persist)
{
    const nlohmann::json row = artifact_row_json(rec, label);
    if (live)
        notify_ui_artifact(row);
    if (persist) {
        ++g_persist_sent;
        persist_artifact_row(row);
    }
}

void refresh_collapse_messages_locked()
{
    for (auto& [pkey, idx] : g_collapse_row) {
        if (idx >= g_artifacts.size())
            continue;
        auto& rec = g_artifacts[idx];
        const std::size_t n = g_parent_counts[pkey];
        const std::string name = file_leaf(rec.path);
        rec.message = (rec.cli.empty() ? rec.source : rec.cli)
            + " → " + (name.empty() ? rec.path : name)
            + " (" + std::to_string(n) + " files)";
    }
}

void notify_ui_artifact(const nlohmann::json& entry)
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    if (!entry.is_object())
        return;
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind != media::cmd_ipc::ProcessKind::Ui)
            continue;
        nlohmann::json reply;
        std::string err;
        (void)media::cmd_ipc::send_action(
            inst, "xblox_artifact", {{"artifact", entry}}, reply, err, 500);
    }
#else
    (void)entry;
#endif
}

bool this_process_is_ui()
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT && defined(_WIN32)
    const auto pid = static_cast<std::int64_t>(::GetCurrentProcessId());
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.pid == pid && inst.kind == media::cmd_ipc::ProcessKind::Ui)
            return true;
    }
#endif
    return false;
}

bool notify_ui_command_finished(const CommandFinishEvent& ev, bool request_effects)
{
    bool acked = false;
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    nlohmann::json extra{
        {"command_id", ev.command_id},
        {"ok", ev.ok},
        {"exit_code", ev.ok ? 0 : ev.exit_code},
        {"artifacts", ev.artifact_count > 0 ? ev.artifact_count : ev.artifact_paths.size()},
        {"label", ev.label},
        {"description", ev.description},
        {"cli_path", ev.cli_path},
        {"cli_stem", ev.cli_stem},
        {"message", ev.message},
        {"tts_text", ev.tts_text},
        {"error", ev.error},
        {"play_sound", request_effects && ev.play_sound},
        {"notify_ui", request_effects && ev.notify_ui},
        {"notify_tts", request_effects && ev.notify_tts},
        {"open_file", request_effects && ev.open_file},
        {"open_in_new_instance", request_effects && ev.open_in_new_instance},
    };
    extra["artifact_paths"] = ev.artifact_paths;
    // Open and TTS run inside whichever UI plays the effects. Hand them to one
    // window so several listening instances do not each open and speak.
    bool effects_handed_off = false;
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind != media::cmd_ipc::ProcessKind::Ui)
            continue;
        nlohmann::json payload = extra;
        if (effects_handed_off) {
            payload["open_file"] = false;
            payload["open_in_new_instance"] = false;
            payload["notify_tts"] = false;
        }
        logger::trace("[command-finish] ipc command_finished → pid="
            + std::to_string(inst.pid)
            + " id=" + ev.command_id
            + " ok=" + std::string(ev.ok ? "1" : "0")
            + " tts=" + std::string(request_effects && ev.notify_tts ? "1" : "0")
            + " tts_text=\"" + ev.tts_text + "\"");
        nlohmann::json reply;
        std::string err;
        // UI may speak synchronously (audioSpeak path). Allow the announcement.
        if (!media::cmd_ipc::send_action(inst, "command_finished", payload, reply, err, 30000)) {
            logger::trace("[command-finish] command_finished ipc failed: " + err);
            continue;
        }
        if (reply.value("ok", false)
            || reply.value("type", std::string{}) == "command_finished_ack") {
            acked = true;
            if (payload.value("open_file", false)
                || payload.value("open_in_new_instance", false)
                || payload.value("notify_tts", false))
                effects_handed_off = true;
            logger::trace("[command-finish] ipc command_finished ack pid="
                + std::to_string(inst.pid));
        } else {
            logger::warn("[command-finish] command_finished ipc reply: " + reply.dump());
        }
    }
#else
    (void)ev;
    (void)request_effects;
#endif
    return acked;
}

std::string json_string(const nlohmann::json& o, const char* key)
{
    if (o.contains(key) && o[key].is_string())
        return o[key].get<std::string>();
    return {};
}

void walk_items(const nlohmann::json& items, const std::function<void(const nlohmann::json&)>& fn)
{
    if (!items.is_array())
        return;
    for (const auto& item : items) {
        if (!item.is_object())
            continue;
        fn(item);
        if (item.contains("items"))
            walk_items(item["items"], fn);
    }
}

nlohmann::json find_command_item(const nlohmann::json& root, const std::string& command_id)
{
    if (command_id.empty())
        return {};
    const nlohmann::json* groups = nullptr;
    if (root.contains("ribbon") && root["ribbon"].is_object() && root["ribbon"].contains("groups"))
        groups = &root["ribbon"]["groups"];
    else if (root.contains("groups"))
        groups = &root["groups"];
    else if (root.is_array())
        groups = &root;
    if (!groups)
        return {};

    nlohmann::json found;
    auto consider = [&](const nlohmann::json& items) {
        walk_items(items, [&](const nlohmann::json& item) {
            if (!found.empty())
                return;
            if (json_string(item, "id") == command_id)
                found = item;
        });
    };
    if (groups->is_array()) {
        for (const auto& group : *groups) {
            if (group.is_object() && group.contains("items"))
                consider(group["items"]);
            else if (group.is_object() && json_string(group, "id") == command_id)
                found = group;
        }
    }
    return found;
}

FinishNotifyPrefs prefs_from_item(const nlohmann::json& item)
{
    FinishNotifyPrefs p;
    p.label = json_string(item, "label");
    p.description = json_string(item, "tooltip");
    if (p.description.empty())
        p.description = json_string(item, "description");
    if (item.contains("runOptions") && item["runOptions"].is_object()) {
        const auto& ro = item["runOptions"];
        p.play_sound = ro.value("notifyOnFinish", false);
        p.notify_ui  = ro.value("notifyUi", false);
        p.notify_tts = ro.value("notifyTts", false);
        p.open_file = ro.value("openFile", false);
        p.open_in_new_instance = ro.value("openInNewInstance", false);
    }
    return p;
}

FinishNotifyPrefs prefs_from_catalog(const std::string& command_id)
{
    FinishNotifyPrefs p;
    if (command_id.empty())
        return p;
    std::string raw;
    std::string err;
    if (!media::runtime_settings::load_command_json_utf8(raw, err) || raw.empty())
        return p;
    try {
        const auto root = nlohmann::json::parse(raw);
        const auto item = find_command_item(root, command_id);
        if (item.is_object() && !item.empty())
            p = prefs_from_item(item);
    } catch (...) {
    }
    if (p.label.empty())
        p.label = command_id;
    return p;
}

std::wstring utf8_to_wide(const std::string& s)
{
#if defined(_WIN32)
    if (s.empty())
        return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
#else
    return std::wstring(s.begin(), s.end());
#endif
}

std::string primary_artifact_path(const CommandFinishEvent& ev)
{
    for (auto it = ev.artifact_paths.rbegin(); it != ev.artifact_paths.rend(); ++it) {
        if (!it->empty())
            return *it;
    }
    return {};
}

#if defined(_WIN32)
std::wstring gui_exe_path()
{
    const auto gui = media::app::exe_gui_executable();
    if (!gui.empty())
        return gui.wstring();
    const auto self = media::app::exe_executable();
    if (!self.empty())
        return self.wstring();
    return {};
}

bool open_artifact_os_default(const std::string& path)
{
    const std::wstring w = utf8_to_wide(path);
    if (w.empty() || w.find(L'\0') != std::wstring::npos)
        return false;
    const HINSTANCE hi = ::ShellExecuteW(nullptr, L"open", w.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    const auto code = reinterpret_cast<INT_PTR>(hi);
    if (code <= 32) {
        logger::warn("[command-finish] open file failed code=" + std::to_string(static_cast<long long>(code)));
        return false;
    }
    logger::info("[command-finish] opened file (os default)");
    return true;
}

// Past this many live UI instances, "open in Tanit" reuses one instead of
// spawning another viewer.
constexpr int kMaxUiInstancesBeforeReuse = 5;

int count_ui_instances()
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    int n = 0;
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind == media::cmd_ipc::ProcessKind::Ui)
            ++n;
    }
    return n;
#else
    return 0;
#endif
}

bool open_artifact_in_existing_ui(const std::string& path)
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    const auto instances = media::cmd_ipc::list_instances();
    // Skip this process: command_finished is handled on its accept thread, so a
    // send back to self cannot be accepted until this call returns.
    const auto self = static_cast<std::int64_t>(::GetCurrentProcessId());
    std::vector<const media::cmd_ipc::InstanceDescriptor*> candidates;
    for (const auto& inst : instances) {
        if (inst.kind != media::cmd_ipc::ProcessKind::Ui || inst.pid == self)
            continue;
        candidates.push_back(&inst);
    }
    std::sort(candidates.begin(), candidates.end(),
        [](const media::cmd_ipc::InstanceDescriptor* a,
           const media::cmd_ipc::InstanceDescriptor* b) {
            return a->started_unix_ms > b->started_unix_ms;
        });
    for (const auto* inst : candidates) {
        nlohmann::json reply;
        std::string err;
        const bool sent = media::cmd_ipc::send_action(*inst, "app_cmd", {
            {"command", "edit"},
            {"args", {{"path", path}}},
        }, reply, err, 5000);
        if (sent && reply.value("type", std::string{}) == "app_cmd_ack") {
            logger::info("[command-finish] opened in existing instance pid="
                + std::to_string(inst->pid));
            return true;
        }
        logger::warn("[command-finish] open in existing instance failed pid="
            + std::to_string(inst->pid)
            + (err.empty() ? std::string{} : " err=" + err)
            + (reply.empty() ? std::string{} : " reply=" + reply.dump()));
    }
    return false;
#else
    (void)path;
    return false;
#endif
}

bool open_artifact_new_instance(const std::string& path)
{
    const std::wstring wpath = utf8_to_wide(path);
    const std::wstring exe = gui_exe_path();
    if (exe.empty() || wpath.empty() || wpath.find(L'\0') != std::wstring::npos)
        return false;
    if (count_ui_instances() >= kMaxUiInstancesBeforeReuse) {
        if (open_artifact_in_existing_ui(path))
            return true;
        logger::warn("[command-finish] " + std::to_string(kMaxUiInstancesBeforeReuse)
            + " Tanit instances already open; not spawning another");
        return false;
    }
    // Same barrel as CWebView hostShellEditDocument / shell::edit_text_document.
    std::wstring cmd = L"\"";
    cmd += exe;
    cmd += L"\" --ui-preset viewer --src \"";
    cmd += wpath;
    cmd += L"\" --edit";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        logger::warn("[command-finish] open in new instance failed err="
            + std::to_string(::GetLastError()));
        return false;
    }
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    logger::info("[command-finish] opened in new instance");
    return true;
}
#endif

void apply_finish_open_actions(const CommandFinishEvent& ev)
{
    if (!ev.ok || (!ev.open_file && !ev.open_in_new_instance))
        return;
    const std::string path = primary_artifact_path(ev);
    if (path.empty()) {
        logger::warn("[command-finish] open skipped: no artifact path");
        return;
    }
#if defined(_WIN32)
    const std::string path_key = effect_path_key(path);
    if (ev.open_in_new_instance) {
        if (effect_recently_done("instance\n" + path_key))
            logger::trace("[command-finish] open in tanit skip duplicate path=" + path);
        else
            (void)open_artifact_new_instance(path);
    }
    if (ev.open_file) {
        if (effect_recently_done("open\n" + path_key))
            logger::trace("[command-finish] open file skip duplicate path=" + path);
        else
            (void)open_artifact_os_default(path);
    }
#else
    (void)path;
    logger::info("[command-finish] open actions unavailable on this platform");
#endif
}

bool env_flag(const char* name, std::optional<bool>& out)
{
    const char* v = std::getenv(name);
    if (!v || !*v)
        return false;
    out = (*v != '0' && *v != 'f' && *v != 'F' && *v != 'n' && *v != 'N');
    return true;
}

std::string build_notify_body(const CommandFinishEvent& ev)
{
    std::string body = ev.description;
    if (!ev.ok) {
        if (!ev.error.empty()) {
            if (!body.empty())
                body += "\n";
            body += ev.error;
        } else if (ev.exit_code != 0) {
            if (!body.empty())
                body += "\n";
            body += command_finish_i18n::current().exit_prefix + std::to_string(ev.exit_code);
        }
    }
    if (!ev.cli_path.empty()) {
        if (!body.empty())
            body += "\n";
        body += ev.cli_path;
    }
    const std::string spoken = ev.message.empty() ? compose_finish_message(ev) : ev.message;
    if (!spoken.empty() && spoken != ev.description) {
        if (!body.empty())
            body += "\n";
        body += spoken;
    }
    if (ev.artifact_paths.size() > 5) {
        if (!body.empty())
            body += "\n";
        body += "+";
        body += std::to_string(ev.artifact_paths.size() - 5);
        body += command_finish_i18n::current().more_suffix;
    }
    return body;
}

} // namespace

void remember_cli_invocation(std::string path, std::string stem, std::string description)
{
    std::lock_guard<std::mutex> lock(g_cli_mu);
    g_cli.cli = std::move(path);
    g_cli.stem = std::move(stem);
    g_cli.message = std::move(description);
    if (g_cli.source.empty())
        g_cli.source = g_cli.stem.empty() ? "cli" : g_cli.stem;
}

RunArtifactRecord current_cli_invocation()
{
    std::lock_guard<std::mutex> lock(g_cli_mu);
    return cli_invocation_unlocked();
}

void remember_session_notify(const std::string& command_id,
                             bool play_sound, bool notify_ui, bool notify_tts,
                             bool open_file, bool open_in_new_instance)
{
    if (command_id.empty())
        return;
    std::lock_guard<std::mutex> lock(g_overlay_mu);
    g_overlay[command_id] = Overlay{play_sound, notify_ui, notify_tts, open_file, open_in_new_instance};
}

FinishNotifyPrefs resolve_finish_notify(const std::string& command_id)
{
    FinishNotifyPrefs p = prefs_from_catalog(command_id);
    if (command_id.empty())
        return p;
    std::lock_guard<std::mutex> lock(g_overlay_mu);
    if (const auto it = g_overlay.find(command_id); it != g_overlay.end()) {
        p.play_sound = it->second.play_sound;
        p.notify_ui  = it->second.notify_ui;
        p.notify_tts = it->second.notify_tts;
        p.open_file = it->second.open_file;
        p.open_in_new_instance = it->second.open_in_new_instance;
    }
    return p;
}

bool finish_notify_from_env(FinishNotifyPrefs& out)
{
    std::optional<bool> sound;
    std::optional<bool> ui;
    std::optional<bool> tts;
    std::optional<bool> open_file;
    std::optional<bool> open_inst;
    const bool have_sound = env_flag("PM_IMAGE_NOTIFY_SOUND", sound);
    const bool have_ui    = env_flag("PM_IMAGE_NOTIFY_UI", ui);
    const bool have_tts   = env_flag("PM_IMAGE_NOTIFY_TTS", tts);
    const bool have_open  = env_flag("PM_IMAGE_OPEN_FILE", open_file);
    const bool have_inst  = env_flag("PM_IMAGE_OPEN_IN_NEW_INSTANCE", open_inst);
    if (!have_sound && !have_ui && !have_tts && !have_open && !have_inst)
        return false;
    if (have_sound)
        out.play_sound = *sound;
    if (have_ui)
        out.notify_ui = *ui;
    if (have_tts)
        out.notify_tts = *tts;
    if (have_open)
        out.open_file = *open_file;
    if (have_inst)
        out.open_in_new_instance = *open_inst;
    return true;
}

void stamp_notify_env_utf8(std::vector<std::pair<std::string, std::string>>& extra_env,
                           const FinishNotifyPrefs& prefs)
{
    extra_env.emplace_back("PM_IMAGE_NOTIFY_SOUND", prefs.play_sound ? "1" : "0");
    extra_env.emplace_back("PM_IMAGE_NOTIFY_UI", prefs.notify_ui ? "1" : "0");
    extra_env.emplace_back("PM_IMAGE_NOTIFY_TTS", prefs.notify_tts ? "1" : "0");
    extra_env.emplace_back("PM_IMAGE_OPEN_FILE", prefs.open_file ? "1" : "0");
    extra_env.emplace_back("PM_IMAGE_OPEN_IN_NEW_INSTANCE", prefs.open_in_new_instance ? "1" : "0");
    append_voice_utterance_env(extra_env);
}

void ensure_finish_speech(CommandFinishEvent& ev)
{
    if (ev.message.empty())
        ev.message = compose_finish_message(ev);
    if (ev.tts_text.empty())
        ev.tts_text = compose_finish_speech(ev);
    logger::trace("[command-finish] tts text=\"" + ev.tts_text + "\" chars="
        + std::to_string(ev.tts_text.size())
        + " notify_tts=" + std::string(ev.notify_tts ? "1" : "0")
        + " id=" + ev.command_id
        + " ok=" + std::string(ev.ok ? "1" : "0")
        + " label=" + ev.label
        + " cli=" + ev.cli_path);
}

void play_finish_effects(const CommandFinishEvent& ev)
{
    CommandFinishEvent spoken = ev;
    ensure_finish_speech(spoken);

    if (!spoken.play_sound && !spoken.notify_ui && !spoken.notify_tts
        && !spoken.open_file && !spoken.open_in_new_instance) {
        logger::trace("[command-finish] effects skipped (all flags off) id="
            + spoken.command_id);
        return;
    }

    if (spoken.play_sound) {
        try {
            pm::audio::notifications::Options opts;
            opts.force = true;
            const auto id = spoken.ok
                ? pm::audio::notifications::SoundId::Finish
                : pm::audio::notifications::SoundId::Error;
            (void)pm::audio::notifications::play(id, opts);
        } catch (const std::exception& e) {
            logger::warn(std::string("[command-finish] sound: ") + e.what());
        } catch (...) {
            logger::warn("[command-finish] sound: unknown error");
        }
    }

    if (spoken.notify_ui) {
        try {
            std::string title = spoken.label.empty() ? spoken.command_id : spoken.label;
            const auto& tr = command_finish_i18n::current();
            if (title.empty())
                title = spoken.cli_path.empty() ? tr.command_title : spoken.cli_path;
            if (!spoken.ok)
                title += tr.failed_suffix;
            const std::string body = build_notify_body(spoken);
#if defined(_WIN32)
            std::vector<std::wstring> artifacts;
            artifacts.reserve(spoken.artifact_paths.size());
            for (const auto& path : spoken.artifact_paths)
                artifacts.push_back(utf8_to_wide(path));
            media::win::show_desktop_notification(utf8_to_wide(title), utf8_to_wide(body), artifacts);
#else
            logger::info("[command-finish] " + title + (body.empty() ? std::string{} : (": " + body)));
#endif
        } catch (const std::exception& e) {
            logger::warn(std::string("[command-finish] toast: ") + e.what());
        } catch (...) {
            logger::warn("[command-finish] toast: unknown error");
        }
    }

    if (spoken.notify_tts && finish_tts_already_spoken(spoken.tts_text))
        spoken.notify_tts = false;

    if (spoken.notify_tts) {
        try {
            speak_finish_message(spoken.tts_text);
        } catch (const std::exception& e) {
            logger::warn(std::string("[command-finish] tts: ") + e.what());
        } catch (...) {
            logger::warn("[command-finish] tts: unknown error");
        }
    }

    try {
        apply_finish_open_actions(spoken);
    } catch (const std::exception& e) {
        logger::warn(std::string("[command-finish] open: ") + e.what());
    } catch (...) {
        logger::warn("[command-finish] open: unknown error");
    }

    logger::info("[command-finish] id=" + spoken.command_id
        + " cli=" + spoken.cli_path
        + " ok=" + std::string(spoken.ok ? "1" : "0")
        + " sound=" + std::string(spoken.play_sound ? "1" : "0")
        + " ui=" + std::string(spoken.notify_ui ? "1" : "0")
        + " tts=" + std::string(spoken.notify_tts ? "1" : "0")
        + " tts_text=\"" + spoken.tts_text + "\""
        + " open=" + std::string(spoken.open_file ? "1" : "0")
        + " instance=" + std::string(spoken.open_in_new_instance ? "1" : "0")
        + " artifacts=" + std::to_string(spoken.artifact_count > 0 ? spoken.artifact_count : spoken.artifact_paths.size()));
}

void notify_command_finished(const CommandFinishEvent& ev)
{
    g_finish_notified.store(true, std::memory_order_release);

    CommandFinishEvent spoken = ev;
    ensure_finish_speech(spoken);

    const bool delegate = !this_process_is_ui() && ui_host_is_listening();
    bool acked = false;
    try {
        acked = notify_ui_command_finished(spoken, delegate);
    } catch (const std::exception& e) {
        logger::warn(std::string("[command-finish] ipc: ") + e.what());
    } catch (...) {
        logger::warn("[command-finish] ipc: unknown error");
    }
    if (delegate && acked) {
        /*
        logger::trace("[command-finish] delegated to ui id=" + spoken.command_id
            + " tts=" + std::string(spoken.notify_tts ? "1" : "0")
            + " tts_text=\"" + spoken.tts_text + "\""
            + " open=" + std::string(spoken.open_file ? "1" : "0")
            + " instance=" + std::string(spoken.open_in_new_instance ? "1" : "0"));
            */
        return;
    }
    play_finish_effects(spoken);
}

void maybe_notify_command_finished(const CommandFinishEvent& ev)
{
    CommandFinishEvent next = ev;
    FinishNotifyPrefs prefs;
    if (!finish_notify_from_env(prefs))
        prefs = resolve_finish_notify(ev.command_id);
    else {
        const auto catalog = resolve_finish_notify(ev.command_id);
        if (next.label.empty())
            next.label = catalog.label;
        if (next.description.empty())
            next.description = catalog.description;
    }
    if (next.label.empty())
        next.label = prefs.label;
    if (next.description.empty())
        next.description = prefs.description;
    next.play_sound = prefs.play_sound;
    next.notify_ui  = prefs.notify_ui;
    next.notify_tts = prefs.notify_tts;
    next.open_file = prefs.open_file;
    next.open_in_new_instance = prefs.open_in_new_instance;
    const auto inv = current_cli_invocation();
    if (next.cli_path.empty())
        next.cli_path = inv.cli;
    if (next.cli_stem.empty())
        next.cli_stem = inv.stem;
    // A nested `llm agent` process has no ribbon command id. Each tool exit
    // otherwise says "agent finished".
    if (next.command_id.empty()
        && (next.cli_stem == "agent" || next.label == "agent"))
        next.notify_tts = false;
    if (next.artifact_paths.empty())
        next.artifact_paths = snapshot_run_artifacts();
    if (next.artifact_count == 0) {
        std::lock_guard<std::mutex> lock(g_artifacts_mu);
        next.artifact_count = g_artifact_total > 0 ? g_artifact_total : next.artifact_paths.size();
    }
    if (next.message.empty()) {
        const auto rows = snapshot_run_artifact_records();
        std::size_t used = 0;
        for (const auto& row : rows) {
            if (row.message.empty())
                continue;
            if (!next.message.empty())
                next.message += "\n";
            next.message += row.message;
            if (++used == 3)
                break;
        }
        if (next.artifact_count > used && used > 0) {
            next.message += "\n";
            next.message += std::to_string(next.artifact_count);
            next.message += " files";
        }
    }
    if (!next.ok && command_finish_succeeded(false, next.exit_code, next.artifact_count)) {
        logger::info("[command-finish] treating exit " + std::to_string(next.exit_code)
            + " as success artifacts=" + std::to_string(next.artifact_count));
        next.ok = true;
        next.exit_code = 0;
        next.error.clear();
    }
    logger::trace("[command-finish] maybe_notify id=" + next.command_id
        + " ok=" + std::string(next.ok ? "1" : "0")
        + " exit=" + std::to_string(next.exit_code)
        + " sound=" + std::string(next.play_sound ? "1" : "0")
        + " ui=" + std::string(next.notify_ui ? "1" : "0")
        + " tts=" + std::string(next.notify_tts ? "1" : "0")
        + " artifacts=" + std::to_string(next.artifact_count));
    notify_command_finished(next);
}

std::vector<std::string> artifact_paths_from_snapshot(const nlohmann::json& snapshot)
{
    std::vector<std::string> out;
    const nlohmann::json* rows = &snapshot;
    nlohmann::json nested;
    if (snapshot.is_object() && snapshot.contains("files") && snapshot["files"].is_array()) {
        nested = snapshot["files"];
        rows = &nested;
    }
    if (!rows->is_array())
        return out;
    out.reserve(rows->size());
    for (const auto& row : *rows) {
        if (!row.is_object() || !row.contains("path") || !row["path"].is_string())
            continue;
        std::string path = row["path"].get<std::string>();
        if (!path.empty())
            out.push_back(std::move(path));
    }
    return out;
}

void emit_run_artifact(std::string path, std::string source, std::string message)
{
    path = normalize_artifact_path(std::move(path));
    if (path.empty())
        return;
    const std::string key = artifact_key(path);
    if (key.empty())
        return;
    RunArtifactRecord inv;
    {
        std::lock_guard<std::mutex> lock(g_cli_mu);
        inv = cli_invocation_unlocked();
    }
    RunArtifactRecord rec;
    rec.path = path;
    rec.cli = inv.cli;
    rec.stem = inv.stem;
    rec.source = source.empty() ? (inv.stem.empty() ? (inv.cli.empty() ? "cli" : inv.cli) : inv.stem)
                                : std::move(source);
    rec.message = message.empty() ? default_artifact_message(path, inv) : std::move(message);

    const std::string parent = parent_dir_of(path);
    const std::string parent_key = artifact_key(parent);

    bool live = false;
    bool persist = false;
    RunArtifactRecord extra;
    bool have_extra = false;
    {
        std::lock_guard<std::mutex> lock(g_artifacts_mu);
        if (!g_artifact_keys.insert(key).second)
            return;
        ++g_artifact_total;

        bool collapsed = false;
        if (!parent_key.empty()) {
            for (const auto& p : g_collapsed_parents) {
                if (path_under_parent(path, p)) {
                    collapsed = true;
                    g_parent_counts[p] += 1;
                    break;
                }
            }
        }
        if (collapsed)
            return;

        if (!parent_key.empty())
            g_parent_counts[parent_key] += 1;

        if (g_artifacts.size() < kBagCap)
            g_artifacts.push_back(rec);

        live = allow_live_notify_locked();
        persist = g_persist_sent < kPersistCap;

        if (!parent_key.empty() && g_parent_counts[parent_key] == kCollapseAfter
            && g_collapsed_parents.insert(parent_key).second) {
            extra = rec;
            extra.path = parent;
            extra.message = (rec.cli.empty() ? rec.source : rec.cli)
                + " → " + (file_leaf(parent).empty() ? parent : file_leaf(parent))
                + " (" + std::to_string(g_parent_counts[parent_key]) + " files)";
            if (g_artifact_keys.insert(parent_key).second && g_artifacts.size() < kBagCap) {
                g_collapse_row[parent_key] = g_artifacts.size();
                g_artifacts.push_back(extra);
            } else if (const auto it = g_collapse_row.find(parent_key); it == g_collapse_row.end()) {
                g_collapse_row[parent_key] = g_artifacts.size();
                if (g_artifacts.size() < kBagCap)
                    g_artifacts.push_back(extra);
            }
            have_extra = true;
            live = true;
            persist = g_persist_sent < kPersistCap;
        }
    }

    fanout_artifact(rec, inv.message, live, persist);
    if (have_extra)
        fanout_artifact(extra, inv.message, true, persist);
}

std::vector<std::string> snapshot_run_artifacts()
{
    std::lock_guard<std::mutex> lock(g_artifacts_mu);
    refresh_collapse_messages_locked();
    std::vector<std::string> folders;
    std::vector<std::string> files;
    folders.reserve(g_collapse_row.size());
    files.reserve(g_artifacts.size());
    for (const auto& rec : g_artifacts) {
        if (g_collapsed_parents.count(artifact_key(rec.path)))
            folders.push_back(rec.path);
        else
            files.push_back(rec.path);
    }
    folders.insert(folders.end(), files.begin(), files.end());
    if (folders.size() > kToastPaths)
        folders.resize(kToastPaths);
    return folders;
}

std::vector<RunArtifactRecord> snapshot_run_artifact_records()
{
    std::lock_guard<std::mutex> lock(g_artifacts_mu);
    refresh_collapse_messages_locked();
    return g_artifacts;
}


void notify_cli_process_finished(int exit_code)
{
    if (g_finish_notified.load(std::memory_order_acquire)) {
        logger::trace("[command-finish] cli process already notified exit="
            + std::to_string(exit_code));
        return;
    }
    logger::trace("[command-finish] cli process finished exit=" + std::to_string(exit_code));
    CommandFinishEvent ev;
    if (const char* cid = std::getenv("PM_IMAGE_COMMAND_ID"); cid && *cid)
        ev.command_id = cid;
    const auto inv = current_cli_invocation();
    ev.cli_path = inv.cli;
    ev.cli_stem = inv.stem;
    ev.artifact_paths = snapshot_run_artifacts();
    {
        std::lock_guard<std::mutex> lock(g_artifacts_mu);
        ev.artifact_count = g_artifact_total;
    }
    ev.ok = command_finish_succeeded(exit_code == 0, exit_code, ev.artifact_count);
    ev.exit_code = ev.ok ? 0 : exit_code;
    maybe_notify_command_finished(ev);
}

bool command_exit_succeeded(int exit_code)
{
    return exit_code == 0 || exit_code == 130;
}

bool command_child_process_succeeded(int exit_code)
{
    if (command_exit_succeeded(exit_code))
        return true;
    const auto u = static_cast<unsigned>(exit_code);
    if (u == 0xC000013Au)
        return true;
    if ((u & 0xC0000000u) == 0xC0000000u)
        return false;
    return exit_code == 1 || exit_code == -1;
}

bool command_finish_succeeded(bool reported_ok, int exit_code, std::size_t artifact_count)
{
    if (reported_ok || command_exit_succeeded(exit_code))
        return true;
    return artifact_count > 0 && (exit_code == 1 || exit_code < 0);
}

nlohmann::json normalize_output_artifact_row(nlohmann::json row)
{
    return normalize_row_unlocked(std::move(row));
}

} // namespace media::commands
