#include "settings/settings_runtime.hpp"
#include "fs/path_sanitizer.hpp"
#include "ui_defaults.hpp"

#include "settings/chat_settings_schema.hpp"
#include "settings/settings_store.hpp"
#include "logging/pm_log.hpp"
#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
#include "policy/app_policy.hpp"
#endif
#include "lib/pm_zitadel_oauth.hpp"
#include "lib/provider_oauth.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <nlohmann/json.hpp>
#include "string/string_utils.hpp"

namespace fs = std::filesystem;

namespace media::runtime_settings {

namespace {

std::optional<fs::path> g_command_json_path_override;
std::mutex              g_command_override_mutex;
std::string             g_command_override_cache;
fs::file_time_type      g_command_override_mtime{};
bool                    g_command_override_cache_valid = false;
std::mutex              g_logging_dir_mutex;
std::optional<fs::path> g_logging_dir_override;
std::optional<fs::path> g_default_logging_dir;
bool                      g_cli_cwd_explicit = false;
std::mutex              g_chat_launch_mutex;
ChatLaunchOverrides     g_chat_launch_overrides;


std::string ascii_lower_trim(std::string s) {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n'))
        ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n'))
        --e;
    return media::strutil::lower_ascii(s.substr(b, e - b));
}

void dedupe_lower_trim(std::vector<std::string>& inout);

const ProviderEntry* find_provider_ci(const ProviderMap& providers, const std::string& provider) {
    if (provider.empty())
        return nullptr;
    const std::string needle = media::strutil::lower_ascii(provider);
    for (const auto& kv : providers) {
        if (media::strutil::lower_ascii(kv.first) == needle)
            return &kv.second;
    }
    return nullptr;
}

void dedupe_lower_trim(std::vector<std::string>& inout)
{
    std::unordered_set<std::string> seen;
    std::vector<std::string> out;
    out.reserve(inout.size());
    for (std::string s : inout) {
        size_t b = 0;
        while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n'))
            ++b;
        size_t e = s.size();
        while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n'))
            --e;
        s = s.substr(b, e - b);
        if (s.empty())
            continue;
        s = media::strutil::lower_ascii(std::move(s));
        if (seen.insert(s).second)
            out.push_back(std::move(s));
    }
    inout = std::move(out);
}

bool read_utf8_file(const fs::path& path, std::string& out_json, std::string& err)
{
    out_json.clear();
    err.clear();
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        err = "failed to open commands file: " + media::path::path_to_utf8(path);
        return false;
    }
    out_json.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

std::string logging_session_dir_name()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#if defined(_WIN32)
    if (localtime_s(&tm_buf, &t) != 0)
        tm_buf = {};
#else
    if (const std::tm* local = std::localtime(&t))
        tm_buf = *local;
#endif
    std::ostringstream os;
    os << "session-" << std::put_time(&tm_buf, "%m-%d-%H-%M-%S");
    return os.str();
}

std::string iso8601_utc_now()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#if defined(_WIN32)
    if (gmtime_s(&tm_buf, &t) != 0)
        tm_buf = {};
#else
    if (const std::tm* utc = std::gmtime(&t))
        tm_buf = *utc;
#endif
    std::ostringstream os;
    os << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return os.str();
}

fs::path make_default_logging_dir_unlocked()
{
    if (g_logging_dir_override)
        return *g_logging_dir_override;
    if (g_default_logging_dir)
        return *g_default_logging_dir;

    fs::path base;
    try {
        base = media::settings::get_config_dir() / "sessions";
    } catch (...) {
        base = media::path::path_from_utf8("sessions");
    }

    fs::path dir = base / logging_session_dir_name();
    std::error_code ec;
    for (int i = 2; fs::exists(dir, ec) && i < 1000; ++i)
        dir = base / (logging_session_dir_name() + "-" + std::to_string(i));
    fs::create_directories(dir, ec);
    g_default_logging_dir = dir;
    return dir;
}

} // namespace

bool load_chat_provider(ChatProviderSettings& out, std::string& err) {
    return media::settings::load_chat_provider(out, err);
}

bool save_chat_provider(const ChatProviderSettings& in, std::string& err) {
    return media::settings::save_chat_provider(in, err);
}

bool load_selected_chat_preset_id(std::string& out, std::string& err) {
    out.clear();
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        return true;
    if (custom.contains("selected_chat_preset_id") && custom["selected_chat_preset_id"].is_string())
        out = custom["selected_chat_preset_id"].get<std::string>();
    return true;
}

bool save_selected_chat_preset_id(const std::string& id, std::string& err) {
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    if (id.empty())
        custom.erase("selected_chat_preset_id");
    else
        custom["selected_chat_preset_id"] = id;
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool apply_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out, std::string& err) {
    if (!resolve_chat_provider_preset(id_or_name, out, err))
        return false;
    if (!save_chat_provider(out.chat, err))
        return false;
    const std::string key = media::settings_schema::chat_preset_select_key(out);
    return save_selected_chat_preset_id(key, err);
}

bool load_chat_provider_presets(std::vector<ChatProviderPreset>& out, std::string& err) {
    out.clear();
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        return true;
    const nlohmann::json* presets = custom.contains("settings_chat_presets")
        ? &custom["settings_chat_presets"]
        : nullptr;
    if (!presets || !presets->is_array())
        return true;
    for (const auto& item : *presets) {
        ChatProviderPreset p;
        if (media::settings_schema::chat_provider_preset_from_json(item, p))
            out.push_back(std::move(p));
    }
    return true;
}

bool find_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out, std::string& err) {
    const std::string needle = ascii_lower_trim(id_or_name);
    if (needle.empty()) {
        err = "empty chat preset name";
        return false;
    }
    std::vector<ChatProviderPreset> presets;
    if (!load_chat_provider_presets(presets, err))
        return false;
    for (const auto& p : presets) {
        if (ascii_lower_trim(p.id) == needle || ascii_lower_trim(p.name) == needle) {
            out = p;
            return true;
        }
    }
    err = "chat preset not found: " + id_or_name;
    return false;
}

bool resolve_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out, std::string& err) {
    out = ChatProviderPreset{};
    std::vector<ChatProviderPreset> presets;
    if (!load_chat_provider_presets(presets, err))
        return false;
    std::string select_err;
    if (const auto* preset = media::settings_schema::select_chat_provider_preset(presets, id_or_name, &select_err)) {
        out = *preset;
        err.clear();
        return true;
    }
    err = select_err;
    return false;
}

bool save_chat_provider_preset(ChatProviderPreset preset, bool& changed, std::string& err) {
    changed = false;
    preset.name = ascii_lower_trim(preset.name).empty() ? preset.id : preset.name;
    if (preset.name.empty()) {
        err = "empty chat preset name";
        return false;
    }
    if (preset.id.empty()) {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        preset.id = "chat-preset-cli-" + std::to_string(ms);
    }

    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    nlohmann::json presets = nlohmann::json::array();
    if (custom.contains("settings_chat_presets") && custom["settings_chat_presets"].is_array())
        presets = custom["settings_chat_presets"];

    const std::string id_key = ascii_lower_trim(preset.id);
    const std::string name_key = ascii_lower_trim(preset.name);
    nlohmann::json serialized = media::settings_schema::chat_provider_preset_json(preset);
    bool replaced = false;
    for (auto& item : presets) {
        if (!item.is_object())
            continue;
        const std::string item_id = item.value("id", std::string{});
        const std::string item_name = item.value("name", std::string{});
        if ((!id_key.empty() && ascii_lower_trim(item_id) == id_key) || ascii_lower_trim(item_name) == name_key) {
            if (!item_id.empty() && ascii_lower_trim(item_id) != id_key)
                serialized["id"] = item_id;
            if (item != serialized) {
                item = serialized;
                changed = true;
            }
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        presets.push_back(serialized);
        changed = true;
    }

    // Single-default invariant: when the incoming preset is_default, strip the flag from every
    // other stored preset so exactly one entry resolves as default. We do this AFTER insertion so
    // the just-written entry is the one survivor.
    if (preset.is_default) {
        for (auto& item : presets) {
            if (!item.is_object())
                continue;
            const std::string item_id = item.value("id", std::string{});
            const std::string item_name = item.value("name", std::string{});
            const bool same = (!id_key.empty() && ascii_lower_trim(item_id) == id_key)
                || ascii_lower_trim(item_name) == name_key;
            if (same)
                continue;
            const bool had = item.value("is_default", false) || item.value("isDefault", false);
            if (had) {
                item.erase("is_default");
                item.erase("isDefault");
                changed = true;
            }
        }
    }

    if (!changed)
        return true;

    custom["settings_chat_presets"] = std::move(presets);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool load_providers(ProviderMap& out, std::string& err) {
    return media::settings::load_providers(out, err);
}

bool load_command_json_utf8(std::string& out_json, std::string& err) {
    std::lock_guard<std::mutex> lock(g_command_override_mutex);
    if (g_command_json_path_override.has_value()) {
        std::error_code ec;
        const auto mtime = fs::last_write_time(*g_command_json_path_override, ec);
        if (g_command_override_cache_valid && !ec && mtime == g_command_override_mtime) {
            out_json = g_command_override_cache;
            err.clear();
            return true;
        }
        if (!read_utf8_file(*g_command_json_path_override, out_json, err))
            return false;
        g_command_override_cache = out_json;
        g_command_override_mtime = mtime;
        g_command_override_cache_valid = !ec;
        return true;
    }
    return media::settings::load_command_json_utf8(out_json, err);
}

bool save_command_json_utf8(const std::string& utf8_json, std::string& err) {
    return media::settings::save_command_json_utf8(utf8_json, err);
}

bool update_command_json_utf8(const std::function<bool(std::string& utf8_json, std::string& err)>& mutate,
                              std::string& err) {
    return media::settings::update_command_json_utf8(mutate, err);
}

void set_command_json_path_override(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_command_override_mutex);
    g_command_override_cache.clear();
    g_command_override_cache_valid = false;
    if (path.empty()) {
        g_command_json_path_override.reset();
    } else {
        g_command_json_path_override = fs::absolute(media::path::path_from_utf8(path));
    }
}

std::filesystem::path effective_command_document_path() {
    std::lock_guard<std::mutex> lock(g_command_override_mutex);
    if (g_command_json_path_override.has_value())
        return *g_command_json_path_override;
    return media::settings::get_command_json_path();
}

std::filesystem::path effective_command_watch_path() {
    std::lock_guard<std::mutex> lock(g_command_override_mutex);
    if (g_command_json_path_override.has_value())
        return *g_command_json_path_override;
    return media::settings::command_cache_watch_path();
}

void apply_cli_config_dir_override(const std::string& explicit_config_dir) {
    if (!explicit_config_dir.empty()) {
        std::error_code ec;
        fs::path dir = fs::absolute(media::path::path_from_utf8(explicit_config_dir), ec);
        if (ec)
            dir = media::path::path_from_utf8(explicit_config_dir);
        fs::create_directories(dir, ec);
        media::settings::set_config_dir_override(dir);
        return;
    }
    media::settings::maybe_auto_set_config_dir_from_exe_roaming();
}

std::filesystem::path default_logging_dir() {
    std::lock_guard<std::mutex> lock(g_logging_dir_mutex);
    const fs::path dir = make_default_logging_dir_unlocked();
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

namespace {

std::string sanitize_scheduler_id(std::string_view id)
{
    std::string out;
    out.reserve(id.size());
    for (unsigned char c : id) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '.' || c == '-')
            out.push_back(static_cast<char>(c));
        else
            out.push_back('_');
    }
    if (out.empty())
        out = "command";
    return out;
}

fs::path scheduler_dir_for(const fs::path& config_dir)
{
    return config_dir / "run-ipc" / "scheduler";
}

} // namespace

std::filesystem::path scheduler_dir(const std::filesystem::path& config_dir)
{
    return scheduler_dir_for(config_dir);
}

std::filesystem::path scheduler_dir()
{
    return scheduler_dir_for(media::settings::get_config_dir());
}

std::filesystem::path scheduler_state_path(const std::filesystem::path& config_dir)
{
    return scheduler_dir_for(config_dir) / "state.json";
}

std::filesystem::path scheduler_state_path()
{
    return scheduler_state_path(media::settings::get_config_dir());
}

std::filesystem::path scheduler_leader_lock_path(const std::filesystem::path& config_dir)
{
    return scheduler_dir_for(config_dir) / "leader.lock";
}

std::filesystem::path scheduler_leader_lock_path()
{
    return scheduler_leader_lock_path(media::settings::get_config_dir());
}

std::filesystem::path scheduler_claim_path(const std::filesystem::path& config_dir)
{
    return scheduler_dir_for(config_dir) / "claim.json";
}

std::filesystem::path scheduler_claim_path()
{
    return scheduler_claim_path(media::settings::get_config_dir());
}

std::filesystem::path scheduler_command_lease_path(const std::filesystem::path& config_dir,
                                                   std::string_view command_id)
{
    return scheduler_dir_for(config_dir) / "leases" / (sanitize_scheduler_id(command_id) + ".lock");
}

std::filesystem::path scheduler_command_lease_path(std::string_view command_id)
{
    return scheduler_command_lease_path(media::settings::get_config_dir(), command_id);
}

void set_default_logging_dir_override(const std::filesystem::path& dir) {
    std::lock_guard<std::mutex> lock(g_logging_dir_mutex);
    if (dir.empty()) {
        g_logging_dir_override.reset();
        g_default_logging_dir.reset();
        return;
    }
    std::error_code ec;
    fs::path abs = fs::absolute(dir, ec);
    if (ec)
        abs = dir;
    fs::create_directories(abs, ec);
    g_logging_dir_override = abs;
    g_default_logging_dir.reset();
}

std::filesystem::path effective_temp_dir() {
#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    const std::string forced = pm::policy::policy_temp_dir();
    if (!forced.empty()) {
        fs::path dir(forced);
        std::error_code ec;
        fs::create_directories(dir, ec);
        return dir;
    }
#endif
    return media::ui_defaults::effective_user_temp_dir();
}

void set_cli_cwd_explicit(bool explicit_cwd) {
    g_cli_cwd_explicit = explicit_cwd;
}

bool cli_cwd_explicit() {
    return g_cli_cwd_explicit;
}

std::filesystem::path implicit_tool_output_base() {
    if (g_cli_cwd_explicit) {
        std::error_code ec;
        const fs::path cwd = fs::current_path(ec);
        if (!ec && !cwd.empty())
            return cwd;
    }
    return effective_temp_dir();
}

void merge_provider_credentials(const std::string& provider,
                                bool dry_run,
                                std::string& api_key,
                                std::string& base_url) {
    if (dry_run || provider.empty())
        return;

    const std::string provider_lc = media::strutil::lower_ascii(provider);

    // Load settings first so auth_mode is available for priority decisions.
    ProviderMap providers;
    std::string err;
    (void)load_providers(providers, err);
    const ProviderEntry* row = find_provider_ci(providers, provider);

    // Always fill base_url from settings when not already set.
    // Hugging Face Hub token lives on https://huggingface.co; the chat router
    // "huggingface" uses api-inference.huggingface.co instead. Never copy the
    // Hub origin into LLM base_url.
    if (base_url.empty() && row && !row->base_url.empty() && provider_lc != "huggingface")
        base_url = row->base_url;

    // Tanit: ZITADEL token wins; settings api_key is fallback.
    if (provider_lc == "tanit") {
#if defined(FEATURE_TANIT_AUTH) && FEATURE_TANIT_AUTH
        if (api_key.empty()) {
            std::string token, terr;
            if (pm_zitadel_oauth_read_access_token(token, terr) && !token.empty())
                api_key = std::move(token);
        }
#endif
        if (api_key.empty() && row && !row->api_key.empty())
            api_key = row->api_key;
        return;
    }

    // auth_mode controls credential priority for all other providers.
    const std::string mode = (row && !row->auth_mode.empty()) ? row->auth_mode : "auto";

    if (mode == "oauth") {
        // OAuth-only: use OAuth token, ignore settings api_key.
        if (api_key.empty() && media::provider_oauth::is_supported_provider(provider_lc)) {
            std::string token, terr;
            if (media::provider_oauth::read_access_token(provider_lc, token, terr) && !token.empty())
                api_key = std::move(token);
        }
    } else if (mode == "api_key") {
        // API key only: use settings key, ignore OAuth token.
        if (api_key.empty() && row && !row->api_key.empty())
            api_key = row->api_key;
    } else {
        // auto: settings api_key wins; OAuth is fallback.
        if (api_key.empty() && row && !row->api_key.empty())
            api_key = row->api_key;
        if (api_key.empty() && media::provider_oauth::is_supported_provider(provider_lc)) {
            std::string token, terr;
            if (media::provider_oauth::read_access_token(provider_lc, token, terr) && !token.empty())
                api_key = std::move(token);
        }
    }

    if (provider_lc == "openai" || provider_lc == "openrouter") {
        const bool settings_has_key = row && !row->api_key.empty();
        const char* source = "none";
        if (!api_key.empty())
            source = (settings_has_key && api_key == row->api_key) ? "settings" : "oauth";
        logger::debug(provider_lc + " creds: mode=" + mode
            + " source=" + source
            + " settings_key_len=" + std::to_string(settings_has_key ? row->api_key.size() : 0)
            + " resolved_len=" + std::to_string(api_key.size())
            + " base_url=" + (base_url.empty() ? "(default)" : base_url));
    }
}

void update_tanit_api_key(const std::string& api_key, std::string& err) {
    err.clear();
    ProviderMap providers;
    if (!media::settings::load_providers(providers, err))
        return;

    auto& row = providers["tanit"];
    row.api_key = api_key;

    media::settings::save_providers(providers, err);
}

bool append_cms_history_entry(const nlohmann::json& entry, std::string& err, size_t max_entries)
{
    err.clear();
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();

    nlohmann::json cms = custom.contains("cms") && custom["cms"].is_object()
        ? custom["cms"]
        : nlohmann::json::object();
    nlohmann::json history = cms.contains("history") && cms["history"].is_array()
        ? cms["history"]
        : nlohmann::json::array();

    nlohmann::json row = entry.is_object() ? entry : nlohmann::json::object({{"value", entry}});
    if (!row.contains("published_at"))
        row["published_at"] = iso8601_utc_now();
    history.push_back(std::move(row));
    while (max_entries > 0 && history.size() > max_entries)
        history.erase(history.begin());

    cms["history"] = std::move(history);
    custom["cms"]  = std::move(cms);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool load_global_tool_settings(GlobalToolSettings& out, std::string& err)
{
    out = GlobalToolSettings{};
    nlohmann::json node;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, node, err))
        return false;
    if (!node.is_object())
        return true;
    const auto& g = node.contains("global_tools") ? node["global_tools"] : nlohmann::json();
    if (!g.is_object())
        return true;
    media::settings_schema::apply_global_tool_settings_json(g, out);
    return true;
}

bool save_global_tool_settings(const GlobalToolSettings& in, std::string& err)
{
    GlobalToolSettings c = in;
    dedupe_lower_trim(c.disabled_path_tools);
    dedupe_lower_trim(c.disabled_mcp_servers);
    nlohmann::json g = media::settings_schema::global_tool_settings_json(c);
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    custom["global_tools"] = std::move(g);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool load_agent_skills_settings(AgentSkillsSettings& out, std::string& err)
{
    out = AgentSkillsSettings{};
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        return true;
    const auto& g = custom.contains("agent_skills") ? custom["agent_skills"] : nlohmann::json();
    if (!g.is_object())
        return true;
    media::settings_schema::apply_agent_skills_settings_json(g, out);
    return true;
}

namespace {

std::string normalize_recall_profile(std::string raw)
{
    raw = media::strutil::lower_ascii(std::move(raw));
    while (!raw.empty() && raw.front() == ' ') raw.erase(raw.begin());
    while (!raw.empty() && raw.back() == ' ') raw.pop_back();
    if (raw == "off" || raw == "lexical" || raw == "hybrid" || raw == "shadow")
        return raw;
    return "hybrid";
}

std::string normalize_richness(std::string raw)
{
    raw = media::strutil::lower_ascii(std::move(raw));
    while (!raw.empty() && raw.front() == ' ') raw.erase(raw.begin());
    while (!raw.empty() && raw.back() == ' ') raw.pop_back();
    if (raw == "concise" || raw == "balanced" || raw == "rich")
        return raw;
    return "balanced";
}

} // namespace

bool load_agent_memory_settings(AgentMemorySettings& out, std::string& err)
{
    out = AgentMemorySettings{};
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        return true;
    const auto& g = custom.contains("agent_memory") ? custom["agent_memory"] : nlohmann::json();
    if (!g.is_object())
        return true;
    if (g.contains("recall_profile") && g["recall_profile"].is_string())
        out.recall_profile = normalize_recall_profile(g["recall_profile"].get<std::string>());
    if (g.contains("richness") && g["richness"].is_string())
        out.richness = normalize_richness(g["richness"].get<std::string>());
    if (g.contains("dense_budget_ms") && g["dense_budget_ms"].is_number_integer())
        out.dense_budget_ms = g["dense_budget_ms"].get<std::int64_t>();
    return true;
}

bool save_agent_memory_settings(const AgentMemorySettings& in, std::string& err)
{
    AgentMemorySettings c = in;
    c.recall_profile = normalize_recall_profile(std::move(c.recall_profile));
    c.richness = normalize_richness(std::move(c.richness));
    if (c.dense_budget_ms < 0)
        c.dense_budget_ms = 0;
    nlohmann::json g{
        {"recall_profile", c.recall_profile},
        {"richness", c.richness},
        {"dense_budget_ms", c.dense_budget_ms},
    };
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    custom["agent_memory"] = std::move(g);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool save_agent_skills_settings(const AgentSkillsSettings& in, std::string& err)
{
    AgentSkillsSettings c = in;
    dedupe_lower_trim(c.pinned);
    dedupe_lower_trim(c.disabled);
    nlohmann::json g = media::settings_schema::agent_skills_settings_json(c);
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    // VFS skill roots are provider declarations managed independently from
    // the basic skills toggle UI. Preserve them when that UI saves policy.
    if (custom.contains("agent_skills") && custom["agent_skills"].is_object()
        && custom["agent_skills"].contains("vfs_roots"))
        g["vfs_roots"] = custom["agent_skills"]["vfs_roots"];
    custom["agent_skills"] = std::move(g);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool load_audio_video_device_settings(AudioVideoDeviceSettings& out, std::string& err)
{
    out = AudioVideoDeviceSettings{};
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        return true;
    const auto& g = custom.contains("audio_video_devices")
        ? custom["audio_video_devices"]
        : nlohmann::json();
    if (!g.is_object())
        return true;
    if (g.contains("audio_input_device") && g["audio_input_device"].is_string())
        out.audio_input_device = g["audio_input_device"].get<std::string>();
    if (g.contains("audio_output_device") && g["audio_output_device"].is_string())
        out.audio_output_device = g["audio_output_device"].get<std::string>();
    if (g.contains("video_capture_device") && g["video_capture_device"].is_string())
        out.video_capture_device = g["video_capture_device"].get<std::string>();
    if (g.contains("audio_input_source") && g["audio_input_source"].is_string()) {
        const std::string source = g["audio_input_source"].get<std::string>();
        if (source == "mic" || source == "desktop" || source == "mix")
            out.audio_input_source = source;
    }
    if (g.contains("desktop_audio_device") && g["desktop_audio_device"].is_string())
        out.desktop_audio_device = g["desktop_audio_device"].get<std::string>();
    if (g.contains("mic_gain") && g["mic_gain"].is_number()) {
        const float gain = g["mic_gain"].get<float>();
        if (std::isfinite(gain)) out.mic_gain = std::clamp(gain, 0.0f, 4.0f);
    }
    if (g.contains("desktop_gain") && g["desktop_gain"].is_number()) {
        const float gain = g["desktop_gain"].get<float>();
        if (std::isfinite(gain)) out.desktop_gain = std::clamp(gain, 0.0f, 4.0f);
    }
    if (g.contains("absent_policy") && g["absent_policy"].is_string()) {
        out.absent_policy = g["absent_policy"].get<std::string>() == "fail"
            ? DeviceAbsentPolicy::fail
            : DeviceAbsentPolicy::fallback_to_default;
    }
    return true;
}

bool save_audio_video_device_settings(const AudioVideoDeviceSettings& in, std::string& err)
{
    nlohmann::json g = nlohmann::json::object();
    g["audio_input_device"]   = in.audio_input_device;
    g["audio_output_device"]  = in.audio_output_device;
    g["video_capture_device"] = in.video_capture_device;
    g["audio_input_source"]   =
        (in.audio_input_source == "desktop" || in.audio_input_source == "mix")
            ? in.audio_input_source : "mic";
    g["desktop_audio_device"] = in.desktop_audio_device;
    g["mic_gain"]             = std::isfinite(in.mic_gain)
        ? std::clamp(in.mic_gain, 0.0f, 4.0f) : 1.0f;
    g["desktop_gain"]         = std::isfinite(in.desktop_gain)
        ? std::clamp(in.desktop_gain, 0.0f, 4.0f) : 1.0f;
    g["absent_policy"] = (in.absent_policy == DeviceAbsentPolicy::fail)
        ? "fail"
        : "fallback_to_default";
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    custom["audio_video_devices"] = std::move(g);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

namespace {

std::string voice_route_token(std::string value)
{
    value = media::strutil::lower_ascii(std::move(value));
    return (value == "agent") ? "agent" : "trigger";
}

std::string voice_filter_token(std::string value)
{
    value = media::strutil::lower_ascii(std::move(value));
    if (value == "off" || value == "deepfilter" || value == "gtcrn")
        return value;
    return "auto";
}

std::string voice_backend_token(std::string value)
{
    value = media::strutil::lower_ascii(std::move(value));
    return (value == "cpu") ? "cpu" : "gpu";
}

} // namespace

bool load_voice_command_settings(VoiceCommandSettings& out, std::string& err)
{
    out = VoiceCommandSettings{};
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        return true;
    const auto& g = custom.contains("voice_commands")
        ? custom["voice_commands"]
        : nlohmann::json();
    if (!g.is_object())
        return true;
    if (g.contains("enabled") && g["enabled"].is_boolean())
        out.enabled = g["enabled"].get<bool>();
    if (g.contains("wake_phrase") && g["wake_phrase"].is_string())
        out.wake_phrase = g["wake_phrase"].get<std::string>();
    else if (g.contains("wakePhrase") && g["wakePhrase"].is_string())
        out.wake_phrase = g["wakePhrase"].get<std::string>();
    if (g.contains("route") && g["route"].is_string())
        out.route = voice_route_token(g["route"].get<std::string>());
    if (g.contains("filter") && g["filter"].is_string())
        out.filter = voice_filter_token(g["filter"].get<std::string>());
    if (g.contains("filter_model") && g["filter_model"].is_string())
        out.filter_model = g["filter_model"].get<std::string>();
    else if (g.contains("filterModel") && g["filterModel"].is_string())
        out.filter_model = g["filterModel"].get<std::string>();
    if (g.contains("post_filter") && g["post_filter"].is_boolean())
        out.post_filter = g["post_filter"].get<bool>();
    else if (g.contains("postFilter") && g["postFilter"].is_boolean())
        out.post_filter = g["postFilter"].get<bool>();
    if (g.contains("filter_blend") && g["filter_blend"].is_number())
        out.filter_blend = g["filter_blend"].get<float>();
    else if (g.contains("filterBlend") && g["filterBlend"].is_number())
        out.filter_blend = g["filterBlend"].get<float>();
    if (!(out.filter_blend >= 0.0f))
        out.filter_blend = 0.0f;
    else if (out.filter_blend > 1.0f)
        out.filter_blend = 1.0f;
    if (g.contains("provider") && g["provider"].is_string())
        out.provider = g["provider"].get<std::string>();
    if (g.contains("model") && g["model"].is_string())
        out.model = g["model"].get<std::string>();
    if (g.contains("language") && g["language"].is_string()) {
        const std::string language = g["language"].get<std::string>();
        if (!language.empty())
            out.language = language;
    }
    if (g.contains("backend") && g["backend"].is_string())
        out.backend = voice_backend_token(g["backend"].get<std::string>());
    if (g.contains("audio_input_device") && g["audio_input_device"].is_string())
        out.audio_input_device = g["audio_input_device"].get<std::string>();
    else if (g.contains("audioInputDevice") && g["audioInputDevice"].is_string())
        out.audio_input_device = g["audioInputDevice"].get<std::string>();
    return true;
}

bool save_voice_command_settings(const VoiceCommandSettings& in, std::string& err)
{
    nlohmann::json g = nlohmann::json::object();
    g["enabled"] = in.enabled;
    g["wake_phrase"] = in.wake_phrase;
    g["route"] = voice_route_token(in.route);
    g["filter"] = voice_filter_token(in.filter);
    g["filter_model"] = in.filter_model;
    g["post_filter"] = in.post_filter;
    const float blend = in.filter_blend;
    g["filter_blend"] = (!(blend >= 0.0f) ? 0.0f : (blend > 1.0f ? 1.0f : blend));
    g["provider"] = in.provider;
    g["model"] = in.model;
    g["language"] = in.language.empty() ? "auto" : in.language;
    g["backend"] = voice_backend_token(in.backend);
    g["audio_input_device"] = in.audio_input_device;
    nlohmann::json custom;
    if (!media::settings::load_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err))
        return false;
    if (!custom.is_object())
        custom = nlohmann::json::object();
    custom["voice_commands"] = std::move(g);
    return media::settings::save_subtree(media::settings::SettingsSubtreeKeys::custom, custom, err);
}

bool load_sound_notifications_enabled(bool& out, std::string& err)
{
    out = false;
    err.clear();
    media::settings::SettingsRootSnapshot root;
    if (!media::settings::load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (j.contains("workbench") && j["workbench"].is_object()
            && j["workbench"].contains("sound_notifications_enabled")
            && j["workbench"]["sound_notifications_enabled"].is_boolean()) {
            out = j["workbench"]["sound_notifications_enabled"].get<bool>();
        }
    } catch (const std::exception& ex) {
        err = std::string("load_sound_notifications_enabled: ") + ex.what();
        return false;
    }
    return true;
}

bool save_sound_notifications_enabled(bool enabled, std::string& err)
{
    return media::settings::merge_subtree_object(
        "workbench",
        nlohmann::json{{"sound_notifications_enabled", enabled}},
        err);
}

bool load_bookmarks(std::vector<BookmarkItem>& out, std::string& err)
{
    std::vector<media::settings::BookmarkItem> settings_rows;
    if (!media::settings::load_bookmarks(settings_rows, err))
        return false;
    out.clear();
    out.reserve(settings_rows.size());
    for (const auto& row : settings_rows) {
        BookmarkItem item;
        item.kind = row.kind;
        item.node_kind = row.node_kind;
        item.path = row.path;
        item.label = row.label;
        item.searchable = row.searchable;
        item.share = row.share;
        out.push_back(std::move(item));
    }
    return true;
}

bool save_bookmarks(const std::vector<BookmarkItem>& in, std::string& err)
{
    std::vector<media::settings::BookmarkItem> settings_rows;
    settings_rows.reserve(in.size());
    for (const auto& row : in) {
        media::settings::BookmarkItem item;
        item.kind = row.kind;
        item.node_kind = row.node_kind;
        item.path = row.path;
        item.label = row.label;
        item.searchable = row.searchable;
        item.share = row.share;
        settings_rows.push_back(std::move(item));
    }
    return media::settings::save_bookmarks(settings_rows, err);
}

bool load_visited_files(std::vector<VisitedFileEntry>& out, std::string& err)
{
    std::vector<media::settings::VisitedFileEntry> settings_rows;
    if (!media::settings::load_visited_files(settings_rows, err))
        return false;
    out.clear();
    out.reserve(settings_rows.size());
    for (const auto& row : settings_rows) {
        VisitedFileEntry item;
        item.path = row.path;
        item.visited_at = row.visited_at;
        item.workbench = row.workbench;
        out.push_back(std::move(item));
    }
    return true;
}

bool save_visited_files(const std::vector<VisitedFileEntry>& in, std::string& err)
{
    std::vector<media::settings::VisitedFileEntry> settings_rows;
    settings_rows.reserve(in.size());
    for (const auto& row : in) {
        media::settings::VisitedFileEntry item;
        item.path = row.path;
        item.visited_at = row.visited_at;
        item.workbench = row.workbench;
        settings_rows.push_back(std::move(item));
    }
    return media::settings::save_visited_files(settings_rows, err);
}

bool load_command_palette_recent(std::vector<std::string>& out, std::string& err)
{
    return media::settings::load_command_palette_recent(out, err);
}

bool save_command_palette_recent(const std::vector<std::string>& ids, std::string& err)
{
    return media::settings::save_command_palette_recent(ids, err);
}

bool touch_command_palette_recent(const std::string& commandId,
                                  std::string& err,
                                  std::size_t max_entries)
{
    if (commandId.empty())
        return true;
    std::vector<std::string> ids;
    if (!load_command_palette_recent(ids, err))
        return false;
    ids.erase(std::remove(ids.begin(), ids.end(), commandId), ids.end());
    ids.insert(ids.begin(), commandId);
    if (max_entries > 0 && ids.size() > max_entries)
        ids.resize(max_entries);
    return save_command_palette_recent(ids, err);
}

bool load_xblox_artifacts(nlohmann::json& out, std::string& err)
{
    return media::settings::load_xblox_artifacts(out, err);
}

bool append_xblox_artifact_entries(const nlohmann::json& entries,
                                   std::string& err,
                                   std::size_t max_entries)
{
    return media::settings::append_xblox_artifact_entries(entries, err, max_entries);
}

std::string resolve_audio_input_device(const std::string& cli_override,
                                       const AudioVideoDeviceSettings& avs)
{
    if (!cli_override.empty()) return cli_override;
    return avs.audio_input_device;
}

std::string resolve_audio_output_device(const std::string& cli_override,
                                        const AudioVideoDeviceSettings& avs)
{
    if (!cli_override.empty()) return cli_override;
    return avs.audio_output_device;
}

std::string resolve_video_capture_device(const std::string& cli_override,
                                         const AudioVideoDeviceSettings& avs)
{
    if (!cli_override.empty()) return cli_override;
    return avs.video_capture_device;
}

void set_chat_launch_overrides(const ChatLaunchOverrides& overrides)
{
    std::lock_guard<std::mutex> lock(g_chat_launch_mutex);
    g_chat_launch_overrides = overrides;
}

ChatLaunchOverrides chat_launch_overrides()
{
    std::lock_guard<std::mutex> lock(g_chat_launch_mutex);
    return g_chat_launch_overrides;
}

bool native_3d_viewer_enabled()
{
    std::string text;
    const fs::path path = media::settings::get_config_dir() / "settings.json";
    {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open())
            return true;
        text.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    }
    if (text.empty())
        return true;
    try {
        const auto root = nlohmann::json::parse(text);
        if (root.contains("appearance") && root["appearance"].is_object()) {
            const auto& appearance = root["appearance"];
            if (appearance.contains("use_native_3d_viewer") && appearance["use_native_3d_viewer"].is_boolean())
                return appearance["use_native_3d_viewer"].get<bool>();
        }
    } catch (const std::exception&) {
    }
    return true;
}

void apply_global_tool_policy_to_values(std::vector<std::string>& disabled_path_tools,
                                        bool& mcp_tools_enabled,
                                        std::vector<std::string>& disabled_mcp_servers,
                                        std::string& err)
{
    GlobalToolSettings gs;
    if (!load_global_tool_settings(gs, err))
        return;

    // Merge with per-turn disables; global wins and is always present.
    std::vector<std::string> merged = disabled_path_tools;
    merged.insert(merged.end(), gs.disabled_path_tools.begin(), gs.disabled_path_tools.end());
    dedupe_lower_trim(merged);
    disabled_path_tools = std::move(merged);

    // Global MCP master is authoritative false.
    if (!gs.mcp_tools_enabled)
        mcp_tools_enabled = false;

    std::vector<std::string> mcp_merged = disabled_mcp_servers;
    mcp_merged.insert(mcp_merged.end(), gs.disabled_mcp_servers.begin(), gs.disabled_mcp_servers.end());
    dedupe_lower_trim(mcp_merged);
    disabled_mcp_servers = std::move(mcp_merged);
}

} // namespace media::runtime_settings
