#include "settings/chat_settings_schema.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>
#include "string/string_utils.hpp"

namespace media::settings_schema {
namespace {

std::string lower_trim(std::string s)
{
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](char c) {
        return !is_space(static_cast<unsigned char>(c));
    }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](char c) {
        return !is_space(static_cast<unsigned char>(c));
    }).base(), s.end());
    s = media::strutil::lower_ascii(std::move(s));
    return s;
}

void dedupe_lower_trim(std::vector<std::string>& inout)
{
    std::unordered_set<std::string> seen;
    std::vector<std::string> out;
    out.reserve(inout.size());
    for (std::string s : inout) {
        s = lower_trim(std::move(s));
        if (!s.empty() && seen.insert(s).second)
            out.push_back(std::move(s));
    }
    inout = std::move(out);
}

void read_string(const nlohmann::json& node, const char* key, std::string& out)
{
    if (node.contains(key) && node[key].is_string())
        out = node[key].get<std::string>();
}

void read_string_array(const nlohmann::json& node, const char* key, std::vector<std::string>& out)
{
    out.clear();
    if (!node.contains(key) || !node[key].is_array())
        return;
    for (const auto& item : node[key]) {
        if (item.is_string())
            out.push_back(item.get<std::string>());
    }
}

} // namespace

void apply_chat_provider_json(const nlohmann::json& c,
                              media::runtime_settings::ChatProviderSettings& out,
                              ChatJsonOptions options)
{
    if (!c.is_object())
        return;

    read_string(c, "router", out.router);
    read_string(c, "base_url", out.base_url);
    read_string(c, "model", out.model);
    if (c.contains("timeout_ms") && c["timeout_ms"].is_number_integer())
        out.timeout_ms = c["timeout_ms"].get<int>();
    if (c.contains("max_iterations") && c["max_iterations"].is_number_integer())
        out.max_iterations = c["max_iterations"].get<int>();
    if (c.contains("planner_enabled") && c["planner_enabled"].is_boolean())
        out.planner_enabled = c["planner_enabled"].get<bool>();
    read_string(c, "planner_router", out.planner_router);
    read_string(c, "planner_model", out.planner_model);
    read_string(c, "security_router", out.security_router);
    read_string(c, "security_model", out.security_model);
    read_string(c, "realtime_router", out.realtime_router);
    read_string(c, "realtime_model", out.realtime_model);
    read_string(c, "realtime_voice", out.realtime_voice);
    read_string(c, "image_provider", out.image_provider);
    read_string(c, "image_model", out.image_model);
    read_string(c, "image_recognition_provider", out.image_recognition_provider);
    read_string(c, "image_recognition_model", out.image_recognition_model);
    read_string(c, "video_provider", out.video_provider);
    read_string(c, "video_model", out.video_model);
    read_string(c, "ocr_provider", out.ocr_provider);
    read_string(c, "ocr_model", out.ocr_model);
    read_string(c, "stt_provider", out.stt_provider);
    read_string(c, "stt_model", out.stt_model);
    read_string(c, "tts_provider", out.tts_provider);
    if (lower_trim(out.stt_provider) == "pixlwiz")
        out.stt_provider = "tanit";
    if (lower_trim(out.tts_provider) == "pixlwiz")
        out.tts_provider = "tanit";
    read_string(c, "tts_model", out.tts_model);
    read_string(c, "tts_voice_id", out.tts_voice_id);
    read_string(c, "vibevoice_model",     out.vibevoice_model);
    read_string(c, "vibevoice_tokenizer", out.vibevoice_tokenizer);
    read_string(c, "vibevoice_voice",     out.vibevoice_voice);
    read_string(c, "api_mode", out.api_mode);

    if (options.clear_absent_media_fields) {
        if (!c.contains("image_provider") || !c["image_provider"].is_string()) out.image_provider.clear();
        if (!c.contains("image_model") || !c["image_model"].is_string()) out.image_model.clear();
        if (!c.contains("image_recognition_provider") || !c["image_recognition_provider"].is_string())
            out.image_recognition_provider.clear();
        if (!c.contains("image_recognition_model") || !c["image_recognition_model"].is_string())
            out.image_recognition_model.clear();
        if (!c.contains("video_provider") || !c["video_provider"].is_string()) out.video_provider.clear();
        if (!c.contains("video_model") || !c["video_model"].is_string()) out.video_model.clear();
        if (!c.contains("ocr_provider") || !c["ocr_provider"].is_string()) out.ocr_provider.clear();
        if (!c.contains("ocr_model") || !c["ocr_model"].is_string()) out.ocr_model.clear();
    }
}

nlohmann::json chat_provider_settings_json(
    const media::runtime_settings::ChatProviderSettings& c)
{
    return nlohmann::json{
        {"router", c.router},
        {"base_url", c.base_url},
        {"model", c.model},
        {"timeout_ms", c.timeout_ms},
        {"max_iterations", c.max_iterations},
        {"planner_enabled", c.planner_enabled},
        {"planner_router", c.planner_router},
        {"planner_model", c.planner_model},
        {"security_router", c.security_router},
        {"security_model", c.security_model},
        {"realtime_router", c.realtime_router},
        {"realtime_model", c.realtime_model},
        {"realtime_voice", c.realtime_voice},
        {"image_provider", c.image_provider},
        {"image_model", c.image_model},
        {"image_recognition_provider", c.image_recognition_provider},
        {"image_recognition_model", c.image_recognition_model},
        {"video_provider", c.video_provider},
        {"video_model", c.video_model},
        {"ocr_provider", c.ocr_provider},
        {"ocr_model", c.ocr_model},
        {"stt_provider", c.stt_provider},
        {"stt_model", c.stt_model},
        {"tts_provider", c.tts_provider},
        {"tts_model", c.tts_model},
        {"tts_voice_id", c.tts_voice_id},
        {"vibevoice_model",     c.vibevoice_model},
        {"vibevoice_tokenizer", c.vibevoice_tokenizer},
        {"vibevoice_voice",     c.vibevoice_voice},
        {"api_mode", c.api_mode},
    };
}

void apply_global_tool_settings_json(const nlohmann::json& g,
                                     media::runtime_settings::GlobalToolSettings& out)
{
    if (!g.is_object())
        return;
    read_string_array(g, "disabled_path_tools", out.disabled_path_tools);
    read_string_array(g, "disabled_mcp_servers", out.disabled_mcp_servers);
    read_string_array(g, "disabled_mcp_tools",   out.disabled_mcp_tools);
    if (g.contains("mcp_tools_enabled") && g["mcp_tools_enabled"].is_boolean())
        out.mcp_tools_enabled = g["mcp_tools_enabled"].get<bool>();
    dedupe_lower_trim(out.disabled_path_tools);
    dedupe_lower_trim(out.disabled_mcp_servers);
    dedupe_lower_trim(out.disabled_mcp_tools);
}

nlohmann::json global_tool_settings_json(
    media::runtime_settings::GlobalToolSettings t)
{
    dedupe_lower_trim(t.disabled_path_tools);
    dedupe_lower_trim(t.disabled_mcp_servers);
    dedupe_lower_trim(t.disabled_mcp_tools);
    return nlohmann::json{
        {"disabled_path_tools", t.disabled_path_tools},
        {"mcp_tools_enabled", t.mcp_tools_enabled},
        {"disabled_mcp_servers", t.disabled_mcp_servers},
        {"disabled_mcp_tools", t.disabled_mcp_tools},
    };
}

void apply_agent_skills_settings_json(const nlohmann::json& g,
                                      media::runtime_settings::AgentSkillsSettings& out)
{
    if (!g.is_object())
        return;
    read_string_array(g, "pinned", out.pinned);
    read_string_array(g, "disabled", out.disabled);
    if (g.contains("enabled") && g["enabled"].is_boolean())
        out.enabled = g["enabled"].get<bool>();
    if (g.contains("roaming_enabled") && g["roaming_enabled"].is_boolean())
        out.roaming_enabled = g["roaming_enabled"].get<bool>();
    if (g.contains("workspace_enabled") && g["workspace_enabled"].is_boolean())
        out.workspace_enabled = g["workspace_enabled"].get<bool>();
    dedupe_lower_trim(out.pinned);
    dedupe_lower_trim(out.disabled);
}

nlohmann::json agent_skills_settings_json(
    media::runtime_settings::AgentSkillsSettings s)
{
    dedupe_lower_trim(s.pinned);
    dedupe_lower_trim(s.disabled);
    return nlohmann::json{
        {"enabled", s.enabled},
        {"roaming_enabled", s.roaming_enabled},
        {"workspace_enabled", s.workspace_enabled},
        {"pinned", s.pinned},
        {"disabled", s.disabled},
    };
}

std::string normalize_chat_preset_runner(std::string raw)
{
    raw = lower_trim(std::move(raw));
    if (raw.empty() || raw == "native")
        return "native";
    if (raw == "claude" || raw == "claude-code" || raw == "claude_code")
        return "claude-code";
    if (raw == "codex")
        return "codex";
    // if (raw == "cursor")
    //     return "cursor"; // incomplete; keep for later
    return "native";
}

std::string normalize_chat_preset_consent_ui(std::string raw)
{
    raw = lower_trim(std::move(raw));
    if (raw.empty() || raw == "cards" || raw == "webview" || raw == "default" || raw == "auto")
        return {};
    if (raw == "yolo" || raw == "auto-allow" || raw == "auto_allow" || raw == "allow")
        return "yolo";
    if (raw == "auto-deny" || raw == "auto_deny" || raw == "deny")
        return "auto-deny";
    return {};
}

bool chat_provider_preset_from_json(const nlohmann::json& item,
                                    media::runtime_settings::ChatProviderPreset& p)
{
    p = media::runtime_settings::ChatProviderPreset{};
    if (!item.is_object())
        return false;
    read_string(item, "id", p.id);
    read_string(item, "name", p.name);
    if (p.id.empty() && p.name.empty())
        return false;
    if (item.contains("chat"))
        apply_chat_provider_json(item["chat"], p.chat);
    if (item.contains("tools") && item["tools"].is_object()) {
        p.has_tools = true;
        apply_global_tool_settings_json(item["tools"], p.tools);
    }
    if (item.contains("skills") && item["skills"].is_object()) {
        p.has_skills = true;
        apply_agent_skills_settings_json(item["skills"], p.skills);
    }
    // The settings UI edits `isDefault` and spreads the loaded row, which still
    // carries `is_default` from the previous save. An explicit isDefault wins,
    // so clearing the checkbox is not undone by that stale flag. Either key
    // alone still counts (older writers send only one of them).
    if (item.contains("isDefault") && item["isDefault"].is_boolean())
        p.is_default = item["isDefault"].get<bool>();
    else if (item.contains("is_default") && item["is_default"].is_boolean())
        p.is_default = item["is_default"].get<bool>();
    read_string(item, "runner", p.runner);
    p.runner = normalize_chat_preset_runner(std::move(p.runner));
    if (item.contains("add_tanit_mcp_server") && item["add_tanit_mcp_server"].is_boolean())
        p.add_tanit_mcp_server = item["add_tanit_mcp_server"].get<bool>();
    if (item.contains("load_agent_md") && item["load_agent_md"].is_boolean())
        p.load_agent_md = item["load_agent_md"].get<bool>();
    else if (item.contains("loadAgentMd") && item["loadAgentMd"].is_boolean())
        p.load_agent_md = item["loadAgentMd"].get<bool>();
    read_string(item, "consent_ui", p.consent_ui);
    if (p.consent_ui.empty())
        read_string(item, "consentUi", p.consent_ui);
    p.consent_ui = normalize_chat_preset_consent_ui(std::move(p.consent_ui));
    read_string(item, "connection", p.connection);
    if (lower_trim(p.connection) != "lan")
        p.connection.clear();
    else
        p.connection = "lan";
    return true;
}

nlohmann::json chat_provider_preset_json(
    const media::runtime_settings::ChatProviderPreset& p)
{
    nlohmann::json j = {
        {"id", p.id},
        {"name", p.name},
        {"runner", p.runner.empty() ? "native" : p.runner},
        {"add_tanit_mcp_server", p.add_tanit_mcp_server},
        {"load_agent_md", p.load_agent_md},
        {"chat", chat_provider_settings_json(p.chat)},
    };
    if (!p.consent_ui.empty())
        j["consent_ui"] = p.consent_ui;
    if (p.connection == "lan")
        j["connection"] = "lan";
    if (p.has_tools)
        j["tools"] = global_tool_settings_json(p.tools);
    if (p.has_skills)
        j["skills"] = agent_skills_settings_json(p.skills);
    if (p.is_default) {
        j["is_default"] = true;
        j["isDefault"] = true;
    }
    return j;
}

nlohmann::json normalize_chat_provider_preset_json(const nlohmann::json& node)
{
    media::runtime_settings::ChatProviderPreset preset;
    if (!chat_provider_preset_from_json(node, preset))
        return nlohmann::json::object();

    nlohmann::json out = node.is_object() ? node : nlohmann::json::object();
    nlohmann::json known = chat_provider_preset_json(preset);
    for (auto it = known.begin(); it != known.end(); ++it)
        out[it.key()] = it.value();
    if (!preset.is_default) {
        out.erase("is_default");
        out.erase("isDefault");
    }
    if (preset.consent_ui.empty()) {
        out.erase("consent_ui");
        out.erase("consentUi");
    }
    if (preset.connection != "lan")
        out.erase("connection");
    return out;
}

std::string chat_preset_select_key(const media::runtime_settings::ChatProviderPreset& preset)
{
    return preset.id.empty() ? preset.name : preset.id;
}

const media::runtime_settings::ChatProviderPreset* select_chat_provider_preset(
    const std::vector<media::runtime_settings::ChatProviderPreset>& presets,
    const std::string& requested,
    std::string* error)
{
    if (error)
        error->clear();

    const std::string needle = lower_trim(requested);
    if (!needle.empty()) {
        for (const auto& p : presets) {
            if (lower_trim(p.id) == needle || lower_trim(p.name) == needle)
                return &p;
        }
        if (error)
            *error = "chat preset not found: " + requested;
        return nullptr;
    }

    auto it = std::find_if(presets.begin(), presets.end(),
        [](const media::runtime_settings::ChatProviderPreset& p) {
            return p.is_default;
        });
    if (it == presets.end()) {
        it = std::find_if(presets.begin(), presets.end(),
            [](const media::runtime_settings::ChatProviderPreset& p) {
                return lower_trim(p.id) == "default" || lower_trim(p.name) == "default";
            });
    }
    if (it != presets.end())
        return &*it;
    if (presets.size() == 1)
        return &presets.front();
    return nullptr;
}

} // namespace media::settings_schema
