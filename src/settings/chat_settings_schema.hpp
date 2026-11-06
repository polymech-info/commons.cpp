#pragma once

#include "core/settings_runtime.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace media::settings_schema {

struct ChatJsonOptions {
    bool clear_absent_media_fields = false;
};

void apply_chat_provider_json(const nlohmann::json& node,
                              media::runtime_settings::ChatProviderSettings& out,
                              ChatJsonOptions options = {});

nlohmann::json chat_provider_settings_json(
    const media::runtime_settings::ChatProviderSettings& settings);

inline bool is_custom_chat_router(const std::string& router)
{
    return router == "custom" || router == "ollama";
}

/// When @p router is Custom, seed @p url from the preset/global custom base.
/// Empty @p url is always filled. @p overwrite also replaces a providers[] fallback
/// so the preset wins; callers must not overwrite an explicit CLI/spec URL.
inline void apply_custom_router_base(const std::string& router,
                                     const std::string& preset_base,
                                     std::string& url,
                                     bool overwrite = false)
{
    if (!is_custom_chat_router(router) || preset_base.empty())
        return;
    if (overwrite || url.empty())
        url = preset_base;
}

void apply_global_tool_settings_json(const nlohmann::json& node,
                                     media::runtime_settings::GlobalToolSettings& out);

nlohmann::json global_tool_settings_json(
    media::runtime_settings::GlobalToolSettings settings);

void apply_agent_skills_settings_json(const nlohmann::json& node,
                                      media::runtime_settings::AgentSkillsSettings& out);

nlohmann::json agent_skills_settings_json(
    media::runtime_settings::AgentSkillsSettings settings);

bool chat_provider_preset_from_json(const nlohmann::json& node,
                                    media::runtime_settings::ChatProviderPreset& out);

nlohmann::json chat_provider_preset_json(
    const media::runtime_settings::ChatProviderPreset& preset);

nlohmann::json normalize_chat_provider_preset_json(const nlohmann::json& node);

/// Canonical preset runner id: native | claude-code | codex | cursor.
/// Unknown / empty values map to `native`.
std::string normalize_chat_preset_runner(std::string raw);

/// Canonical preset consent surface: empty | yolo | auto-deny.
/// `auto-allow` / `allow` map to `yolo`. Unknown values map to empty.
std::string normalize_chat_preset_consent_ui(std::string raw);

std::string chat_preset_select_key(const media::runtime_settings::ChatProviderPreset& preset);

const media::runtime_settings::ChatProviderPreset* select_chat_provider_preset(
    const std::vector<media::runtime_settings::ChatProviderPreset>& presets,
    const std::string& requested,
    std::string* error = nullptr);

} // namespace media::settings_schema
