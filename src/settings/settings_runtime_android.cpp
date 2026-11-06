/**
 * Android NDK: agent memory settings via portable settings.json `custom.agent_memory`.
 * Sound cues use the same `workbench.sound_notifications_enabled` flag as desktop.
 * Chat presets live in settings_chat_presets_android.cpp.
 */
#include "settings/settings_runtime.hpp"
#include "settings/settings_store.hpp"

#include <cctype>
#include <string>
#include "string/string_utils.hpp"

namespace media::runtime_settings {
namespace {

std::string normalize_recall_profile(std::string raw)
{
  raw = media::strutil::lower_ascii(std::move(raw));
  while (!raw.empty() && raw.front() == ' ')
    raw.erase(raw.begin());
  while (!raw.empty() && raw.back() == ' ')
    raw.pop_back();
  if (raw == "off" || raw == "lexical" || raw == "hybrid" || raw == "shadow")
    return raw;
  return "hybrid";
}

std::string normalize_richness(std::string raw)
{
  raw = media::strutil::lower_ascii(std::move(raw));
  while (!raw.empty() && raw.front() == ' ')
    raw.erase(raw.begin());
  while (!raw.empty() && raw.back() == ' ')
    raw.pop_back();
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

} // namespace media::runtime_settings
