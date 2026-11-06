/**
 * Android: chat provider + presets (desktop-compatible settings.json shape).
 * FEATURE_HOME_LLM_TOOLS stays off — this file is settings-only.
 */
#include "core/settings_runtime.hpp"
#include "core/settings_store.hpp"
#include "core/chat_settings_schema.hpp"

#include <chrono>
#include <cctype>
#include <string>
#include "string/string_utils.hpp"

namespace media::runtime_settings {
namespace {

std::string ascii_lower_trim(std::string raw)
{
  while (!raw.empty() && raw.front() == ' ')
    raw.erase(raw.begin());
  while (!raw.empty() && raw.back() == ' ')
    raw.pop_back();
  raw = media::strutil::lower_ascii(std::move(raw));
  return raw;
}

void coerce_proxy_image_models(ChatProviderSettings& chat)
{
  auto leaf = [](std::string model) {
    const auto slash = model.find_last_of("/\\");
    if (slash != std::string::npos)
      model = model.substr(slash + 1);
    model = media::strutil::lower_ascii(std::move(model));
    return model;
  };
  const std::string gen = leaf(chat.image_model);
  if (gen.empty() || gen == "dall-e-3" || gen == "dall-e-2" || gen == "vision"
      || gen.rfind("image-vision", 0) == 0)
    chat.image_model = "image-generation-fast";
  const std::string rec = leaf(chat.image_recognition_model);
  if (rec.empty() || rec == "dall-e-3" || rec == "dall-e-2" || rec == "vision")
    chat.image_recognition_model = "image-vision-fast";
}

} // namespace

bool load_chat_provider(ChatProviderSettings& out, std::string& err)
{
  if (!media::settings::load_chat_provider(out, err))
    return false;
  coerce_proxy_image_models(out);
  return true;
}

bool save_chat_provider(const ChatProviderSettings& in, std::string& err)
{
  return media::settings::save_chat_provider(in, err);
}

bool load_chat_provider_presets(std::vector<ChatProviderPreset>& out, std::string& err)
{
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
    if (media::settings_schema::chat_provider_preset_from_json(item, p)) {
      coerce_proxy_image_models(p.chat);
      out.push_back(std::move(p));
    }
  }
  return true;
}

bool find_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out,
                               std::string& err)
{
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

bool resolve_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out,
                                  std::string& err)
{
  out = ChatProviderPreset{};
  std::vector<ChatProviderPreset> presets;
  if (!load_chat_provider_presets(presets, err))
    return false;
  std::string select_err;
  if (const auto* preset =
          media::settings_schema::select_chat_provider_preset(presets, id_or_name, &select_err)) {
    out = *preset;
    err.clear();
    return true;
  }
  err = select_err;
  return false;
}

bool save_chat_provider_preset(ChatProviderPreset preset, bool& changed, std::string& err)
{
  changed = false;
  preset.name = ascii_lower_trim(preset.name).empty() ? preset.id : preset.name;
  if (preset.name.empty()) {
    err = "empty chat preset name";
    return false;
  }
  if (preset.id.empty()) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    preset.id = "chat-preset-android-" + std::to_string(ms);
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
    if ((!id_key.empty() && ascii_lower_trim(item_id) == id_key) ||
        ascii_lower_trim(item_name) == name_key) {
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

  if (preset.is_default) {
    for (auto& item : presets) {
      if (!item.is_object())
        continue;
      const std::string item_id = item.value("id", std::string{});
      const std::string item_name = item.value("name", std::string{});
      const bool same = (!id_key.empty() && ascii_lower_trim(item_id) == id_key) ||
                        ascii_lower_trim(item_name) == name_key;
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

bool load_selected_chat_preset_id(std::string& out, std::string& err)
{
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

bool save_selected_chat_preset_id(const std::string& id, std::string& err)
{
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

bool apply_chat_provider_preset(const std::string& id_or_name, ChatProviderPreset& out,
                                std::string& err)
{
  if (!resolve_chat_provider_preset(id_or_name, out, err))
    return false;
  if (!save_chat_provider(out.chat, err))
    return false;
  const std::string key = media::settings_schema::chat_preset_select_key(out);
  return save_selected_chat_preset_id(key, err);
}

bool load_providers(ProviderMap& out, std::string& err)
{
  return media::settings::load_providers(out, err);
}

} // namespace media::runtime_settings
