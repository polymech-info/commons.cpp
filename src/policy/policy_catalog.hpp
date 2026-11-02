#pragma once
//
// Single source of truth for the GPO policy catalog.
//
// Every admin-controllable policy is described exactly once here. The dot-notation
// key doubles as:
//   * the EffectivePolicy lookup key, and
//   * the registry mapping (RegistryPolicyProvider splits "A.B.C" → subkey A\B,
//     value C), and
//   * the ADMX policy id (pol_A_B_C) emitted by scripts/generate-admx.mjs.
//
// Consumers (all derive from this catalog — no parallel hand-maintained lists):
//   policy.cpp        — known_policy_keys() + BuiltinPolicyProvider defaults
//   app_policy.cpp    — build_gpo_settings() / merge_into_app_features() / panel_allowed()
//   pm-image-cli      — `llm info policy --json` → scripts/generate-admx.mjs
//
// Polarity is uniform and POSITIVE: every boolean is Enable*/Require*, default-on
// unless default_on=false. There are deliberately NO Disable* keys.
//
#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace pm::policy {

enum class PolicyType {
    Bool,     // DWORD 0/1
    Multi,    // REG_MULTI_SZ (line list)
    Str,      // REG_SZ free text
    VerEnum,  // REG_SZ verification-level dropdown (none/presence/local_unlock/strong)
    EnumStr,  // REG_SZ generic enum (enum_items)
};

struct PolicyEnumItem {
    std::string value;   ///< registry string value, e.g. "dpapi"
    std::string label;   ///< English display label
};

struct PolicyCategory {
    std::string id;       ///< ADMX category id, e.g. "PM_UI_Panels"
    std::string parent;   ///< parent category id; "" = top-level (PM_Image root)
    std::string display;  ///< English display name
};

struct PolicyEntry {
    std::string key;          ///< dot key — lookup + registry + admx id source
    std::string category;     ///< PolicyCategory::id
    std::string web_key;      ///< GPO_SETTINGS dotted path; "" = not surfaced to web
    PolicyType  type        = PolicyType::Bool;
    bool        hklm_only    = false;  ///< honoured from the HKLM-only stack
    bool        default_on   = true;   ///< Bool compile-time default
    std::string display_name;          ///< ADMX displayName (English)
    std::string explain;               ///< ADMX explainText (English)
    std::vector<PolicyEnumItem> enum_items;  ///< for EnumStr
};

/// Full ordered category tree (parents precede children).
const std::vector<PolicyCategory>& policy_categories();

/// Full policy catalog — static for the process lifetime. Assembled from the
/// fixed descriptors plus the live provider registry (Providers.Enable*).
const std::vector<PolicyEntry>& policy_catalog();

/// Find a catalog entry by dot key (exact match). nullptr if unknown.
const PolicyEntry* policy_find(std::string_view key);

/// Machine-readable dump consumed by scripts/generate-admx.mjs via
/// `pm-image-cli llm info policy --json`.
nlohmann::json policy_catalog_json();

/// Which agent tools each Agent.Tools.Enable* key governs. Tool names are
/// derived from the live agent_tool_registry (by group or by single name).
struct ToolPolicyMapping {
    std::string              key;    ///< e.g. "Agent.Tools.EnableComputerGroup"
    std::vector<std::string> tools;  ///< governed tool names
};
const std::vector<ToolPolicyMapping>& agent_tool_policy_mappings();

/// All agent tool names known to the live registry (for AllowList expansion).
const std::vector<std::string>& agent_tool_all_names();

} // namespace pm::policy
