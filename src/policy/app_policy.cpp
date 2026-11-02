#include "policy/app_policy.hpp"

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO

#include "policy/PolicyProvider.hpp"
#include "policy/policy_catalog.hpp"
#include "host/services.hpp"

#include <algorithm>
#include <cstddef>
#include <string>

namespace {

// Panel view command IDs (from src/win/ui_next/Resource.h).
// Embedded here to avoid pulling Win32 resource headers into the policy layer.
constexpr unsigned int k_IDC_CMD_VIEW_QUEUE     = 350;
constexpr unsigned int k_IDC_CMD_VIEW_LOG       = 351;
constexpr unsigned int k_IDC_CMD_VIEW_SETTINGS  = 352;
constexpr unsigned int k_IDC_CMD_VIEW_RIBBON    = 359;
constexpr unsigned int k_IDC_CMD_VIEW_FILETREE  = 361;
constexpr unsigned int k_IDC_CMD_VIEW_CHAT      = 363;
constexpr unsigned int k_IDC_CMD_VIEW_SEARCH    = 367;
constexpr unsigned int k_IDC_CMD_VIEW_CONSOLE   = 377;

pm::policy::EffectivePolicy& g_policy() {
    static auto p = pm::policy::make_default_policy();
    return p;
}

// Security-sensitive keys (Verification.*, RequireEncryption, RequireSigning)
// must only be honoured from HKLM — a non-admin user must not be able to
// downgrade their own security requirements via HKCU.
pm::policy::EffectivePolicy& g_hklm_policy() {
    static auto p = [] {
        pm::policy::EffectivePolicy ep;
        ep.push_back(std::make_shared<pm::policy::BuiltinPolicyProvider>());
        ep.push_back(std::make_shared<pm::policy::RegistryPolicyProvider>(
                         pm::policy::RegistryHive::HKLM));
        return ep;
    }();
    return p;
}

} // namespace

namespace pm::policy {

void init_app_policy() {
    // Warm up the singleton so the first real call is fast.
    (void)g_policy();
}

const EffectivePolicy& app_policy() {
    return g_policy();
}

bool panel_allowed(unsigned int view_cmd_id) {
    const auto& pol = g_policy();
    switch (view_cmd_id) {
    case k_IDC_CMD_VIEW_RIBBON:    return pol.is_enabled("UI.Panels.EnableRibbon",   true);
    case k_IDC_CMD_VIEW_FILETREE:  return pol.is_enabled("UI.Panels.EnableExplorer", true);
    case k_IDC_CMD_VIEW_SEARCH:    return pol.is_enabled("UI.Panels.EnableSearch",   true);
    case k_IDC_CMD_VIEW_CONSOLE:   return pol.is_enabled("UI.Panels.EnableShell",    true);
    case k_IDC_CMD_VIEW_SETTINGS:  return pol.is_enabled("UI.Panels.EnableSettings", true);
    case k_IDC_CMD_VIEW_QUEUE:     return pol.is_enabled("UI.Panels.EnableQueue",    true);
    case k_IDC_CMD_VIEW_LOG:       return pol.is_enabled("UI.Panels.EnableLog",      true);
    case k_IDC_CMD_VIEW_CHAT:      return pol.is_enabled("UI.Panels.EnableChat",     true);
    default:                       return true;
    }
}

bool flag_enabled(const char* key, bool fallback) {
    return g_policy().is_enabled(key ? key : "", fallback);
}

bool app_cmd_allowed(int cmd_enum) {
    bool handled = false;
    const bool allow = pm::commons::host::app_cmd_allowed(cmd_enum, handled);
    return handled ? allow : true;
}

bool cli_group_allowed(std::string_view group) {
    const auto& pol = g_policy();
    // search & discovery
    if (group == "search") return pol.is_enabled("CLI.EnableSearch", true);
    // media / capture
    if (group == "audio") return pol.is_enabled("CLI.EnableAudio", true);
    if (group == "voice") return pol.is_enabled("CLI.EnableAudio", true);
    if (group == "video") return pol.is_enabled("CLI.EnableVideo", true);
    if (group == "xblox") return pol.is_enabled("CLI.EnableXblox", true);
    if (group == "llama") return pol.is_enabled("Local.EnableLlama", true);
    if (group == "onnx")  return pol.is_enabled("Local.EnableOnnx",  true);
    // setup / install
    if (group == "register-explorer")  return pol.is_enabled("CLI.EnableRegisterExplorer",  true);
    if (group == "register-startmenu") return pol.is_enabled("CLI.EnableRegisterStartMenu", true);
    if (group == "installer")          return pol.is_enabled("CLI.EnableInstaller",         true);
    if (group == "settings")           return pol.is_enabled("CLI.EnableSettings",          true);
    // service / auth
    if (group == "service")  return pol.is_enabled("CLI.EnableService", true);
    if (group == "login")    return pol.is_enabled("CLI.EnableLogin",   true);
    if (group == "status")   return pol.is_enabled("CLI.EnableStatus",  true);
    // servers
    if (group == "run-ipc")    return pol.is_enabled("CLI.EnableRunIpc",    true);
    if (group == "mcp-server") return pol.is_enabled("CLI.EnableMcpServer", true);
    // automation
    if (group == "daemon")    return pol.is_enabled("CLI.EnableDaemon",    true);
    if (group == "assistant") return pol.is_enabled("CLI.EnableAssistant", true);
    if (group == "batch")     return pol.is_enabled("CLI.EnableBatch",     true);
    // media / devices
    if (group == "bluetooth") return pol.is_enabled("CLI.EnableBluetooth", true);
    if (group == "media")     return pol.is_enabled("CLI.EnableMedia",     true);
    return true;
}

bool web_command_run_allowed(std::string_view kind) {
    const auto& pol = g_policy();
    if (!pol.is_enabled("Web.EnableCommandRun", true))
        return false;
    if (kind == "external" && !pol.is_enabled("Web.EnableExternalShell", true))
        return false;
    return true;
}

std::vector<std::string> policy_disabled_tools() {
    const auto& pol = g_policy();
    std::vector<std::string> disabled;

    auto add = [&](const std::string& t) {
        if (std::find(disabled.begin(), disabled.end(), t) == disabled.end())
            disabled.push_back(t);
    };

    // Per-key tool gates — mapping (key → governed tools) comes from the live
    // agent_tool_registry via the policy catalog, not a hand-maintained list.
    for (const auto& m : agent_tool_policy_mappings()) {
        if (!pol.is_enabled(m.key, true))
            for (const auto& t : m.tools)
                add(t);
    }

    // Agent.EnableComputerUse=0 is a coarse UI-automation lock: desktop
    // computer-use and in-app browser-use. EnableBrowserUse=0 is browser only.
    if (!pol.is_enabled("Agent.EnableComputerUse", true)) {
        for (const auto& m : agent_tool_policy_mappings())
            if (m.key == "Agent.Tools.EnableComputerGroup"
                || m.key == "Agent.Tools.EnableBrowserGroup")
                for (const auto& t : m.tools)
                    add(t);
    }
    if (!pol.is_enabled("Agent.EnableBrowserUse", true)) {
        for (const auto& m : agent_tool_policy_mappings())
            if (m.key == "Agent.Tools.EnableBrowserGroup")
                for (const auto& t : m.tools)
                    add(t);
    }

    // Explicit BlockList
    for (const auto& t : pol.get_multi_or("Agent.Tools.BlockList"))
        add(t);

    // AllowList: when non-empty, block every registry tool not in the list.
    const auto allow = pol.get_multi_or("Agent.Tools.AllowList");
    if (!allow.empty()) {
        for (const auto& t : agent_tool_all_names())
            if (std::find(allow.begin(), allow.end(), t) == allow.end())
                add(t);
    }

    return disabled;
}

std::vector<std::string> policy_disabled_providers() {
    const auto& pol = g_policy();
    std::vector<std::string> disabled;
    const auto rows = pm::commons::host::provider_rows();
    for (const auto& row : rows) {
        if (!pol.is_enabled(row.policy_key, true))
            disabled.push_back(row.name);
    }
    return disabled;
}

bool provider_enabled(std::string_view name) {
    const auto rows = pm::commons::host::provider_rows();
    const auto* info = pm::commons::host::find_provider(name, rows);
    if (!info || !info->build_enabled)
        return false;
    return g_policy().is_enabled(info->policy_key, true);
}

namespace {

// Assign value into a nested json object following a dotted web_key
// (e.g. "ui.panels.explorer" → g["ui"]["panels"]["explorer"]).
void set_nested(nlohmann::json& root, std::string_view path, nlohmann::json value) {
    nlohmann::json* cur = &root;
    std::size_t start = 0;
    while (true) {
        const std::size_t dot = path.find('.', start);
        const std::string seg(path.substr(start, dot - start));
        if (dot == std::string_view::npos) {
            (*cur)[seg] = std::move(value);
            return;
        }
        cur = &(*cur)[seg];
        if (!cur->is_object())
            *cur = nlohmann::json::object();
        start = dot + 1;
    }
}

// Build the canonical nested GPO object from the catalog. Every value is a
// POSITIVE boolean ("enabled/allowed") or a string-list (multi). HKLM-only
// entries read from the HKLM stack so users cannot self-downgrade.
nlohmann::json build_gpo_object() {
    const auto& pol  = g_policy();
    const auto& hpol = g_hklm_policy();
    nlohmann::json g = nlohmann::json::object();

    for (const auto& e : policy_catalog()) {
        if (e.web_key.empty())
            continue;
        const auto& stack = e.hklm_only ? hpol : pol;
        if (e.type == PolicyType::Bool)
            set_nested(g, e.web_key, stack.is_enabled(e.key, e.default_on));
        else if (e.type == PolicyType::Multi)
            set_nested(g, e.web_key, stack.get_multi_or(e.key));
    }

    // AI providers — registry rows carry build + policy status for the UI.
    nlohmann::json providers = nlohmann::json::object();
    for (const auto& row : pm::commons::host::provider_rows()) {
        providers[row.name] = nlohmann::json{
            {"buildEnabled", row.build_enabled},
            {"policyEnabled", pol.is_enabled(row.policy_key, true)},
        };
    }
    g["providers"] = std::move(providers);

    return g;
}

} // namespace

void merge_into_app_features(nlohmann::json& features) {
    features["gpo"] = build_gpo_object();
}

nlohmann::json build_gpo_settings() {
    return build_gpo_object();
}

bool editor_save_allowed(std::string_view operation) {
    const auto& pol = g_policy();
    if (operation == "promptTemplate.update") return pol.is_enabled("UI.Editors.EnablePrompt",  true);
    if (operation == "commandConfig.update")  return pol.is_enabled("UI.Editors.EnableCommand", true);
    if (operation == "mcpConfig.update")      return pol.is_enabled("UI.Editors.EnableMcp",     true);
    if (operation == "homePage.update")       return pol.is_enabled("UI.Editors.EnablePage",    true);
    return true; // unknown operations are not blocked
}

bool is_agent_feature_enabled(std::string_view key) {
    return g_policy().is_enabled(std::string(key), true);
}

std::string policy_forced_verification_protector() {
    return g_hklm_policy().get_str("Security.ForceVerificationProtector").value_or(std::string{});
}

bool policy_require_encryption() {
    return g_hklm_policy().is_enabled("Security.RequireEncryption", false);
}

bool policy_require_signing() {
    return g_hklm_policy().is_enabled("Security.RequireSigning", false);
}

std::string policy_session_storage_root() {
    const auto v = g_hklm_policy().get_str_with_source("SessionStorage.Root");
    if (!v || v->source != "hklm")
        return {};
    return v->value;
}

std::string policy_session_storage_protection() {
    const auto v = g_hklm_policy().get_str_with_source("SessionStorage.Protection");
    if (!v || v->source != "hklm")
        return {};
    return v->value;
}

std::string policy_temp_dir() {
    const auto v = g_hklm_policy().get_str_with_source("Paths.TempDirectory");
    if (!v || v->source != "hklm")
        return {};
    return v->value;
}

std::string policy_default_folder() {
    const auto v = g_hklm_policy().get_str_with_source("Paths.DefaultFolder");
    if (!v || v->source != "hklm")
        return {};
    return v->value;
}

bool policy_session_storage_require_encryption() {
    const auto v = g_hklm_policy().get_int_with_source("SessionStorage.RequireEncryption");
    return v && v->source == "hklm" && v->value != "0";
}

bool policy_session_storage_require_signing() {
    const auto v = g_hklm_policy().get_int_with_source("SessionStorage.RequireSigning");
    return v && v->source == "hklm" && v->value != "0";
}

bool local_whisper_enabled() {
    return g_policy().is_enabled("Local.EnableWhisper", true);
}

bool local_onnx_enabled() {
    return g_policy().is_enabled("Local.EnableOnnx", true);
}

bool local_llama_enabled() {
    return g_policy().is_enabled("Local.EnableLlama", true);
}

bool url_schemes_enabled() {
    return g_hklm_policy().is_enabled("CLI.EnableUrlSchemes", true);
}

bool ssh_access_allowed() {
    return g_policy().is_enabled("Network.EnableSsh", true);
}

bool ftp_access_allowed() {
    return g_policy().is_enabled("Network.EnableFtp", true);
}

bool browser_use_allowed() {
    return g_policy().is_enabled("Agent.EnableBrowserUse", true)
        && g_policy().is_enabled("Agent.EnableComputerUse", true)
        && g_policy().is_enabled("Agent.Tools.EnableBrowserGroup", true);
}

std::optional<pm::security::VerificationLevel>
policy_verification_level(std::string_view operation) {
    // Maps operation name → Security.Verification.<key>
    // Only operations that admins should be able to configure are listed.
    static const std::vector<std::pair<std::string_view, const char*>> k_map = {
        {"settings.importPlain",          "Security.Verification.SettingsImportPlain"},
        {"settings.exportPlain",          "Security.Verification.SettingsExportPlain"},
        {"commandConfig.update",          "Security.Verification.CommandConfigUpdate"},
        {"commandConfig.importPlain",     "Security.Verification.CommandConfigImport"},
        {"commandConfig.exportPlain",     "Security.Verification.CommandConfigExport"},
        {"mcpConfig.update",              "Security.Verification.McpConfigUpdate"},
        {"mcpConfig.importPlain",         "Security.Verification.McpConfigImport"},
        {"promptTemplate.update",         "Security.Verification.PromptUpdate"},
        {"promptTemplate.importPlain",    "Security.Verification.PromptImport"},
        {"homePage.update",               "Security.Verification.HomePageUpdate"},
        {"homePage.importPlain",          "Security.Verification.HomePageImport"},
        {"homePage.exportPlain",          "Security.Verification.HomePageExport"},
        {"asset.importPlain",             "Security.Verification.AssetImport"},
        {"asset.importVendorSeed",        "Security.Verification.AssetImport"},
        {"oauthCredentials.save",         "Security.Verification.OAuthCredentialsSave"},
        {"oauthCredentials.clear",        "Security.Verification.OAuthCredentialsClear"},
    };

    for (const auto& [op, key] : k_map) {
        if (op != operation) continue;
        const auto val = g_hklm_policy().get_str(key);  // HKLM only — user must not self-downgrade
        if (!val || val->empty()) return std::nullopt;
        return pm::security::verification_level_from_string(*val);
    }
    return std::nullopt;
}

bool clipboard_context_allowed() {
    return g_policy().is_enabled("Privacy.EnableClipboardContext", true);
}

} // namespace pm::policy

#endif // FEATURE_WINDOWS_GPO
