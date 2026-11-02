#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "security/UserVerification.hpp"

namespace pm::policy {

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO

// Initialize the global effective policy singleton.
// Call once at startup before any UI construction or CLI registration.
void init_app_policy();

// Is showing this panel currently allowed by policy?
// Pass IDC_CMD_VIEW_FILETREE / _SEARCH / _CONSOLE / _RIBBON.
// Returns true (allow) for unknown IDs — fail-open.
bool panel_allowed(unsigned int view_cmd_id);

// Is this app command allowed by policy?
// Pass media::win::app_cmd::Command cast to int.
// The command switch lives on the host and calls flag_enabled.
bool app_cmd_allowed(int cmd_enum);
bool flag_enabled(const char* key, bool fallback);

// Is this CLI command group allowed by policy?
// group: "audio", "video", "xblox" (matches pm::cli metadata canonical IDs).
bool cli_group_allowed(std::string_view group);

// Is host-bridge command execution from a web surface allowed by policy?
// kind: "cli"      → pm-image-cli verb (request.cliCommand)
//       "external" → arbitrary executable / shell line (request.externalCommand)
// Web.EnableCommandRun=0 blocks every inline run; Web.EnableExternalShell=0
// blocks only the arbitrary-process path while leaving curated ids + cli verbs.
// Both default to allowed (this is an automation tool) so admins opt in to lockdown.
bool web_command_run_allowed(std::string_view kind);

// Returns tool names that policy requires to be disabled.
// Merge into turn.disabled_path_tools in ToolsFeature::on_prepare.
std::vector<std::string> policy_disabled_tools();

// Returns provider ids that policy requires to be disabled.
std::vector<std::string> policy_disabled_providers();

// True when the provider exists, is enabled in this build, and is not disabled by policy.
bool provider_enabled(std::string_view name);

// Overlay GPO flags into the APP_FEATURES JSON before it is injected
// as window.APP_FEATURES into all WebViews.
// Adds a "gpo" sub-object with disable booleans and provider restrictions.
void merge_into_app_features(nlohmann::json& features);

// Build the GPO_SETTINGS object injected as window.GPO_SETTINGS.
// Contains all policy values relevant to web surfaces (UI gates, agent
// capabilities, tool flags). Returns an empty object when GPO is disabled.
nlohmann::json build_gpo_settings();

// Returns a policy-overridden verification level for the given operation name,
// or nullopt if no policy override is set (compiled default applies).
// Reads Security.Verification.<camelCaseOp> from the HKLM-only policy stack.
// HKCU is intentionally excluded: non-admin users must not self-downgrade
// their verification requirements via the user hive.
std::optional<pm::security::VerificationLevel> policy_verification_level(std::string_view operation);

// Is saving editor content with this operation name permitted by policy?
// operation: "promptTemplate.update" | "commandConfig.update" | "mcpConfig.update"
// Backend-side guard — mirrors frontend GPO_SETTINGS.disablePromptEditor etc.
bool editor_save_allowed(std::string_view operation);

// Is this named agent feature (Agent.EnableMcpClient, Agent.EnableSkills, …) enabled?
bool is_agent_feature_enabled(std::string_view key);

// Returns the admin-forced verification protector string from HKLM, or empty.
// Values: "windows-hello" | "dpapi". Empty = no override, use env var / compiled default.
std::string policy_forced_verification_protector();

// Returns true if the org policy requires documents to be encrypted / signed.
// Reads Security.RequireEncryption / Security.RequireSigning from HKLM-only stack.
bool policy_require_encryption();
bool policy_require_signing();
std::string policy_session_storage_root();
std::string policy_session_storage_protection();
bool policy_session_storage_require_encryption();
bool policy_session_storage_require_signing();
std::string policy_temp_dir();
std::string policy_default_folder();

// Is local whisper.cpp inference allowed by policy?  Default: true.
bool local_whisper_enabled();
// Is ONNX runtime inference allowed by policy?  Default: true.
bool local_onnx_enabled();
// Is llama.cpp inference (text + embedding) allowed by policy?  Default: true.
bool local_llama_enabled();

// Is the tanit:// custom URL scheme handler allowed by policy?  Default: true.
// HKLM-only: prevents both scheme registration and protocol URI dispatch.
bool url_schemes_enabled();

// Clipboard as an OS context source. Default: true.
bool clipboard_context_allowed();

// Outbound remote file access. Default: true. Covers file panel, viewer,
// VFS queue, XBlox, and tanit-cli. ssh:// and sftp:// share EnableSsh.
bool ssh_access_allowed();
bool ftp_access_allowed();

// In-app WebView browser-use tools. Default: true.
// Also off when Agent.EnableComputerUse is off (coarse UI-automation lock).
bool browser_use_allowed();

#else

// ── No-op stubs for builds without FEATURE_WINDOWS_GPO ───────────────────────
inline void init_app_policy() {}
inline bool panel_allowed(unsigned int)                   { return true;  }
inline bool app_cmd_allowed(int)                          { return true;  }
inline bool flag_enabled(const char*, bool fallback)      { return fallback; }
inline bool cli_group_allowed(std::string_view)           { return true;  }
inline bool web_command_run_allowed(std::string_view)     { return true;  }
inline std::vector<std::string> policy_disabled_tools()   { return {};    }
inline std::vector<std::string> policy_disabled_providers(){ return {};    }
inline bool provider_enabled(std::string_view)            { return true;  }
inline void merge_into_app_features(nlohmann::json&)      {}
inline nlohmann::json build_gpo_settings()                { return nlohmann::json::object(); }
inline std::optional<pm::security::VerificationLevel>
    policy_verification_level(std::string_view)           { return std::nullopt; }
inline bool editor_save_allowed(std::string_view)         { return true;  }
inline bool is_agent_feature_enabled(std::string_view)    { return true;  }
inline std::string policy_forced_verification_protector() { return {};    }
inline bool policy_require_encryption()                   { return false; }
inline bool policy_require_signing()                      { return false; }
inline std::string policy_session_storage_root()          { return {};    }
inline std::string policy_session_storage_protection()    { return {};    }
inline bool policy_session_storage_require_encryption()   { return false; }
inline bool policy_session_storage_require_signing()      { return false; }
inline std::string policy_temp_dir()                      { return {};    }
inline std::string policy_default_folder()                { return {};    }
inline bool local_whisper_enabled()                       { return true;  }
inline bool local_onnx_enabled()                          { return true;  }
inline bool local_llama_enabled()                         { return true;  }
inline bool url_schemes_enabled()                         { return true;  }
inline bool clipboard_context_allowed()                   { return true; }
inline bool ssh_access_allowed()                          { return true;  }
inline bool ftp_access_allowed()                          { return true;  }
inline bool browser_use_allowed()                         { return true;  }

#endif // FEATURE_WINDOWS_GPO

} // namespace pm::policy
