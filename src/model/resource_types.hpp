#pragma once

#include <cstdint>
#include <string>

namespace pm::model {

enum class ResourceType {
    PromptTemplate,
    CommandConfig,
    McpConfig,
    Prompt,
    Page,
    SettingsProfile,
    OAuthCredentials,
    WebAppBundle,
    AssetArchive,
    SessionTranscript,
    SessionMemory,
    SessionArtifact,
    SessionLog,
    Unknown,
};

enum class TrustLevel {
    Builtin,
    SignedVendor,
    UserLocal,
    PeerSigned,
    Workspace,
    Untrusted,
};

struct ResourceDigest {
    std::string algorithm = "sha256";
    std::string hex;
};

struct ResourceMeta {
    std::string uri;
    ResourceType type = ResourceType::Unknown;
    TrustLevel trust = TrustLevel::Untrusted;
    ResourceDigest digest;
    std::string version;
    std::string provider;
    std::string signer_id;
    std::string bundle_id;
    std::string created_at;
    std::string updated_at;
    bool encrypted = false;
    std::uint64_t size_bytes = 0;
};

inline std::string to_string(ResourceType type) {
    switch (type) {
    case ResourceType::PromptTemplate: return "prompt-template";
    case ResourceType::CommandConfig: return "command-config";
    case ResourceType::McpConfig: return "mcp-config";
    case ResourceType::Prompt: return "prompt";
    case ResourceType::Page: return "page";
    case ResourceType::SettingsProfile: return "settings-profile";
    case ResourceType::OAuthCredentials: return "oauth-credentials";
    case ResourceType::WebAppBundle: return "web-app-bundle";
    case ResourceType::AssetArchive: return "asset-archive";
    case ResourceType::SessionTranscript: return "session-transcript";
    case ResourceType::SessionMemory: return "session-memory";
    case ResourceType::SessionArtifact: return "session-artifact";
    case ResourceType::SessionLog: return "session-log";
    case ResourceType::Unknown: return "unknown";
    }
    return "unknown";
}

inline ResourceType resource_type_from_string(const std::string& s) {
    if (s == "prompt-template" || s == "PromptTemplate") return ResourceType::PromptTemplate;
    if (s == "command-config" || s == "CommandConfig") return ResourceType::CommandConfig;
    if (s == "mcp-config" || s == "McpConfig") return ResourceType::McpConfig;
    if (s == "prompt" || s == "Prompt") return ResourceType::Prompt;
    if (s == "page" || s == "Page") return ResourceType::Page;
    if (s == "settings-profile" || s == "SettingsProfile") return ResourceType::SettingsProfile;
    if (s == "oauth-credentials" || s == "OAuthCredentials") return ResourceType::OAuthCredentials;
    if (s == "web-app-bundle" || s == "WebAppBundle") return ResourceType::WebAppBundle;
    if (s == "asset-archive" || s == "AssetArchive") return ResourceType::AssetArchive;
    if (s == "session-transcript" || s == "SessionTranscript") return ResourceType::SessionTranscript;
    if (s == "session-memory" || s == "SessionMemory") return ResourceType::SessionMemory;
    if (s == "session-artifact" || s == "SessionArtifact") return ResourceType::SessionArtifact;
    if (s == "session-log" || s == "SessionLog") return ResourceType::SessionLog;
    return ResourceType::Unknown;
}

inline std::string to_string(TrustLevel trust) {
    switch (trust) {
    case TrustLevel::Builtin: return "builtin";
    case TrustLevel::SignedVendor: return "signed-vendor";
    case TrustLevel::UserLocal: return "user-local";
    case TrustLevel::PeerSigned: return "peer-signed";
    case TrustLevel::Workspace: return "workspace";
    case TrustLevel::Untrusted: return "untrusted";
    }
    return "untrusted";
}

inline TrustLevel trust_level_from_string(const std::string& s) {
    if (s == "builtin" || s == "Builtin") return TrustLevel::Builtin;
    if (s == "signed-vendor" || s == "SignedVendor") return TrustLevel::SignedVendor;
    if (s == "user-local" || s == "UserLocal") return TrustLevel::UserLocal;
    if (s == "peer-signed" || s == "PeerSigned") return TrustLevel::PeerSigned;
    if (s == "workspace" || s == "Workspace") return TrustLevel::Workspace;
    return TrustLevel::Untrusted;
}

} // namespace pm::model
