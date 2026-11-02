#pragma once
//
// pm::security — core value types for the local tool-call security gateway.
//
// This header is the single source of truth for the security module's enums,
// request/grant/decision structs, the MCP server policy record, the built-in
// secret-pattern tables, and the classification *delegate* interfaces that are
// meant to gradually replace the ad-hoc predicate tables in
// `src/file_extensions.hpp` (see docs/security/todos.md → "Delegate migration").
//
// Companions:
//   - src/constants.hpp       product-wide defaults (branding, endpoints)
//   - src/llm/llm_constants.hpp  LLM/agent policy knobs (FS/run strict, memory)
//   - src/security/security_default.hpp  feature-macro defaults + profile select
//
// Design reference: docs/security/design.md ("Core types", "ToolRequest",
// "Capability grants", "PolicyDecision", "MCP rules").
//
// Keep this header dependency-light: std only. Backends and engines pull in
// platform/third-party headers in their own translation units.
//

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pm::security {

// ── Enumerations ──────────────────────────────────────────────────────────────

/// Overall security posture. Selected at compile time by `SECURITY_PROFILE`
/// (see security_default.hpp) and overridable per request. Names mirror the
/// CMake flag values; design.md calls these EndUser/OEM/Dev respectively.
enum class Profile : std::uint8_t {
    Light,      ///< CMake LIGHT  — design "EndUser": workspace-friendly, ask on medium risk.
    Strict,     ///< CMake STRICT — design "OEM": deny all except explicitly registered signed tools.
    Developer,  ///< CMake DEVELOPER — design "Dev": broad workspace allow, ask on package/network.
};

/// Who is driving the request. The LLM, plugins, and MCP servers are untrusted.
enum class Actor : std::uint8_t {
    User,
    LLM,
    Plugin,
    McpServer,
    BackgroundAgent,
};

/// The operation a tool wants to perform on a resource.
enum class Action : std::uint8_t {
    Read,
    Write,
    Delete,
    Execute,
    Network,
    Upload,
    Download,
    GitPush,
    Publish,
    ProtocolActivate,  ///< External URI (e.g. tanit://) activating a handler
};

/// Escalating risk tiers produced by the ResourceClassifier / PolicyEngine.
enum class Risk : std::uint8_t {
    Low,
    Medium,
    High,
    Critical,
};

/// The gateway's verdict for a single request.
enum class DecisionKind : std::uint8_t {
    Allow,          ///< Execute immediately.
    Deny,           ///< Block; never prompt.
    Ask,            ///< Require fresh user consent (ConsentDelegate).
    Sandbox,        ///< Allow only inside a constrained sandbox (future).
    AllowRedacted,  ///< Allow with sensitive content redacted (future).
};

/// How long a granted capability persists.
enum class GrantLifetime : std::uint8_t {
    Once,
    Session,
    UntilTimestamp,
    Permanent,
    Task,  ///< Bound to a single agent task/turn (cleared when the task ends).
};

/// Provenance of a request: which of our own binaries (or a third party) is
/// driving the call. Recorded for audit + first-party trust; not (yet) a
/// grant-matching dimension. The registry lives in Origin.hpp.
enum class OriginKind : std::uint8_t {
    Unknown,   ///< not one of our known binaries → third-party / untrusted provenance
    Ui,        ///< tanit.exe (desktop UI app)
    Cli,       ///< pm-image-cli.exe (headless CLI)
    Service,   ///< background service / worker (future)
    Security,  ///< pm-image-security.exe (this gateway test CLI)
};

// ── Enum → string (stable tokens for audit/persistence/logging) ──────────────

constexpr std::string_view to_string(Profile p) noexcept {
    switch (p) {
        case Profile::Light:     return "LIGHT";
        case Profile::Strict:    return "STRICT";
        case Profile::Developer: return "DEVELOPER";
    }
    return "LIGHT";
}

constexpr std::string_view to_string(Actor a) noexcept {
    switch (a) {
        case Actor::User:            return "user";
        case Actor::LLM:             return "llm";
        case Actor::Plugin:          return "plugin";
        case Actor::McpServer:       return "mcp_server";
        case Actor::BackgroundAgent: return "background_agent";
    }
    return "llm";
}

constexpr std::string_view to_string(Action a) noexcept {
    switch (a) {
        case Action::Read:     return "read";
        case Action::Write:    return "write";
        case Action::Delete:   return "delete";
        case Action::Execute:  return "execute";
        case Action::Network:  return "network";
        case Action::Upload:   return "upload";
        case Action::Download: return "download";
        case Action::GitPush:           return "git_push";
        case Action::Publish:           return "publish";
        case Action::ProtocolActivate:  return "protocol_activate";
    }
    return "read";
}

constexpr std::string_view to_string(Risk r) noexcept {
    switch (r) {
        case Risk::Low:      return "low";
        case Risk::Medium:   return "medium";
        case Risk::High:     return "high";
        case Risk::Critical: return "critical";
    }
    return "low";
}

constexpr std::string_view to_string(DecisionKind d) noexcept {
    switch (d) {
        case DecisionKind::Allow:         return "allow";
        case DecisionKind::Deny:          return "deny";
        case DecisionKind::Ask:           return "ask";
        case DecisionKind::Sandbox:       return "sandbox";
        case DecisionKind::AllowRedacted: return "allow_redacted";
    }
    return "deny";
}

constexpr std::string_view to_string(GrantLifetime l) noexcept {
    switch (l) {
        case GrantLifetime::Once:           return "once";
        case GrantLifetime::Session:        return "session";
        case GrantLifetime::UntilTimestamp: return "until_timestamp";
        case GrantLifetime::Permanent:      return "permanent";
        case GrantLifetime::Task:           return "task";
    }
    return "once";
}

constexpr std::string_view to_string(OriginKind k) noexcept {
    switch (k) {
        case OriginKind::Unknown:  return "unknown";
        case OriginKind::Ui:       return "ui";
        case OriginKind::Cli:      return "cli";
        case OriginKind::Service:  return "service";
        case OriginKind::Security: return "security";
    }
    return "unknown";
}

/// Order comparison for risk tiers (e.g. classifier ∪ policy = max risk).
constexpr bool operator<(Risk a, Risk b) noexcept {
    return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
}
constexpr Risk max_risk(Risk a, Risk b) noexcept { return (a < b) ? b : a; }

// ── Request shape (design.md "ToolRequest") ──────────────────────────────────

/// What a tool wants to touch. `uri` distinguishes file:// mcp:// https:// git://.
struct ResourceTarget {
    std::string uri;
    std::filesystem::path path;
    std::string mime;
    std::string extension;
};

/// Resolved provenance of a request. Built from the calling binary name via the
/// registry in Origin.hpp. `firstParty` is true for our own signed binaries.
struct Origin {
    std::string id;           ///< stable id, e.g. "pm-image.ui", "pm-image.cli"
    std::string binaryName;   ///< resolved binary basename, e.g. "tanit.exe"
    std::string displayName;  ///< human label for the consent UI
    OriginKind kind = OriginKind::Unknown;
    bool firstParty = false;  ///< one of our own binaries (implicitly trusted for now)
};

/// Hash-bound identity of the calling tool. Manifest/executable hash changes
/// invalidate previously persisted grants (see PermissionStore).
struct ToolIdentity {
    std::string toolId;          ///< e.g. file.read, shell.exec, mcp.github.issue.create
    std::string provider;        ///< builtin | plugin | mcp
    std::string serverId;        ///< MCP / plugin id (empty for builtin)
    std::string executableHash;  ///< SHA-256 hex of the backing executable
    std::string manifestHash;    ///< SHA-256 hex of the tool/MCP manifest
    bool signedManifest = false; ///< true when the manifest carries a valid signature
};

/// A single proposed tool call, normalized before policy evaluation.
struct ToolRequest {
    Actor actor = Actor::LLM;
    Profile profile = Profile::Light;

    Origin origin;  ///< which of our binaries is driving the call (provenance)

    ToolIdentity tool;
    Action action = Action::Read;
    std::optional<ResourceTarget> target;

    std::string workspaceId;
    std::filesystem::path workspaceRoot;

    std::string sessionId;  ///< binds Session-lifetime grants
    std::string taskId;     ///< binds Task-lifetime grants (one agent task/turn)
    std::string userVisibleIntent;
    std::string argumentsJson;
    std::string argumentsHash;

    /// Optional caller-supplied sandbox hint (Phase B). A front-end/tool may
    /// request isolation (e.g. "appcontainer"); the gateway honours it only when
    /// a backend of that name is registered. Persisted grants still take
    /// precedence. Empty = no preference.
    std::string sandboxHint;

    /// True when the platform has a working sandbox backend (FEATURE_SECURITY_SANDBOX).
    /// Used by PolicyEngine to set the Execute risk floor: sandboxed Execute → Medium
    /// (contained), uncontained Execute → High. Affects only the consent card display;
    /// the Ask decision is emitted regardless.
    bool sandboxAvailable = false;
};

// ── Capability grants (design.md "Capability grants") ────────────────────────

/// A persisted, scoped permission. We persist *capabilities*, never vague
/// "user said yes" approvals. Some actions are never persistable — see
/// `is_never_persistable()`.
struct CapabilityGrant {
    std::string id;

    Profile profile = Profile::Light;
    std::string subject;  ///< user / session / agent / mcp-server id
    ToolIdentity tool;
    Action action = Action::Read;

    std::vector<std::string> resourceScopes;  ///< glob / pathspec / URI patterns

    bool readOnly = true;
    bool allowSecrets = false;
    bool allowNetwork = false;

    std::uint64_t maxFiles = 100;
    std::uint64_t maxBytes = 10ull * 1024 * 1024;

    GrantLifetime lifetime = GrantLifetime::Once;
    std::optional<std::chrono::system_clock::time_point> expiresAt;

    /// Binding ids. When non-empty, `find()` only matches a request carrying the
    /// same id — so a Session/Task grant is scoped to its session/task. Empty =
    /// unbound (matches any), preserving the simple global-grant case.
    std::string sessionId;
    std::string taskId;

    std::string workspaceId;
    std::string policyVersion;
    std::string reason;

    /// Phase 1.10 provenance. Human grants stay `approvedBy="human"`.
    /// AI-routed grants set `aiDelegated=true` and `approvedBy="ai:<preset>"`.
    bool aiDelegated = false;
    std::string approvedBy = "human";

    /// Sandbox routing (Phase B). When set (e.g. "appcontainer"), a request that
    /// matches this grant is allowed *only* inside that backend — the gateway
    /// copies this into PolicyDecision::sandboxBackend. This is the user-consent
    /// signal: an "Always run in sandbox" choice persists as a grant carrying it.
    std::string sandboxBackend;

    std::optional<std::chrono::system_clock::time_point> createdAt;
};

/// Actions that must never be backed by a persisted grant — they always require
/// fresh consent, regardless of scope. Currently only irreversible external
/// actions (push/publish) are in this category.  Execute/Write/Delete are
/// intentionally NOT in this list — a scoped, resource-bound grant (e.g.
/// "always allow `run ls *.md` in this workspace") is a legitimate persistent
/// capability, provided the resource scope is non-empty (enforced separately).
constexpr bool is_never_persistable(Action a) noexcept {
    switch (a) {
        case Action::GitPush:
        case Action::Publish:
            return true;
        default:
            return false;
    }
}

/// Actions that must never be granted Permanent lifetime.
///
/// A permanent grant for a network/upload action becomes ambient
/// authority over the network boundary and must cap at Session.
///
/// • Network/Upload/Download — egress outside the workstation boundary.
/// • GitPush/Publish — already never persistable; included for completeness.
///
/// Execute/Write/Delete with explicit resource scopes MAY be permanent —
/// the user is consciously granting a named, scoped capability.
constexpr bool is_never_permanent(Action a) noexcept {
    switch (a) {
        case Action::Network:
        case Action::Upload:
        case Action::Download:
        case Action::GitPush:
        case Action::Publish:
            return true;
        default:
            return false;
    }
}

// ── Consent + decision (design.md "PolicyDecision") ──────────────────────────

/// Structured consent prompt. The UI renders Tool/Action/Target/Risk/Reason/
/// Scope/Lifetime — never raw LLM text.
struct ConsentRequest {
    std::string title;
    Risk risk = Risk::Medium;

    ToolRequest request;

    std::string userGoal;
    std::string whyNeeded;
    std::string possibleRisk;

    std::vector<std::string> resourcePreview;
    std::vector<std::string> choices;

    /// Sandbox backends the user may opt into for this request (e.g.
    /// "appcontainer"). Empty means the consent UI should not show sandbox
    /// routing controls. Populated only by SecurityGateway from registered
    /// backends; UI replies must choose one of these names.
    std::vector<std::string> sandboxBackends;

    /// Pre-computed scope suggestion for the consent card scope field.
    /// When non-empty, the UI pre-fills the editable scope input with this
    /// value instead of the raw resource URI.  Useful for normalizing
    /// cmd:// targets to "cmd://**" so one grant covers a session's commands
    /// rather than only the exact command string.
    std::string suggestedScope;

    /// Whether this request is eligible for SecurityAgent review / AI-delegated
    /// consent choices.  This is computed server-side from tool/action/target;
    /// UI payloads must not widen it.
    bool aiAutoAvailable = false;
};

/// What the user picked in the consent UI, resolved into a scoped grant.
struct ConsentResult {
    DecisionKind kind = DecisionKind::Deny;
    std::optional<CapabilityGrant> grant;
    bool openSettings = false;
    bool aiDelegated = false;
};

/// Internal record for AI consent attempts. It deliberately stores structured
/// request/decision metadata, not raw user prompt text.
struct AiConsentTrace {
    std::string presetName;
    std::string router;
    std::string model;
    Risk inputRisk = Risk::Medium;
    Risk ceilingRisk = Risk::Medium;
    DecisionKind outputDecision = DecisionKind::Deny;
    GrantLifetime outputLifetime = GrantLifetime::Once;
    bool ceilingExceeded = false;
    bool validJson = false;
    bool timedOut = false;
    std::string reason;
};

/// The gateway's decision for a request.
struct PolicyDecision {
    DecisionKind kind = DecisionKind::Deny;
    Risk risk = Risk::Medium;

    std::string reason;

    std::optional<CapabilityGrant> grant;
    std::optional<ConsentRequest> consent;

    /// Sandbox routing (Phase B). When non-empty the request is permitted *only*
    /// when executed inside the named backend (e.g. "appcontainer"); the gateway
    /// resolves the name via its BackendRouter. Empty = run in-process as usual.
    /// Sourced from a matching grant's `sandboxBackend` (user-consent driven).
    std::string sandboxBackend;
};

// ── MCP server policy (design.md "MCP rules") ────────────────────────────────

/// Per-server policy. MCP servers are untrusted unless registered here; remote
/// MCP defaults to High. Tool descriptions are never policy.
struct McpServerPolicy {
    std::string serverId;
    std::string executableHash;
    std::string manifestHash;
    bool signedManifest = false;

    Risk maxRisk = Risk::High;
    std::vector<std::string> allowedTools;
    std::vector<std::string> deniedTools;
};

// ── Classification result ─────────────────────────────────────────────────────

/// Output of the ResourceClassifier: the risk tier plus the signals that drove
/// it (for the audit log + consent "why").
struct ClassificationResult {
    Risk risk = Risk::Low;
    bool isSecret = false;            ///< matched a known secret pattern
    bool isOsProtected = false;       ///< OS-protected directory
    bool outsideWorkspace = false;    ///< target resolves outside workspaceRoot
    bool atWorkspaceRoot  = false;    ///< target lands directly in the workspace root dir (no subdir)
    std::vector<std::string> signals; ///< human-readable reasons (audit/consent)
};

// ── Built-in secret / high-risk pattern tables (design.md "Resource classifier")
//
// Lowercase, glob-style basenames/fragments. These are the security-relevant
// subset that should migrate *out* of src/file_extensions.hpp and behind the
// SecretPatternDelegate. Null-terminated for cheap C-style iteration.

inline constexpr const char* k_secret_basename_globs[] = {
    "*.pem", "*.key", "*.p12", "*.pfx", "*.crt", "*.der", "*.csr",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "known_hosts", "authorized_keys",
    "*.env", ".env*",
    "wallet.dat", "*.kdbx",
    "cookies.sqlite", "login data", "web data",
    "*token*", "*secret*", "*password*", "*credential*",
    "credentials", "credentials.json", "secrets.json",
    "*.vault-token", ".npmrc", ".netrc", ".pgpass",
    nullptr,
};

/// Directory fragments that always classify High (credential stores / OS dirs).
/// Forward-slash, lowercase; matched as a path substring after normalization.
inline constexpr const char* k_high_risk_dir_fragments[] = {
    "/.ssh/", "/.gnupg/", "/.aws/", "/.gcloud/", "/.azure/", "/.kube/",
    "/.docker/", "/.config/gh/", "/.config/git/",
    "/library/keychains/",
    "/appdata/roaming/microsoft/credentials/",
    "/appdata/roaming/microsoft/protect/",
    "/appdata/roaming/microsoft/vault/",
    "/windows/system32/config/",
    nullptr,
};

// ── Classification delegates (the file_extensions.hpp replacement seam) ───────
//
// Instead of hard-coding extension/secret predicates at every call site, the
// ResourceClassifier consults pluggable delegates. The default delegate (see
// ResourceClassifier.cpp) is backed by the tables above; richer delegates can
// layer MIME sniffing, content scans, gitignore/workspace-trust, or imported
// gitleaks/trufflehog rule sets without touching call sites.

/// Decides whether a resource matches a known-secret pattern.
class SecretPatternDelegate {
public:
    virtual ~SecretPatternDelegate() = default;
    /// True when @p target looks like a credential/secret by name or content.
    virtual bool isSecret(const ResourceTarget& target) const = 0;
};

/// Maps an extension / resource to a base risk tier (writes > reads handled by
/// the classifier, not the delegate).
class ExtensionRiskDelegate {
public:
    virtual ~ExtensionRiskDelegate() = default;
    /// Base risk implied purely by the resource's type/extension.
    virtual Risk riskForResource(const ResourceTarget& target) const = 0;
};

} // namespace pm::security
