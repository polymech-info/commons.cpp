#include "security/PolicyEngine.hpp"

namespace pm::security {

namespace {

PolicyDecision make(DecisionKind kind, Risk risk, std::string reason) {
    PolicyDecision d;
    d.kind = kind;
    d.risk = risk;
    d.reason = std::move(reason);
    return d;
}

// Actions that are categorically dangerous regardless of profile-specific allow
// lists: arbitrary execute, delete, push, publish, upload. Never allow-by-default.
// Push/publish are also never persistable (see is_never_persistable); Execute may
// persist as a scoped grant after user consent.
bool is_dangerous(Action a) {
    switch (a) {
        case Action::Execute:
        case Action::Delete:
        case Action::GitPush:
        case Action::Publish:
        case Action::Upload:
            return true;
        default:
            return false;
    }
}

} // namespace

// ── LIGHT (design "EndUser") ──────────────────────────────────────────────────
// Default deny agent/plugin shell/delete/push/publish/upload, secrets, writes
// outside the workspace. Ask for Documents/Desktop reads, generated writes,
// external URLs, and user-initiated execute (web commandRun / shell-open).
// Allow workspace reads, selected files, chosen output writes.
PolicyDecision PolicyEngine::evalLight(const ToolRequest& req,
                                       const ClassificationResult& cls) const {
    if (cls.isSecret)
        return make(DecisionKind::Deny, Risk::Critical, "secret/credential access denied (LIGHT)");
    if (is_dangerous(req.action)) {
        // ButtonWidget / page-authored commandRun is Actor::User. Agent, plugin,
        // and MCP execute stay deny so LIGHT never silently runs a tool.
        if (req.action == Action::Execute && req.actor == Actor::User)
            return make(DecisionKind::Ask, max_risk(cls.risk, Risk::High),
                        "execute requires consent (LIGHT)");
        return make(DecisionKind::Deny, max_risk(cls.risk, Risk::High),
                    "dangerous action denied by default (LIGHT)");
    }

    switch (req.action) {
        case Action::Read:
            if (cls.outsideWorkspace)
                return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                            "read outside workspace requires consent (LIGHT)");
            return make(DecisionKind::Allow, cls.risk, "workspace read allowed (LIGHT)");
        case Action::Write:
            if (cls.outsideWorkspace)
                return make(DecisionKind::Deny, max_risk(cls.risk, Risk::High),
                            "write outside workspace denied (LIGHT)");
            return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                        "write requires consent (LIGHT)");
        case Action::Network:
        case Action::Download:
            return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                        "network access requires consent (LIGHT)");
        case Action::ProtocolActivate:
            return make(DecisionKind::Ask, cls.risk,
                        "protocol URI activation requires consent (LIGHT)");
        default:
            return make(DecisionKind::Ask, cls.risk, "requires consent (LIGHT)");
    }
}

// ── STRICT (design "OEM") ─────────────────────────────────────────────────────
// Deny everything except explicitly registered, signed tools. No arbitrary
// shell/file system, signed plugins/MCP only, approved directories only.
PolicyDecision PolicyEngine::evalStrict(const ToolRequest& req,
                                        const ClassificationResult& cls) const {
    const bool registered_signed =
        req.tool.signedManifest && !req.tool.manifestHash.empty();
    if (!registered_signed)
        return make(DecisionKind::Deny, max_risk(cls.risk, Risk::High),
                    "STRICT: only explicitly registered, signed tools are allowed");
    if (cls.isSecret || is_dangerous(req.action))
        return make(DecisionKind::Deny, Risk::Critical,
                    "STRICT: dangerous/secret access denied");
    if (cls.outsideWorkspace)
        return make(DecisionKind::Deny, max_risk(cls.risk, Risk::High),
                    "STRICT: access outside approved directories denied");
    if (req.action == Action::Read)
        return make(DecisionKind::Allow, cls.risk, "STRICT: registered tool workspace read");
    return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                "STRICT: registered tool action requires consent");
}

// ── DEVELOPER (design "Dev") ──────────────────────────────────────────────────
// Allow workspace read/write, known build/test, git status/diff, local RO MCP.
// Ask for package managers, docker, network POST, git commit, writes outside.
// Deny / critical-ask git push, publish, sudo, ~/.ssh, browser profiles, creds.
PolicyDecision PolicyEngine::evalDeveloper(const ToolRequest& req,
                                           const ClassificationResult& cls) const {
    if (cls.isSecret)
        return make(DecisionKind::Deny, Risk::Critical,
                    "secret/credential access denied (DEVELOPER)");
    if (req.action == Action::GitPush || req.action == Action::Publish)
        return make(DecisionKind::Deny, Risk::High,
                    "git push / publish denied by default (DEVELOPER)");
    if (req.action == Action::Delete || req.action == Action::Upload)
        return make(DecisionKind::Ask, max_risk(cls.risk, Risk::High),
                    "high-impact action requires consent (DEVELOPER)");
    if (req.action == Action::Execute) {
        // Risk shown on the consent card reflects containment, not the classifier's
        // generic Execute→High floor. Secret targets always surface as Critical.
        // Sandbox available → Medium (contained); no sandbox → High (full user context).
        const Risk effective = cls.isSecret  ? Risk::Critical
                             : req.sandboxAvailable ? Risk::Medium
                             : Risk::High;
        const char* reason = req.sandboxAvailable
            ? "execute requires consent (DEVELOPER) — runs in AppContainer"
            : "execute requires consent (DEVELOPER) — no sandbox";
        return make(DecisionKind::Ask, effective, reason);
    }

    switch (req.action) {
        case Action::Read:
            // Out-of-workspace reads (Desktop, Documents, arbitrary paths) need
            // consent even in Developer mode — workspace contents are trusted,
            // the rest of the filesystem is not.
            if (cls.outsideWorkspace)
                return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Low),
                            "read outside workspace requires consent (DEVELOPER)");
            return make(DecisionKind::Allow, cls.risk, "workspace/dev read allowed (DEVELOPER)");
        case Action::Write:
            if (!cls.outsideWorkspace && req.tool.toolId == "builtin.download_url")
                return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                            "download requires consent (DEVELOPER)");
            if (cls.outsideWorkspace)
                return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                            "write outside workspace requires consent (DEVELOPER)");
            return make(DecisionKind::Allow, cls.risk, "workspace write allowed (DEVELOPER)");
        case Action::Network:
        case Action::Download:
            return make(DecisionKind::Ask, max_risk(cls.risk, Risk::Medium),
                        "network access requires consent (DEVELOPER)");
        case Action::ProtocolActivate:
            return make(DecisionKind::Ask, cls.risk,
                        "protocol URI activation requires consent (DEVELOPER)");
        default:
            return make(DecisionKind::Ask, cls.risk, "requires consent (DEVELOPER)");
    }
}

PolicyDecision PolicyEngine::evaluateBaseline(const ToolRequest& request,
                                              const ClassificationResult& classification) const {
    PolicyDecision d;
    switch (request.profile) {
        case Profile::Strict:    d = evalStrict(request, classification); break;
        case Profile::Developer: d = evalDeveloper(request, classification); break;
        case Profile::Light:
        default:                 d = evalLight(request, classification); break;
    }
    // TODO(security, Phase 3): apply signed policy bundle, then user overrides
    // that may only tighten (allow→ask, add deny); never loosen.
    return d;
}

} // namespace pm::security
