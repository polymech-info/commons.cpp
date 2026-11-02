#pragma once
//
// pm::security::CliConsentDelegate — stdio consent surface shared by the
// pm-image-security CLI tool and the LLM agent loop.
//
// The gateway hands a structured ConsentRequest to requestConsent(); we emit it
// to stderr (JSON when json_mode=true, human-readable otherwise) and block on
// one stdin line. Safe default on blank input / EOF = Deny.
//
// Also provides build_consent_grant() — the shared grant factory used by both
// the CLI authorize command and the agent's session-scoped grants.
//
// Design reference: docs/security/design.md ("Consent delegate").
//

#include "security/security_default.hpp"
#include "security/SecurityPersistence.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace pm::security {

// ── Shared helpers ────────────────────────────────────────────────────────────

inline std::string consent_new_grant_id(std::string_view prefix = "grant") {
    static std::atomic<uint32_t> seq{0};
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    return std::string(prefix) + "-" + std::to_string(ms)
           + "-" + std::to_string(seq.fetch_add(1));
}

inline std::string consent_trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

/// Build a CapabilityGrant from the request after the user chose a lifetime.
/// Empty @p scopes → derive a default scope from request.target (canonical
/// path or URI). Falls back to "any:" sentinel when there is no target.
///
/// Browser-use tools share one family grant (`builtin.browser_*`) so a single
/// Allow covers click/type/batch/navigate/… for the chosen origin scope.
inline CapabilityGrant build_consent_grant(const ToolRequest&      req,
                                           GrantLifetime           lt,
                                           std::vector<std::string> scopes = {})
{
    CapabilityGrant g;
    g.id          = consent_new_grant_id("grant-consent");
    g.subject     = std::string(to_string(req.actor));
    g.profile     = req.profile;
    g.policyVersion = k_policy_version;
    g.tool        = req.tool;
    // One consent covers the whole browser-use tool family (exact toolId would
    // re-prompt on browser_batch after browser_click, etc.).
    if (g.tool.provider == "builtin"
        && g.tool.toolId.rfind("builtin.browser_", 0) == 0)
        g.tool.toolId = "builtin.browser_*";
    g.action      = req.action;
    g.readOnly    = (req.action == Action::Read);
    g.lifetime    = lt;
    g.workspaceId = req.workspaceId;
    if (g.workspaceId.empty() && !req.workspaceRoot.empty())
        g.workspaceId = req.workspaceRoot.generic_string();
    if (lt == GrantLifetime::Session) g.sessionId = req.sessionId;
    if (lt == GrantLifetime::Task)    g.taskId    = req.taskId;
    if (!scopes.empty()) {
        g.resourceScopes = std::move(scopes);
    } else if (req.target) {
        PathSecurity ps;
        if (!req.target->path.empty())
            g.resourceScopes = {ps.canonicalize(req.target->path).value.generic_string()};
        else if (!req.target->uri.empty())
            g.resourceScopes = {req.target->uri};
    }
    if (g.resourceScopes.empty())
        g.resourceScopes = {"any:"};  // sentinel: no resource target for this tool
    g.reason = "granted via consent";
    return g;
}

/// Non-interactive delegate that allows everything — harness / yolo mode.
/// Mirror of `DenyAllConsentDelegate`. Issues a Session-scoped grant so the
/// gateway does not re-prompt on every subsequent Ask in the same run.
class AllowAllConsentDelegate final : public ConsentDelegate {
public:
    explicit AllowAllConsentDelegate(GrantLifetime lt = GrantLifetime::Session)
        : lifetime_(lt)
    {
    }

    ConsentResult requestConsent(const ConsentRequest& cr) override
    {
        ConsentResult r;
        r.kind  = DecisionKind::Allow;
        r.grant = build_consent_grant(cr.request, lifetime_);
        if (r.grant) {
            r.grant->reason     = "auto-allow (yolo)";
            r.grant->approvedBy = "auto-allow";
        }
        return r;
    }

private:
    GrantLifetime lifetime_;
};

// ── CliConsentDelegate ────────────────────────────────────────────────────────

/// Stdio consent surface. Presents the ConsentRequest on stderr and reads one
/// response line from stdin. Accepts bare choice tokens
/// ("allow_once" | "allow_session" | "allow_task" | "allow" |
/// "ai_auto_once" | "ai_auto_session" | "ai_auto_task" | "ai_auto_always" |
/// "deny" | "open_settings") or a JSON object
/// {"choice","lifetime","scopes":[...],"sandboxBackend":"appcontainer"}.
///
/// @param json_mode  When true emits a machine-readable JSON event on stderr;
///                   when false emits a human-readable prompt.
class CliConsentDelegate final : public ConsentDelegate {
public:
    explicit CliConsentDelegate(bool json_mode = false) : json_mode_(json_mode) {}

    ConsentResult requestConsent(const ConsentRequest& cr) override {
        emit_prompt(cr);
        std::string line;
        if (!std::getline(std::cin, line))
            return deny(false);  // non-interactive / EOF → safe default
        return parse_response(cr, line);
    }

private:
    bool json_mode_;

    static ConsentResult deny(bool openSettings = false) {
        ConsentResult r;
        r.kind         = DecisionKind::Deny;
        r.openSettings = openSettings;
        return r;
    }

    void emit_prompt(const ConsentRequest& cr) const {
        if (json_mode_) {
            nlohmann::json p{
                {"event",           "consent_request"},
                {"title",           cr.title},
                {"risk",            std::string(to_string(cr.risk))},
                {"action",          std::string(to_string(cr.request.action))},
                {"tool",            cr.request.tool.toolId},
                {"provider",        cr.request.tool.provider},
                {"whyNeeded",       cr.whyNeeded},
                {"possibleRisk",    cr.possibleRisk},
                {"resourcePreview", cr.resourcePreview},
                {"choices",         cr.choices},
                {"sandboxBackends", cr.sandboxBackends},
                {"aiAutoAvailable", cr.aiAutoAvailable},
            };
            std::cerr << p.dump() << "\n";
            return;
        }
        std::cerr << "\n[consent] " << cr.title
                  << "  (risk: " << to_string(cr.risk) << ")\n";
        if (!cr.whyNeeded.empty())
            std::cerr << "  why: " << cr.whyNeeded << "\n";
        for (const auto& rp : cr.resourcePreview)
            std::cerr << "  resource: " << rp << "\n";
        if (!cr.sandboxBackends.empty()) {
            std::cerr << "  sandbox: ";
            for (std::size_t i = 0; i < cr.sandboxBackends.size(); ++i) {
                if (i) std::cerr << ", ";
                std::cerr << cr.sandboxBackends[i];
            }
            std::cerr << " (JSON: {\"sandboxBackend\":\"...\"})\n";
        }
        std::cerr << "  choose: allow_once | allow_session | allow_task | allow_always"
                     " | ai_auto_once | ai_auto_session | ai_auto_task | ai_auto_always"
                     " | deny | open_settings\n> " << std::flush;
    }

    ConsentResult parse_response(const ConsentRequest& cr,
                                 const std::string&    raw) const
    {
        std::string              choice;
        std::string              lifetime_str;
        std::string              sandbox_backend;
        bool                     sandbox_default = false;
        bool                     ai_delegated = false;
        std::vector<std::string> scopes;

        const std::string t = consent_trim(raw);
        if (!t.empty() && t.front() == '{') {
            try {
                const auto j = nlohmann::json::parse(t);
                choice       = j.value("choice",   std::string{});
                lifetime_str = j.value("lifetime",  std::string{});
                sandbox_backend = j.value("sandboxBackend", std::string{});
                if (sandbox_backend.empty())
                    sandbox_backend = j.value("sandbox_backend", std::string{});
                sandbox_default = j.value("sandbox", false);
                if (j.contains("scopes") && j["scopes"].is_array())
                    for (const auto& s : j["scopes"])
                        if (s.is_string()) scopes.push_back(s.get<std::string>());
            } catch (...) {
                choice = t;
            }
        } else {
            choice = t;
        }

        if (choice.empty() || choice == "deny")          return deny(false);
        if (choice == "open_settings")                   return deny(true);

        GrantLifetime lt = GrantLifetime::Once;
        if (choice == "ai_auto") {
            if (!cr.aiAutoAvailable) return deny(false);
            ai_delegated = true;
            lt = persist::parse_lifetime(lifetime_str).value_or(GrantLifetime::Once);
        } else if (choice.rfind("ai_auto_", 0) == 0) {
            if (!cr.aiAutoAvailable) return deny(false);
            ai_delegated = true;
            const std::string suffix = choice.substr(std::string("ai_auto_").size());
            if      (suffix == "session") lt = GrantLifetime::Session;
            else if (suffix == "task")    lt = GrantLifetime::Task;
            else if (suffix == "always" || suffix == "permanent")
                                           lt = GrantLifetime::Permanent;
            else                           lt = GrantLifetime::Once;
        } else if (choice == "allow_session")            lt = GrantLifetime::Session;
        else if (choice == "allow_task")                 lt = GrantLifetime::Task;
        else if (choice == "allow_always" || choice == "allow_permanent")
                                                         lt = GrantLifetime::Permanent;
        else if (choice == "allow_once" || choice == "allow")
                                                         lt = GrantLifetime::Once;
        else if (!lifetime_str.empty())
            lt = persist::parse_lifetime(lifetime_str).value_or(GrantLifetime::Once);
        else
            return deny(false);  // unrecognised token → deny

        if (scopes.empty() && !cr.suggestedScope.empty())
            scopes.push_back(cr.suggestedScope);

        ConsentResult r;
        r.kind  = DecisionKind::Allow;
        r.aiDelegated = ai_delegated;
        r.grant = build_consent_grant(cr.request, lt, std::move(scopes));
        if (r.grant) {
            r.grant->aiDelegated = ai_delegated;
            r.grant->approvedBy = ai_delegated ? "ai:cli" : "human";
            if (sandbox_backend.empty() && sandbox_default && !cr.sandboxBackends.empty())
                sandbox_backend = cr.sandboxBackends.front();
            if (!sandbox_backend.empty()) {
                for (const auto& name : cr.sandboxBackends) {
                    if (name == sandbox_backend) {
                        r.grant->sandboxBackend = sandbox_backend;
                        break;
                    }
                }
            }
        }
        return r;
    }
};

} // namespace pm::security
