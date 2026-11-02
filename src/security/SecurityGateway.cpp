#include "security/SecurityGateway.hpp"
#include "security/security_default.hpp"
#include "security/UriScope.hpp"
#include "logging/pm_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
constexpr std::string_view k_ch = "sec";

bool has_uri_scheme(const pm::security::ResourceTarget& target, std::string_view scheme)
{
    return target.uri.size() >= scheme.size()
        && target.uri.compare(0, scheme.size(), scheme) == 0;
}

// True when a scheme URI carries something after "scheme://" (e.g. cmd://<cmd>,
// screen://<app>, https://host/…) rather than a bare "screen://".
bool uri_has_detail(const std::string& uri)
{
    const auto parsed = pm::security::uri::parse_uri(uri);
    return parsed && !parsed->scheme.empty()
        && (!parsed->authority.empty() || !parsed->path.empty()
            || !parsed->query.empty() || !parsed->fragment.empty());
}

// General fallback preview: many tools (computer-use, inspection, MCP calls…)
// carry no concrete file/command/app target — their meaning lives in the call
// arguments. Emit a compact, human-readable "key: value" summary of the scalar
// top-level args so the consent dialog can always explain WHAT will happen,
// regardless of which tool is asking. Nested/opaque/noise keys are skipped.
void append_args_preview(std::vector<std::string>& out, const std::string& argumentsJson)
{
    if (argumentsJson.empty()) return;
    nlohmann::json j;
    try { j = nlohmann::json::parse(argumentsJson); } catch (...) { return; }
    if (!j.is_object()) return;

    static const std::set<std::string> skip = {
        "session", "session_id", "sessionId", "min_score", "minScore",
        "timeout_ms", "timeoutMs", "wait_ms", "waitMs", "hwnd", "ref", "nth",
    };
    int shown = 0;
    for (auto it = j.begin(); it != j.end() && shown < 6; ++it) {
        if (skip.count(it.key())) continue;
        const auto& v = it.value();
        std::string val;
        if (v.is_string())              val = v.get<std::string>();
        else if (v.is_boolean())        val = v.get<bool>() ? "true" : "false";
        else if (v.is_number_integer()) val = std::to_string(v.get<long long>());
        else if (v.is_number_unsigned())val = std::to_string(v.get<unsigned long long>());
        else if (v.is_number_float())   val = std::to_string(v.get<double>());
        else                            continue;  // objects/arrays/null → skip
        if (val.empty()) continue;
        if (val.size() > 120) val = val.substr(0, 117) + "...";
        out.push_back(it.key() + ": " + val);
        ++shown;
    }
}

bool ai_consent_eligible(const pm::security::ToolRequest& request)
{
    const std::string& tool = request.tool.toolId;

    // Shell, custom commands, schedulers, and computer-use are the primary
    // SecurityAgent advisory surface: they can mutate the machine or act outside
    // the workspace while still being legitimate agent work.
    if (request.action == pm::security::Action::Execute) {
        if (tool == "builtin.run" || tool == "builtin.run_sequence" ||
            tool == "builtin.create_command" ||
            tool == "builtin.schedule_at" || tool == "builtin.schedule_in" ||
            tool == "builtin.schedule_every" ||
            tool == "builtin.app_inspect_dump" || tool == "builtin.app_inspect_find" ||
            tool == "builtin.app_screenshot"    || tool == "builtin.app_click" ||
            tool == "builtin.app_drag"          || tool == "builtin.app_open" ||
            tool == "builtin.app_type"          || tool == "builtin.app_hotkey" ||
            tool == "builtin.app_close"         || tool == "builtin.app_batch" ||
            tool == "builtin.browser_click"     || tool == "builtin.browser_type" ||
            tool == "builtin.browser_select"      || tool == "builtin.browser_batch" ||
            tool == "builtin.browser_navigate"    ||
            tool == "builtin.app_command") {
            return true;
        }
        if (request.target && (has_uri_scheme(*request.target, "cmd://") ||
                               has_uri_scheme(*request.target, "screen://") ||
                               has_uri_scheme(*request.target, "app://"))) {
            return true;
        }
    }

    // File and generated-artifact writes benefit from advisory review because
    // scope and target path are often the difference between safe and dangerous.
    if (request.action == pm::security::Action::Write) {
        if (tool == "builtin.write_file" || tool == "builtin.create_file" ||
            tool == "builtin.download_url" ||
            tool == "builtin.image_transform" || tool == "builtin.transform" ||
            tool == "builtin.image_create"    || tool == "builtin.create_video" ||
            tool == "builtin.app_screenshot"  ||
            tool == "builtin.memory_write"    || tool == "builtin.memory_append_event") {
            return true;
        }
        if (request.target && (!request.target->path.empty() ||
                               has_uri_scheme(*request.target, "file://") ||
                               has_uri_scheme(*request.target, "screen://"))) {
            return true;
        }
    }

    return false;
}
} // namespace

namespace pm::security {

SecurityGateway::SecurityGateway(std::string appName, ConsentDelegate* consent)
    : appName_(std::move(appName)),
      crypto_(make_crypto_store()),
      store_(crypto_),
      consent_(consent) {
    // Best-effort: ensure the hardened security directory exists for later
    // SQLite persistence. Failure is non-fatal in Phase 1 (in-memory store).
    const SecurityPaths sp = resolve_security_paths(appName_);
    (void)harden_security_dir(sp.dir);
}

SecurityGateway::~SecurityGateway() = default;

ToolRequest SecurityGateway::normalize(const ToolRequest& request) const {
    ToolRequest req = request;
    if (req.target) {
        const CanonicalPath cp = paths_.canonicalize(req.target->path);
        req.target->path = cp.value;
        if (req.target->extension.empty())
            req.target->extension = cp.value.extension().string();
    }
    return req;
}

std::string SecurityGateway::denialKey(const ToolRequest& request) const {
    std::string key;
    key.reserve(256);
    key += request.sessionId;
    key += '|';
    key += request.taskId;
    key += '|';
    key += request.tool.provider;
    key += '|';
    key += request.tool.serverId;
    key += '|';
    key += request.tool.toolId;
    key += '|';
    key += std::string(to_string(request.action));
    key += '|';
    if (request.target) {
        if (!request.target->path.empty())
            key += request.target->path.generic_string();
        else
            key += request.target->uri;
    }
    return key;
}

PolicyDecision SecurityGateway::authorize(const ToolRequest& request) {
    const ToolRequest req = normalize(request);

    // 1) Invalidate any stored grants whose bound tool hash changed.
    if (const std::size_t n = store_.invalidateOnHashMismatch(req.tool); n > 0)
        audit_.recordEvent(AuditEvent::ToolHashChanged,
                           "invalidated " + std::to_string(n) + " grant(s)");

    // 2) Classify the target.
    std::optional<CanonicalPath> wsRoot;
    if (!req.workspaceRoot.empty())
        wsRoot = paths_.canonicalize(req.workspaceRoot);

    ClassificationResult cls;
    if (req.target)
        cls = classifier_.classify(*req.target, req.action, wsRoot);

    // 3) Compiled baseline decision.
    PolicyDecision decision = policy_.evaluateBaseline(req, cls);

    // 4) On Ask, an existing live grant upgrades to Allow.
    if (decision.kind == DecisionKind::Ask) {
        if (auto grant = store_.find(req)) {
            decision.kind = DecisionKind::Allow;
            decision.grant = std::move(grant);
            decision.reason = "covered by existing capability grant";
            pm::log::info_lazy(k_ch, [&decision] {
                const auto& g = *decision.grant;
                return std::string("existing grant matched id=") + g.id
                    + " lifetime=" + std::string(to_string(g.lifetime))
                    + " sessionId=" + g.sessionId
                    + " scopes=" + std::to_string(g.resourceScopes.size());
            });
        } else if (const std::string dk = denialKey(req);
                   std::find(deniedConsentKeys_.begin(), deniedConsentKeys_.end(), dk) != deniedConsentKeys_.end()) {
            decision.kind = DecisionKind::Deny;
            decision.reason = "covered by prior user denial";
        } else {
            pm::log::debug_lazy(k_ch, [&req] {
                return std::string("consent required tool=") + req.tool.toolId
                    + " action=" + std::string(to_string(req.action))
                    + " sessionId=" + req.sessionId
                    + " taskId=" + req.taskId;
            });
            decision.consent = buildConsentRequest(req, decision);
        }
    }

    // 4b) Sandbox routing (Phase B). A permitted request runs inside a sandbox
    //     when (a) the matching grant says so — the user-consent signal — or
    //     (b) the caller passed a hint. Either way we only route to a backend
    //     that is actually registered, so absence degrades safely to in-process.
    if (decision.kind == DecisionKind::Allow) {
        std::string want;
        if (decision.grant && !decision.grant->sandboxBackend.empty())
            want = decision.grant->sandboxBackend;
        else if (!req.sandboxHint.empty())
            want = req.sandboxHint;
        if (!want.empty() && sandboxRouter_.has(want))
            decision.sandboxBackend = want;
    }

    // 5) Audit the (pre-consent) decision.
    AuditEvent ev = AuditEvent::Deny;
    switch (decision.kind) {
        case DecisionKind::Allow:         ev = AuditEvent::Allow; break;
        case DecisionKind::Ask:           ev = AuditEvent::Ask; break;
        case DecisionKind::Sandbox:       ev = AuditEvent::Sandbox; break;
        case DecisionKind::AllowRedacted: ev = AuditEvent::Redacted; break;
        case DecisionKind::Deny:          ev = AuditEvent::Deny; break;
    }
    audit_.record(req, ev, decision.risk, decision.reason,
                  decision.grant ? decision.grant->id : std::string{});
    return decision;
}

ConsentRequest SecurityGateway::buildConsentRequest(const ToolRequest& request,
                                                    const PolicyDecision& decision) const {
    ConsentRequest cr;
    cr.title = "Allow " + std::string(to_string(request.action)) + "?";
    cr.risk = decision.risk;
    cr.request = request;
    cr.userGoal = request.userVisibleIntent;
    cr.whyNeeded = decision.reason;
    cr.possibleRisk = std::string(to_string(decision.risk)) + " risk";
    cr.aiAutoAvailable = ai_consent_eligible(request);
    if (request.target) {
        // Prefer the concrete filesystem path. For scheme URIs that carry no
        // path — cmd:// shell commands, screen:// computer-use, http(s)://
        // fetches — surface the URI itself so the human (and the AI reviewer)
        // can see WHAT actually runs. The grant scope deliberately stays broad
        // (e.g. cmd://**): arbitrary shell strings can't be safely pattern-
        // matched, so containment comes from the sandbox + AI review, not from
        // narrowing the scope. Showing the command here is the missing context.
        // A download carries both: the URL being fetched and the folder it
        // lands in. Show the URL first.
        if (request.tool.toolId == "builtin.download_url"
            && uri_has_detail(request.target->uri))
            cr.resourcePreview.push_back(request.target->uri);
        if (!request.target->path.empty())
            cr.resourcePreview.push_back(
                PathSecurity::normalizeForMatch(request.target->path));
        else if (uri_has_detail(request.target->uri)
                 && cr.resourcePreview.empty())
            cr.resourcePreview.push_back(request.target->uri);
    }
    // No concrete path/command/app target (computer-use, inspection, MCP, …):
    // fall back to a compact preview of the call arguments so the dialog always
    // shows meaningful detail rather than a bare scheme or nothing.
    if (cr.resourcePreview.empty())
        append_args_preview(cr.resourcePreview, request.argumentsJson);
    cr.choices = {"allow_once", "allow_session", "allow_always", "deny", "open_settings"};
    if ((request.action == Action::Execute || request.action == Action::Write) &&
        sandboxRouter_.size() > 0) {
        cr.sandboxBackends = sandboxRouter_.names();
    }

    // Execute: bind Always to a concrete file when the request carries one
    // (web.commandRun from a .page). cmd://** is only for path-less agent
    // shell so one session grant covers successive commands.
    if (request.action == Action::Execute && request.target) {
        if (!request.target->path.empty())
            cr.suggestedScope = PathSecurity::normalizeForMatch(request.target->path);
        else {
            const std::string& uri = request.target->uri;
            if (uri.size() >= 6 && uri.compare(0, 6, "cmd://") == 0)
                cr.suggestedScope = (request.tool.provider == "web") ? uri : "cmd://**";
        }
    }
    // Browser-use: one origin-level grant covers the whole builtin.browser_*
    // family (see build_consent_grant). Prefill scheme://host/** so "Always"
    // is meaningful without editing the scope field.
    if (cr.suggestedScope.empty() && request.target
        && request.tool.provider == "builtin"
        && request.tool.toolId.rfind("builtin.browser_", 0) == 0) {
        const auto pu = uri::parse_uri_lenient(request.target->uri);
        if (pu && pu->valid
            && (pu->scheme == "http" || pu->scheme == "https")
            && !pu->host.empty()) {
            cr.suggestedScope = pu->scheme + "://" + pu->host
                + (pu->port.empty() ? "" : ":" + pu->port) + "/**";
        } else if (request.target->uri.rfind("browser://", 0) == 0) {
            cr.suggestedScope = "browser://**";
        }
    }
    if (cr.suggestedScope.empty() && request.tool.toolId == "builtin.download_url"
        && request.target) {
        const auto pu = uri::parse_uri_lenient(request.target->uri);
        if (pu && pu->valid
            && (pu->scheme == "http" || pu->scheme == "https")
            && !pu->host.empty()) {
            cr.suggestedScope = pu->scheme + "://" + pu->host
                + (pu->port.empty() ? "" : ":" + pu->port) + "/**";
        }
    }
    if (cr.suggestedScope.empty()
        && request.action == Action::Write && request.target && !request.target->path.empty()) {
        const auto dir = request.target->path.parent_path();
        if (!dir.empty())
            cr.suggestedScope = "file://" + dir.generic_string() + "/**";
    }

    // Protocol-activate: pre-fill scope based on risk tier so "Allow always"
    // is meaningful without requiring the user to edit the field manually.
    //
    //  High  (xblox, scripts)  → exact URI   — each file must be approved
    //  Medium (html, svg)      → auth/dir/**  — folder-level
    //  Low   (images, docs)    → auth/**/*.ext — type-wide
    //
    // Uses uri::parse_uri() so all URI deconstruction is in one place.
    if (request.action == Action::ProtocolActivate && request.target
            && !request.target->uri.empty() && cr.suggestedScope.empty()) {

        const std::string& raw = request.target->uri;
        const auto pu = uri::parse_uri(raw);

        if (!pu || !pu->valid || pu->scheme.empty()) {
            // Unparseable — fall back to the exact URI.
            cr.suggestedScope = raw;
        } else {
            // Derive the extension from the last path segment (no query/fragment).
            const auto dot = pu->path.rfind('.');
            const auto sl  = pu->path.rfind('/');
            const std::string ext = (dot != std::string::npos &&
                                     (sl == std::string::npos || dot > sl))
                                    ? pu->path.substr(dot) : "";

            // Reconstruct "scheme://authority" prefix for scope patterns.
            const std::string auth_prefix = pu->scheme + "://"
                + (pu->host.empty() ? "" : pu->host)
                + (pu->port.empty() ? "" : ":" + pu->port);

            if (decision.risk >= Risk::High || ext.empty()) {
                // High risk or no extension: exact URI — must approve each resource.
                cr.suggestedScope = raw;
            } else if (decision.risk == Risk::Medium) {
                // Medium: folder subtree — strip the filename, keep the directory.
                // e.g. tanit://view/vfs/models/test/page.html → tanit://view/vfs/models/test/**
                const std::string dir = sl != std::string::npos
                    ? pu->path.substr(0, sl) : pu->path;
                cr.suggestedScope = auth_prefix + dir + "/**";
            } else {
                // Low: type glob — any file with this extension under the authority.
                // e.g. tanit://view/vfs/models/test/pic.png → tanit://view/**/*.png
                cr.suggestedScope = auth_prefix + "/**/*" + ext;
            }
        }
    }

    return cr;
}

PolicyDecision SecurityGateway::resolveConsent(const ToolRequest& request,
                                               PolicyDecision decision) {
    ConsentDelegate* delegate = consent_ ? consent_ : &denyAll_;

    ConsentRequest cr = decision.consent ? *decision.consent
                                         : buildConsentRequest(request, decision);
    ConsentResult result = delegate->requestConsent(cr);

    if (result.kind == DecisionKind::Allow) {
        decision.kind = DecisionKind::Allow;
        decision.reason = "user granted consent";
        if (result.grant) {
            result.grant->aiDelegated = result.aiDelegated || result.grant->aiDelegated;
            if (result.grant->approvedBy.empty() || result.grant->approvedBy == "human") {
                result.grant->approvedBy = result.grant->aiDelegated ? "ai:auto" : "human";
            }
            const CapabilityGrant& g = *result.grant;
            decision.grant = result.grant;
            if (store_.put(g)) {
                pm::log::info_lazy(k_ch, [&g] {
                    return std::string("grant stored id=") + g.id
                        + " action=" + std::string(to_string(g.action))
                        + " lifetime=" + std::string(to_string(g.lifetime))
                        + " sessionId=" + g.sessionId
                        + " scopes=" + std::to_string(g.resourceScopes.size());
                });
            } else {
                pm::log::warn_lazy(k_ch, [&g] {
                    return std::string("grant in-memory store rejected id=") + g.id
                        + " action=" + std::string(to_string(g.action))
                        + " lifetime=" + std::string(to_string(g.lifetime))
                        + " sessionId=" + g.sessionId
                        + " scopes=" + std::to_string(g.resourceScopes.size())
                        + " (will still attempt disk upsert if caller persists)";
                });
            }
        }
        // Route freshly-consented grants the same way authorize() does: an
        // "Always run in sandbox" choice persists as a grant carrying the name.
        {
            std::string want;
            if (decision.grant && !decision.grant->sandboxBackend.empty())
                want = decision.grant->sandboxBackend;
            else if (!request.sandboxHint.empty())
                want = request.sandboxHint;
            if (!want.empty() && sandboxRouter_.has(want))
                decision.sandboxBackend = want;
        }
        audit_.record(request, AuditEvent::UserGranted, decision.risk,
                      decision.reason, decision.grant ? decision.grant->id : std::string{});
    } else {
        decision.kind = DecisionKind::Deny;
        decision.reason = result.openSettings ? "user opened settings"
                                              : "user denied consent";
        const ToolRequest req = normalize(request);
        deniedConsentKeys_.push_back(denialKey(req));
        audit_.record(request, AuditEvent::UserDenied, decision.risk, decision.reason);
    }
    return decision;
}

} // namespace pm::security
