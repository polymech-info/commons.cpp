#pragma once
//
// pm::security::SecurityGateway — the single choke point for tool authorization.
//
//      ToolRequest → authorize() → normalize/canonicalize → classify risk
//        → baseline policy → persisted/session grants → decision
//        (allow / deny / ask / sandbox / allow_redacted)
//
// No native tool, MCP tool, plugin, or background agent may bypass this class
// (design.md "SecurityGateway API"). `executeIfAllowed` is the convenience
// wrapper that runs a scoped executor only when the decision permits it,
// prompting through the ConsentDelegate on `Ask`.
//
// Design reference: docs/security/design.md ("Main flow", "SecurityGateway API").
//

#include "security/AuditLog.hpp"
#include "security/ConsentDelegate.hpp"
#include "security/CryptoStore.hpp"
#include "security/PermissionStore.hpp"
#include "security/PolicyEngine.hpp"
#include "security/ResourceClassifier.hpp"
#include "security/ToolIdentity.hpp"
#include "security/types.hpp"
#include "security/backends/BackendRouter.hpp"

#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace pm::security {

/// Failure carried back from `executeIfAllowed` when a request is not permitted.
struct SecurityError {
    DecisionKind kind = DecisionKind::Deny;
    Risk risk = Risk::Medium;
    std::string reason;
};

/// Minimal Expected<T>: holds either a value or a SecurityError. A void
/// specialization follows for executors that return nothing.
template <class T>
class Expected {
public:
    static Expected success(T v) { Expected e; e.value_ = std::move(v); return e; }
    static Expected failure(SecurityError err) { Expected e; e.error_ = std::move(err); return e; }

    bool ok() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return ok(); }

    T& operator*() { return *value_; }
    const T& operator*() const { return *value_; }
    const SecurityError& error() const { return *error_; }

private:
    std::optional<T> value_;
    std::optional<SecurityError> error_;
};

template <>
class Expected<void> {
public:
    static Expected success() { Expected e; e.ok_ = true; return e; }
    static Expected failure(SecurityError err) { Expected e; e.ok_ = false; e.error_ = std::move(err); return e; }

    bool ok() const noexcept { return ok_; }
    explicit operator bool() const noexcept { return ok_; }
    const SecurityError& error() const { return *error_; }

private:
    bool ok_ = false;
    std::optional<SecurityError> error_;
};

class SecurityGateway {
public:
    /// @p appName drives the security/ storage path (default "pm-image").
    /// @p consent is borrowed (not owned); when null, `Ask` degrades to deny.
    explicit SecurityGateway(std::string appName = "pm-image",
                             ConsentDelegate* consent = nullptr);
    ~SecurityGateway();

    /// Core decision: classify → policy → grants. Does not run anything and does
    /// not prompt; `Ask` results carry a populated `consent` request.
    PolicyDecision authorize(const ToolRequest& request);

    /// Authorize and, on `Ask`, immediately prompt through the consent delegate,
    /// returning the final folded decision (Allow/Deny) plus any persisted grant.
    /// Convenience for front-ends that *are* the consent UI (CLI, embedded apps).
    PolicyDecision authorizeWithConsent(const ToolRequest& request) {
        PolicyDecision d = authorize(request);
        if (d.kind == DecisionKind::Ask)
            d = resolveConsent(request, std::move(d));
        return d;
    }

    /// Authorize @p request and, if permitted (allow, or ask→consent→allow), run
    /// @p executor. Returns the executor's result or a SecurityError.
    template <class Fn>
    auto executeIfAllowed(const ToolRequest& request, Fn&& executor)
        -> Expected<std::invoke_result_t<Fn>> {
        using R = std::invoke_result_t<Fn>;

        PolicyDecision decision = authorize(request);
        if (decision.kind == DecisionKind::Ask)
            decision = resolveConsent(request, std::move(decision));

        if (decision.kind != DecisionKind::Allow) {
            SecurityError err{decision.kind, decision.risk, decision.reason};
            if constexpr (std::is_void_v<R>)
                return Expected<void>::failure(std::move(err));
            else
                return Expected<R>::failure(std::move(err));
        }

        if constexpr (std::is_void_v<R>) {
            std::forward<Fn>(executor)();
            return Expected<void>::success();
        } else {
            return Expected<R>::success(std::forward<Fn>(executor)());
        }
    }

    /// Swap the consent delegate (e.g. once the UI is constructed).
    void setConsentDelegate(ConsentDelegate* consent) noexcept { consent_ = consent; }

    /// Register a sandbox backend (borrowed). Call once at startup, e.g.
    /// `gw.registerSandboxBackend(&appContainer)` on Win32. A request whose
    /// decision carries a matching `sandboxBackend` name routes through it.
    void registerSandboxBackend(SandboxBackend* backend) {
        sandboxRouter_.registerBackend(backend);
    }
    BackendRouter& sandboxRouter() noexcept { return sandboxRouter_; }

    /// Resolve the backend a permitted decision must run inside, or nullptr when
    /// the decision is not sandbox-routed (or the named backend is unregistered).
    SandboxBackend* sandboxBackendFor(const PolicyDecision& decision) const {
        return sandboxRouter_.resolve(decision.sandboxBackend);
    }

    /// Access the underlying components (for settings UIs / tests).
    PermissionStore& permissions() noexcept { return store_; }
    AuditLog& audit() noexcept { return audit_; }
    ResourceClassifier& classifier() noexcept { return classifier_; }

private:
    /// Build the structured ConsentRequest for an `Ask` decision.
    ConsentRequest buildConsentRequest(const ToolRequest& request,
                                       const PolicyDecision& decision) const;

    /// Prompt via the consent delegate, persist any returned grant, audit the
    /// outcome, and fold it back into a decision.
    PolicyDecision resolveConsent(const ToolRequest& request, PolicyDecision decision);

    /// Fill canonical path / extension on a copy of the request's target.
    ToolRequest normalize(const ToolRequest& request) const;

    /// Stable in-process key for a denied consent request. This is deliberately
    /// session-local (not persisted): an exact repeated request in the same
    /// agent/gateway instance should fail closed without nagging the user again.
    std::string denialKey(const ToolRequest& request) const;

    std::string appName_;
    std::shared_ptr<CryptoStore> crypto_;
    PolicyEngine policy_;
    PermissionStore store_;
    ResourceClassifier classifier_;
    AuditLog audit_;
    PathSecurity paths_;
    ConsentDelegate* consent_ = nullptr;       // borrowed
    DenyAllConsentDelegate denyAll_;           // fallback when consent_ is null
    BackendRouter sandboxRouter_;              // name → SandboxBackend (borrowed)
    std::vector<std::string> deniedConsentKeys_;
};

} // namespace pm::security
