#pragma once
//
// pm::security::ConsentDelegate — UI seam for fresh user consent.
//
// The gateway hands the UI a structured `ConsentRequest` (Tool / Action /
// Target / Risk / Reason / Scope / Lifetime) and receives back a scoped
// `ConsentResult` — never raw LLM text, never a bare "Allow tool?".
//
// This header is interface-only; concrete delegates live in the UI layers
// (Win32 dialog, WebView consent surface) and are injected into the gateway.
//
// Design reference: docs/security/design.md ("Consent delegate").
//

#include "security/types.hpp"

namespace pm::security {

class ConsentDelegate {
public:
    virtual ~ConsentDelegate() = default;

    /// Present @p request to the user and return their scoped choice. Implementations
    /// must default to deny on cancel/timeout/non-interactive contexts.
    virtual ConsentResult requestConsent(const ConsentRequest& request) = 0;
};

/// Non-interactive delegate that denies everything — the safe default when no UI
/// is wired (headless CLI, services). Injected by the gateway when consent is
/// null so an `Ask` decision degrades to deny rather than silently allowing.
class DenyAllConsentDelegate final : public ConsentDelegate {
public:
    ConsentResult requestConsent(const ConsentRequest&) override {
        ConsentResult r;
        r.kind = DecisionKind::Deny;
        return r;
    }
};

} // namespace pm::security
