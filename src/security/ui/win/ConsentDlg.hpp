#pragma once
//
// pm::security::ui — Win32 consent surface for the security gateway.
//
// This is the first concrete `ConsentDelegate` (the CLI stdio delegate aside): a
// modal Win32 dialog that renders a structured `ConsentRequest`
// (Tool / Action / Risk / Why / Resource / Scope) and returns a scoped
// `ConsentResult`. It never shows raw LLM text and defaults to *deny* on cancel.
//
// Design goals (the security tool may ship as a standalone lib/CLI for other
// apps — docs/security/design.md):
//   * No dependency on the main app's UI stack (theme/font/settings helpers).
//     DPI, i18n and a minimal dark/light palette are self-contained here; the
//     caller passes *options* (language, theme) — "defaults & store & options".
//   * Grant construction is injected (`makeGrant`) so the dialog stays agnostic
//     of how a choice maps to a persisted capability grant.
//
// Windows-only; the header is intentionally free of <windows.h> so it can be
// included from the portable CLI translation unit without macro pollution.
//

#include "security/ConsentDelegate.hpp"
#include "security/types.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace pm::security::ui {

/// Structured result of an on-demand AI security review, mirroring the WebView
/// ConsentCard's `aiReview` block. Kept as plain data so the dialog stays free
/// of the LLM/agent + JSON layer; the host converts its review JSON into this
/// (see consent_ai_review.hpp) and hands it back via `ConsentUiOptions::runAiReview`.
struct AiConsentReview {
    /// The review completed and produced a usable verdict.
    bool ok = false;
    /// The review failed / timed out; `reason` carries the human-readable error.
    bool error = false;

    /// Risk the reviewer assessed (may exceed the request's original risk).
    Risk assessedRisk = Risk::Medium;
    /// True when the reviewer raised the risk above the request's original tier.
    bool riskRaised = false;

    /// Reviewer rationale (never raw model text beyond this single field).
    std::string reason;
    /// Optional bullet notes.
    std::vector<std::string> notes;

    /// Recommendation: "allow" | "deny" | "ask" (empty when none).
    std::string decision;
    /// Recommended grant lifetime, when the reviewer suggested one.
    std::optional<GrantLifetime> lifetime;
    /// Recommended (narrowed) scope, when suggested.
    std::string scope;
    /// Recommended sandbox backend, when suggested (must be one the request offered).
    std::string sandboxBackend;
};

/// Caller-supplied configuration. The embedding app provides these; the dialog
/// owns no global state.
struct ConsentUiOptions {
    /// UI language: "en", "de", "es", "fr", "it", "ar", "zh"
    /// (extension/region-insensitive; unknown → en).
    std::string language = "en";

    /// Dark vs light palette + titlebar.
    bool dark = false;

    /// Whether to show AI-delegated allow choices. The delegate still returns a
    /// normal scoped grant, marked `aiDelegated`, for the gateway to persist.
    bool aiAutoAvailable = false;

    /// Builds the capability grant for an *allow* choice. Receives the request,
    /// the chosen lifetime, and any user-narrowed resource scopes (empty = derive
    /// a default from the request). When unset, an allow yields no stored grant
    /// (one-shot allow). Lets the host own the grant model.
    std::function<CapabilityGrant(const ToolRequest&,
                                  GrantLifetime,
                                  std::vector<std::string>)>
        makeGrant;

    /// Config directory the host may surface elsewhere. Currently unused by the
    /// dialog (the in-dialog "Open settings" button was removed); kept so hosts
    /// can keep populating it without a signature change.
    std::string settingsPath;

    /// Optional: run a synchronous AI security review of the request. When set
    /// (and `aiAutoAvailable`), the dialog shows a "Review with AI" button;
    /// clicking it invokes this callback **on a worker thread**, then renders the
    /// returned reason/notes, raises the displayed risk if the review does, and
    /// enables "Apply recommendation" + AI-delegated allow. Injected as a
    /// callback so this UI stays free of the LLM/agent layer. May block (network
    /// LLM call); the dialog stays responsive while it runs.
    std::function<AiConsentReview(const ConsentRequest&)> runAiReview;
};

/// Show the modal consent dialog for @p request. Returns the user's scoped
/// choice. Closing / cancelling (Esc, the close box, the Deny button) yields a
/// `Deny` (`openSettings == false`).
ConsentResult show_consent_dialog(const ConsentRequest& request,
                                  const ConsentUiOptions& opts);

/// `ConsentDelegate` that drives the Win32 dialog. Options are copied at
/// construction; inject it into a `SecurityGateway` like any other delegate.
class Win32ConsentDelegate final : public ConsentDelegate {
public:
    explicit Win32ConsentDelegate(ConsentUiOptions opts) : opts_(std::move(opts)) {}

    ConsentResult requestConsent(const ConsentRequest& request) override {
        return show_consent_dialog(request, opts_);
    }

private:
    ConsentUiOptions opts_;
};

} // namespace pm::security::ui
