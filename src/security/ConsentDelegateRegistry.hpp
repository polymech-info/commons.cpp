#pragma once
//
// pm::security — global active-consent-delegate registry.
//
// Provides a lightweight, thread-safe slot that the UI layer (e.g.
// CChatWebView::Impl) fills while a panel is alive so that the LLM
// agent loop can use an interactive in-app consent surface instead of
// the CLI fallback.
//
// Lifecycle:
//   • CChatWebView::Impl::InstallChatConsentDelegate() calls
//     set_active_consent_delegate(&webview_delegate_) on the UI thread.
//   • agent_factory.cpp reads active_consent_delegate() before each turn
//     and passes the result (or a CliConsentDelegate fallback) to the
//     SecurityGateway that guards that turn.
//   • CChatWebView::Impl::ClearChatConsentDelegate() calls
//     clear_active_consent_delegate(&webview_delegate_) on teardown.
//

namespace pm::security {

class ConsentDelegate;

/// Install a consent delegate for this process. Thread-safe.
/// Passing nullptr is equivalent to clear_active_consent_delegate(nullptr).
void set_active_consent_delegate(ConsentDelegate* d) noexcept;

/// Clear the registry slot.  If `d` is non-null only clears if the slot
/// still holds exactly `d` (CAS — prevents a late-arriving dtor from
/// evicting a replacement that installed after it).  If `d` is nullptr
/// unconditionally clears.
void clear_active_consent_delegate(ConsentDelegate* d = nullptr) noexcept;

/// Return the currently registered delegate or nullptr. Thread-safe.
ConsentDelegate* active_consent_delegate() noexcept;

} // namespace pm::security
