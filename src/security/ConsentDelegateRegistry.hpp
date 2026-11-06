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
// The slot is one per process. It is compiled into pm-media and exported,
// because the exe installs the delegate and tanit-chat-plugin reads it.
// A copy inside pm-commons-lib is a different pointer in each image, so the
// plugin never sees the exe's auto-allow or WebView delegate and denies.

#include "export/polymech_export.h"

namespace pm::security {

class ConsentDelegate;

/// Install a consent delegate for this process. Thread-safe.
/// Passing nullptr is equivalent to clear_active_consent_delegate(nullptr).
POLYMECH_API void set_active_consent_delegate(ConsentDelegate* d) noexcept;

/// Clear the registry slot.  If `d` is non-null only clears if the slot
/// still holds exactly `d` (CAS — prevents a late-arriving dtor from
/// evicting a replacement that installed after it).  If `d` is nullptr
/// unconditionally clears.
POLYMECH_API void clear_active_consent_delegate(ConsentDelegate* d = nullptr) noexcept;

/// Return the currently registered delegate or nullptr. Thread-safe.
POLYMECH_API ConsentDelegate* active_consent_delegate() noexcept;

} // namespace pm::security
