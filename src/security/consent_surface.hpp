#pragma once
//
// Shared consent-surface installer for CLI `llm agent` and headless xblox
// `llmAgent` turns. Selects cli | win32 | stream | auto-deny | auto-allow and installs
// the matching ConsentDelegate into ConsentDelegateRegistry for the RAII
// lifetime. Win32 dialog code is gated on PM_CLI_CONSENT_UI (compiled into
// the exe and tanit-chat-plugin, not pm-media).
//

#include <cstdint>
#include <functional>
#include <string>

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
#include "security/ConsentDelegate.hpp"
#include "security/ui/win/ConsentDlg.hpp"

#include <functional>
#include <memory>
#endif

namespace pm::security {

/// Lowercase / trim a `--consent-ui` token. `yolo` → `auto-allow`.
std::string normalize_consent_ui_token(std::string raw);

/// Resolve the surface token used at launch.
/// Empty / `auto` / `preset` fall through to @p preset_consent_ui when set,
/// otherwise @p fallback_when_empty (`win32` for `llm agent` and xblox).
std::string resolve_consent_ui_mode(std::string requested,
                                    const std::string& preset_consent_ui,
                                    const std::string& fallback_when_empty = "auto");

/// Side-panel consent. `payload_json` is the card body. The emit must flush
/// before it returns; requestConsent then blocks until resolve or cancel.
using StreamConsentEmit = std::function<bool(const std::string& type, const std::string& payload_json)>;

/// Push @p emit until restore_stream_consent_emit(ticket). Ticket 0 is unused.
/// A later bind sits above this one; restoring an older ticket leaves the
/// newer emit in place, so a voice session and a typed turn do not clobber
/// each other.
std::uint64_t bind_stream_consent_emit(StreamConsentEmit emit);
void restore_stream_consent_emit(std::uint64_t ticket);
bool resolve_stream_consent(const std::string& reply_json);
void cancel_stream_consent();

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI

/// Install the consent surface selected by @p consent_ui_raw for the lifetime
/// of this object. Restores any previous registry slot on teardown.
class ConsentSurfaceScope {
public:
    using ReviewFn =
        std::function<ui::AiConsentReview(const ConsentRequest&)>;

    /// @p replace_existing  When false and a delegate is already registered
    ///                      (e.g. Chat WebView), leave it in place.
    ConsentSurfaceScope(const std::string& consent_ui_raw,
                        const std::string& consent_owner = {},
                        ReviewFn review_fn = {},
                        bool replace_existing = true);
    ~ConsentSurfaceScope();

    ConsentSurfaceScope(const ConsentSurfaceScope&)            = delete;
    ConsentSurfaceScope& operator=(const ConsentSurfaceScope&) = delete;

    const std::string& resolved() const { return resolved_; }

private:
    std::unique_ptr<ConsentDelegate> delegate_;
    ConsentDelegate*                 previous_ = nullptr;
    std::string                      resolved_;
};

#endif // PM_CLI_CONSENT_UI

} // namespace pm::security
