#include "security/consent_surface.hpp"

#include "settings/chat_settings_schema.hpp"
#include "process/cli_cancel.hpp"
#include "settings/settings_store.hpp"
#include "logging/pm_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI
#include "security/CliConsentDelegate.hpp"
#include "security/ConsentDelegateRegistry.hpp"
#include "win/settings_store.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#include <stdio.h>
#endif

namespace pm::security {
namespace {

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

std::string normalize_consent_ui_token(std::string raw)
{
    raw = lower_copy(std::move(raw));
    const auto b = raw.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return {};
    const auto e = raw.find_last_not_of(" \t\r\n");
    raw = raw.substr(b, e - b + 1);
    if (raw == "yolo")
        return "auto-allow";
    return raw;
}

std::string resolve_consent_ui_mode(std::string requested,
                                    const std::string& preset_consent_ui,
                                    const std::string& fallback_when_empty)
{
    std::string mode = normalize_consent_ui_token(std::move(requested));
    if (mode.empty() || mode == "auto" || mode == "preset") {
        const std::string from_preset =
            media::settings_schema::normalize_chat_preset_consent_ui(preset_consent_ui);
        if (!from_preset.empty())
            return from_preset;
        return mode.empty() ? fallback_when_empty : mode;
    }
    return mode;
}

namespace {

struct StreamConsentSlot {
    std::promise<nlohmann::json> promise;
    std::atomic<bool> done{false};

    void finish(nlohmann::json reply)
    {
        bool expected = false;
        if (done.compare_exchange_strong(expected, true))
            promise.set_value(std::move(reply));
    }
};

struct StreamEmitFrame {
    std::uint64_t ticket = 0;
    StreamConsentEmit fn;
};

struct StreamConsentState {
    std::mutex mu;
    std::uint64_t next_ticket = 0;
    std::vector<StreamEmitFrame> stack;
    StreamConsentEmit emit;
    std::unordered_map<std::string, std::shared_ptr<StreamConsentSlot>> pending;
};

StreamConsentState& stream_consent_state()
{
    static StreamConsentState state;
    return state;
}

void publish_top_emit(StreamConsentState& state)
{
    state.emit = state.stack.empty() ? StreamConsentEmit{} : state.stack.back().fn;
}

} // namespace

std::uint64_t bind_stream_consent_emit(StreamConsentEmit emit)
{
    std::lock_guard lock(stream_consent_state().mu);
    auto& state = stream_consent_state();
    const std::uint64_t ticket = ++state.next_ticket;
    state.stack.push_back(StreamEmitFrame{ticket, std::move(emit)});
    publish_top_emit(state);
    return ticket;
}

void restore_stream_consent_emit(std::uint64_t ticket)
{
    if (ticket == 0)
        return;
    std::lock_guard lock(stream_consent_state().mu);
    auto& state = stream_consent_state();
    for (auto it = state.stack.begin(); it != state.stack.end(); ++it) {
        if (it->ticket != ticket)
            continue;
        state.stack.erase(it);
        publish_top_emit(state);
        return;
    }
}

bool resolve_stream_consent(const std::string& reply_json)
{
    nlohmann::json reply = nlohmann::json::parse(reply_json, nullptr, false);
    if (!reply.is_object())
        return false;
    const std::string req_id = reply.value("reqId", std::string{});
    if (req_id.empty())
        return false;
    std::shared_ptr<StreamConsentSlot> slot;
    {
        std::lock_guard lock(stream_consent_state().mu);
        const auto it = stream_consent_state().pending.find(req_id);
        if (it == stream_consent_state().pending.end()) {
            logger::warn("[consent-stream] resolve missed req_id=" + req_id);
            return false;
        }
        slot = it->second;
    }
    logger::info("[consent-stream] resolved req_id=" + req_id
                 + " decision=" + reply.value("decision", std::string("?")));
    slot->finish(std::move(reply));
    return true;
}

void cancel_stream_consent()
{
    std::unordered_map<std::string, std::shared_ptr<StreamConsentSlot>> pending;
    {
        std::lock_guard lock(stream_consent_state().mu);
        pending.swap(stream_consent_state().pending);
    }
    for (auto& [req_id, slot] : pending) {
        if (!slot)
            continue;
        slot->finish(nlohmann::json{{"reqId", req_id}, {"decision", "deny"}, {"cancelled", true}});
    }
}

nlohmann::json wait_stream_consent(const std::string& req_id, const std::string& request_json)
{
    auto slot = std::make_shared<StreamConsentSlot>();
    auto future = slot->promise.get_future();
    StreamConsentEmit emit;
    {
        std::lock_guard lock(stream_consent_state().mu);
        stream_consent_state().pending[req_id] = slot;
        emit = stream_consent_state().emit;
    }
    logger::info("[consent-stream] waiting req_id=" + req_id
                 + " emitter=" + (emit ? std::string("1") : std::string("0")));
    if (!emit || !emit("consent", request_json)) {
        logger::warn("[consent-stream] emit failed req_id=" + req_id);
        slot->finish(nlohmann::json{{"reqId", req_id}, {"decision", "deny"}});
    }

    nlohmann::json reply{{"reqId", req_id}, {"decision", "deny"}};
    for (;;) {
        if (future.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready)
            break;
        if (media::cli::cancel_requested()) {
            slot->finish(nlohmann::json{{"reqId", req_id}, {"decision", "deny"}, {"cancelled", true}});
            break;
        }
    }
    if (future.valid())
        reply = future.get();
    logger::info("[consent-stream] finished req_id=" + req_id
                 + " decision=" + reply.value("decision", std::string("?")));
    {
        std::lock_guard lock(stream_consent_state().mu);
        const auto it = stream_consent_state().pending.find(req_id);
        if (it != stream_consent_state().pending.end() && it->second == slot)
            stream_consent_state().pending.erase(it);
    }
    if (emit)
        emit("consent.dismiss", nlohmann::json{{"reqId", req_id}}.dump());
    return reply;
}

#if defined(PM_CLI_CONSENT_UI) && PM_CLI_CONSENT_UI

namespace {

bool handle_can_prompt(HANDLE h)
{
    if (h == nullptr || h == INVALID_HANDLE_VALUE)
        return false;
    // Console input often reports FILE_TYPE_UNKNOWN. tanit-cli is a GUI-subsystem
    // exe, so that false negative made `auto` skip the stdio prompt and open
    // the Win32 consent dialog whenever a desktop was present.
    DWORD mode = 0;
    if (::GetConsoleMode(h, &mode))
        return true;
    const DWORD ft = ::GetFileType(h);
    return ft == FILE_TYPE_CHAR || ft == FILE_TYPE_PIPE || ft == FILE_TYPE_DISK;
}

bool consent_stdin_attached()
{
    if (handle_can_prompt(::GetStdHandle(STD_INPUT_HANDLE)))
        return true;
    // AttachConsole + freopen(CONIN$) updates the CRT stream. The Win32 standard
    // handle can stay the original null handle from process start.
    const int fd = _fileno(stdin);
    if (fd < 0)
        return false;
    const intptr_t os = _get_osfhandle(fd);
    if (os == -1)
        return false;
    return handle_can_prompt(reinterpret_cast<HANDLE>(os));
}

bool consent_desktop_interactive()
{
    HDESK d = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (d) {
        ::CloseDesktop(d);
        return true;
    }
    return false;
}

bool consent_theme_is_dark(media::settings::Theme t)
{
    switch (t) {
    case media::settings::Theme::Light:
        return false;
    case media::settings::Theme::Dark:
        return true;
    case media::settings::Theme::System:
    default:
        break;
    }
    HKEY key = nullptr;
    bool dark = false;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_READ, &key) == ERROR_SUCCESS) {
        DWORD value = 1, sz = sizeof(value), type = 0;
        if (::RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type,
                reinterpret_cast<BYTE*>(&value), &sz) == ERROR_SUCCESS &&
            type == REG_DWORD)
            dark = (value == 0);
        ::RegCloseKey(key);
    }
    return dark;
}

nlohmann::json consent_request_json(const std::string& req_id, const ConsentRequest& cr)
{
    nlohmann::json j;
    j["reqId"] = req_id;
    j["title"] = cr.title;
    j["risk"] = std::string(to_string(cr.risk));
    j["tool"] = cr.request.tool.toolId;
    j["action"] = std::string(to_string(cr.request.action));
    if (cr.request.target) {
        if (!cr.request.target->uri.empty())
            j["resource"] = cr.request.target->uri;
        else if (!cr.request.target->path.empty())
            j["resource"] = cr.request.target->path.string();
    }
    if (!cr.userGoal.empty())
        j["userGoal"] = cr.userGoal;
    if (!cr.whyNeeded.empty())
        j["whyNeeded"] = cr.whyNeeded;
    if (!cr.possibleRisk.empty())
        j["possibleRisk"] = cr.possibleRisk;
    j["resourcePreview"] = cr.resourcePreview;
    j["choices"] = cr.choices;
    j["sandboxBackends"] = cr.sandboxBackends;
    j["aiAutoAvailable"] = cr.aiAutoAvailable;
    if (!cr.suggestedScope.empty())
        j["suggestedScope"] = cr.suggestedScope;
    j["profile"] = std::string(to_string(cr.request.profile));
    return j;
}

ConsentResult consent_result_from_json(const ConsentRequest& cr, const nlohmann::json& j)
{
    ConsentResult result;
    const std::string decision = j.value("decision", std::string("deny"));
    if (decision == "allow") {
        result.kind = DecisionKind::Allow;
        result.aiDelegated = j.value("aiDelegated", false);
        const bool ai_review_applied = j.value("aiReviewApplied", false);
        const std::string lifetime = j.value("lifetime", std::string("session"));
        GrantLifetime lt = GrantLifetime::Session;
        if (lifetime == "once")
            lt = GrantLifetime::Once;
        else if (lifetime == "task")
            lt = GrantLifetime::Task;
        else if (lifetime == "permanent")
            lt = GrantLifetime::Permanent;
        std::vector<std::string> scopes;
        if (j.contains("scopes") && j["scopes"].is_array()) {
            for (const auto& s : j["scopes"]) {
                if (s.is_string() && !s.get<std::string>().empty())
                    scopes.push_back(s.get<std::string>());
            }
        } else {
            const std::string scope = j.value("scope", std::string{});
            if (!scope.empty())
                scopes.push_back(scope);
        }
        if (scopes.empty() && !cr.suggestedScope.empty())
            scopes.push_back(cr.suggestedScope);
        CapabilityGrant grant = build_consent_grant(cr.request, lt, std::move(scopes));
        grant.aiDelegated = result.aiDelegated;
        grant.approvedBy = result.aiDelegated
            ? "ai:stream"
            : (ai_review_applied ? "human+ai:stream" : "human");
        std::string sandbox_backend = j.value("sandboxBackend", std::string{});
        if (!sandbox_backend.empty()) {
            for (const auto& name : cr.sandboxBackends) {
                if (name == sandbox_backend) {
                    grant.sandboxBackend = sandbox_backend;
                    break;
                }
            }
        }
        if (!cr.request.workspaceId.empty() && grant.workspaceId.empty())
            grant.workspaceId = cr.request.workspaceId;
        result.grant = std::move(grant);
    } else if (decision == "settings") {
        result.kind = DecisionKind::Deny;
        result.openSettings = true;
    } else {
        result.kind = DecisionKind::Deny;
    }
    return result;
}

class StreamConsentDelegate final : public ConsentDelegate {
public:
    ConsentResult requestConsent(const ConsentRequest& req) override
    {
        const std::string req_id = "c" + std::to_string(++seq_);
        const nlohmann::json reply = wait_stream_consent(req_id, consent_request_json(req_id, req).dump());
        return consent_result_from_json(req, reply);
    }

private:
    std::atomic<std::uint64_t> seq_{0};
};

} // namespace

ConsentSurfaceScope::ConsentSurfaceScope(const std::string& consent_ui_raw,
                                         const std::string& consent_owner,
                                         ReviewFn review_fn,
                                         bool replace_existing)
{
    previous_ = active_consent_delegate();
    if (!replace_existing && previous_) {
        resolved_ = "host";
        logger::debug("[consent] surface = host (existing delegate kept)");
        return;
    }

    std::string mode = normalize_consent_ui_token(consent_ui_raw);
    if (mode.empty())
        mode = "auto";

    if (mode == "owner") {
        logger::warn(std::string("[consent] --consent-ui owner not implemented yet"
                                 " (owner=") + (consent_owner.empty() ? "(none)" : consent_owner)
                     + "); falling back to auto");
        mode = "auto";
    }
    if (mode == "auto") {
        // Native dialog on a desktop session. The stdio prompt is the
        // fallback when there is no desktop and stdin can answer.
        if (consent_desktop_interactive())
            mode = "win32";
        else if (consent_stdin_attached())
            mode = "cli";
        else
            mode = "auto-deny";
    }

    if (mode == "win32") {
        ui::ConsentUiOptions ui;
        {
            media::settings::AppearanceSettings app;
            std::string appErr;
            media::settings::load_appearance(app, appErr);
            ui.language = app.display_language.empty() ? "en" : app.display_language;
            ui.dark     = consent_theme_is_dark(app.theme);
        }
        ui.aiAutoAvailable = static_cast<bool>(review_fn);
        ui.makeGrant = [](const ToolRequest& r,
                          GrantLifetime lt,
                          std::vector<std::string> scopes) {
            return build_consent_grant(r, lt, std::move(scopes));
        };
        if (review_fn)
            ui.runAiReview = std::move(review_fn);
        try {
            ui.settingsPath = media::settings::get_config_dir().generic_string();
        } catch (...) {
        }
        delegate_ = std::make_unique<ui::Win32ConsentDelegate>(std::move(ui));
    } else if (mode == "auto-deny") {
        delegate_ = std::make_unique<DenyAllConsentDelegate>();
    } else if (mode == "auto-allow") {
        delegate_ = std::make_unique<AllowAllConsentDelegate>(GrantLifetime::Session);
    } else if (mode == "stream") {
        delegate_ = std::make_unique<StreamConsentDelegate>();
    } else if (mode == "cli") {
        // Leave the registry empty. The agent factory then installs its
        // json_mode delegate: one consent_request object on stderr, one stdin
        // line, deny on EOF. A delegate installed here would replace that
        // protocol (and the AI-review wrapper) with a human-readable prompt.
    }

    resolved_ = mode;
    if (delegate_)
        set_active_consent_delegate(delegate_.get());
    logger::debug(std::string("[consent] surface = ") + resolved_);
}

ConsentSurfaceScope::~ConsentSurfaceScope()
{
    if (delegate_)
        clear_active_consent_delegate(delegate_.get());
    if (previous_ && previous_ != delegate_.get())
        set_active_consent_delegate(previous_);
}

#endif // PM_CLI_CONSENT_UI

} // namespace pm::security
