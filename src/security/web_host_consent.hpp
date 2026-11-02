#pragma once
//
// Consent gate for web-originated process launch and shell-open.
//
// Origin pinning already keeps untrusted frames off the host bridge. User
// pages that *are* on an own-app origin (viewer pages, home widgets) can
// still author ButtonWidget cliCommand / externalCommand. Those, and shell
// open of files outside the install tree, go through the existing
// SecurityGateway + Win32ConsentDelegate (same machinery as tanit://).
//
// Catalog commandRun (id / appCommand / ribbonCommand) is a WM_COMMAND hop
// into our UI and is not gated here.
//

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "logger/logger.h"

#if defined(_WIN32) && !defined(PM_IMAGE_CLI_ONLY)
#  include "constants.hpp"
#  include "core/app_exe_directory.hpp"
#  include "core/settings_store.hpp"
#  include "security/security_default.hpp"
#  include "security/SecurityPersistence.hpp"
#  include "security/CliConsentDelegate.hpp"
#  include "security/ui/win/ConsentDlg.hpp"
#  include <chrono>
#  include <filesystem>
#  include <memory>
#  include <process.h>
#endif

namespace pm::security {

#if defined(_WIN32) && !defined(PM_IMAGE_CLI_ONLY) \
    && defined(FEATURE_SECURITY_GATEWAY) && FEATURE_SECURITY_GATEWAY \
    && defined(FEATURE_SECURITY_CONSENT_DELEGATE) && FEATURE_SECURITY_CONSENT_DELEGATE

namespace web_host_consent_detail {

// App-run id for "Allow for session". Chat agents have their own session
// ids; web pages do not. fromId is a WebView surface ("preview"/"home"),
// not a consent session — binding to it re-prompts across surfaces and
// each authorize() builds a fresh gateway.
inline const std::string& host_process_session_id()
{
    static const std::string id = [] {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
#if defined(_WIN32)
        const auto pid = static_cast<long>(_getpid());
#else
        const auto pid = static_cast<long>(::getpid());
#endif
        return std::string("host-") + std::to_string(pid) + "-" + std::to_string(ms);
    }();
    return id;
}

// Session/task grants for this process. Permanent grants still round-trip
// through persist::load/upsert; ephemeral ones live here so a new gateway
// per click still sees the previous Allow-for-session.
inline PermissionStore& host_session_grants()
{
    static PermissionStore store{std::shared_ptr<CryptoStore>{}};
    return store;
}

inline bool looks_like_web_url(std::string_view s)
{
    auto starts = [s](std::string_view p) {
        if (s.size() < p.size())
            return false;
        for (size_t i = 0; i < p.size(); ++i) {
            char c = s[i];
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
            if (c != p[i])
                return false;
        }
        return true;
    };
    return starts("http://") || starts("https://") || starts("ftp://");
}

inline bool path_is_under(const std::filesystem::path& child,
                          const std::filesystem::path& root)
{
    if (child.empty() || root.empty())
        return false;
    std::error_code ec;
    auto c = std::filesystem::weakly_canonical(child, ec);
    if (ec)
        c = std::filesystem::absolute(child, ec);
    auto r = std::filesystem::weakly_canonical(root, ec);
    if (ec)
        r = std::filesystem::absolute(root, ec);
    if (c.empty() || r.empty())
        return false;
    const auto rel = c.lexically_relative(r);
    if (rel.empty() || rel.has_root_path())
        return false;
    for (const auto& part : rel) {
        if (part == "..")
            return false;
    }
    return true;
}

// First-party chrome that already represents an in-app click (settings link,
// chat "open file", search result). User pages ride preview/home/browser/xblox.
inline bool shell_from_app_chrome(std::string_view fromId)
{
    return fromId == "settings" || fromId == "search" || fromId == "perf"
        || fromId == "console" || fromId == "chat";
}

inline bool shell_path_is_builtin(std::string_view pathOrUrl)
{
    if (pathOrUrl.empty() || looks_like_web_url(pathOrUrl))
        return false;
    const auto exe = media::app::exe_parent_directory();
    if (exe.empty())
        return false;
    try {
        return path_is_under(std::filesystem::u8path(std::string(pathOrUrl)), exe);
    } catch (...) {
        return false;
    }
}

inline bool bind_document_target(ToolRequest& req, ResourceTarget& tgt,
                                 std::string_view pagePath)
{
    if (pagePath.empty())
        return false;
    std::filesystem::path p;
    try {
        p = std::filesystem::u8path(std::string(pagePath));
    } catch (...) {
        return false;
    }
    PathSecurity ps;
    const auto canon = ps.canonicalize(p);
    tgt.path = canon.value;
    const auto parent = canon.value.parent_path();
    if (!parent.empty()) {
        req.workspaceRoot = parent;
        req.workspaceId = parent.generic_string();
    }
    return true;
}

inline void apply_ui_opts(ui::ConsentUiOptions& uiOpts)
{
    uiOpts.dark = true;
    try {
        media::settings::AppearanceSettings app;
        std::string appErr;
        media::settings::load_appearance(app, appErr);
        uiOpts.language = app.display_language.empty() ? "en" : app.display_language;
    } catch (...) {
    }
    try {
        uiOpts.settingsPath = media::settings::get_config_dir().generic_string();
    } catch (...) {
    }
    uiOpts.makeGrant = [](const ToolRequest& r, GrantLifetime lt,
                          std::vector<std::string> scopes) {
        return build_consent_grant(r, lt, std::move(scopes));
    };
}

inline bool authorize_user_execute(ToolRequest& req)
{
    namespace persist = pm::security::persist;

    req.actor = Actor::User;
    req.action = Action::Execute;
    req.profile = k_default_profile;
    req.origin = current_process_origin();
    req.sessionId = host_process_session_id();

    ui::ConsentUiOptions uiOpts;
    apply_ui_opts(uiOpts);
    ui::Win32ConsentDelegate win32(std::move(uiOpts));

    SecurityGateway gw(std::string(pm::brand::k_app_id_u8), &win32);
    {
        std::string err;
        persist::load_grants(gw.permissions(), err);
    }
    for (const auto& g : host_session_grants().list())
        gw.permissions().put(g);

    const PolicyDecision d = gw.authorizeWithConsent(req);
    if (d.kind != DecisionKind::Allow) {
        logger::warn(std::string("[web-consent] denied tool=") + req.tool.toolId
            + " session=" + req.sessionId
            + " reason=" + d.reason);
        return false;
    }
    if (d.grant) {
        if (d.grant->lifetime == GrantLifetime::Session
            || d.grant->lifetime == GrantLifetime::Task) {
            host_session_grants().put(*d.grant);
        } else if (d.grant->lifetime != GrantLifetime::Once) {
            std::string err;
            persist::upsert_grant(*d.grant, err);
        }
    }
    return true;
}

} // namespace web_host_consent_detail

#endif // Win32 + gateway + consent

/// Prompt for inline cliCommand / externalCommand. Catalog ids skip this.
/// @p pagePath is the current document (viewer .page / preview). Always binds
/// the grant to that file and its parent folder as workspaceId.
inline bool confirm_web_command_run(const std::string& fromId,
                                    const nlohmann::json& request,
                                    std::string_view pagePath = {})
{
#if defined(_WIN32) && !defined(PM_IMAGE_CLI_ONLY) \
    && defined(FEATURE_SECURITY_GATEWAY) && FEATURE_SECURITY_GATEWAY \
    && defined(FEATURE_SECURITY_CONSENT_DELEGATE) && FEATURE_SECURITY_CONSENT_DELEGATE
    ToolRequest req;
    req.tool.toolId = "web.commandRun";
    req.tool.provider = "web";
    req.userVisibleIntent = pagePath.empty()
        ? std::string("Run a command from a page")
        : ("Run a command from " + std::string(pagePath));
    try {
        nlohmann::json args = request;
        args["fromId"] = fromId;
        req.argumentsJson = args.dump();
    } catch (...) {
        try {
            req.argumentsJson = request.dump();
        } catch (...) {
        }
    }

    ResourceTarget tgt;
    if (request.contains("externalCommand") && request["externalCommand"].is_object()) {
        const auto& ext = request["externalCommand"];
        if (ext.value("mode", std::string{}) == "shell")
            tgt.uri = "cmd://" + ext.value("shellLine", std::string{});
        else
            tgt.uri = "cmd://" + ext.value("command", std::string{});
    } else {
        tgt.uri = "cmd://" + request.value("cliCommand", std::string{});
    }
    web_host_consent_detail::bind_document_target(req, tgt, pagePath);
    req.target = std::move(tgt);
    return web_host_consent_detail::authorize_user_execute(req);
#else
    (void)fromId;
    (void)request;
    (void)pagePath;
    return true;
#endif
}

/// Prompt for host shell-open of a non-builtin path from a user page.
/// Settings / chat / search chrome and files under the install dir skip.
inline bool confirm_web_shell_open(std::string_view fromId,
                                   std::string_view pathOrUrl,
                                   std::string_view verb = "open")
{
#if defined(_WIN32) && !defined(PM_IMAGE_CLI_ONLY) \
    && defined(FEATURE_SECURITY_GATEWAY) && FEATURE_SECURITY_GATEWAY \
    && defined(FEATURE_SECURITY_CONSENT_DELEGATE) && FEATURE_SECURITY_CONSENT_DELEGATE
    using web_host_consent_detail::shell_from_app_chrome;
    using web_host_consent_detail::shell_path_is_builtin;

    if (pathOrUrl.empty() || shell_from_app_chrome(fromId) || shell_path_is_builtin(pathOrUrl))
        return true;

    ToolRequest req;
    req.tool.toolId = "web.shellOpen";
    req.tool.provider = "web";
    req.userVisibleIntent = std::string(verb) + " " + std::string(pathOrUrl);
    try {
        req.argumentsJson = nlohmann::json{
            {"fromId", std::string(fromId)},
            {"path", std::string(pathOrUrl)},
            {"verb", std::string(verb)},
        }.dump();
    } catch (...) {
    }

    ResourceTarget tgt;
    if (web_host_consent_detail::looks_like_web_url(pathOrUrl))
        tgt.uri = std::string(pathOrUrl);
    else
        web_host_consent_detail::bind_document_target(req, tgt, pathOrUrl);
    req.target = std::move(tgt);
    return web_host_consent_detail::authorize_user_execute(req);
#else
    (void)fromId;
    (void)pathOrUrl;
    (void)verb;
    return true;
#endif
}

} // namespace pm::security
