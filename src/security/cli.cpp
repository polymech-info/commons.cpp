//
// pm-image-security — security gateway test CLI.
//
// A dedicated, EXCLUDE_FROM_ALL console target used to implement and exercise the
// pm::security gateway in isolation before it is wired into the shipping app
// (docs/security/design.md, docs/security/todos.md). It mirrors the JSON-probe
// style of `pm-image-cli test core` (src/cli/pm_image_register_test.cpp) so the
// orchestrator suite (tests/orchestrator/test-security.mjs) can drive it.
//
// Persistence is intentionally routed through the app's existing settings store
// (media::settings load_subtree/save_subtree under the `permissions` / `security`
// keys) rather than a bespoke file, so grants live alongside the rest of the
// profile and inherit its DPAPI encryption (see src/security/SecurityPersistence.*).
//
// Layers OFF for now (added later): FEATURE_SECURITY_AUDIT_LOG, FEATURE_SECURITY_WIN_ACL.
//

#include "security/cli_info.hpp"
#include "security/CliConsentDelegate.hpp"
#include "security/anti_hack.hpp"
#include "security/security_default.hpp"
#include "security/SecurityPersistence.hpp"
#include "security/ToolIdentity.hpp"
#include "security/UserVerification.hpp"
#include "security/ui/win/ConsentDlg.hpp"
#include "security/security_defaults.hpp"
#include "pm_branding_config.hpp"
#include "version.hpp"

#include "commons/commons_host.hpp"
#include "core/settings_store.hpp"
#include "llm/chat_session_store.hpp"
#include "llm/mcp_config.hpp"
#include "logger/logger.h"
#include "model/resource_schema.hpp"
#include "storage/asset_bundle.hpp"
#include "storage/bundle_pub_key.hpp"
#include "storage/secure_storage.hpp"

#include <sodium.h>

#ifndef FEATURE_COMMAND_TEST
#  define FEATURE_COMMAND_TEST 1
#endif
#if FEATURE_COMMAND_TEST
#include "lib/pm_license_service.hpp"
#endif

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
#include "policy/PolicyProvider.hpp"
#endif

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#if FEATURE_SECURITY_SANDBOX && defined(_WIN32)
#include "security/backends/win/SandboxAppContainer.hpp"
#include "security/sandbox_presets.hpp"
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
namespace sec = pm::security;

namespace {

// ── process-wide parsed globals ──────────────────────────────────────────────
bool        g_json = false;   ///< --json: compact machine output (default: pretty)
std::string g_profile = std::string(sec::to_string(sec::k_default_profile));
std::string g_config_dir;     ///< --config-dir: isolate the settings store (tests)
std::string g_app_name = "pm-image";
std::string g_origin = pm::brand::k_exe_basename_security_u8;  ///< --origin: calling binary (provenance)
std::string g_session;        ///< --session: session id (binds Session grants)
std::string g_task;           ///< --task: task id (binds Task grants)
std::string g_lang;           ///< --lang: consent UI language override (en/de/es); empty = read from settings store
bool        g_dark = false;   ///< --dark: dark consent UI theme
/// --storage: "settings-store" (encrypted settings.json) or "grants.json" (plain file).
/// "settings-store" is the default so existing integrations are unaffected.
std::string g_storage = "settings-store";
int         g_exit = 0;

// ── logging ───────────────────────────────────────────────────────────────────
// --log-level none|error|info|debug  --log-file <path>
// Sandbox commands emit structured log lines showing profile lifecycle, ACL
// grants, IPC messages (when wired), and timing.  Output goes to --log-file
// when specified, otherwise to stderr so it doesn't interfere with --json stdout.

enum class SbLog : int { None = 0, Error = 1, Info = 2, Debug = 3 };
SbLog       g_log_lvl  = SbLog::None;
std::string g_log_file;

void log_msg(SbLog level, const std::string& msg) {
    if (level > g_log_lvl) return;

    // Build timestamp HH:MM:SS.mmm
    const auto now   = std::chrono::system_clock::now();
    const auto ms    = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now.time_since_epoch()).count() % 1000;
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_val{};
#if defined(_WIN32)
    localtime_s(&tm_val, &t);
#else
    localtime_r(&t, &tm_val);
#endif
    char ts[12];
    std::strftime(ts, sizeof(ts), "%H:%M:%S", &tm_val);
    char ms_buf[5];
    std::snprintf(ms_buf, sizeof(ms_buf), ".%03d", static_cast<int>(ms));

    const char* lbl = level == SbLog::Error ? "ERROR" :
                      level == SbLog::Info  ? "INFO " : "DEBUG";
    const std::string line = std::string("[") + ts + ms_buf + "] [" + lbl + "] " + msg;

    // Static stream opened once (after globals are set by arg parse).
    static bool s_opened = false;
    static std::ofstream s_stream;
    if (!s_opened) {
        s_opened = true;
        if (!g_log_file.empty())
            s_stream.open(g_log_file, std::ios::app);
    }
    if (s_stream.is_open()) {
        s_stream << line << "\n";
        s_stream.flush();
    } else {
        std::cerr << line << "\n";
    }
}

// Convenience shorthands — only compiled when sandbox is active.
#define SBLOG_INFO(m)  log_msg(SbLog::Info,  (m))
#define SBLOG_DEBUG(m) log_msg(SbLog::Debug, (m))
#define SBLOG_ERROR(m) log_msg(SbLog::Error, (m))

void apply_config_dir() {
    if (g_config_dir.empty())
        return;
    const fs::path dir = fs::absolute(g_config_dir);
    media::settings::set_config_dir_override(dir);
#if FEATURE_SECURE_STORAGE
    media::settings::clear_settings_read_path_override();
#else
    // Also pin the read path to the same dir.  Without this the store falls
    // back to Priority-1 (settings.json in cwd), which may have been written
    // with a different encryption key — producing a spurious crypto error.
    media::settings::set_settings_read_path_override(dir / "settings.json");
#endif
}

// ── storage dispatch ─────────────────────────────────────────────────────────

/// Resolved path for the grants.json file (always inside the active config dir).
fs::path grants_file_path() {
    return media::settings::get_config_dir() / "grants.json";
}

/// Load grants from whichever backend --storage selects.
bool load_active_grants(sec::PermissionStore& store, std::string& err) {
    if (g_storage == "grants.json")
        return sec::persist::load_grants_file(store, grants_file_path(), err);
    return sec::persist::load_grants(store, err);
}

/// Persist grants to whichever backend --storage selects.
bool save_active_grants(const sec::PermissionStore& store, std::string& err) {
    if (g_storage == "grants.json")
        return sec::persist::save_grants_file(store, grants_file_path(), err);
    return sec::persist::save_grants(store, err);
}

sec::Profile active_profile() {
    return sec::persist::parse_profile(g_profile).value_or(sec::k_default_profile);
}

void emit(const json& payload) {
    std::cout << payload.dump(g_json ? -1 : 2) << "\n";
    g_exit = payload.value("ok", false) ? 0 : 1;
}

json err_json(const std::string& fn, const std::string& message) {
    return json{{"ok", false}, {"function", fn}, {"error", message}};
}

#if FEATURE_COMMAND_TEST
void cmd_license_endpoints(const std::string& server_url) {
    const auto plan = media::license_service::endpoint_plan(server_url);
    emit({
        {"ok", !plan.base_url.empty()},
        {"function", "license.endpoints"},
        {"endpoints", media::license_service::to_json(plan)},
        {"error", plan.base_url.empty() ? "service base URL is empty" : ""},
    });
}

void cmd_license_purchase_payload(const std::string& email,
                                  const std::string& app_user_id,
                                  const std::string& machine_hash,
                                  const std::string& machine_label,
                                  const std::string& app_version,
                                  const std::string& product_id,
                                  const std::string& product_slug,
                                  const std::string& product_title,
                                  std::int64_t amount_cents,
                                  const std::string& currency,
                                  int quantity,
                                  bool calculate_tax) {
    media::license_service::PurchaseIntentRequest req;
    req.buyer.email = email;
    req.buyer.app_user_id = app_user_id;
    req.machine.machine_hash = machine_hash;
    req.machine.machine_label = machine_label;
    req.machine.app_version = app_version;
    req.product.id = product_id;
    req.product.slug = product_slug;
    req.product.title = product_title;
    req.product.amount_cents = amount_cents;
    req.product.currency = currency;
    req.product.quantity = quantity;
    req.calculate_tax = calculate_tax;

    const bool ok = !req.machine.machine_hash.empty()
                    && req.product.amount_cents > 0
                    && !req.product.currency.empty();
    emit({
        {"ok", ok},
        {"function", "license.purchase-payload"},
        {"endpoint", media::license_service::k_stripe_payment_intent_path},
        {"auth", "bearer"},
        {"payload", media::license_service::to_json(req)},
        {"error", ok ? "" : "machine hash, positive amount, and currency are required"},
    });
}

void cmd_license_issue_payload(const std::string& email,
                               const std::string& app_user_id,
                               const std::string& machine_hash,
                               const std::string& machine_label,
                               const std::string& app_version,
                               const std::string& transaction_id,
                               const std::string& stripe_payment_intent_id,
                               const std::vector<std::string>& features,
                               const std::string& format) {
    media::license_service::LicenseIssueRequest req;
    req.buyer.email = email;
    req.buyer.app_user_id = app_user_id;
    req.machine.machine_hash = machine_hash;
    req.machine.machine_label = machine_label;
    req.machine.app_version = app_version;
    req.transaction_id = transaction_id;
    req.stripe_payment_intent_id = stripe_payment_intent_id;
    req.features = features;
    req.entitlements = features;
    req.format = format;

    const bool ok = !req.machine.machine_hash.empty()
                    && (!req.transaction_id.empty() || !req.stripe_payment_intent_id.empty())
                    && !req.features.empty();
    emit({
        {"ok", ok},
        {"function", "license.issue-payload"},
        {"endpoint", media::license_service::k_license_issue_path},
        {"auth", "bearer"},
        {"payload", media::license_service::to_json(req)},
        {"error", ok ? "" : "machine hash, transaction/payment id, and at least one entitlement are required"},
    });
}

void cmd_license_revalidate_payload(const std::string& license_id,
                                    const std::string& user_email,
                                    const std::string& machine_hash,
                                    const std::string& app_version,
                                    std::int64_t generation,
                                    std::int64_t active_seconds) {
    media::license_service::LicenseRevalidationRequest req;
    req.license_id = license_id;
    req.user_email = user_email;
    req.machine_hash = machine_hash;
    req.app_version = app_version;
    req.state_generation = generation;
    req.accumulated_active_seconds = active_seconds;

    const bool ok = !req.license_id.empty() && !req.machine_hash.empty();
    emit({
        {"ok", ok},
        {"function", "license.revalidate-payload"},
        {"endpoint", media::license_service::k_license_revalidate_path},
        {"auth", "bearer"},
        {"payload", media::license_service::to_json(req)},
        {"error", ok ? "" : "license id and machine hash are required"},
    });
}
#endif // FEATURE_COMMAND_TEST

pm::storage::StoragePaths active_storage_paths() {
    apply_config_dir();
    return pm::storage::resolve_storage_paths(media::settings::get_config_dir());
}

bool read_file_for_storage(const fs::path& path, std::vector<std::uint8_t>& out, std::string& err) {
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open file: " + path.string();
        return false;
    }
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size < 0) {
        err = "failed to stat file: " + path.string();
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(size));
    if (!out.empty())
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (!in.good() && !in.eof()) {
        err = "failed to read file: " + path.string();
        return false;
    }
    return true;
}

bool write_file_for_storage(const fs::path& path, const std::vector<std::uint8_t>& data, std::string& err) {
    std::error_code ec;
    if (!path.parent_path().empty())
        fs::create_directories(path.parent_path(), ec);
    if (ec) {
        err = "failed to create directory: " + path.parent_path().string();
        return false;
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        err = "failed to open output file: " + path.string();
        return false;
    }
    if (!data.empty())
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out.good()) {
        err = "failed to write output file: " + path.string();
        return false;
    }
    return true;
}

json storage_meta_json(const pm::model::ResourceMeta& meta) {
    return pm::model::resource_meta_to_json(meta);
}

sec::ResourceTarget make_target(const std::string& path, const std::string& uri = {}) {
    sec::ResourceTarget t;
    if (!path.empty()) {
        t.path = fs::path(path);
        t.extension = t.path.extension().string();
        t.uri = uri.empty() ? ("file://" + t.path.generic_string()) : uri;
    } else if (!uri.empty()) {
        t.uri = uri;
        const auto slash = uri.find_last_of('/');
        const std::string tail = slash == std::string::npos ? uri : uri.substr(slash + 1);
        if (const auto dot = tail.find_last_of('.'); dot != std::string::npos)
            t.extension = tail.substr(dot);
    }
    return t;
}

nlohmann::json origin_json(const sec::Origin& o) {
    return nlohmann::json{
        {"id", o.id},
        {"binaryName", o.binaryName},
        {"displayName", o.displayName},
        {"kind", std::string(sec::to_string(o.kind))},
        {"firstParty", o.firstParty},
    };
}

std::string new_grant_id() {
    return sec::consent_new_grant_id("grant-cli");
}

// ── profile ──────────────────────────────────────────────────────────────────

void cmd_profile() {
    apply_config_dir();
    sec::Profile persisted = sec::k_default_profile;
    std::string err;
    sec::persist::load_active_profile(persisted, sec::k_default_profile, err);
    emit({
        {"ok", true},
        {"function", "profile"},
        {"compiledDefault", std::string(sec::to_string(sec::k_default_profile))},
        {"requested", g_profile},
        {"persisted", std::string(sec::to_string(persisted))},
        {"hasCryptoBackend", sec::k_has_crypto_backend},
        {"policyVersion", sec::k_policy_version},
    });
}

void cmd_set_profile() {
    apply_config_dir();
    std::string err;
    const bool ok = sec::persist::save_active_profile(active_profile(), err);
    emit({
        {"ok", ok},
        {"function", "set-profile"},
        {"profile", std::string(sec::to_string(active_profile()))},
        {"error", err},
    });
}

// ── path ─────────────────────────────────────────────────────────────────────

void cmd_path_canonicalize(const std::string& path) {
    sec::PathSecurity ps;
    const sec::CanonicalPath c = ps.canonicalize(fs::path(path));
    emit({
        {"ok", true},
        {"function", "path.canonicalize"},
        {"input", path},
        {"canonical", c.value.generic_string()},
        {"normalized", sec::PathSecurity::normalizeForMatch(c.value)},
        {"resolved", c.resolved},
    });
}

void cmd_path_inside(const std::string& path, const std::string& root) {
    sec::PathSecurity ps;
    const sec::CanonicalPath c = ps.canonicalize(fs::path(path));
    const sec::CanonicalPath r = ps.canonicalize(fs::path(root));
    emit({
        {"ok", true},
        {"function", "path.inside"},
        {"path", c.value.generic_string()},
        {"root", r.value.generic_string()},
        {"inside", ps.isInside(c, r)},
    });
}

void cmd_path_glob(const std::string& path, const std::string& pattern) {
    const std::string norm = sec::PathSecurity::normalizeForMatch(fs::path(path));
    emit({
        {"ok", true},
        {"function", "path.glob"},
        {"path", path},
        {"normalized", norm},
        {"pattern", pattern},
        {"match", sec::PathSecurity::globMatch(norm, pattern)},
    });
}

// ── identity ─────────────────────────────────────────────────────────────────

void cmd_identity_hash_file(const std::string& path) {
    sec::ToolIdentityResolver resolver;
    const std::string hash = resolver.hashFile(fs::path(path));
    emit({
        {"ok", !hash.empty()},
        {"function", "identity.hash-file"},
        {"path", path},
        {"sha256", hash},
    });
}

// ── classify ─────────────────────────────────────────────────────────────────

void cmd_classify(const std::string& path, sec::Action action, const std::string& workspace,
                  const std::string& uri) {
    sec::ResourceClassifier rc;
    sec::PathSecurity ps;
    std::optional<sec::CanonicalPath> root;
    if (!workspace.empty())
        root = ps.canonicalize(fs::path(workspace));

    const sec::ResourceTarget t = make_target(path, uri);
    const sec::ClassificationResult cr = rc.classify(t, action, root);
    emit({
        {"ok", true},
        {"function", "classify"},
        {"path", t.path.generic_string()},
        {"action", std::string(sec::to_string(action))},
        {"risk", std::string(sec::to_string(cr.risk))},
        {"isSecret", cr.isSecret},
        {"isOsProtected", cr.isOsProtected},
        {"outsideWorkspace", cr.outsideWorkspace},
        {"atWorkspaceRoot",  cr.atWorkspaceRoot},
        {"signals", cr.signals},
    });
}

// ── authorize ────────────────────────────────────────────────────────────────

sec::ToolRequest build_request(const std::string& tool,
                               const std::string& provider,
                               sec::Actor actor,
                               sec::Action action,
                               const std::string& path,
                               const std::string& workspace,
                               const std::string& intent,
                               bool signed_manifest,
                               const std::string& executable_hash,
                               const std::string& manifest_hash,
                               const std::string& server = {},
                               const std::string& uri = {}) {
    sec::ToolRequest req;
    req.actor = actor;
    req.profile = active_profile();
    req.origin = sec::resolve_origin(g_origin);
    req.sessionId = g_session;
    req.taskId = g_task;
    req.tool.toolId = tool;
    req.tool.provider = provider;
    req.tool.serverId = server;
    req.tool.signedManifest = signed_manifest;
    req.tool.executableHash = executable_hash;
    req.tool.manifestHash = manifest_hash;
    req.action = action;
    if (!path.empty() || !uri.empty())
        req.target = make_target(path, uri);
    req.userVisibleIntent = intent;
    if (!workspace.empty()) {
        req.workspaceRoot = fs::path(workspace);
        req.workspaceId = fs::path(workspace).filename().generic_string();
    }
    return req;
}

std::string trim(const std::string& s) {
    return sec::consent_trim(s);
}

void cmd_authorize(const sec::ToolRequest& req, bool use_grants, bool interactive, bool gui) {
    // Pick the consent surface: GUI = Win32 dialog, otherwise stdio CLI. Both
    // share sec::build_consent_grant (CliConsentDelegate.hpp) so grants persist
    // identically regardless of which surface approved the request.
    sec::CliConsentDelegate cliDelegate(g_json);
    sec::ui::ConsentUiOptions uiOpts;
    if (!g_lang.empty()) {
        uiOpts.language = g_lang;
    } else {
        media::settings::AppearanceSettings appearance{};
        std::string err;
        if (media::settings::load_appearance(appearance, err) && !appearance.display_language.empty())
            uiOpts.language = appearance.display_language;
        // else: leave at the struct default ("en")
    }
    uiOpts.dark = g_dark;
    uiOpts.aiAutoAvailable = true;
    uiOpts.makeGrant = [](const sec::ToolRequest& r, sec::GrantLifetime lt,
                          std::vector<std::string> scopes) {
        return sec::build_consent_grant(r, lt, std::move(scopes));
    };
    // "Open settings…" opens the active grants storage location in Explorer /
    // the default editor so the user can inspect or edit grants directly.
    //   • settings-store → open the config dir (settings.json lives there)
    //   • grants.json    → open the grants.json file in the default text editor
    try {
        if (g_storage == "grants.json") {
            uiOpts.settingsPath = grants_file_path().generic_string();
        } else {
            uiOpts.settingsPath = media::settings::get_config_dir().generic_string();
        }
    } catch (...) {}
    // NOTE: the "Review with AI" surface (ConsentUiOptions::runAiReview) is
    // intentionally NOT wired here. A real SecurityAgent review pulls the whole
    // agent → tool-catalog → media (xblox/video/audio/net) subsystem into the
    // link, which this deliberately lean gateway test CLI does not link. The
    // review is wired in the product surfaces instead (pm-image WebView card +
    // pm-image-cli `llm agent --consent-ui win32`).
    sec::ui::Win32ConsentDelegate guiDelegate(uiOpts);

    sec::ConsentDelegate* delegate = nullptr;
    if (interactive) delegate = gui ? static_cast<sec::ConsentDelegate*>(&guiDelegate)
                                    : static_cast<sec::ConsentDelegate*>(&cliDelegate);

    sec::SecurityGateway gw(g_app_name, delegate);
#if FEATURE_SECURITY_SANDBOX && defined(_WIN32)
    // Register the AppContainer backend so a grant carrying
    // sandboxBackend="appcontainer" resolves and surfaces in the decision.
    static sec::SandboxAppContainer cli_sandbox_backend;
    gw.registerSandboxBackend(&cli_sandbox_backend);
#endif
    if (use_grants) {
        std::string err;
        load_active_grants(gw.permissions(), err);
    }
    const sec::PolicyDecision d = interactive ? gw.authorizeWithConsent(req) : gw.authorize(req);
    if (use_grants || (interactive && d.grant)) {
        std::string err;
        save_active_grants(gw.permissions(), err);
    }

    json out{
        {"ok", d.kind == sec::DecisionKind::Allow},
        {"function", "authorize"},
        {"profile", std::string(sec::to_string(req.profile))},
        {"actor", std::string(sec::to_string(req.actor))},
        {"action", std::string(sec::to_string(req.action))},
        {"toolId", req.tool.toolId},
        {"decision", std::string(sec::to_string(d.kind))},
        {"risk", std::string(sec::to_string(d.risk))},
        {"reason", d.reason},
        {"hasGrant", d.grant.has_value()},
        {"grantId", d.grant ? d.grant->id : std::string{}},
        {"sandboxBackend", d.sandboxBackend},
        {"usedGrants", use_grants},
        {"interactive", interactive},
        {"gui", gui},
        {"origin", origin_json(req.origin)},
        {"sessionId", req.sessionId},
        {"taskId", req.taskId},
    };
    if (d.consent) {
        out["consent"] = {
            {"title", d.consent->title},
            {"risk", std::string(sec::to_string(d.consent->risk))},
            {"whyNeeded", d.consent->whyNeeded},
            {"possibleRisk", d.consent->possibleRisk},
            {"sandboxBackends", d.consent->sandboxBackends},
            {"aiAutoAvailable", d.consent->aiAutoAvailable},
        };
    }
    emit(out);
}

// ── grants ───────────────────────────────────────────────────────────────────

void cmd_grant_add(sec::CapabilityGrant g) {
    apply_config_dir();
    if (g.id.empty())
        g.id = new_grant_id();
    g.profile = active_profile();
    g.policyVersion = sec::k_policy_version;

    sec::PermissionStore store;
    std::string err;
    load_active_grants(store, err);
    const bool put_ok = store.put(g);
    bool save_ok = false;
    if (put_ok)
        save_ok = save_active_grants(store, err);

    emit({
        {"ok", put_ok && save_ok},
        {"function", "grant.add"},
        {"id", g.id},
        {"persisted", put_ok},
        {"saved", save_ok},
        {"reason", put_ok ? "" : "action is never persistable or lifetime is Once"},
        {"error", err},
        {"count", static_cast<std::uint64_t>(store.list().size())},
    });
}

void cmd_grant_list() {
    apply_config_dir();
    sec::PermissionStore store;
    std::string err;
    const bool ok = load_active_grants(store, err);
    json grants = json::array();
    for (const auto& g : store.list())
        grants.push_back(sec::persist::to_json(g));
    emit({
        {"ok", ok},
        {"function", "grant.list"},
        {"storage", g_storage},
        {"grantsFile", g_storage == "grants.json" ? grants_file_path().generic_string() : std::string{}},
        {"count", static_cast<std::uint64_t>(grants.size())},
        {"grants", grants},
        {"error", err},
    });
}

void cmd_grant_find(const sec::ToolRequest& req) {
    apply_config_dir();
    sec::PermissionStore store;
    std::string err;
    load_active_grants(store, err);
    const std::optional<sec::CapabilityGrant> g = store.find(req);
    json out{
        {"ok", g.has_value()},
        {"function", "grant.find"},
        {"toolId", req.tool.toolId},
        {"action", std::string(sec::to_string(req.action))},
        {"found", g.has_value()},
    };
    if (g)
        out["grant"] = sec::persist::to_json(*g);
    emit(out);
}

void cmd_grant_revoke(const std::string& id) {
    apply_config_dir();
    sec::PermissionStore store;
    std::string err;
    load_active_grants(store, err);
    const bool removed = store.revoke(id);
    bool save_ok = true;
    if (removed)
        save_ok = save_active_grants(store, err);
    emit({
        {"ok", removed && save_ok},
        {"function", "grant.revoke"},
        {"id", id},
        {"removed", removed},
        {"saved", save_ok},
        {"error", err},
    });
}

// ── grant import ─────────────────────────────────────────────────────────────
//
// Merges grants from a plain JSON file (same format as --storage grants.json)
// into the active store (settings-store or grants.json backend). Each grant is
// validated against the same rules as `grant add`:
//   - must have at least one resource scope (no ambient authority)
//   - action must not be never_persistable
//   - permanent lifetime only allowed for Read
//   - lifetime must not be Once
//
// Use cases:
//   1. App/plugin installer ships a pre-validated pm-grants.json and calls:
//        pm-image-security.exe grant import --file pm-grants.json
//   2. Workspace-level grants committed to git (pm-grants.json in repo root).
//   3. Enterprise/MDM policy distribution: import from a signed grants manifest.
//
// --replace replaces the entire store; default is --merge (additive, keeps
// existing grants not present in the file).

void cmd_grant_import(const fs::path& file, bool replace) {
    apply_config_dir();

    // Parse the source file directly without PermissionStore validation so that
    // shipped templates missing an "id" (or with other non-standard fields) are
    // still read. Validation happens below via dest.put().
    std::string err;
    std::ifstream f(file, std::ios::binary);
    if (!f) {
        emit({
            {"ok", false}, {"function", "grant.import"},
            {"file", file.generic_string()},
            {"error", "cannot open file: " + file.generic_string()},
        });
        return;
    }
    const std::string raw(std::istreambuf_iterator<char>(f), {});
    json arr;
    try { arr = json::parse(raw); } catch (const json::exception& e) {
        emit({
            {"ok", false}, {"function", "grant.import"},
            {"file", file.generic_string()},
            {"error", std::string("JSON parse error: ") + e.what()},
        });
        return;
    }
    const auto candidates = sec::persist::parse_grants_array(arr);

    // Load (or start fresh for --replace) the active destination store.
    sec::PermissionStore dest;
    if (!replace) load_active_grants(dest, err);

    int imported = 0, rejected = 0;
    json rejected_reasons = json::array();

    for (auto g : candidates) {
        // Auto-assign id when missing (e.g. shipped templates omit the id).
        if (g.id.empty()) g.id = new_grant_id();
        // Assign current profile and policy version so imported grants align
        // with the runtime policy.
        if (g.profile == sec::k_default_profile) g.profile = active_profile();
        g.policyVersion = sec::k_policy_version;

        if (!dest.put(g)) {
            ++rejected;
            rejected_reasons.push_back({
                {"id", g.id},
                {"tool", g.tool.toolId},
                {"action", std::string(sec::to_string(g.action))},
                {"lifetime", std::string(sec::to_string(g.lifetime))},
                {"scopes", g.resourceScopes.empty() ? 0 : (int)g.resourceScopes.size()},
                {"reason", "refused by PermissionStore (ambient/perm/never_persistable)"},
            });
        } else {
            ++imported;
        }
    }

    bool saved = false;
    if (imported > 0 || replace)
        saved = save_active_grants(dest, err);

    emit({
        {"ok", imported > 0 && (err.empty())},
        {"function", "grant.import"},
        {"file", file.generic_string()},
        {"mode", replace ? "replace" : "merge"},
        {"candidates", static_cast<int>(candidates.size())},
        {"imported", imported},
        {"rejected", rejected},
        {"rejectedGrants", rejected_reasons},
        {"saved", saved},
        {"error", err},
    });
}

// ── crypto ───────────────────────────────────────────────────────────────────

void cmd_crypto_roundtrip(const std::string& text) {
    auto cs = sec::make_crypto_store();
    const std::string aad = "pm-image-security/test";
    std::vector<std::uint8_t> pt(text.begin(), text.end());
    const std::vector<std::uint8_t> ct = cs->encryptBlob(pt, aad);
    const std::vector<std::uint8_t> rt = cs->decryptBlob(ct, aad);
    const bool roundtrip = (rt == pt);
    emit({
        {"ok", roundtrip},
        {"function", "crypto.roundtrip"},
        {"isSecure", cs->isSecure()},
        {"inputBytes", static_cast<std::uint64_t>(pt.size())},
        {"cipherBytes", static_cast<std::uint64_t>(ct.size())},
        {"roundtrip", roundtrip},
    });
}

// ── secure storage ────────────────────────────────────────────────────────────

void cmd_storage_put(const std::string& uri,
                     const std::string& file,
                     const std::string& type,
                     const std::string& trust,
                     const std::string& version,
                     const std::string& provider,
                     const std::string& signer,
                     const std::string& bundle) {
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("storage.put", err));
        return;
    }

    pm::storage::PutResourceRequest req;
    req.uri = uri;
    req.type = pm::model::resource_type_from_string(type);
    req.trust = pm::model::trust_level_from_string(trust);
    req.version = version.empty() ? "1" : version;
    req.provider = provider.empty() ? "user" : provider;
    req.signer_id = signer;
    req.bundle_id = bundle.empty() ? "local" : bundle;
    req.data = std::move(data);

    const auto r = pm::storage::put_resource(active_storage_paths(), req);
    emit({
        {"ok", r.ok},
        {"function", "storage.put"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"error", r.error},
    });
}

void cmd_storage_get(const std::string& uri) {
    const auto r = pm::storage::load_resource(active_storage_paths(), uri);
    std::string text;
    if (r.ok)
        text.assign(reinterpret_cast<const char*>(r.resource.data.data()), r.resource.data.size());
    emit({
        {"ok", r.ok},
        {"function", "storage.get"},
        {"uri", uri},
        {"meta", storage_meta_json(r.resource.meta)},
        {"bytes", r.ok ? static_cast<std::uint64_t>(r.resource.data.size()) : 0},
        {"dataUtf8", r.ok ? json(text) : json(nullptr)},
        {"error", r.error},
    });
}

void cmd_storage_list() {
    const auto r = pm::storage::list_resources(active_storage_paths());
    json items = json::array();
    for (const auto& meta : r.items)
        items.push_back(storage_meta_json(meta));
    emit({
        {"ok", r.ok},
        {"function", "storage.list"},
        {"count", static_cast<std::uint64_t>(items.size())},
        {"resources", std::move(items)},
        {"error", r.error},
    });
}

void cmd_storage_verify(const std::string& uri) {
    const auto r = pm::storage::verify_resource(active_storage_paths(), uri);
    emit({
        {"ok", r.ok},
        {"function", "storage.verify"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"actualDigest", r.actual_digest},
        {"signedManifest", r.signed_manifest},
        {"signatureValid", r.signature_valid},
        {"signerPublicKey", r.signer_public_key.empty() ? json(nullptr) : json(r.signer_public_key)},
        {"error", r.error},
    });
}

void cmd_storage_sign(const std::string& uri) {
    const auto r = pm::storage::sign_resource_manifest(active_storage_paths(), uri);
    emit({
        {"ok", r.ok},
        {"function", "storage.sign"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"publicKey", r.public_key.empty() ? json(nullptr) : json(r.public_key)},
        {"signature", r.signature.empty() ? json(nullptr) : json(r.signature)},
        {"error", r.error},
    });
}

void cmd_storage_export(const std::string& uri, const std::string& file) {
    const auto r = pm::storage::export_resource_package(active_storage_paths(), uri, fs::path(file));
    emit({
        {"ok", r.ok},
        {"function", "storage.export"},
        {"uri", uri},
        {"file", file},
        {"meta", storage_meta_json(r.meta)},
        {"error", r.error},
    });
}

void cmd_storage_import(const std::string& file) {
    const auto r = pm::storage::import_resource_package(active_storage_paths(), fs::path(file));
    emit({
        {"ok", r.ok},
        {"function", "storage.import"},
        {"file", file},
        {"meta", storage_meta_json(r.meta)},
        {"error", r.error},
    });
}

#if FEATURE_COMMAND_TEST
json session_store_options_json() {
    const auto opts = media::llm::chat_sessions::active_options();
    const auto backend = opts.backend == media::llm::chat_sessions::StoreBackend::SecureStorage
        ? "secure-storage"
        : "legacy-files";
    std::string protection = "encrypted";
    if (opts.protection == media::llm::chat_sessions::ProtectionMode::Plain)
        protection = "plain";
    else if (opts.protection == media::llm::chat_sessions::ProtectionMode::Signed)
        protection = "signed";
    else if (opts.protection == media::llm::chat_sessions::ProtectionMode::EncryptedWithUserPresence)
        protection = "encrypted+up";
    return {
        {"backend", backend},
        {"protection", protection},
        {"root", media::llm::chat_sessions::store_dir().generic_string()},
        {"maxSessions", opts.max_sessions},
    };
}

bool read_json_document_file(const std::string& file, json& out, std::string& err) {
    out = nullptr;
    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open file: " + file;
        return false;
    }
    out = json::parse(in, nullptr, false);
    if (!out.is_object()) {
        err = "expected object JSON file: " + file;
        return false;
    }
    return true;
}

void cmd_session_store_put(const std::string& id, const std::string& file) {
    apply_config_dir();
    std::string err;
    json session;
    if (!read_json_document_file(file, session, err)) {
        emit(err_json("session-store.put", err));
        return;
    }
    if (!id.empty())
        session["id"] = id;
    const bool ok = media::llm::chat_sessions::save(session, err);
    emit({
        {"ok", ok},
        {"function", "session-store.put"},
        {"options", session_store_options_json()},
        {"id", session.value("id", std::string{})},
        {"error", err},
    });
}

void cmd_session_store_load(const std::string& id) {
    apply_config_dir();
    std::string err;
    json session;
    const bool ok = media::llm::chat_sessions::load(id, session, err);
    emit({
        {"ok", ok},
        {"function", "session-store.load"},
        {"options", session_store_options_json()},
        {"id", id},
        {"found", session.is_object()},
        {"session", session.is_object() ? session : json(nullptr)},
        {"error", err},
    });
}

void cmd_session_store_list() {
    apply_config_dir();
    std::string err;
    auto items = media::llm::chat_sessions::list_meta(err);
    json arr = json::array();
    for (auto& item : items)
        arr.push_back(std::move(item));
    emit({
        {"ok", err.empty()},
        {"function", "session-store.list"},
        {"options", session_store_options_json()},
        {"count", static_cast<std::uint64_t>(arr.size())},
        {"sessions", std::move(arr)},
        {"error", err},
    });
}

void cmd_session_store_delete(const std::string& id) {
    apply_config_dir();
    std::string err;
    const auto r = media::llm::chat_sessions::remove(id, err);
    emit({
        {"ok", err.empty()},
        {"function", "session-store.delete"},
        {"options", session_store_options_json()},
        {"id", id},
        {"removed", r.removed},
        {"agentSessionRemoved", r.agent_session_removed},
        {"agentLogsRemoved", r.agent_logs_removed},
        {"error", err},
    });
}

void cmd_session_store_memory_put(const std::string& id, const std::string& file) {
    apply_config_dir();
    std::string err;
    json doc;
    if (!read_json_document_file(file, doc, err)) {
        emit(err_json("session-store.memory-put", err));
        return;
    }
    const bool ok = media::llm::chat_sessions::save_session_memory_document(id, doc, err);
    emit({
        {"ok", ok},
        {"function", "session-store.memory-put"},
        {"options", session_store_options_json()},
        {"id", id},
        {"error", err},
    });
}

void cmd_session_store_log_put(const std::string& id, const std::string& log_id, const std::string& file) {
    apply_config_dir();
    std::string err;
    json doc;
    if (!read_json_document_file(file, doc, err)) {
        emit(err_json("session-store.log-put", err));
        return;
    }
    const bool ok = media::llm::chat_sessions::save_session_log_document(id, log_id, doc, err);
    emit({
        {"ok", ok},
        {"function", "session-store.log-put"},
        {"options", session_store_options_json()},
        {"id", id},
        {"logId", log_id},
        {"error", err},
    });
}

void cmd_session_store_query() {
    apply_config_dir();
    std::string err;
    json q = media::llm::chat_sessions::query_store(err);
    q["ok"] = err.empty();
    q["function"] = "session-store.query";
    q["options"] = session_store_options_json();
    q["error"] = err;
    emit(q);
}

void cmd_session_store_prune(int keep_latest) {
    apply_config_dir();
    std::string err;
    media::llm::chat_sessions::PruneOptions opts;
    opts.keep_latest = keep_latest;
    const auto r = media::llm::chat_sessions::prune(opts, err);
    emit({
        {"ok", err.empty()},
        {"function", "session-store.prune"},
        {"options", session_store_options_json()},
        {"keepLatest", keep_latest},
        {"sessionsRemoved", r.sessions_removed},
        {"documentsRemoved", r.documents_removed},
        {"error", err},
    });
}
#endif // FEATURE_COMMAND_TEST

// ── web app bundle (all-in-one *.pmbundle, store-only zip; PhysFS-mountable) ──

bool bundle_bytes_from_source(const std::string& uri,
                              const std::string& file,
                              std::vector<std::uint8_t>& out,
                              json& verify_out,
                              std::string& err) {
    verify_out = nullptr;
    if (!uri.empty()) {
        // Serve from verified secure storage: prove digest + signature first.
        const auto v = pm::storage::verify_resource(active_storage_paths(), uri);
        verify_out = {
            {"signedManifest", v.signed_manifest},
            {"signatureValid", v.signature_valid},
            {"actualDigest", v.actual_digest},
        };
        if (!v.ok) {
            err = v.error.empty() ? "bundle verification failed" : v.error;
            return false;
        }
        const auto loaded = pm::storage::load_resource(active_storage_paths(), uri);
        if (!loaded.ok) {
            err = loaded.error;
            return false;
        }
        out = std::move(loaded.resource.data);
        return true;
    }
    if (file.empty()) {
        err = "either --uri or --file is required";
        return false;
    }
    return read_file_for_storage(fs::path(file), out, err);
}

void cmd_storage_bundle_pack(const std::string& dir, const std::string& file) {
    std::vector<std::uint8_t> zip;
    std::string err;
    if (!pm::storage::bundle::pack_directory(fs::path(dir), zip, err)) {
        emit(err_json("storage.bundle.pack", err));
        return;
    }
    std::error_code ec;
    fs::create_directories(fs::path(file).parent_path(), ec);
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        emit(err_json("storage.bundle.pack", "failed to open output: " + file));
        return;
    }
    out.write(reinterpret_cast<const char*>(zip.data()), static_cast<std::streamsize>(zip.size()));
    pm::storage::bundle::ParsedBundle parsed;
    (void)pm::storage::bundle::parse_bundle(zip, parsed, err);
    json names = json::array();
    for (const auto& e : parsed.entries) names.push_back(e.path);
    emit({
        {"ok", true},
        {"function", "storage.bundle.pack"},
        {"file", file},
        {"bytes", static_cast<std::uint64_t>(zip.size())},
        {"sha256", pm::storage::sha256_hex(zip)},
        {"entryCount", static_cast<std::uint64_t>(parsed.entries.size())},
        {"entries", std::move(names)},
    });
}

void cmd_storage_bundle_sign(const std::string& file, const std::string& seed_hex, const std::string& out) {
    if (sodium_init() < 0) {
        emit(err_json("storage.bundle.sign", "sodium_init failed"));
        return;
    }
    std::vector<std::uint8_t> zip;
    std::string err;
    if (!read_file_for_storage(fs::path(file), zip, err)) {
        emit(err_json("storage.bundle.sign", err));
        return;
    }
    // Seed may come from --seed-hex or PM_BUNDLE_SIGNING_SEED_HEX (keep the
    // production seed out of argv/shell history).
    std::string seed_text = seed_hex;
    if (seed_text.empty()) {
        if (const char* env = std::getenv("PM_BUNDLE_SIGNING_SEED_HEX"))
            seed_text = env;
    }
    if (seed_text.size() != 64) {
        emit(err_json("storage.bundle.sign", "expected a 64-hex-char (32-byte) Ed25519 seed"));
        return;
    }
    unsigned char seed[32];
    if (sodium_hex2bin(seed, sizeof(seed), seed_text.c_str(), seed_text.size(),
                       nullptr, nullptr, nullptr) != 0) {
        emit(err_json("storage.bundle.sign", "seed is not valid hex"));
        return;
    }
    std::vector<std::uint8_t> sig;
    const bool ok = pm::storage::bundle::sign_detached(zip, seed, sig, err);
    sodium_memzero(seed, sizeof(seed));
    if (!ok) {
        emit(err_json("storage.bundle.sign", err));
        return;
    }
    const std::string sig_path = out.empty() ? (file + ".sig") : out;
    std::ofstream so(sig_path, std::ios::binary | std::ios::trunc);
    if (!so.is_open()) {
        emit(err_json("storage.bundle.sign", "failed to open output: " + sig_path));
        return;
    }
    so.write(reinterpret_cast<const char*>(sig.data()), static_cast<std::streamsize>(sig.size()));
    emit({
        {"ok", true},
        {"function", "storage.bundle.sign"},
        {"file", file},
        {"sig", sig_path},
        {"bytes", static_cast<std::uint64_t>(sig.size())},
        {"sha256", pm::storage::sha256_hex(zip)},
    });
}

void cmd_storage_bundle_verify_file(const std::string& file, const std::string& sig_file) {
    std::vector<std::uint8_t> zip;
    std::vector<std::uint8_t> sig;
    std::string err;
    if (!read_file_for_storage(fs::path(file), zip, err)) {
        emit(err_json("storage.bundle.verify", err));
        return;
    }
    const std::string sp = sig_file.empty() ? (file + ".sig") : sig_file;
    if (!read_file_for_storage(fs::path(sp), sig, err)) {
        emit(err_json("storage.bundle.verify", "signature missing: " + sp));
        return;
    }
    const bool ok = pm::storage::bundle::verify_detached(
        zip, sig, pm::storage::bundle::k_bundle_signing_public_key_ed25519, err);
    emit({
        {"ok", ok},
        {"function", "storage.bundle.verify"},
        {"file", file},
        {"sig", sp},
        {"signatureValid", ok},
        {"error", ok ? json(nullptr) : json(err)},
    });
}

void cmd_storage_bundle_list(const std::string& uri, const std::string& file) {
    std::vector<std::uint8_t> zip;
    json verify;
    std::string err;
    if (!bundle_bytes_from_source(uri, file, zip, verify, err)) {
        emit(err_json("storage.bundle.list", err));
        return;
    }
    pm::storage::bundle::ParsedBundle parsed;
    if (!pm::storage::bundle::parse_bundle(zip, parsed, err)) {
        emit(err_json("storage.bundle.list", err));
        return;
    }
    json items = json::array();
    for (const auto& e : parsed.entries) {
        items.push_back({
            {"path", e.path},
            {"bytes", static_cast<std::uint64_t>(e.data_size)},
            {"contentType", pm::storage::bundle::content_type_for_path(e.path)},
        });
    }
    emit({
        {"ok", true},
        {"function", "storage.bundle.list"},
        {"verify", verify},
        {"count", static_cast<std::uint64_t>(parsed.entries.size())},
        {"entries", std::move(items)},
    });
}

// Emulate a web engine subresource request against the (verified) bundle.
void cmd_storage_bundle_serve(const std::string& uri, const std::string& file, const std::string& path) {
    std::vector<std::uint8_t> zip;
    json verify;
    std::string err;
    if (!bundle_bytes_from_source(uri, file, zip, verify, err)) {
        emit(err_json("storage.bundle.serve", err));
        return;
    }
    pm::storage::bundle::ParsedBundle parsed;
    if (!pm::storage::bundle::parse_bundle(zip, parsed, err)) {
        emit(err_json("storage.bundle.serve", err));
        return;
    }
    std::vector<std::uint8_t> data;
    if (!pm::storage::bundle::find_entry(parsed, zip, path, data, err)) {
        emit({
            {"ok", false},
            {"function", "storage.bundle.serve"},
            {"verify", verify},
            {"path", path},
            {"found", false},
            {"error", err},
        });
        return;
    }
    // UTF-8 round-trip is best-effort; binary entries (e.g. .wasm) report null.
    json data_utf8 = nullptr;
    const std::string text(reinterpret_cast<const char*>(data.data()), data.size());
    if (text.find('\0') == std::string::npos)
        data_utf8 = text;
    emit({
        {"ok", true},
        {"function", "storage.bundle.serve"},
        {"verify", verify},
        {"path", path},
        {"found", true},
        {"contentType", pm::storage::bundle::content_type_for_path(path)},
        {"bytes", static_cast<std::uint64_t>(data.size())},
        {"sha256", pm::storage::sha256_hex(data)},
        {"dataUtf8", data_utf8},
    });
}

void cmd_storage_bundle_unpack(const std::string& uri, const std::string& file, const std::string& out_dir) {
    std::vector<std::uint8_t> zip;
    json verify;
    std::string err;
    if (!bundle_bytes_from_source(uri, file, zip, verify, err)) {
        emit(err_json("storage.bundle.unpack", err));
        return;
    }
    if (!pm::storage::bundle::unpack_to_dir(zip, fs::path(out_dir), err)) {
        emit(err_json("storage.bundle.unpack", err));
        return;
    }
    pm::storage::bundle::ParsedBundle parsed;
    (void)pm::storage::bundle::parse_bundle(zip, parsed, err);
    emit({
        {"ok", true},
        {"function", "storage.bundle.unpack"},
        {"verify", verify},
        {"outDir", out_dir},
        {"entryCount", static_cast<std::uint64_t>(parsed.entries.size())},
    });
}

void cmd_storage_doc_put(const std::string& uri,
                         const std::string& file,
                         const std::string& type,
                         const std::string& trust,
                         const std::string& version,
                         const std::string& provider,
                         const std::string& signer,
                         bool encrypt,
                         bool allow_plaintext_seed) {
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("storage.doc.put", err));
        return;
    }

    pm::storage::PutDocumentRequest req;
    req.uri = uri;
    req.type = pm::model::resource_type_from_string(type);
    req.trust = pm::model::trust_level_from_string(trust);
    req.version = version.empty() ? "1" : version;
    req.provider = provider.empty() ? "user" : provider;
    req.signer_id = signer;
    req.encrypt = encrypt;
    req.allow_plaintext_seed = allow_plaintext_seed;
    req.data = std::move(data);

    const auto r = pm::storage::put_document(active_storage_paths(), req);
    emit({
        {"ok", r.ok},
        {"function", "storage.doc.put"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"error", r.error},
    });
}

void cmd_storage_doc_import_plain(const std::string& uri,
                                  const std::string& file,
                                  const std::string& type,
                                  const std::string& trust,
                                  const std::string& version,
                                  const std::string& provider,
                                  const std::string& signer,
                                  bool encrypt,
                                  bool allow_plaintext_seed,
                                  bool sign_after_import) {
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("storage.doc.import-plain", err));
        return;
    }

    pm::storage::PutDocumentRequest req;
    req.uri = uri;
    req.type = pm::model::resource_type_from_string(type);
    req.trust = pm::model::trust_level_from_string(trust);
    req.version = version.empty() ? "1" : version;
    req.provider = provider.empty() ? "user" : provider;
    req.signer_id = signer;
    req.encrypt = encrypt;
    req.allow_plaintext_seed = allow_plaintext_seed;
    req.data = std::move(data);

    const auto stored = pm::storage::put_document(active_storage_paths(), req);
    if (!stored.ok || !sign_after_import) {
        emit({
            {"ok", stored.ok},
            {"function", "storage.doc.import-plain"},
            {"uri", uri},
            {"file", file},
            {"meta", storage_meta_json(stored.meta)},
            {"signed", false},
            {"error", stored.error},
        });
        return;
    }
    const auto signed_doc = pm::storage::sign_document(active_storage_paths(), uri);
    emit({
        {"ok", signed_doc.ok},
        {"function", "storage.doc.import-plain"},
        {"uri", uri},
        {"file", file},
        {"meta", storage_meta_json(stored.meta)},
        {"signed", signed_doc.ok},
        {"publicKey", signed_doc.public_key.empty() ? json(nullptr) : json(signed_doc.public_key)},
        {"error", signed_doc.error},
    });
}

pm::storage::DocumentLoadPolicy make_document_policy(bool require_signature,
                                                     bool require_encryption,
                                                     bool allow_vendor_seed_plaintext,
                                                     const std::vector<std::string>& allowed_trust) {
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = require_signature;
    policy.require_encryption = require_encryption;
    policy.allow_vendor_seed_plaintext = allow_vendor_seed_plaintext;
    for (const auto& trust : allowed_trust)
        policy.allowed_trust.push_back(pm::model::trust_level_from_string(trust));
    return policy;
}

void cmd_storage_doc_get(const std::string& uri,
                         bool require_signature,
                         bool require_encryption,
                         bool allow_vendor_seed_plaintext,
                         const std::vector<std::string>& allowed_trust) {
    const auto policy = make_document_policy(require_signature, require_encryption, allow_vendor_seed_plaintext, allowed_trust);
    const auto r = pm::storage::load_document(active_storage_paths(), uri, policy);
    std::string text;
    if (r.ok)
        text.assign(reinterpret_cast<const char*>(r.document.data.data()), r.document.data.size());
    emit({
        {"ok", r.ok},
        {"function", "storage.doc.get"},
        {"uri", uri},
        {"meta", storage_meta_json(r.document.meta)},
        {"bytes", r.ok ? static_cast<std::uint64_t>(r.document.data.size()) : 0},
        {"dataUtf8", r.ok ? json(text) : json(nullptr)},
        {"signerPin", pm::storage::signer_pin_code_name(r.signer_pin)},
        {"error", r.error},
    });
}

void cmd_storage_doc_export_plain(const std::string& uri,
                                  const std::string& file,
                                  bool require_signature,
                                  bool require_encryption,
                                  bool allow_vendor_seed_plaintext,
                                  const std::vector<std::string>& allowed_trust) {
    const auto policy = make_document_policy(require_signature, require_encryption, allow_vendor_seed_plaintext, allowed_trust);
    const auto r = pm::storage::load_document(active_storage_paths(), uri, policy);
    if (!r.ok) {
        emit({
            {"ok", false},
            {"function", "storage.doc.export-plain"},
            {"uri", uri},
            {"file", file},
            {"error", r.error},
        });
        return;
    }
    std::string err;
    const bool wrote = write_file_for_storage(fs::path(file), r.document.data, err);
    emit({
        {"ok", wrote},
        {"function", "storage.doc.export-plain"},
        {"uri", uri},
        {"file", file},
        {"meta", storage_meta_json(r.document.meta)},
        {"bytes", wrote ? static_cast<std::uint64_t>(r.document.data.size()) : 0},
        {"error", err},
    });
}

void cmd_storage_doc_list() {
    const auto r = pm::storage::list_documents(active_storage_paths());
    json items = json::array();
    for (const auto& meta : r.items)
        items.push_back(storage_meta_json(meta));
    emit({
        {"ok", r.ok},
        {"function", "storage.doc.list"},
        {"count", static_cast<std::uint64_t>(items.size())},
        {"documents", std::move(items)},
        {"error", r.error},
    });
}

void cmd_storage_doc_verify(const std::string& uri,
                            bool require_signature,
                            bool require_encryption,
                            bool allow_vendor_seed_plaintext,
                            const std::vector<std::string>& allowed_trust) {
    const auto policy = make_document_policy(require_signature, require_encryption, allow_vendor_seed_plaintext, allowed_trust);
    const auto r = pm::storage::verify_document(active_storage_paths(), uri, policy);
    emit({
        {"ok", r.ok},
        {"function", "storage.doc.verify"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"actualDigest", r.actual_digest},
        {"signedManifest", r.signed_manifest},
        {"signatureValid", r.signature_valid},
        {"signerPublicKey", r.signer_public_key.empty() ? json(nullptr) : json(r.signer_public_key)},
        {"signerPin", pm::storage::signer_pin_code_name(r.signer_pin)},
        {"error", r.error},
    });
}

void cmd_storage_doc_sign(const std::string& uri) {
    const auto r = pm::storage::sign_document(active_storage_paths(), uri);
    emit({
        {"ok", r.ok},
        {"function", "storage.doc.sign"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"publicKey", r.public_key.empty() ? json(nullptr) : json(r.public_key)},
        {"signature", r.signature.empty() ? json(nullptr) : json(r.signature)},
        {"error", r.error},
    });
}

void cmd_storage_doc_delete(const std::string& uri) {
    const auto r = pm::storage::delete_document(active_storage_paths(), uri);
    emit({
        {"ok", r.ok},
        {"function", "storage.doc.delete"},
        {"uri", uri},
        {"meta", storage_meta_json(r.meta)},
        {"error", r.error},
    });
}

void cmd_storage_doc_import_seed(const std::string& seed_config_dir, const std::string& uri) {
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.allow_vendor_seed_plaintext = true;
    policy.allowed_trust = {pm::model::TrustLevel::Builtin, pm::model::TrustLevel::SignedVendor};
    const auto seed_paths = pm::storage::resolve_storage_paths(fs::path(seed_config_dir));
    const auto verified = pm::storage::verify_document(seed_paths, uri, policy);
    if (!verified.ok) {
        emit({
            {"ok", false},
            {"function", "storage.doc.import-seed"},
            {"uri", uri},
            {"error", verified.error.empty() ? "seed document verification failed" : verified.error},
        });
        return;
    }
    const auto loaded = pm::storage::load_document(seed_paths, uri, policy);
    if (!loaded.ok) {
        emit({
            {"ok", false},
            {"function", "storage.doc.import-seed"},
            {"uri", uri},
            {"error", loaded.error.empty() ? "seed document load failed" : loaded.error},
        });
        return;
    }

    pm::storage::PutDocumentRequest req;
    req.uri = loaded.document.meta.uri;
    req.type = loaded.document.meta.type;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = loaded.document.meta.version.empty() ? "1" : loaded.document.meta.version;
    req.provider = loaded.document.meta.provider.empty() ? "vendor-seed" : loaded.document.meta.provider;
    req.signer_id = verified.signer_public_key.empty()
        ? loaded.document.meta.signer_id
        : std::string("vendor:") + verified.signer_public_key;
    req.encrypt = true;
    req.data = loaded.document.data;
    const auto stored = pm::storage::put_document(active_storage_paths(), req);
    if (!stored.ok) {
        emit({
            {"ok", false},
            {"function", "storage.doc.import-seed"},
            {"uri", uri},
            {"seedMeta", storage_meta_json(loaded.document.meta)},
            {"error", stored.error},
        });
        return;
    }
    const auto signed_local = pm::storage::sign_document(active_storage_paths(), uri);
    emit({
        {"ok", signed_local.ok},
        {"function", "storage.doc.import-seed"},
        {"uri", uri},
        {"seedMeta", storage_meta_json(loaded.document.meta)},
        {"meta", storage_meta_json(stored.meta)},
        {"vendorSignerPublicKey", verified.signer_public_key.empty() ? json(nullptr) : json(verified.signer_public_key)},
        {"localPublicKey", signed_local.public_key.empty() ? json(nullptr) : json(signed_local.public_key)},
        {"error", signed_local.error},
    });
}

// ── settings-store (app settings facade over secure SettingsProfile) ──────────

#if FEATURE_SECURE_STORAGE

// Verification provider for headless CLI callers.
// - DPAPI / PlatformDefault mode: verify_user_presence() returns true immediately
//   (pass through — the OS process credential is the protection layer).
// - MockWindowsHello / WindowsHelloTpm: triggers the appropriate challenge UI.
//   Windows Hello works from CLI too; it opens its own dialog window.
// - ExportSecret / Strong: never available headless (return NotConfigured).
class CliVerificationProvider final : public sec::IUserVerificationProvider {
public:
    sec::VerificationResult verify(const sec::VerificationOptions& options) override
    {
        if (options.level == sec::VerificationLevel::ExportSecret ||
            options.level == sec::VerificationLevel::Strong)
            return sec::VerificationResult::NotConfigured;
        if (options.level == sec::VerificationLevel::None)
            return sec::VerificationResult::Success;
        std::string err;
        if (!pm::storage::verify_user_presence(err)) {
            if (err.find("cancel") != std::string::npos ||
                err.find("Cancel") != std::string::npos)
                return sec::VerificationResult::Cancelled;
            return sec::VerificationResult::NotConfigured;
        }
        return sec::VerificationResult::Success;
    }
};

bool cli_operation_allowed(std::string_view operation, std::string& err)
{
#if defined(FEATURE_VENDOR_PLAINTEXT_EXPORT) && FEATURE_VENDOR_PLAINTEXT_EXPORT
    if (operation == "settings.exportPlain" ||
        operation == "commandConfig.exportPlain" ||
        operation == "mcpConfig.exportPlain" ||
        operation == "promptTemplate.exportPlain" ||
        operation == "homePage.exportPlain") {
        std::cerr << "[SECURITY WARNING] vendor plaintext export bypass enabled for "
                  << operation << '\n';
        return true;
    }
#endif

    static CliVerificationProvider        provider;
    static sec::VerificationSessionCache  cache;
    static std::mutex                     guard_mutex;

    sec::OperationGuardOptions options;
    options.operation.assign(operation.begin(), operation.end());
    options.verification_ttl = std::chrono::minutes(10);

    std::lock_guard<std::mutex> lock(guard_mutex);
    const auto result = sec::ensure_operation_allowed(provider, cache, options);
    if (result.allowed)
        return true;
    err = result.error.empty() ? "operation_not_allowed" : result.error;
    return false;
}

#endif // FEATURE_SECURE_STORAGE

void cmd_settings_store_put(const std::string& file) {
    apply_config_dir();
    media::settings::clear_settings_read_path_override();
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("settings.importPlain", policy_err)) {
            emit(err_json("settings-store.put", policy_err));
            return;
        }
    }
#endif
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("settings-store.put", err));
        return;
    }
    const std::string text(reinterpret_cast<const char*>(data.data()), data.size());
    const bool saved = media::settings::save_settings_utf8(text, err);
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {pm::model::TrustLevel::UserLocal};
    const auto verified = saved
        ? pm::storage::verify_document(active_storage_paths(), "pm://config/settings.json", policy)
        : pm::storage::VerifyDocumentResult{};
    emit({
        {"ok", saved && verified.ok},
        {"function", "settings-store.put"},
        {"file", file},
        {"uri", "pm://config/settings.json"},
        {"meta", storage_meta_json(verified.meta)},
        {"verified", verified.ok},
        {"error", saved ? verified.error : err},
    });
}

void cmd_settings_store_update(const std::string& file) {
    cmd_settings_store_put(file);
}

void cmd_settings_store_get() {
    apply_config_dir();
    media::settings::clear_settings_read_path_override();
    std::string err;
    std::string text;
    const bool loaded = media::settings::load_settings_utf8(text, err);
    emit({
        {"ok", loaded},
        {"function", "settings-store.get"},
        {"uri", "pm://config/settings.json"},
        {"bytes", loaded ? static_cast<std::uint64_t>(text.size()) : 0},
        {"dataUtf8", loaded ? json(text) : json(nullptr)},
        {"error", err},
    });
}

void cmd_settings_store_export(const std::string& file, bool encrypted) {
    apply_config_dir();
    media::settings::clear_settings_read_path_override();
#if FEATURE_SECURE_STORAGE
    {
        const char* op = encrypted ? "settings.exportEncrypted" : "settings.exportPlain";
        std::string policy_err;
        if (!cli_operation_allowed(op, policy_err)) {
            emit(err_json("settings-store.export", policy_err));
            return;
        }
    }
#endif
    std::string err;
    const bool exported = media::settings::export_settings_file(fs::path(file), encrypted, err);
    emit({
        {"ok", exported},
        {"function", "settings-store.export"},
        {"uri", "pm://config/settings.json"},
        {"file", file},
        {"encrypted", encrypted},
        {"error", err},
    });
}

// ── command-store (app commands facade over secure CommandConfig) ──────────────

void cmd_command_store_import_plain(const std::string& file) {
    apply_config_dir();
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("commandConfig.importPlain", policy_err)) {
            emit(err_json("command-store.import-plain", policy_err));
            return;
        }
    }
#endif
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("command-store.import-plain", err));
        return;
    }
    const std::string text(reinterpret_cast<const char*>(data.data()), data.size());
    const bool saved = media::settings::save_command_json_utf8(text, err);
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {pm::model::TrustLevel::UserLocal};
    const auto verified = saved
        ? pm::storage::verify_document(active_storage_paths(), "pm://config/commands.json", policy)
        : pm::storage::VerifyDocumentResult{};
    emit({
        {"ok", saved && verified.ok},
        {"function", "command-store.import-plain"},
        {"file", file},
        {"uri", "pm://config/commands.json"},
        {"meta", storage_meta_json(verified.meta)},
        {"verified", verified.ok},
        {"error", saved ? verified.error : err},
    });
}

void cmd_command_store_get() {
    apply_config_dir();
    std::string err;
    std::string text;
    const bool loaded = media::settings::load_command_json_utf8(text, err);
    emit({
        {"ok", loaded},
        {"function", "command-store.get"},
        {"uri", "pm://config/commands.json"},
        {"bytes", loaded ? static_cast<std::uint64_t>(text.size()) : 0},
        {"dataUtf8", loaded ? json(text) : json(nullptr)},
        {"error", err},
    });
}

void cmd_command_store_export_plain(const std::string& file) {
    apply_config_dir();
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("commandConfig.exportPlain", policy_err)) {
            emit(err_json("command-store.export-plain", policy_err));
            return;
        }
    }
#endif
    std::string err;
    std::string text;
    const bool loaded = media::settings::load_command_json_utf8(text, err);
    bool written = false;
    if (loaded) {
        if (text.empty())
            text = "{}";
        const std::vector<std::uint8_t> data(text.begin(), text.end());
        written = write_file_for_storage(fs::path(file), data, err);
    }
    emit({
        {"ok", loaded && written},
        {"function", "command-store.export-plain"},
        {"uri", "pm://config/commands.json"},
        {"file", file},
        {"error", loaded ? err : err},
    });
}

// ── mcp-store (MCP config facade over secure McpConfig) ───────────────────────

constexpr const char* kMcpConfigUri = "pm://config/mcp.json";

pm::storage::DocumentLoadPolicy strict_mcp_config_policy() {
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {pm::model::TrustLevel::UserLocal};
    return policy;
}

bool validate_mcp_config_json(const std::vector<std::uint8_t>& data, std::string& err) {
    try {
        const auto parsed = json::parse(std::string(reinterpret_cast<const char*>(data.data()), data.size()));
        if (!parsed.is_object()) {
            err = "mcp.json root must be a JSON object";
            return false;
        }
        if (parsed.contains("mcpServers") && !parsed["mcpServers"].is_object()) {
            err = "mcp.json mcpServers must be an object";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        err = std::string("mcp.json parse error: ") + e.what();
        return false;
    }
}

void cmd_mcp_store_import_plain(const std::string& file) {
    apply_config_dir();
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("mcpConfig.importPlain", policy_err)) {
            emit(err_json("mcp-store.import-plain", policy_err));
            return;
        }
    }
#endif
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("mcp-store.import-plain", err));
        return;
    }
    if (!validate_mcp_config_json(data, err)) {
        emit(err_json("mcp-store.import-plain", err));
        return;
    }
    pm::storage::PutDocumentRequest req;
    req.uri = kMcpConfigUri;
    req.type = pm::model::ResourceType::McpConfig;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = "1";
    req.provider = "user";
    req.signer_id = "local-mcp";
    req.encrypt = true;
    req.data = std::move(data);
    const auto stored = pm::storage::put_document(active_storage_paths(), req);
    bool verified = false;
    std::string verify_err;
    pm::model::ResourceMeta meta;
    if (stored.ok) {
        const auto signed_doc = pm::storage::sign_document(active_storage_paths(), kMcpConfigUri);
        if (!signed_doc.ok) {
            verify_err = signed_doc.error;
        } else {
            const auto check = pm::storage::verify_document(active_storage_paths(), kMcpConfigUri, strict_mcp_config_policy());
            verified = check.ok;
            verify_err = check.error;
            meta = check.meta;
        }
    }
    if (stored.ok && verified)
        media::llm::mcp::invalidate_mcp_tools_cache();
    emit({
        {"ok", stored.ok && verified},
        {"function", "mcp-store.import-plain"},
        {"file", file},
        {"uri", kMcpConfigUri},
        {"meta", storage_meta_json(stored.ok && verified ? meta : stored.meta)},
        {"verified", verified},
        {"error", stored.ok ? verify_err : stored.error},
    });
}

void cmd_mcp_store_get() {
    apply_config_dir();
    const auto loaded = pm::storage::load_document(active_storage_paths(), kMcpConfigUri, strict_mcp_config_policy());
    std::string text;
    if (loaded.ok)
        text.assign(reinterpret_cast<const char*>(loaded.document.data.data()), loaded.document.data.size());
    emit({
        {"ok", loaded.ok},
        {"function", "mcp-store.get"},
        {"uri", kMcpConfigUri},
        {"bytes", loaded.ok ? static_cast<std::uint64_t>(text.size()) : 0},
        {"dataUtf8", loaded.ok ? json(text) : json(nullptr)},
        {"error", loaded.error},
    });
}

void cmd_mcp_store_export_plain(const std::string& file) {
    apply_config_dir();
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("mcpConfig.exportPlain", policy_err)) {
            emit(err_json("mcp-store.export-plain", policy_err));
            return;
        }
    }
#endif
    const auto loaded = pm::storage::load_document(active_storage_paths(), kMcpConfigUri, strict_mcp_config_policy());
    std::string err;
    bool written = false;
    if (loaded.ok)
        written = write_file_for_storage(fs::path(file), loaded.document.data, err);
    emit({
        {"ok", loaded.ok && written},
        {"function", "mcp-store.export-plain"},
        {"uri", kMcpConfigUri},
        {"file", file},
        {"error", loaded.ok ? err : loaded.error},
    });
}

// ── prompt-store (app prompt facade over secure PromptTemplate docs) ───────────

std::string prompt_uri_for_name(const std::string& name) {
    if (name == "system") return "pm://config/prompts/system-prompt.md";
    if (name == "planner") return "pm://config/prompts/planner-prompt.md";
    if (name == "realtime") return "pm://config/prompts/realtime-prompt.md";
    if (name == "security") return "pm://config/prompts/security-prompt.md";
    if (name.rfind("mode-", 0) == 0 && name.size() > 5)
        return "pm://config/prompts/" + name + ".md";
    if (name.rfind("pm://", 0) == 0)
        return name;
    return {};
}

std::string prompt_filename_for_name(const std::string& name) {
    if (name == "system") return "system-prompt.md";
    if (name == "planner") return "planner-prompt.md";
    if (name == "realtime") return "realtime-prompt.md";
    if (name == "security") return "security-prompt.md";
    if (name.rfind("mode-", 0) == 0 && name.size() > 5)
        return name + ".md";
    return {};
}

std::string trim_prompt_text(std::string text) {
    while (!text.empty() && static_cast<unsigned char>(text.front()) <= 32U)
        text.erase(0, 1);
    while (!text.empty() && static_cast<unsigned char>(text.back()) <= 32U)
        text.pop_back();
    return text;
}

pm::model::ResourceMeta strict_prompt_verify_meta(const std::string& uri, bool& ok, std::string& err) {
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {
        pm::model::TrustLevel::Builtin,
        pm::model::TrustLevel::SignedVendor,
        pm::model::TrustLevel::UserLocal,
    };
    const auto verified = pm::storage::verify_document(active_storage_paths(), uri, policy);
    ok = verified.ok;
    err = verified.error;
    return verified.meta;
}

void cmd_prompt_store_import_plain(const std::string& name, const std::string& file) {
    apply_config_dir();
    const std::string uri = prompt_uri_for_name(name);
    if (uri.empty()) {
        emit(err_json("prompt-store.import-plain", "unknown prompt name: " + name));
        return;
    }
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("promptTemplate.importPlain", policy_err)) {
            emit(err_json("prompt-store.import-plain", policy_err));
            return;
        }
    }
#endif
    std::string err;
    std::vector<std::uint8_t> data;
    if (!read_file_for_storage(fs::path(file), data, err)) {
        emit(err_json("prompt-store.import-plain", err));
        return;
    }
    pm::storage::PutDocumentRequest req;
    req.uri = uri;
    req.type = pm::model::ResourceType::PromptTemplate;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = "1";
    req.provider = "user";
    req.signer_id = "local-prompts";
    req.encrypt = true;
    req.data = std::move(data);
    const auto stored = pm::storage::put_document(active_storage_paths(), req);
    bool signed_ok = false;
    std::string verify_err;
    pm::model::ResourceMeta meta;
    if (stored.ok) {
        const auto signed_doc = pm::storage::sign_document(active_storage_paths(), uri);
        signed_ok = signed_doc.ok;
        if (!signed_ok) {
            verify_err = signed_doc.error;
        } else {
            meta = strict_prompt_verify_meta(uri, signed_ok, verify_err);
        }
    }
    emit({
        {"ok", stored.ok && signed_ok},
        {"function", "prompt-store.import-plain"},
        {"name", name},
        {"uri", uri},
        {"file", file},
        {"meta", storage_meta_json(stored.ok && signed_ok ? meta : stored.meta)},
        {"verified", signed_ok},
        {"error", stored.ok ? verify_err : stored.error},
    });
}

void cmd_prompt_store_get(const std::string& name) {
    apply_config_dir();
    const std::string uri = prompt_uri_for_name(name);
    const std::string filename = prompt_filename_for_name(name);
    if (uri.empty() || filename.empty()) {
        emit(err_json("prompt-store.get", "unknown prompt name: " + name));
        return;
    }
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {
        pm::model::TrustLevel::Builtin,
        pm::model::TrustLevel::SignedVendor,
        pm::model::TrustLevel::UserLocal,
    };
    const auto loaded = pm::storage::load_document(active_storage_paths(), uri, policy);
    std::string source = uri;
    std::string text;
    if (loaded.ok)
        text.assign(reinterpret_cast<const char*>(loaded.document.data.data()), loaded.document.data.size());
    emit({
        {"ok", loaded.ok},
        {"function", "prompt-store.get"},
        {"name", name},
        {"uri", uri},
        {"bytes", loaded.ok ? static_cast<std::uint64_t>(text.size()) : 0},
        {"dataUtf8", loaded.ok ? json(trim_prompt_text(std::move(text))) : json(nullptr)},
        {"source", loaded.ok ? json(source) : json(nullptr)},
        {"error", loaded.error},
    });
}

void cmd_prompt_store_export_plain(const std::string& name, const std::string& file) {
    apply_config_dir();
    const std::string uri = prompt_uri_for_name(name);
    if (uri.empty()) {
        emit(err_json("prompt-store.export-plain", "unknown prompt name: " + name));
        return;
    }
#if FEATURE_SECURE_STORAGE
    {
        std::string policy_err;
        if (!cli_operation_allowed("promptTemplate.exportPlain", policy_err)) {
            emit(err_json("prompt-store.export-plain", policy_err));
            return;
        }
    }
#endif
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {
        pm::model::TrustLevel::Builtin,
        pm::model::TrustLevel::SignedVendor,
        pm::model::TrustLevel::UserLocal,
    };
    const auto loaded = pm::storage::load_document(active_storage_paths(), uri, policy);
    std::string err;
    bool written = false;
    if (loaded.ok)
        written = write_file_for_storage(fs::path(file), loaded.document.data, err);
    emit({
        {"ok", loaded.ok && written},
        {"function", "prompt-store.export-plain"},
        {"name", name},
        {"uri", uri},
        {"file", file},
        {"error", loaded.ok ? err : loaded.error},
    });
}

// ── origin (provenance) ──────────────────────────────────────────────────────

void cmd_origin_list() {
    json arr = json::array();
    for (const auto& o : sec::known_origins())
        arr.push_back(origin_json(o));
    emit({{"ok", true}, {"function", "origin.list"}, {"count", static_cast<std::uint64_t>(arr.size())}, {"origins", arr}});
}

void cmd_origin_resolve(const std::string& binary) {
    const sec::Origin o = sec::resolve_origin(binary);
    emit({{"ok", true}, {"function", "origin.resolve"}, {"input", binary}, {"origin", origin_json(o)}});
}

// ── uri (RFC-3986 scope) ─────────────────────────────────────────────────────

void cmd_uri_parse(const std::string& in) {
    const auto p = sec::uri::parse_uri(in);
    if (!p || !p->valid) {
        emit(err_json("uri.parse", "could not parse: " + in));
        return;
    }
    emit({
        {"ok", true},
        {"function", "uri.parse"},
        {"input", in},
        {"scheme", p->scheme},
        {"host", p->host},
        {"port", p->port},
        {"path", p->path},
    });
}

void cmd_uri_match(const std::string& target_uri, const std::vector<std::string>& scopes) {
    const sec::ResourceTarget t = make_target("", target_uri);
    json results = json::array();
    bool any = false;
    for (const auto& s : scopes) {
        const bool m = sec::uri::scope_matches_target(s, t);
        any = any || m;
        results.push_back({{"scope", s}, {"match", m}});
    }
    emit({
        {"ok", any},
        {"function", "uri.match"},
        {"target", target_uri},
        {"any", any},
        {"results", results},
    });
}

// ── verification policy ───────────────────────────────────────────────────────

class CountingVerificationProvider final : public sec::IUserVerificationProvider {
public:
    explicit CountingVerificationProvider(sec::VerificationResult result)
        : result_(result) {}

    sec::VerificationResult verify(const sec::VerificationOptions&) override {
        ++count_;
        return result_;
    }

    int count() const noexcept { return count_; }

private:
    sec::VerificationResult result_ = sec::VerificationResult::Success;
    int count_ = 0;
};

json verification_policy_json(const sec::OperationVerificationPolicy& policy) {
    return {
        {"operation", policy.operation},
        {"level", std::string(sec::to_string(policy.level))},
        {"verification", std::string(sec::to_string(policy.level))},
        {"privilege", std::string(sec::to_string(policy.privilege))},
        {"reason", policy.reason},
    };
}

void cmd_verification_defaults() {
    json policies = json::array();
    for (const auto& policy : sec::default_operation_verification_policies())
        policies.push_back(verification_policy_json(policy));
    emit({
        {"ok", true},
        {"function", "verification.defaults"},
        {"provider", "platform"},
        {"policies", policies},
        {"operationPolicies", sec::default_operation_policies_json()},
        {"settingsShape", sec::default_security_settings_json()},
        {"configDir", media::settings::get_config_dir().generic_string()},
        {"respectsConfigDir", true},
    });
}

json operation_guard_result_json(const sec::OperationGuardResult& result) {
    return {
        {"allowed", result.allowed},
        {"operation", result.operation},
        {"level", std::string(sec::to_string(result.level))},
        {"verification", std::string(sec::to_string(result.verification))},
        {"verificationRequired", result.verification_required},
        {"verificationCacheHit", result.verification_cache_hit},
        {"privilege", std::string(sec::to_string(result.privilege))},
        {"privilegeSatisfied", result.privilege_satisfied},
        {"reason", result.reason},
        {"error", result.error.empty() ? json(nullptr) : json(result.error)},
    };
}

void cmd_verification_guard(const std::string& operation,
                            const std::string& provider_result,
                            std::uint32_t ttl_seconds,
                            std::uint32_t repeat,
                            bool assume_privilege) {
    auto parsed = sec::verification_result_from_string(provider_result);
    if (!parsed) {
        emit(err_json("verification.guard", "unknown provider result: " + provider_result));
        return;
    }

    CountingVerificationProvider provider(*parsed);
    sec::VerificationSessionCache cache;
    json attempts = json::array();
    sec::OperationGuardResult last;
    const std::uint32_t attempt_count = repeat == 0 ? 1 : repeat;

    for (std::uint32_t i = 0; i < attempt_count; ++i) {
        sec::OperationGuardOptions options;
        options.operation = operation;
        options.verification_ttl = std::chrono::seconds(ttl_seconds);
        options.assume_privilege_satisfied = assume_privilege;
        last = sec::ensure_operation_allowed(provider, cache, options);
        json attempt = operation_guard_result_json(last);
        attempt["index"] = i + 1;
        attempts.push_back(attempt);
    }

    emit({
        {"ok", last.allowed},
        {"function", "verification.guard"},
        {"operation", operation},
        {"providerResult", provider_result},
        {"ttlSeconds", ttl_seconds},
        {"repeat", attempt_count},
        {"promptCount", provider.count()},
        {"cacheSize", cache.size()},
        {"attempts", attempts},
        {"last", operation_guard_result_json(last)},
    });
}

// ── schema (UI contract for web + win32 native) ──────────────────────────────

void cmd_schema() {
    auto strvec = [](std::initializer_list<const char*> xs) {
        json a = json::array();
        for (const char* x : xs) a.push_back(x);
        return a;
    };
    json schemes = json::array();
    for (const auto sv : sec::uri::k_uri_schemes) schemes.push_back(std::string(sv));

    const json enums = {
        {"profiles", strvec({"LIGHT", "STRICT", "DEVELOPER"})},
        {"actors", strvec({"user", "llm", "plugin", "mcp_server", "background_agent"})},
        {"actions", strvec({"read", "write", "delete", "execute", "network", "upload", "download", "git_push", "publish"})},
        {"risks", strvec({"low", "medium", "high", "critical"})},
        {"decisions", strvec({"allow", "deny", "ask", "sandbox", "allow_redacted"})},
        {"lifetimes", strvec({"once", "session", "task", "until_timestamp", "permanent"})},
        {"originKinds", strvec({"unknown", "ui", "cli", "service", "security"})},
        {"verificationLevels", strvec({"none", "presence", "local_unlock", "strong", "export_secret"})},
        {"verificationResults", strvec({"success", "cancelled", "timeout", "not_configured", "failed"})},
        {"privilegeRequirements", strvec({"none", "admin_preferred", "admin_required", "system_broker_required"})},
        {"uriSchemes", schemes},
    };

    // Field descriptors the UIs render. Each entry: name → {type, required?, enum?}.
    const json defs = {
        {"Origin", {
            {"id", "string"}, {"binaryName", "string"}, {"displayName", "string"},
            {"kind", "enum:originKinds"}, {"firstParty", "bool"},
        }},
        {"ToolIdentity", {
            {"toolId", "string (glob in grants)"}, {"provider", "string (glob in grants)"},
            {"serverId", "string (glob in grants)"}, {"executableHash", "string"},
            {"manifestHash", "string"}, {"signedManifest", "bool"},
        }},
        {"ResourceTarget", {
            {"uri", "string (uriSchemes)"}, {"path", "string"}, {"mime", "string"}, {"extension", "string"},
        }},
        {"CapabilityGrant", {
            {"id", "string"}, {"profile", "enum:profiles"}, {"subject", "string"},
            {"tool", "ToolIdentity"}, {"action", "enum:actions"},
            {"resourceScopes", "string[] (uri pattern | path glob)"},
            {"readOnly", "bool"}, {"allowSecrets", "bool"}, {"allowNetwork", "bool"},
            {"maxFiles", "uint64"}, {"maxBytes", "uint64"},
            {"lifetime", "enum:lifetimes"}, {"expiresAtMs", "int64?"},
            {"sessionId", "string (binds session lifetime)"}, {"taskId", "string (binds task lifetime)"},
            {"workspaceId", "string"}, {"policyVersion", "string"}, {"reason", "string"},
            {"aiDelegated", "bool"}, {"approvedBy", "string"},
            {"sandboxBackend", "string? (sandbox routing backend name)"},
        }},
        {"ConsentRequest", {
            {"title", "string"}, {"risk", "enum:risks"}, {"userGoal", "string"},
            {"whyNeeded", "string"}, {"possibleRisk", "string"},
            {"resourcePreview", "string[]"}, {"choices", "string[]"},
            {"sandboxBackends", "string[] (registered backends offered for this request)"},
        }},
        {"PolicyDecision", {
            {"kind", "enum:decisions"}, {"risk", "enum:risks"}, {"reason", "string"},
            {"grant", "CapabilityGrant?"}, {"consent", "ConsentRequest?"},
            {"sandboxBackend", "string? (backend required by this decision)"},
        }},
        {"OperationVerificationPolicy", {
            {"operation", "string (settings.load | asset.signSharedBundle | permissions.grant.*)"},
            {"level", "enum:verificationLevels"},
            {"verification", "enum:verificationLevels"},
            {"privilege", "enum:privilegeRequirements"},
            {"reason", "string"},
        }},
    };

    emit({
        {"ok", true},
        {"function", "schema"},
        {"version", "security-schema-1"},
        {"policyVersion", sec::k_policy_version},
        {"enums", enums},
        {"defs", defs},
    });
}

// ── sandbox (AppContainer / LPAC experimentation) ─────────────────────────────
//
// Gated by FEATURE_SECURITY_SANDBOX (default ON via security_default.hpp).
//
// Thin CLI wrappers over SandboxAppContainer (the portable backend).
// All Win32 primitives live in backends/win/SandboxAppContainer.cpp.
//
// Typical test loop:
//   1. sandbox probe   --moniker pm-mcp-test --retain
//   2. sandbox wrap-mcp --moniker pm-mcp-test --tool mcp.fs.write
//                        --action write --path <workspace>
//   3. sandbox acl     --moniker pm-mcp-test --path <workspace> --access write
//   4. sandbox wrap-mcp (repeat) → aclGranted=true
//   5. sandbox launch  --moniker pm-mcp-test --exe cmd.exe --retain

#if FEATURE_SECURITY_SANDBOX && defined(_WIN32)

// Process-wide singleton backend — created once at first sandbox command use.
static sec::SandboxAppContainer& sandbox_backend() {
    static sec::SandboxAppContainer s_backend;
    return s_backend;
}

// ── JSON-driven sandbox-config (CLI-only, maps onto SandboxSpawnOptions) ──────
//
// Accepted by `sandbox launch --sandbox-config <@file.json | inline-json>`.
// All fields optional; individual CLI flags overlay the parsed config.
//
// JSON shape:
// {
//   "moniker":       "pm-mcp-test",
//   "lpac":          false,
//   "noWin32k":      false,
//   "retainProfile": false,
//   "timeoutMs":     10000,
//   "run":           "cmd.exe",
//   "args":          ["/c", "exit 0"],
//   "capabilities":  [],
//   "paths": [
//     { "path": "C:\\workspace", "access": "read-write" },
//     { "path": "C:\\tools\\bin", "access": "exec" }
//   ]
// }

sec::SandboxSpawnOptions parse_sandbox_config(const std::string& src) {
    std::string raw;
    if (!src.empty() && src[0] == '@') {
        const std::string fpath = src.substr(1);
        std::ifstream f(fpath, std::ios::binary);
        if (!f) throw std::runtime_error("cannot open --sandbox-config file: " + fpath);
        raw.assign(std::istreambuf_iterator<char>(f), {});
    } else {
        raw = src;
    }
    const json j = json::parse(raw);
    sec::SandboxSpawnOptions opts;
    if (j.contains("moniker")       && j["moniker"].is_string())
        opts.moniker       = j["moniker"].get<std::string>();
    if (j.contains("lpac")          && j["lpac"].is_boolean())
        opts.lpac          = j["lpac"].get<bool>();
    if (j.contains("noWin32k")        && j["noWin32k"].is_boolean())
        opts.noWin32k        = j["noWin32k"].get<bool>();
    if (j.contains("noChildProcess")  && j["noChildProcess"].is_boolean())
        opts.noChildProcess  = j["noChildProcess"].get<bool>();
    if (j.contains("retainProfile") && j["retainProfile"].is_boolean())
        opts.retain        = j["retainProfile"].get<bool>();
    if (j.contains("timeoutMs")     && j["timeoutMs"].is_number())
        opts.timeoutMs     = j["timeoutMs"].get<uint32_t>();
    if (j.contains("run")           && j["run"].is_string())
        opts.run           = j["run"].get<std::string>();
    if (j.contains("args")          && j["args"].is_array())
        for (const auto& a : j["args"]) if (a.is_string()) opts.args.push_back(a.get<std::string>());
    if (j.contains("capabilities")  && j["capabilities"].is_array())
        for (const auto& c : j["capabilities"]) if (c.is_string()) opts.capabilities.push_back(c.get<std::string>());
    if (j.contains("retain")           && j["retain"].is_boolean())
        opts.retain        = j["retain"].get<bool>();
    if (j.contains("createScratchDir") && j["createScratchDir"].is_boolean())
        opts.createScratchDir = j["createScratchDir"].get<bool>();
    if (j.contains("paths")         && j["paths"].is_array()) {
        for (const auto& p : j["paths"]) {
            if (!p.is_object()) continue;
            sec::SandboxPathGrant g;
            g.path            = p.value("path",            "");
            g.access          = p.value("access",          "read");
            g.deleteOnRevoke  = p.value("deleteOnRevoke",  false);
            // propagation: "node" (O(1)) | "immediate" | "recursive".
            // Explicit config grants default to "immediate" so pre-existing files
            // in the folder remain readable (shared-folder semantics).
            const std::string prop = p.value("propagation", std::string{"immediate"});
            if (prop == "node")           g.propagation = sec::GrantPropagation::NodeOnly;
            else if (prop == "recursive") g.propagation = sec::GrantPropagation::Recursive;
            else                          g.propagation = sec::GrantPropagation::ImmediateFiles;
            if (!g.path.empty()) opts.paths.push_back(std::move(g));
        }
    }
    return opts;
}

// ── sandbox probe ─────────────────────────────────────────────────────────────

void cmd_sandbox_probe(const std::string& moniker, bool retain) {
    SBLOG_INFO("sandbox.probe: ensuring profile moniker=" + moniker);
    auto& ac = sandbox_backend();
    bool was_created = false;
    const std::string sid_str = ac.containerSid(moniker);
    if (sid_str.empty()) {
        SBLOG_ERROR("sandbox.probe: failed rc=" + std::to_string(ac.lastError()));
        emit(err_json("sandbox.probe",
            "AppContainer profile setup failed (Win32 " + std::to_string(ac.lastError()) + ")"));
        return;
    }
    // Detect whether this call created the profile (first call with fresh cache).
    was_created = true; // conservative: sid was just acquired
    SBLOG_INFO("sandbox.probe: profile ensured sid=" + sid_str);

    json out{
        {"ok", true},
        {"function", "sandbox.probe"},
        {"moniker", moniker},
        {"sid", sid_str},
        {"profileCreated", was_created},
        {"retained", retain},
    };
    if (!retain) {
        const bool deleted = ac.deleteProfile(moniker);
        out["profileDeleted"] = deleted;
        if (!deleted) out["deleteError"] = static_cast<int>(ac.lastError());
        SBLOG_INFO("sandbox.probe: profile " + std::string(deleted ? "deleted" : "delete-failed"));
    }
    emit(out);
}

// ── sandbox acl ("shared folder" grant) ──────────────────────────────────────

void cmd_sandbox_acl(const std::string& moniker,
                     const std::string& path_u8,
                     const std::string& access_str,
                     bool check_only) {
    SBLOG_INFO("sandbox.acl: resolving sid moniker=" + moniker);
    auto& ac = sandbox_backend();
    const std::string sid_str = ac.containerSid(moniker);
    if (sid_str.empty()) {
        SBLOG_ERROR("sandbox.acl: SID resolution failed rc=" + std::to_string(ac.lastError()));
        emit(err_json("sandbox.acl",
            "could not resolve container SID (Win32 " + std::to_string(ac.lastError()) + ")"));
        return;
    }

    if (check_only) {
        // Read-only probe: report whether the path DACL already has the container SID.
        SBLOG_INFO("sandbox.acl: check-access path=" + path_u8 + " sid=" + sid_str);
        const bool granted = ac.checkAccess(moniker, path_u8);
        SBLOG_INFO("sandbox.acl: check-access result=" + std::string(granted ? "granted" : "not-granted"));
        emit({
            {"ok", granted},
            {"function", "sandbox.acl"},
            {"moniker", moniker},
            {"path", path_u8},
            {"sid", sid_str},
            {"aclGranted", granted},
            {"checkOnly", true},
            {"error", granted ? std::string{} : "path DACL does not contain the container SID"},
        });
        return;
    }

    SBLOG_INFO("sandbox.acl: granting path=" + path_u8 + " access=" + access_str +
               " sid=" + sid_str);
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = ac.grantPath(moniker, path_u8, access_str);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    if (ok)
        SBLOG_INFO("sandbox.acl: grant ok elapsed=" + std::to_string(elapsed_ms) + "ms");
    else
        SBLOG_ERROR("sandbox.acl: SetNamedSecurityInfo failed rc=" + std::to_string(ac.lastError()));
    emit({
        {"ok", ok},
        {"function", "sandbox.acl"},
        {"moniker", moniker},
        {"path", path_u8},
        {"access", access_str},
        {"sid", sid_str},
        {"elapsedMs", static_cast<int>(elapsed_ms)},
        {"error", !ok
            ? "SetNamedSecurityInfo failed (Win32 " + std::to_string(ac.lastError()) + ")"
            : std::string{}},
    });
}

// ── sandbox launch ────────────────────────────────────────────────────────────

void cmd_sandbox_launch(const std::string& moniker_u8,
                        const std::string& exe_u8,
                        bool lpac,
                        bool no_win32k,
                        bool no_child_process,
                        const std::vector<std::string>& capabilities,
                        bool retain,
                        uint32_t timeout_ms,
                        const std::string& config_src = {},
                        const std::string& preset_name = {},
                        const std::string& bin_dir_override = {},
                        const std::vector<std::string>& user_paths = {}) {
    // ── Derive the bin directory ─────────────────────────────────────────────
    // Default: dirname(this exe)/bin.  Caller may override via --bin-dir.
    std::string bin_dir = bin_dir_override;
    if (bin_dir.empty()) {
        try {
            const fs::path self = fs::read_symlink("/proc/self/exe");
            bin_dir = (self.parent_path() / "bin").generic_string();
        } catch (...) {}
    }
#if defined(_WIN32)
    if (bin_dir.empty()) {
        WCHAR buf[MAX_PATH + 1] = {};
        if (GetModuleFileNameW(nullptr, buf, MAX_PATH)) {
            const fs::path self(buf);
            bin_dir = (self.parent_path() / "bin").generic_string();
        }
    }
#endif

    sec::SandboxSpawnOptions opts;

    // ── Named preset: fill in baseline before config JSON or CLI flags ───────
    // Preset establishes the default flags/paths for a tool category.
    // Config JSON and individual CLI flags both override preset values.
    std::string resolved_preset;
    // For the "self" preset, --capabilities replaces (not appends to) the
    // preset's default capability set.  Track whether we consumed caps here
    // so the CLI-flags section below does not double-add them.
    bool caps_used_as_preset_override = false;
    if (!preset_name.empty()) {
        sec::SandboxPresetContext pctx;
        pctx.binDir   = bin_dir;
        // dist dir = parent of bin dir (dist/win-x64)
        if (!bin_dir.empty()) {
            try {
                pctx.distDir = fs::path(bin_dir).parent_path().generic_string();
            } catch (...) {}
        }
        // Roaming settings profile (%APPDATA%\PolyMech\pm-image)
        try {
            pctx.roamingDir = media::settings::get_config_dir().generic_string();
        } catch (...) {}
        // cwd is not yet known at this point; will be filled after config parse
        try {
            pctx.cacheDir = fs::temp_directory_path().generic_string();
        } catch (...) {}
        // User-defined extra paths (--user-path flags)
        pctx.userPaths = user_paths;
        // self preset: --capabilities overrides (replaces) the default cap set
        if (preset_name == sec::k_preset_self && !capabilities.empty()) {
            pctx.capsOverride = capabilities;
            caps_used_as_preset_override = true;
        }
        if (!sec::resolve_preset(preset_name, pctx, opts)) {
            emit(err_json("sandbox.launch", "unknown preset: " + preset_name +
                 " (known: offline, fetch, run, strict, self)"));
            return;
        }
        resolved_preset = preset_name;
        SBLOG_INFO("sandbox.launch: applied preset=" + preset_name +
                   " distDir=" + pctx.distDir +
                   " roamingDir=" + pctx.roamingDir);
    }

    if (!config_src.empty()) {
        try {
            sec::SandboxSpawnOptions cfg = parse_sandbox_config(config_src);
            // Merge config on top of preset: non-empty / non-default config fields win.
            if (!cfg.moniker.empty())    opts.moniker   = cfg.moniker;
            if (!cfg.run.empty())        opts.run       = cfg.run;
            if (!cfg.args.empty())       opts.args      = cfg.args;
            if (!cfg.cwd.empty())        opts.cwd       = cfg.cwd;
            if (cfg.lpac)               opts.lpac           = true;
            if (cfg.noWin32k)           opts.noWin32k       = true;
            if (cfg.noChildProcess)     opts.noChildProcess = true;
            if (cfg.retain)             opts.retain         = true;
            if (cfg.createScratchDir)   opts.createScratchDir = true;
            if (cfg.timeoutMs != 10000) opts.timeoutMs      = cfg.timeoutMs;
            for (const auto& c : cfg.capabilities)
                opts.capabilities.push_back(c);
            for (const auto& p : cfg.paths)
                opts.paths.push_back(p);
        } catch (const std::exception& e) {
            emit(err_json("sandbox.launch", std::string("--sandbox-config parse error: ") + e.what()));
            return;
        }
        SBLOG_INFO("sandbox.launch: loaded sandbox-config paths=" +
                   std::to_string(opts.paths.size()) + " run=" + opts.run);
    }

    // ── If preset has a cwd-dependent path, re-resolve after cwd is known ───
    // (The preset applied an empty cwd earlier; now that config JSON may have
    //  populated opts.cwd we retroactively add the cwd grant if the preset
    //  would have done so and the path isn't already in the list.)
    if (!resolved_preset.empty() && !opts.cwd.empty()) {
        // Check if cwd is already in opts.paths (config may have added it)
        const bool cwd_granted = [&] {
            for (const auto& pg : opts.paths)
                if (pg.path == opts.cwd) return true;
            return false;
        }();
        if (!cwd_granted && (resolved_preset == "offline" ||
                             resolved_preset == "fetch"   ||
                             resolved_preset == "run")) {
            opts.paths.push_back({opts.cwd, "read-write",
                                  sec::GrantPropagation::ImmediateFiles, false});
        }
    }

    // ── Individual CLI flags override everything ──────────────────────────────
    if (!moniker_u8.empty())    opts.moniker         = moniker_u8;
    if (lpac)                   opts.lpac            = true;
    if (no_win32k)              opts.noWin32k        = true;
    if (no_child_process)       opts.noChildProcess  = true;
    if (!capabilities.empty() && !caps_used_as_preset_override) {
        // Append caps to whatever the preset set (or empty for no-preset launch).
        // Exception: "self" preset caps were already consumed as capsOverride above.
        for (const auto& c : capabilities)
            opts.capabilities.push_back(c);
    }
    if (retain)                 opts.retain          = true;
    if (timeout_ms != 10000 || opts.timeoutMs == 10000) opts.timeoutMs = timeout_ms;

    // --exe wins over config "run" + "args".
    if (!exe_u8.empty()) {
        opts.run  = exe_u8;
        opts.args = {};
    }

    SBLOG_INFO("sandbox.launch: moniker=" + opts.moniker +
               " lpac=" + (opts.lpac ? "true" : "false") +
               " exe=" + opts.run);

    auto& ac = sandbox_backend();
    const sec::SandboxResult res = ac.spawn(opts);

    // ok=true here means "process was successfully spawned" (mirrors original behavior).
    // Exit code / timedOut are reported as separate fields; callers check those.
    // Derive the distDir reflected in output from binDir (for "self" preset info).
    std::string out_dist_dir;
    if (!bin_dir.empty()) {
        try {
            out_dist_dir = fs::path(bin_dir).parent_path().generic_string();
        } catch (...) {}
    }
    json out{
        {"ok", res.launched},
        {"function", "sandbox.launch"},
        {"moniker", opts.moniker},
        {"exe", opts.run},
        {"lpac", opts.lpac},
        {"noWin32k", opts.noWin32k},
        {"noChildProcess", opts.noChildProcess},
        {"capabilities", opts.capabilities},
        {"preset", resolved_preset},
        {"binDir", bin_dir},
        {"distDir", out_dist_dir},
        {"userPaths", user_paths},
        {"profileCreated", res.profileCreated},
        {"containerSid", res.containerSid},
        {"stdout", res.stdoutText},
        {"stderr", res.stderrText},
    };
    if (!res.scratchDir.empty())
        out["scratchDir"] = res.scratchDir;
    if (!res.grantedPaths.empty()) {
        json arr = json::array();
        for (const auto& g : res.grantedPaths)
            arr.push_back({{"path", g.path}, {"access", g.access},
                           {"ok", g.ok}, {"error", g.error}});
        out["grantedPaths"] = arr;
    }
    if (res.launched) {
        out["pid"]      = static_cast<int>(res.pid);
        out["timedOut"] = res.timedOut;
        if (!res.timedOut) out["exitCode"] = res.exitCode;
        SBLOG_INFO("sandbox.launch: " +
                   (res.timedOut ? "timed out" : "exited exitCode=" + std::to_string(res.exitCode)));
    } else if (!res.error.empty()) {
        out["error"] = res.error;
        SBLOG_ERROR("sandbox.launch: " + res.error);
    }
    if (!res.revokedPaths.empty()) {
        json arr = json::array();
        for (const auto& r : res.revokedPaths)
            arr.push_back({{"path", r.path}, {"ok", r.ok}, {"error", r.error}});
        out["revokedPaths"] = arr;
    }
    if (!opts.retain) out["profileDeleted"] = true;
    else              out["retained"]       = true;
    emit(out);
}

// ── sandbox wrap-mcp ──────────────────────────────────────────────────────────
//
// Simulates wrapping an MCP tool call inside an AppContainer. Checks whether
// the target path's DACL already covers the container SID ("shared folder").
// On miss, synthesizes a PrivilegeEscalationRequest — the signal the broker
// would receive from the sandboxed worker and route through
// SecurityGateway::authorizeWithConsent().

void cmd_sandbox_wrap_mcp(const std::string& moniker,
                          const std::string& tool,
                          const std::string& action,
                          const std::string& path_u8,
                          bool lpac,
                          bool retain) {
    SBLOG_INFO("sandbox.wrap-mcp: tool=" + tool + " action=" + action +
               " path=" + path_u8 + " lpac=" + (lpac ? "true" : "false"));
    auto& ac = sandbox_backend();
    const std::string sid_str = ac.containerSid(moniker);
    if (sid_str.empty()) {
        SBLOG_ERROR("sandbox.wrap-mcp: profile setup failed rc=" + std::to_string(ac.lastError()));
        emit(err_json("sandbox.wrap-mcp",
            "profile setup failed (Win32 " + std::to_string(ac.lastError()) + ")"));
        return;
    }
    SBLOG_DEBUG("sandbox.wrap-mcp: profile ensured sid=" + sid_str);
    SBLOG_DEBUG("sandbox.wrap-mcp: checking ACL path=" + path_u8);
    const bool acl_granted   = ac.checkAccess(moniker, path_u8);
    const bool access_denied = !acl_granted;
    SBLOG_INFO("sandbox.wrap-mcp: aclGranted=" + std::string(acl_granted ? "true" : "false") +
               (access_denied ? " -> emitting PrivilegeEscalationRequest" : " -> access allowed"));

    json out{
        {"ok", !access_denied},
        {"function", "sandbox.wrap-mcp"},
        {"moniker", moniker},
        {"tool", tool},
        {"action", action},
        {"path", path_u8},
        {"lpac", lpac},
        {"containerSid", sid_str},
        {"aclGranted", acl_granted},
        {"accessDenied", access_denied},
    };

    if (access_denied) {
        const std::string fix = "sandbox acl --moniker " + moniker +
                                " --path <workspace-root> --access " +
                                (action == "write" ? "read-write" : "read");
        out["privilegeEscalationRequest"] = {
            {"tool", tool},
            {"action", action},
            {"path", path_u8},
            {"containerSid", sid_str},
            {"lpac", lpac},
            {"reason", "path not covered by AppContainer ACL grant (no shared-folder entry)"},
            {"callSite", "sandbox.wrap-mcp -> SecurityGateway::authorizeWithConsent()"},
            {"suggestedFix", fix},
        };
        SBLOG_DEBUG("sandbox.wrap-mcp: ipc-sim -> privilege_escalation "
                    "{ tool:" + tool + " action:" + action + " path:" + path_u8 + " }");
    }

    if (!retain) {
        ac.deleteProfile(moniker);
        out["profileDeleted"] = true;
    }
    emit(out);
}

#endif // FEATURE_SECURITY_SANDBOX && _WIN32

// ── gpo ────────────────────────────────────────────────────────────────────────

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO

void cmd_gpo_effective(bool set_only) {
    const auto policy = pm::policy::make_default_policy();
    const auto& keys  = pm::policy::known_policy_keys();
    const auto effective = policy.dump_json(keys);

    // "set" = only the keys explicitly configured via GPO (registry), i.e.
    // whose value did not come from the compiled-in "builtin" defaults.
    json set = json::object();
    for (const auto& [k, v] : effective.items()) {
        if (v.value("source", "builtin") != "builtin")
            set[k] = v;
    }

    json out;
    out["ok"]  = true;
    out["set"] = set;
    // Omit the full policy dump when --set-only is requested to keep output short.
    if (!set_only)
        out["policy"] = effective;
    emit(out);
}

void cmd_gpo_read(const std::string& hive_str) {
    const bool do_hkcu = (hive_str == "hkcu" || hive_str == "both");
    const bool do_hklm = (hive_str == "hklm" || hive_str == "both");

    json out;
    out["ok"] = true;

    if (do_hkcu) {
        pm::policy::RegistryPolicyProvider hkcu(pm::policy::RegistryHive::HKCU);
        out["hkcu"]["present"] = hkcu.is_present();
        out["hkcu"]["values"]  = hkcu.read_all_json();
    }
    if (do_hklm) {
        pm::policy::RegistryPolicyProvider hklm(pm::policy::RegistryHive::HKLM);
        out["hklm"]["present"] = hklm.is_present();
        out["hklm"]["values"]  = hklm.read_all_json();
    }
    emit(out);
}

void cmd_gpo_list_tools() {
    const auto policy = pm::policy::make_default_policy();

    // Tool names derived from Agent.Tools.Enable* keys.
    static const std::vector<std::pair<std::string, std::string>> k_tools = {
        {"run",             "Agent.Tools.EnableRun"},
        {"run_sequence",    "Agent.Tools.EnableRunSequence"},
        {"write_file",      "Agent.Tools.EnableWriteFile"},
        {"file_str_replace","Agent.Tools.EnableFileStrReplace"},
        {"file_delete",     "Agent.Tools.EnableFileDelete"},
        {"create_command",  "Agent.Tools.EnableCreateCommand"},
        {"computer_group",  "Agent.Tools.EnableComputerGroup"},
        {"app_commands",    "Agent.Tools.EnableAppCommands"},
        {"network_group",   "Agent.Tools.EnableNetworkGroup"},
        {"scheduler",       "Agent.Tools.EnableScheduler"},
        {"memory",          "Agent.Tools.EnableMemory"},
    };

    const auto block_list  = policy.get_multi_or("Agent.Tools.BlockList");
    const auto allow_list  = policy.get_multi_or("Agent.Tools.AllowList");
    const bool has_allowlist = !allow_list.empty();

    json tools = json::array();
    for (const auto& [name, key] : k_tools) {
        const bool in_blocklist = std::find(block_list.begin(), block_list.end(), name)
                                  != block_list.end();
        const bool in_allowlist = std::find(allow_list.begin(), allow_list.end(), name)
                                  != allow_list.end();
        const bool flag_enabled = policy.is_enabled(key, true);

        // Disable if: flag OFF, in blocklist, or (allowlist non-empty and not in allowlist).
        bool enabled = flag_enabled && !in_blocklist;
        if (has_allowlist) enabled = enabled && in_allowlist;

        std::string source = "builtin";
        if (const auto ws = policy.get_int_with_source(key)) source = ws->source;

        json t;
        t["name"]         = name;
        t["policy_key"]   = key;
        t["enabled"]      = enabled;
        t["policy_source"] = source;
        if (in_blocklist)  t["blocklisted"] = true;
        if (has_allowlist) t["allowlisted"]  = in_allowlist;
        tools.push_back(t);
    }

    json out;
    out["ok"]    = true;
    out["tools"] = tools;
    emit(out);
}

#endif // FEATURE_WINDOWS_GPO

// ── antihack — runtime tamper telemetry probes ───────────────────────────────
#if FEATURE_ANTI_HACKING
namespace ah = pm::security::antihack;

json antihack_signal_json(const ah::Signal& s) {
    json j;
    j["category"] = ah::to_string(s.category);
    j["name"]     = s.name;
    j["detected"] = s.detected;
    j["severity"] = ah::to_string(s.severity);
    if (!s.detail.empty()) j["detail"] = s.detail;
    if (!s.locus.empty())  j["locus"]  = s.locus;
    return j;
}

json antihack_report_json(const ah::Report& rep) {
    json sigs = json::array();
    for (const auto& s : rep.signals)
        sigs.push_back(antihack_signal_json(s));

    json counters;
    counters["debugger"] = rep.debugger_detected;
    counters["dll_hook"] = rep.dll_hook_detected;
    counters["module"]   = rep.module_detected;
    counters["memory"]   = rep.memory_detected;

    json out;
    out["ok"]            = true;
    out["available"]    = ah::available();
    out["anyDetected"]  = rep.any_detected();
    out["detectedCount"] = rep.detected_count();
    out["maxSeverity"]  = ah::to_string(rep.max_severity());
    out["modulesTotal"] = rep.modules_total;
    out["counters"]     = counters;
    out["signals"]      = sigs;
    return out;
}

void cmd_antihack(const ah::ScanOptions& opts) {
    emit(antihack_report_json(ah::run(opts)));
}
#endif // FEATURE_ANTI_HACKING

} // namespace

int main(int argc, char** argv) {
    // pm-media-security is a static library. Without this call the linker drops
    // commons_host.cpp and every settings load/save reports "not installed".
    pm::commons::host::install_process_hooks();

    // Route all pm::log / spdlog output to stderr so it never contaminates the
    // JSON-over-stdout protocol used by the test orchestrator. "trace" gives
    // maximum visibility into gateway decisions during development.
    logger::init_stderr("sec-cli", "trace");

    CLI::App app{std::string(pm::brand::k_exe_basename_security_u8) + " — local tool-call security gateway test CLI"};
    app.set_version_flag("-v,--version", std::string(pm::version::cli_string()));
    app.require_subcommand(1);

    app.add_flag("--json", g_json, "Emit compact machine-readable JSON (default: pretty).");
    app.add_option("--profile", g_profile, "Security profile: LIGHT, STRICT, DEVELOPER.")
        ->check(CLI::IsMember({"LIGHT", "STRICT", "DEVELOPER"}, CLI::ignore_case));
    app.add_option("--config-dir", g_config_dir,
                   "Profile/settings root override (isolates the settings store for tests).");
    app.add_option("--app-name", g_app_name, "App id for the security storage path (default pm-image).");
    app.add_option("--origin", g_origin, "Calling binary for provenance (e.g. tanit.exe, pm-image-cli.exe).");
    app.add_option("--session", g_session, "Session id (binds Session-lifetime grants).");
    app.add_option("--task", g_task, "Task id (binds Task-lifetime grants).");
    app.add_option("--lang", g_lang, "Consent UI language for --gui (en, de, es, fr, it); overrides the settings store.");
    app.add_flag("--dark", g_dark, "Use the dark consent UI theme for --gui.");
    app.add_option("--log-level", g_log_lvl,
                   "Sandbox log verbosity: none|error|info|debug (default: none).\n"
                   "Logs go to --log-file when specified, otherwise to stderr.\n"
                   "Covers: profile lifecycle, ACL grant/revoke, process spawn, IPC sim.")
        ->transform(CLI::CheckedTransformer(
            std::map<std::string, SbLog>{
                {"none",  SbLog::None},
                {"error", SbLog::Error},
                {"info",  SbLog::Info},
                {"debug", SbLog::Debug},
            }, CLI::ignore_case));
    app.add_option("--log-file", g_log_file,
                   "Write sandbox log to this file (append). "
                   "Omit to write to stderr when --log-level > none.");
    app.add_option("--storage", g_storage,
                   "Grant persistence backend.\n"
                   "  settings-store  Encrypted settings.json[\"permissions\"] (default).\n"
                   "  grants.json     Plain human-readable <config-dir>/grants.json file.")
        ->check(CLI::IsMember({"settings-store", "grants.json"}));

    static const std::vector<std::string> k_actions = {
        "read", "write", "delete", "execute", "network", "upload", "download", "git_push", "publish"};
    static const std::vector<std::string> k_actors = {
        "user", "llm", "plugin", "mcp_server", "background_agent"};

    // profile / set-profile
    app.add_subcommand("profile", "Print compiled + persisted security profile.")
        ->callback([] { cmd_profile(); });
    app.add_subcommand("set-profile", "Persist --profile as the active profile.")
        ->callback([] { cmd_set_profile(); });

    // path probes
    {
        auto* path_cmd = app.add_subcommand("path", "PathSecurity canonicalization / containment / glob probes.");
        path_cmd->require_subcommand(1);

        auto* canon = path_cmd->add_subcommand("canonicalize", "Canonicalize --path.");
        auto canon_path = std::make_shared<std::string>();
        canon->add_option("--path", *canon_path, "Path to canonicalize.")->required();
        canon->callback([canon_path] { cmd_path_canonicalize(*canon_path); });

        auto* inside = path_cmd->add_subcommand("inside", "Test whether --path is inside --root.");
        auto inside_path = std::make_shared<std::string>();
        auto inside_root = std::make_shared<std::string>();
        inside->add_option("--path", *inside_path, "Child path.")->required();
        inside->add_option("--root", *inside_root, "Root path.")->required();
        inside->callback([inside_path, inside_root] { cmd_path_inside(*inside_path, *inside_root); });

        auto* glob = path_cmd->add_subcommand("glob", "Match --path against glob --pattern.");
        auto glob_path = std::make_shared<std::string>();
        auto glob_pat = std::make_shared<std::string>();
        glob->add_option("--path", *glob_path, "Path to match.")->required();
        glob->add_option("--pattern", *glob_pat, "Glob pattern (**, *, ?).")->required();
        glob->callback([glob_path, glob_pat] { cmd_path_glob(*glob_path, *glob_pat); });
    }

    // identity
    {
        auto* cmd = app.add_subcommand("identity", "Tool identity / hash probes.");
        cmd->require_subcommand(1);

        auto* hash_file = cmd->add_subcommand("hash-file", "Compute SHA-256 for a file.");
        auto path = std::make_shared<std::string>();
        hash_file->add_option("--path", *path, "File to hash.")->required();
        hash_file->callback([path] { cmd_identity_hash_file(*path); });
    }

    // classify
    {
        auto* cmd = app.add_subcommand("classify", "Classify a resource target for an action.");
        auto path = std::make_shared<std::string>();
        auto action = std::make_shared<std::string>("read");
        auto workspace = std::make_shared<std::string>();
        auto uri = std::make_shared<std::string>();
        cmd->add_option("--path", *path, "Resource path.");
        cmd->add_option("--uri", *uri, "Resource URI (alternative to --path).");
        cmd->add_option("--action", *action, "Action.")->check(CLI::IsMember(k_actions));
        cmd->add_option("--workspace", *workspace, "Workspace root (drives outside-workspace signal).");
        cmd->callback([path, action, workspace, uri] {
            cmd_classify(*path, sec::persist::parse_action(*action).value_or(sec::Action::Read),
                         *workspace, *uri);
        });
    }

    // authorize
    {
        auto* cmd = app.add_subcommand("authorize", "Run the full gateway authorization for a request.");
        auto tool = std::make_shared<std::string>("file.read");
        auto provider = std::make_shared<std::string>("builtin");
        auto actor = std::make_shared<std::string>("llm");
        auto action = std::make_shared<std::string>("read");
        auto path = std::make_shared<std::string>();
        auto workspace = std::make_shared<std::string>();
        auto intent = std::make_shared<std::string>();
        auto use_grants = std::make_shared<bool>(false);
        auto signed_manifest = std::make_shared<bool>(false);
        auto executable_hash = std::make_shared<std::string>();
        auto manifest_hash = std::make_shared<std::string>();
        auto server = std::make_shared<std::string>();
        auto uri = std::make_shared<std::string>();
        cmd->add_option("--tool", *tool, "Tool id (e.g. file.read, shell.exec).");
        cmd->add_option("--provider", *provider, "builtin | plugin | mcp.");
        cmd->add_option("--server", *server, "MCP/plugin server id (empty for builtin).");
        cmd->add_option("--actor", *actor, "Actor.")->check(CLI::IsMember(k_actors));
        cmd->add_option("--action", *action, "Action.")->check(CLI::IsMember(k_actions));
        cmd->add_option("--path", *path, "Target resource path.");
        cmd->add_option("--uri", *uri, "Target resource URI (file/https/ftp/ws...). Overrides path for non-file resources.");
        cmd->add_option("--workspace", *workspace, "Workspace root.");
        cmd->add_option("--intent", *intent, "User-visible intent string.");
        auto interactive = std::make_shared<bool>(false);
        auto gui = std::make_shared<bool>(false);
        cmd->add_flag("--use-grants", *use_grants, "Load persisted grants before deciding.");
        cmd->add_flag("--interactive", *interactive,
                      "Act as the consent UI: on Ask, prompt on stderr and read a choice from stdin.");
        cmd->add_flag("--gui", *gui,
                      "With --interactive: show the native Win32 consent dialog instead of stdio.");
        cmd->add_flag("--signed", *signed_manifest, "Mark the tool manifest as signed.");
        cmd->add_option("--executable-hash", *executable_hash,
                        "Bound executable hash for grant invalidation.");
        cmd->add_option("--manifest-hash", *manifest_hash,
                        "Bound manifest hash (STRICT registered-signed requires non-empty).");
        cmd->callback([=] {
            apply_config_dir();
            const sec::ToolRequest req = build_request(
                *tool, *provider, sec::persist::parse_actor(*actor).value_or(sec::Actor::LLM),
                sec::persist::parse_action(*action).value_or(sec::Action::Read),
                *path, *workspace, *intent, *signed_manifest,
                *executable_hash, *manifest_hash, *server, *uri);
            cmd_authorize(req, *use_grants, *interactive, *gui);
        });
    }

    // grant
    {
        auto* grant_cmd = app.add_subcommand("grant", "Capability grant store (settings-backed).");
        grant_cmd->require_subcommand(1);

        auto* add = grant_cmd->add_subcommand("add", "Persist a capability grant.");
        auto g_id = std::make_shared<std::string>();
        auto g_tool = std::make_shared<std::string>("file.read");
        auto g_provider = std::make_shared<std::string>("builtin");
        auto g_subject = std::make_shared<std::string>("user");
        auto g_action = std::make_shared<std::string>("read");
        auto g_scopes = std::make_shared<std::vector<std::string>>();
        auto g_server = std::make_shared<std::string>();
        auto g_lifetime = std::make_shared<std::string>("session");
        auto g_session_id = std::make_shared<std::string>();
        auto g_task_id = std::make_shared<std::string>();
        auto g_workspace = std::make_shared<std::string>();
        auto g_reason = std::make_shared<std::string>();
        auto g_allow_secrets = std::make_shared<bool>(false);
        auto g_allow_network = std::make_shared<bool>(false);
        auto g_sandbox_backend = std::make_shared<std::string>();
        auto g_signed_manifest = std::make_shared<bool>(false);
        auto g_executable_hash = std::make_shared<std::string>();
        auto g_manifest_hash = std::make_shared<std::string>();
        add->add_option("--id", *g_id, "Grant id (generated when omitted).");
        add->add_option("--tool", *g_tool, "Tool id (supports * / ? wildcards).");
        add->add_option("--provider", *g_provider, "Provider (supports wildcards).");
        add->add_option("--server", *g_server, "MCP/plugin server id (supports wildcards; empty = any).");
        add->add_option("--subject", *g_subject, "Subject (user/session/agent/mcp id).");
        add->add_option("--action", *g_action, "Action.")->check(CLI::IsMember(k_actions));
        add->add_option("--scope", *g_scopes, "Resource scope: URI pattern or path glob (repeatable).");
        add->add_option("--lifetime", *g_lifetime, "once|session|task|until_timestamp|permanent.")
            ->check(CLI::IsMember({"once", "session", "task", "until_timestamp", "permanent"}));
        add->add_option("--bind-session", *g_session_id, "Bind this grant to a session id.");
        add->add_option("--bind-task", *g_task_id, "Bind this grant to a task id.");
        add->add_option("--workspace", *g_workspace, "Workspace id/root.");
        add->add_option("--reason", *g_reason, "Why this grant exists.");
        add->add_flag("--allow-secrets", *g_allow_secrets, "Permit secret-classified resources.");
        add->add_flag("--allow-network", *g_allow_network, "Permit network egress.");
        add->add_flag("--signed", *g_signed_manifest, "Mark the bound tool manifest as signed.");
        add->add_option("--executable-hash", *g_executable_hash, "Bind grant to an executable hash.");
        add->add_option("--manifest-hash", *g_manifest_hash, "Bind grant to a manifest/config hash.");
        add->add_option("--sandbox-backend", *g_sandbox_backend,
            "Require this grant to run inside the named sandbox backend "
            "(e.g. appcontainer). Surfaces as PolicyDecision.sandboxBackend.");
        add->callback([=] {
            sec::CapabilityGrant g;
            g.id = *g_id;
            g.subject = *g_subject;
            g.tool.toolId = *g_tool;
            g.tool.provider = *g_provider;
            g.tool.serverId = *g_server;
            g.tool.signedManifest = *g_signed_manifest;
            g.tool.executableHash = *g_executable_hash;
            g.tool.manifestHash = *g_manifest_hash;
            g.action = sec::persist::parse_action(*g_action).value_or(sec::Action::Read);
            g.resourceScopes = *g_scopes;
            g.lifetime = sec::persist::parse_lifetime(*g_lifetime).value_or(sec::GrantLifetime::Session);
            g.sessionId = *g_session_id;
            g.taskId = *g_task_id;
            g.workspaceId = *g_workspace;
            g.reason = *g_reason;
            g.allowSecrets = *g_allow_secrets;
            g.allowNetwork = *g_allow_network;
            g.sandboxBackend = *g_sandbox_backend;
            g.readOnly = (g.action == sec::Action::Read);
            cmd_grant_add(std::move(g));
        });

        grant_cmd->add_subcommand("list", "List persisted grants.")
            ->callback([] { cmd_grant_list(); });

        auto* find = grant_cmd->add_subcommand("find", "Find a live grant covering a request.");
        auto f_tool = std::make_shared<std::string>("file.read");
        auto f_provider = std::make_shared<std::string>("builtin");
        auto f_server = std::make_shared<std::string>();
        auto f_action = std::make_shared<std::string>("read");
        auto f_path = std::make_shared<std::string>();
        auto f_uri = std::make_shared<std::string>();
        auto f_workspace = std::make_shared<std::string>();
        auto f_signed_manifest = std::make_shared<bool>(false);
        auto f_executable_hash = std::make_shared<std::string>();
        auto f_manifest_hash = std::make_shared<std::string>();
        find->add_option("--tool", *f_tool, "Tool id.");
        find->add_option("--provider", *f_provider, "Provider.");
        find->add_option("--server", *f_server, "MCP/plugin server id.");
        find->add_option("--action", *f_action, "Action.")->check(CLI::IsMember(k_actions));
        find->add_option("--path", *f_path, "Target path.");
        find->add_option("--uri", *f_uri, "Target URI (non-file resources).");
        find->add_option("--workspace", *f_workspace, "Workspace root.");
        find->add_flag("--signed", *f_signed_manifest, "Mark the request manifest as signed.");
        find->add_option("--executable-hash", *f_executable_hash, "Request executable hash.");
        find->add_option("--manifest-hash", *f_manifest_hash, "Request manifest/config hash.");
        find->callback([=] {
            apply_config_dir();
            const sec::ToolRequest req = build_request(
                *f_tool, *f_provider, sec::Actor::LLM,
                sec::persist::parse_action(*f_action).value_or(sec::Action::Read),
                *f_path, *f_workspace, "", *f_signed_manifest,
                *f_executable_hash, *f_manifest_hash, *f_server, *f_uri);
            cmd_grant_find(req);
        });

        auto* revoke = grant_cmd->add_subcommand("revoke", "Revoke a grant by id.");
        auto r_id = std::make_shared<std::string>();
        revoke->add_option("--id", *r_id, "Grant id.")->required();
        revoke->callback([r_id] { cmd_grant_revoke(*r_id); });

        auto* import_cmd = grant_cmd->add_subcommand("import",
            "Merge (or replace) grants from a plain JSON file into the active store.\n"
            "The file must be a JSON array of CapabilityGrant objects (same format as\n"
            "--storage grants.json). Each grant is validated before it is accepted:\n"
            "  - must have at least one resource scope (no ambient authority)\n"
            "  - action must not be never_persistable (Execute/Delete/GitPush/...)\n"
            "  - permanent lifetime is only allowed for Read\n"
            "Use --replace to overwrite the store instead of merging.");
        auto import_file = std::make_shared<std::string>();
        auto import_replace = std::make_shared<bool>(false);
        import_cmd->add_option("--file", *import_file,
            "Path to the grants JSON file to import.")->required();
        import_cmd->add_flag("--replace", *import_replace,
            "Replace the entire active store instead of merging.");
        import_cmd->callback([import_file, import_replace] {
            cmd_grant_import(fs::path(*import_file), *import_replace);
        });
    }

    // crypto
    {
        auto* cmd = app.add_subcommand("crypto", "CryptoStore probes.");
        cmd->require_subcommand(1);
        auto* rt = cmd->add_subcommand("roundtrip", "Encrypt then decrypt --text.");
        auto text = std::make_shared<std::string>("the quick brown fox");
        rt->add_option("--text", *text, "Plaintext to round-trip.");
        rt->callback([text] { cmd_crypto_roundtrip(*text); });
    }

    // secure resource storage
    {
        auto* cmd = app.add_subcommand("storage", "Secure resource storage probes.");
        cmd->require_subcommand(1);

        auto* put = cmd->add_subcommand("put", "Store a file as a pm:// resource.");
        auto uri = std::make_shared<std::string>();
        auto file = std::make_shared<std::string>();
        auto type = std::make_shared<std::string>("prompt-template");
        auto trust = std::make_shared<std::string>("user-local");
        auto version = std::make_shared<std::string>("1");
        auto provider = std::make_shared<std::string>("user");
        auto signer = std::make_shared<std::string>();
        auto bundle = std::make_shared<std::string>("local");
        put->add_option("--uri", *uri, "Resource URI, e.g. pm://config/prompts/system-prompt.md.")->required();
        put->add_option("--file", *file, "File to store.")->required();
        put->add_option("--type", *type, "prompt-template | command-config | mcp-config | prompt | page | settings-profile | web-app-bundle | asset-archive.")
            ->check(CLI::IsMember({"prompt-template", "command-config", "mcp-config", "prompt", "page", "settings-profile", "web-app-bundle", "asset-archive"}));
        put->add_option("--trust", *trust, "builtin | signed-vendor | user-local | peer-signed | workspace | untrusted.")
            ->check(CLI::IsMember({"builtin", "signed-vendor", "user-local", "peer-signed", "workspace", "untrusted"}));
        put->add_option("--version", *version, "Resource version token.");
        put->add_option("--provider", *provider, "Provider id.");
        put->add_option("--signer", *signer, "Signer id/fingerprint.");
        put->add_option("--bundle", *bundle, "Bundle id.");
        put->callback([=] {
            cmd_storage_put(*uri, *file, *type, *trust, *version, *provider, *signer, *bundle);
        });

        auto* get = cmd->add_subcommand("get", "Load a resource by URI.");
        auto get_uri = std::make_shared<std::string>();
        get->add_option("--uri", *get_uri, "Resource URI.")->required();
        get->callback([get_uri] { cmd_storage_get(*get_uri); });

        cmd->add_subcommand("list", "List indexed resources.")
            ->callback([] { cmd_storage_list(); });

        auto* verify = cmd->add_subcommand("verify", "Verify a resource digest by URI.");
        auto verify_uri = std::make_shared<std::string>();
        verify->add_option("--uri", *verify_uri, "Resource URI.")->required();
        verify->callback([verify_uri] { cmd_storage_verify(*verify_uri); });

        auto* sign = cmd->add_subcommand("sign", "Sign a resource manifest by URI.");
        auto sign_uri = std::make_shared<std::string>();
        sign->add_option("--uri", *sign_uri, "Resource URI.")->required();
        sign->callback([sign_uri] { cmd_storage_sign(*sign_uri); });

        auto* import_pkg = cmd->add_subcommand("import", "Import a single-resource .pmbundle JSON package.");
        auto import_file = std::make_shared<std::string>();
        import_pkg->add_option("--file", *import_file, "Package file to import.")->required();
        import_pkg->callback([import_file] { cmd_storage_import(*import_file); });

        auto* export_pkg = cmd->add_subcommand("export", "Export a single-resource .pmbundle JSON package.");
        auto export_uri = std::make_shared<std::string>();
        auto export_file = std::make_shared<std::string>();
        export_pkg->add_option("--uri", *export_uri, "Resource URI.")->required();
        export_pkg->add_option("--file", *export_file, "Package file to write.")->required();
        export_pkg->callback([export_uri, export_file] { cmd_storage_export(*export_uri, *export_file); });

        // ── all-in-one web app bundle (store-only zip; PhysFS-mountable) ──
        auto* bundle_cmd = cmd->add_subcommand("bundle", "All-in-one web app bundle (*.pmbundle) probes.");
        bundle_cmd->require_subcommand(1);

        auto* b_pack = bundle_cmd->add_subcommand("pack", "Pack a directory into an all-in-one *.pmbundle archive.");
        auto b_pack_dir = std::make_shared<std::string>();
        auto b_pack_file = std::make_shared<std::string>();
        b_pack->add_option("--dir", *b_pack_dir, "Source directory (the built web app).")->required();
        b_pack->add_option("--file", *b_pack_file, "Output .pmbundle file.")->required();
        b_pack->callback([b_pack_dir, b_pack_file] { cmd_storage_bundle_pack(*b_pack_dir, *b_pack_file); });

        auto* b_sign = bundle_cmd->add_subcommand("sign", "Sign a *.pmbundle with an Ed25519 seed (detached <file>.sig).");
        auto b_sign_file = std::make_shared<std::string>();
        auto b_sign_seed = std::make_shared<std::string>();
        auto b_sign_out  = std::make_shared<std::string>();
        b_sign->add_option("--file", *b_sign_file, "Bundle to sign.")->required();
        b_sign->add_option("--seed-hex", *b_sign_seed, "32-byte Ed25519 seed (hex). Defaults to $PM_BUNDLE_SIGNING_SEED_HEX.");
        b_sign->add_option("--out", *b_sign_out, "Output signature path (default: <file>.sig).");
        b_sign->callback([b_sign_file, b_sign_seed, b_sign_out] {
            cmd_storage_bundle_sign(*b_sign_file, *b_sign_seed, *b_sign_out);
        });

        auto* b_verify = bundle_cmd->add_subcommand("verify-file", "Verify a *.pmbundle against the pinned signing key.");
        auto b_verify_file = std::make_shared<std::string>();
        auto b_verify_sig  = std::make_shared<std::string>();
        b_verify->add_option("--file", *b_verify_file, "Bundle to verify.")->required();
        b_verify->add_option("--sig", *b_verify_sig, "Signature path (default: <file>.sig).");
        b_verify->callback([b_verify_file, b_verify_sig] {
            cmd_storage_bundle_verify_file(*b_verify_file, *b_verify_sig);
        });

        auto* b_list = bundle_cmd->add_subcommand("list", "List entries in a bundle (--uri verifies storage, --file reads raw).");
        auto b_list_uri = std::make_shared<std::string>();
        auto b_list_file = std::make_shared<std::string>();
        b_list->add_option("--uri", *b_list_uri, "Stored bundle resource URI (verified).");
        b_list->add_option("--file", *b_list_file, "Raw .pmbundle file (unverified).");
        b_list->callback([b_list_uri, b_list_file] { cmd_storage_bundle_list(*b_list_uri, *b_list_file); });

        auto* b_serve = bundle_cmd->add_subcommand("serve", "Resolve one request path inside a bundle (emulates a web engine request).");
        auto b_serve_uri = std::make_shared<std::string>();
        auto b_serve_file = std::make_shared<std::string>();
        auto b_serve_path = std::make_shared<std::string>();
        b_serve->add_option("--uri", *b_serve_uri, "Stored bundle resource URI (verified before serve).");
        b_serve->add_option("--file", *b_serve_file, "Raw .pmbundle file (unverified).");
        b_serve->add_option("--path", *b_serve_path, "Request path inside the bundle, e.g. /index.html.")->required();
        b_serve->callback([b_serve_uri, b_serve_file, b_serve_path] {
            cmd_storage_bundle_serve(*b_serve_uri, *b_serve_file, *b_serve_path);
        });

        auto* b_unpack = bundle_cmd->add_subcommand("unpack", "Extract a bundle to a directory (--uri verifies storage).");
        auto b_unpack_uri = std::make_shared<std::string>();
        auto b_unpack_file = std::make_shared<std::string>();
        auto b_unpack_out = std::make_shared<std::string>();
        b_unpack->add_option("--uri", *b_unpack_uri, "Stored bundle resource URI (verified).");
        b_unpack->add_option("--file", *b_unpack_file, "Raw .pmbundle file (unverified).");
        b_unpack->add_option("--out", *b_unpack_out, "Output directory.")->required();
        b_unpack->callback([b_unpack_uri, b_unpack_file, b_unpack_out] {
            cmd_storage_bundle_unpack(*b_unpack_uri, *b_unpack_file, *b_unpack_out);
        });

        auto* doc = cmd->add_subcommand("doc", "Named secure document probes.");
        doc->require_subcommand(1);

        auto* doc_put = doc->add_subcommand("put", "Store a file as a named secure document.");
        auto doc_put_uri = std::make_shared<std::string>();
        auto doc_put_file = std::make_shared<std::string>();
        auto doc_put_type = std::make_shared<std::string>("settings-profile");
        auto doc_put_trust = std::make_shared<std::string>("user-local");
        auto doc_put_version = std::make_shared<std::string>("1");
        auto doc_put_provider = std::make_shared<std::string>("user");
        auto doc_put_signer = std::make_shared<std::string>();
        auto doc_put_no_encrypt = std::make_shared<bool>(false);
        auto doc_put_encrypt = std::make_shared<bool>(false);
        auto doc_put_seed_plaintext = std::make_shared<bool>(false);
        doc_put->add_option("--uri", *doc_put_uri, "Document URI.")->required();
        doc_put->add_option("--file", *doc_put_file, "File to store.")->required();
        doc_put->add_option("--type", *doc_put_type, "settings-profile | oauth-credentials | command-config | mcp-config | prompt-template | prompt | page.")
            ->check(CLI::IsMember({"settings-profile", "oauth-credentials", "command-config", "mcp-config", "prompt-template", "prompt", "page"}));
        doc_put->add_option("--trust", *doc_put_trust, "builtin | signed-vendor | user-local | peer-signed | workspace | untrusted.")
            ->check(CLI::IsMember({"builtin", "signed-vendor", "user-local", "peer-signed", "workspace", "untrusted"}));
        doc_put->add_option("--version", *doc_put_version, "Document version token.");
        doc_put->add_option("--provider", *doc_put_provider, "Provider id.");
        doc_put->add_option("--signer", *doc_put_signer, "Signer id/fingerprint.");
        doc_put->add_flag("--encrypt", *doc_put_encrypt, "Encrypt document bytes (default; explicit for scripts).");
        doc_put->add_flag("--no-encrypt", *doc_put_no_encrypt, "Store plaintext document bytes (requires --seed-plaintext).");
        doc_put->add_flag("--seed-plaintext", *doc_put_seed_plaintext, "Allow plaintext signed vendor seed documents.");
        doc_put->callback([=] {
            if (*doc_put_no_encrypt) {
                if (*doc_put_type == "oauth-credentials") {
                    emit(err_json("storage.doc.put", "oauth credential documents must be encrypted"));
                    return;
                }
                if (*doc_put_type == "settings-profile") {
                    emit(err_json("storage.doc.put", "settings profile documents must be encrypted"));
                    return;
                }
                if (!*doc_put_seed_plaintext) {
                    emit(err_json("storage.doc.put", "--no-encrypt requires --seed-plaintext"));
                    return;
                }
            }
            cmd_storage_doc_put(*doc_put_uri,
                                *doc_put_file,
                                *doc_put_type,
                                *doc_put_trust,
                                *doc_put_version,
                                *doc_put_provider,
                                *doc_put_signer,
                                !*doc_put_no_encrypt,
                                *doc_put_seed_plaintext);
        });

        auto* doc_import_plain = doc->add_subcommand("import-plain", "Import a plaintext settings/commands/prompt file as a secure document.");
        auto doc_import_uri = std::make_shared<std::string>();
        auto doc_import_file = std::make_shared<std::string>();
        auto doc_import_type = std::make_shared<std::string>("settings-profile");
        auto doc_import_trust = std::make_shared<std::string>("user-local");
        auto doc_import_version = std::make_shared<std::string>("1");
        auto doc_import_provider = std::make_shared<std::string>("user");
        auto doc_import_signer = std::make_shared<std::string>();
        auto doc_import_no_encrypt = std::make_shared<bool>(false);
        auto doc_import_encrypt = std::make_shared<bool>(false);
        auto doc_import_seed_plaintext = std::make_shared<bool>(false);
        auto doc_import_sign = std::make_shared<bool>(true);
        doc_import_plain->add_option("--uri", *doc_import_uri, "Document URI.")->required();
        doc_import_plain->add_option("--file", *doc_import_file, "Plain file to import.")->required();
        doc_import_plain->add_option("--type", *doc_import_type, "settings-profile | command-config | mcp-config | prompt-template | prompt | page.")
            ->check(CLI::IsMember({"settings-profile", "command-config", "mcp-config", "prompt-template", "prompt", "page"}));
        doc_import_plain->add_option("--trust", *doc_import_trust, "builtin | signed-vendor | user-local | peer-signed | workspace | untrusted.")
            ->check(CLI::IsMember({"builtin", "signed-vendor", "user-local", "peer-signed", "workspace", "untrusted"}));
        doc_import_plain->add_option("--version", *doc_import_version, "Document version token.");
        doc_import_plain->add_option("--provider", *doc_import_provider, "Provider id.");
        doc_import_plain->add_option("--signer", *doc_import_signer, "Signer id/fingerprint.");
        doc_import_plain->add_flag("--encrypt", *doc_import_encrypt, "Encrypt document bytes (default; explicit for scripts).");
        doc_import_plain->add_flag("--no-encrypt", *doc_import_no_encrypt, "Store plaintext document bytes (requires --seed-plaintext).");
        doc_import_plain->add_flag("--seed-plaintext", *doc_import_seed_plaintext, "Allow plaintext signed vendor seed documents.");
        doc_import_plain->add_flag("--sign,!--no-sign", *doc_import_sign, "Sign the imported document manifest.");
        doc_import_plain->callback([=] {
            if (*doc_import_no_encrypt && !*doc_import_seed_plaintext) {
                emit(err_json("storage.doc.import-plain", "--no-encrypt requires --seed-plaintext"));
                return;
            }
            cmd_storage_doc_import_plain(*doc_import_uri,
                                         *doc_import_file,
                                         *doc_import_type,
                                         *doc_import_trust,
                                         *doc_import_version,
                                         *doc_import_provider,
                                         *doc_import_signer,
                                         !*doc_import_no_encrypt,
                                         *doc_import_seed_plaintext,
                                         *doc_import_sign);
        });

        auto* doc_get = doc->add_subcommand("get", "Load a secure document by URI.");
        auto doc_get_uri = std::make_shared<std::string>();
        auto doc_get_require_signature = std::make_shared<bool>(false);
        auto doc_get_require_encryption = std::make_shared<bool>(false);
        auto doc_get_allow_vendor_seed_plaintext = std::make_shared<bool>(false);
        auto doc_get_allowed_trust = std::make_shared<std::vector<std::string>>();
        doc_get->add_option("--uri", *doc_get_uri, "Document URI.")->required();
        doc_get->add_flag("--require-signature", *doc_get_require_signature, "Reject unsigned documents.");
        doc_get->add_flag("--require-encryption", *doc_get_require_encryption, "Reject plaintext documents.");
        doc_get->add_flag("--allow-vendor-seed-plaintext", *doc_get_allow_vendor_seed_plaintext,
            "Allow plaintext builtin/signed-vendor seed documents when encryption is required.");
        doc_get->add_option("--allow-trust", *doc_get_allowed_trust,
            "Allowed trust level. Repeatable.")
            ->check(CLI::IsMember({"builtin", "signed-vendor", "user-local", "peer-signed", "workspace", "untrusted"}));
        doc_get->callback([=] {
            cmd_storage_doc_get(*doc_get_uri,
                                *doc_get_require_signature,
                                *doc_get_require_encryption,
                                *doc_get_allow_vendor_seed_plaintext,
                                *doc_get_allowed_trust);
        });

        auto* doc_export_plain = doc->add_subcommand("export-plain", "Export a secure document plaintext payload to a file.");
        auto doc_export_uri = std::make_shared<std::string>();
        auto doc_export_file = std::make_shared<std::string>();
        auto doc_export_require_signature = std::make_shared<bool>(false);
        auto doc_export_require_encryption = std::make_shared<bool>(false);
        auto doc_export_allow_vendor_seed_plaintext = std::make_shared<bool>(false);
        auto doc_export_allowed_trust = std::make_shared<std::vector<std::string>>();
        doc_export_plain->add_option("--uri", *doc_export_uri, "Document URI.")->required();
        doc_export_plain->add_option("--file", *doc_export_file, "Plain output file.")->required();
        doc_export_plain->add_flag("--require-signature", *doc_export_require_signature, "Reject unsigned documents.");
        doc_export_plain->add_flag("--require-encryption", *doc_export_require_encryption, "Reject plaintext documents.");
        doc_export_plain->add_flag("--allow-vendor-seed-plaintext", *doc_export_allow_vendor_seed_plaintext,
            "Allow plaintext builtin/signed-vendor seed documents when encryption is required.");
        doc_export_plain->add_option("--allow-trust", *doc_export_allowed_trust,
            "Allowed trust level. Repeatable.")
            ->check(CLI::IsMember({"builtin", "signed-vendor", "user-local", "peer-signed", "workspace", "untrusted"}));
        doc_export_plain->callback([=] {
            cmd_storage_doc_export_plain(*doc_export_uri,
                                         *doc_export_file,
                                         *doc_export_require_signature,
                                         *doc_export_require_encryption,
                                         *doc_export_allow_vendor_seed_plaintext,
                                         *doc_export_allowed_trust);
        });

        doc->add_subcommand("list", "List indexed secure documents.")
            ->callback([] { cmd_storage_doc_list(); });

        auto* doc_verify = doc->add_subcommand("verify", "Verify a secure document by URI.");
        auto doc_verify_uri = std::make_shared<std::string>();
        auto doc_verify_require_signature = std::make_shared<bool>(false);
        auto doc_verify_require_encryption = std::make_shared<bool>(false);
        auto doc_verify_allow_vendor_seed_plaintext = std::make_shared<bool>(false);
        auto doc_verify_allowed_trust = std::make_shared<std::vector<std::string>>();
        doc_verify->add_option("--uri", *doc_verify_uri, "Document URI.")->required();
        doc_verify->add_flag("--require-signature", *doc_verify_require_signature, "Reject unsigned documents.");
        doc_verify->add_flag("--require-encryption", *doc_verify_require_encryption, "Reject plaintext documents.");
        doc_verify->add_flag("--allow-vendor-seed-plaintext", *doc_verify_allow_vendor_seed_plaintext,
            "Allow plaintext builtin/signed-vendor seed documents when encryption is required.");
        doc_verify->add_option("--allow-trust", *doc_verify_allowed_trust,
            "Allowed trust level. Repeatable.")
            ->check(CLI::IsMember({"builtin", "signed-vendor", "user-local", "peer-signed", "workspace", "untrusted"}));
        doc_verify->callback([=] {
            cmd_storage_doc_verify(*doc_verify_uri,
                                   *doc_verify_require_signature,
                                   *doc_verify_require_encryption,
                                   *doc_verify_allow_vendor_seed_plaintext,
                                   *doc_verify_allowed_trust);
        });

        auto* doc_sign = doc->add_subcommand("sign", "Sign a secure document manifest by URI.");
        auto doc_sign_uri = std::make_shared<std::string>();
        doc_sign->add_option("--uri", *doc_sign_uri, "Document URI.")->required();
        doc_sign->callback([doc_sign_uri] { cmd_storage_doc_sign(*doc_sign_uri); });

        auto* doc_delete = doc->add_subcommand("delete", "Delete a secure document by URI.");
        auto doc_delete_uri = std::make_shared<std::string>();
        doc_delete->add_option("--uri", *doc_delete_uri, "Document URI.")->required();
        doc_delete->callback([doc_delete_uri] { cmd_storage_doc_delete(*doc_delete_uri); });

        auto* doc_import_seed = doc->add_subcommand(
            "import-seed",
            "Verify a signed plaintext vendor seed document and import it encrypted into the active profile.");
        auto doc_seed_config_dir = std::make_shared<std::string>();
        auto doc_seed_uri = std::make_shared<std::string>();
        doc_import_seed->add_option("--seed-config-dir", *doc_seed_config_dir, "Source seed config dir.")->required();
        doc_import_seed->add_option("--uri", *doc_seed_uri, "Document URI.")->required();
        doc_import_seed->callback([doc_seed_config_dir, doc_seed_uri] {
            cmd_storage_doc_import_seed(*doc_seed_config_dir, *doc_seed_uri);
        });
    }

    // settings-store facade
    {
        auto* cmd = app.add_subcommand("settings-store", "Probe app settings_store backed by secure SettingsProfile.");
        cmd->require_subcommand(1);

        auto* put = cmd->add_subcommand("put", "Save a plaintext JSON file through media::settings::save_settings_utf8.");
        auto put_file = std::make_shared<std::string>();
        put->add_option("--file", *put_file, "Plain settings JSON file.")->required();
        put->callback([put_file] { cmd_settings_store_put(*put_file); });

        auto* import_plain = cmd->add_subcommand("import-plain", "Import a plaintext JSON file into the secure settings profile.");
        auto import_plain_file = std::make_shared<std::string>();
        import_plain->add_option("--file", *import_plain_file, "Plain settings JSON file.")->required();
        import_plain->callback([import_plain_file] { cmd_settings_store_put(*import_plain_file); });

        auto* update = cmd->add_subcommand("update", "Update the secure settings profile from a plaintext JSON file.");
        auto update_file = std::make_shared<std::string>();
        update->add_option("--file", *update_file, "Plain settings JSON file.")->required();
        update->callback([update_file] { cmd_settings_store_update(*update_file); });

        cmd->add_subcommand("get", "Load settings through media::settings::load_settings_utf8.")
            ->callback([] { cmd_settings_store_get(); });

        auto* exp = cmd->add_subcommand("export", "Export settings through media::settings::export_settings_file.");
        auto exp_file = std::make_shared<std::string>();
        auto exp_encrypted = std::make_shared<bool>(false);
        exp->add_option("--file", *exp_file, "Output file.")->required();
        exp->add_flag("--encrypted", *exp_encrypted, "Export encrypted PME1 compatibility blob.");
        exp->callback([exp_file, exp_encrypted] { cmd_settings_store_export(*exp_file, *exp_encrypted); });

        auto* export_plain = cmd->add_subcommand("export-plain", "Export the secure settings profile as plaintext JSON.");
        auto export_plain_file = std::make_shared<std::string>();
        export_plain->add_option("--file", *export_plain_file, "Plain output file.")->required();
        export_plain->callback([export_plain_file] { cmd_settings_store_export(*export_plain_file, false); });
    }

    // command-store facade
    {
        auto* cmd = app.add_subcommand("command-store", "Probe app command config backed by secure CommandConfig.");
        cmd->require_subcommand(1);

        auto* import_plain = cmd->add_subcommand("import-plain", "Import plaintext commands JSON into the secure command config.");
        auto import_plain_file = std::make_shared<std::string>();
        import_plain->add_option("--file", *import_plain_file, "Plain commands JSON file.")->required();
        import_plain->callback([import_plain_file] { cmd_command_store_import_plain(*import_plain_file); });

        cmd->add_subcommand("get", "Load commands through media::settings::load_command_json_utf8.")
            ->callback([] { cmd_command_store_get(); });

        auto* export_plain = cmd->add_subcommand("export-plain", "Export the secure command config as plaintext JSON.");
        auto export_plain_file = std::make_shared<std::string>();
        export_plain->add_option("--file", *export_plain_file, "Plain output file.")->required();
        export_plain->callback([export_plain_file] { cmd_command_store_export_plain(*export_plain_file); });
    }

    // mcp-store facade
    {
        auto* cmd = app.add_subcommand("mcp-store", "Probe MCP config backed by secure McpConfig.");
        cmd->require_subcommand(1);

        auto* import_plain = cmd->add_subcommand("import-plain", "Import plaintext mcp.json into secure MCP config.");
        auto import_plain_file = std::make_shared<std::string>();
        import_plain->add_option("--file", *import_plain_file, "Plain mcp.json file.")->required();
        import_plain->callback([import_plain_file] { cmd_mcp_store_import_plain(*import_plain_file); });

        cmd->add_subcommand("get", "Load the secure MCP config document.")
            ->callback([] { cmd_mcp_store_get(); });

        auto* export_plain = cmd->add_subcommand("export-plain", "Export secure MCP config as plaintext JSON.");
        auto export_plain_file = std::make_shared<std::string>();
        export_plain->add_option("--file", *export_plain_file, "Plain output file.")->required();
        export_plain->callback([export_plain_file] { cmd_mcp_store_export_plain(*export_plain_file); });
    }

    // prompt-store facade
    {
        auto* cmd = app.add_subcommand("prompt-store", "Probe app prompts backed by secure PromptTemplate documents.");
        cmd->require_subcommand(1);

        auto* import_plain = cmd->add_subcommand("import-plain", "Import a plaintext prompt into secure prompt storage.");
        auto import_name = std::make_shared<std::string>();
        auto import_file = std::make_shared<std::string>();
        import_plain->add_option("--name", *import_name, "system | planner | realtime | mode-<name>.")->required();
        import_plain->add_option("--file", *import_file, "Plain prompt Markdown file.")->required();
        import_plain->callback([import_name, import_file] { cmd_prompt_store_import_plain(*import_name, *import_file); });

        auto* get = cmd->add_subcommand("get", "Load a prompt through the agent prompt loader.");
        auto get_name = std::make_shared<std::string>();
        get->add_option("--name", *get_name, "system | planner | realtime | mode-<name>.")->required();
        get->callback([get_name] { cmd_prompt_store_get(*get_name); });

        auto* export_plain = cmd->add_subcommand("export-plain", "Export a secure prompt document as plaintext Markdown.");
        auto export_name = std::make_shared<std::string>();
        auto export_file = std::make_shared<std::string>();
        export_plain->add_option("--name", *export_name, "system | planner | realtime | mode-<name>.")->required();
        export_plain->add_option("--file", *export_file, "Plain output file.")->required();
        export_plain->callback([export_name, export_file] { cmd_prompt_store_export_plain(*export_name, *export_file); });
    }

    // origin
    {
        auto* cmd = app.add_subcommand("origin", "First-party binary provenance registry.");
        cmd->require_subcommand(1);
        cmd->add_subcommand("list", "List registered first-party origins.")
            ->callback([] { cmd_origin_list(); });
        auto* resolve = cmd->add_subcommand("resolve", "Resolve a binary name/path to an origin.");
        auto bin = std::make_shared<std::string>();
        resolve->add_option("--binary", *bin, "Binary name or path (e.g. tanit.exe).")->required();
        resolve->callback([bin] { cmd_origin_resolve(*bin); });
    }

    // uri
    {
        auto* cmd = app.add_subcommand("uri", "RFC-3986 resource URI parse / scope match.");
        cmd->require_subcommand(1);

        auto* parse = cmd->add_subcommand("parse", "Parse --uri into scheme/host/port/path.");
        auto p_uri = std::make_shared<std::string>();
        parse->add_option("--uri", *p_uri, "URI/scope to parse (fs:// normalizes to file://).")->required();
        parse->callback([p_uri] { cmd_uri_parse(*p_uri); });

        auto* match = cmd->add_subcommand("match", "Match --uri against one or more --scope patterns.");
        auto m_uri = std::make_shared<std::string>();
        auto m_scopes = std::make_shared<std::vector<std::string>>();
        match->add_option("--uri", *m_uri, "Target URI.")->required();
        match->add_option("--scope", *m_scopes, "Scope pattern (repeatable).")->required();
        match->callback([m_uri, m_scopes] { cmd_uri_match(*m_uri, *m_scopes); });
    }

    // verification policy
    {
        auto* cmd = app.add_subcommand("verification", "User verification policy and provider probes.");
        cmd->require_subcommand(1);
        cmd->add_subcommand("defaults", "Print compiled default verification policies for settings/assets/grants.")
            ->callback([] { cmd_verification_defaults(); });

        auto* guard = cmd->add_subcommand("guard", "Evaluate an operation through verification + privilege policy.");
        auto guard_operation = std::make_shared<std::string>();
        auto guard_result = std::make_shared<std::string>("success");
        auto guard_ttl = std::make_shared<std::uint32_t>(600u);
        auto guard_repeat = std::make_shared<std::uint32_t>(1u);
        auto guard_assume_privilege = std::make_shared<bool>(false);
        guard->add_option("--operation", *guard_operation, "Operation id, e.g. settings.exportPlain.")
            ->required();
        guard->add_option("--provider-result", *guard_result, "success|cancelled|timeout|not_configured|failed.")
            ->check(CLI::IsMember({"success", "cancelled", "canceled", "timeout", "not_configured", "not-configured", "failed"}));
        guard->add_option("--ttl-seconds", *guard_ttl, "Verification session TTL in seconds.");
        guard->add_option("--repeat", *guard_repeat, "Repeat in one process to exercise the session cache.");
        guard->add_flag("--assume-privilege", *guard_assume_privilege, "Treat admin/system broker requirements as already satisfied.");
        guard->callback([guard_operation, guard_result, guard_ttl, guard_repeat, guard_assume_privilege] {
            cmd_verification_guard(*guard_operation, *guard_result, *guard_ttl, *guard_repeat, *guard_assume_privilege);
        });
    }

#if FEATURE_SECURITY_SANDBOX && defined(_WIN32)
    // sandbox (AppContainer / LPAC experimentation)
    // Probe AppContainer profile lifecycle, filesystem ACL grants ("shared folders"),
    // real process launch, and MCP-wrap simulation with privilege-escalation capture.
    // All sub-commands emit one JSON object; see docs/security/todos.md § Sandbox.
    {
        auto* sb = app.add_subcommand("sandbox",
            "AppContainer / LPAC experimentation [FEATURE_SECURITY_SANDBOX].\n"
            "probe     — create/derive profile, report SID.\n"
            "acl       — grant a path to the container SID ('shared folder').\n"
            "launch    — spawn an exe inside AppContainer (or LPAC), wait for exit.\n"
            "wrap-mcp  — simulate an MCP tool call inside the container;\n"
            "            on ACL miss synthesizes a PrivilegeEscalationRequest.");
        sb->require_subcommand(1);

        // sandbox probe
        {
            auto* p = sb->add_subcommand("probe",
                "Create (or derive) an AppContainer profile and report its SID.");
            auto mon    = std::make_shared<std::string>();
            auto retain = std::make_shared<bool>(false);
            p->add_option("--moniker", *mon,
                "AppContainer package moniker (e.g. pm-mcp-sandbox-test).")->required();
            p->add_flag("--retain", *retain,
                "Keep the profile after the probe (default: delete it).");
            p->callback([mon, retain] { cmd_sandbox_probe(*mon, *retain); });
        }

        // sandbox acl  ("shared folder" grant / check-access probe)
        {
            auto* p = sb->add_subcommand("acl",
                "Grant a filesystem path to the container SID ('shared folder' semantics).\n"
                "Adds an ALLOW ACE for the AppContainer SID to the path's DACL.\n"
                "Run sandbox probe --retain first to ensure the profile exists.\n"
                "\n"
                "--check-access: read-only probe — reports whether the path DACL already\n"
                "has the container SID ACE without making any changes (no grant, no profile\n"
                "creation). Useful for verifying ACE inheritance on child files/dirs.");
            auto mon    = std::make_shared<std::string>();
            auto path   = std::make_shared<std::string>();
            auto access = std::make_shared<std::string>("read");
            auto check  = std::make_shared<bool>(false);
            p->add_option("--moniker", *mon, "AppContainer moniker.")->required();
            p->add_option("--path",    *path, "Filesystem path to grant or check.")->required();
            p->add_option("--access",  *access,
                "read | write | read-write | exec  (default: read). Ignored with --check-access.")
             ->check(CLI::IsMember({"read", "write", "read-write", "exec"}));
            p->add_flag("--check-access", *check,
                "Read-only: check whether the path DACL has the container SID ACE.");
            p->callback([mon, path, access, check] {
                cmd_sandbox_acl(*mon, *path, *access, *check);
            });
        }

        // sandbox launch
        {
            auto* p = sb->add_subcommand("launch",
                "Launch an exe inside an AppContainer (or LPAC) and wait for exit.\n"
                "Uses PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES + optional\n"
                "ALL_APPLICATION_PACKAGES_OPT_OUT (LPAC) and Win32k lockdown.\n"
                "\n"
                "--sandbox-config accepts @file.json or inline JSON:\n"
                "  { \"moniker\":\"pm-test\", \"run\":\"cmd.exe\", \"args\":[\"/c\",\"exit 0\"],\n"
                "    \"lpac\":false, \"paths\":[{\"path\":\"C:\\\\ws\",\"access\":\"read-write\"}] }\n"
                "Config paths are granted before launch and revoked after exit.");
            auto mon              = std::make_shared<std::string>();
            auto exe              = std::make_shared<std::string>();
            auto lpac             = std::make_shared<bool>(false);
            auto no_win32k        = std::make_shared<bool>(false);
            auto no_child_process = std::make_shared<bool>(false);
            auto capabilities     = std::make_shared<std::vector<std::string>>();
            auto retain           = std::make_shared<bool>(false);
            auto timeout          = std::make_shared<uint32_t>(10000u);
            auto cfg_src          = std::make_shared<std::string>();
            auto preset           = std::make_shared<std::string>();
            auto bin_dir          = std::make_shared<std::string>();
            auto user_paths       = std::make_shared<std::vector<std::string>>();
            p->add_option("--moniker",          *mon,
                "AppContainer moniker (overrides config.moniker). "
                "Required if --sandbox-config is not provided.");
            p->add_option("--exe",              *exe,
                "Executable path / command line (overrides config.run+args). "
                "Required if --sandbox-config.run is not set.");
            p->add_flag("--lpac",               *lpac,
                "Launch as Less-Privileged AppContainer (LPAC).");
            p->add_flag("--no-win32k",          *no_win32k,
                "Enable Win32k syscall disable mitigation.");
            p->add_flag("--no-child-process",   *no_child_process,
                "Prevent the sandboxed child from spawning sub-processes "
                "(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY / "
                "PROCESS_CREATION_CHILD_PROCESS_RESTRICTED).");
            p->add_option("--capabilities",     *capabilities,
                "WinRT capability names granted to the AC profile (e.g. internetClient). "
                "Repeatable: --capabilities internetClient --capabilities picturesLibrary.")
             ->allow_extra_args(false)
             ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);
            p->add_flag("--retain",             *retain,
                "Keep the AppContainer profile after launch.");
            p->add_option("--timeout-ms",       *timeout,
                "Wait timeout in milliseconds (default 10 000; 0 = no wait).");
            p->add_option("--sandbox-config",   *cfg_src,
                "JSON sandbox spec: @path/to/file.json or inline JSON.\n"
                "Specifies run, args, paths (grant+revoke), capabilities, etc.\n"
                "Individual flags overlay matching config fields.");
            p->add_option("--preset",           *preset,
                "Named sandbox configuration preset.\n"
                "offline: linters/formatters — no network, exec+rw on bin+cwd.\n"
                "fetch:   package managers  — internetClient, scratch dir.\n"
                "run:     general scripts   — scratch dir, no network default.\n"
                "strict:  untrusted MCP     — LPAC + no network + no sub-spawn + no Win32k.\n"
                "self:    app own binary    — all network caps, dist+bin+roaming+userPaths.\n"
                "         --capabilities replaces (not appends) the self default cap set.\n"
                "Config JSON and individual flags overlay the preset.");
            p->add_option("--bin-dir",          *bin_dir,
                "Path to the sidecar binary directory (default: dirname(this exe)/bin).\n"
                "Used to build the exec path grant when a --preset is active.");
            p->add_option("--user-path",        *user_paths,
                "Additional path granted read-write to the AppContainer (self preset).\n"
                "Repeatable: --user-path /workspace --user-path /models.")
             ->allow_extra_args(false)
             ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);
            p->callback([mon, exe, lpac, no_win32k, no_child_process, capabilities,
                         retain, timeout, cfg_src, preset, bin_dir, user_paths] {
                cmd_sandbox_launch(*mon, *exe, *lpac, *no_win32k, *no_child_process,
                                   *capabilities, *retain, *timeout, *cfg_src,
                                   *preset, *bin_dir, *user_paths);
            });
        }

        // sandbox wrap-mcp
        {
            auto* p = sb->add_subcommand("wrap-mcp",
                "Simulate wrapping an MCP tool call inside an AppContainer.\n"
                "Checks the target path's DACL for the container SID.\n"
                "On ACL miss: emits a PrivilegeEscalationRequest — the structured\n"
                "signal the broker receives and routes to SecurityGateway.\n"
                "On ACL hit: confirms the 'shared folder' grant allows the call.\n"
                "No child process is launched; this is a pure ACL-check simulation.");
            auto mon    = std::make_shared<std::string>("pm-mcp-sandbox-test");
            auto tool   = std::make_shared<std::string>();
            auto action = std::make_shared<std::string>("read");
            auto path   = std::make_shared<std::string>();
            auto lpac   = std::make_shared<bool>(false);
            auto retain = std::make_shared<bool>(false);
            p->add_option("--moniker", *mon,
                "AppContainer moniker (default: pm-mcp-sandbox-test).");
            p->add_option("--tool",   *tool,
                "MCP tool id (e.g. mcp.fs.write, mcp.fs.read).")->required();
            p->add_option("--action", *action, "Action.")
             ->check(CLI::IsMember(k_actions));
            p->add_option("--path",   *path,
                "Resource path the MCP tool is requesting.")->required();
            p->add_flag("--lpac",     *lpac, "Simulate LPAC container.");
            p->add_flag("--retain",   *retain,
                "Keep the AppContainer profile after the probe.");
            p->callback([mon, tool, action, path, lpac, retain] {
                cmd_sandbox_wrap_mcp(*mon, *tool, *action, *path, *lpac, *retain);
            });
        }
    }
#endif // FEATURE_SECURITY_SANDBOX && _WIN32

    // schema
    app.add_subcommand("schema", "Emit the UI contract (enums + type defs) for web & win32.")
        ->callback([] { cmd_schema(); });

#if FEATURE_COMMAND_TEST
    // session-store — shared chat/agent session persistence probes.
    // Controlled by PM_CHAT_SESSION_STORE / PM_CHAT_SESSION_STORE_ROOT /
    // PM_CHAT_SESSION_STORE_PROTECTION so the same chat_session_store APIs can
    // be exercised without adding production policy/GPO plumbing yet.
    {
        auto* ss = app.add_subcommand("session-store",
            "Chat/agent session persistence probes [FEATURE_COMMAND_TEST].");
        ss->require_subcommand(1);

        {
            auto* p = ss->add_subcommand("put", "Save one session JSON document.");
            auto id = std::make_shared<std::string>();
            auto file = std::make_shared<std::string>();
            p->add_option("--id", *id, "Override session id from the JSON file.");
            p->add_option("--file", *file, "Session JSON file.")->required();
            p->callback([id, file] { cmd_session_store_put(*id, *file); });
        }
        {
            auto* p = ss->add_subcommand("load", "Load one session JSON document.");
            auto id = std::make_shared<std::string>();
            p->add_option("--id", *id, "Session id.")->required();
            p->callback([id] { cmd_session_store_load(*id); });
        }
        {
            auto* p = ss->add_subcommand("memory-put", "Save one session memory sidecar document.");
            auto id = std::make_shared<std::string>();
            auto file = std::make_shared<std::string>();
            p->add_option("--id", *id, "Session id.")->required();
            p->add_option("--file", *file, "Memory JSON file.")->required();
            p->callback([id, file] { cmd_session_store_memory_put(*id, *file); });
        }
        {
            auto* p = ss->add_subcommand("log-put", "Save one session log sidecar document.");
            auto id = std::make_shared<std::string>();
            auto log_id = std::make_shared<std::string>();
            auto file = std::make_shared<std::string>();
            p->add_option("--id", *id, "Session id.")->required();
            p->add_option("--log-id", *log_id, "Log id.")->required();
            p->add_option("--file", *file, "Log JSON file.")->required();
            p->callback([id, log_id, file] { cmd_session_store_log_put(*id, *log_id, *file); });
        }
        ss->add_subcommand("list", "List session metadata.")
            ->callback([] { cmd_session_store_list(); });
        ss->add_subcommand("query", "Enumerate sessions, memory items, artifacts, and security sidecar items.")
            ->callback([] { cmd_session_store_query(); });
        {
            auto* p = ss->add_subcommand("delete", "Delete one session.");
            auto id = std::make_shared<std::string>();
            p->add_option("--id", *id, "Session id.")->required();
            p->callback([id] { cmd_session_store_delete(*id); });
        }
        {
            auto* p = ss->add_subcommand("prune", "Keep the newest N sessions and delete the rest.");
            auto keep = std::make_shared<int>(0);
            p->add_option("--keep-latest", *keep, "Number of newest sessions to keep.")->required();
            p->callback([keep] { cmd_session_store_prune(*keep); });
        }
    }

    // license — pure payload/endpoint probes for the future purchase + activation flow.
    // No network calls and no token reads here; retail builds can compile this away
    // with FEATURE_COMMAND_TEST=OFF.
    {
        auto* lic = app.add_subcommand("license",
            "License purchase/activation payload probes [FEATURE_COMMAND_TEST].");
        lic->require_subcommand(1);

        {
            auto* p = lic->add_subcommand("endpoints", "Resolve planned Tanit purchase/license endpoints.");
            auto server = std::make_shared<std::string>();
            p->add_option("--server-url", *server,
                "Override service base URL; empty = SERVER_URL / VITE_SERVER_IMAGE_API_URL / built-in default.");
            p->callback([server] { cmd_license_endpoints(*server); });
        }

        {
            auto* p = lic->add_subcommand("purchase-payload", "Build Stripe PaymentIntent request payload.");
            auto email = std::make_shared<std::string>();
            auto app_user = std::make_shared<std::string>();
            auto machine = std::make_shared<std::string>();
            auto label = std::make_shared<std::string>();
            auto version = std::make_shared<std::string>();
            auto product_id = std::make_shared<std::string>();
            auto slug = std::make_shared<std::string>("tanit-pro");
            auto title = std::make_shared<std::string>("Tanit Pro");
            auto amount = std::make_shared<std::int64_t>(0);
            auto currency = std::make_shared<std::string>("usd");
            auto quantity = std::make_shared<int>(1);
            auto tax = std::make_shared<bool>(false);
            p->add_option("--email", *email, "Buyer email.");
            p->add_option("--app-user-id", *app_user, "Authenticated app user id from login metadata.");
            p->add_option("--machine-hash", *machine, "64-hex hardware fingerprint.")->required();
            p->add_option("--machine-label", *label, "Human label for this machine.");
            p->add_option("--app-version", *version, "Client app version.");
            p->add_option("--product-id", *product_id, "Server/product page id.");
            p->add_option("--slug", *slug, "Product slug.");
            p->add_option("--title", *title, "Product title.");
            p->add_option("--amount-cents", *amount, "Price in smallest currency unit.")->required();
            p->add_option("--currency", *currency, "ISO currency code.");
            p->add_option("--quantity", *quantity, "Quantity.");
            p->add_flag("--calculate-tax", *tax, "Request server-side tax calculation where supported.");
            p->callback([=] {
                cmd_license_purchase_payload(*email, *app_user, *machine, *label, *version,
                                             *product_id, *slug, *title, *amount, *currency,
                                             *quantity, *tax);
            });
        }

        {
            auto* p = lic->add_subcommand("issue-payload", "Build post-purchase license issue payload.");
            auto email = std::make_shared<std::string>();
            auto app_user = std::make_shared<std::string>();
            auto machine = std::make_shared<std::string>();
            auto label = std::make_shared<std::string>();
            auto version = std::make_shared<std::string>();
            auto transaction = std::make_shared<std::string>();
            auto payment_intent = std::make_shared<std::string>();
            auto features = std::make_shared<std::vector<std::string>>();
            auto format = std::make_shared<std::string>("dat");
            p->add_option("--email", *email, "Buyer email.");
            p->add_option("--app-user-id", *app_user, "Authenticated app user id from login metadata.");
            p->add_option("--machine-hash", *machine, "64-hex hardware fingerprint.")->required();
            p->add_option("--machine-label", *label, "Human label for this machine.");
            p->add_option("--app-version", *version, "Client app version.");
            p->add_option("--transaction-id", *transaction, "Server transaction id.");
            p->add_option("--stripe-payment-intent-id", *payment_intent, "Stripe PaymentIntent id.");
            p->add_option("--feature", *features, "Feature id (repeatable; default: pro).");
            p->add_option("--entitlement", *features, "Deprecated alias for --feature.");
            p->add_option("--format", *format, "License file format: dat or json.")
                ->check(CLI::IsMember({"dat", "json"}));
            p->callback([=] {
                if (features->empty())
                    features->push_back("pro");
                cmd_license_issue_payload(*email, *app_user, *machine, *label, *version,
                                          *transaction, *payment_intent, *features, *format);
            });
        }

        {
            auto* p = lic->add_subcommand("revalidate-payload", "Build future home-call revalidation payload.");
            auto license_id = std::make_shared<std::string>();
            auto email = std::make_shared<std::string>();
            auto machine = std::make_shared<std::string>();
            auto version = std::make_shared<std::string>();
            auto generation = std::make_shared<std::int64_t>(0);
            auto active = std::make_shared<std::int64_t>(0);
            p->add_option("--license-id", *license_id, "Signed license id.")->required();
            p->add_option("--email", *email, "Buyer email.");
            p->add_option("--machine-hash", *machine, "64-hex hardware fingerprint.")->required();
            p->add_option("--app-version", *version, "Client app version.");
            p->add_option("--generation", *generation, "Local license-state generation.");
            p->add_option("--active-seconds", *active, "Accumulated active-use seconds.");
            p->callback([=] {
                cmd_license_revalidate_payload(*license_id, *email, *machine, *version, *generation, *active);
            });
        }
    }
#endif // FEATURE_COMMAND_TEST

#if FEATURE_ANTI_HACKING
    // antihack — runtime tamper telemetry (docs/security/dehack.md).
    // Signals only; never terminates. Each probe emits one JSON report.
    {
        auto* ah_cmd = app.add_subcommand("antihack",
            "Runtime tamper telemetry [FEATURE_ANTI_HACKING].\n"
            "debugger  — debugger presence (PEB / NtQueryInformationProcess / DRx).\n"
            "hooks     — inline hooks on sensitive ntdll/kernel32 exports.\n"
            "modules   — loaded-module provenance snapshot.\n"
            "memory    — private executable / RWX memory regions.\n"
            "scan      — run all of the above and aggregate.");
        ah_cmd->require_subcommand(1);

        ah_cmd->add_subcommand("debugger", "Probe debugger-presence signals.")
            ->callback([] {
                ah::ScanOptions o;
                o.debugger = true; o.dll_hooks = false; o.modules = false; o.memory = false;
                cmd_antihack(o);
            });

        {
            auto* p = ah_cmd->add_subcommand("hooks", "Probe inline hooks on sensitive exports.");
            auto mods = std::make_shared<std::vector<std::string>>();
            p->add_option("--module", *mods,
                "Restrict to module(s), e.g. ntdll.dll (repeatable; default: all).");
            p->callback([mods] {
                ah::ScanOptions o;
                o.debugger = false; o.dll_hooks = true; o.modules = false; o.memory = false;
                o.hook_modules = *mods;
                cmd_antihack(o);
            });
        }

        ah_cmd->add_subcommand("modules", "Snapshot loaded modules + flag suspicious paths.")
            ->callback([] {
                ah::ScanOptions o;
                o.debugger = false; o.dll_hooks = false; o.modules = true; o.memory = false;
                cmd_antihack(o);
            });

        {
            auto* p = ah_cmd->add_subcommand("memory", "Scan for private-executable / RWX regions.");
            auto rwx = std::make_shared<bool>(false);
            p->add_flag("--self-test-rwx", *rwx,
                "Allocate one RWX page first so the scan has a deterministic positive (test harness).");
            p->callback([rwx] {
                ah::ScanOptions o;
                o.debugger = false; o.dll_hooks = false; o.modules = false; o.memory = true;
                o.memory_self_test_rwx = *rwx;
                cmd_antihack(o);
            });
        }

        {
            auto* p = ah_cmd->add_subcommand("scan", "Run every probe and aggregate one report.");
            auto rwx = std::make_shared<bool>(false);
            p->add_flag("--self-test-rwx", *rwx, "Inject an RWX page for the memory probe (test harness).");
            p->callback([rwx] {
                ah::ScanOptions o;
                o.memory_self_test_rwx = *rwx;
                cmd_antihack(o);
            });
        }
    }
#endif // FEATURE_ANTI_HACKING

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    // gpo
    {
        auto* gpo = app.add_subcommand("gpo",
            "Windows Group Policy Object queries.\n"
            "Read HKCU/HKLM policy keys under "
            "Software\\Policies\\PolyMech\\pm-image and show the effective policy.");
        gpo->require_subcommand(1);

        // gpo effective
        {
            auto* p = gpo->add_subcommand("effective",
                "Show the merged effective policy for all known keys.\n"
                "Builtin defaults are overridden by HKCU, which is overridden by HKLM.");
            auto set_only = std::make_shared<bool>(false);
            p->add_flag("--set-only", *set_only,
                "Only emit keys explicitly configured via GPO (omit the full policy dump).");
            p->callback([set_only] { cmd_gpo_effective(*set_only); });
        }

        // gpo read
        {
            auto* p = gpo->add_subcommand("read",
                "Dump raw registry values from HKCU and/or HKLM.");
            auto hive = std::make_shared<std::string>("both");
            p->add_option("--hive", *hive,
                "Which hive(s) to read: hkcu | hklm | both (default: both).")
             ->check(CLI::IsMember({"hkcu", "hklm", "both"}));
            p->callback([hive] { cmd_gpo_read(*hive); });
        }

        // gpo list-tools
        gpo->add_subcommand("list-tools",
                "List all agent tools with their GPO-effective enabled/disabled status.")
            ->callback([] { cmd_gpo_list_tools(); });
    }
#endif // FEATURE_WINDOWS_GPO

    SecCliInfoState info_st;
    sec_cli_register_info(app, info_st);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    } catch (const std::exception& e) {
        emit(err_json("cli", e.what()));
        return g_exit;
    }
    if (info_st.info_cmd && info_st.info_cmd->parsed())
        return sec_cli_cmd_info(app, info_st);
    return g_exit;
}
