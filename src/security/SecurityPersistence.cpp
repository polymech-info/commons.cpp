#include "security/SecurityPersistence.hpp"

#include "host/services.hpp"
#include "logging/pm_log.hpp"
#include "security/PathSecurity.hpp"
#include "security/PolicyEngine.hpp"
#include "security/security_default.hpp"
#include "security/security_defaults.hpp"

#include <chrono>
#include <cstdint>
#include <fstream>
#include <optional>
#include <system_error>

namespace pm::security::persist {

namespace {

using json = nlohmann::json;
constexpr std::string_view k_ch = "sec-persist";

std::string str(const json& j, const char* key, const std::string& def = {}) {
    return j.contains(key) && j[key].is_string() ? j[key].get<std::string>() : def;
}

std::string stored_path(const std::string& path) {
    return pm::commons::host::path_to_stored(path);
}

std::string expanded_text(const std::string& text) {
    return pm::commons::host::expand_stored_text(text);
}

json stored_scopes(const std::vector<std::string>& scopes) {
    json arr = json::array();
    for (const auto& scope : scopes) {
        arr.push_back(pm::commons::host::stored_scope(scope));
    }
    return arr;
}

std::int64_t to_unix_ms(std::chrono::system_clock::time_point tp) {
    using namespace std::chrono;
    return duration_cast<milliseconds>(tp.time_since_epoch()).count();
}

std::chrono::system_clock::time_point from_unix_ms(std::int64_t ms) {
    return std::chrono::system_clock::time_point(std::chrono::milliseconds(ms));
}

} // namespace

// ── parsing ──────────────────────────────────────────────────────────────────

std::optional<Profile> parse_profile(std::string_view s) noexcept {
    if (s == "LIGHT" || s == "light")         return Profile::Light;
    if (s == "STRICT" || s == "strict")       return Profile::Strict;
    if (s == "DEVELOPER" || s == "developer") return Profile::Developer;
    return std::nullopt;
}

std::optional<Action> parse_action(std::string_view s) noexcept {
    if (s == "read")     return Action::Read;
    if (s == "write")    return Action::Write;
    if (s == "delete")   return Action::Delete;
    if (s == "execute")  return Action::Execute;
    if (s == "network")  return Action::Network;
    if (s == "upload")   return Action::Upload;
    if (s == "download") return Action::Download;
    if (s == "git_push" || s == "gitpush") return Action::GitPush;
    if (s == "publish")  return Action::Publish;
    return std::nullopt;
}

std::optional<Actor> parse_actor(std::string_view s) noexcept {
    if (s == "user")             return Actor::User;
    if (s == "llm")              return Actor::LLM;
    if (s == "plugin")           return Actor::Plugin;
    if (s == "mcp_server" || s == "mcp") return Actor::McpServer;
    if (s == "background_agent" || s == "agent") return Actor::BackgroundAgent;
    return std::nullopt;
}

std::optional<GrantLifetime> parse_lifetime(std::string_view s) noexcept {
    if (s == "once")            return GrantLifetime::Once;
    if (s == "session")         return GrantLifetime::Session;
    if (s == "until_timestamp") return GrantLifetime::UntilTimestamp;
    if (s == "permanent")       return GrantLifetime::Permanent;
    if (s == "task")            return GrantLifetime::Task;
    return std::nullopt;
}

// ── serialization ────────────────────────────────────────────────────────────

json to_json(const ToolIdentity& id) {
    return json{
        {"toolId", id.toolId},
        {"provider", id.provider},
        {"serverId", id.serverId},
        {"executableHash", id.executableHash},
        {"manifestHash", id.manifestHash},
        {"signedManifest", id.signedManifest},
    };
}

json to_json(const CapabilityGrant& g) {
    json j{
        {"id", g.id},
        {"profile", std::string(to_string(g.profile))},
        {"subject", g.subject},
        {"tool", to_json(g.tool)},
        {"action", std::string(to_string(g.action))},
        {"resourceScopes", stored_scopes(g.resourceScopes)},
        {"readOnly", g.readOnly},
        {"allowSecrets", g.allowSecrets},
        {"allowNetwork", g.allowNetwork},
        {"maxFiles", g.maxFiles},
        {"maxBytes", g.maxBytes},
        {"lifetime", std::string(to_string(g.lifetime))},
        {"sessionId", g.sessionId},
        {"taskId", g.taskId},
        {"workspaceId", stored_path(g.workspaceId)},
        {"policyVersion", g.policyVersion},
        {"reason", g.reason},
        {"aiDelegated", g.aiDelegated},
        {"approvedBy", g.approvedBy},
        {"sandboxBackend", g.sandboxBackend},
    };
    if (g.expiresAt)
        j["expiresAtMs"] = to_unix_ms(*g.expiresAt);
    if (g.createdAt)
        j["createdAtMs"] = to_unix_ms(*g.createdAt);
    return j;
}

bool from_json(const json& j, ToolIdentity& out) {
    if (!j.is_object())
        return false;
    out.toolId         = str(j, "toolId");
    out.provider       = str(j, "provider");
    out.serverId       = str(j, "serverId");
    out.executableHash = str(j, "executableHash");
    out.manifestHash   = str(j, "manifestHash");
    out.signedManifest = j.value("signedManifest", false);
    return true;
}

bool from_json(const json& j, CapabilityGrant& out) {
    if (!j.is_object())
        return false;
    out.id = str(j, "id");
    // id may be absent in shipped grant templates — the importer assigns one.
    // Stored grants (from save_grants) always carry an id; missing id is only
    // skipped when loading from the active store (load_grants / load_grants_file
    // in the settings-store / grants.json round-trip path), not during import.
    if (const auto p = parse_profile(str(j, "profile", "LIGHT")))
        out.profile = *p;
    out.subject = str(j, "subject");
    if (j.contains("tool"))
        from_json(j["tool"], out.tool);
    if (const auto a = parse_action(str(j, "action", "read")))
        out.action = *a;
    out.resourceScopes.clear();
    if (j.contains("resourceScopes") && j["resourceScopes"].is_array())
        for (const auto& s : j["resourceScopes"])
            if (s.is_string())
                out.resourceScopes.push_back(expanded_text(s.get<std::string>()));
    out.readOnly     = j.value("readOnly", true);
    out.allowSecrets = j.value("allowSecrets", false);
    out.allowNetwork = j.value("allowNetwork", false);
    out.maxFiles     = j.value("maxFiles", static_cast<std::uint64_t>(100));
    out.maxBytes     = j.value("maxBytes", static_cast<std::uint64_t>(10ull * 1024 * 1024));
    if (const auto l = parse_lifetime(str(j, "lifetime", "session")))
        out.lifetime = *l;
    out.sessionId = str(j, "sessionId");
    out.taskId    = str(j, "taskId");
    if (j.contains("expiresAtMs") && j["expiresAtMs"].is_number_integer())
        out.expiresAt = from_unix_ms(j["expiresAtMs"].get<std::int64_t>());
    if (j.contains("createdAtMs") && j["createdAtMs"].is_number_integer())
        out.createdAt = from_unix_ms(j["createdAtMs"].get<std::int64_t>());
    out.workspaceId    = expanded_text(str(j, "workspaceId"));
    out.policyVersion  = str(j, "policyVersion");
    out.reason         = str(j, "reason");
    out.aiDelegated    = j.value("aiDelegated", false);
    out.approvedBy     = str(j, "approvedBy", "human");
    out.sandboxBackend = str(j, "sandboxBackend");
    return true;
}

namespace {

constexpr const char* k_seeded_ids_key = "seededDefaultGrantIds";

std::string home_page_scope() {
    try {
        PathSecurity ps;
        const auto canon = ps.canonicalize(
            pm::commons::host::config_dir() / k_home_page_filename);
        if (canon.value.empty())
            return {};
        return PathSecurity::normalizeForMatch(canon.value);
    } catch (...) {
        return {};
    }
}

CapabilityGrant make_default_home_page_grant() {
    CapabilityGrant g;
    g.id = k_default_home_page_grant_id;
    g.subject = "user";
    g.profile = k_default_profile;
    g.policyVersion = k_policy_version;
    g.tool.toolId = "web.commandRun";
    g.tool.provider = "web";
    g.action = Action::Execute;
    g.readOnly = false;
    g.lifetime = GrantLifetime::Permanent;
    const std::string scope = home_page_scope();
    if (!scope.empty())
        g.resourceScopes = {scope};
    g.reason = "shipped home.page dashboard";
    g.approvedBy = "default";
    g.createdAt = std::chrono::system_clock::now();
    return g;
}

bool seeded_ids_contains(const json& arr, std::string_view id) {
    if (!arr.is_array())
        return false;
    for (const auto& row : arr) {
        if (row.is_string() && row.get<std::string>() == id)
            return true;
    }
    return false;
}

void remember_seeded_id(json& security, std::string_view id) {
    json& ids = security[k_seeded_ids_key];
    if (!ids.is_array())
        ids = json::array();
    if (seeded_ids_contains(ids, id))
        return;
    ids.push_back(std::string(id));
}

bool save_security_node(const json& security, std::string& err) {
    return pm::commons::host::save_subtree(
        "security", security, err);
}

// Insert (or refresh the scope of) the compiled home.page execute grant.
// Revoke sticks: once the id is in security.seededDefaultGrantIds and the
// grant is gone, we do not put it back.
void seed_default_grants(PermissionStore& store) {
    const CapabilityGrant wanted = make_default_home_page_grant();
    if (wanted.resourceScopes.empty() || wanted.id.empty())
        return;

    json security;
    std::string err;
    if (!pm::commons::host::load_subtree(
            "security", security, err))
        security = json::object();
    if (!security.is_object())
        security = json::object();

    std::optional<CapabilityGrant> existing;
    for (const auto& g : store.list()) {
        if (g.id == wanted.id) {
            existing = g;
            break;
        }
    }

    if (existing) {
        if (existing->resourceScopes != wanted.resourceScopes) {
            existing->resourceScopes = wanted.resourceScopes;
            store.put(*existing);
            upsert_grant(*existing, err);
        }
        if (!seeded_ids_contains(security[k_seeded_ids_key], wanted.id)) {
            remember_seeded_id(security, wanted.id);
            save_security_node(security, err);
        }
        return;
    }

    if (seeded_ids_contains(security[k_seeded_ids_key], wanted.id))
        return;

    store.put(wanted);
    upsert_grant(wanted, err);
    remember_seeded_id(security, wanted.id);
    save_security_node(security, err);
    pm::log::info_lazy(k_ch, [] {
        return std::string("seeded default grant id=") + k_default_home_page_grant_id;
    });
}

} // namespace

// ── grant store ──────────────────────────────────────────────────────────────

bool load_grants(PermissionStore& store, std::string& err) {
    json node;
    if (!pm::commons::host::load_subtree("permissions", node, err))
        return false;
    if (node.is_array()) {
        for (const auto& row : node) {
            CapabilityGrant g;
            if (from_json(row, g))
                store.put(g);  // put() silently drops non-persistable / Once rows
        }
    }
    seed_default_grants(store);
    return true;
}

bool save_grants(const PermissionStore& store, std::string& err) {
    json arr = json::array();
    for (const auto& g : store.list())
        arr.push_back(to_json(g));
    return pm::commons::host::save_subtree("permissions", arr, err);
}

bool upsert_grant(const CapabilityGrant& grant, std::string& err) {
    // Consent-created session/task grants must survive process boundaries for
    // the same agent context; only one-shot approvals are intentionally ephemeral.
    if (grant.lifetime == GrantLifetime::Once) {
        err = "upsert_grant: once grant skipped";
        pm::log::trace_lazy(k_ch, [&err] { return err; });
        return true;   // not an error — just a no-op
    }
    if (grant.id.empty()) {
        err = "upsert_grant: grant has no id";
        pm::log::warn_lazy(k_ch, [&err] { return err; });
        return false;
    }

    pm::log::debug_lazy(k_ch, [&grant] {
        return std::string("upsert id=") + grant.id
            + " action=" + std::string(to_string(grant.action))
            + " scopes=" + std::to_string(grant.resourceScopes.size());
    });

    // Read the current in-memory settings array (or start fresh if missing).
    json arr;
    std::string load_err;
    if (!pm::commons::host::load_subtree(
            "permissions", arr, load_err)) {
        pm::log::warn_lazy(k_ch, [&load_err] {
            return std::string("upsert: load_subtree failed: ") + load_err;
        });
    }
    if (!arr.is_array()) {
        pm::log::debug_lazy(k_ch, [] { return std::string("upsert: no existing permissions array, starting fresh"); });
        arr = json::array();
    }

    auto same_capability = [&grant](const json& row) {
        if (!row.is_object()) return false;
        if (row.value("id", std::string{}) == grant.id)
            return true;
        CapabilityGrant existing;
        if (!from_json(row, existing))
            return false;
        return existing.tool.toolId == grant.tool.toolId
            && existing.tool.provider == grant.tool.provider
            && existing.action == grant.action
            && existing.resourceScopes == grant.resourceScopes;
    };

    bool replaced = false;
    json next = json::array();
    for (const auto& row : arr) {
        if (same_capability(row)) {
            replaced = true;
            continue;
        }
        next.push_back(row);
    }
    next.push_back(to_json(grant));

    pm::log::debug_lazy(k_ch, [&grant, replaced, &next] {
        return std::string("upsert: writing ") + std::to_string(next.size())
            + " grant(s) (" + (replaced ? "replaced" : "added") + " id=" + grant.id + ")";
    });

    const bool ok = pm::commons::host::save_subtree(
        "permissions", next, err);
    if (ok)
        pm::log::info_lazy(k_ch, [&grant] {
            return std::string("upsert ok id=") + grant.id
                + " action=" + std::string(to_string(grant.action))
                + " lifetime=" + std::string(to_string(grant.lifetime));
        });
    else
        pm::log::warn_lazy(k_ch, [&err] {
            return std::string("upsert: save_subtree failed: ") + err;
        });
    return ok;
}

std::vector<CapabilityGrant> parse_grants_array(const json& arr) {
    std::vector<CapabilityGrant> out;
    if (!arr.is_array()) return out;
    for (const auto& row : arr) {
        CapabilityGrant g;
        if (from_json(row, g))
            out.push_back(std::move(g));
    }
    return out;
}

// ── grants.json file backend ─────────────────────────────────────────────────

bool load_grants_file(PermissionStore& store,
                      const std::filesystem::path& path,
                      std::string& err) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
        return true;  // no file yet = empty store, not an error

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        err = "cannot open " + path.generic_string();
        return false;
    }
    std::string raw(std::istreambuf_iterator<char>(f), {});
    if (raw.empty())
        return true;

    json arr;
    try {
        arr = json::parse(raw);
    } catch (const json::exception& e) {
        err = "grants.json parse error: " + std::string(e.what());
        return false;
    }
    if (!arr.is_array())
        return true;  // empty / null / wrong format → treat as empty

    for (const auto& row : arr) {
        CapabilityGrant g;
        if (from_json(row, g))
            store.put(g);
    }
    return true;
}

bool save_grants_file(const PermissionStore& store,
                      const std::filesystem::path& path,
                      std::string& err) {
    // Ensure parent directory exists.
    std::error_code ec;
    if (!path.parent_path().empty())
        std::filesystem::create_directories(path.parent_path(), ec);

    json arr = json::array();
    for (const auto& g : store.list())
        arr.push_back(to_json(g));

    // Write to a sibling temp file and rename for atomic replacement.
    const std::filesystem::path tmp = std::filesystem::path(path).replace_extension(".tmp");
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            err = "cannot write " + tmp.generic_string();
            return false;
        }
        f << arr.dump(2);   // pretty-printed, 2-space indent
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        err = "rename failed: " + ec.message();
        return false;
    }
    return true;
}

// ── active profile ───────────────────────────────────────────────────────────

bool load_active_profile(Profile& out, Profile fallback, std::string& err) {
    out = fallback;
    json node;
    if (!pm::commons::host::load_subtree("security", node, err))
        return false;
    if (node.is_object() && node.contains("profile") && node["profile"].is_string()) {
        if (const auto p = parse_profile(node["profile"].get<std::string>()))
            out = *p;
    }
    return true;
}

bool save_active_profile(Profile profile, std::string& err) {
    json node;
    if (!pm::commons::host::load_subtree("security", node, err))
        return false;
    if (!node.is_object())
        node = json::object();
    node["profile"] = std::string(to_string(profile));
    return pm::commons::host::save_subtree("security", node, err);
}

} // namespace pm::security::persist
