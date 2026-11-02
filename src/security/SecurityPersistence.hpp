#pragma once
//
// pm::security::persist — settings-backed persistence for the security gateway.
//
// Phase-1 persistence layer (driven by the `pm-image-security` test CLI). Capability
// grants and the active security profile are stored in the app's encrypted
// settings.json via media::settings::load_subtree / save_subtree under the
// reserved `permissions` and `security` keys (see SettingsSubtreeKeys). This is a
// deliberate first step before the dedicated SQLite grants.db lands
// (FEATURE_SECURITY_PERMISSION_STORE, docs/security/todos.md → Phase 3).
//
// This file lives in the security module but depends on media::settings, which is
// linked into the `pm-image-security` target (and the main app). It is NOT
// compiled into pm-media so the shipping library stays free of security wiring.
//
// JSON serialization of CapabilityGrant / ToolIdentity is shared by the CLI
// probes and (later) the settings UI.
//

#include "security/PermissionStore.hpp"
#include "security/types.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace pm::security::persist {

// ── String → enum parsing (inverse of types.hpp to_string) ───────────────────

std::optional<Profile>       parse_profile(std::string_view s) noexcept;
std::optional<Action>        parse_action(std::string_view s) noexcept;
std::optional<Actor>         parse_actor(std::string_view s) noexcept;
std::optional<GrantLifetime> parse_lifetime(std::string_view s) noexcept;

// ── JSON (de)serialization ───────────────────────────────────────────────────

nlohmann::json to_json(const ToolIdentity& id);
nlohmann::json to_json(const CapabilityGrant& grant);

bool from_json(const nlohmann::json& j, ToolIdentity& out);
bool from_json(const nlohmann::json& j, CapabilityGrant& out);

/// Parse a JSON array of grant objects into a vector, without running any
/// PermissionStore validation rules. Used by `grant import` to inspect
/// candidates before assignment/validation. Invalid rows are silently skipped.
std::vector<CapabilityGrant> parse_grants_array(const nlohmann::json& arr);

// ── Backend A: settings-store (key: SettingsSubtreeKeys::permissions) ─────────
//
// Grants live inside the app's encrypted settings.json. Use this when the
// security gateway is embedded in tanit.exe / pm-image-cli.exe.

/// Load every persisted grant from settings.json["permissions"] into @p store.
/// Missing/empty key is success with an empty store. Malformed rows are skipped.
/// After load, seeds the compiled home.page execute grant when it has not been
/// revoked (see security.seededDefaultGrantIds).
bool load_grants(PermissionStore& store, std::string& err);

/// Replace settings.json["permissions"] with the live grants from @p store.
/// NOTE: drops any grant that PermissionStore::put() rejected (empty scopes,
/// Once lifetime, etc.). Prefer upsert_grant for adding a single new grant
/// without touching existing on-disk entries.
bool save_grants(const PermissionStore& store, std::string& err);

/// Upsert a single grant into settings.json["permissions"] without touching
/// any other entry.  Reads the live in-memory settings array, replaces any
/// entry with the same id *or* the same tool/action/scopes (so Always cannot
/// stack duplicates), and writes back.  Once grants are intentionally not persisted.
bool upsert_grant(const CapabilityGrant& grant, std::string& err);

// ── Backend B: grants.json (plain UTF-8 file, human-readable) ─────────────────
//
// A standalone JSON file — no dependency on the app settings machinery. Intended
// for the security tool used as a standalone library / CLI by external apps, for
// testing, and for direct human inspection/editing.

/// Load grants from a plain JSON file (array of grant objects).
/// Returns true and an empty store when the file does not exist yet.
bool load_grants_file(PermissionStore& store,
                      const std::filesystem::path& path,
                      std::string& err);

/// Atomically write grants to a plain JSON file (pretty-printed, human-readable).
/// Creates parent directories if needed.
bool save_grants_file(const PermissionStore& store,
                      const std::filesystem::path& path,
                      std::string& err);

// ── Active profile (key: SettingsSubtreeKeys::security → "profile") ───────────

/// Load the persisted active profile. Falls back to @p fallback when unset.
bool load_active_profile(Profile& out, Profile fallback, std::string& err);

/// Persist the active profile, preserving other keys under "security".
bool save_active_profile(Profile profile, std::string& err);

} // namespace pm::security::persist
