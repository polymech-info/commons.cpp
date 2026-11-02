#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string_view>

namespace pm::security {

// ── Secure session persistence defaults ──────────────────────────────────────
// These are intentionally kept with the security defaults, not with the active
// profile setting. A profile like LIGHT/STRICT does not decide where sessions
// are stored or whether they are signed/encrypted.
inline constexpr const char k_session_storage_backend_default[] = "secure-storage";
inline constexpr const char k_session_storage_root_default[] = "";
// Signed session documents stay readable JSON with a local signature. Encryption
// remains available as an explicit protection mode (and via managed policy).
inline constexpr const char k_session_storage_protection_default[] = "signed";
inline constexpr int k_session_storage_max_sessions_default = 50;
// Session memory *sidecar* documents (pm://session-memory/<id>) are signed-only
// by default. Encryption can be layered on top when the global protection mode
// is Encrypted or EncryptedWithUserPresence, but integrity without confidentiality
// is sufficient for the default case.
inline constexpr const char k_session_memory_doc_protection_default[] = "signed";

// Default centre dashboard. Signed `pm://config/home.page` when
// FEATURE_SECURE_STORAGE is on (tanit / tanit-chat). tanit-viewer keeps the
// plaintext ${KNOWNFOLDER:Config}/home.page file.
inline constexpr const char k_home_page_document_uri[] = "pm://config/home.page";
inline constexpr const char k_home_page_filename[] = "home.page";
/// Stable id for the shipped home-dashboard execute grant. Seeded on first
/// load_grants; a later revoke is remembered via security.seededDefaultGrantIds.
inline constexpr const char k_default_home_page_grant_id[] = "grant-default-home-page";

// ── Protocol activation (tanit:// URI) fetch limits ──────────────────────────
// Hard cap on the payload downloaded for a protocol-activated VFS view
// (tanit://view/vfs/…). Anything larger is rejected before it reaches the
// temp file / viewer — a protocol click must never become a bulk-download
// primitive.
inline constexpr std::size_t k_protocol_fetch_max_bytes = 10ull * 1024 * 1024;  // 10 MB

/// JSON-compatible defaults for UI/settings policy storage.
///
/// These defaults are intentionally data-shaped so the settings UI, GPO/ADMX
/// generation, and CLI probes can all read the same policy vocabulary.
nlohmann::json default_operation_policies_json();
nlohmann::json default_secure_storage_settings_json();
nlohmann::json default_security_settings_json();
nlohmann::json default_operation_policy_json(std::string_view operation);

} // namespace pm::security
