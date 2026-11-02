#pragma once
//
// pm::security::AuditLog — record of every gateway decision and grant lifecycle
// event.
//
// Phase 1 (this file): an in-memory ring + stderr sink with the full event
// vocabulary. Phase 3 adds an spdlog sink and a SQLite audit.db with sensitive
// columns encrypted via CryptoStore.
//
// Design reference: docs/security/design.md ("Audit", SQLite "audit" table).
//

#include "security/types.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace pm::security {

/// Auditable lifecycle events (design.md "Audit").
enum class AuditEvent : std::uint8_t {
    Allow,
    Deny,
    Ask,
    UserGranted,
    UserDenied,
    Sandbox,
    Redacted,
    PolicyChanged,
    GrantRevoked,
    GrantExpired,
    ToolHashChanged,
};

constexpr std::string_view to_string(AuditEvent e) noexcept {
    switch (e) {
        case AuditEvent::Allow:           return "ALLOW";
        case AuditEvent::Deny:            return "DENY";
        case AuditEvent::Ask:             return "ASK";
        case AuditEvent::UserGranted:     return "USER_GRANTED";
        case AuditEvent::UserDenied:      return "USER_DENIED";
        case AuditEvent::Sandbox:         return "SANDBOX";
        case AuditEvent::Redacted:        return "REDACTED";
        case AuditEvent::PolicyChanged:   return "POLICY_CHANGED";
        case AuditEvent::GrantRevoked:    return "GRANT_REVOKED";
        case AuditEvent::GrantExpired:    return "GRANT_EXPIRED";
        case AuditEvent::ToolHashChanged: return "TOOL_HASH_CHANGED";
    }
    return "DENY";
}

/// One audit row (mirrors the SQLite `audit` table columns).
struct AuditRecord {
    std::int64_t tsUnixMs = 0;
    std::string sessionId;
    Profile profile = Profile::Light;
    Actor actor = Actor::LLM;
    std::string toolId;
    std::string provider;
    std::string serverId;
    Action action = Action::Read;
    std::string target;   // redacted/canonical target string
    AuditEvent event = AuditEvent::Deny;
    Risk risk = Risk::Low;
    std::string grantId;
    std::string reason;
    std::string argsHash;
};

class AuditLog {
public:
    explicit AuditLog(std::size_t ringCapacity = 1024);
    ~AuditLog();

    /// Record a decision for @p request with @p event/@p risk/@p reason.
    void record(const ToolRequest& request,
                AuditEvent event,
                Risk risk,
                const std::string& reason,
                const std::string& grantId = {});

    /// Record a bare lifecycle event not tied to a live request.
    void recordEvent(AuditEvent event, const std::string& reason);

    /// Most recent records (oldest→newest), for a settings/audit UI.
    std::vector<AuditRecord> recent(std::size_t max = 100) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace pm::security
