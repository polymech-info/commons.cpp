#pragma once
//
// pm::security::PermissionStore — persistence of scoped capability grants.
//
// Phase 1 (this file): an in-memory store with the full query surface and the
// non-persistable-action + expiry rules enforced. Phase 3 swaps the backing
// store for SQLite (grants.db, WAL mode) with sensitive columns encrypted via
// CryptoStore and grant invalidation on tool/policy hash mismatch.
//
// Design reference: docs/security/design.md ("Persistence", SQLite "grants"
// table, "Capability grants").
//

#include "security/CryptoStore.hpp"
#include "security/types.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace pm::security {

class PermissionStore {
public:
    /// @p crypto seals sensitive columns once SQLite persistence lands. May be
    /// null for the in-memory Phase 1 store.
    explicit PermissionStore(std::shared_ptr<CryptoStore> crypto = nullptr);
    ~PermissionStore();

    /// Persist @p grant. Refuses (returns false) for actions that must always
    /// require fresh consent (`is_never_persistable`) or for `Once` lifetime.
    bool put(const CapabilityGrant& grant);

    /// Find a live grant covering @p request (identity match + hash binding +
    /// not expired/revoked + action + resource scope). std::nullopt if none.
    std::optional<CapabilityGrant> find(const ToolRequest& request) const;

    /// Drop a grant by id. Returns true if one was removed.
    bool revoke(const std::string& grantId);

    /// Drop grants whose bound tool hashes no longer match @p current
    /// (TOOL_HASH_CHANGED). Returns the number invalidated.
    std::size_t invalidateOnHashMismatch(const ToolIdentity& current);

    /// Remove expired grants. Returns the number purged.
    std::size_t purgeExpired();

    /// All currently stored (non-revoked) grants — for settings/audit UIs.
    std::vector<CapabilityGrant> list() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace pm::security
