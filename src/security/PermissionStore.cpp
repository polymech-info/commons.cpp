#include "security/PermissionStore.hpp"
#include "security/PathSecurity.hpp"
#include "security/ToolIdentity.hpp"
#include "security/UriScope.hpp"

#include <chrono>
#include <unordered_map>

namespace pm::security {

struct PermissionStore::Impl {
    std::shared_ptr<CryptoStore> crypto;
    std::unordered_map<std::string, CapabilityGrant> grants;  // id → grant
    PathSecurity paths;

    static bool expired(const CapabilityGrant& g) {
        if (!g.expiresAt) return false;
        return std::chrono::system_clock::now() >= *g.expiresAt;
    }
};

PermissionStore::PermissionStore(std::shared_ptr<CryptoStore> crypto)
    : impl_(std::make_unique<Impl>()) {
    impl_->crypto = std::move(crypto);
    // TODO(security, Phase 3): open SQLite grants.db (WAL), load non-revoked
    // grants, decrypt sealed columns via impl_->crypto.
}

PermissionStore::~PermissionStore() = default;

bool PermissionStore::put(const CapabilityGrant& grant) {
    // Critical actions and one-shot grants are never persisted.
    if (is_never_persistable(grant.action)) return false;
    if (grant.lifetime == GrantLifetime::Once) return false;
    if (grant.id.empty()) return false;

    // Permanent lifetime is disallowed for egress / externally irreversible
    // actions. Scoped local write/execute grants are permitted.
    if (grant.lifetime == GrantLifetime::Permanent && is_never_permanent(grant.action))
        return false;

    // A grant with no resource scopes is ambient authority for any targeted
    // request.  We refuse to store it — the caller must always supply at least
    // one explicit scope.  (Scoped to no-target requests this does not apply;
    // callers building such grants should set a sentinel like "*" or "any:".)
    if (grant.resourceScopes.empty()) return false;

    // TODO(security, Phase 3): persist to SQLite with sealed scopes/reason BLOBs.
    impl_->grants[grant.id] = grant;
    return true;
}

std::optional<CapabilityGrant> PermissionStore::find(const ToolRequest& request) const {
    for (const auto& [id, g] : impl_->grants) {
        if (Impl::expired(g)) continue;
        if (g.action != request.action) continue;
        if (!ToolIdentityResolver::matches(g.tool, request.tool)) continue;

        // Binding ids: a grant bound to a session/task only covers requests
        // carrying the same id. Empty binding = unbound (matches any).
        if (!g.sessionId.empty() && g.sessionId != request.sessionId) continue;
        if (!g.taskId.empty() && g.taskId != request.taskId) continue;

        // Resource scope: a grant with no scopes is ambient authority — it would
        // silently allow any resource for that tool/action pair.  We reject the
        // match so the caller must always state at least one explicit scope.
        //
        // Exception: the request itself has no resource target (e.g. a tool that
        // acts on no specific file — a future "shell ping" or "list servers").  In
        // that case an empty grant scope is acceptable (the tool has no target to
        // restrict).
        if (request.target) {
            if (g.resourceScopes.empty())
                continue;  // refuse — empty scope = ambient authority
            ResourceTarget t = *request.target;
            // Canonicalize the filesystem path so file scopes compare against the
            // resolved absolute path; network targets keep their URI as-is.
            if (!t.path.empty())
                t.path = impl_->paths.canonicalize(t.path).value;
            if (!uri::scope_matches_any(g.resourceScopes, t))
                continue;
        }
        return g;
    }
    return std::nullopt;
}

bool PermissionStore::revoke(const std::string& grantId) {
    return impl_->grants.erase(grantId) > 0;
}

std::size_t PermissionStore::invalidateOnHashMismatch(const ToolIdentity& current) {
    std::size_t n = 0;
    for (auto it = impl_->grants.begin(); it != impl_->grants.end();) {
        const auto& g = it->second;
        const bool sameTool =
            ToolIdentityResolver::identityKey(g.tool) ==
            ToolIdentityResolver::identityKey(current);
        if (sameTool && !ToolIdentityResolver::matches(g.tool, current)) {
            it = impl_->grants.erase(it);
            ++n;
        } else {
            ++it;
        }
    }
    return n;
}

std::size_t PermissionStore::purgeExpired() {
    std::size_t n = 0;
    for (auto it = impl_->grants.begin(); it != impl_->grants.end();) {
        if (Impl::expired(it->second)) {
            it = impl_->grants.erase(it);
            ++n;
        } else {
            ++it;
        }
    }
    return n;
}

std::vector<CapabilityGrant> PermissionStore::list() const {
    std::vector<CapabilityGrant> out;
    out.reserve(impl_->grants.size());
    for (const auto& [id, g] : impl_->grants) out.push_back(g);
    return out;
}

} // namespace pm::security
