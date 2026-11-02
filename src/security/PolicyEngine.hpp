#pragma once
//
// pm::security::PolicyEngine — compiled baseline policy + (later) signed bundle
// + user overrides.
//
// Trust order (design.md "Policy source"):
//   1. compiled built-in baseline policy   (this file, per Profile)
//   2. optional signed policy bundle        (Phase 3 TODO)
//   3. user overrides — may only TIGHTEN    (Phase 3 TODO)
//   4. runtime/session grants               (applied by SecurityGateway)
//
// The engine maps (profile, actor, action, classification) → a baseline
// DecisionKind. The gateway layers persisted/session grants on top.
//
// Design reference: docs/security/design.md ("Built-in profiles", "Policy source").
//

#include "security/types.hpp"

#include <string>

namespace pm::security {

/// Monotonic version string for the compiled baseline (stamped on grants/audit).
inline constexpr const char* k_policy_version = "builtin-1";

class PolicyEngine {
public:
    /// Baseline decision from compiled rules only (no grants). The gateway calls
    /// this first, then consults the PermissionStore for an Ask→Allow upgrade.
    PolicyDecision evaluateBaseline(const ToolRequest& request,
                                    const ClassificationResult& classification) const;

    /// The compiled policy version (see `k_policy_version`).
    std::string version() const { return k_policy_version; }

private:
    PolicyDecision evalLight(const ToolRequest&, const ClassificationResult&) const;
    PolicyDecision evalStrict(const ToolRequest&, const ClassificationResult&) const;
    PolicyDecision evalDeveloper(const ToolRequest&, const ClassificationResult&) const;
};

} // namespace pm::security
