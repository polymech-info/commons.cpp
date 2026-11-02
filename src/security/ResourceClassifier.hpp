#pragma once
//
// pm::security::ResourceClassifier — multi-signal risk scoring for a resource.
//
// Combines path location, extension, secret patterns, OS-protected dirs, and
// workspace containment into a `ClassificationResult`. Signals are gathered
// through pluggable delegates (SecretPatternDelegate / ExtensionRiskDelegate)
// so the security-relevant predicate tables can migrate *out* of
// src/file_extensions.hpp without churning call sites
// (see docs/security/todos.md → "Delegate migration").
//
// Phase 1 (this file): default delegates backed by the built-in tables in
// types.hpp. MIME sniffing, content scans, and gitignore/workspace-trust are
// Phase 2+ TODOs.
//
// Design reference: docs/security/design.md ("Resource classifier").
//

#include "security/PathSecurity.hpp"
#include "security/types.hpp"

#include <memory>
#include <optional>

namespace pm::security {

class ResourceClassifier {
public:
    ResourceClassifier();
    ~ResourceClassifier();

    /// Swap the secret detector (e.g. for imported gitleaks/trufflehog rules).
    void setSecretDelegate(std::shared_ptr<SecretPatternDelegate> d);
    /// Swap the extension→risk mapper.
    void setExtensionRiskDelegate(std::shared_ptr<ExtensionRiskDelegate> d);

    /// Classify @p target for @p action. @p workspaceRoot (already canonical)
    /// drives the "outside workspace" signal when present.
    ClassificationResult classify(const ResourceTarget& target,
                                  Action action,
                                  const std::optional<CanonicalPath>& workspaceRoot = std::nullopt) const;

private:
    std::shared_ptr<SecretPatternDelegate> secret_;
    std::shared_ptr<ExtensionRiskDelegate> extRisk_;
    PathSecurity paths_;
};

// ── Default delegates (built-in tables) ──────────────────────────────────────

/// Default secret detector: matches basenames against `k_secret_basename_globs`
/// and path fragments against `k_high_risk_dir_fragments`.
class DefaultSecretPatternDelegate final : public SecretPatternDelegate {
public:
    bool isSecret(const ResourceTarget& target) const override;
};

/// Default extension→risk: shell-open/executable types are High, everything
/// else Low. Intentionally conservative; richer mapping is a follow-up.
class DefaultExtensionRiskDelegate final : public ExtensionRiskDelegate {
public:
    Risk riskForResource(const ResourceTarget& target) const override;
};

} // namespace pm::security
