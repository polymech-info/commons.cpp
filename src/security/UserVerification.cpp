#include "security/UserVerification.hpp"

#include <algorithm>
#include <cctype>

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
#include "policy/app_policy.hpp"
#endif

namespace pm::security {

namespace {

std::string lower_ascii(std::string_view value) {
    std::string out(value.begin(), value.end());
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

} // namespace

VerificationResult NullUserVerificationProvider::verify(const VerificationOptions& options) {
    return options.level == VerificationLevel::None
        ? VerificationResult::Success
        : VerificationResult::NotConfigured;
}

VerificationResult MockUserVerificationProvider::verify(const VerificationOptions&) {
    return result_;
}

std::string_view to_string(VerificationLevel level) noexcept {
    switch (level) {
    case VerificationLevel::None: return "none";
    case VerificationLevel::Presence: return "presence";
    case VerificationLevel::LocalUnlock: return "local_unlock";
    case VerificationLevel::Strong: return "strong";
    case VerificationLevel::ExportSecret: return "export_secret";
    }
    return "none";
}

std::string_view to_string(VerificationResult result) noexcept {
    switch (result) {
    case VerificationResult::Success: return "success";
    case VerificationResult::Cancelled: return "cancelled";
    case VerificationResult::Timeout: return "timeout";
    case VerificationResult::NotConfigured: return "not_configured";
    case VerificationResult::Failed: return "failed";
    }
    return "failed";
}

std::string_view to_string(PrivilegeRequirement requirement) noexcept {
    switch (requirement) {
    case PrivilegeRequirement::None: return "none";
    case PrivilegeRequirement::AdminPreferred: return "admin_preferred";
    case PrivilegeRequirement::AdminRequired: return "admin_required";
    case PrivilegeRequirement::SystemBrokerRequired: return "system_broker_required";
    }
    return "none";
}

std::optional<VerificationLevel> verification_level_from_string(std::string_view value) {
    const std::string s = lower_ascii(value);
    if (s == "none") return VerificationLevel::None;
    if (s == "presence") return VerificationLevel::Presence;
    if (s == "local_unlock" || s == "local-unlock" || s == "localunlock") return VerificationLevel::LocalUnlock;
    if (s == "strong") return VerificationLevel::Strong;
    if (s == "export_secret" || s == "export-secret" || s == "exportsecret") return VerificationLevel::ExportSecret;
    return std::nullopt;
}

std::optional<VerificationResult> verification_result_from_string(std::string_view value) {
    const std::string s = lower_ascii(value);
    if (s == "success") return VerificationResult::Success;
    if (s == "cancelled" || s == "canceled") return VerificationResult::Cancelled;
    if (s == "timeout") return VerificationResult::Timeout;
    if (s == "not_configured" || s == "not-configured" || s == "notconfigured") return VerificationResult::NotConfigured;
    if (s == "failed" || s == "failure") return VerificationResult::Failed;
    return std::nullopt;
}

std::optional<PrivilegeRequirement> privilege_requirement_from_string(std::string_view value) {
    const std::string s = lower_ascii(value);
    if (s == "none") return PrivilegeRequirement::None;
    if (s == "admin_preferred" || s == "admin-preferred" || s == "adminpreferred") return PrivilegeRequirement::AdminPreferred;
    if (s == "admin_required" || s == "admin-required" || s == "adminrequired") return PrivilegeRequirement::AdminRequired;
    if (s == "system_broker_required" || s == "system-broker-required" || s == "systembrokerrequired") return PrivilegeRequirement::SystemBrokerRequired;
    return std::nullopt;
}

std::string VerificationSessionCache::cache_key(std::string_view operation, VerificationLevel level) {
    std::string key(operation);
    key.push_back('\n');
    key.append(to_string(level));
    return key;
}

bool VerificationSessionCache::has_valid(std::string_view operation,
                                         VerificationLevel level,
                                         Clock::time_point now) const {
    const auto it = entries_.find(cache_key(operation, level));
    return it != entries_.end() && it->second.expires_at > now;
}

void VerificationSessionCache::grant(std::string_view operation,
                                     VerificationLevel level,
                                     std::chrono::milliseconds ttl,
                                     Clock::time_point now) {
    if (level == VerificationLevel::None || ttl <= std::chrono::milliseconds::zero())
        return;
    entries_[cache_key(operation, level)] = Entry{now + ttl};
}

void VerificationSessionCache::clear() {
    entries_.clear();
}

std::size_t VerificationSessionCache::size() const noexcept {
    return entries_.size();
}

std::vector<OperationVerificationPolicy> default_operation_verification_policies() {
    auto policies = std::vector<OperationVerificationPolicy>{
        {"settings.load", VerificationLevel::None, PrivilegeRequirement::None, "Load local settings profile"},
        {"settings.save", VerificationLevel::None, PrivilegeRequirement::None, "Save local settings profile"},
        {"settings.update", VerificationLevel::None, PrivilegeRequirement::None, "Update local settings profile"},
        {"settings.importPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import settings from a plaintext file"},
        {"settings.exportPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Export settings as a plaintext file"},
        {"settings.exportEncrypted", VerificationLevel::Presence, PrivilegeRequirement::None, "Export encrypted settings"},

        {"oauthCredentials.load", VerificationLevel::None, PrivilegeRequirement::None, "Load local ZITADEL OAuth credentials"},
        // The completed OIDC browser flow already verified the user. Requiring
        // Windows Hello again makes token persistence fail on systems where
        // Hello is unavailable or not provisioned; DPAPI still protects the
        // stored encryption key. Managed installations can raise this via GPO.
        {"oauthCredentials.save", VerificationLevel::None, PrivilegeRequirement::None, "Save ZITADEL OAuth credentials after login"},
        {"oauthCredentials.clear", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Clear stored ZITADEL OAuth credentials"},

        {"commandConfig.load", VerificationLevel::None, PrivilegeRequirement::None, "Load local command configuration"},
        {"commandConfig.update", VerificationLevel::Presence, PrivilegeRequirement::None, "Update local command configuration"},
        {"commandConfig.importPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import commands from a plaintext file"},
        {"commandConfig.exportPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Export commands as a plaintext file"},

        {"mcpConfig.load", VerificationLevel::None, PrivilegeRequirement::None, "Load local MCP configuration"},
        {"mcpConfig.update", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Update local MCP configuration"},
        {"mcpConfig.importPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import MCP configuration from a plaintext file"},
        {"mcpConfig.exportPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Export MCP configuration as a plaintext file"},

        {"promptTemplate.load", VerificationLevel::None, PrivilegeRequirement::None, "Load local prompt templates"},
        {"promptTemplate.update", VerificationLevel::Presence, PrivilegeRequirement::None, "Update local prompt templates"},
        {"promptTemplate.importPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import prompt templates from plaintext files"},
        {"promptTemplate.exportPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Export prompt templates as plaintext files"},

        {"homePage.load", VerificationLevel::None, PrivilegeRequirement::None, "Load the signed home.page dashboard"},
        {"homePage.update", VerificationLevel::Presence, PrivilegeRequirement::None, "Update the signed home.page dashboard"},
        {"homePage.importPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import home.page from a plaintext file"},
        {"homePage.exportPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Export home.page as a plaintext file"},

        {"asset.load", VerificationLevel::None, PrivilegeRequirement::None, "Load a trusted local asset"},
        {"asset.save", VerificationLevel::None, PrivilegeRequirement::None, "Save a local profile asset"},
        {"asset.update", VerificationLevel::Presence, PrivilegeRequirement::None, "Update a local profile asset"},
        {"asset.importPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import a plaintext asset into secure storage"},
        {"asset.exportPlain", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Export a secure asset as plaintext"},
        {"asset.importVendorSeed", VerificationLevel::Presence, PrivilegeRequirement::None, "Import a signed vendor seed asset"},
        {"asset.importUntrusted", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Import an untrusted asset"},
        {"asset.exportBundle", VerificationLevel::Presence, PrivilegeRequirement::None, "Export an asset bundle"},
        {"asset.signSharedBundle", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Sign a shared asset bundle"},
        {"asset.installMachineWide", VerificationLevel::LocalUnlock, PrivilegeRequirement::AdminRequired, "Install asset data machine-wide"},

        {"localSigningKey.export", VerificationLevel::ExportSecret, PrivilegeRequirement::None, "Export a private local signing key"},
        {"permissions.grant.ReadSsh", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Grant access to SSH material"},
        {"permissions.grant.ExecutePowerShell", VerificationLevel::LocalUnlock, PrivilegeRequirement::None, "Grant PowerShell execution"},
        {"permissions.grant.ProgramFilesWrite", VerificationLevel::LocalUnlock, PrivilegeRequirement::AdminRequired, "Grant writes under Program Files"},
        {"service.install", VerificationLevel::Strong, PrivilegeRequirement::AdminRequired, "Install or update a Windows service"},
        {"registry.writeHklm", VerificationLevel::Strong, PrivilegeRequirement::AdminRequired, "Write machine-wide registry settings"},
    };

#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    // Apply GPO overrides: an admin can raise (but not lower) the verification level
    // for configurable operations via Security\Verification\* registry keys.
    for (auto& p : policies) {
        const auto override = pm::policy::policy_verification_level(p.operation);
        if (override.has_value())
            p.level = *override;  // admin-set value replaces compiled default unconditionally
    }
#endif

    return policies;
}

VerificationLevel default_verification_level_for_operation(std::string_view operation) {
    for (const auto& policy : default_operation_verification_policies()) {
        if (policy.operation == operation)
            return policy.level;
    }
    return VerificationLevel::None;
}

PrivilegeRequirement default_privilege_requirement_for_operation(std::string_view operation) {
    for (const auto& policy : default_operation_verification_policies()) {
        if (policy.operation == operation)
            return policy.privilege;
    }
    return PrivilegeRequirement::None;
}

VerificationResult request_user_verification(IUserVerificationProvider& provider,
                                             std::string_view reason,
                                             VerificationLevel level,
                                             std::chrono::milliseconds timeout) {
    if (level == VerificationLevel::None)
        return VerificationResult::Success;
    VerificationOptions options;
    options.level = level;
    options.reason.assign(reason.begin(), reason.end());
    options.timeout = timeout;
    return provider.verify(options);
}

OperationGuardResult ensure_operation_allowed(IUserVerificationProvider& provider,
                                              VerificationSessionCache& cache,
                                              OperationGuardOptions options) {
    OperationGuardResult result;
    result.operation = options.operation;

    OperationVerificationPolicy policy;
    policy.operation = options.operation;
    bool found = false;
    for (const auto& candidate : default_operation_verification_policies()) {
        if (candidate.operation == options.operation) {
            policy = candidate;
            found = true;
            break;
        }
    }

    result.level = policy.level;
    result.privilege = policy.privilege;
    result.reason = found ? policy.reason : std::string("Unconfigured operation");

    if ((policy.privilege == PrivilegeRequirement::AdminRequired ||
         policy.privilege == PrivilegeRequirement::SystemBrokerRequired) &&
        !options.assume_privilege_satisfied) {
        result.allowed = false;
        result.privilege_satisfied = false;
        result.error = "privilege requirement not satisfied: ";
        result.error.append(to_string(policy.privilege));
        return result;
    }

    result.verification_required = policy.level != VerificationLevel::None;
    if (!result.verification_required) {
        result.allowed = true;
        return result;
    }

    if (cache.has_valid(policy.operation, policy.level)) {
        result.allowed = true;
        result.verification_cache_hit = true;
        return result;
    }

    result.verification = request_user_verification(provider,
                                                   policy.reason,
                                                   policy.level,
                                                   options.verification_timeout);
    if (result.verification != VerificationResult::Success) {
        result.allowed = false;
        result.error = "user verification failed: ";
        result.error.append(to_string(result.verification));
        return result;
    }

    cache.grant(policy.operation, policy.level, options.verification_ttl);
    result.allowed = true;
    return result;
}

} // namespace pm::security
