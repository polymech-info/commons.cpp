#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace pm::security {

enum class VerificationLevel {
    None,
    Presence,
    LocalUnlock,
    Strong,
    ExportSecret,
};

enum class VerificationResult {
    Success,
    Cancelled,
    Timeout,
    NotConfigured,
    Failed,
};

enum class PrivilegeRequirement {
    None,
    AdminPreferred,
    AdminRequired,
    SystemBrokerRequired,
};

struct VerificationOptions {
    VerificationLevel level = VerificationLevel::None;
    std::string reason;
    std::chrono::milliseconds timeout{0};
};

class IUserVerificationProvider {
public:
    virtual ~IUserVerificationProvider() = default;
    virtual VerificationResult verify(const VerificationOptions& options) = 0;
};

struct OperationVerificationPolicy {
    std::string operation;
    VerificationLevel level = VerificationLevel::None;
    PrivilegeRequirement privilege = PrivilegeRequirement::None;
    std::string reason;
};

struct OperationGuardOptions {
    std::string operation;
    std::chrono::milliseconds verification_ttl{std::chrono::minutes(10)};
    std::chrono::milliseconds verification_timeout{0};
    bool assume_privilege_satisfied = false;
};

struct OperationGuardResult {
    bool allowed = false;
    bool verification_required = false;
    bool verification_cache_hit = false;
    bool privilege_satisfied = true;
    VerificationLevel level = VerificationLevel::None;
    VerificationResult verification = VerificationResult::Success;
    PrivilegeRequirement privilege = PrivilegeRequirement::None;
    std::string operation;
    std::string reason;
    std::string error;
};

class VerificationSessionCache {
public:
    using Clock = std::chrono::steady_clock;

    bool has_valid(std::string_view operation, VerificationLevel level, Clock::time_point now = Clock::now()) const;
    void grant(std::string_view operation,
               VerificationLevel level,
               std::chrono::milliseconds ttl,
               Clock::time_point now = Clock::now());
    void clear();
    std::size_t size() const noexcept;

private:
    struct Entry {
        Clock::time_point expires_at;
    };

    static std::string cache_key(std::string_view operation, VerificationLevel level);
    std::unordered_map<std::string, Entry> entries_;
};

class NullUserVerificationProvider final : public IUserVerificationProvider {
public:
    VerificationResult verify(const VerificationOptions& options) override;
};

class MockUserVerificationProvider final : public IUserVerificationProvider {
public:
    explicit MockUserVerificationProvider(VerificationResult result = VerificationResult::Success)
        : result_(result) {}
    VerificationResult verify(const VerificationOptions& options) override;

private:
    VerificationResult result_ = VerificationResult::Success;
};

std::string_view to_string(VerificationLevel level) noexcept;
std::string_view to_string(VerificationResult result) noexcept;
std::string_view to_string(PrivilegeRequirement requirement) noexcept;
std::optional<VerificationLevel> verification_level_from_string(std::string_view value);
std::optional<VerificationResult> verification_result_from_string(std::string_view value);
std::optional<PrivilegeRequirement> privilege_requirement_from_string(std::string_view value);

std::vector<OperationVerificationPolicy> default_operation_verification_policies();
VerificationLevel default_verification_level_for_operation(std::string_view operation);
PrivilegeRequirement default_privilege_requirement_for_operation(std::string_view operation);

VerificationResult request_user_verification(IUserVerificationProvider& provider,
                                             std::string_view reason,
                                             VerificationLevel level,
                                             std::chrono::milliseconds timeout = {});

OperationGuardResult ensure_operation_allowed(IUserVerificationProvider& provider,
                                              VerificationSessionCache& cache,
                                              OperationGuardOptions options);

} // namespace pm::security
