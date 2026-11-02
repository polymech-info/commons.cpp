#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace pm::policy {

// ── IPolicyProvider ────────────────────────────────────────────────────────────
//
// Flat dot-notation key → value lookup.  e.g. "Agent.Tools.BlockList".
// Returns nullopt when the provider has no opinion on a key.
// EffectivePolicy merges providers: last pushed = highest priority.

class IPolicyProvider {
public:
    virtual ~IPolicyProvider() = default;
    virtual const char*                             source_name() const noexcept = 0;
    virtual std::optional<int>                      get_int  (std::string_view key) const = 0;
    virtual std::optional<std::string>              get_str  (std::string_view key) const = 0;
    virtual std::optional<std::vector<std::string>> get_multi(std::string_view key) const = 0;
};

// ── EffectivePolicy ────────────────────────────────────────────────────────────

struct PolicyValueWithSource {
    std::string value;  // always the string form
    std::string source; // provider source_name()
};

class EffectivePolicy {
public:
    // Push in ascending priority order: first = lowest, last = highest.
    void push_back(std::shared_ptr<IPolicyProvider> provider);

    std::optional<int>                      get_int  (std::string_view key) const;
    std::optional<std::string>              get_str  (std::string_view key) const;
    std::optional<std::vector<std::string>> get_multi(std::string_view key) const;

    int  get_int_or (std::string_view key, int  fallback = 1) const;
    bool is_enabled (std::string_view key, bool def = true)   const;
    std::vector<std::string> get_multi_or(std::string_view key,
                                          std::vector<std::string> def = {}) const;

    std::optional<PolicyValueWithSource> get_str_with_source(std::string_view key) const;
    std::optional<PolicyValueWithSource> get_int_with_source(std::string_view key) const;

    // Dump a JSON object { key: { value, source, type } } for the given keys.
    nlohmann::json dump_json(const std::vector<std::string>& keys) const;

private:
    // Stored in reverse priority (index 0 = highest).
    std::vector<std::shared_ptr<IPolicyProvider>> providers_;
};

// ── BuiltinPolicyProvider ──────────────────────────────────────────────────────
// Compiled-in defaults.  Never returns nullopt for a known key.

class BuiltinPolicyProvider final : public IPolicyProvider {
public:
    const char*                             source_name() const noexcept override { return "builtin"; }
    std::optional<int>                      get_int  (std::string_view key) const override;
    std::optional<std::string>              get_str  (std::string_view key) const override;
    std::optional<std::vector<std::string>> get_multi(std::string_view key) const override;
};

// ── RegistryPolicyProvider ─────────────────────────────────────────────────────
// Reads HKCU or HKLM under Software\Policies\<PM_BRAND_VENDOR>\<PM_APP_ID_SLUG>
// (see pm::brand::k_reg_policy_root_w from pm_branding_config.hpp).
// No-op stubs on non-Windows.

enum class RegistryHive { HKCU, HKLM };

class RegistryPolicyProvider final : public IPolicyProvider {
public:
    explicit RegistryPolicyProvider(RegistryHive hive);
    const char*                             source_name() const noexcept override;
    std::optional<int>                      get_int  (std::string_view key) const override;
    std::optional<std::string>              get_str  (std::string_view key) const override;
    std::optional<std::vector<std::string>> get_multi(std::string_view key) const override;

    bool           is_present   () const; // true if root key exists
    nlohmann::json read_all_json() const; // all values for 'gpo read'

private:
    RegistryHive hive_;
};

// ── Factory ────────────────────────────────────────────────────────────────────

// Standard stack: Builtin < HKCU < HKLM (HKLM wins).
EffectivePolicy make_default_policy();

// All dot-notation policy keys known to this build.
const std::vector<std::string>& known_policy_keys();

} // namespace pm::policy
