#include "policy/PolicyProvider.hpp"
#include "policy/policy_catalog.hpp"

#include <algorithm>
#include <cstddef>
#include <string>

namespace pm::policy {

// ── known_policy_keys ──────────────────────────────────────────────────────────
//
// Derived entirely from the single-source policy_catalog(). No hand-maintained
// list — adding a row to policy_catalog.cpp is the only place a key is declared.

const std::vector<std::string>& known_policy_keys() {
    static const std::vector<std::string> k_keys = [] {
        std::vector<std::string> keys;
        const auto& cat = policy_catalog();
        keys.reserve(cat.size());
        for (const auto& e : cat)
            keys.push_back(e.key);
        return keys;
    }();
    return k_keys;
}

// ── BuiltinPolicyProvider ──────────────────────────────────────────────────────
//
// Compile-time defaults come straight from the catalog descriptor (type +
// default_on), so polarity / defaults never drift from the ADMX template.

namespace {

// Returns the compile-time default int for a known bool key, or -2 otherwise.
int builtin_int(std::string_view key) {
    const PolicyEntry* e = policy_find(key);
    if (!e || e->type != PolicyType::Bool)
        return -2;
    return e->default_on ? 1 : 0;
}

bool is_multi_key(std::string_view key) {
    const PolicyEntry* e = policy_find(key);
    return e && e->type == PolicyType::Multi;
}

bool is_str_key(std::string_view key) {
    const PolicyEntry* e = policy_find(key);
    return e && (e->type == PolicyType::Str ||
                 e->type == PolicyType::VerEnum ||
                 e->type == PolicyType::EnumStr);
}

} // namespace

std::optional<int> BuiltinPolicyProvider::get_int(std::string_view key) const {
    const int v = builtin_int(key);
    if (v == -2) return std::nullopt;
    return v;
}

std::optional<std::string> BuiltinPolicyProvider::get_str(std::string_view key) const {
    if (!is_str_key(key)) return std::nullopt;
    return std::string{}; // empty = "use compiled default"
}

std::optional<std::vector<std::string>> BuiltinPolicyProvider::get_multi(std::string_view key) const {
    if (!is_multi_key(key)) return std::nullopt;
    return std::vector<std::string>{}; // empty = no restriction
}

// ── EffectivePolicy ────────────────────────────────────────────────────────────

void EffectivePolicy::push_back(std::shared_ptr<IPolicyProvider> provider) {
    providers_.insert(providers_.begin(), std::move(provider));
}

std::optional<int> EffectivePolicy::get_int(std::string_view key) const {
    for (const auto& p : providers_) {
        if (auto v = p->get_int(key)) return v;
    }
    return std::nullopt;
}

std::optional<std::string> EffectivePolicy::get_str(std::string_view key) const {
    for (const auto& p : providers_) {
        if (auto v = p->get_str(key)) return v;
    }
    return std::nullopt;
}

std::optional<std::vector<std::string>> EffectivePolicy::get_multi(std::string_view key) const {
    for (const auto& p : providers_) {
        if (auto v = p->get_multi(key)) return v;
    }
    return std::nullopt;
}

int EffectivePolicy::get_int_or(std::string_view key, int fallback) const {
    return get_int(key).value_or(fallback);
}

bool EffectivePolicy::is_enabled(std::string_view key, bool def) const {
    return get_int(key).value_or(def ? 1 : 0) != 0;
}

std::vector<std::string> EffectivePolicy::get_multi_or(
        std::string_view key, std::vector<std::string> def) const {
    return get_multi(key).value_or(std::move(def));
}

std::optional<PolicyValueWithSource>
EffectivePolicy::get_str_with_source(std::string_view key) const {
    for (const auto& p : providers_) {
        if (auto v = p->get_str(key))
            return PolicyValueWithSource{*v, p->source_name()};
    }
    return std::nullopt;
}

std::optional<PolicyValueWithSource>
EffectivePolicy::get_int_with_source(std::string_view key) const {
    for (const auto& p : providers_) {
        if (auto v = p->get_int(key))
            return PolicyValueWithSource{std::to_string(*v), p->source_name()};
    }
    return std::nullopt;
}

nlohmann::json EffectivePolicy::dump_json(const std::vector<std::string>& keys) const {
    nlohmann::json out = nlohmann::json::object();
    for (const auto& k : keys) {
        // Try multi first, then int, then str
        if (auto mv = get_multi(k)) {
            std::string src = "builtin";
            for (const auto& p : providers_) {
                if (p->get_multi(k)) { src = p->source_name(); break; }
            }
            out[k] = {{"value", *mv}, {"source", src}, {"type", "multi"}};
            continue;
        }
        if (auto iv = get_int_with_source(k)) {
            out[k] = {{"value", std::stoi(iv->value)}, {"source", iv->source}, {"type", "int"}};
            continue;
        }
        if (auto sv = get_str_with_source(k)) {
            out[k] = {{"value", sv->value}, {"source", sv->source}, {"type", "str"}};
        }
    }
    return out;
}

// ── Factory ────────────────────────────────────────────────────────────────────

EffectivePolicy make_default_policy() {
    EffectivePolicy ep;
    ep.push_back(std::make_shared<BuiltinPolicyProvider>());
#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    ep.push_back(std::make_shared<RegistryPolicyProvider>(RegistryHive::HKCU));
    ep.push_back(std::make_shared<RegistryPolicyProvider>(RegistryHive::HKLM));
#endif
    return ep;
}

} // namespace pm::policy
