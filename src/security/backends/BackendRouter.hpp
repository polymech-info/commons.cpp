#pragma once
//
// pm::security — BackendRouter: name → SandboxBackend registry.
//
// The gateway is the single choke point for *whether* a request is allowed and,
// when allowed, *which* sandbox (if any) must run it. The router is the lookup
// table that turns PolicyDecision::sandboxBackend (a name like "appcontainer")
// into a concrete SandboxBackend* to spawn through.
//
// Backends are borrowed, not owned — they are typically process-lifetime
// statics registered once at startup (SandboxAppContainer on Win32). Keeping
// ownership outside the router lets platform-specific backends live behind
// their own #ifdef without leaking into this portable header.
//
// Design reference: docs/security/security.md § "Sandbox backends".
//

#include "security/backends/SandboxBackend.hpp"

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace pm::security {

class BackendRouter {
public:
    /// Register under the backend's own name() (e.g. "appcontainer").
    void registerBackend(SandboxBackend* backend) {
        if (backend) m_backends[backend->name()] = backend;
    }

    /// Register under an explicit name (alias / override).
    void registerBackend(const std::string& name, SandboxBackend* backend) {
        if (backend && !name.empty()) m_backends[name] = backend;
    }

    /// Resolve a backend by name; nullptr when not registered or name empty.
    SandboxBackend* resolve(const std::string& name) const {
        if (name.empty()) return nullptr;
        const auto it = m_backends.find(name);
        return it == m_backends.end() ? nullptr : it->second;
    }

    bool        has(const std::string& name) const { return resolve(name) != nullptr; }
    void        clear()       { m_backends.clear(); }
    std::size_t size() const  { return m_backends.size(); }

    std::vector<std::string> names() const {
        std::vector<std::string> out;
        out.reserve(m_backends.size());
        for (const auto& [name, backend] : m_backends)
            if (backend) out.push_back(name);
        return out;
    }

private:
    std::unordered_map<std::string, SandboxBackend*> m_backends;
};

} // namespace pm::security
