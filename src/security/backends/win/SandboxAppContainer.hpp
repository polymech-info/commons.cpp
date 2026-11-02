#pragma once
//
// pm::security (Win32) — AppContainer / LPAC sandbox backend.
//
// Implements SandboxBackend using Windows AppContainer isolation
// (CreateAppContainerProfile + CreateProcessW with SECURITY_CAPABILITIES).
//
// Capabilities exposed:
//   spawn()       — Full lifecycle: profile, ACL grants, process, revoke.
//   grantPath()   — Add an AppContainer-SID ALLOW ACE to a path's DACL.
//   revokePath()  — Remove all AppContainer-SID ALLOW ACEs from a path DACL.
//   checkAccess() — Inspect a path DACL: does it contain the container SID?
//   containerSid()— Ensure profile exists, return S-1-15-2-... SID string.
//   deleteProfile()— DeleteAppContainerProfile for a moniker.
//
// Profile SIDs are cached in-process by moniker (deterministic hash, cross-
// session stable via DeriveAppContainerSidFromAppContainerName).
//
// Guard: compiled only when _WIN32 is defined.
// The CLI wires the flag FEATURE_SECURITY_SANDBOX separately.
//
// Design reference: docs/security/security.md § "Sandbox backends"
//

#if defined(_WIN32)

#include "security/backends/SandboxBackend.hpp"

#include <string>
#include <unordered_map>
#include <Windows.h>

namespace pm::security {

class SandboxAppContainer final : public SandboxBackend {
public:
    SandboxAppContainer();
    ~SandboxAppContainer() override;

    // SandboxBackend interface
    SandboxResult spawn(const SandboxSpawnOptions& opts) override;
    bool          grantPath(const std::string& moniker, const std::string& path,
                            const std::string& access) override;
    bool          revokePath(const std::string& moniker, const std::string& path) override;
    bool          checkAccess(const std::string& moniker, const std::string& path) override;
    std::string   containerSid(const std::string& moniker) override;
    bool          deleteProfile(const std::string& moniker) override;
    std::string   name() const override { return "appcontainer"; }

    // Discard all cached profile SIDs (call on shutdown or between test cases).
    void clearCache();

    // Last Win32 error code from the most recent failed operation.
    DWORD lastError() const { return m_lastError; }

private:
    // Ensure the AppContainer profile exists and return a borrowed PSID pointer
    // owned by the cache.  Returns nullptr on failure (m_lastError set).
    PSID  acquireSid(const std::string& moniker, bool* wasCreated = nullptr);

    // Low-level helpers (mirrors of the sandbox_impl statics in cli.cpp).
    static std::wstring toWide(const std::string& s);
    static std::string  sidToStr(PSID sid);
    static DWORD        grantPathImpl(const std::wstring& path, PSID sid,
                                      const std::string& access,
                                      GrantPropagation propagation);
    static DWORD        revokePathImpl(const std::wstring& path, PSID sid,
                                       GrantPropagation propagation);
    static bool         checkAccessImpl(const std::wstring& path, PSID sid);

    struct CachedProfile {
        PSID        sid        = nullptr;  // freed in clearCache / destructor
        std::string sidStr;
    };
    std::unordered_map<std::string, CachedProfile> m_cache;
    DWORD m_lastError = 0;
};

// Immediately tree-kill whichever sandboxed process is currently running (if
// any). Thread-safe; intended for the UI "Stop" button / external abort path,
// mirroring media::process::abort_captured_run() for the non-sandbox path.
// No-op when nothing is running. The in-flight spawn() observes the kill and
// returns with SandboxResult.cancelled = true.
void abort_active_sandbox();

} // namespace pm::security

#endif // _WIN32
