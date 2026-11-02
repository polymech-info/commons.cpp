//
// pm::security backend (win32) — ACL-hardened security directory.
//
// Restricts %LOCALAPPDATA%/<App>/security to the current user so other local
// accounts cannot read the grant / audit databases. Same-user malware and
// administrators are explicitly out of scope (design.md "Non-goals").
//
// Compiled only when FEATURE_SECURITY_WIN_ACL is on.
//

#if defined(_WIN32)

#include "security/security_default.hpp"

#if FEATURE_SECURITY_WIN_ACL

#include "security/CryptoStore.hpp"

#include <filesystem>

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")

namespace pm::security::detail {

bool win_harden_dir(const std::filesystem::path& dir) {
    // TODO(security, Phase 2): build an explicit DACL granting only the current
    // user (token user SID) full control, disable inheritance, and apply via
    // SetNamedSecurityInfoW(PROTECTED_DACL_SECURITY_INFORMATION). For Phase 1 we
    // only confirm the directory exists; the directory already inherits the
    // user-profile ACL under %LOCALAPPDATA%.
    //
    //   HANDLE token; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    //   GetTokenInformation(token, TokenUser, ...);  // current user SID
    //   SetEntriesInAclW(1, &ea, nullptr, &dacl);    // user => FULL, no inherit
    //   SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
    //       DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
    //       nullptr, nullptr, dacl, nullptr);
    (void)dir;
    return std::filesystem::exists(dir);
}

} // namespace pm::security::detail

#endif // FEATURE_SECURITY_WIN_ACL
#endif // _WIN32
