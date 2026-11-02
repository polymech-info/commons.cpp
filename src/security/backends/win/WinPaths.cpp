//
// pm::security backend (win32) — %LOCALAPPDATA% resolution.
//
// Provides detail::win_local_appdata() consumed by CryptoStore.cpp to build the
// security/ storage directory. Always compiled on Windows (cheap, no feature
// guard) so path resolution works even when the DPAPI/ACL backends are off.
//

#if defined(_WIN32)

#include "security/CryptoStore.hpp"

#include <cstdlib>
#include <filesystem>

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>   // SHGetKnownFolderPath
#include <knownfolders.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace pm::security::detail {

std::filesystem::path win_local_appdata() {
    PWSTR raw = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw)) && raw) {
        std::filesystem::path p(raw);
        CoTaskMemFree(raw);
        return p;
    }
    if (raw) CoTaskMemFree(raw);

    // Fallback to the environment variable.
    if (const wchar_t* env = _wgetenv(L"LOCALAPPDATA"); env && *env)
        return std::filesystem::path(env);
    return std::filesystem::temp_directory_path();
}

} // namespace pm::security::detail

#endif // _WIN32
