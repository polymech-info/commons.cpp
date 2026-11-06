#include "app_storage.hpp"
#include "fs/path_sanitizer.hpp"

#include "pm_branding_config.hpp"

#if !defined(_WIN32)

#include <cstdlib>
#include <string>

namespace pm::appdata {
namespace {

std::filesystem::path home_dir()
{
    if (const char* home = std::getenv("HOME"); home && home[0])
        return media::path::path_from_utf8(home);
    return {};
}

std::filesystem::path xdg_or(const char* env_name, const char* fallback_child)
{
    if (const char* value = std::getenv(env_name); value && value[0])
        return media::path::path_from_utf8(value);
    const auto home = home_dir();
    if (home.empty())
        return {};
    return home / fallback_child;
}

std::filesystem::path config_child()
{
    std::string sub = pm::brand::k_config_subpath_u8;
    for (char& c : sub) {
        if (c == '\\')
            c = '/';
    }
    return media::path::path_from_utf8(sub);
}

} // namespace

bool is_packaged()
{
    return false;
}

bool uses_package_appdata()
{
    return false;
}

std::wstring package_family_name()
{
    return {};
}

std::filesystem::path portable_roaming_default()
{
    const auto base = xdg_or("XDG_CONFIG_HOME", ".config");
    if (base.empty())
        return {};
    return base / config_child();
}

std::filesystem::path portable_local_default()
{
    const auto base = xdg_or("XDG_CACHE_HOME", ".cache");
    if (base.empty())
        return {};
    return base / config_child();
}

std::filesystem::path local_state()
{
    return portable_roaming_default();
}

std::filesystem::path local_cache()
{
    return portable_local_default();
}

} // namespace pm::appdata

#else

#include <Windows.h>
#include <appmodel.h>
#include <shlobj.h>

#include <cwchar>

namespace pm::appdata {

namespace {

// `Packages\<family>\` lives under FOLDERID_LocalAppData for the current user.
std::filesystem::path local_app_data()
{
    PWSTR path_tmp = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path_tmp)))
        return {};
    std::filesystem::path path(path_tmp);
    CoTaskMemFree(path_tmp);
    return path;
}

std::filesystem::path roaming_app_data()
{
    PWSTR path_tmp = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path_tmp)))
        return {};
    std::filesystem::path path(path_tmp);
    CoTaskMemFree(path_tmp);
    return path;
}

// Full package name has the shape `Name_Version_Arch_ResourceId_PublisherId`
// (ResourceId is often empty, giving a `__` before the publisher hash). The
// package identity Name cannot contain underscores, so splitting on `_` is
// unambiguous: family = Name + "_" + PublisherId (the first and last segments).
std::wstring family_name_from_full(const std::wstring& full)
{
    if (full.empty())
        return {};
    const auto first = full.find(L'_');
    if (first == std::wstring::npos)
        return {};
    const auto last = full.rfind(L'_');
    if (last == std::wstring::npos || last <= first)
        return {};
    return full.substr(0, first) + L"_" + full.substr(last + 1);
}

} // namespace

bool is_packaged()
{
    static const bool cached = [] {
        UINT32 len = 0;
        return ::GetCurrentPackageFullName(&len, nullptr) != APPMODEL_ERROR_NO_PACKAGE;
    }();
    return cached;
}

std::wstring package_family_name()
{
    static const std::wstring cached = []() -> std::wstring {
        UINT32 len = 0;
        const LONG rc = ::GetCurrentPackageFullName(&len, nullptr);
        if (rc == APPMODEL_ERROR_NO_PACKAGE)
            return {};
        // rc is ERROR_INSUFFICIENT_BUFFER; len is the required size in wchar_t (incl. NUL).
        std::wstring full(len, L'\0');
        UINT32 out_len = len;
        if (::GetCurrentPackageFullName(&out_len, full.data()) != ERROR_SUCCESS)
            return {};
        while (!full.empty() && full.back() == L'\0')
            full.pop_back();
        return family_name_from_full(full);
    }();
    return cached;
}

namespace {

// Sparse Win11 compact-menu packages (desktop5:FileExplorerContextMenus) use
// AllowExternalContent + Application Executable=tanit.exe, so launching the
// installed exe reports a package identity. That must not redirect settings.
bool is_explorer11_sparse_family(const std::wstring& family)
{
    // e.g. PolyMech.tanit.Explorer11_<publisher>, PolyMech.tanit-viewer.Explorer11_…
    return family.find(L".Explorer11_") != std::wstring::npos;
}

} // namespace

bool uses_package_appdata()
{
    if (!is_packaged())
        return false;
    const auto family = package_family_name();
    if (family.empty() || is_explorer11_sparse_family(family))
        return false;
    return true;
}

std::filesystem::path portable_roaming_default()
{
    const auto base = roaming_app_data();
    if (base.empty())
        return {};
    return base / pm::brand::k_config_subpath_w;
}

std::filesystem::path portable_local_default()
{
    const auto base = local_app_data();
    if (base.empty())
        return {};
    return base / pm::brand::k_config_subpath_w;
}

std::filesystem::path local_state()
{
    if (!uses_package_appdata())
        return portable_roaming_default();
    const auto family = package_family_name();
    if (family.empty())
        return portable_roaming_default();
    const auto base = local_app_data();
    if (base.empty())
        return {};
    return base / "Packages" / family / "LocalState";
}

std::filesystem::path local_cache()
{
    if (!uses_package_appdata())
        return portable_local_default();
    const auto family = package_family_name();
    if (family.empty())
        return portable_local_default();
    const auto base = local_app_data();
    if (base.empty())
        return {};
    return base / "Packages" / family / "LocalCache";
}

} // namespace pm::appdata

#endif // !_WIN32
