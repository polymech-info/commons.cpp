#include "policy/PolicyProvider.hpp"

#if defined(_WIN32)

#include "host/services.hpp"

#include <windows.h>

#include <sstream>
#include <stdexcept>
#include <vector>

namespace pm::policy {

namespace {

const wchar_t* policy_root()
{
    return pm::commons::host::policy_registry_root().c_str();
}

std::wstring utf8_to_wide(std::string_view s)
{
    if (s.empty())
        return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                        nullptr, 0);
    if (n <= 0)
        return std::wstring(s.begin(), s.end());
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string wide_to_utf8(std::wstring_view w)
{
    if (w.empty())
        return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

HKEY hive_handle(RegistryHive h) {
    return h == RegistryHive::HKLM ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
}

// Convert dot-notation key "A.B.C" → subkey L"A\\B", value name L"C".
void split_key(std::string_view key,
               std::wstring& subkey_out,
               std::wstring& value_out) {
    const auto last_dot = key.rfind('.');
    std::string subkey_part;
    std::string value_part;
    if (last_dot == std::string_view::npos) {
        value_part = std::string(key);
    } else {
        subkey_part = std::string(key.substr(0, last_dot));
        value_part  = std::string(key.substr(last_dot + 1));
        // Replace dots with backslashes in the subkey part
        for (auto& c : subkey_part)
            if (c == '.') c = '\\';
    }
    subkey_out = utf8_to_wide(subkey_part);
    value_out  = utf8_to_wide(value_part);
}

// Build the full subkey path under the policy root.
std::wstring full_subkey(const std::wstring& relative) {
    if (relative.empty()) return std::wstring(policy_root());
    return std::wstring(policy_root()) + L"\\" + relative;
}

// Open a registry key, returns nullptr on failure (caller must close).
HKEY open_key(HKEY root, const std::wstring& path) {
    HKEY h = nullptr;
    RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &h);
    return h; // nullptr if not found
}

std::optional<DWORD> read_dword(HKEY root, const std::wstring& path, const std::wstring& name) {
    HKEY h = open_key(root, path);
    if (!h) return std::nullopt;
    DWORD val = 0, size = sizeof(val), type = 0;
    const LSTATUS st = RegQueryValueExW(h, name.c_str(), nullptr, &type,
                                        reinterpret_cast<LPBYTE>(&val), &size);
    RegCloseKey(h);
    if (st != ERROR_SUCCESS || type != REG_DWORD) return std::nullopt;
    return val;
}

std::optional<std::string> read_sz(HKEY root, const std::wstring& path, const std::wstring& name) {
    HKEY h = open_key(root, path);
    if (!h) return std::nullopt;
    DWORD size = 0, type = 0;
    LSTATUS st = RegQueryValueExW(h, name.c_str(), nullptr, &type, nullptr, &size);
    if (st != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(h);
        return std::nullopt;
    }
    std::vector<WCHAR> buf(size / sizeof(WCHAR) + 1, L'\0');
    st = RegQueryValueExW(h, name.c_str(), nullptr, &type,
                          reinterpret_cast<LPBYTE>(buf.data()), &size);
    RegCloseKey(h);
    if (st != ERROR_SUCCESS) return std::nullopt;
    return wide_to_utf8(buf.data());
}

std::optional<std::vector<std::string>> read_multi_sz(HKEY root,
                                                       const std::wstring& path,
                                                       const std::wstring& name) {
    HKEY h = open_key(root, path);
    if (!h) return std::nullopt;
    DWORD size = 0, type = 0;
    LSTATUS st = RegQueryValueExW(h, name.c_str(), nullptr, &type, nullptr, &size);
    if (st != ERROR_SUCCESS || type != REG_MULTI_SZ) {
        RegCloseKey(h);
        return std::nullopt;
    }
    std::vector<WCHAR> buf(size / sizeof(WCHAR) + 2, L'\0');
    st = RegQueryValueExW(h, name.c_str(), nullptr, &type,
                          reinterpret_cast<LPBYTE>(buf.data()), &size);
    RegCloseKey(h);
    if (st != ERROR_SUCCESS) return std::nullopt;
    std::vector<std::string> result;
    const WCHAR* p = buf.data();
    while (p && *p) {
        const std::wstring ws(p);
        if (!ws.empty())
            result.emplace_back(wide_to_utf8(ws));
        p += ws.size() + 1;
    }
    return result;
}

// Recursively enumerate all values under a key tree into a flat dot-notation JSON object.
// reg_path  : full registry path from the hive root (e.g. policy_root() + "\\Agent\\Tools")
// dot_prefix: the dot-notation prefix so far (e.g. "Agent.Tools"); empty at the root.
void enum_values_recursive(HKEY hive,
                           const std::wstring& reg_path,
                           const std::string&  dot_prefix,
                           nlohmann::json&     out) {
    HKEY h = open_key(hive, reg_path);
    if (!h) return;

    // Enumerate values in this key
    for (DWORD idx = 0; ; ++idx) {
        WCHAR vname[256]; DWORD vname_len = 256;
        DWORD type = 0, data_size = 0;
        if (RegEnumValueW(h, idx, vname, &vname_len,
                          nullptr, &type, nullptr, &data_size) != ERROR_SUCCESS)
            break;
        const std::string vn = wide_to_utf8(std::wstring_view(vname, wcslen(vname)));
        const std::string dot_key = dot_prefix.empty() ? vn : dot_prefix + "." + vn;

        if (type == REG_DWORD) {
            DWORD val = 0; DWORD sz = sizeof(val);
            if (RegQueryValueExW(h, vname, nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(&val), &sz) == ERROR_SUCCESS)
                out[dot_key] = {{"value", static_cast<int>(val)}, {"type", "dword"}};
        } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
            std::vector<WCHAR> buf(data_size / sizeof(WCHAR) + 1, L'\0');
            DWORD sz = data_size;
            if (RegQueryValueExW(h, vname, nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(buf.data()), &sz) == ERROR_SUCCESS) {
                const std::wstring ws(buf.data(), buf.data() + wcslen(buf.data()));
                out[dot_key] = {{"value", wide_to_utf8(ws)}, {"type", "sz"}};
            }
        } else if (type == REG_MULTI_SZ) {
            std::vector<WCHAR> buf(data_size / sizeof(WCHAR) + 2, L'\0');
            DWORD sz = data_size;
            if (RegQueryValueExW(h, vname, nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(buf.data()), &sz) == ERROR_SUCCESS) {
                nlohmann::json arr = nlohmann::json::array();
                for (const WCHAR* p = buf.data(); p && *p; p += wcslen(p) + 1)
                    arr.push_back(wide_to_utf8(std::wstring_view(p, wcslen(p))));
                out[dot_key] = {{"value", arr}, {"type", "multi_sz"}};
            }
        }
    }

    // Enumerate subkeys and recurse
    for (DWORD idx = 0; ; ++idx) {
        WCHAR sname[256]; DWORD sname_len = 256;
        if (RegEnumKeyExW(h, idx, sname, &sname_len,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        const std::wstring child_path = reg_path + L"\\" + sname;
        const std::string  child_sn = wide_to_utf8(std::wstring_view(sname, wcslen(sname)));
        const std::string  child_prefix = dot_prefix.empty()
                                          ? child_sn
                                          : dot_prefix + "." + child_sn;
        enum_values_recursive(hive, child_path, child_prefix, out);
    }
    RegCloseKey(h);
}

} // namespace

// ── RegistryPolicyProvider ────────────────────────────────────────────────────

RegistryPolicyProvider::RegistryPolicyProvider(RegistryHive hive) : hive_(hive) {}

const char* RegistryPolicyProvider::source_name() const noexcept {
    return hive_ == RegistryHive::HKLM ? "hklm" : "hkcu";
}

std::optional<int> RegistryPolicyProvider::get_int(std::string_view key) const {
    std::wstring subkey, value;
    split_key(key, subkey, value);
    const auto v = read_dword(hive_handle(hive_), full_subkey(subkey), value);
    if (!v) return std::nullopt;
    return static_cast<int>(*v);
}

std::optional<std::string> RegistryPolicyProvider::get_str(std::string_view key) const {
    std::wstring subkey, value;
    split_key(key, subkey, value);
    return read_sz(hive_handle(hive_), full_subkey(subkey), value);
}

std::optional<std::vector<std::string>>
RegistryPolicyProvider::get_multi(std::string_view key) const {
    std::wstring subkey, value;
    split_key(key, subkey, value);
    return read_multi_sz(hive_handle(hive_), full_subkey(subkey), value);
}

bool RegistryPolicyProvider::is_present() const {
    HKEY h = open_key(hive_handle(hive_), policy_root());
    if (!h) return false;
    RegCloseKey(h);
    return true;
}
nlohmann::json RegistryPolicyProvider::read_all_json() const {
    nlohmann::json out = nlohmann::json::object();
    enum_values_recursive(hive_handle(hive_), policy_root(), std::string{}, out);
    return out;
}

} // namespace pm::policy

#endif // _WIN32
