#include "library_utils.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif !defined(__wasm__)
#include <dlfcn.h>
#endif

namespace media::library {
namespace {

// ---------------------------------------------------------------------------
// Expand ${ENV:VAR} tokens in a path string using std::getenv.
// Any unknown / empty env var causes the function to return an empty string
// so callers can silently skip the directory.
std::string expand_env_tokens(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ) {
        if (i + 1 < in.size() && in[i] == '$' && in[i + 1] == '{') {
            const std::size_t key_start = i + 2;
            std::size_t k = key_start;
            while (k < in.size() && in[k] != '}') ++k;
            if (k >= in.size())
                return {};  // malformed — skip
            const std::string key = in.substr(key_start, k - key_start);
            if (key.rfind("ENV:", 0) == 0) {
                const char* val = std::getenv(key.c_str() + 4);
                if (!val || !*val)
                    return {};  // env var absent or empty — skip dir
                out += val;
            } else {
                return {};  // unsupported token type — skip
            }
            i = k + 1;
            continue;
        }
        out += in[i];
        ++i;
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------

bool probe(const std::string& name) noexcept
{
#if defined(_WIN32)
    if (name.empty()) return false;
    const int wlen = ::MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring wname(static_cast<size_t>(wlen - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, wname.data(), wlen);
    HMODULE h = ::LoadLibraryExW(wname.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) return false;
    ::FreeLibrary(h);
    return true;
#elif !defined(__wasm__)
    // On macOS and Linux use dlopen.  RTLD_NOLOAD avoids loading a new library
    // (fast, no side effects); if that fails we try a real load so that
    // libraries on DYLD_LIBRARY_PATH / LD_LIBRARY_PATH are also detected.
    if (name.empty()) return false;
    void* h = ::dlopen(name.c_str(), RTLD_LAZY | RTLD_NOLOAD);
    if (h) { ::dlclose(h); return true; }
    h = ::dlopen(name.c_str(), RTLD_LAZY);
    if (h) { ::dlclose(h); return true; }
    return false;
#else
    (void)name;
    return false;
#endif
}

// ---------------------------------------------------------------------------

bool probe_loadable(
    const std::string& name,
    const std::string& search_dir,
    std::uint32_t* os_error) noexcept
{
#if defined(_WIN32)
    ::SetLastError(ERROR_SUCCESS);
#endif
    void* handle = load(name, search_dir);
    if (!handle) {
#if defined(_WIN32)
        if (os_error)
            *os_error = static_cast<std::uint32_t>(::GetLastError());
#else
        if (os_error)
            *os_error = 0;
#endif
        return false;
    }
    if (os_error)
        *os_error = 0;
    unload(handle);
    return true;
}

// ---------------------------------------------------------------------------

void* load(const std::string& name, const std::string& search_dir) noexcept
{
#if defined(_WIN32)
    if (name.empty()) return nullptr;

    auto to_wide = [](const std::string& s) -> std::wstring {
        if (s.empty()) return {};
        const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        if (n <= 0) return {};
        std::wstring w(static_cast<size_t>(n - 1), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
        return w;
    };

    // Try explicit path first.
    if (!search_dir.empty()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::path full = fs::path(search_dir) / name;
        const std::wstring wfull = full.wstring();
        HMODULE h = ::LoadLibraryExW(wfull.c_str(), nullptr,
                                     LOAD_WITH_ALTERED_SEARCH_PATH);
        if (h) return static_cast<void*>(h);
    }

    // Fall back to default search paths.
    const std::wstring wname = to_wide(name);
    if (wname.empty()) return nullptr;
    HMODULE h = ::LoadLibraryExW(wname.c_str(), nullptr,
                                 LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
                                 LOAD_LIBRARY_SEARCH_USER_DIRS);
    return static_cast<void*>(h);
#elif !defined(__wasm__)
    if (name.empty()) return nullptr;
    if (!search_dir.empty()) {
        namespace fs = std::filesystem;
        fs::path full = fs::path(search_dir) / name;
        void* h = ::dlopen(full.c_str(), RTLD_LAZY);
        if (h) return h;
    }
    return ::dlopen(name.c_str(), RTLD_LAZY);
#else
    (void)name; (void)search_dir;
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------

void* sym(void* handle, const std::string& symbol) noexcept
{
#if defined(_WIN32)
    if (!handle || symbol.empty()) return nullptr;
    return reinterpret_cast<void*>(
        ::GetProcAddress(static_cast<HMODULE>(handle), symbol.c_str()));
#elif !defined(__wasm__)
    if (!handle || symbol.empty()) return nullptr;
    return ::dlsym(handle, symbol.c_str());
#else
    (void)handle; (void)symbol;
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------

void unload(void* handle) noexcept
{
#if defined(_WIN32)
    if (handle)
        ::FreeLibrary(static_cast<HMODULE>(handle));
#elif !defined(__wasm__)
    if (handle)
        ::dlclose(handle);
#else
    (void)handle;
#endif
}

// ---------------------------------------------------------------------------

void add_search_dir(const std::string& dir) noexcept
{
#if defined(_WIN32)
    if (dir.empty()) return;

    const std::string resolved = expand_env_tokens(dir);
    if (resolved.empty()) return;

    // Verify the directory exists before registering.
    {
        std::error_code ec;
        if (!std::filesystem::is_directory(resolved, ec) || ec)
            return;
    }

    const int wlen = ::MultiByteToWideChar(CP_UTF8, 0, resolved.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return;
    std::wstring wdir(static_cast<size_t>(wlen - 1), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, resolved.c_str(), -1, wdir.data(), wlen);

    // Resolve AddDllDirectory at first call — Win8+; graceful no-op on older Windows.
    using AddDllDirectory_t = DLL_DIRECTORY_COOKIE(WINAPI*)(PCWSTR);
    static AddDllDirectory_t s_add = []() -> AddDllDirectory_t {
        HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
        if (!k32) return nullptr;
        return reinterpret_cast<AddDllDirectory_t>(
            ::GetProcAddress(k32, "AddDllDirectory"));
    }();

    if (s_add) s_add(wdir.c_str());
#else
    (void)dir;
#endif
}

} // namespace media::library
