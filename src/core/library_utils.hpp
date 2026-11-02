#pragma once
//
// Portable shared-library find / load / symbol-resolve utilities.
//
// Win32 implementation only for now; POSIX stubs compile cleanly but no-op / return nullptr.
//
// All functions are noexcept. Callers are responsible for logging based on return values.
//
// add_search_dir() accepts paths containing ${ENV:VAR} tokens — same syntax as
// command_variables.cpp — expanded via std::getenv before registering the directory.
//
#include <cstdint>
#include <string>

namespace media::library {

// ---------------------------------------------------------------------------
// probe — check whether a named library can be located by the OS loader.
// Does not execute any code from the library (LOAD_LIBRARY_AS_DATAFILE on Win32).
// Returns true if the library can be found, false otherwise.
bool probe(const std::string& name) noexcept;

// ---------------------------------------------------------------------------
// probe_loadable — verify that a library and its dependent libraries can load.
// Unlike probe(), this executes loader initialization before unloading.
bool probe_loadable(
    const std::string& name,
    const std::string& search_dir = {},
    std::uint32_t* os_error = nullptr) noexcept;

// ---------------------------------------------------------------------------
// load — load a shared library, returning an opaque handle or nullptr on failure.
// search_dir, if non-empty, is searched first (full path constructed as search_dir/name).
// Falls back to default OS loader paths when the explicit path fails or is empty.
// Win32: LoadLibraryExW with LOAD_WITH_ALTERED_SEARCH_PATH.
// POSIX: dlopen(RTLD_LAZY | RTLD_LOCAL).
void* load(const std::string& name, const std::string& search_dir = {}) noexcept;

// ---------------------------------------------------------------------------
// sym — resolve a named symbol from a handle returned by load().
// Returns nullptr if the symbol is absent or the handle is null.
// Win32: GetProcAddress.  POSIX: dlsym.
void* sym(void* handle, const std::string& symbol) noexcept;

// ---------------------------------------------------------------------------
// unload — release a handle returned by load().  No-op on nullptr.
// Win32: FreeLibrary.  POSIX: dlclose.
void unload(void* handle) noexcept;

// ---------------------------------------------------------------------------
// add_search_dir — register a directory with the OS loader search path for
// the *current* process.  Must be called before the first load() that needs
// the directory.
//
// dir may contain ${ENV:VAR} tokens; they are expanded via std::getenv.
// A token that expands to an empty string (env var absent) causes the whole
// call to be silently skipped.
//
// Win32: AddDllDirectory (Win8+); resolved via GetProcAddress on first call —
//        graceful no-op on older Windows.
// POSIX: no-op (use RPATH / LD_LIBRARY_PATH instead).
void add_search_dir(const std::string& dir) noexcept;

} // namespace media::library
