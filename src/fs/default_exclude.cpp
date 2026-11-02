#include "fs/default_exclude.hpp"

#include "fs/path_sanitizer.hpp"

#include <cctype>
#include <string>
#include <unordered_set>

namespace media::exclude {

namespace {

std::string lower_ascii(std::string_view name)
{
    std::string out;
    out.reserve(name.size());
    for (unsigned char c : name)
        out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

const std::unordered_set<std::string>& names()
{
    static const std::unordered_set<std::string> k = {
        "vfs-settings.json",
        ".git", ".svn", ".hg",
        "node_modules", ".npm", ".yarn", ".pnp.cjs", ".pnp.loader.mjs",
        "thumbs.db", "desktop.ini", "ehthumbs.db",
        ".ds_store", ".appledouble", ".lsoverride", ".spotlight-v100", ".trashes",
        ".fseventsd", ".temporaryitems", "__macosx",
        ".vscode", ".idea", ".fleet",
        ".env", ".env.local", ".env.production", "zita.json",
        ".cache", ".turbo", ".next", ".nuxt", ".parcel-cache", ".tsbuildinfo",
        ".angular", ".svelte-kit",
        "__pycache__", ".venv", "venv", ".eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        "target",
        "coverage", ".nyc_output",
        "npm-debug.log", "yarn-debug.log", "yarn-error.log",
        ".terraform", ".vagrant", "bower_components",
        "cmakefiles", "cmakecache.txt", "cmake_install.cmake", "cmakescripts",
        "out", "compile_commands.json",
        ".vs", "debug", "release", "x64", "x86", "ipch", "packages", "testresults",
    };
    return k;
}

} // namespace

bool is_default_excluded(std::string_view name)
{
    if (name.empty())
        return false;
    if (name.front() == '.')
        return true;
    return names().count(lower_ascii(name)) != 0;
}

bool is_default_excluded(const std::filesystem::path& name)
{
    return is_default_excluded(std::string_view{media::path::path_to_utf8(name)});
}

} // namespace media::exclude
