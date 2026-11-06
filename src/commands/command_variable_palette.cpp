#include "command_variables.hpp"

#include "settings/settings_store.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
extern "C" char** environ;
#endif

namespace media::commands {
namespace {

std::string wide_to_utf8(const std::wstring& w)
{
    if (w.empty()) return {};
#if defined(_WIN32)
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
#else
    (void)w;
    return {};
#endif
}

bool is_safe_token_part(const std::string& value)
{
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_';
    });
}

} // namespace

nlohmann::json command_variable_palette_json()
{
    install_host_variables();
    nlohmann::json variables = nlohmann::json::array();
    std::set<std::string> variable_names;

    const auto push = [&](const char* name, const char* group, const char* description) {
        std::string n = name ? name : "";
        if (n.empty() || !variable_names.insert(n).second)
            return;
        variables.push_back({
            {"name", std::move(n)},
            {"group", group ? group : ""},
            {"description", description ? description : ""},
        });
    };

    push("CURRENT_FILE", "Current file", "Current file absolute path from Explorer selection or the open preview.");
    push("CURRENT_FILE_NAME", "Current file", "Current file name including extension.");
    push("CURRENT_PATH", "Current file", "Current Explorer folder, or current file parent folder when a file is selected.");
    push("CURRENT_SELECTION", "Current file", "Whitespace-separated current Explorer selection list; entries are files or folders. In an args array each path becomes its own argument.");
    push("CURRENT_SELECTION_COUNT", "Current file", "Number of paths in the current selection. Omitted when nothing is selected.");
    push("CURRENT_SELECTION_0", "Current file", "First selected path (0-based, same order as CURRENT_SELECTION). Replace 0 with 1, 2, ... for later files. One argument, unlike CURRENT_SELECTION.");
    push("CURRENT_SELECTION_1", "Current file", "Second selected path. Same pattern as CURRENT_SELECTION_0.");

    push("CURRENT_HWND", "Current window", "Decimal HWND of the selected taskbar app (launcher Apps pill).");
    push("CURRENT_PID", "Current window", "Process id of the selected taskbar app.");
    push("CURRENT_WINTITLE", "Current window", "Window title of the selected taskbar app.");
    push("CURRENT_PROCESS", "Current window", "Process image name of the selected taskbar app (e.g. soffice.bin).");
    push("CURRENT_SCREEN_SPEC", "Current window", "xblox capture spec `screen:0:hwnd=${CURRENT_HWND}`.");

    push("CURRENT_URL", "Browser", "URL of the current centre browser tab. Skips about:blank. Omitted when no page is open.");
    push("CURRENT_URL_TITLE", "Browser", "Title of the current centre browser tab.");
    push("LAST_URL", "Browser", "Newest centre-browser history URL, including a tab that is already closed.");
    push("BROWSER_TAB_COUNT", "Browser", "Number of open centre browser tabs with a real page. Omitted when none are open.");
    push("BROWSER_TAB_0", "Browser", "URL of the first open centre browser tab (0-based, tab order). Replace 0 with 1, 2, ... One argument.");
    push("BROWSER_TAB_1", "Browser", "URL of the second open centre browser tab. Same pattern as BROWSER_TAB_0.");
    push("BROWSER_TAB_TITLE_0", "Browser", "Title of the first open centre browser tab. Replace 0 with 1, 2, ...");
    push("BROWSER_TAB_TITLE_1", "Browser", "Title of the second open centre browser tab. Same pattern as BROWSER_TAB_TITLE_0.");

    push("VOICE_WAKE", "Voice", "Wake phrase that matched this utterance. Empty when listening has no prefix.");
    push("VOICE_COMMAND", "Voice", "Spoken command after the wake phrase.");
    push("VOICE_FULL", "Voice", "Full transcript, including the wake phrase when one was used.");

    push("SRC_FILE", "Source", "Selected source file path.");
    push("SRC_DIR", "Source", "Selected source parent directory.");
    push("SRC_NAME", "Source", "Selected source filename without extension.");
    push("SRC_EXT", "Source", "Selected source extension without the leading dot.");
    push("SRC_FILE_EXT", "Source", "Selected source extension including the leading dot.");
    push("SRC_REL", "Source", "Selected source path relative to a bundle root when available.");

    push("CWD", "Process", "Current command working directory.");
    push("PATH_SEP", "Process", "Native path separator for this platform.");
    push("PATH_LIST_SEP", "Process", "Native delimiter for lists of paths.");

    push("OS_LANG", "Locale", "OS/system default locale (BCP-47), e.g. en-US.");
    push("USER_LANG", "Locale", "User UI / preferred language (BCP-47), e.g. de-DE.");

    push("YYYY", "Date / time", "Current four-digit year.");
    push("MM", "Date / time", "Current two-digit month.");
    push("DD", "Date / time", "Current two-digit day of month.");
    push("HH", "Date / time", "Current two-digit hour.");
    push("mm", "Date / time", "Current two-digit minute.");
    push("SS", "Date / time", "Current two-digit seconds.");

    push("CACHE_DIR", "Process", "OS temporary directory.");

    install_host_variables();
    apply_palette_contributors(push);

    push("INSTALL_ROOT", "Install", "Bundle or install root directory when install context is set.");
    push("INSTALL_BIN", "Install", "Install bin directory, or install root when bin/ is absent.");
    push("DEFAULT_VFS_SERVER", "Install", "Default CMS base URL for vfs:// sources.");

    push("PROGRAM_FILES", "OS paths", "Program Files folder.");
    push("PROGRAM_FILES_X86", "OS paths", "Program Files (x86) folder.");
    push("PROGRAM_DATA", "OS paths", "Shared program data folder.");
    push("START_MENU", "OS paths", "Current user's Start Menu folder.");
    push("START_MENU_COMMON", "OS paths", "Common Start Menu folder.");
    push("PROGRAMS", "OS paths", "Current user's Start Menu Programs folder.");
    push("PROGRAMS_COMMON", "OS paths", "Common Start Menu Programs folder.");
    push("STARTUP", "OS paths", "Current user's Startup folder.");
    push("STARTUP_COMMON", "OS paths", "Common Startup folder.");
    push("FONTS", "OS paths", "Fonts folder.");
    push("SYSTEM_DIR", "OS paths", "Windows System folder.");
    push("WINDOWS_DIR", "OS paths", "Windows installation folder.");
    push("PUBLIC", "OS paths", "Public user profile folder.");
    push("PUBLIC_DESKTOP", "OS paths", "Public Desktop folder.");
    push("SEND_TO", "OS paths", "Send To folder.");
    push("RECENT", "OS paths", "Recent items folder.");

    push("KNOWNFOLDER:Home", "Known folders - Portable", "User home/profile folder.");
    push("KNOWNFOLDER:Config", "Known folders - Portable", "User configuration folder.");
    push("KNOWNFOLDER:Data", "Known folders - Portable", "User data folder.");
    push("KNOWNFOLDER:Cache", "Known folders - Portable", "User cache folder.");
    push("KNOWNFOLDER:Temp", "Known folders - Portable", "Temporary files folder.");

    push("KNOWNFOLDER:Profile", "Known folders - User", "User profile folder.");
    push("KNOWNFOLDER:Desktop", "Known folders - User", "Current user's Desktop folder.");
    push("KNOWNFOLDER:Documents", "Known folders - User", "Current user's Documents folder.");
    push("KNOWNFOLDER:Downloads", "Known folders - User", "Current user's Downloads folder.");
    push("KNOWNFOLDER:Pictures", "Known folders - User", "Current user's Pictures folder.");
    push("KNOWNFOLDER:Music", "Known folders - User", "Current user's Music folder.");
    push("KNOWNFOLDER:Videos", "Known folders - User", "Current user's Videos folder.");
    push("KNOWNFOLDER:Templates", "Known folders - User", "Current user's Templates folder.");
    push("KNOWNFOLDER:Favorites", "Known folders - User", "Current user's Favorites folder.");
    push("KNOWNFOLDER:Links", "Known folders - User", "Current user's Links folder.");
    push("KNOWNFOLDER:Saved_Games", "Known folders - User", "Current user's Saved Games folder.");
    push("KNOWNFOLDER:Screenshots", "Known folders - User", "Current user's Screenshots folder.");

    push("KNOWNFOLDER:Local_App_Data", "Known folders - App data", "Current user's local application data folder.");
    push("KNOWNFOLDER:Roaming_App_Data", "Known folders - App data", "Current user's roaming application data folder.");
    push("KNOWNFOLDER:Program_Data", "Known folders - App data", "Shared program data folder.");

    push("KNOWNFOLDER:Public", "Known folders - Public", "Public user profile folder.");
    push("KNOWNFOLDER:Public_Desktop", "Known folders - Public", "Public Desktop folder.");
    push("KNOWNFOLDER:Public_Documents", "Known folders - Public", "Public Documents folder.");
    push("KNOWNFOLDER:Public_Downloads", "Known folders - Public", "Public Downloads folder.");
    push("KNOWNFOLDER:Public_Pictures", "Known folders - Public", "Public Pictures folder.");
    push("KNOWNFOLDER:Public_Music", "Known folders - Public", "Public Music folder.");
    push("KNOWNFOLDER:Public_Videos", "Known folders - Public", "Public Videos folder.");

    push("KNOWNFOLDER:Windows", "Known folders - System", "Windows installation folder.");
    push("KNOWNFOLDER:System", "Known folders - System", "Windows System folder.");
    push("KNOWNFOLDER:Program_Files", "Known folders - System", "Program Files folder.");
    push("KNOWNFOLDER:Program_Files_X86", "Known folders - System", "Program Files (x86) folder.");
    push("KNOWNFOLDER:Fonts", "Known folders - System", "Fonts folder.");
    push("KNOWNFOLDER:Start_Menu", "Known folders - System", "Current user's Start Menu folder.");
    push("KNOWNFOLDER:Programs", "Known folders - System", "Current user's Start Menu Programs folder.");
    push("KNOWNFOLDER:Startup", "Known folders - System", "Current user's Startup folder.");

    push("ENV:PATH", "Environment", "Environment variable lookup. Replace PATH with any variable name.");
    push("USER:MY_VARIABLE", "User", "User variable lookup from settings. Replace MY_VARIABLE with a saved variable name.");

    push("PATH_DIR:CURRENT_SELECTION_0", "Path helpers", "Parent directory of the first selected path. Replace 0 with any selection index.");
    push("PATH_NAME:CURRENT_SELECTION_0", "Path helpers", "Stem (filename without extension) of the first selected path.");
    push("PATH_BASE:CURRENT_SELECTION_0", "Path helpers", "Filename including extension of the first selected path.");
    push("PATH_EXT:CURRENT_SELECTION_0", "Path helpers", "Extension of the first selected path.");
    push("PATH_ABS:CURRENT_SELECTION_0", "Path helpers", "Absolute path of the first selected path.");
    push("PATH_DIR:CURRENT_FILE", "Path helpers", "Parent directory of the current file.");
    push("PATH_NAME:CURRENT_FILE", "Path helpers", "Current file stem (filename without extension).");
    push("PATH_BASE:CURRENT_FILE", "Path helpers", "Current file filename including extension.");
    push("PATH_EXT:CURRENT_FILE", "Path helpers", "Current file extension.");
    push("PATH_ABS:CURRENT_FILE", "Path helpers", "Current file as an absolute normalized path.");
    push("PATH_DIR:MY_PATH", "Path helpers", "Parent directory of a path variable. Replace MY_PATH with a variable name.");
    push("PATH_NAME:MY_PATH", "Path helpers", "Stem (filename without extension) of a path variable.");
    push("PATH_EXT:MY_PATH", "Path helpers", "Extension of a path variable.");
    push("PATH_BASE:MY_PATH", "Path helpers", "Filename including extension of a path variable.");
    push("PATH_ABS:MY_PATH", "Path helpers", "Absolute normalized path of a path variable.");

#if defined(_WIN32)
    if (LPWCH block = ::GetEnvironmentStringsW()) {
        for (const wchar_t* p = block; p && *p; p += std::wcslen(p) + 1) {
            std::wstring entry(p);
            const auto eq = entry.find(L'=');
            if (eq == std::wstring::npos || eq == 0)
                continue;
            const std::string name = wide_to_utf8(entry.substr(0, eq));
            if (!is_safe_token_part(name))
                continue;
            push((std::string("ENV:") + name).c_str(), "Environment", (std::string("Environment variable: ") + name).c_str());
        }
        ::FreeEnvironmentStringsW(block);
    }
#else
    for (char** env = ::environ; env && *env; ++env) {
        const std::string entry(*env);
        const auto eq = entry.find('=');
        if (eq == std::string::npos || eq == 0)
            continue;
        const std::string name = entry.substr(0, eq);
        if (!is_safe_token_part(name))
            continue;
        push((std::string("ENV:") + name).c_str(), "Environment", (std::string("Environment variable: ") + name).c_str());
    }
#endif

    nlohmann::json user_vars;
    std::string user_vars_err;
    if (media::settings::load_subtree("variables", user_vars, user_vars_err) && user_vars.is_object()) {
        for (auto it = user_vars.begin(); it != user_vars.end(); ++it) {
            if (!is_safe_token_part(it.key()))
                continue;
            push((std::string("USER:") + it.key()).c_str(), "User", "User variable from settings.");
        }
    }

    return variables;
}

} // namespace media::commands
