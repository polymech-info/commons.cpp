#include "cli_tty.hpp"

#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <cstdio>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace cli_tty {

bool stdin_is_tty()
{
#if defined(_WIN32)
    // _isatty(0) can mis-report when invoked through a .cmd wrapper because the CRT
    // fd-0 mapping lags the Win32 handle state.  GetFileType on the Win32 handle is
    // the same API used by pm_image_prepare_windows_stdio and is always accurate.
    const HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE)
        return false;
    return GetFileType(h) == FILE_TYPE_CHAR;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

bool stdout_is_tty()
{
#if defined(_WIN32)
    return _isatty(1) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

bool env_requests_plain_output()
{
    if (const char* nc = std::getenv("NO_COLOR")) {
        if (nc[0] != '\0')
            return true;
    }
    if (const char* term = std::getenv("TERM")) {
        if (std::strcmp(term, "dumb") == 0)
            return true;
    }
    return false;
}

int terminal_width_columns()
{
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE)
        return 0;
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(h, &info))
        return 0;
    const int w = static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1);
    return w > 1 ? w : 0;
#else
    if (!isatty(STDOUT_FILENO))
        return 0;
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0)
        return 0;
    return ws.ws_col > 0 ? static_cast<int>(ws.ws_col) : 0;
#endif
}

#if defined(_WIN32)
void win_enable_virtual_terminal_processing_stdout()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE)
        return;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode))
        return;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    (void)SetConsoleMode(h, mode);
}
#endif

} // namespace cli_tty
