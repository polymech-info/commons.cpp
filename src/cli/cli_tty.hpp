#pragma once

namespace cli_tty {

/// True when standard input is an interactive terminal (TTY).
bool stdin_is_tty();

/// True when standard output is an interactive terminal (TTY).
bool stdout_is_tty();

/// True when `NO_COLOR` is set (any non-empty value) or `TERM` is `dumb`.
bool env_requests_plain_output();

/// Best-effort terminal width in columns; 0 if unknown.
int terminal_width_columns();

#if defined(_WIN32)
/// Enable ANSI escape processing on the stdout console handle when supported. No-op if not a console.
void win_enable_virtual_terminal_processing_stdout();
#endif

} // namespace cli_tty
