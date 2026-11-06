#pragma once

#include "polymech_export.h"

#include <string>
#include <string_view>

namespace pm::system_browser {

enum class Policy {
    TrustedAppBuilt,
    UserInitiated,
    Untrusted,
};

enum class ErrorCode {
    None,
    EmptyUrl,
    EmbeddedNul,
    UrlTooLong,
    InvalidUtf8,
    InvalidHttpUrl,
    PrivateOrInvalidHost,
    OsLaunchFailed,
    ForkFailed,
};

struct Error {
    ErrorCode code = ErrorCode::None;
    std::string message;
};

struct Result {
    bool success = false;
    Error error;

    explicit operator bool() const noexcept { return success; }
};

/// Validate and ask the OS default browser to open an HTTP(S) URL.
/// A successful POSIX result confirms only that the launcher process was forked.
POLYMECH_API Result open(std::string_view url_utf8, Policy policy);

/// Open an HTTP(S) URL in a discovered browser profile.
/// Empty executable or profile uses the OS default browser.
/// On Windows, Chromium gets `--profile-directory` and Firefox gets `-P`.
/// A failed profile launch falls back to the OS default browser.
POLYMECH_API Result open_for_login(
    std::string_view url_utf8,
    Policy policy,
    std::string_view executable,
    std::string_view profile,
    bool firefox);

} // namespace pm::system_browser
