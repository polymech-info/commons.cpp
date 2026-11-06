#include "core/system_browser.hpp"

#include "net/uri.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <unistd.h>
#endif

namespace pm::system_browser {
namespace {

Result fail(ErrorCode code, std::string message)
{
    return {false, {code, std::move(message)}};
}

bool valid_utf8(std::string_view value)
{
    const auto* p = reinterpret_cast<const unsigned char*>(value.data());
    std::size_t remaining = value.size();
    while (remaining != 0) {
        unsigned length = 0;
        unsigned char min_second = 0x80;
        unsigned char max_second = 0xbf;
        if (p[0] <= 0x7f) {
            length = 1;
        } else if (p[0] >= 0xc2 && p[0] <= 0xdf) {
            length = 2;
        } else if (p[0] == 0xe0) {
            length = 3;
            min_second = 0xa0;
        } else if (p[0] >= 0xe1 && p[0] <= 0xec) {
            length = 3;
        } else if (p[0] == 0xed) {
            length = 3;
            max_second = 0x9f;
        } else if (p[0] >= 0xee && p[0] <= 0xef) {
            length = 3;
        } else if (p[0] == 0xf0) {
            length = 4;
            min_second = 0x90;
        } else if (p[0] >= 0xf1 && p[0] <= 0xf3) {
            length = 4;
        } else if (p[0] == 0xf4) {
            length = 4;
            max_second = 0x8f;
        } else {
            return false;
        }

        if (remaining < length)
            return false;
        if (length > 1 && (p[1] < min_second || p[1] > max_second))
            return false;
        for (unsigned i = 2; i < length; ++i)
            if (p[i] < 0x80 || p[i] > 0xbf)
                return false;
        p += length;
        remaining -= length;
    }
    return true;
}

Result validate(std::string_view url_utf8, Policy policy)
{
    if (url_utf8.empty())
        return fail(ErrorCode::EmptyUrl, "empty URL");
    if (url_utf8.find('\0') != std::string_view::npos)
        return fail(ErrorCode::EmbeddedNul, "embedded NUL in URL");
    if (url_utf8.size() > 2048)
        return fail(ErrorCode::UrlTooLong, "URL exceeds 2048 bytes");
    if (!valid_utf8(url_utf8))
        return fail(ErrorCode::InvalidUtf8, "URL is not valid UTF-8");

    const auto parsed = pm::uri::parse_http_uri(
        url_utf8, {.reject_userinfo = true, .reject_percent_encoded_authority = true});
    if (!parsed)
        return fail(ErrorCode::InvalidHttpUrl, "malformed or non-HTTP(S) URL");

    if (policy == Policy::Untrusted) {
        std::string reason;
        if (pm::uri::host_is_private_or_invalid(*parsed, reason))
            return fail(ErrorCode::PrivateOrInvalidHost,
                        "private or invalid URL host: " + reason);
    }
    return {true, {}};
}

bool profile_argument_ok(std::string_view profile)
{
    if (profile.empty() || profile.size() > 200)
        return false;
    for (unsigned char ch : profile) {
        if (ch < 0x20 || ch == '"' || ch == '\\')
            return false;
    }
    return true;
}

#if defined(_WIN32)
std::wstring utf8_to_wide(std::string_view value)
{
    if (value.empty())
        return {};
    const int wide_length = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (wide_length <= 0)
        return {};
    std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
    if (::MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            wide.data(), wide_length) != wide_length)
        return {};
    return wide;
}

std::wstring quote_arg(const std::wstring& value)
{
    std::wstring out = L"\"";
    for (wchar_t ch : value) {
        if (ch == L'"')
            out += L"\\\"";
        else
            out += ch;
    }
    out += L'"';
    return out;
}

bool launch_profile(const std::wstring& exe, const std::wstring& profile, const std::wstring& url, bool firefox)
{
    const DWORD attrs = ::GetFileAttributesW(exe.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return false;
    std::wstring command = quote_arg(exe);
    command += firefox ? L" -P " : L" --profile-directory=";
    command += quote_arg(profile);
    command += L" ";
    command += quote_arg(url);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!::CreateProcessW(
            exe.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
            nullptr, nullptr, &startup, &process))
        return false;
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    return true;
}
#endif

} // namespace

Result open(std::string_view url_utf8, Policy policy)
{
    if (const Result checked = validate(url_utf8, policy); !checked)
        return checked;

    const std::string url(url_utf8);
#if defined(_WIN32)
    const int wide_length = ::MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, url.data(), static_cast<int>(url.size()),
        nullptr, 0);
    if (wide_length <= 0)
        return fail(ErrorCode::InvalidUtf8, "MultiByteToWideChar rejected URL UTF-8");

    std::wstring wide_url(static_cast<std::size_t>(wide_length), L'\0');
    if (::MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, url.data(), static_cast<int>(url.size()),
            wide_url.data(), wide_length) != wide_length) {
        return fail(ErrorCode::InvalidUtf8, "MultiByteToWideChar failed for URL");
    }

    const HINSTANCE result = ::ShellExecuteW(
        nullptr, L"open", wide_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    const auto code = reinterpret_cast<INT_PTR>(result);
    if (code <= 32)
        return fail(ErrorCode::OsLaunchFailed,
                    "ShellExecuteW failed (code " + std::to_string(code) + ")");
#else
    const pid_t pid = ::fork();
    if (pid < 0)
        return fail(ErrorCode::ForkFailed,
                    std::string("fork failed: ") + std::strerror(errno));
    if (pid == 0) {
#if defined(__APPLE__)
        ::execlp("open", "open", url.c_str(), static_cast<char*>(nullptr));
#else
        ::execlp("xdg-open", "xdg-open", url.c_str(), static_cast<char*>(nullptr));
        ::execlp("open", "open", url.c_str(), static_cast<char*>(nullptr));
#endif
        ::_exit(127);
    }
#endif
    return {true, {}};
}

Result open_for_login(
    std::string_view url_utf8,
    Policy policy,
    std::string_view executable,
    std::string_view profile,
    bool firefox)
{
    if (const Result checked = validate(url_utf8, policy); !checked)
        return checked;
    if (executable.empty() || !profile_argument_ok(profile))
        return open(url_utf8, policy);

#if defined(_WIN32)
    const std::wstring wide_exe = utf8_to_wide(executable);
    const std::wstring wide_profile = utf8_to_wide(profile);
    const std::wstring wide_url = utf8_to_wide(url_utf8);
    if (launch_profile(wide_exe, wide_profile, wide_url, firefox))
        return {true, {}};
#else
    (void)firefox;
#endif
    return open(url_utf8, policy);
}

} // namespace pm::system_browser
