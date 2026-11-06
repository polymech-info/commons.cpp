#pragma once

#include <cctype>
#include <string_view>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
// iphlpapi.h must include netioapi.h. A direct include takes the kernel
// path and declares these APIs as returning NTSTATUS.
#include <iphlpapi.h>
#endif

namespace pm::net {

/// Curl `CURLOPT_CONNECTTIMEOUT_MS` for remote login / catalog calls. DNS on a
/// dead NIC still often ignores this; pair with @ref remote_http_should_skip.
inline constexpr long k_fail_fast_connect_ms = 1500;

inline constexpr const char k_no_internet_err[] = "no internet connection";

namespace detail {

inline bool ascii_ieq(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb))
            return false;
    }
    return true;
}

inline bool ascii_istarts(std::string_view host, std::string_view prefix) noexcept
{
    return host.size() >= prefix.size()
        && ascii_ieq(host.substr(0, prefix.size()), prefix);
}

inline bool ascii_iends(std::string_view host, std::string_view suffix) noexcept
{
    return host.size() >= suffix.size()
        && ascii_ieq(host.substr(host.size() - suffix.size()), suffix);
}

} // namespace detail

/// Minimal parser for canonical HTTP(S) URLs generated internally.
/// Not suitable for arbitrary user-supplied URLs.
inline std::string_view host_of_url(std::string_view url) noexcept
{
    auto rest = url;
    const auto scheme = rest.find("://");
    if (scheme != std::string_view::npos)
        rest = rest.substr(scheme + 3);
    const auto slash = rest.find('/');
    if (slash != std::string_view::npos)
        rest = rest.substr(0, slash);
    const auto query = rest.find_first_of("?#");
    if (query != std::string_view::npos)
        rest = rest.substr(0, query);
    const auto at = rest.rfind('@');
    if (at != std::string_view::npos)
        rest = rest.substr(at + 1);
    if (!rest.empty() && rest.front() == '[') {
        const auto end = rest.find(']');
        return end == std::string_view::npos ? rest : rest.substr(1, end - 1);
    }
    const auto colon = rest.rfind(':');
    if (colon != std::string_view::npos)
        rest = rest.substr(0, colon);
    return rest;
}

/// True when this host should not be suppressed just because there is no
/// public Internet route. Loopback, mDNS `.local`, and private addresses
/// (including ones reached through a VPN) all count. Deliberately permissive.
inline bool host_may_be_local(std::string_view host) noexcept
{
    if (host.empty())
        return true;
    if (host.size() >= 256)
        return false;

    if (detail::ascii_ieq(host, "localhost")
        || detail::ascii_ieq(host, "127.0.0.1")
        || detail::ascii_ieq(host, "::1"))
        return true;
    if (detail::ascii_iends(host, ".local") || detail::ascii_iends(host, ".localhost"))
        return true;
    if (detail::ascii_istarts(host, "127.")
        || detail::ascii_istarts(host, "10.")
        || detail::ascii_istarts(host, "192.168.")
        || detail::ascii_istarts(host, "169.254."))
        return true;
    if (detail::ascii_istarts(host, "172.") && host.size() >= 6) {
        unsigned octet = 0;
        size_t i = 4;
        while (i < host.size() && host[i] >= '0' && host[i] <= '9') {
            octet = octet * 10u + static_cast<unsigned>(host[i] - '0');
            ++i;
        }
        if (i < host.size() && host[i] == '.' && octet >= 16 && octet <= 31)
            return true;
    }
    if (detail::ascii_istarts(host, "fe80:")
        || detail::ascii_istarts(host, "fc")
        || detail::ascii_istarts(host, "fd"))
        return true;
    return false;
}

/// Cheap negative gate. True unless Windows already reports no useful public
/// route. Unknown, constrained, and a missing API all return true so curl can
/// still try. A false negative would suppress a legitimate call.
inline bool internet_likely_available() noexcept
{
#if defined(_WIN32)
    typedef DWORD (WINAPI* HintFn)(NL_NETWORK_CONNECTIVITY_HINT*);

    static const HintFn fn = [] {
        HMODULE mod = ::GetModuleHandleW(L"iphlpapi.dll");
        if (!mod)
            mod = ::LoadLibraryW(L"iphlpapi.dll");
        return mod
            ? reinterpret_cast<HintFn>(::GetProcAddress(mod, "GetNetworkConnectivityHint"))
            : nullptr;
    }();

    if (!fn)
        return true;

    NL_NETWORK_CONNECTIVITY_HINT hint{};
    if (fn(&hint) != NO_ERROR)
        return true;

    switch (hint.ConnectivityLevel) {
    case NetworkConnectivityLevelHintNone:
    case NetworkConnectivityLevelHintLocalAccess:
    case NetworkConnectivityLevelHintHidden:
        return false;
    default:
        return true;
    }
#else
    return true;
#endif
}

/// True when this host needs a public route and the OS already says there is none.
inline bool remote_host_should_skip(std::string_view host) noexcept
{
    if (host_may_be_local(host))
        return false;
    return !internet_likely_available();
}

/// True when this URL needs a public route and the OS already says there is none.
inline bool remote_http_should_skip(std::string_view url) noexcept
{
    return remote_host_should_skip(host_of_url(url));
}

} // namespace pm::net
