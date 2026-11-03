#include "installer/vfs/vfs_spec.hpp"

#include "fs/glob_paths.hpp"
#include "string/string_utils.hpp"

#include <algorithm>
#include <cctype>

namespace pm::installer::vfs_spec {

namespace {

bool icmp_prefix(std::string_view s, std::string_view prefix)
{
    if (s.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i]))
            != std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    return true;
}

bool looks_like_server_host(std::string_view authority)
{
    return authority.find('.') != std::string_view::npos
        || authority.find(':') != std::string_view::npos;
}

std::string clean_remote(std::string p)
{
    while (!p.empty() && (p.front() == '/' || p.front() == '\\'))
        p.erase(p.begin());
    while (!p.empty() && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    return p;
}

bool path_has_glob(const std::string& s)
{
    return media::has_glob_tokens(s) || s.find("**") != std::string::npos;
}

} // namespace

bool is_vfs_url(std::string_view value)
{
    return media::strutil::starts_with_ascii_ci(value, "vfs://");
}

bool parse_vfs_url(std::string_view url, ParsedVfsUrl& out, std::string* err)
{
    out = {};
    if (!is_vfs_url(url)) {
        if (err) *err = "not a vfs:// URL";
        return false;
    }

    std::string rest(url.substr(6));
    while (!rest.empty() && rest.front() == '/')
        rest.erase(rest.begin());

    if (rest.empty()) {
        if (err) *err = "vfs:// URL is missing mount/path";
        return false;
    }

    // mount@host/remote/path
    const auto at = rest.find('@');
    if (at != std::string::npos) {
        out.mount = rest.substr(0, at);
        rest.erase(0, at + 1);
        const auto slash = rest.find('/');
        if (slash == std::string::npos || slash == 0) {
            if (err) *err = "vfs:// mount@host form requires /remote/path";
            return false;
        }
        out.server = rest.substr(0, slash);
        out.remote_path = clean_remote(rest.substr(slash + 1));
    } else {
        const auto slash = rest.find('/');
        if (slash == std::string::npos) {
            if (err) *err = "vfs:// URL requires /remote/path after mount or host";
            return false;
        }
        const std::string authority = rest.substr(0, slash);
        const std::string path_part = rest.substr(slash + 1);

        if (looks_like_server_host(authority)) {
            out.server = authority;
            const auto mount_sep = path_part.find('/');
            if (mount_sep == std::string::npos) {
                out.mount = clean_remote(path_part);
                out.remote_path.clear();
            } else {
                out.mount = path_part.substr(0, mount_sep);
                out.remote_path = clean_remote(path_part.substr(mount_sep + 1));
            }
        } else {
            out.mount = authority;
            out.remote_path = clean_remote(path_part);
        }
    }

    if (out.mount.empty()) {
        if (err) *err = "vfs:// URL is missing mount";
        return false;
    }

    out.globbed = path_has_glob(out.remote_path);
    return true;
}

} // namespace pm::installer::vfs_spec
