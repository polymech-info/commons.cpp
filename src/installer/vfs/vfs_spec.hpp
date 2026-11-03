#pragma once
// installer/vfs/vfs_spec.hpp — parse vfs:// source URLs for installer copy/pull.

#include <string>
#include <string_view>

namespace pm::installer::vfs_spec {

struct ParsedVfsUrl {
    // Empty when the URL omits a host (uses DEFAULT_VFS_SERVER from --config).
    std::string server;
    std::string mount;
    // Remote path inside the mount; may contain glob tokens (**/*, *.md, …).
    std::string remote_path;
    bool        globbed = false;
};

// Returns true when `value` begins with vfs:// (case-insensitive).
bool is_vfs_url(std::string_view value);

// Parse a vfs URI after ${VAR} expansion.
//
// Supported forms (RFC 3986–friendly):
//   vfs://{mount}@{host}/{remote/path}[/** glob]
//   vfs://{host}/{mount}/{remote/path}[/** glob]
//   vfs://{mount}/{remote/path}[/** glob]   — host from DEFAULT_VFS_SERVER (--config)
//
// `host` is recognized when the authority contains '.' or ':' (port).
bool parse_vfs_url(std::string_view url, ParsedVfsUrl& out, std::string* err = nullptr);

} // namespace pm::installer::vfs_spec
