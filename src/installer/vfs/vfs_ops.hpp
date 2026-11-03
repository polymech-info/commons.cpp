#pragma once
#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS

#include "installer/events.hpp"
#include "installer/verb.hpp"

namespace pm::installer::vfs_ops {

// Resolve CMS base URL + optional bearer for installer VFS verbs.
// Uses ctx.vfs_server when set (per-URL host), else ctx.service_server_url
// (DEFAULT_VFS_SERVER from --config).  Does not read process environment.
// When require_auth is false (vfs_pull / copy vfs://), bearer may stay empty for
// public mounts.  When true (vfs_push), OAuth / ctx.service_bearer is mandatory.
bool resolve_service(const VerbContext& ctx, std::string& base, std::string& bearer, std::string& err,
                     bool require_auth = false);

// Pull remote VFS objects into `local_root`, honoring glob + pattern filters.
// Fills `result.files_*` / `bytes_written`; sets result.ok=false on failure.
bool pull_to_local(const VerbContext& ctx, PackageResult& result);

} // namespace pm::installer::vfs_ops

#endif
