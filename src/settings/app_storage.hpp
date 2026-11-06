#pragma once

// Packaged-app storage abstraction for Tanit.
//
// MSIX full-trust desktop apps must not rely on raw %APPDATA% / %LOCALAPPDATA% /
// HKCU writes being globally visible. Without the (Store-rejected)
// `unvirtualizedResources` capability, HKCU and AppData writes get virtualised
// into a per-package, per-user hive. Instead we resolve the package's own
// durable/cache roots explicitly:
//
//   - LocalState  -> durable per-user settings/config (settings.json, sessions,
//                    daemon.json, ipc, resources/documents, encryption key).
//   - LocalCache  -> rebuildable data (downloaded models, thumbnails,
//                    embeddings, temp, logs).
//
// Both tanit.exe and tanit-cli.exe belong to the same package, so
// ApplicationData.Current.LocalFolder / LocalCacheFolder resolve to the same
// physical path for every binary, helper, and scheduler component in the
// package. This helper is the single shared seam they all use.
//
// Portable (unzipped / desktop) builds keep the historical behaviour:
//   - local_state() -> %APPDATA%\<vendor>\<config-slug>      (roaming)
//   - local_cache() -> %LOCALAPPDATA%\<vendor>\<config-slug> (local)
//
// Large, user-managed model downloads can live on a normal filesystem folder
// outside AppData (configured via settings.json["ui"]["modelsDirectoryPath"],
// read by media::ui_defaults::effective_models_dir) so they survive an
// uninstall/reinstall. local_cache()/models remains the default.

#include "polymech_export.h"

#include <filesystem>
#include <string>

namespace pm::appdata {

/// True when the current process runs inside an MSIX/AppX package
/// (GetCurrentPackageFullName() != APPMODEL_ERROR_NO_PACKAGE).
/// Note: desktop sparse Explorer11 packages also report packaged; use
/// @ref uses_package_appdata for settings/config roots.
POLYMECH_API bool is_packaged();

/// True when settings/config should live under the package LocalState/LocalCache.
/// False for portable/desktop builds and for Win11 sparse Explorer11 packages
/// (`*.Explorer11_*`) — those only wrap the compact context menu and must keep
/// `%APPDATA%\<vendor>\<config-slug>` (e.g. tanit-chat-free for the free EXE).
POLYMECH_API bool uses_package_appdata();

/// Package family name (`Name_PublisherHash`), or empty when not packaged.
/// The per-user package data root is `%LOCALAPPDATA%\Packages\<family>\`.
POLYMECH_API std::wstring package_family_name();

/// Durable per-user settings/config root.
///  - Store MSIX: `%LOCALAPPDATA%\Packages\<family>\LocalState`
///              (== ApplicationData.Current.LocalFolder)
///  - portable / sparse Explorer11: `%APPDATA%\<vendor>\<config-slug>`
POLYMECH_API std::filesystem::path local_state();

/// Rebuildable cache root (models, temp, logs, thumbnails, embeddings).
///  - Store MSIX: `%LOCALAPPDATA%\Packages\<family>\LocalCache`
///              (== ApplicationData.Current.LocalCacheFolder)
///  - portable / sparse Explorer11: `%LOCALAPPDATA%\<vendor>\<config-slug>`
POLYMECH_API std::filesystem::path local_cache();

/// Historical portable roaming root `%APPDATA%\<vendor>\<config-slug>`.
/// Returned even when packaged (used as a fallback / migration source).
POLYMECH_API std::filesystem::path portable_roaming_default();

/// Historical portable local root `%LOCALAPPDATA%\<vendor>\<config-slug>`.
POLYMECH_API std::filesystem::path portable_local_default();

} // namespace pm::appdata
