#pragma once
// Declarations only. Definitions are fs/path_sanitizer.cpp in this package.

#if defined(_MSC_VER)
#define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING 1
#endif

#include <filesystem>
#include <string>
#include <string_view>

namespace media::path {

inline std::string path_to_utf8(const std::filesystem::path& path)
{
    const auto utf8 = path.u8string();
    return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}

inline std::filesystem::path path_from_utf8(std::string_view text)
{
    return std::filesystem::u8path(text.begin(), text.end());
}

inline std::string path_to_generic_utf8(const std::filesystem::path& path)
{
    const auto utf8 = path.generic_u8string();
    return std::string(reinterpret_cast<const char*>(utf8.data()), utf8.size());
}

/**
 * VFS subpath: relative, no null / traversal / `C:\` (matches ref `sanitizeSubpath`).
 * Empty input → empty output (ok).
 */
std::string sanitize_subpath(const std::string &input, std::string &err);

/**
 * Filename cleaner used after `sanitize_subpath`. Drops ASCII controls and `<>:"/\|?*`.
 * It does not reject `..` and is not a path authorization check.
 */
std::string sanitize_write_path(const std::string &subpath, std::string &err, bool is_directory = false);

/** Single path segment: illegal chars, control, Windows reserved, trailing dots/spaces. */
std::string sanitize_filename(const std::string &input, const std::string &replacement = std::string());

/**
 * True when `name` is safe to append as one filesystem component during local
 * traversal. Less strict than @ref sanitize_filename — allows trailing dots and
 * spaces that already exist on NTFS — but rejects separators, controls, "..",
 * overlong names, and reserved device names.
 */
bool is_safe_path_component(std::string_view name);

#if defined(_WIN32)
std::wstring normalize_local_path_w(const std::wstring& input, bool force = true);
bool is_safe_path_component_w(std::wstring_view name) noexcept;
/** Case-insensitive path key for matching scan results to shell paths. */
std::wstring path_compare_key_w(std::wstring path);
#endif

/** Heuristic: drive / UNC / slash token without URL scheme or `${}` placeholders. */
bool looks_like_local_path(const std::string &s);

/**
 * Normalize a resolved local filesystem path: trim outer whitespace, drop UTF-8
 * BOM / ASCII control chars (\\r, \\n, \\0, …), collapse duplicate `/` or `\\`,
 * then unify via std::filesystem (`.` / `..`, native separators). Emojis and
 * other printable Unicode in filenames are kept (valid on Windows). Returns input
 * unchanged when empty, still contains `${...}`, or looks like a URL (`://`).
 * With `force == false` (default), skips strings that do not look like a path
 * token. With `force == true`, always normalizes (xblox path params, LLM tools,
 * fs guard).
 */
std::string normalize_local_path(const std::string &input, bool force = false);

/**
 * User-facing local / glob / UNC path string (not `http`/`https` — use
 * @ref `validate_url_spec_for_input_selection` later). Reuses tamper+traversal rules from
 * `sanitize_subpath` (steps 1–7) without VFS “no drive / root” restrictions.
 */
bool validate_path_spec_for_input_selection(const std::string &raw, std::string &err);

/**
 * Placeholder for future URL allowlists (schemes, hosts). Currently only structural checks
 * you may want to expand (delegate to @ref is_http_url in callers, or stricter here later).
 */
bool validate_url_spec_for_input_selection(const std::string &raw, std::string &err);

/**
 * Join `root` and a relative key. Rejects an absolute key, `..`, and any symlink
 * along the key. The result stays inside the canonical root.
 */
std::filesystem::path confine_to_root(const std::filesystem::path& root,
                                      std::string_view key,
                                      std::string& err);

/**
 * One cache filename for a remote object. `scope` is the server and account, not a token.
 * The leaf is a display suffix, not the identity.
 */
std::string vfs_object_filename(std::string_view scope,
                                std::string_view mount,
                                std::string_view relative);

/** Mount token: length, separators, and control characters including DEL. */
bool vfs_mount_name_ok(std::string_view name);

/** Unique temporary path in `directory`. The caller creates and deletes the file. */
std::filesystem::path make_cache_temp(const std::filesystem::path& directory);

/**
 * Replace `destination` with a completed temporary file in the same directory.
 * Does not delete `completed_temp` when the replace fails.
 */
bool publish_file(const std::filesystem::path& completed_temp,
                  const std::filesystem::path& destination,
                  std::string& err);

/** Remove a temporary download and its `.part` file. Does not touch `dest`. */
void discard_file(const std::filesystem::path& incoming);

} // namespace media::path
