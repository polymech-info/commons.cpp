#pragma once
// installer/resolve.hpp — path/variable resolution and constraint checks.
//
// All ${VAR} expansion goes through the central command_variables engine; the
// installer never hardcodes brand or OS paths (brand-agnostic guarantee).

#include "installer/manifest.hpp"
#include "installer/variables.hpp"

#include <string>
#include <vector>

namespace pm::installer {

// Canonical OS token for the current platform: "win32" | "darwin" | "linux".
const char* current_os_token() noexcept;

// Default target subdirectory for an artifact type.
// e.g. "skills" → "skills",  "app-extensions:zip" → "extensions"
std::string type_subdir(const std::string& type);

// Glob-like filename match: empty/"**"/"**/*" = all, "*.ext" = by extension,
// exact name, or a single "prefix*suffix" split (basename only).
bool matches_pattern(const std::string& filename, const std::string& pattern);

// Path-aware pattern match for source-relative paths.  Uses path_matches_path_glob
// when the pattern contains `/` or `**`; otherwise matches the basename only.
bool matches_path_pattern(const std::string& rel_path, const std::string& pattern);

// Longest literal directory prefix before the first glob token in `pattern`.
std::string glob_path_prefix(const std::string& pattern);

// True when the package constraints accept the current platform.
bool constraints_satisfied(const PackageConstraints& c);

// Resolved local/VFS source after ${VAR} expansion and optional glob expansion.
struct ResolvedSource {
    // Primary path string (directory, file, glob pattern, or remote prefix).
    std::string path;
    // Populated when source.path contained glob tokens: absolute local file paths.
    std::vector<std::string> files;
    // Directory prefix stripped when mapping glob matches into the target tree.
    std::string rel_base;
    // True when `path` contained glob tokens (local or remote).
    bool globbed = false;

    // vfs:// service source (copy verb pulls then applies on_exist locally).
    bool        is_vfs = false;
    std::string vfs_server; // empty → DEFAULT_VFS_SERVER from --config
    std::string vfs_mount;
};

// Resolve a manifest dependency path: expand ${VAR}, then resolve paths relative
// to the parent manifest file's directory (not process CWD).
std::string resolve_manifest_dependency_path(const std::string& raw,
                                             const std::string& parent_manifest_path,
                                             const VariableMap& vars,
                                             std::string* err = nullptr);

// Resolve source.path: expand variables, then expand local globs via glob_paths.
// VfsRemote paths are variable-expanded only; glob matching happens in the verb.
bool resolve_source(const Package& pkg,
                    const VariableMap& vars,
                    ResolvedSource& out,
                    std::string* err = nullptr);

// Resolve the effective local source path (variables expanded, kind base
// applied).  Prefer resolve_source() when glob expansion is needed.
std::string resolve_source_path(const Package& pkg,
                                const VariableMap& vars,
                                std::string* err = nullptr);

// Resolve the effective target path.  For TargetKind::VfsRemote the remote
// directory prefix is returned after variable expansion.
std::string resolve_target_path(const Package& pkg,
                                const VariableMap& vars,
                                std::string* err = nullptr);

// Resolve shell command/cwd/args for verb == "shell".  Returns false and sets
// *err when the effective command is empty after expansion.
bool resolve_shell_action(const Package& pkg,
                          const VariableMap& vars,
                          PackageShell& out,
                          std::string* err = nullptr);

} // namespace pm::installer
