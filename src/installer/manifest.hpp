#pragma once
// installer/manifest.hpp — JSON bundle manifest data model + parser.
//
// A manifest describes one or more packages (artifact bundles) to move from a
// source location to a target location by executing a *verb* (copy, vfs_pull,
// vfs_push, …).  Paths are ${VAR}-aware and resolved through the central
// command_variables machinery, so all variables in VariableMap are available
// (${APP_DATA}, ${INSTALL_ROOT}, ${VFS_PUBLIC_DIR}, ${PROGRAM_FILES}, …).
//
// Minimal manifest example:
//
//   {
//     "version": 1,
//     "packages": [
//       {
//         "id":      "core-skills-v1",
//         "type":    "skills",
//         "verb":    "copy",
//         "source":  { "kind": "dist-release-bundle", "path": "${INSTALL_ROOT}/data/skills" },
//         "source":  { "path": "vfs://models/test/skills/**/*.md" },
//         "dependencies": ["./base.json"],
//         "target":  { "kind": "default-roaming" },
//         "on_exist": "skip"
//       }
//     ]
//   }
//
// When `verb` is omitted it is inferred: vfs-remote target → "vfs_push",
// vfs-remote source → "vfs_pull", otherwise "copy".

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pm::installer {

// ── Source ────────────────────────────────────────────────────────────────────

enum class SourceKind {
    DistReleaseBundle,  // "dist-release-bundle"  — local dir shipped with the installer
    VfsPublicVersioned, // "vfs-public-versioned"  — relative to ${VFS_PUBLIC_DIR}
    VfsPrivateUser,     // "vfs-private-user"      — relative to ${VFS_USER_DIR}
    LocalDirCustom,     // "local-dir-custom"      — explicit local path in source.path
    VfsRemote,          // "vfs-remote"            — service VFS (mount + remote path)
    CustomStore,        // "custom-store"          — reserved; not yet implemented
};

struct PackageSource {
    SourceKind  kind    = SourceKind::DistReleaseBundle;
    std::string path;            // ${VAR}-aware; relative to kind base when not absolute
    std::vector<std::string> paths;   // optional multi-source globs (copy-only)
    std::string pattern;              // glob-like include-filter on relative paths
    std::vector<std::string> exclude; // glob patterns for paths to skip (string or [])
    std::string mount = "home";       // service VFS mount (kind == VfsRemote)
};

// ── Target ────────────────────────────────────────────────────────────────────

enum class TargetKind {
    DefaultRoaming,  // "default-roaming"   — ${APP_DATA}/<type-subdir>  (auto from type)
    LocalDirCustom,  // "local-dir-custom"  — explicit path in target.path
    Vfs,             // "vfs"               — ${VFS_USER_DIR}/<type-subdir>
    VfsRemote,       // "vfs-remote"        — service VFS (mount + remote dir)
    Unc,             // "unc"               — explicit UNC path in target.path
};

struct PackageTarget {
    TargetKind  kind = TargetKind::DefaultRoaming;
    std::string path;            // ${VAR}-aware; used by LocalDirCustom / Unc / VfsRemote
    std::string mount = "home";  // service VFS mount (kind == VfsRemote)
};

// ── Constraints ───────────────────────────────────────────────────────────────

struct PackageConstraints {
    // Each list is ANDed; empty = unconstrained (accept all).
    std::vector<std::string> os;           // "win32" | "darwin" | "linux"
    std::vector<std::string> subscription; // "free" | "pro" | "team" | …
    std::string              min_version;  // semver lower bound; empty = any
};

// ── On-exist policy ───────────────────────────────────────────────────────────

enum class OnExist {
    Skip,           // "skip"            — keep existing file (default; safe for user data)
    Overwrite,      // "overwrite"       — always replace
    UpdateIfNewer,  // "update-if-newer" — replace only when source mtime > dest mtime
    Error,          // "error"           — abort with an error if destination exists
};

// ── Shell action (verb == "shell") ────────────────────────────────────────────
//
// Runs a host command through media::llm::run::execute (ProcessRunner +
// RunValidators security).  Mirrors xblox shell block fields.
//
//   "shell": {
//     "command": "echo ${APP_ID}",
//     "cwd": "${INSTALL_ROOT}",
//     "shell": "auto",
//     "mode": "shell",
//     "timeout_ms": 30000,
//     "args": []
//   }
//
// Fallback when `shell.command` is empty: `source.path` → command,
// `target.path` → cwd.

struct PackageShell {
    std::string              command;
    std::string              cwd;
    std::string              shell = "auto";  // auto | cmd | powershell | bash | sh
    std::string              mode  = "shell";   // shell | argv
    std::vector<std::string> args;            // argv mode only
    int                      timeout_ms = 0;  // 0 = RunTool default
};

// ── Sign / encrypt options (verb == "sign" | "encrypt") ───────────────────────
//
// Used both by a standalone sign/encrypt package and by before/after hook
// entries.  All string fields are ${VAR}-aware and re-resolved *per file* against
// the first-class source vocabulary (${SRC_FILE}, ${SRC_REL}, …), so signing is
// user-customizable through variables.
//
//   "after": [{
//     "verb": "sign",
//     "mask": "*.json,prompts/**/*.md",
//     "uri":  "pm://config/${SRC_REL}",
//     "type": "auto",
//     "trust": "signed-vendor"
//   }]
//
// `mask` is a comma-separated list of path globs filtering the working set (the
// parent verb's produced files for a hook, or resolved source files for a
// standalone verb).  `type: "auto"` infers the resource type from the resolved
// uri filename.  Vendor seeds write under config_dir/resources/ (dist/data
// layout); private signing/encryption keys are stripped after when strip_keys.

struct PackageSign {
    std::string uri;         // pm:// target (per-file ${SRC_*}-templated)
    std::string doc_type;    // JSON key "type"; "auto"/empty => infer from uri
    std::string trust;       // signed-vendor | user-local | …
    std::string provider;
    std::string signer;
    std::string version;
    std::string config_dir;  // store root; empty => derived from the file / rel_base
    std::string key_dir;     // dist keystore for the signer (sign; reserved)
    std::string mask;        // comma-separated path globs over the working set
    bool        verify        = true;
    bool        encrypt       = false;  // set by the encrypt verb (at-rest, user-local)
    bool        strip_keys    = true;   // strip private keys from the store when done
    bool        delete_source = false;  // delete plain-text source files after signing
};

// ── VFS download options (vfs_pull / vfs:// copy source) ───────────────────────
//
// Optional per-package tuning for remote VFS pulls.  All fields are optional;
// unset values use installer/service defaults (progress on, resume on, skip via on_exist).
//
//   "vfs_download": {
//     "progress": true,
//     "resume": true,
//     "retries": 3,
//     "endpoint": "get"
//   }

struct PackageVfsDownload {
    bool        progress_set = false;
    bool        progress     = true;
    bool        resume_set   = false;
    bool        resume       = true;
    bool        retries_set  = false;
    int         retries      = 3;
    bool        endpoint_set = false;
    std::string endpoint; ///< "get" | "read"; empty = get (public mounts)
};

// ── Package ───────────────────────────────────────────────────────────────────

struct Package {
    std::string        id;           // unique identifier for logging / journal idempotency
    std::string        type;         // artifact type list in docs/dist/artifacts.md
    std::string        description;  // optional human note
    std::string        verb;         // "copy" | "vfs_pull" | "vfs_push" | …; empty = inferred

    PackageSource      source;
    PackageTarget      target;
    PackageShell       shell;
    PackageVfsDownload vfs_download;
    OnExist            on_exist    = OnExist::Skip;
    bool               clear       = false;  // remove target dir before copy
    // Missing source is a skip, not a failed run. Used when a shared first-run
    // manifest copies a tree some packages do not ship.
    bool               optional    = false;
    PackageConstraints constraints;
    // Paths to other manifest JSON files (resolved relative to the parent
    // manifest directory after ${VAR} expansion).  JSON key: "dependencies"
    // or legacy alias "requires".
    std::vector<std::string> dependencies_;

    // Options for verb == "sign" | "encrypt" (standalone or as a hook entry).
    PackageSign sign;

    // Verb lifecycle hooks: ordinary verb packages run around the main verb.
    // `after_` entries receive this package's produced files (written_files) as
    // their VerbContext::input_files; `before_` entries run first (empty input).
    // JSON keys: "before" / "after".  `std::vector<Package>` of an incomplete
    // type is well-formed for std::vector (C++17).
    std::vector<Package> before_;
    std::vector<Package> after_;
};

// ── Manifest ──────────────────────────────────────────────────────────────────

struct Manifest {
    int                  version = 1;
    std::string          manifest_path; // set to the file path used to load it
    std::vector<std::string> dependencies_; // top-level manifest dependencies (run before packages)
    std::vector<Package> packages;

    // Optional run policy read by pm::installer::run_manifest (in-app / startup).
    // The CLI installer ignores these and always executes.
    // "ttl": "1d" | "24h" | "30m" | "45s" | <seconds>. 0 = no skip window.
    std::int64_t ttl_sec = 0;
    // Failures stay in ManifestResult; callers that set forgiving do not treat
    // them as process errors.
    bool forgiving = false;
    // "auth": "none" — public resource, do not read or send a bearer.
    // "auto" (default) attaches a token when one is already stored.
    bool auth_none = false;
};

// ── Parse API ─────────────────────────────────────────────────────────────────

// Load and parse a manifest from a JSON file.  Returns std::nullopt and sets
// *err on failure.
std::optional<Manifest> load_manifest(const std::string& path,
                                      std::string*       err = nullptr);

// Parse a manifest from an already-loaded JSON object.  `source_path` is
// stored in Manifest::manifest_path for diagnostics.
std::optional<Manifest> parse_manifest(const nlohmann::json& j,
                                       const std::string&    source_path = {},
                                       std::string*          err         = nullptr);

// Effective verb for a package: explicit `verb` field, or inferred from the
// source/target kinds ("vfs_push" / "vfs_pull" / "copy").
std::string effective_verb(const Package& pkg);

} // namespace pm::installer
