#pragma once
//
// pm::security — compile-time hard-limit tables for the LLM FS guard.
//
// These tables define the deny floors that no grant or policy can override.
// They are intentionally self-contained (no media/probe.hpp, no UI headers,
// no FEATURE_* guards) so they can be compiled into any target — security
// CLI, main app, or test harness — without dragging in the full UI stack.
//
// Relationship to src/file_extensions.hpp:
//   The pmui:: tables in file_extensions.hpp are the CURRENT consumers of
//   the same logical data.  Future work ("Delegate migration" in todos.md):
//   migrate llm_fs_guard.cpp / FsTools.cpp / RunTool.cpp to use these
//   pm::security tables as the authoritative source and delete the duplicate
//   pmui:: copies.  Until then both live in parallel; keep them in sync.
//
// Design: hard limits vs. permission gates
//   Scripts and source-code are NOT hard-blocked on extension alone; they are
//   gated through the PolicyEngine (Ask / High-risk consent).  Hard limits apply
//   only when the TARGET DIRECTORY is protected or the format is an opaque binary
//   carrier.  The "combine" rule: directory-protection check (k_write_blocked_abs_prefixes
//   / k_sensitive_path_prefixes) fires FIRST and produces a hard Deny regardless
//   of extension — so writing a .ps1 into C:\Windows\ is still unconditionally
//   denied even though .ps1 is not in k_write_blocked_exts.
//
// Naming convention
//   k_sensitive_path_prefixes    — paths that must never be exposed to the LLM
//   k_write_blocked_exts         — opaque-binary/executable exts: always Deny
//   k_write_elevated_risk_exts   — scripts/source: permission-gated (Ask/High risk)
//   k_write_blocked_abs_prefixes — absolute directory prefixes always denied for writes
//   k_read_blocked_exts          — extensions blocked from LLM glob/read enumeration
//   k_shell_exec_blocked_exts    — extensions that ShellExecute "open" must not run
//
// All narrow-string arrays are null-terminated (iterate: for(const char* const* p = …; *p; ++p)).
// k_shell_exec_blocked_exts uses std::string_view (cross-platform; no wchar_t).
//

#include <string_view>

namespace pm::security {

// ── Sensitive path prefixes ───────────────────────────────────────────────────
// Normalized to forward slashes. On Windows both path and pattern are lowercased
// before comparison. Glob patterns use ** / * / ? (see PathSecurity::globMatch).
// Null-terminated.

inline constexpr const char* k_sensitive_path_prefixes[] = {
    // ===== UNIX system paths =====
    "/etc/",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/",
    "/root/",
    "/var/lib/",
    "/var/run/secrets/",
    "/proc/",
    "/sys/",

    // ===== Generic secrets mounts =====
    "/run/secrets/",
    "/mnt/secrets/",
    "/secrets/",

    // ===== Portable user / app secrets =====
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.config/gcloud/**",
    "**/.aws/**",
    "**/.kube/**",
    "**/.docker/**",
    "**/.local/share/keyrings/**",
    "**/.azure/**",
    "**/.oci/**",
    "**/.config/gh/**",
    "**/.config/doctl/**",
    "**/.config/git/**",
    "**/.config/openstack/**",
    "**/.netlify/**",
    "**/.vercel/**",
    "**/.cargo/**",
    "**/.gem/**",
    "**/.bundle/**",
    "**/.composer/**",
    "**/.m2/**",
    "**/.terraform.d/**",
    "**/.vault-token",

    // ===== Developer credential / token files =====
    "**/.npmrc",
    "**/.yarnrc",
    "**/.yarnrc.yml",
    "**/.pnpmrc",
    "**/.git-credentials",
    "**/.gitconfig",
    "**/.netrc",
    "**/_netrc",
    "**/.pgpass",
    "**/.my.cnf",
    "**/.htpasswd",
    "**/.pypirc",
    "**/.boto",
    "**/.s3cfg",
    "**/.terraformrc",
    "**/credentials",
    "**/credentials.toml",
    "**/auth.json",
    "**/*.tfstate",
    "**/*.tfstate.backup",
    "**/secring.gpg",

    // macOS user Library
    "**/Library/Keychains/**",
    "**/Library/Application Support/CloudDocs/**",
    "**/Library/Application Support/com.apple.TCC/**",
    "**/Library/Containers/**",
    "**/.zsh_history",
    "**/.bash_history",

    // ===== Windows (lowercase; matches any drive letter) =====
    "**/windows/system32/config/",
    "**/windows/system32/drivers/etc/hosts",
    "**/users/*/appdata/roaming/microsoft/credentials/**",
    "**/users/*/appdata/local/microsoft/credentials/**",
    "**/users/*/appdata/roaming/microsoft/protect/**",
    "**/users/*/appdata/roaming/microsoft/crypto/**",
    "**/users/*/appdata/roaming/microsoft/vault/**",
    "**/users/*/ntuser.dat",
    "**/Google/Chrome/**",
    "**/Mozilla/Firefox/**",

    // ===== Project-level =====
    "**/.git/**",
    "**/.env*",
    "**/node_modules/**",

    // ===== Sensitive basenames anywhere =====
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.crt",
    "**/*.der",
    "**/*.csr",
    "**/*.env",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/known_hosts",
    "**/authorized_keys",
    "**/wallet.dat",
    "**/*.kdbx",
    "**/*.sqlite",
    "**/*.sqlite3",
    "**/*.sqlite-wal",
    "**/*.sqlite-shm",
    "**/*.db-shm",
    "**/*.db-wal",
    "**/*.db",
    "**/*.mdb",
    "**/*.accdb",
    "**/*.duckdb",
    "**/*.realm",
    "**/*.fdb",
    "**/*.sql",
    "**/*.dump",
    "**/*.backup",
    "**/*.bak",
    "**/*.ndjson",
    "**/*.parquet",
    "**/*.orc",
    "**/*.avro",
    "**/*.bson",
    "**/cookies.sqlite",
    "**/Login Data",
    "**/Web Data",
    "**/NTUSER.DAT",
    "**/config.json",
    "**/credentials.json",
    "**/secrets.json",

    // common dev seed / migration / fixture filenames
    "**/seed.sql",
    "**/seeds.sql",
    "**/seed.json",
    "**/seeds.json",
    "**/seed.yaml",
    "**/seed.yml",
    "**/seeds.yaml",
    "**/seeds.yml",
    "**/seed.ts",
    "**/seed.js",
    "**/seed.mjs",
    "**/seed.cjs",
    "**/seeds.ts",
    "**/seeds.js",
    "**/fixtures.sql",
    "**/.seed.sql",

    nullptr,
};

// ── Write-blocked extensions ──────────────────────────────────────────────────
// Hard limits: extensions the LLM tool layer may NEVER write, regardless of any
// grant.  Only opaque binary/executable/package/archive formats belong here.
//
// Scripts and source-code files are NOT hard-blocked; they are gated through the
// permission system (PolicyEngine raises risk → Ask or Deny based on context).
// The "directory + extension" combination rule applies: writing any file —
// including plaintext/source — into a protected directory (k_write_blocked_abs_prefixes
// or k_sensitive_path_prefixes) is a hard Deny regardless of extension.
//
// Null-terminated.

inline constexpr const char* k_write_blocked_exts[] = {
    // Windows executables, launchers & shortcuts
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msc",
    ".msi", ".msp", ".msix", ".appx", ".application",
    ".lnk", ".url", ".scf",
    // JVM / managed packages
    ".jar", ".war", ".ear", ".class",
    // OS packages & disk images
    ".deb", ".rpm", ".dmg", ".pkg",
    // archives (opaque carriers; content cannot be audited at write time)
    ".zip", ".7z", ".rar", ".cab", ".tar", ".lz4",
    ".tgz", ".tbz2", ".txz",
    ".iso", ".img", ".vhd", ".vhdx", ".wim",
    // databases & data dumps (often PII / credentials)
    ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb",
    ".duckdb", ".realm", ".fdb",
    ".dump", ".backup",
    ".parquet", ".orc", ".avro", ".bson",
    // other opaque binary carriers
    ".wasm", ".apk", ".ipa",
    // shared libraries (cannot be safely written into arbitrary locations)
    ".so", ".dylib",
    nullptr,
};

// ── Write elevated-risk extensions ────────────────────────────────────────────
// Scripts and source-code files: NOT hard-blocked — they can be written with
// an explicit user grant.  The PolicyEngine uses this list to escalate writes
// to High risk (→ Ask consent) and to generate targeted recovery hints.
// Combined with k_write_blocked_abs_prefixes this achieves the "directory +
// extension" rule: a script write into a protected directory is a hard Deny
// (the directory check fires first); a script write into the workspace asks.
// Null-terminated.

inline constexpr const char* k_write_elevated_risk_exts[] = {
    // Windows script engines
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
    ".reg", ".inf",
    // POSIX shells
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh", ".tcsh",
    // interpreted languages
    ".py", ".pyw", ".pl", ".pm", ".rb", ".lua", ".php",
    ".tcl", ".awk", ".r",
    // JavaScript / TypeScript runtimes
    ".js", ".jse", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts",
    // compiled-language source (high-risk when written to build dirs)
    ".rs", ".go", ".java", ".cs", ".fs", ".fsx",
    ".kt", ".kts", ".swift", ".scala", ".groovy", ".gradle",
    ".dart", ".nim", ".ex", ".exs",
    ".jsx", ".vue", ".svelte",
    nullptr,
};

// ── Write-blocked absolute path prefixes ─────────────────────────────────────
// Null-terminated. Checked case-insensitively on Windows.

inline constexpr const char* k_write_blocked_abs_prefixes[] = {
#if defined(_WIN32)
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\",
#endif
    "/bin/",
    "/sbin/",
    "/boot/",
    "/lib/",
    "/lib64/",
    "/usr/bin/",
    "/usr/sbin/",
    "/etc/",
    "/root/",
    nullptr,
};

// ── Read/glob-blocked extensions ─────────────────────────────────────────────
// Extensions blocked from LLM file-read / glob enumeration.
// Null-terminated.

inline constexpr const char* k_read_blocked_exts[] = {
    ".png",  ".apng", ".jpg",  ".jpeg", ".jpe",  ".jfif", ".gif",  ".webp", ".bmp",
    ".tif",  ".tiff", ".ico",  ".heic", ".heif", ".avif", ".jxl",  ".psd",
    ".exr",  ".hdr",  ".raw",  ".cr2",  ".nef",  ".orf",  ".sr2",  ".dng",
    ".exe",  ".dll",  ".sys",  ".msi",  ".com",  ".cab",  ".so",   ".dylib",
    ".bundle", ".lib", ".a",   ".o",    ".obj",  ".pdb",  ".ilk",  ".exp",
    ".zip",  ".7z",   ".rar",  ".tar",  ".gz",   ".bz2",  ".xz",   ".zst",
    ".apk",  ".ipa",  ".wasm",
    ".woff", ".woff2", ".ttf", ".otf",  ".eot",
    ".mp3",  ".mp4",  ".m4a",  ".webm", ".mov",  ".avi",  ".mkv",  ".flac",
    ".pdf",
    nullptr,
};

// ── Shell-execute-blocked extensions ─────────────────────────────────────────
// Extensions that ShellExecute "open" would run rather than display.
// Used by open_path / open_user_file to block LLM-injected executable paths.
// Uses std::string_view (cross-platform; avoids wchar_t dependency).

inline constexpr std::string_view k_shell_exec_blocked_exts[] = {
    // Windows executables & launchers
    ".exe", ".com", ".pif", ".scr", ".cpl", ".msc",
    ".msi", ".msp", ".msix", ".appx", ".application",
    // shortcuts & jump targets
    ".lnk", ".url", ".scf",
    // scripts (Windows)
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
    ".reg", ".inf",
    // scripts (cross-platform)
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh",
    ".py", ".pyw", ".pl", ".rb", ".lua", ".php",
    ".js", ".jse", ".mjs", ".cjs", ".ts",
    // libraries & bytecode that shellexec can launch indirectly
    ".dll", ".jar",
};

} // namespace pm::security
