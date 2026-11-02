#pragma once
//
// pm::security — global header / module umbrella.
//
// Include this from call sites that route tool calls through the gateway. It:
//   1. provides backward-compatible defaults for every FEATURE_SECURITY_* macro
//      (so the module compiles even when CMake hasn't defined them),
//   2. resolves the compiled default `Profile` from `SECURITY_PROFILE_DEFAULT`,
//   3. pulls in the public surface of the security module.
//
// Feature flags are documented in CMakePresets.json (vendor.pm.features) and
// wired as compile definitions in CMakeLists.txt. Profile mapping and the
// per-OS encryption backends are described in docs/security/design.md and
// tracked in docs/security/todos.md.
//

#include "security/types.hpp"

// ── FEATURE_SECURITY_* defaults ───────────────────────────────────────────────
// When CMake does not pass a definition (e.g. tooling, IntelliSense, unit-test
// harnesses), default the portable gateway pieces ON and the OS crypto/ACL
// backends OFF (they require explicit per-OS opt-in).

#ifndef FEATURE_SECURITY_GATEWAY
#  define FEATURE_SECURITY_GATEWAY 1
#endif
#ifndef FEATURE_SECURITY_SANDBOX
#  define FEATURE_SECURITY_SANDBOX 1
#endif
#ifndef FEATURE_SECURITY_POLICY_ENGINE
#  define FEATURE_SECURITY_POLICY_ENGINE 1
#endif
#ifndef FEATURE_SECURITY_PERMISSION_STORE
#  define FEATURE_SECURITY_PERMISSION_STORE 1
#endif
#ifndef FEATURE_SECURITY_AUDIT_LOG
#  define FEATURE_SECURITY_AUDIT_LOG 1
#endif
#ifndef FEATURE_SECURITY_CONSENT_DELEGATE
#  define FEATURE_SECURITY_CONSENT_DELEGATE 1
#endif
#ifndef FEATURE_SECURITY_RESOURCE_CLASSIFIER
#  define FEATURE_SECURITY_RESOURCE_CLASSIFIER 1
#endif
#ifndef FEATURE_SECURITY_PATH_SECURITY
#  define FEATURE_SECURITY_PATH_SECURITY 1
#endif
#ifndef FEATURE_SECURITY_TOOL_IDENTITY
#  define FEATURE_SECURITY_TOOL_IDENTITY 1
#endif
#ifndef FEATURE_SECURITY_MCP_POLICY
#  define FEATURE_SECURITY_MCP_POLICY 1
#endif
#ifndef FEATURE_SECURITY_SECRET_SCAN
#  define FEATURE_SECURITY_SECRET_SCAN 1
#endif

// OS-specific encryption / hardening backends — explicit opt-in only.
#ifndef FEATURE_SECURITY_CRYPTO_WIN_DPAPI
#  define FEATURE_SECURITY_CRYPTO_WIN_DPAPI 0
#endif
#ifndef FEATURE_SECURITY_WIN_ACL
#  define FEATURE_SECURITY_WIN_ACL 0
#endif
#ifndef FEATURE_SECURITY_CRYPTO_MAC_KEYCHAIN
#  define FEATURE_SECURITY_CRYPTO_MAC_KEYCHAIN 0
#endif
#ifndef FEATURE_SECURITY_CRYPTO_LINUX_SECRET_SERVICE
#  define FEATURE_SECURITY_CRYPTO_LINUX_SECRET_SERVICE 0
#endif

// ── Compiled default profile ──────────────────────────────────────────────────
// CMake translates the `SECURITY_PROFILE` string to a numeric
// `SECURITY_PROFILE_DEFAULT` (0=LIGHT, 1=STRICT, 2=DEVELOPER). Default LIGHT.

#ifndef SECURITY_PROFILE_DEFAULT
#  define SECURITY_PROFILE_DEFAULT 0
#endif

namespace pm::security {

/// Whether any encryption backend is compiled in for this platform/build.
inline constexpr bool k_has_crypto_backend =
    (FEATURE_SECURITY_CRYPTO_WIN_DPAPI != 0) ||
    (FEATURE_SECURITY_CRYPTO_MAC_KEYCHAIN != 0) ||
    (FEATURE_SECURITY_CRYPTO_LINUX_SECRET_SERVICE != 0);

/// The compile-time default posture (overridable per ToolRequest).
inline constexpr Profile k_default_profile =
#if SECURITY_PROFILE_DEFAULT == 1
    Profile::Strict;
#elif SECURITY_PROFILE_DEFAULT == 2
    Profile::Developer;
#else
    Profile::Light;
#endif

} // namespace pm::security

// ── Hard-limit tables ─────────────────────────────────────────────────────────
// Self-contained deny-list tables (no UI / probe dependencies).
// Exposed here so any consumer of security_default.hpp automatically has access
// to k_sensitive_path_prefixes, k_write_blocked_exts, k_shell_exec_blocked_exts,
// etc. without a separate include.  See docs/security/todos.md "Delegate migration"
// for the planned migration away from the parallel pmui:: tables in
// src/file_extensions.hpp.
#include "security/hard_limits.hpp"

// ── Public module surface ─────────────────────────────────────────────────────
#include "security/PathSecurity.hpp"
#include "security/UriScope.hpp"
#include "security/Origin.hpp"
#include "security/ResourceClassifier.hpp"
#include "security/ToolIdentity.hpp"
#include "security/CryptoStore.hpp"
#include "security/PermissionStore.hpp"
#include "security/AuditLog.hpp"
#include "security/ConsentDelegate.hpp"
#include "security/PolicyEngine.hpp"
#include "security/SecurityGateway.hpp"
