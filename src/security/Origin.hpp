#pragma once
//
// pm::security::origin — first-party binary provenance registry.
//
// Every ToolRequest carries an `Origin` (types.hpp) describing which of our own
// binaries is driving the call. For now this is provenance + implicit trust
// only: requests originating from one of our known binaries are `firstParty`
// (trusted), everything else is third-party / Unknown. Hash-binding the origin
// (verifying the actual executable signature) is a later phase — the map here is
// keyed by binary basename.
//
// Design reference: docs/security/design.md, docs/security/todos.md.
//

#include "security/types.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace pm::security {

/// Resolve a binary name or full path to an Origin. Accepts "tanit.exe",
/// "pm-image", or an absolute path; matching is on the (lowercased) basename and
/// is extension-insensitive. Unknown binaries resolve to a non-first-party
/// Origin with `kind == OriginKind::Unknown`.
Origin resolve_origin(std::string_view binaryNameOrPath);

/// The full set of registered first-party origins (UI app, CLI, security CLI).
std::vector<Origin> known_origins();

/// Best-effort Origin of the current process (from the OS module path). Falls
/// back to a generic Unknown origin when the path cannot be determined.
Origin current_process_origin();

} // namespace pm::security
