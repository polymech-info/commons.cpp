#pragma once
// installer/engine.hpp — manifest execution entry point.

#include "installer/events.hpp"
#include "installer/manifest.hpp"
#include "installer/variables.hpp"

namespace pm::installer {

// Execute all packages in the manifest through the verb registry.
ManifestResult execute_manifest(const Manifest&                     manifest,
                                const VariableMap& vars,
                                RunOptions                          options = {},
                                InstallEvents                       events    = {});

} // namespace pm::installer
