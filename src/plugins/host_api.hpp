#pragma once

#include "plugin_abi.h"

namespace pm::plugins {

/** Process-wide host table passed to plugins on load. Valid for the process lifetime. */
const PmHostApi& host_api() noexcept;

void refresh_host_paths() noexcept;

} // namespace pm::plugins
