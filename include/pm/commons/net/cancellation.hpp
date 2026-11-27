#pragma once

#include <functional>

namespace pm::commons::net {

/// Return true to abort an in-flight transfer. Empty means never cancel.
using CancelCheck = std::function<bool()>;

} // namespace pm::commons::net
