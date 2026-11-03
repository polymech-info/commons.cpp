#pragma once

#include <string>
#include <unordered_map>

namespace pm::installer {

// Same type as media::commands::VariableMap. Callers can pass that map
// without a conversion.
using VariableMap = std::unordered_map<std::string, std::string>;

} // namespace pm::installer
