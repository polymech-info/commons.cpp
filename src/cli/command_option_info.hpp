#pragma once

#include <string>

namespace pm::cli {

struct CommandOptionInfo {
    std::string name;
    std::string type_name;
    std::string description;
    std::string default_value;
    bool        required = false;
    bool        positional = false;
};

} // namespace pm::cli
