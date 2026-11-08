#ifndef CLI_COMMAND_TREE_DOC_HPP
#define CLI_COMMAND_TREE_DOC_HPP

#include "cli/command_option_info.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace pm::cli {

/// One node in a CLI11 command tree, with its markdown documentation.
/// Top-level commands carry markdown that includes subcommands, plus a
/// `children` list. Child nodes carry markdown for that subcommand only.
struct CommandTreeDocNode {
    std::string                     id;
    std::string                     label;
    std::string                     group;
    std::string                     description;
    std::string                     usage;
    std::string                     markdown;
    std::vector<CommandOptionInfo>  options;
    std::vector<CommandTreeDocNode> children;
    bool                            available = true;
};

/// Copy of the cached tree. Empty until `set_command_tree_hooks` runs.
std::vector<CommandTreeDocNode> command_tree_doc();

/// `{ "commands": [ {id,label,group,description,usage,markdown,options,children,available} ] }`
nlohmann::json command_tree_doc_payload();

} // namespace pm::cli

#endif
