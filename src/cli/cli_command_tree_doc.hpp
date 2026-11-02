#ifndef CLI_COMMAND_TREE_DOC_HPP
#define CLI_COMMAND_TREE_DOC_HPP

#include "pm_image_command_info.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace pm::cli {

/// One node in the registered-CLI command tree, with its markdown documentation.
/// Top-level commands (e.g. "audio") carry their own markdown (which includes
/// subcommands) plus a `children` list; child nodes (e.g. "audio record") carry
/// a focused markdown for just that subcommand.
struct CommandTreeDocNode {
    std::string                        id;          ///< full path, e.g. "audio" or "audio record"
    std::string                        label;       ///< CLI11 subcommand name
    std::string                        group;       ///< CLI11 display group ("Image", "Search", ...)
    std::string                        description;
    std::string                        usage;
    std::string                        markdown;    ///< generated markdown for this node
    std::vector<CommandOptionInfo>     options;
    std::vector<CommandTreeDocNode>    children;
    bool                               available = true;
};

/// Build (and cache) the registered-CLI command tree with per-node markdown.
/// The CLI11 app is constructed once via pm_image_register_cli() and kept in
/// memory for the process lifetime; subsequent calls return the cached tree.
const std::vector<CommandTreeDocNode>& command_tree_doc();

/// JSON payload for the shared host bridge: an array of nodes, each with
/// {id,label,group,description,usage,markdown,options,children,available}.
nlohmann::json command_tree_doc_payload();

} // namespace pm::cli

#endif
