#pragma once

#include "cli/cli_command_tree_doc.hpp"

#include <CLI/CLI.hpp>

#include <functional>
#include <string>
#include <vector>

namespace pm::cli {

/// One catalog row. A synthetic row is copied as-is. Any other row is filled
/// from the matching CLI11 subcommand, or from these fields when it has none.
struct CommandTreeCatalogEntry {
    std::string id;
    std::string label;
    bool        available = true;
    bool        synthetic = false;
    std::string group;
    std::string description;
    std::string usage;
    std::string markdown;
};

/// `register_app` fills a CLI11 app. `catalog`, when set, is the whole list:
/// an empty result stays empty. When `catalog` is unset, the tree is the
/// app's top-level subcommands. `exe_name` is the usage prefix.
struct CommandTreeHooks {
    std::function<void(CLI::App&)> register_app;
    std::function<std::vector<CommandTreeCatalogEntry>()> catalog;
    std::string exe_name;
};

void set_command_tree_hooks(CommandTreeHooks hooks);

} // namespace pm::cli
