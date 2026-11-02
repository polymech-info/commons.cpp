#include "cli_command_tree_doc.hpp"

#include "pm_image_register_cli.hpp"
#include "cli/cli_ui_launch.hpp"
#include "doc/cli_md_generator.hpp"

#include <CLI/CLI.hpp>

#include <mutex>
#include <sstream>

namespace pm::cli {

namespace md = pm::cli_md;

namespace {

struct CachedTree {
    std::vector<CommandTreeDocNode> nodes;
    CLI::App app{"__command_tree_doc__"};
    PmImageCliState state{};
    bool built = false;
};

// Forward decl: defined below. Walks the CLI11 app into doc nodes.
std::vector<CommandTreeDocNode> build_command_tree_doc(CLI::App& app);

CachedTree& cached_tree()
{
    static CachedTree t;
    static std::mutex m;
    std::lock_guard<std::mutex> lock(m);
    if (!t.built) {
        // Build the full CLI11 grammar once. This populates subcommands and
        // registered_cli_command_details() as a side effect; both are
        // deterministic and idempotent across a process lifetime.
        pm_image_register_cli(t.app, t.state, k_cmds_all);
        t.nodes = build_command_tree_doc(t.app);
        t.built = true;
    }
    return t;
}

std::string command_option_primary_name(const CLI::Option* opt)
{
    if (!opt)
        return {};
    return opt->get_name(opt->get_positional(), true);
}

std::vector<CommandOptionInfo> collect_options(CLI::App* cmd)
{
    std::vector<CommandOptionInfo> out;
    if (!cmd)
        return out;
    for (const auto* opt : cmd->get_options()) {
        if (!opt)
            continue;
        const std::string name = command_option_primary_name(opt);
        if (name.empty() || name == "-h,--help" || name == "--help" || name == "-h")
            continue;
        out.push_back(CommandOptionInfo{
            name,
            opt->get_type_name(),
            opt->get_description(),
            opt->get_default_str(),
            opt->get_required(),
            opt->get_positional(),
        });
    }
    return out;
}

std::string build_usage(const std::string& path)
{
    return std::string(pm::brand::k_exe_basename_cli_u8) + " " + path + " [OPTIONS]";
}

md::AppendConfig doc_config()
{
    md::AppendConfig cfg;
    cfg.heading_base = 1;   // top command -> "##"
    cfg.fixed_heading = 0;
    cfg.hr_between_siblings = true;
    return cfg;
}

std::string generate_markdown(CLI::App* sub, const std::string& path)
{
    if (!sub || path.empty())
        return {};
    std::ostringstream os;
    md::append_cli_app(os, sub, path, 1, doc_config());
    return os.str();
}

void build_node(CommandTreeDocNode& node, CLI::App* sub, const std::string& path)
{
    node.id = path;
    node.label = sub ? sub->get_name() : path;
    node.group = sub ? sub->get_group() : std::string{};
    node.description = sub ? sub->get_description() : std::string{};
    node.usage = build_usage(path);
    node.options = collect_options(sub);
    node.markdown = generate_markdown(sub, path);
    node.available = true;
    if (sub) {
        for (auto* child : sub->get_subcommands({})) {
            if (!child || child->get_name().empty())
                continue;
            CommandTreeDocNode childNode;
            build_node(childNode, child, path + " " + child->get_name());
            node.children.push_back(std::move(childNode));
        }
    }
}

std::vector<CommandTreeDocNode> build_command_tree_doc(CLI::App& app)
{
    std::vector<CommandTreeDocNode> out;
    const auto registered = pm::cli::registered_cli_commands();
    for (const auto& c : registered) {
        if (!c.available)
            continue;
        const std::string id = c.id ? c.id : "";
        if (id.empty())
            continue;
        CommandTreeDocNode node;
        if (auto* sub = md::find_child_command(app, id)) {
            build_node(node, sub, id);
        } else if (pm::cli::is_cli_ui_launch_command(id)) {
            // Synthetic "ui" launch command has no CLI11 subcommand.
            node.id = id;
            node.label = id;
            node.group = "App Control";
            node.description = c.label ? c.label : "";
            node.usage = std::string(pm::brand::k_exe_basename_u8) + " --ui-preset main";
            node.available = true;
            std::ostringstream os;
            os << "## " << id << "\n\n";
            if (c.label && c.label[0])
                os << c.label << ". ";
            os << "Launch `" << pm::brand::k_exe_basename_u8
               << "` with **no subcommand** (full reference: `info ui`).\n\n";
            node.markdown = os.str();
        } else {
            // Registered but no live CLI11 subcommand: minimal stub.
            node.id = id;
            node.label = id;
            node.group = "Other";
            node.description = c.label ? c.label : "";
            node.usage = build_usage(id);
            node.available = true;
            std::ostringstream os;
            os << "## " << id << "\n\n";
            if (c.label && c.label[0])
                os << c.label << ".\n\n";
            node.markdown = os.str();
        }
        out.push_back(std::move(node));
    }
    return out;
}

nlohmann::json options_json(const std::vector<CommandOptionInfo>& opts)
{
    auto arr = nlohmann::json::array();
    for (const auto& o : opts) {
        arr.push_back({
            {"name", o.name},
            {"type", o.type_name},
            {"description", o.description},
            {"default", o.default_value},
            {"required", o.required},
            {"positional", o.positional},
        });
    }
    return arr;
}

nlohmann::json nodes_json(const std::vector<CommandTreeDocNode>& nodes)
{
    auto arr = nlohmann::json::array();
    for (const auto& n : nodes) {
        arr.push_back({
            {"id", n.id},
            {"label", n.label},
            {"group", n.group},
            {"description", n.description},
            {"usage", n.usage},
            {"markdown", n.markdown},
            {"options", options_json(n.options)},
            {"children", nodes_json(n.children)},
            {"available", n.available},
        });
    }
    return arr;
}

} // namespace

const std::vector<CommandTreeDocNode>& command_tree_doc()
{
    return cached_tree().nodes;
}

nlohmann::json command_tree_doc_payload()
{
    return nlohmann::json{{"commands", nodes_json(command_tree_doc())}};
}

} // namespace pm::cli
