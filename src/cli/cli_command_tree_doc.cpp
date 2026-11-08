#include "cli_command_tree_hooks.hpp"

#include "cli_md_generator.hpp"

#include <CLI/CLI.hpp>

#include <memory>
#include <mutex>
#include <sstream>
#include <utility>

namespace pm::cli {

namespace md = pm::cli_md;

namespace {

struct State {
    std::mutex mutex;
    CommandTreeHooks hooks;
    std::unique_ptr<CLI::App> app;
    std::vector<CommandTreeDocNode> nodes;
    bool built = false;
};

State& state()
{
    static State s;
    return s;
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

std::string build_usage(const std::string& exe, const std::string& path)
{
    if (exe.empty())
        return path + " [OPTIONS]";
    return exe + " " + path + " [OPTIONS]";
}

md::AppendConfig doc_config()
{
    md::AppendConfig cfg;
    cfg.heading_base = 1;
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

void build_node(CommandTreeDocNode& node,
                CLI::App* sub,
                const std::string& path,
                const std::string& exe)
{
    node.id = path;
    node.label = sub ? sub->get_name() : path;
    node.group = sub ? sub->get_group() : std::string{};
    node.description = sub ? sub->get_description() : std::string{};
    node.usage = build_usage(exe, path);
    node.options = collect_options(sub);
    node.markdown = generate_markdown(sub, path);
    node.available = true;
    if (sub) {
        for (auto* child : sub->get_subcommands({})) {
            if (!child || child->get_name().empty())
                continue;
            CommandTreeDocNode childNode;
            build_node(childNode, child, path + " " + child->get_name(), exe);
            node.children.push_back(std::move(childNode));
        }
    }
}

std::string stub_markdown(const std::string& id, const std::string& label)
{
    std::ostringstream os;
    os << "## " << id << "\n\n";
    if (!label.empty())
        os << label << ".\n\n";
    return os.str();
}

std::vector<CommandTreeCatalogEntry> catalog_or_subcommands(CLI::App& app, const CommandTreeHooks& hooks)
{
    if (hooks.catalog)
        return hooks.catalog();
    std::vector<CommandTreeCatalogEntry> entries;
    for (auto* child : app.get_subcommands({})) {
        if (!child || child->get_name().empty())
            continue;
        CommandTreeCatalogEntry e;
        e.id = child->get_name();
        e.label = e.id;
        entries.push_back(std::move(e));
    }
    return entries;
}

std::vector<CommandTreeDocNode> build_command_tree_doc(CLI::App& app, const CommandTreeHooks& hooks)
{
    std::vector<CommandTreeDocNode> out;
    for (const auto& e : catalog_or_subcommands(app, hooks)) {
        if (!e.available || e.id.empty())
            continue;
        CommandTreeDocNode node;
        if (!e.synthetic) {
            if (auto* sub = md::find_child_command(app, e.id)) {
                build_node(node, sub, e.id, hooks.exe_name);
                out.push_back(std::move(node));
                continue;
            }
        }
        node.id = e.id;
        node.label = e.label.empty() ? e.id : e.label;
        node.group = e.group.empty() ? "Other" : e.group;
        node.description = !e.description.empty() ? e.description : e.label;
        node.usage = !e.usage.empty() ? e.usage : build_usage(hooks.exe_name, e.id);
        node.available = true;
        node.markdown = !e.markdown.empty() ? e.markdown : stub_markdown(e.id, e.label);
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

const std::vector<CommandTreeDocNode>& build_locked(State& s)
{
    if (s.built)
        return s.nodes;
    s.app = std::make_unique<CLI::App>("__command_tree_doc__");
    if (s.hooks.register_app)
        s.hooks.register_app(*s.app);
    s.nodes = build_command_tree_doc(*s.app, s.hooks);
    s.built = true;
    return s.nodes;
}

} // namespace

void set_command_tree_hooks(CommandTreeHooks hooks)
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    s.hooks = std::move(hooks);
    s.app.reset();
    s.nodes.clear();
    s.built = false;
}

std::vector<CommandTreeDocNode> command_tree_doc()
{
    auto& s = state();
    std::lock_guard<std::mutex> lock(s.mutex);
    return build_locked(s);
}

nlohmann::json command_tree_doc_payload()
{
    return nlohmann::json{{"commands", nodes_json(command_tree_doc())}};
}

} // namespace pm::cli
