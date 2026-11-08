#include "cli/cli_doc_markdown.hpp"
#include "fs/path_sanitizer.hpp"
#include "cli/cli_option_schema.hpp"
#include "cli_md_generator.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace pm::cli_md {
namespace {

std::string first_enum_token(const std::string& type_name)
{
    const auto lb = type_name.find('{');
    const auto rb = type_name.find('}');
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb + 1)
        return {};
    std::string inner = type_name.substr(lb + 1, rb - lb - 1);
    const auto comma = inner.find(',');
    if (comma != std::string::npos)
        inner = inner.substr(0, comma);
    const auto arrow = inner.find("->");
    if (arrow != std::string::npos)
        inner = inner.substr(0, arrow);
    while (!inner.empty() && (inner.front() == ' ' || inner.front() == '\t'))
        inner.erase(inner.begin());
    while (!inner.empty() && (inner.back() == ' ' || inner.back() == '\t'))
        inner.pop_back();
    return inner;
}

bool looks_numeric(const std::string& value)
{
    if (value.empty())
        return false;
    std::size_t i = 0;
    if (value[i] == '-' || value[i] == '+')
        ++i;
    if (i >= value.size())
        return false;
    bool saw_digit = false;
    for (; i < value.size(); ++i) {
        const char c = value[i];
        if (c >= '0' && c <= '9') {
            saw_digit = true;
            continue;
        }
        if (c == '.' && saw_digit)
            continue;
        return false;
    }
    return saw_digit;
}

std::string format_shell_value(const std::string& value, bool force_string)
{
    if (value.empty())
        return "''";
    if (!force_string && looks_numeric(value))
        return value;
    std::string out;
    out.push_back('\'');
    for (char c : value) {
        if (c == '\'')
            out += "'\\''";
        else
            out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

std::string infer_option_value(const CLI::Option* opt)
{
    if (!opt)
        return "foo";

    const std::string def = option_default_str(opt);
    if (!def.empty())
        return def;

    const std::string type = opt->get_type_name();
    if (type.find("INT") != std::string::npos
        || type.find("NUMBER") != std::string::npos
        || type.find("size_t") != std::string::npos
        || type.find("BIGINT") != std::string::npos) {
        return "1";
    }

    if (const std::string token = first_enum_token(type); !token.empty())
        return token;

    return "foo";
}

std::string required_arg_placeholder(const std::string& flag)
{
    if (flag.find("path") != std::string::npos)
        return "<path>";
    if (flag.find("file") != std::string::npos)
        return "<file>";
    if (flag.find("uri") != std::string::npos)
        return "<uri>";
    if (flag.find("id") != std::string::npos)
        return "<id>";
    return "<value>";
}

} // namespace

std::string option_primary_name(const CLI::Option* opt)
{
    if (!opt)
        return {};
    return opt->get_name(opt->get_positional(), true);
}

bool skip_option_name(const std::string& name)
{
    return name.empty()
        || name == "-h,--help"
        || name == "--help"
        || name == "-h"
        || name == "--json";
}

std::string option_default_str(const CLI::Option* opt)
{
    if (!opt)
        return {};
    std::string s = opt->get_default_str();
    if (!s.empty())
        return s;
    auto* mut = const_cast<CLI::Option*>(opt);
    mut->capture_default_str();
    return opt->get_default_str();
}

std::string option_long_flag_name(const CLI::Option* opt)
{
    if (!opt)
        return {};
    std::string flag = opt->get_name(opt->get_positional(), true);
    const auto comma = flag.find(',');
    if (comma == std::string::npos)
        return flag;
    const std::string first = flag.substr(0, comma);
    const std::string second = flag.substr(comma + 1);
    if (!second.empty() && second.front() != '-')
        return second;
    if (!first.empty() && first.front() == '-')
        return first;
    return flag;
}

bool option_takes_value(const CLI::Option* opt)
{
    if (!opt)
        return false;
    if (!opt->get_type_name().empty())
        return true;
    if (opt->get_required())
        return true;
    return opt->get_expected_min() > 0;
}

std::string md_escape_cell(std::string s)
{
    for (char& c : s) {
        if (c == '\n' || c == '\r')
            c = ' ';
        if (c == '|')
            c = '/';
    }
    return s;
}

namespace {

std::string trim_cell(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    return s;
}

std::vector<std::string> split_shell_flags_for_display(const std::string& arg)
{
    std::vector<std::string> parts;
    std::size_t pos = 0;
    while (pos < arg.size()) {
        const auto next = arg.find(" --", pos);
        if (next == std::string::npos) {
            const std::string tail = trim_cell(arg.substr(pos));
            if (!tail.empty())
                parts.push_back(tail);
            break;
        }
        const std::string chunk = trim_cell(arg.substr(pos, next - pos));
        if (!chunk.empty())
            parts.push_back(chunk);
        pos = next + 1;
    }
    return parts;
}

} // namespace

std::string format_table_args_cell(const std::vector<std::string>& args)
{
    if (args.empty())
        return {};
    std::ostringstream cell;
    bool first_line = true;
    for (const auto& arg : args) {
        std::vector<std::string> lines = split_shell_flags_for_display(arg);
        if (lines.empty())
            lines.push_back(arg);
        for (const auto& line : lines) {
            if (!first_line)
                cell << "<br>";
            first_line = false;
            cell << "`" << md_escape_cell(line) << "`";
        }
    }
    return cell.str();
}

void append_cli_options(std::ostringstream& os, CLI::App* cmd)
{
    if (!cmd)
        return;

    struct OptGroup {
        std::string name;
        std::vector<const CLI::Option*> opts;
    };
    std::vector<OptGroup> groups;
    for (const auto* opt : cmd->get_options()) {
        if (!opt)
            continue;
        const std::string name = option_primary_name(opt);
        if (skip_option_name(name))
            continue;
        const std::string grp = opt->get_group();
        bool found = false;
        for (auto& g : groups) {
            if (g.name == grp) {
                g.opts.push_back(opt);
                found = true;
                break;
            }
        }
        if (!found)
            groups.push_back({grp, {opt}});
    }

    if (groups.empty())
        return;

    bool has_named = false;
    for (const auto& g : groups) {
        if (!g.name.empty() && g.name != "Options") {
            has_named = true;
            break;
        }
    }
    const bool multi_group = has_named && groups.size() > 1;

    os << "Options:\n\n";
    for (const auto& g : groups) {
        if (multi_group && !g.name.empty() && g.name != "Options")
            os << "**" << g.name << "**\n";
        for (const auto* opt : g.opts) {
            if (skip_option_name(option_primary_name(opt)))
                continue;
            pm::cli::doc_md::append_option_list_line(os, opt);
        }
        os << "\n";
    }
}

void append_cli_app(std::ostringstream& os,
                    CLI::App* cmd,
                    const std::string& path,
                    int depth,
                    const AppendConfig& cfg)
{
    if (!cmd || path.empty())
        return;
    const int heading = cfg.fixed_heading > 0
        ? cfg.fixed_heading
        : std::min(depth + cfg.heading_base, 6);
    const std::string hashes(static_cast<std::size_t>(heading), '#');
    const std::string more_href = overlay_more_href(
        cfg.overlay_dir, cfg.output_dst, path, cfg.overlay_prefix,
        cfg.pages_author, cfg.pages_base);
    if (!more_href.empty())
        os << hashes << " [" << path << "](" << more_href << ")\n\n";
    else
        os << hashes << " " << path << "\n\n";
    if (!cmd->get_description().empty())
        os << cmd->get_description() << "\n\n";

    if (cfg.hooks.on_begin)
        cfg.hooks.on_begin(os, cmd, path);

    append_cli_options(os, cmd);

    if (cfg.hooks.on_end)
        cfg.hooks.on_end(os, cmd, path);

    bool first_child = true;
    for (auto* child : cmd->get_subcommands({})) {
        if (!child || child->get_name().empty())
            continue;
        if (cfg.hr_between_siblings && !first_child)
            os << "---\n\n";
        first_child = false;
        append_cli_app(os, child, path + " " + child->get_name(), depth + 1, cfg);
    }
}

CLI::App* find_child_command(CLI::App& app, const std::string& name)
{
    for (auto* child : app.get_subcommands({})) {
        if (child && child->get_name() == name)
            return child;
    }
    return nullptr;
}

std::string exe_stem_from_basename(const char* exe_basename)
{
    if (!exe_basename || !exe_basename[0])
        return {};
    std::string stem = exe_basename;
    if (stem.size() >= 4 && stem.compare(stem.size() - 4, 4, ".exe") == 0)
        stem.resize(stem.size() - 4);
    return stem;
}

CLI::App* resolve_min_leaf(CLI::App* cmd, std::string& cmd_path)
{
    // Only descend when the node requires a subcommand (e.g. `llm` → `llm agent`).
    // Runnable parents that also have children (e.g. `llm agent` + `each`,
    // `audio record` + `stop`) keep their own examples.
    while (cmd && cmd->get_require_subcommand_min() > 0) {
        CLI::App* next = nullptr;
        for (auto* child : cmd->get_subcommands({})) {
            if (child && !child->get_name().empty()) {
                next = child;
                break;
            }
        }
        if (!next)
            return cmd;
        cmd_path += " ";
        cmd_path += next->get_name();
        cmd = next;
    }
    return cmd;
}

std::string build_min_example_line(const std::string& exe_stem,
                                   const std::string& cmd_path,
                                   CLI::App* leaf)
{
    if (!leaf || cmd_path.empty() || exe_stem.empty())
        return {};

    std::ostringstream ex;
    ex << exe_stem << ' ' << cmd_path;

    for (const auto* opt : leaf->get_options()) {
        if (!opt)
            continue;
        const std::string name = option_primary_name(opt);
        if (skip_option_name(name))
            continue;
        if (!opt->get_required())
            continue;

        const std::string flag = option_long_flag_name(opt);
        ex << ' ' << flag;
        const std::string def = option_default_str(opt);
        if (!def.empty()) {
            if (def.find_first_of(" \t\"'$`\\") != std::string::npos)
                ex << " '" << def << "'";
            else
                ex << ' ' << def;
        } else {
            ex << ' ' << required_arg_placeholder(flag);
        }
    }
    return ex.str();
}

std::string build_full_example_line(const std::string& exe_stem,
                                    const std::string& cmd_path,
                                    CLI::App* leaf)
{
    if (!leaf || cmd_path.empty() || exe_stem.empty())
        return {};

    std::ostringstream ex;
    ex << exe_stem << ' ' << cmd_path;

    for (const auto* opt : leaf->get_options()) {
        if (!opt)
            continue;
        const std::string name = option_primary_name(opt);
        if (skip_option_name(name))
            continue;

        const std::string flag = option_long_flag_name(opt);
        ex << ' ' << flag;
        if (!option_takes_value(opt))
            continue;

        const std::string value = infer_option_value(opt);
        const bool force_string = !opt->get_type_name().empty()
            && opt->get_type_name().find("INT") == std::string::npos
            && opt->get_type_name().find("NUMBER") == std::string::npos
            && opt->get_type_name().find("BIGINT") == std::string::npos;
        ex << ' ' << format_shell_value(value, force_string);
    }
    return ex.str();
}

void append_example_blocks(std::ostringstream& os,
                           const std::string& min_line,
                           const std::string& full_line)
{
    if (min_line.empty())
        return;
    os << "**Example**\n\n```sh\n" << min_line << "\n```\n\n";
    if (!full_line.empty() && full_line != min_line)
        os << "**Full example**\n\n```sh\n" << full_line << "\n```\n\n";
}

void append_command_examples(std::ostringstream& os,
                             CLI::App* cmd,
                             const std::string& path,
                             const std::string& exe_stem)
{
    if (!cmd || path.empty() || exe_stem.empty())
        return;

    std::string example_path = path;
    CLI::App* leaf = resolve_min_leaf(cmd, example_path);
    append_example_blocks(os,
                          build_min_example_line(exe_stem, example_path, leaf),
                          build_full_example_line(exe_stem, example_path, leaf));
}

std::string path_to_overlay_stem(const std::string& path)
{
    std::string stem;
    stem.reserve(path.size());
    for (char c : path)
        stem.push_back(c == ' ' ? '_' : c);
    return stem;
}

std::string kind_to_overlay_stem(const std::string& kind)
{
    const std::string list_devices = "ListDevices";
    if (kind.size() > list_devices.size()
        && kind.compare(kind.size() - list_devices.size(), list_devices.size(), list_devices) == 0) {
        std::string prefix = kind.substr(0, kind.size() - list_devices.size());
        const std::string snake = kind_to_overlay_stem(prefix);
        return snake.empty() ? "list" : snake + "_list";
    }

    std::string stem;
    stem.reserve(kind.size() + 8);
    for (std::size_t i = 0; i < kind.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(kind[i]);
        if (c >= 'A' && c <= 'Z') {
            if (!stem.empty())
                stem.push_back('_');
            stem.push_back(static_cast<char>(c - 'A' + 'a'));
            continue;
        }
        stem.push_back(static_cast<char>(c));
    }
    return stem;
}

namespace {

std::string overlay_lookup_path(const std::string& overlay_prefix, const std::string& path)
{
    if (overlay_prefix == "xblox_" && path.rfind("xblox ", 0) == 0)
        return path.substr(6);
    return path;
}

std::string overlay_file_stem(const std::string& overlay_prefix, const std::string& path)
{
    return overlay_prefix + path_to_overlay_stem(overlay_lookup_path(overlay_prefix, path));
}

} // namespace

std::filesystem::path overlay_dir_from_dst(const std::filesystem::path& dst)
{
    if (dst.empty())
        return {};
    std::error_code ec;
    if (std::filesystem::is_directory(dst, ec) && !ec)
        return dst;
    return dst.parent_path();
}

std::string overlay_relative_href(const std::filesystem::path& output_dst,
                                  const std::filesystem::path& target)
{
    std::string href;
    if (output_dst.empty())
        href = media::path::path_to_generic_utf8(target.filename());
    else {
        std::error_code ec;
        const std::filesystem::path rel =
            std::filesystem::relative(target, output_dst.parent_path(), ec);
        if (ec || rel.empty())
            href = media::path::path_to_generic_utf8(target.filename());
        else
            href = media::path::path_to_generic_utf8(rel);
    }
    if (href.size() >= 3 && href.compare(href.size() - 3, 3, ".md") == 0)
        href.resize(href.size() - 3);
    return href;
}

namespace {

std::string& pages_base_default()
{
    static std::string value;
    return value;
}

std::string& pages_author_default()
{
    static std::string value;
    return value;
}

std::string trim_trailing_slashes(std::string s)
{
    while (!s.empty() && (s.back() == '/' || s.back() == '\\'))
        s.pop_back();
    return s;
}

std::string pages_more_absolute_href(const std::string& slug,
                                     const std::string& pages_author,
                                     const std::string& pages_base)
{
    const std::string base = trim_trailing_slashes(
        pages_base.empty() ? pages_base_default() : pages_base);
    const std::string author =
        pages_author.empty() ? pages_author_default() : pages_author;
    if (base.empty() || author.empty() || slug.empty())
        return {};
    return base + "/user/" + author + "/pages/" + slug;
}

} // namespace

void set_pages_defaults(std::string base, std::string author)
{
    pages_base_default() = std::move(base);
    pages_author_default() = std::move(author);
}

std::string overlay_more_href(const std::filesystem::path& overlay_dir,
                              const std::filesystem::path& output_dst,
                              const std::string& path,
                              const std::string& overlay_prefix,
                              const std::string& pages_author,
                              const std::string& pages_base)
{
    (void)output_dst;
    if (overlay_dir.empty() || path.empty())
        return {};
    const std::filesystem::path more_file =
        overlay_dir / (overlay_file_stem(overlay_prefix, path) + "_more.md");
    std::error_code ec;
    if (!std::filesystem::is_regular_file(more_file, ec) || ec)
        return {};
    return pages_more_absolute_href(media::path::path_to_utf8(more_file.stem()), pages_author, pages_base);
}

void append_more_links(std::ostringstream& os, const std::string& href)
{
    os << "[Read more](" << href << ")\n\n";
}

nlohmann::json xblox_widget_default_options()
{
    return {
        {"showToolbar", true},
        {"showPalette", false},
        {"showProps", false},
        {"hasProps", true},
        {"showRunLog", false},
        {"hasRunLog", true},
        {"showLog", true},
        {"hasLog", true},
        {"showHelp", true},
        {"editable", false},
        {"defaultExpandedDepth", 3},
        {"autoHeight", true},
    };
}

void append_xblox_example_fence(std::ostringstream& os,
                                const std::filesystem::path& overlay_dir,
                                const std::string& path,
                                const std::string& overlay_prefix)
{
    if (overlay_dir.empty() || path.empty())
        return;
    const std::filesystem::path file =
        overlay_dir / (overlay_file_stem(overlay_prefix, path) + "_example.xblox");
    std::error_code ec;
    if (!std::filesystem::is_regular_file(file, ec) || ec)
        return;

    const std::string raw = read_text_file(file);
    if (raw.empty())
        return;

    nlohmann::json document;
    try {
        document = nlohmann::json::parse(raw);
    } catch (...) {
        return;
    }

    const nlohmann::json wrapper = {
        {"options", xblox_widget_default_options()},
        {"document", std::move(document)},
    };

    os << "**Example flow**\n\n```xblox\n";
    os << wrapper.dump(2);
    os << "\n```\n\n";
}

void append_command_overlay(std::ostringstream& os,
                            const std::filesystem::path& overlay_dir,
                            const std::filesystem::path& output_dst,
                            const std::string& path,
                            const std::string& overlay_prefix,
                            const std::string& pages_author,
                            const std::string& pages_base)
{
    if (overlay_dir.empty() || path.empty())
        return;

    const std::filesystem::path file =
        overlay_dir / (overlay_file_stem(overlay_prefix, path) + "_examples.md");
    const std::filesystem::path xblox_file =
        overlay_dir / (overlay_file_stem(overlay_prefix, path) + "_example.xblox");
    const std::string content = read_text_file(file);
    const bool has_overlay = !content.empty();
    const std::string more_href =
        overlay_more_href(overlay_dir, output_dst, path, overlay_prefix, pages_author, pages_base);
    const bool has_more = !more_href.empty();
    std::error_code ec;
    const bool has_xblox =
        std::filesystem::is_regular_file(xblox_file, ec) && !ec;

    if (!has_overlay && !has_more && !has_xblox)
        return;

    if (has_overlay) {
        os << content;
        if (content.back() != '\n')
            os << "\n";
        os << "\n";
    }

    append_xblox_example_fence(os, overlay_dir, path, overlay_prefix);

    if (has_more)
        append_more_links(os, more_href);
}

void on_cli_begin(std::ostringstream& /*os*/, CLI::App* /*cmd*/, const std::string& /*path*/)
{
}

void on_cli_end(std::ostringstream& os,
                CLI::App* cmd,
                const std::string& path,
                const std::string& exe_stem,
                const std::filesystem::path& overlay_dir,
                const std::filesystem::path& output_dst,
                const std::string& overlay_prefix,
                const std::string& pages_author,
                const std::string& pages_base)
{
    append_command_examples(os, cmd, path, exe_stem);
    append_command_overlay(os, overlay_dir, output_dst, path, overlay_prefix, pages_author, pages_base);
}

nlohmann::json cli_options_json(CLI::App* cmd)
{
    nlohmann::json opts = nlohmann::json::array();
    if (!cmd)
        return opts;
    for (const auto* opt : cmd->get_options()) {
        if (!opt)
            continue;
        const std::string nm = option_primary_name(opt);
        if (skip_option_name(nm))
            continue;
        nlohmann::json row = pm::cli::cli_option_to_json(opt);
        row["type"] = row.value("typeName", std::string{});
        opts.push_back(std::move(row));
    }
    return opts;
}

nlohmann::json cli_app_json(CLI::App* cmd)
{
    if (!cmd)
        return nullptr;
    nlohmann::json node = {
        {"name", cmd->get_name()},
        {"description", cmd->get_description()},
        {"group", cmd->get_group()},
        {"options", cli_options_json(cmd)},
        {"subcommands", nlohmann::json::array()},
    };
    for (auto* child : cmd->get_subcommands({})) {
        if (!child || child->get_name().empty())
            continue;
        node["subcommands"].push_back(cli_app_json(child));
    }
    return node;
}

std::string read_text_file(const std::filesystem::path& path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
        return {};
    std::ostringstream ss;
    ss << ifs.rdbuf();
    return ss.str();
}

bool write_text_file(const std::filesystem::path& path,
                     const std::string& text,
                     std::string& err)
{
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        err = "create directories failed: " + ec.message();
        return false;
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        err = "cannot write " + media::path::path_to_utf8(path);
        return false;
    }
    ofs << text;
    return true;
}

std::string compose_skill(const std::filesystem::path& dst,
                          const std::string& default_frontmatter,
                          const std::string& generated_marker,
                          const std::string& generated_body)
{
    const std::filesystem::path skill_in = dst.parent_path() / "skill.in.md";
    const std::string prefix = read_text_file(skill_in);
    if (!prefix.empty()) {
        std::string out = prefix;
        if (out.back() != '\n')
            out.push_back('\n');
        out += "\n";
        out += generated_marker;
        out += generated_body;
        return out;
    }
    return default_frontmatter + "\n" + generated_marker + generated_body;
}

namespace {

std::string squash_line(std::string s)
{
    std::string out;
    out.reserve(s.size());
    bool space = false;
    for (unsigned char c : s) {
        if (c == '\r')
            continue;
        if (std::isspace(c)) {
            if (!out.empty() && !space)
                out.push_back(' ');
            space = true;
            continue;
        }
        out.push_back(static_cast<char>(c));
        space = false;
    }
    while (!out.empty() && out.back() == ' ')
        out.pop_back();
    return out;
}

std::string first_line_clipped(std::string s, std::size_t max_chars)
{
    s = squash_line(std::move(s));
    if (s.size() <= max_chars)
        return s;
    std::size_t cut = max_chars;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80)
        --cut;
    const auto space = s.rfind(' ', cut);
    if (space != std::string::npos && space > max_chars / 2)
        cut = space;
    s.resize(cut);
    while (!s.empty() && s.back() == ' ')
        s.pop_back();
    if (!s.empty())
        s += "...";
    return s;
}

std::string overlay_return_text(const std::filesystem::path& overlay_dir, const std::string& stem)
{
    if (overlay_dir.empty() || stem.empty())
        return {};
    const auto file = overlay_dir / (path_to_overlay_stem(stem) + "_return.txt");
    std::string text = read_text_file(file);
    const auto nl = text.find_first_of("\r\n");
    if (nl != std::string::npos)
        text.resize(nl);
    return squash_line(std::move(text));
}

std::string compact_arg_name(const CLI::Option* opt)
{
    if (!opt)
        return {};
    std::string name;
    if (opt->get_positional()) {
        name = option_primary_name(opt);
        const auto comma = name.find(',');
        if (comma != std::string::npos)
            name = name.substr(0, comma);
    } else if (option_takes_value(opt)) {
        name = option_long_flag_name(opt);
        while (!name.empty() && name.front() == '-')
            name.erase(name.begin());
    }
    if (skip_option_name(name) || name == "json" || name == "help")
        return {};
    for (char& c : name) {
        if (c == ' ' || c == '\t')
            c = '_';
    }
    return name;
}

std::string clip_token(std::string s, std::size_t max_chars)
{
    s = squash_line(std::move(s));
    if (s.size() <= max_chars)
        return s;
    s.resize(max_chars);
    while (!s.empty() && (static_cast<unsigned char>(s.back()) & 0xC0) == 0x80)
        s.pop_back();
    if (!s.empty())
        s += "...";
    return s;
}

bool command_is_runnable(CLI::App* cmd)
{
    if (!cmd)
        return false;
    if (cmd->get_require_subcommand_min() <= 0)
        return true;
    for (auto* child : cmd->get_subcommands({})) {
        if (child && !child->get_name().empty())
            return false;
    }
    return true;
}

} // namespace

nlohmann::json compact_commands_json(CLI::App& app,
                                     const std::filesystem::path& overlay_dir,
                                     const std::vector<CompactHint>& hints)
{
    std::unordered_map<std::string, const CompactHint*> by_id;
    for (const auto& hint : hints) {
        if (!hint.id.empty())
            by_id.emplace(hint.id, &hint);
    }

    nlohmann::json commands = nlohmann::json::array();
    std::unordered_set<std::string> seen;

    const auto emit = [&](CLI::App* cmd, const std::string& stem, bool custom) {
        if (!cmd || stem.empty() || !seen.insert(stem).second)
            return;
        nlohmann::json row;
        row["stem"] = stem;
        row["kind"] = custom ? "custom" : "builtin";
        nlohmann::json args = nlohmann::json::array();
        const CompactHint* hint = nullptr;
        if (const auto it = by_id.find(stem); it != by_id.end())
            hint = it->second;
        if (custom && hint && !hint->args.empty()) {
            for (const auto& arg : hint->args) {
                const std::string token = clip_token(arg, 48);
                if (!token.empty())
                    args.push_back(token);
            }
        } else {
            for (const auto* opt : cmd->get_options()) {
                const std::string token = compact_arg_name(opt);
                if (!token.empty())
                    args.push_back(token);
            }
        }
        row["args"] = std::move(args);

        std::string returns;
        std::string summary = first_line_clipped(cmd->get_description(), 96);
        if (hint) {
            if (!hint->returns.empty())
                returns = squash_line(hint->returns);
            if (!hint->summary.empty())
                summary = first_line_clipped(hint->summary, 96);
        }
        if (returns.empty())
            returns = overlay_return_text(overlay_dir, stem);
        if (!returns.empty())
            row["returns"] = returns;
        if (!summary.empty())
            row["summary"] = summary;
        commands.push_back(std::move(row));
    };

    const auto walk = [&](auto&& self, CLI::App* cmd, const std::string& stem) -> void {
        if (!cmd || stem.empty())
            return;
        if (command_is_runnable(cmd))
            emit(cmd, stem, by_id.count(stem) != 0);
        for (auto* child : cmd->get_subcommands({})) {
            if (!child || child->get_name().empty())
                continue;
            self(self, child, stem + " " + child->get_name());
        }
    };

    for (auto* child : app.get_subcommands({})) {
        if (!child || child->get_name().empty())
            continue;
        walk(walk, child, child->get_name());
    }

    for (const auto& hint : hints) {
        if (hint.id.empty() || seen.count(hint.id))
            continue;
        nlohmann::json row;
        row["stem"] = hint.id;
        row["kind"] = "custom";
        nlohmann::json hint_args = nlohmann::json::array();
        for (const auto& arg : hint.args) {
            const std::string token = clip_token(arg, 48);
            if (!token.empty())
                hint_args.push_back(token);
        }
        row["args"] = std::move(hint_args);
        const std::string returns = !hint.returns.empty()
            ? squash_line(hint.returns)
            : overlay_return_text(overlay_dir, hint.id);
        if (!returns.empty())
            row["returns"] = returns;
        const std::string summary = first_line_clipped(hint.summary, 96);
        if (!summary.empty())
            row["summary"] = summary;
        commands.push_back(std::move(row));
    }

    std::sort(commands.begin(), commands.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
        return a.value("stem", std::string{}) < b.value("stem", std::string{});
    });

    return nlohmann::json{
        {"format", "cli-compact"},
        {"commands", std::move(commands)},
    };
}

std::string compact_commands_markdown(const nlohmann::json& doc)
{
    std::ostringstream os;
    os << "# CLI compact\n\n";
    os << "One command per line: `stem (arg0,arg1,...)` then a short description. "
          "`...` means more arguments follow. "
          "`=> return` is present when that command names a result "
          "(`{stem}_return.txt`, or `returns` on a custom command).\n\n";
    const auto cmds = doc.find("commands");
    if (cmds == doc.end() || !cmds->is_array())
        return os.str();
    constexpr std::size_t k_max_shown_args = 4;
    const auto format_arg = [](std::string s) {
        if (s.find_first_of(",()\" ") == std::string::npos)
            return s;
        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        for (char c : s) {
            if (c == '"')
                out += "\\\"";
            else
                out.push_back(c);
        }
        out.push_back('"');
        return out;
    };
    for (const auto& row : *cmds) {
        if (!row.is_object())
            continue;
        const std::string stem = row.value("stem", std::string{});
        if (stem.empty())
            continue;
        os << stem;
        if (row.contains("args") && row["args"].is_array() && !row["args"].empty()) {
            os << " (";
            std::size_t shown = 0;
            for (const auto& arg : row["args"]) {
                if (!arg.is_string())
                    continue;
                if (shown == k_max_shown_args) {
                    os << ",...";
                    break;
                }
                if (shown)
                    os << ',';
                os << format_arg(arg.get<std::string>());
                ++shown;
            }
            os << ')';
        }
        const std::string returns = row.value("returns", std::string{});
        if (!returns.empty())
            os << " => " << returns;
        const std::string summary = row.value("summary", std::string{});
        if (!summary.empty())
            os << " - " << summary;
        os << "\n";
    }
    return os.str();
}

} // namespace pm::cli_md
