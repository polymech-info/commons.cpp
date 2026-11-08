#ifndef CLI_MD_GENERATOR_HPP
#define CLI_MD_GENERATOR_HPP

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace pm::cli_md {

/// Site base and author used when a call leaves `pages_base` or `pages_author` empty.
/// If either value is empty, the absolute page URL stays empty.
void set_pages_defaults(std::string base, std::string author);

struct DocHooks {
    std::function<void(std::ostringstream&, CLI::App*, const std::string& path)> on_begin;
    std::function<void(std::ostringstream&, CLI::App*, const std::string& path)> on_end;
};

struct AppendConfig {
    /// Heading level is min(depth + heading_base, 6) unless fixed_heading is set.
    int heading_base = 2;
    /// When > 0, every command block uses this heading depth (e.g. 4 = ####).
    /// Useful when a parent section (### group) already consumes a level.
    int fixed_heading = 0;
    bool hr_between_siblings = true;
    /// When non-empty, probe `<overlay_dir>/<verb>_<subverb>_examples.md` per command path
    /// and append file contents after the generated block (e.g. after examples).
    /// `<stem>_more.md` links from the command heading and a trailing "Read more".
    /// `<stem>_example.xblox` embeds a markdown `xblox` widget fence (wrapper + document).
    std::filesystem::path overlay_dir;
    /// Output markdown path (--dst); overlay dir is parent of this path.
    std::filesystem::path output_dst;
    /// Prepended to overlay file stems (e.g. `xblox_` -> `xblox_run_examples.md`).
    std::string overlay_prefix;
    /// CMS user UUID for absolute `*_more.md` page URLs. Empty uses `set_pages_defaults`.
    std::string pages_author;
    /// CMS site base (no trailing slash required). Empty uses `set_pages_defaults`.
    std::string pages_base;
    DocHooks hooks;
};

// ── option helpers ──────────────────────────────────────────────────────────

std::string option_primary_name(const CLI::Option* opt);
bool skip_option_name(const std::string& name);
std::string option_default_str(const CLI::Option* opt);
std::string option_long_flag_name(const CLI::Option* opt);
bool option_takes_value(const CLI::Option* opt);

// ── markdown tables ─────────────────────────────────────────────────────────

std::string md_escape_cell(std::string s);
std::string format_table_args_cell(const std::vector<std::string>& args);

// ── CLI tree markdown ───────────────────────────────────────────────────────

void append_cli_options(std::ostringstream& os, CLI::App* cmd);
void append_cli_app(std::ostringstream& os,
                    CLI::App* cmd,
                    const std::string& path,
                    int depth,
                    const AppendConfig& cfg = {});

CLI::App* find_child_command(CLI::App& app, const std::string& name);

// ── shell examples ──────────────────────────────────────────────────────────

std::string exe_stem_from_basename(const char* exe_basename);

CLI::App* resolve_min_leaf(CLI::App* cmd, std::string& cmd_path);
std::string build_min_example_line(const std::string& exe_stem,
                                   const std::string& cmd_path,
                                   CLI::App* leaf);
std::string build_full_example_line(const std::string& exe_stem,
                                    const std::string& cmd_path,
                                    CLI::App* leaf);
void append_example_blocks(std::ostringstream& os,
                           const std::string& min_line,
                           const std::string& full_line);
void append_command_examples(std::ostringstream& os,
                             CLI::App* cmd,
                             const std::string& path,
                             const std::string& exe_stem);

void on_cli_begin(std::ostringstream& os, CLI::App* cmd, const std::string& path);
void on_cli_end(std::ostringstream& os,
                CLI::App* cmd,
                const std::string& path,
                const std::string& exe_stem,
                const std::filesystem::path& overlay_dir = {},
                const std::filesystem::path& output_dst = {},
                const std::string& overlay_prefix = {},
                const std::string& pages_author = {},
                const std::string& pages_base = {});

std::string path_to_overlay_stem(const std::string& path);
std::string kind_to_overlay_stem(const std::string& kind);
std::filesystem::path overlay_dir_from_dst(const std::filesystem::path& dst);
std::string overlay_relative_href(const std::filesystem::path& output_dst,
                                  const std::filesystem::path& target);
/// Absolute CMS page URL when `*_more.md` exists: `{base}/user/{author}/pages/{stem}`.
std::string overlay_more_href(const std::filesystem::path& overlay_dir,
                              const std::filesystem::path& output_dst,
                              const std::string& path,
                              const std::string& overlay_prefix = {},
                              const std::string& pages_author = {},
                              const std::string& pages_base = {});
void append_command_overlay(std::ostringstream& os,
                            const std::filesystem::path& overlay_dir,
                            const std::filesystem::path& output_dst,
                            const std::string& path,
                            const std::string& overlay_prefix = {},
                            const std::string& pages_author = {},
                            const std::string& pages_base = {});
void append_xblox_example_fence(std::ostringstream& os,
                                const std::filesystem::path& overlay_dir,
                                const std::string& path,
                                const std::string& overlay_prefix = {});

// ── JSON export ─────────────────────────────────────────────────────────────

nlohmann::json cli_options_json(CLI::App* cmd);
nlohmann::json cli_app_json(CLI::App* cmd);

/// Optional result name, summary, and configured argv for a custom command.
struct CompactHint {
    std::string id;
    std::string returns;
    std::string summary;
    std::vector<std::string> args;
};

/// Runnable commands as `{stem, args, kind, summary}` plus `returns` when one is named.
/// Args are positional names, then value-taking flags. Custom commands use `CompactHint::args`.
/// `returns` comes from `CompactHint::returns`, otherwise `{stem}_return.txt` in `overlay_dir`.
nlohmann::json compact_commands_json(CLI::App& app,
                                     const std::filesystem::path& overlay_dir,
                                     const std::vector<CompactHint>& hints);

/// One command per line: `stem (arg0,arg1,...)` then a short description.
/// `=> return` when `returns` is set. The parenthesized list stops after a few names.
std::string compact_commands_markdown(const nlohmann::json& doc);

// ── skill / file helpers ────────────────────────────────────────────────────

std::string read_text_file(const std::filesystem::path& path);
bool write_text_file(const std::filesystem::path& path,
                     const std::string& text,
                     std::string& err);
std::string compose_skill(const std::filesystem::path& dst,
                          const std::string& default_frontmatter,
                          const std::string& generated_marker,
                          const std::string& generated_body);

} // namespace pm::cli_md

#endif
