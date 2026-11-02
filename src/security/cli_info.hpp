#ifndef SECURITY_CLI_INFO_HPP
#define SECURITY_CLI_INFO_HPP

#include <CLI/CLI.hpp>
#include <functional>
#include <sstream>
#include <string>

struct SecCliInfoState {
    CLI::App* info_cmd = nullptr;
    CLI::App* info_commands_cmd = nullptr;
    std::string info_dst;
    bool info_stdout = false;
    bool info_skill = false;
    bool info_json = false;

    /// Called at the start of each documented command block (after heading + description).
    std::function<void(std::ostringstream&, CLI::App*, const std::string& path)> on_cli_begin;
    /// Called after options for each command block. Default: example blocks via cli_md_generator.
    std::function<void(std::ostringstream&, CLI::App*, const std::string& path)> on_cli_end;
};

void sec_cli_register_info(CLI::App& app, SecCliInfoState& st);
int sec_cli_cmd_info(CLI::App& app, const SecCliInfoState& st);

#endif
