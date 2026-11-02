#pragma once

#include <CLI/CLI.hpp>

#include <nlohmann/json.hpp>

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
inline constexpr const char* kCliPanelIds[] = {
    "filetree", "search", "queue", "log", "console", "settings",
    "chat", "findresults", "dupresults", "nodes",
};
inline constexpr const char* kCliComponentIds[] = {
    "ribbon",
    "statusbar",
};
#endif

namespace pm::cli {

inline std::vector<std::string> choices_from_type_name(std::string_view type_name)
{
    const auto open = type_name.find('{');
    const auto close = type_name.rfind('}');
    if (open == std::string_view::npos || close == std::string_view::npos || close <= open)
        return {};
    std::vector<std::string> out;
    std::string token;
    for (std::size_t i = open + 1; i < close; ++i) {
        const char c = type_name[i];
        if (c == ',') {
            if (!token.empty()) {
                out.push_back(token);
                token.clear();
            }
            continue;
        }
        if (c != ' ')
            token.push_back(c);
    }
    if (!token.empty())
        out.push_back(token);
    return out;
}

inline bool option_has_long_name(const CLI::Option* opt, std::string_view name)
{
    if (!opt)
        return false;
    for (const auto& n : opt->get_lnames()) {
        if (n == name)
            return true;
    }
    return false;
}

inline void enrich_cli_option_schema(nlohmann::json& j, const CLI::Option* opt)
{
    if (!opt)
        return;

    if (opt->get_expected_min() == 0) {
        j["valueKind"] = "flag";
        return;
    }

#if defined(_WIN32)
    if (option_has_long_name(opt, "show-panel") || option_has_long_name(opt, "hide-panel")) {
        nlohmann::json choices = nlohmann::json::array();
        for (const char* id : kCliPanelIds)
            choices.push_back(id);
        j["choices"] = std::move(choices);
        j["valueKind"] = "flags";
        return;
    }
    if (option_has_long_name(opt, "show-components") || option_has_long_name(opt, "hide-components")) {
        nlohmann::json choices = nlohmann::json::array();
        for (const char* id : kCliComponentIds)
            choices.push_back(id);
        j["choices"] = std::move(choices);
        j["valueKind"] = "flags";
        return;
    }
#endif

    const auto choices = choices_from_type_name(j.value("typeName", std::string{}));
    if (choices.size() >= 2) {
        j["choices"] = choices;
        j["valueKind"] = "enum";
    }
}

inline nlohmann::json cli_option_to_json(const CLI::Option* opt)
{
    nlohmann::json names = nlohmann::json::array();
    for (const auto& n : opt->get_snames())
        names.push_back("-" + n);
    for (const auto& n : opt->get_lnames())
        names.push_back("--" + n);

    nlohmann::json j = nlohmann::json{
        {"name", opt->get_name(opt->get_positional(), true)},
        {"names", std::move(names)},
        {"positional", opt->get_positional()},
        {"required", opt->get_required()},
        {"group", opt->get_group()},
        {"description", opt->get_description()},
        {"typeName", opt->get_type_name()},
        {"default", opt->get_default_str()},
        {"expectedMin", opt->get_expected_min()},
        {"expectedMax", opt->get_expected_max()},
        {"allowExtraArgs", opt->get_allow_extra_args()},
    };
    enrich_cli_option_schema(j, opt);
    return j;
}

} // namespace pm::cli
