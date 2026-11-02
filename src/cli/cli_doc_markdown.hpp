#pragma once

#include "cli_option_schema.hpp"

#include <CLI/CLI.hpp>

#include <nlohmann/json.hpp>

#include <sstream>
#include <string>
#include <string_view>

namespace pm::cli::doc_md {

inline std::string escape_html(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        default: out.push_back(c);
        }
    }
    return out;
}

inline void append_span(std::ostringstream& os,
                        std::string_view kind,
                        std::string_view text,
                        std::string_view variant = {})
{
    os << "<span data-cli=\"" << kind << "\"";
    if (!variant.empty())
        os << " data-variant=\"" << variant << "\"";
    os << ">" << escape_html(text) << "</span>";
}

inline std::string base_type_name(std::string_view type_name)
{
    const auto pos = type_name.find('{');
    if (pos == std::string_view::npos)
        return std::string(type_name);
    return std::string(type_name.substr(0, pos));
}

inline void append_choice_bits_html(std::ostringstream& os,
                                    const nlohmann::json& meta,
                                    bool& first_meta)
{
    if (!meta.contains("choices") || !meta["choices"].is_array() || meta["choices"].empty())
        return;

    const std::string value_kind = meta.value("valueKind", std::string{});
    const char* label = value_kind == "flags" ? "flags" : "one of";
    const char* variant = value_kind == "flags" ? "flags" : "enum";

    if (!first_meta)
        os << ", ";
    first_meta = false;

    append_span(os, "tag", label, variant);
    os << " <span data-cli=\"choices\" data-variant=\"" << variant << "\">";
    bool first_choice = true;
    for (const auto& choice : meta["choices"]) {
        if (!choice.is_string())
            continue;
        if (!first_choice)
            os << " ";
        first_choice = false;
        append_span(os, "choice", choice.get<std::string>());
    }
    os << "</span>";
}

inline void append_option_meta_html(std::ostringstream& os,
                                    const nlohmann::json& meta,
                                    const CLI::Option* opt)
{
    bool first = true;
    const int expected_min = meta.value("expectedMin", opt ? opt->get_expected_min() : 1);
    const std::string value_kind = meta.value("valueKind", std::string{});
    const std::string type_name = meta.value("typeName", opt ? opt->get_type_name() : std::string{});

    if (value_kind == "flag" || expected_min == 0) {
        if (!first)
            os << ", ";
        first = false;
        append_span(os, "tag", "flag", "flag");
    } else if (value_kind != "enum" && value_kind != "flags") {
        const std::string base = base_type_name(type_name);
        if (!base.empty()) {
            if (!first)
                os << ", ";
            first = false;
            append_span(os, "type", base);
        }
    }

    if (meta.value("required", false)) {
        if (!first)
            os << ", ";
        first = false;
        append_span(os, "tag", "required", "required");
    }

    std::string def = meta.value("default", std::string{});
    if (!def.empty()) {
        if (!first)
            os << ", ";
        first = false;
        os << "<span data-cli=\"default\">default ";
        append_span(os, "value", def);
        os << "</span>";
    }

    append_choice_bits_html(os, meta, first);
}

inline void append_enum_values_html(std::ostringstream& os,
                                    const std::vector<std::string>& values,
                                    bool& first_meta,
                                    std::string_view value_kind = "enum")
{
    if (values.empty())
        return;
    nlohmann::json meta = nlohmann::json::object();
    meta["valueKind"] = std::string(value_kind);
    meta["choices"] = nlohmann::json::array();
    for (const auto& value : values)
        meta["choices"].push_back(value);
    append_choice_bits_html(os, meta, first_meta);
}

inline void append_json_enum_html(std::ostringstream& os,
                                  const nlohmann::json& enum_values,
                                  bool& first_meta)
{
    if (!enum_values.is_array() || enum_values.empty())
        return;
    std::vector<std::string> values;
    values.reserve(enum_values.size());
    for (const auto& ev : enum_values) {
        if (ev.is_string())
            values.push_back(ev.get<std::string>());
        else
            values.push_back(ev.dump());
    }
    append_enum_values_html(os, values, first_meta);
}

inline void append_meta_block(std::ostringstream& os, const std::string& inner)
{
    if (inner.empty())
        return;
    os << " (<span data-cli=\"meta\">" << inner << "</span>)";
}

inline void append_option_list_line(std::ostringstream& os, const CLI::Option* opt)
{
    if (!opt)
        return;
    const nlohmann::json meta = cli_option_to_json(opt);
    const std::string name = meta.value("name", opt->get_name(opt->get_positional(), true));

    os << "- `" << name << "`";
    std::ostringstream meta_html;
    append_option_meta_html(meta_html, meta, opt);
    append_meta_block(os, meta_html.str());

    const std::string desc = meta.value("description", std::string{});
    if (!desc.empty())
        os << " - " << desc;
    os << "\n";
}

} // namespace pm::cli::doc_md
