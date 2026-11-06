#pragma once

#include <string>
#include <unordered_map>

namespace media::str_tpl {

/**
 * Renders a Mustache template (https://mustache.github.io) using a flat string map
 * (object context). For sections, lists, and lambdas, include `mustache.hpp` from
 * kainjow/Mustache and build @c kainjow::mustache::data yourself.
 */
std::string render_mustache_flat(const std::string &tmpl, const std::unordered_map<std::string, std::string> &vars);

} // namespace media::str_tpl
