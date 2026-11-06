#include "mustache_render.hpp"

#include "mustache.hpp"

#include <string>
#include <unordered_map>

namespace media::str_tpl {

std::string render_mustache_flat(const std::string &tmpl, const std::unordered_map<std::string, std::string> &vars) {
    kainjow::mustache::data ctx{kainjow::mustache::data::type::object};
    for (const auto &p : vars)
        ctx.set(p.first, kainjow::mustache::data{p.second});
    kainjow::mustache::mustache m{tmpl};
    return m.render(ctx);
}

} // namespace media::str_tpl
