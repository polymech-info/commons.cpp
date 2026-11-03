#include "installer/verb_registry.hpp"
#include "installer/resolve.hpp"

namespace pm::installer {

VerbRegistry& VerbRegistry::instance()
{
    static VerbRegistry g;
    return g;
}

void VerbRegistry::register_verb(std::unique_ptr<IVerb> verb)
{
    if (!verb)
        return;
    const std::string name = verb->name();
    for (auto& v : verbs_) {
        if (name == v->name()) {
            v = std::move(verb);
            return;
        }
    }
    verbs_.push_back(std::move(verb));
}

IVerb* VerbRegistry::find(const std::string& name) const
{
    for (const auto& v : verbs_)
        if (name == v->name())
            return v.get();
    return nullptr;
}

std::vector<std::string> VerbRegistry::registered_names() const
{
    std::vector<std::string> names;
    names.reserve(verbs_.size());
    for (const auto& v : verbs_)
        names.emplace_back(v->name());
    return names;
}

void VerbRegistry::set_policy_gate(PolicyGate gate)
{
    policy_gate_ = std::move(gate);
}

bool VerbRegistry::is_allowed(const std::string& name,
                              const std::vector<std::string>& allow_globs) const
{
    if (policy_gate_ && !policy_gate_(name))
        return false;
    if (allow_globs.empty())
        return true;
    for (const auto& glob : allow_globs)
        if (matches_pattern(name, glob))
            return true;
    return false;
}

} // namespace pm::installer
