#pragma once
// installer/verb_registry.hpp — verb lookup + the three masking levels:
//
//   1. compile time — a verb TU is only registered when its FEATURE_INSTALLER_*
//      flag is on (see verbs/register_verbs.cpp).
//   2. machine policy — a pluggable policy gate (wired to GPO keys
//      Installer.Verbs.Enable<Verb> on Windows builds).
//   3. run time — RunOptions::verb_allow_globs ("copy", "vfs_*", …).

#include "installer/verb.hpp"

#include <memory>
#include <string>
#include <vector>

namespace pm::installer {

class VerbRegistry {
public:
    static VerbRegistry& instance();

    // Takes ownership; replaces any verb previously registered under the
    // same name.
    void register_verb(std::unique_ptr<IVerb> verb);

    // nullptr when the verb is unknown (not compiled in / not registered).
    IVerb* find(const std::string& name) const;

    std::vector<std::string> registered_names() const;

    // Machine-policy gate; return false to mask a verb.  Default allows all.
    using PolicyGate = std::function<bool(const std::string& verb_name)>;
    void set_policy_gate(PolicyGate gate);

    // Combined mask check: policy gate + allow globs (empty globs = all).
    bool is_allowed(const std::string& name,
                    const std::vector<std::string>& allow_globs) const;

private:
    VerbRegistry() = default;
    std::vector<std::unique_ptr<IVerb>> verbs_;
    PolicyGate policy_gate_;
};

// Registers all verbs compiled into this build (idempotent).  Called by the
// engine before execution; explicit registration keeps behavior identical
// across static-lib and direct-source builds (no static-initializer tricks).
void register_builtin_verbs();

} // namespace pm::installer
