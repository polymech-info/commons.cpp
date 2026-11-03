#include "installer/verbs/register_verbs.hpp"

namespace pm::installer {

static bool g_verbs_registered = false;

void register_builtin_verbs()
{
    if (g_verbs_registered)
        return;
    g_verbs_registered = true;

    auto& reg = VerbRegistry::instance();
    register_copy_verb(reg);
#if defined(FEATURE_INSTALLER_EXTRACT) && FEATURE_INSTALLER_EXTRACT
    register_extract_verb(reg);
#endif
#if defined(FEATURE_INSTALLER_SHELL) && FEATURE_INSTALLER_SHELL
    register_shell_verb(reg);
#endif
#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS
    register_vfs_verbs(reg);
#endif
#if defined(FEATURE_SECURE_STORAGE) && FEATURE_SECURE_STORAGE
    register_sign_verbs(reg);
#endif
}

} // namespace pm::installer
