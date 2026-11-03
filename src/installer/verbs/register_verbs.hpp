#pragma once

#include "installer/verb_registry.hpp"

namespace pm::installer {

void register_copy_verb(VerbRegistry& reg);

#if defined(FEATURE_INSTALLER_EXTRACT) && FEATURE_INSTALLER_EXTRACT
void register_extract_verb(VerbRegistry& reg);
#endif

#if defined(FEATURE_INSTALLER_SHELL) && FEATURE_INSTALLER_SHELL
void register_shell_verb(VerbRegistry& reg);
#endif

#if defined(FEATURE_INSTALLER_VFS) && FEATURE_INSTALLER_VFS
void register_vfs_verbs(VerbRegistry& reg);
#endif

#if defined(FEATURE_SECURE_STORAGE) && FEATURE_SECURE_STORAGE
void register_sign_verbs(VerbRegistry& reg);
#endif

} // namespace pm::installer
