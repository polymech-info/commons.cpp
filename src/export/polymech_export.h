#pragma once

/**
 * DLL / shared-object exports for the Polymech media library (resize, transform).
 *
 * CMake:
 *   - Building pm-media: POLYMECH_BUILDING_LIBRARY (PRIVATE)
 *   - Linking static pm-media: POLYMECH_STATIC_BUILD=1 (INTERFACE)
 *   - Linking shared pm-media: default import on Windows
 */

#if defined(POLYMECH_STATIC_BUILD)
#  define POLYMECH_API
#elif defined(_WIN32)
#  if defined(POLYMECH_BUILDING_LIBRARY)
#    define POLYMECH_API __declspec(dllexport)
#  else
#    define POLYMECH_API __declspec(dllimport)
#  endif
#else
#  if defined(POLYMECH_BUILDING_LIBRARY)
#    define POLYMECH_API __attribute__((visibility("default")))
#  else
#    define POLYMECH_API
#  endif
#endif

/*
 * Chat / agent loop lives in tanit-chat-plugin when PM_PLUGIN_CHAT=1.
 * Three owners, three macros:
 *   POLYMECH_API  — pm-media.dll (fs_guard, leftover tools, host façades)
 *   PM_CHAT_API   — plugin build: export from tanit-chat-plugin
 *                   host build: same as POLYMECH_API (pm-media thunks via FindComponent)
 *   (none)        — plugin-private
 * pm-media must not import tanit-chat-plugin (no DLL cycle, no DELAYLOAD).
 * Win32++ CWnd / CDocker stay in the exe (CWinApp is per-module).
 * Host lookup is FindComponent only.
 */
#if !defined(PM_PLUGIN_CHAT) || !PM_PLUGIN_CHAT
#  define PM_CHAT_API POLYMECH_API
#elif defined(PM_CHAT_BUILD)
#  if defined(_WIN32)
#    define PM_CHAT_API __declspec(dllexport)
#  else
#    define PM_CHAT_API __attribute__((visibility("default")))
#  endif
#else
#  define PM_CHAT_API POLYMECH_API
#endif
