#pragma once
//
// Shared keyboard-shortcut plumbing (Win32).
//
// One parser + one binding source for every process that registers shortcuts,
// so a combo can never mean two different things in two processes:
//
//   • `tanit.exe` (CMainFrame::RegisterForegroundHotkeys) — registers app
//     command shortcuts and window-scoped custom command shortcuts.
//     Foreground-scoped (registered on WM_ACTIVATE, released on deactivate).
//   • `pm-image-cli.exe daemon` — RegisterHotKey on the tray HWND for every
//     commands.json entry with `shortcut` + `shortcutGlobal: true`. Survives
//     other apps being focused and the UI process exiting.
//   • `pm-image-cli.exe assistant` — `GlobalHotkeyHost` registers the same
//     `shortcutGlobal` bindings when the daemon is not already the owner.
//
// Ownership rules:
//   • UI-bound app commands (fullscreen, PTT, …) stay foreground-only in the
//     frame. No collision by construction.
//   • Window-scoped custom shortcuts stay with the UI frame.
//   • Global custom shortcuts have one registrar: the daemon when alive, else
//     the assistant GlobalHotkeyHost. RegisterHotKey is the final arbiter.
//
// Dispatch from the assistant:
//   • cliCommand / externalCommand → media::cmd_run::Runner (same path as the
//     launcher popup, including the PM_IMAGE_COMMAND_ID stamp → IPC tree,
//     pulse states and toggle-stop work for hotkey-fired runs).
//   • appCommand → routed to a live UI instance over cmd_ipc `app_cmd`
//     (works even while the UI is in the background). No UI → logged + dropped.
//
#if defined(_WIN32)

#include "core/launcher_commands.hpp"

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace media::hotkeys {

/// Parse "Ctrl+Alt+P" / "F11" / "Alt+Home" → Win32 `MOD_*` bits (always
/// includes MOD_NOREPEAT) + virtual key. Returns false on malformed input.
bool parse_shortcut(const std::string& s, unsigned& mods_out, unsigned& vk_out);

/// Inverse of parse for OSD display: mods (MOD_CONTROL|…) + vk → "Ctrl+Shift+P".
/// @p include_modifiers false returns the bare key name only.
std::string format_key_display(unsigned mods, unsigned vk,
                               bool include_modifiers = true);

/// True while every key of the combo is physically held (GetAsyncKeyState).
bool shortcut_down(unsigned mods, unsigned vk);

/// Probe whether the combo can currently be registered system-wide
/// (transient RegisterHotKey + UnregisterHotKey).
bool shortcut_available(unsigned mods, unsigned vk);

/// One custom command binding: parsed combo + the full dispatchable entry
/// (`entry.shortcut` holds the source string).
struct CustomBinding {
    unsigned mods = 0;
    unsigned vk   = 0;
    media::launcher::LauncherEntry entry;
};

/// Which `shortcut` / `shortcutGlobal` rows to load.
enum class BindingScope {
    All,
    Window,  ///< `shortcut` set, `shortcutGlobal` false/absent
    Global,  ///< `shortcut` set and `shortcutGlobal` true
};

/// Load enabled commands.json entries with a `shortcut` field and parse the
/// combos. Invalid strings are skipped with a warning; duplicate combos keep
/// the first occurrence. Never throws.
std::vector<CustomBinding> load_custom_command_bindings(
    BindingScope scope = BindingScope::All);

/// Dispatch a commands.json shortcut binding (cli/external/url/path via
/// Runner; appCommand via cmd_ipc to a live UI).
void dispatch_custom_binding(const media::launcher::LauncherEntry& e);

/// Route an app-command verb to a live UI instance over cmd_ipc. Safe from
/// CLI / daemon / voice — no-op when no UI is listening. @p extra is merged
/// into the IPC `args` object (e.g. voice slot captures like `query`).
void dispatch_app_command(const std::string& name, const std::string& sourceId = {},
                          const std::map<std::string, std::string>& extra = {});

/// Look up a shortcut binding by commands.json `id` and dispatch it.
/// @p scope defaults to Global (daemon / GlobalHotkeyHost). Pass All from the
/// UI so a window-scoped command still runs. Returns false when the id is
/// unknown, disabled, or outside @p scope.
bool dispatch_custom_command_id(const std::string& id,
                                BindingScope scope = BindingScope::Global);

/// One live RegisterHotKey slot owned by the daemon or GlobalHotkeyHost.
struct LiveGlobalHotkey {
    int         id = 0;
    unsigned    mods = 0;
    unsigned    vk = 0;
    std::string shortcut;
    std::string command_id;
};

/// Drop deleted / disabled / non-global combos with UnregisterHotKey, then
/// register any new `shortcutGlobal` bindings. @p hwnd may be null (thread queue).
std::size_t sync_global_command_hotkeys(
    void* hwnd,
    std::vector<LiveGlobalHotkey>& live,
    int id_base);

/// True when a global custom-shortcut registrar (live assistant or daemon in
/// the cmd_ipc registry) exists. Always false when FEATURE_COMMAND_IPC_NEXT
/// is off.
bool global_registrar_active();

// ── GlobalHotkeyHost ──────────────────────────────────────────────────────────
//
// Assistant-side registrar. Owns a dedicated message-loop thread that
// RegisterHotKey()s every `shortcutGlobal` custom command binding (hwnd =
// nullptr → WM_HOTKEY lands in the thread queue) and dispatches on receipt.
//
// Combos that fail to register (typically because the UI frame is foreground
// and still holds them) stay on a retry list serviced every couple of seconds
// until they succeed — converges within one UI activation cycle once the frame
// starts yielding.
class GlobalHotkeyHost {
public:
    GlobalHotkeyHost();
    ~GlobalHotkeyHost();
    GlobalHotkeyHost(const GlobalHotkeyHost&)            = delete;
    GlobalHotkeyHost& operator=(const GlobalHotkeyHost&) = delete;

    /// Starts the registrar thread (even with zero bindings so later
    /// commands.json edits can add/drop combos). Returns current binding count.
    std::size_t start();

    /// Re-read commands.json and unregister deleted/disabled global combos.
    void reload();

    /// Unregisters everything and joins the thread. Safe to call twice.
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace media::hotkeys

#endif // _WIN32
