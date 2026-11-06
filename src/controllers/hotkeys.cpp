// Shared keyboard-shortcut plumbing — see `hotkeys.hpp`.
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h> // ShellExecuteW (path bindings)

#include "controllers/hotkeys.hpp"

#include "commands/command_control.hpp"
#include "commands/command_runner.hpp"
#include "fs/file_watcher.hpp"
#include "settings/settings_runtime.hpp"
#include "process/system_browser.hpp"
#include "logging/logger.h"
#include "win/taskbar_status.hpp"
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
#  include "ipc/cmd_ipc.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include "string/string_utils.hpp"

namespace media::hotkeys {

// ─────────────────────────────────────────────────────────────────────────────
// Parser / probes (moved verbatim from Mainfrm.cpp so UI and assistant agree)
// ─────────────────────────────────────────────────────────────────────────────

namespace {

std::string trim_ascii(std::string s)
{
    const auto not_space = [](unsigned char c) { return !std::isspace(c); };
    const auto b = std::find_if(s.begin(), s.end(), not_space);
    const auto e = std::find_if(s.rbegin(), s.rend(), not_space).base();
    if (b >= e) return {};
    return std::string(b, e);
}

using media::strutil::lower_ascii;

std::wstring widen(const std::string& s)
{
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

} // namespace

bool parse_shortcut(const std::string& s, unsigned& mods_out, unsigned& vk_out)
{
    if (s.empty()) return false;
    std::vector<std::string> parts;
    std::string tok;
    for (char c : s) {
        if (c == '+') { if (!tok.empty()) { parts.push_back(trim_ascii(tok)); tok.clear(); } }
        else           { tok += c; }
    }
    if (!tok.empty()) parts.push_back(trim_ascii(tok));
    if (parts.empty()) return false;

    UINT mods = MOD_NOREPEAT;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
        const auto m = lower_ascii(parts[i]);
        if (m == "ctrl" || m == "control") mods |= MOD_CONTROL;
        else if (m == "alt")               mods |= MOD_ALT;
        else if (m == "shift")             mods |= MOD_SHIFT;
        else if (m == "win" || m == "windows") mods |= MOD_WIN;
        else return false;
    }

    const std::string key = trim_ascii(parts.back());
    const std::string lower_key = lower_ascii(key);
    UINT vk = 0;
    if (key.size() == 1 && std::isalpha(static_cast<unsigned char>(key[0])))
        vk = static_cast<UINT>(std::toupper(static_cast<unsigned char>(key[0])));
    else if (key.size() == 1 && std::isdigit(static_cast<unsigned char>(key[0])))
        vk = static_cast<UINT>(key[0]);
    else {
        static const std::map<std::string, UINT> kSpecial = {
            {"f1",VK_F1},{"f2",VK_F2},{"f3",VK_F3},{"f4",VK_F4},
            {"f5",VK_F5},{"f6",VK_F6},{"f7",VK_F7},{"f8",VK_F8},
            {"f9",VK_F9},{"f10",VK_F10},{"f11",VK_F11},{"f12",VK_F12},
            {"f13",VK_F13},{"f14",VK_F14},{"f15",VK_F15},{"f16",VK_F16},
            {"f17",VK_F17},{"f18",VK_F18},{"f19",VK_F19},{"f20",VK_F20},
            {"f21",VK_F21},{"f22",VK_F22},{"f23",VK_F23},{"f24",VK_F24},
            {"space",VK_SPACE},{"enter",VK_RETURN},{"return",VK_RETURN},
            {"escape",VK_ESCAPE},{"esc",VK_ESCAPE},
            {"delete",VK_DELETE},{"del",VK_DELETE},
            {"insert",VK_INSERT},{"ins",VK_INSERT},
            {"home",VK_HOME},{"end",VK_END},
            {"pageup",VK_PRIOR},{"pagedown",VK_NEXT},
            {"backspace",VK_BACK},{"tab",VK_TAB},
            {"printscreen",VK_SNAPSHOT},
            {"up",VK_UP},{"down",VK_DOWN},{"left",VK_LEFT},{"right",VK_RIGHT},
            {"pause",VK_PAUSE},{"capslock",VK_CAPITAL},
            {"numlock",VK_NUMLOCK},{"scrolllock",VK_SCROLL},
            {"apps",VK_APPS},{"menu",VK_APPS},
            // Numpad (layout-independent VK codes)
            {"numpad0",VK_NUMPAD0},{"numpad1",VK_NUMPAD1},{"numpad2",VK_NUMPAD2},
            {"numpad3",VK_NUMPAD3},{"numpad4",VK_NUMPAD4},{"numpad5",VK_NUMPAD5},
            {"numpad6",VK_NUMPAD6},{"numpad7",VK_NUMPAD7},{"numpad8",VK_NUMPAD8},
            {"numpad9",VK_NUMPAD9},
            {"numpadadd",VK_ADD},{"numpadplus",VK_ADD},
            {"numpadsubtract",VK_SUBTRACT},{"numpadminus",VK_SUBTRACT},
            {"numpadmultiply",VK_MULTIPLY},{"numpaddivide",VK_DIVIDE},
            {"numpaddecimal",VK_DECIMAL},
            // Punctuation by name — needed for keys the '+'-split syntax can't
            // express literally ("Ctrl+Plus") and for layout-stable configs.
            // US-position VK_OEM_* codes, same naming family as browsers/engines.
            {"plus",VK_OEM_PLUS},{"equals",VK_OEM_PLUS},
            {"minus",VK_OEM_MINUS},{"dash",VK_OEM_MINUS},
            {"comma",VK_OEM_COMMA},{"period",VK_OEM_PERIOD},{"dot",VK_OEM_PERIOD},
            {"semicolon",VK_OEM_1},{"slash",VK_OEM_2},
            {"backquote",VK_OEM_3},{"grave",VK_OEM_3},{"tilde",VK_OEM_3},
            {"lbracket",VK_OEM_4},{"backslash",VK_OEM_5},{"rbracket",VK_OEM_6},
            {"quote",VK_OEM_7},{"apostrophe",VK_OEM_7},
        };
        auto it = kSpecial.find(lower_key);
        if (it != kSpecial.end()) {
            vk = it->second;
        } else {
            // Layout-aware fallback for any printable key — the standard
            // game-engine/Win32 approach: VkKeyScanW maps a character to the
            // virtual key (low byte) + implied modifiers (high byte) on the
            // active keyboard layout. Handles ";", "[", "é", "ü", … without
            // enumerating every key. Implied modifiers fold into the combo,
            // so "Ctrl+:" means whatever physically produces ':' here.
            const std::wstring wkey = widen(key);
            if (wkey.size() != 1) return false;
            const SHORT scan = ::VkKeyScanW(wkey[0]);
            if (scan == -1) return false;
            vk = LOBYTE(scan);
            const UINT implied = HIBYTE(scan);
            if (implied & 1) mods |= MOD_SHIFT;
            if (implied & 2) mods |= MOD_CONTROL;
            if (implied & 4) mods |= MOD_ALT;
        }
    }
    if (!vk) return false;
    mods_out = mods;
    vk_out   = vk;
    return true;
}

std::string format_key_display(unsigned mods, unsigned vk, bool include_modifiers)
{
    std::string key;
    if (vk >= 'A' && vk <= 'Z')
        key.assign(1, static_cast<char>(vk));
    else if (vk >= '0' && vk <= '9')
        key.assign(1, static_cast<char>(vk));
    else if (vk >= VK_F1 && vk <= VK_F24)
        key = "F" + std::to_string(vk - VK_F1 + 1);
    else {
        static const std::map<UINT, const char*> kNames = {
            {VK_SPACE, "Space"}, {VK_RETURN, "Enter"}, {VK_ESCAPE, "Esc"},
            {VK_DELETE, "Del"}, {VK_INSERT, "Ins"}, {VK_HOME, "Home"},
            {VK_END, "End"}, {VK_PRIOR, "PgUp"}, {VK_NEXT, "PgDn"},
            {VK_BACK, "Backspace"}, {VK_TAB, "Tab"},
            {VK_UP, "Up"}, {VK_DOWN, "Down"}, {VK_LEFT, "Left"}, {VK_RIGHT, "Right"},
            {VK_OEM_PLUS, "+"}, {VK_OEM_MINUS, "-"},
            {VK_OEM_COMMA, ","}, {VK_OEM_PERIOD, "."},
            {VK_OEM_1, ";"}, {VK_OEM_2, "/"}, {VK_OEM_3, "`"},
            {VK_OEM_4, "["}, {VK_OEM_5, "\\"}, {VK_OEM_6, "]"}, {VK_OEM_7, "'"},
            {VK_ADD, "Num+"}, {VK_SUBTRACT, "Num-"},
            {VK_MULTIPLY, "Num*"}, {VK_DIVIDE, "Num/"}, {VK_DECIMAL, "Num."},
            {VK_NUMPAD0, "Num0"}, {VK_NUMPAD1, "Num1"}, {VK_NUMPAD2, "Num2"},
            {VK_NUMPAD3, "Num3"}, {VK_NUMPAD4, "Num4"}, {VK_NUMPAD5, "Num5"},
            {VK_NUMPAD6, "Num6"}, {VK_NUMPAD7, "Num7"}, {VK_NUMPAD8, "Num8"},
            {VK_NUMPAD9, "Num9"},
        };
        auto it = kNames.find(vk);
        if (it != kNames.end())
            key = it->second;
        else {
            // Best-effort printable via MapVirtualKey + ToUnicode.
            const UINT sc = ::MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
            wchar_t buf[8] = {};
            BYTE state[256] = {};
            if (::ToUnicode(vk, sc, state, buf, 8, 0) == 1 && buf[0] >= 32) {
                char utf8[8] = {};
                ::WideCharToMultiByte(CP_UTF8, 0, buf, 1, utf8, sizeof(utf8), nullptr, nullptr);
                key = utf8;
                for (char& c : key) {
                    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
                }
            } else {
                key = "VK" + std::to_string(vk);
            }
        }
    }

    if (!include_modifiers) return key;
    std::string out;
    if (mods & MOD_CONTROL) out += "Ctrl+";
    if (mods & MOD_ALT)     out += "Alt+";
    if (mods & MOD_SHIFT)   out += "Shift+";
    if (mods & MOD_WIN)     out += "Win+";
    out += key;
    return out;
}

namespace {

bool key_down(UINT vk)
{
    return (::GetAsyncKeyState(static_cast<int>(vk)) & 0x8000) != 0;
}

std::string narrow(const std::wstring& s)
{
    if (s.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

} // namespace

bool shortcut_down(unsigned mods, unsigned vk)
{
    if (!key_down(vk)) return false;
    if ((mods & MOD_CONTROL) && !(key_down(VK_CONTROL) || key_down(VK_LCONTROL) || key_down(VK_RCONTROL))) return false;
    if ((mods & MOD_ALT) && !(key_down(VK_MENU) || key_down(VK_LMENU) || key_down(VK_RMENU))) return false;
    if ((mods & MOD_SHIFT) && !(key_down(VK_SHIFT) || key_down(VK_LSHIFT) || key_down(VK_RSHIFT))) return false;
    if ((mods & MOD_WIN) && !(key_down(VK_LWIN) || key_down(VK_RWIN))) return false;
    return true;
}

bool shortcut_available(unsigned mods, unsigned vk)
{
    constexpr int probe_id = 0x504D; // 'PM'
    if (!::RegisterHotKey(nullptr, probe_id, mods | MOD_NOREPEAT, vk))
        return false;
    ::UnregisterHotKey(nullptr, probe_id);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Bindings
// ─────────────────────────────────────────────────────────────────────────────

std::vector<CustomBinding> load_custom_command_bindings(BindingScope scope)
{
    std::vector<CustomBinding> out;
    std::map<unsigned, std::string> seen; // (mods << 16) | vk -> first command name

    for (auto& e : media::launcher::load_shortcut_entries({})) {
        if (scope == BindingScope::Global && !e.shortcutGlobal)
            continue;
        if (scope == BindingScope::Window && e.shortcutGlobal)
            continue;
        unsigned mods = 0, vk = 0;
        if (!parse_shortcut(e.shortcut, mods, vk)) {
            logger::warn("[hotkeys] invalid shortcut '" + e.shortcut + "' on " + e.id);
            continue;
        }
        const unsigned key = (mods << 16) | (vk & 0xFFFFu);
        const std::string name = narrow(e.label);
        if (auto it = seen.find(key); it != seen.end()) {
            logger::warn("[hotkeys] duplicate shortcut '" + e.shortcut + "' on " + name
                         + " — first binding wins (" + it->second + ")");
            continue;
        }
        seen.emplace(key, name.empty() ? e.id : name);
        CustomBinding b;
        b.mods  = mods;
        b.vk    = vk;
        b.entry = std::move(e);
        out.push_back(std::move(b));
    }
    return out;
}

bool global_registrar_active()
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind == media::cmd_ipc::ProcessKind::Assistant
            || inst.kind == media::cmd_ipc::ProcessKind::Daemon)
            return true;
    }
#endif
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch (assistant side)
// ─────────────────────────────────────────────────────────────────────────────

void dispatch_app_command(const std::string& name, const std::string& sourceId,
                          const std::map<std::string, std::string>& extra)
{
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    nlohmann::json args = {{"sourceId", sourceId}};
    for (const auto& [k, v] : extra) {
        if (k != "sourceId")
            args[k] = v;
    }
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.kind != media::cmd_ipc::ProcessKind::Ui) continue;
        nlohmann::json reply;
        std::string    err;
        if (media::cmd_ipc::send_action(inst, "app_cmd", {
                {"command", name},
                {"args", args},
            }, reply, err)
            && reply.value("type", std::string{}) == "app_cmd_ack") {
            logger::info("[hotkeys] app_cmd '" + name + "' -> " + inst.id + " (" + sourceId + ")");
            return;
        }
        logger::warn("[hotkeys] app_cmd '" + name + "' -> " + inst.id + " failed: " + err);
    }
    logger::warn("[hotkeys] app_cmd '" + name + "' dropped: no live UI instance (" + sourceId + ")");
#else
    (void)name;
    (void)extra;
    //logger::warn("[hotkeys] app_cmd dropped: command IPC unavailable (" + sourceId + ")");
#endif
}

void dispatch_custom_binding(const media::launcher::LauncherEntry& e)
{
    //logger::info("[hotkeys] fired '" + e.shortcut + "' -> " + e.id);

    media::launcher::LauncherEntry resolved = e;
    media::launcher::resolve_entry_variables(resolved);

    if (resolved.toggle && media::command_control::is_command_running(resolved.id)) {
        //logger::trace("[hotkeys] toggle stop id=" + resolved.id);
        media::command_control::stop_command_by_id_async(resolved.id, "[hotkeys]");
        return;
    }

    // In-app UI commands can't run here — route to a live UI instance.
    if (!resolved.appCommand.empty()) {
        std::thread(dispatch_app_command, resolved.appCommand, resolved.id,
                    std::map<std::string, std::string>{}).detach();
        return;
    }

    if (!resolved.openUrl.empty()) {
        const auto result = pm::system_browser::open(
            narrow(resolved.openUrl), pm::system_browser::Policy::Untrusted);
        if (!result)
            logger::warn("[hotkeys] openUrl blocked for '" + resolved.id + "': "
                         + result.error.message);
        return;
    }
    if (!resolved.openPath.empty()) {
        (void)::ShellExecuteW(nullptr, L"open", resolved.openPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return;
    }

    if (resolved.executable.empty() && resolved.shellLine.empty()) {
        logger::warn("[hotkeys] cannot dispatch '" + resolved.id + "': no executable / shellLine");
        return;
    }

    // Same spawn path as the launcher popup tile click — including the
    // PM_IMAGE_COMMAND_ID stamp so the child's cmd_ipc descriptor links back
    // to the originating commands.json entry (IPC tree / pulse / toggle-stop).
    media::cmd_run::RunOptions opt;
    opt.cmdId             = resolved.cmdId;
    opt.commandId         = resolved.id;
    opt.sequential        = resolved.sequential;
    opt.executable        = resolved.executable;
    opt.args              = resolved.args;
    opt.externalShellMode = resolved.externalShellMode;
    opt.shellLine         = resolved.shellLine;
    opt.shellInterpreter  = resolved.shellInterpreter;
    opt.validateExpanded  = media::cmd_run::user_data_marks_agent_authored(resolved.userDataJson);
    opt.cwd               = resolved.cwd;
    opt.newConsoleWindow  = resolved.runNewShellWindow;
    opt.closeOnExit       = resolved.closeOnExit;
    opt.closePolicy       = resolved.closePolicy;
    if (!resolved.id.empty()) {
        std::wstring wid;
        wid.reserve(resolved.id.size());
        for (char c : resolved.id) wid.push_back(static_cast<wchar_t>(c));
        opt.extraEnv.emplace_back(L"PM_IMAGE_COMMAND_ID", std::move(wid));
    }
    // Headless / global-hotkey children have no taskbar button. Stamp the
    // Tanit frame the same way screen:current / the transcribe HUD resolve
    // a host: env, this/parent window, else the app on the cursor's monitor.
    if (HWND host = media::win::TaskbarStatus::resolve_host_hwnd()) {
        opt.extraEnv.emplace_back(
            L"PM_IMAGE_HOST_HWND",
            std::to_wstring(static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(host))));
    }
    const std::uint64_t runId = media::cmd_run::Runner::instance().start(opt);
    //logger::trace("[hotkeys] dispatched id=" + resolved.id + " runId=" + std::to_string(runId));
}

bool dispatch_custom_command_id(const std::string& id, BindingScope scope)
{
    if (id.empty())
        return false;
    for (const auto& b : load_custom_command_bindings(scope)) {
        if (b.entry.id == id) {
            dispatch_custom_binding(b.entry);
            return true;
        }
    }
    logger::warn("[hotkeys] unknown or disabled command '" + id + "'");
    return false;
}

namespace {

bool live_matches_binding(const LiveGlobalHotkey& h, const CustomBinding& b)
{
    if (h.mods != b.mods || h.vk != b.vk)
        return false;
    if (!h.command_id.empty() && !b.entry.id.empty())
        return h.command_id == b.entry.id;
    return h.shortcut == b.entry.shortcut;
}

} // namespace

std::size_t sync_global_command_hotkeys(
    void* hwnd,
    std::vector<LiveGlobalHotkey>& live,
    int id_base)
{
    HWND const window = static_cast<HWND>(hwnd);
    const auto wanted = load_custom_command_bindings(BindingScope::Global);

    std::vector<LiveGlobalHotkey> keep;
    keep.reserve(live.size());
    for (const auto& h : live) {
        bool still = false;
        for (const auto& b : wanted) {
            if (live_matches_binding(h, b)) {
                still = true;
                break;
            }
        }
        if (still) {
            keep.push_back(h);
            continue;
        }
        if (h.id)
            (void)::UnregisterHotKey(window, h.id);
        //logger::info("[hotkeys] unregistered '" + h.shortcut + "' -> " + h.command_id);
    }
    live.swap(keep);

    auto id_used = [&](int id) {
        for (const auto& h : live) {
            if (h.id == id)
                return true;
        }
        return false;
    };

    int next_id = id_base > 0 ? id_base : 1;
    for (const auto& b : wanted) {
        bool have = false;
        for (const auto& h : live) {
            if (live_matches_binding(h, b)) {
                have = true;
                break;
            }
        }
        if (have)
            continue;
        while (id_used(next_id))
            ++next_id;
        const int id = next_id++;
        if (!::RegisterHotKey(window, id, b.mods, b.vk)) {
            const DWORD gle = ::GetLastError();
            const std::string why = (gle == ERROR_HOTKEY_ALREADY_REGISTERED)
                ? "already registered"
                : ("err=" + std::to_string(gle));
            logger::warn("[hotkeys] register failed '" + b.entry.shortcut
                         + "' (" + why + ") -> " + b.entry.id);
            continue;
        }
        live.push_back(LiveGlobalHotkey{
            id, b.mods, b.vk, b.entry.shortcut, b.entry.id,
        });
        //logger::info("[hotkeys] registered '" + b.entry.shortcut + "' -> " + b.entry.id);
    }
    return live.size();
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalHotkeyHost
// ─────────────────────────────────────────────────────────────────────────────

struct GlobalHotkeyHost::Impl {
    std::thread       thread;
    HANDLE            stop_event = nullptr;
    HANDLE            reload_event = nullptr;
    std::atomic<bool> running{false};
};

GlobalHotkeyHost::GlobalHotkeyHost() : impl_(std::make_unique<Impl>()) {}
GlobalHotkeyHost::~GlobalHotkeyHost() { stop(); }

std::size_t GlobalHotkeyHost::start()
{
    if (impl_->running.load()) return 0;

    impl_->stop_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    impl_->reload_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!impl_->stop_event || !impl_->reload_event) {
        stop();
        return 0;
    }
    impl_->running.store(true);

    HANDLE stop = impl_->stop_event;
    HANDLE reload = impl_->reload_event;
    impl_->thread = std::thread([stop, reload]() {
        MSG msg{};
        (void)::PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

        std::vector<LiveGlobalHotkey> live;
        auto apply = [&]() {
            sync_global_command_hotkeys(nullptr, live, 1);
        };
        apply();

        media::FileWatcher watcher([&](std::vector<media::FileChange>) {
            ::SetEvent(reload);
        });
        const auto watch_file = media::runtime_settings::effective_command_watch_path();
        if (watch_file.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(watch_file.parent_path(), ec);
            (void)watcher.Watch(watch_file.parent_path());
        }

        HANDLE events[2] = { stop, reload };
        bool quit = false;
        while (!quit) {
            const DWORD wait = ::MsgWaitForMultipleObjects(2, events, FALSE, INFINITE, QS_ALLINPUT);
            if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED)
                break;
            if (wait == WAIT_OBJECT_0 + 1) {
                ::ResetEvent(reload);
                // Directory watch fires per sidecar (.sig / index / meta). Coalesce
                // a burst so we don't unregister/re-register on every settings put.
                for (;;) {
                    HANDLE debounce[2] = { stop, reload };
                    const DWORD extra = ::WaitForMultipleObjects(2, debounce, FALSE, 250);
                    if (extra == WAIT_OBJECT_0) {
                        quit = true;
                        break;
                    }
                    if (extra != WAIT_OBJECT_0 + 1)
                        break;
                    ::ResetEvent(reload);
                }
                if (!quit)
                    apply();
                continue;
            }
            while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    quit = true;
                    break;
                }
                if (msg.message != WM_HOTKEY) {
                    ::TranslateMessage(&msg);
                    ::DispatchMessageW(&msg);
                    continue;
                }
                const int id = static_cast<int>(msg.wParam);
                const LiveGlobalHotkey* hit = nullptr;
                for (const auto& h : live) {
                    if (h.id == id) { hit = &h; break; }
                }
                if (!hit)
                    continue;
                if (!dispatch_custom_command_id(hit->command_id))
                    apply();
            }
        }

        for (const auto& h : live) {
            if (h.id)
                (void)::UnregisterHotKey(nullptr, h.id);
        }
    });

    const std::size_t count = load_custom_command_bindings(BindingScope::Global).size();
    logger::info("[hotkeys] global registrar started (" + std::to_string(count) + " binding(s))");
    return count;
}

void GlobalHotkeyHost::reload()
{
    if (impl_ && impl_->reload_event)
        ::SetEvent(impl_->reload_event);
}

void GlobalHotkeyHost::stop()
{
    if (!impl_ || !impl_->running.exchange(false)) {
        if (impl_ && impl_->stop_event) {
            ::CloseHandle(impl_->stop_event);
            impl_->stop_event = nullptr;
        }
        if (impl_ && impl_->reload_event) {
            ::CloseHandle(impl_->reload_event);
            impl_->reload_event = nullptr;
        }
        return;
    }
    if (impl_->stop_event)
        ::SetEvent(impl_->stop_event);
    if (impl_->thread.joinable())
        impl_->thread.join();
    if (impl_->stop_event) {
        ::CloseHandle(impl_->stop_event);
        impl_->stop_event = nullptr;
    }
    if (impl_->reload_event) {
        ::CloseHandle(impl_->reload_event);
        impl_->reload_event = nullptr;
    }
    logger::trace("[hotkeys] global registrar stopped");
}

} // namespace media::hotkeys

#endif // _WIN32
