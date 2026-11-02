//
// pm::security::antihack — runtime tamper telemetry (implementation).
//
// See anti_hack.hpp and docs/security/dehack.md. The Windows backend produces
// real signals; every other platform (and FEATURE_ANTI_HACKING=0) returns an
// empty/clean result.
//

#include "security/anti_hack.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#if FEATURE_ANTI_HACKING && defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <winternl.h>
#  include <tlhelp32.h>
#endif

namespace pm::security::antihack {

// ── report helpers ────────────────────────────────────────────────────────────

bool Report::any_detected() const noexcept { return detected_count() > 0; }

int Report::detected_count() const noexcept {
    return debugger_detected + dll_hook_detected + module_detected + memory_detected;
}

Severity Report::max_severity() const noexcept {
    Severity worst = Severity::Info;
    for (const auto& s : signals)
        if (s.detected && static_cast<int>(s.severity) > static_cast<int>(worst))
            worst = s.severity;
    return worst;
}

const char* to_string(Category c) noexcept {
    switch (c) {
        case Category::Debugger: return "debugger";
        case Category::DllHook:  return "dll_hook";
        case Category::Module:   return "module";
        case Category::Memory:   return "memory";
    }
    return "unknown";
}

const char* to_string(Severity s) noexcept {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Low:      return "low";
        case Severity::Medium:   return "medium";
        case Severity::High:     return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

#if FEATURE_ANTI_HACKING && defined(_WIN32)

bool available() noexcept { return true; }

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string wide_to_utf8(const wchar_t* w) {
    if (!w || !*w) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::string hex_addr(const void* p) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(p)));
    return buf;
}

// NtQueryInformationProcess information classes used for debug detection.
constexpr ULONG kProcessDebugPort          = 7;
constexpr ULONG kProcessDebugObjectHandle  = 0x1E;
constexpr ULONG kProcessDebugFlags         = 0x1F;

using NtQIP_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

NtQIP_t nt_query_information_process() {
    static NtQIP_t fn = [] {
        HMODULE nt = ::GetModuleHandleW(L"ntdll.dll");
        return nt ? reinterpret_cast<NtQIP_t>(
                        reinterpret_cast<void*>(::GetProcAddress(nt, "NtQueryInformationProcess")))
                  : nullptr;
    }();
    return fn;
}

// Read the in-process PEB once. winternl exposes BeingDebugged; NtGlobalFlag is
// read by raw offset (0xBC on x64, 0x68 on x86).
const BYTE* peb_base() {
#if defined(_M_X64) || defined(__x86_64__)
    return reinterpret_cast<const BYTE*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<const BYTE*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

constexpr std::size_t kNtGlobalFlagOffset =
#if defined(_M_X64) || defined(__x86_64__)
    0xBC;
#else
    0x68;
#endif

// Heap flags forced on when a process is created under a debugger.
constexpr DWORD kNtGlobalFlagDebugHeap = 0x70;  // FLG_HEAP_*: TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS

// ── inline-hook prologue classification ───────────────────────────────────────
// A freshly loaded export prologue should not begin with an unconditional
// control transfer. These opcode shapes are the classic inline-hook trampolines
// installed by Detours/EasyHook/MinHook/EDR/cheat engines.
const char* classify_hook_prologue(const BYTE* p) {
    if (!p) return nullptr;
    // E9 cd            jmp rel32
    if (p[0] == 0xE9) return "jmp rel32";
    // EB cb            jmp rel8
    if (p[0] == 0xEB) return "jmp rel8";
    // FF 25 xx         jmp qword ptr [rip+disp32] / [disp32]
    if (p[0] == 0xFF && p[1] == 0x25) return "jmp [mem]";
    // 68 id  ... C3    push imm32 ; ret
    if (p[0] == 0x68 && p[5] == 0xC3) return "push/ret";
    // 48 B8 imm64 FF E0   mov rax, imm64 ; jmp rax
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return "mov rax;jmp rax";
    // B8 id FF E0       mov eax, imm32 ; jmp rax/eax
    if (p[0] == 0xB8 && p[5] == 0xFF && (p[6] == 0xE0)) return "mov eax;jmp";
    return nullptr;
}

struct ExportProbe {
    const wchar_t* module;
    const char*    name;
    bool           syscall_stub;  // ntdll Nt* stub → hook is High severity
};

const std::array<ExportProbe, 28>& default_export_probes() {
    static const std::array<ExportProbe, 28> probes = {{
        {L"ntdll.dll", "NtCreateFile",               true},
        {L"ntdll.dll", "NtOpenProcess",              true},
        {L"ntdll.dll", "NtReadVirtualMemory",        true},
        {L"ntdll.dll", "NtWriteVirtualMemory",       true},
        {L"ntdll.dll", "NtProtectVirtualMemory",     true},
        {L"ntdll.dll", "NtAllocateVirtualMemory",    true},
        {L"ntdll.dll", "NtMapViewOfSection",         true},
        {L"ntdll.dll", "NtSetContextThread",         true},
        {L"ntdll.dll", "NtSetInformationThread",     true},
        {L"ntdll.dll", "NtQueryInformationProcess",  true},
        {L"ntdll.dll", "NtCreateThreadEx",           true},
        {L"ntdll.dll", "NtResumeThread",             true},
        {L"ntdll.dll", "LdrLoadDll",                 false},
        {L"ntdll.dll", "EtwEventWrite",              false},  // dehack P0.7: ETW blinding
        {L"ntdll.dll", "DbgUiRemoteBreakin",         false},
        {L"ntdll.dll", "DbgBreakPoint",              false},
        {L"kernel32.dll", "CreateFileW",             false},
        {L"kernel32.dll", "LoadLibraryExW",          false},
        {L"kernel32.dll", "VirtualProtect",          false},
        {L"kernel32.dll", "VirtualAllocEx",          false},
        {L"kernel32.dll", "WriteProcessMemory",      false},
        {L"kernel32.dll", "CreateProcessW",          false},
        {L"kernel32.dll", "CreateRemoteThread",      false},
        {L"kernelbase.dll", "CreateFileW",           false},
        {L"kernelbase.dll", "VirtualProtect",        false},
        {L"kernelbase.dll", "LoadLibraryExW",        false},
        {L"amsi.dll",  "AmsiScanBuffer",             false},  // only if already loaded
        {L"amsi.dll",  "AmsiScanString",             false},
    }};
    return probes;
}

bool path_is_suspicious(const std::string& lower_path) {
    if (lower_path.empty()) return false;
    // Code loaded from user-writable transient locations is a provenance smell.
    static const char* k_markers[] = {
        "\\temp\\", "\\tmp\\", "\\downloads\\",
        "\\appdata\\local\\temp\\", "\\windows\\temp\\",
        "\\users\\public\\", "\\$recycle.bin\\",
    };
    for (const char* m : k_markers)
        if (lower_path.find(m) != std::string::npos) return true;
    return false;
}

} // namespace

// ── debugger ──────────────────────────────────────────────────────────────────

std::vector<Signal> scan_debugger() {
    std::vector<Signal> out;
    auto add = [&](const char* name, bool detected, Severity sev, std::string detail) {
        out.push_back(Signal{Category::Debugger, name, detected, sev, std::move(detail), {}});
    };

    add("debugger.is_debugger_present", ::IsDebuggerPresent() != FALSE,
        Severity::High, "kernel32!IsDebuggerPresent");

    BOOL remote = FALSE;
    if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &remote))
        add("debugger.remote_present", remote != FALSE, Severity::High,
            "CheckRemoteDebuggerPresent");

    if (const BYTE* peb = peb_base()) {
        const auto* p = reinterpret_cast<const PEB*>(peb);
        add("debugger.peb_being_debugged", p->BeingDebugged != 0, Severity::High,
            "PEB.BeingDebugged");

        const DWORD ntgf = *reinterpret_cast<const DWORD*>(peb + kNtGlobalFlagOffset);
        add("debugger.peb_nt_global_flag", (ntgf & kNtGlobalFlagDebugHeap) == kNtGlobalFlagDebugHeap,
            Severity::Medium, "PEB.NtGlobalFlag debug-heap bits");
    }

    if (auto fn = nt_query_information_process()) {
        const HANDLE self = ::GetCurrentProcess();

        ULONG_PTR debug_port = 0;
        if (fn(self, kProcessDebugPort, &debug_port, sizeof(debug_port), nullptr) == 0)
            add("debugger.nt_debug_port", debug_port != 0, Severity::High,
                "NtQueryInformationProcess(ProcessDebugPort)");

        HANDLE debug_object = nullptr;
        if (fn(self, kProcessDebugObjectHandle, &debug_object, sizeof(debug_object), nullptr) == 0)
            add("debugger.nt_debug_object", debug_object != nullptr, Severity::High,
                "NtQueryInformationProcess(ProcessDebugObjectHandle)");

        DWORD debug_flags = 0;
        if (fn(self, kProcessDebugFlags, &debug_flags, sizeof(debug_flags), nullptr) == 0)
            // NoDebugInherit == 0 means the process IS being debugged.
            add("debugger.nt_debug_flags", debug_flags == 0, Severity::Medium,
                "NtQueryInformationProcess(ProcessDebugFlags)");
    }

    // Hardware breakpoints set in the debug registers of the current thread.
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
        const bool hw = ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
        add("debugger.hardware_breakpoints", hw, Severity::Medium,
            "thread debug registers Dr0-Dr3 set");
    }

    return out;
}

// ── inline DLL hooks ───────────────────────────────────────────────────────────

std::vector<Signal> scan_dll_hooks(const std::vector<std::string>& modules) {
    std::vector<Signal> out;

    auto probe_one = [&](const wchar_t* mod_w, const char* fn_name, bool syscall_stub) {
        HMODULE h = ::GetModuleHandleW(mod_w);
        if (!h) return;  // module not loaded (e.g. amsi.dll) — nothing to check
        FARPROC addr = ::GetProcAddress(h, fn_name);
        if (!addr) return;
        const BYTE* p = reinterpret_cast<const BYTE*>(addr);
        const char* shape = classify_hook_prologue(p);
        const std::string mod = wide_to_utf8(mod_w);
        const std::string locus = mod + "!" + fn_name;
        if (shape) {
            out.push_back(Signal{
                Category::DllHook, "dll_hook.inline", true,
                syscall_stub ? Severity::High : Severity::Medium,
                std::string("inline hook prologue (") + shape + ")", locus});
        }
    };

    if (modules.empty()) {
        for (const auto& pr : default_export_probes())
            probe_one(pr.module, pr.name, pr.syscall_stub);
    } else {
        // Caller-supplied module list: probe the same export set, but only for
        // the requested modules (case-insensitive name match).
        for (const auto& want : modules) {
            const std::string want_l = lower(want);
            for (const auto& pr : default_export_probes()) {
                if (lower(wide_to_utf8(pr.module)) == want_l)
                    probe_one(pr.module, pr.name, pr.syscall_stub);
            }
        }
    }

    return out;
}

// ── loaded-module provenance ───────────────────────────────────────────────────

std::vector<Signal> scan_modules() {
    std::vector<Signal> out;

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ::GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) {
        out.push_back(Signal{Category::Module, "module.snapshot_failed", true, Severity::Low,
                             "CreateToolhelp32Snapshot failed", {}});
        return out;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    int total = 0;
    if (::Module32FirstW(snap, &me)) {
        do {
            ++total;
            const std::string path = wide_to_utf8(me.szExePath);
            const std::string path_l = lower(path);
            if (path_is_suspicious(path_l)) {
                out.push_back(Signal{Category::Module, "module.suspicious_path", true,
                                     Severity::Medium,
                                     "module loaded from user-writable/transient path", path});
            }
        } while (::Module32NextW(snap, &me));
    }
    ::CloseHandle(snap);

    // Info snapshot row so the report records a baseline module count.
    out.push_back(Signal{Category::Module, "module.count", false, Severity::Info,
                         std::to_string(total) + " loaded modules", {}});
    return out;
}

// ── private executable memory ───────────────────────────────────────────────────

std::vector<Signal> scan_memory(bool self_test_rwx) {
    std::vector<Signal> out;

    // Test hook: leak one RWX page so the scan has a deterministic positive.
    if (self_test_rwx) {
        void* p = ::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) {
            *static_cast<volatile BYTE*>(p) = 0xC3;  // touch it so the page is committed
            // Informational marker only (our own injection) — not an anomaly,
            // so detected=false. The RWX region it creates is flagged by the
            // scan below as the real positive.
            out.push_back(Signal{Category::Memory, "memory.self_test_rwx", false, Severity::Info,
                                 "allocated RWX page for self-test", hex_addr(p)});
        }
    }

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    auto* addr = static_cast<const BYTE*>(si.lpMinimumApplicationAddress);
    const auto* max_addr = static_cast<const BYTE*>(si.lpMaximumApplicationAddress);

    int rwx = 0;
    int private_exec = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < max_addr && ::VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            const DWORD prot = mbi.Protect & 0xFF;
            const bool exec_writable =
                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            const bool exec =
                prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || exec_writable;
            if (exec_writable) {
                ++rwx;
                out.push_back(Signal{Category::Memory, "memory.rwx_region", true, Severity::High,
                                     "writable+executable committed region",
                                     hex_addr(mbi.BaseAddress)});
            } else if (exec && mbi.Type == MEM_PRIVATE) {
                // Executable code not backed by an image/section — manually mapped
                // code or a JIT page. Low severity: JIT engines legitimately do this.
                ++private_exec;
                out.push_back(Signal{Category::Memory, "memory.private_exec", true, Severity::Low,
                                     "executable private (non-image) region",
                                     hex_addr(mbi.BaseAddress)});
            }
        }
        auto next = static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;  // guard against wrap / zero region
        addr = next;
    }

    out.push_back(Signal{Category::Memory, "memory.summary", false, Severity::Info,
                         std::to_string(rwx) + " rwx, " + std::to_string(private_exec) +
                             " private-exec regions",
                         {}});
    return out;
}

#else  // !FEATURE_ANTI_HACKING || !_WIN32 — portable clean stubs

bool available() noexcept { return false; }

std::vector<Signal> scan_debugger() { return {}; }
std::vector<Signal> scan_dll_hooks(const std::vector<std::string>&) { return {}; }
std::vector<Signal> scan_modules() { return {}; }
std::vector<Signal> scan_memory(bool) { return {}; }

#endif

// ── aggregate ───────────────────────────────────────────────────────────────────

Report run(const ScanOptions& opts) {
    Report rep;

    auto absorb = [&](std::vector<Signal>&& sigs) {
        for (auto& s : sigs) rep.signals.push_back(std::move(s));
    };

    if (opts.debugger)  absorb(scan_debugger());
    if (opts.dll_hooks) absorb(scan_dll_hooks(opts.hook_modules));
    if (opts.modules)   absorb(scan_modules());
    if (opts.memory)    absorb(scan_memory(opts.memory_self_test_rwx));

    for (const auto& s : rep.signals) {
        if (s.name == "module.count") {
            // detail begins with the integer count.
            rep.modules_total = std::atoi(s.detail.c_str());
        }
        if (!s.detected) continue;
        switch (s.category) {
            case Category::Debugger: ++rep.debugger_detected; break;
            case Category::DllHook:  ++rep.dll_hook_detected; break;
            case Category::Module:   ++rep.module_detected;   break;
            case Category::Memory:   ++rep.memory_detected;   break;
        }
    }

    return rep;
}

} // namespace pm::security::antihack
