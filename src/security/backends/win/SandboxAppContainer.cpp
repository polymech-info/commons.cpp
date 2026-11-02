//
// pm::security (Win32) — AppContainer / LPAC sandbox backend.
//
// Implements the SandboxBackend interface using Windows AppContainer isolation.
// All public methods mirror what the cli.cpp sandbox sub-commands exercised;
// the cli.cpp wrappers are thin callers that translate results to JSON.
//
// References:
//   docs/security/security.md   § Sandbox backends
//   docs/security/sandbox.md    § Architecture, ACL strategy, pitfalls
//   ref/SandboxSecurityTools/   LaunchAppContainer reference sample
//

#if defined(_WIN32)

#include "security/backends/win/SandboxAppContainer.hpp"

#include "logging/pm_log.hpp"

#include <UserEnv.h>
#include <sddl.h>
#include <aclapi.h>
#pragma comment(lib, "userenv.lib")

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

namespace pm::security {

namespace {

// All currently-running sandbox jobs. Parallel agents can run sandboxed tools
// concurrently; a single atomic handle loses older jobs and leaves processes
// behind on cancel.
std::mutex g_active_jobs_mu;
std::unordered_set<HANDLE> g_active_jobs;

// Stream a pipe to a string, forwarding each chunk live to an optional hook.
void read_pipe_streaming(HANDLE read_handle, std::string& out, std::mutex& mtx,
                         const std::string& stream_name,
                         const SandboxOutputHook& hook,
                         const std::atomic<bool>& stop) {
    char buffer[4096];
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_handle, nullptr, 0, nullptr, &available, nullptr))
            break;
        if (available == 0) {
            if (stop.load(std::memory_order_acquire))
                break;
            Sleep(10);
            continue;
        }

        DWORD n = 0;
        const DWORD want = std::min<DWORD>(available, static_cast<DWORD>(sizeof(buffer)));
        if (!ReadFile(read_handle, buffer, want, &n, nullptr) || n == 0)
            break;
        std::string chunk(buffer, buffer + n);
        { std::lock_guard<std::mutex> lk(mtx); out.append(chunk); }
        if (hook) hook(stream_name, chunk);
    }
}

void close_if_valid(HANDLE& h) {
    if (h && h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        h = nullptr;
    }
}

// ── Volume-query shim helpers ─────────────────────────────────────────────────
// Return the absolute path of pm-sb-shim.dll when it exists in the same
// directory as the current host executable; empty string when absent.
static std::wstring find_shim_dll() {
    WCHAR exe[MAX_PATH + 1] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring p = exe;
    const auto sep = p.find_last_of(L"\\/");
    if (sep != std::wstring::npos) p = p.substr(0, sep + 1);
    p += L"pm-sb-shim.dll";
    return (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) ? p : L"";
}

// Inject dll_path into hProcess via a remote LoadLibraryW thread.
// Returns true when LoadLibraryW inside the child reports success.
// The remote thread is created with CREATE_SUSPENDED=0 so it starts
// immediately without disturbing pi.hThread (which remains suspended).
static bool inject_dll(HANDLE hProcess, const std::wstring& dll_path,
                       DWORD timeout_ms = 5000) {
    const size_t path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote_buf = VirtualAllocEx(hProcess, nullptr, path_bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) return false;

    bool ok = false;
    if (WriteProcessMemory(hProcess, remote_buf, dll_path.c_str(), path_bytes, nullptr)) {
        const HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        const FARPROC load_lib = k32 ? GetProcAddress(k32, "LoadLibraryW") : nullptr;
        if (load_lib) {
            HANDLE t = CreateRemoteThread(
                hProcess, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(load_lib),
                remote_buf, 0, nullptr);
            if (t) {
                WaitForSingleObject(t, timeout_ms);
                DWORD exit_code = 0;
                GetExitCodeThread(t, &exit_code);
                // LoadLibraryW returns the HMODULE (non-zero on success).
                ok = (exit_code != 0);
                CloseHandle(t);
            }
        }
    }
    VirtualFreeEx(hProcess, remote_buf, 0, MEM_RELEASE);
    return ok;
}

} // namespace

void abort_active_sandbox() {
    std::lock_guard<std::mutex> lk(g_active_jobs_mu);
    for (HANDLE h : g_active_jobs)
        if (h) (void)TerminateJobObject(h, 130);
}

// ── Construction / destruction ─────────────────────────────────────────────────

SandboxAppContainer::SandboxAppContainer() = default;

SandboxAppContainer::~SandboxAppContainer() {
    clearCache();
}

void SandboxAppContainer::clearCache() {
    for (auto& [k, v] : m_cache)
        if (v.sid) FreeSid(v.sid);
    m_cache.clear();
}

// ── Low-level helpers (static) ────────────────────────────────────────────────

std::wstring SandboxAppContainer::toWide(const std::string& s) {
    if (s.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                        static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        w.data(), len);
    return w;
}

std::string SandboxAppContainer::sidToStr(PSID sid) {
    LPWSTR ws = nullptr;
    if (!ConvertSidToStringSidW(sid, &ws)) return {};
    const int n = WideCharToMultiByte(CP_ACP, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string s;
    if (n > 0) {
        s.resize(static_cast<size_t>(n - 1));
        WideCharToMultiByte(CP_ACP, 0, ws, -1, s.data(), n, nullptr, nullptr);
    }
    LocalFree(ws);
    return s;
}

// Write a directory/file DACL.
//   NodeOnly → SetFileSecurityW: writes the DACL to *this object only* and does
//     NOT run the auto-inheritance propagation engine. Critical for large trees:
//     SetNamedSecurityInfoW always re-stamps the directory's inheritable ACEs
//     across the entire subtree (O(descendants)), which stalls for tens of
//     seconds on a workspace root (node_modules/.git/dist). Node-only edits skip
//     that walk entirely → O(1).
//   ImmediateFiles / Recursive → SetNamedSecurityInfoW: intentional propagation
//     so pre-existing files inside the folder pick up the ACE.
// Caller owns pNew; this function does not free it.
static DWORD write_dacl(const std::wstring& path, PACL pNew,
                        GrantPropagation propagation) {
    if (propagation == GrantPropagation::NodeOnly) {
        SECURITY_DESCRIPTOR sd;
        if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
            return GetLastError();
        if (!SetSecurityDescriptorDacl(&sd, TRUE, pNew, FALSE))
            return GetLastError();
        if (!SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, &sd))
            return GetLastError();
        return ERROR_SUCCESS;
    }
    return SetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, nullptr, nullptr, pNew, nullptr);
}

// Grant an AppContainer SID access to a path's DACL.
// Inheritance depends on GrantPropagation:
//   NodeOnly       → OBJECT_INHERIT | CONTAINER_INHERIT, written with
//                    SetFileSecurityW (no auto-propagation): O(1). Existing
//                    children keep their DACLs. A file or directory created
//                    afterwards inherits the ACE, so the container can write it.
//   ImmediateFiles → CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE |
//                    NO_PROPAGATE_INHERIT_ACE: pushes the ACE to immediate
//                    children (so pre-existing files become readable), cost
//                    O(direct entries).
//   Recursive      → CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE: full subtree
//                    propagation. Rare/explicit; can stall on large trees.
DWORD SandboxAppContainer::grantPathImpl(const std::wstring& path, PSID sid,
                                         const std::string& access,
                                         GrantPropagation propagation) {
    DWORD mask = GENERIC_READ | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
    if (access == "write" || access == "read-write")
        mask |= GENERIC_WRITE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
              | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | DELETE;
    if (access == "exec")
        mask |= GENERIC_EXECUTE | FILE_EXECUTE;

    PACL              pOld = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD rc = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, &pOld, nullptr, &pSD);
    if (rc != ERROR_SUCCESS) return rc;

    // NodeOnly still marks the ACE inheritable. SetFileSecurityW does not push
    // that ACE onto existing children; only objects created later pick it up.
    DWORD inheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    if (propagation == GrantPropagation::ImmediateFiles)
        inheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE;
    else if (propagation == GrantPropagation::Recursive)
        inheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

    EXPLICIT_ACCESS_W ea = {};
    ea.grfAccessPermissions = mask;
    ea.grfAccessMode        = GRANT_ACCESS;
    ea.grfInheritance       = inheritance;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = reinterpret_cast<LPWSTR>(sid);

    PACL pNew = nullptr;
    rc = SetEntriesInAclW(1, &ea, pOld, &pNew);
    if (rc == ERROR_SUCCESS) {
        rc = write_dacl(path, pNew, propagation);
        LocalFree(pNew);
    }
    if (pSD) LocalFree(pSD);
    return rc;
}

// Remove every ALLOW ACE for `sid` from a path DACL.
// The write mirrors the grant's propagation mode (NodeOnly → non-propagating
// node-only write, so revoking a workspace-root grant is also O(1)).
DWORD SandboxAppContainer::revokePathImpl(const std::wstring& path, PSID sid,
                                          GrantPropagation propagation) {
    PACL              pDacl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD rc = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, &pDacl, nullptr, &pSD);
    if (rc != ERROR_SUCCESS || !pDacl) {
        if (pSD) LocalFree(pSD);
        return rc;
    }

    ACL_SIZE_INFORMATION info = {};
    GetAclInformation(pDacl, &info, sizeof(info), AclSizeInformation);

    DWORD new_size = sizeof(ACL);
    std::vector<std::pair<void*, WORD>> keep;
    for (DWORD i = 0; i < info.AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(pDacl, i, &ace)) continue;
        const auto* hdr = reinterpret_cast<const ACE_HEADER*>(ace);
        bool is_ours = false;
        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            PSID ace_sid = reinterpret_cast<PSID>(
                &reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart);
            is_ours = EqualSid(ace_sid, sid) != 0;
        }
        if (!is_ours) {
            keep.emplace_back(ace, hdr->AceSize);
            new_size += hdr->AceSize;
        }
    }

    auto* pNew = reinterpret_cast<PACL>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, new_size));
    if (!pNew) { if (pSD) LocalFree(pSD); return ERROR_OUTOFMEMORY; }

    InitializeAcl(pNew, new_size, ACL_REVISION);
    for (auto [ace, sz] : keep)
        AddAce(pNew, ACL_REVISION, MAXDWORD, ace, sz);

    rc = write_dacl(path, pNew, propagation);
    HeapFree(GetProcessHeap(), 0, pNew);
    if (pSD) LocalFree(pSD);
    return rc;
}

bool SandboxAppContainer::checkAccessImpl(const std::wstring& path, PSID sid) {
    PACL              pDacl = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD rc = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, &pDacl, nullptr, &pSD);
    if (rc != ERROR_SUCCESS || !pDacl) {
        if (pSD) LocalFree(pSD);
        return false;
    }

    ACL_SIZE_INFORMATION info = {};
    GetAclInformation(pDacl, &info, sizeof(info), AclSizeInformation);
    bool found = false;
    for (DWORD i = 0; i < info.AceCount && !found; ++i) {
        void* ace = nullptr;
        if (!GetAce(pDacl, i, &ace)) continue;
        if (reinterpret_cast<ACE_HEADER*>(ace)->AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        PSID ace_sid = reinterpret_cast<PSID>(
            &reinterpret_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart);
        if (EqualSid(ace_sid, sid)) found = true;
    }
    if (pSD) LocalFree(pSD);
    return found;
}

// ── Profile SID cache ─────────────────────────────────────────────────────────

PSID SandboxAppContainer::acquireSid(const std::string& moniker, bool* wasCreated) {
    auto it = m_cache.find(moniker);
    if (it != m_cache.end()) {
        if (wasCreated) *wasCreated = false;
        return it->second.sid;
    }

    const std::wstring wmon = toWide(moniker);
    PSID sid = nullptr;
    bool created = false;

    HRESULT hr = CreateAppContainerProfile(wmon.c_str(), wmon.c_str(), wmon.c_str(),
                                           nullptr, 0, &sid);
    if (SUCCEEDED(hr)) {
        created = true;
    } else if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        hr = DeriveAppContainerSidFromAppContainerName(wmon.c_str(), &sid);
    }

    if (FAILED(hr) || !sid) {
        m_lastError = HRESULT_CODE(hr);
        return nullptr;
    }

    m_lastError = ERROR_SUCCESS;
    if (wasCreated) *wasCreated = created;

    CachedProfile cp;
    cp.sid    = sid;
    cp.sidStr = sidToStr(sid);
    m_cache.emplace(moniker, std::move(cp));
    return m_cache[moniker].sid;
}

// ── SandboxBackend implementation ──────────────────────────────────────────────

std::string SandboxAppContainer::containerSid(const std::string& moniker) {
    PSID sid = acquireSid(moniker);
    if (!sid) return {};
    return m_cache[moniker].sidStr;
}

bool SandboxAppContainer::deleteProfile(const std::string& moniker) {
    const std::wstring wmon = toWide(moniker);
    const HRESULT hr = DeleteAppContainerProfile(wmon.c_str());
    if (SUCCEEDED(hr)) {
        // Remove from cache; the SID is freed here.
        auto it = m_cache.find(moniker);
        if (it != m_cache.end()) {
            if (it->second.sid) FreeSid(it->second.sid);
            m_cache.erase(it);
        }
    }
    m_lastError = SUCCEEDED(hr) ? ERROR_SUCCESS : HRESULT_CODE(hr);
    return SUCCEEDED(hr);
}

bool SandboxAppContainer::grantPath(const std::string& moniker,
                                    const std::string& path,
                                    const std::string& access) {
    PSID sid = acquireSid(moniker);
    if (!sid) return false;
    // The standalone grant API is used by `sandbox acl` / shared-folder flows,
    // which expect pre-existing files in the folder to become readable.
    const DWORD rc = grantPathImpl(toWide(path), sid, access,
                                   GrantPropagation::ImmediateFiles);
    m_lastError = rc;
    return rc == ERROR_SUCCESS;
}

bool SandboxAppContainer::revokePath(const std::string& moniker,
                                     const std::string& path) {
    PSID sid = acquireSid(moniker);
    if (!sid) return false;
    // Mirror grantPath()'s ImmediateFiles default so children stamped during the
    // grant are cleaned up.
    const DWORD rc = revokePathImpl(toWide(path), sid, GrantPropagation::ImmediateFiles);
    m_lastError = rc;
    return rc == ERROR_SUCCESS;
}

bool SandboxAppContainer::checkAccess(const std::string& moniker,
                                      const std::string& path) {
    PSID sid = acquireSid(moniker);
    if (!sid) return false;
    return checkAccessImpl(toWide(path), sid);
}

// ── spawn() — full isolated process lifecycle ──────────────────────────────────

SandboxResult SandboxAppContainer::spawn(const SandboxSpawnOptions& opts_in) {
    // Make a mutable copy so we can append the scratch-dir path grant.
    SandboxSpawnOptions opts = opts_in;

    SandboxResult res;
    HANDLE stdin_read = nullptr;
    HANDLE stdin_write = nullptr;
    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    HANDLE stderr_read = nullptr;
    HANDLE stderr_write = nullptr;
    DWORD attr_count = 1;  // SECURITY_CAPABILITIES is always present
    SIZE_T attr_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = nullptr;
    HANDLE job = nullptr;  // per-spawn Job Object: kills the whole process tree
    // Capability SID storage — declared early so goto cleanup_caps is well-formed.
    // cap_group_ptr_arrays / cap_ptr_arrays hold the arrays returned by
    // DeriveCapabilitySidsFromName; they are LocalFree'd in the cleanup block.
    std::vector<SID_AND_ATTRIBUTES> cap_sa;
    std::vector<PSID*> cap_group_ptr_arrays, cap_ptr_arrays;

    // ── Acquire profile SID ──────────────────────────────────────────────────
    bool wasCreated = false;
    PSID sid = acquireSid(opts.moniker, &wasCreated);
    if (!sid) {
        res.error = "AppContainer profile setup failed (Win32 "
                  + std::to_string(m_lastError) + ")";
        return res;
    }
    res.profileCreated = wasCreated;
    res.containerSid   = m_cache[opts.moniker].sidStr;
    pm::log::debug_lazy("sandbox_ac", [&] {
        return "spawn: sid acquired moniker=" + opts.moniker + " paths=" +
               std::to_string(opts.paths.size()) + " cwd=" + opts.cwd; });

    // ── Create scratch temp dir (if requested) ────────────────────────────────
    // Provides the sandboxed process with a private read-write scratch area
    // (`%TEMP%\pm-sidecar-<pid>-<tick>`) that is created before launch,
    // granted to the container SID, and deleted after the process exits.
    if (opts.createScratchDir) {
        WCHAR tmp[MAX_PATH + 1] = {};
        GetTempPathW(MAX_PATH, tmp);
        static std::atomic<std::uint32_t> s_seq{0};
        std::wstring scratchW = tmp;
        scratchW += L"pm-sidecar-";
        scratchW += std::to_wstring(GetCurrentProcessId());
        scratchW += L"-";
        scratchW += std::to_wstring(GetTickCount64());
        scratchW += L"-";
        scratchW += std::to_wstring(s_seq.fetch_add(1, std::memory_order_relaxed));
        if (CreateDirectoryW(scratchW.c_str(), nullptr)) {
            const int n = WideCharToMultiByte(CP_UTF8, 0, scratchW.c_str(), -1,
                                              nullptr, 0, nullptr, nullptr);
            std::string scratchU8(static_cast<size_t>(n > 0 ? n - 1 : 0), '\0');
            WideCharToMultiByte(CP_UTF8, 0, scratchW.c_str(), -1,
                                scratchU8.data(), n, nullptr, nullptr);
            res.scratchDir = scratchU8;
            // Scratch is a private, freshly-created dir; ImmediateFiles keeps any
            // files the child creates re-readable, and the dir is empty so the
            // propagation cost is ~0.
            opts.paths.push_back({scratchU8, "read-write",
                                  GrantPropagation::ImmediateFiles, /*deleteOnRevoke=*/true});
        }
        // Failure to create scratch dir is non-fatal: log is omitted here (caller
        // can check res.scratchDir.empty() to detect the failure).
    }

    // ── Locate volume-query shim DLL ─────────────────────────────────────────
    // Resolved before CreateProcessW so we can grant exec access before launch
    // and revoke it after.  Empty when shim is absent or disabled.
    std::wstring shim_path;
    if (opts.injectVolumeShim) {
        shim_path = find_shim_dll();
        pm::log::debug_lazy("sandbox_ac", [&] {
            return std::string("spawn: shim ") +
                   (shim_path.empty() ? "not found (skipping)" : "found"); });
    }

    // ── Grant paths before launch ────────────────────────────────────────────
    pm::log::debug_lazy("sandbox_ac", [] { return "spawn: granting paths…"; });
    for (const auto& pg : opts.paths) {
        pm::log::debug_lazy("sandbox_ac", [&] {
            const char* pn = pg.propagation == GrantPropagation::NodeOnly ? "node"
                           : pg.propagation == GrantPropagation::Recursive ? "recursive"
                           : "immediate";
            return std::string("spawn: granting path access=") + pg.access +
                   " prop=" + pn + " path=" + pg.path; });
        const auto g0 = std::chrono::steady_clock::now();
        const DWORD rc = grantPathImpl(toWide(pg.path), sid, pg.access, pg.propagation);
        pm::log::debug_lazy("sandbox_ac", [&] {
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - g0).count();
            return "spawn: grant rc=" + std::to_string(rc) + " ms=" + std::to_string(ms) +
                   " path=" + pg.path; });
        SandboxPathGrantResult gr;
        gr.path   = pg.path;
        gr.access = pg.access;
        gr.ok     = (rc == ERROR_SUCCESS);
        if (!gr.ok) gr.error = "Win32 " + std::to_string(rc);
        res.grantedPaths.push_back(std::move(gr));
    }

    // ── Grant shim DLL exec access (if found) ────────────────────────────────
    // The AppContainer must be able to read+execute the shim before we inject
    // it.  Grant a NodeOnly (O(1)) exec ACE on the DLL file itself so
    // LoadLibraryW inside the child can open and map it.
    if (!shim_path.empty()) {
        const DWORD rc = grantPathImpl(shim_path, sid, "exec",
                                       GrantPropagation::NodeOnly);
        pm::log::debug_lazy("sandbox_ac", [&] {
            return "spawn: shim exec grant rc=" + std::to_string(rc); });
        if (rc != ERROR_SUCCESS) shim_path.clear();  // skip injection if grant failed
    }

    // ── Build thread-attribute list ──────────────────────────────────────────
    SECURITY_ATTRIBUTES pipe_sa = {};
    pipe_sa.nLength = sizeof(pipe_sa);
    pipe_sa.bInheritHandle = TRUE;

    if (!CreatePipe(&stdin_read, &stdin_write, &pipe_sa, 0) ||
        !CreatePipe(&stdout_read, &stdout_write, &pipe_sa, 0) ||
        !CreatePipe(&stderr_read, &stderr_write, &pipe_sa, 0)) {
        res.error = "CreatePipe failed (Win32 " + std::to_string(GetLastError()) + ")";
        goto cleanup_caps;
    }
    SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

    // Per-spawn Job Object so a timeout (or handle close) tears down the entire
    // child process tree, not just the immediate shell. KILL_ON_JOB_CLOSE means
    // even an early/abnormal return from this function reaps any survivors.
    job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                &jeli, sizeof(jeli));
    }

    // ── Resolve capability SIDs ───────────────────────────────────────────────
    // DeriveCapabilitySidsFromName lives in kernelbase.dll (not re-exported by
    // advapi32.dll in this SDK version). Load dynamically to avoid a hard import
    // that would break older link environments.
    using PfnDeriveCap = BOOL(WINAPI*)(LPCWSTR, PSID**, DWORD*, PSID**, DWORD*);
    static const PfnDeriveCap s_deriveCap = [] {
        HMODULE h = GetModuleHandleW(L"kernelbase.dll");
        return h ? reinterpret_cast<PfnDeriveCap>(
            GetProcAddress(h, "DeriveCapabilitySidsFromName")) : nullptr;
    }();

    for (const auto& cap_name : opts.capabilities) {
        const std::wstring wcap = toWide(cap_name);
        PSID* group_arr = nullptr; DWORD n_group = 0;
        PSID* cap_arr   = nullptr; DWORD n_cap   = 0;
        if (s_deriveCap && s_deriveCap(wcap.c_str(),
                &group_arr, &n_group, &cap_arr, &n_cap) && n_cap > 0) {
            for (DWORD i = 0; i < n_cap; ++i) {
                SID_AND_ATTRIBUTES sa = {};
                sa.Sid        = cap_arr[i];
                sa.Attributes = SE_GROUP_ENABLED;
                cap_sa.push_back(sa);
            }
            cap_group_ptr_arrays.push_back(group_arr);
            cap_ptr_arrays.push_back(cap_arr);
        }
    }

    if (opts.lpac)           attr_count++;
    if (opts.noWin32k)       attr_count++;
    if (opts.noChildProcess) attr_count++;
    attr_count++;  // PROC_THREAD_ATTRIBUTE_HANDLE_LIST (always — limits handle leakage)

    InitializeProcThreadAttributeList(nullptr, attr_count, 0, &attr_size);
    attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attr_size));
    if (!attr_list || !InitializeProcThreadAttributeList(attr_list, attr_count, 0, &attr_size)) {
        if (attr_list) HeapFree(GetProcessHeap(), 0, attr_list);
        res.error = "InitializeProcThreadAttributeList failed";
        goto cleanup_caps;
    }

    {
        SECURITY_CAPABILITIES sc = {};
        sc.AppContainerSid  = sid;
        sc.Capabilities     = cap_sa.empty() ? nullptr : cap_sa.data();
        sc.CapabilityCount  = static_cast<DWORD>(cap_sa.size());
        UpdateProcThreadAttribute(attr_list, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &sc, sizeof(sc), nullptr, nullptr);

        if (opts.lpac) {
            const DWORD opt = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
            UpdateProcThreadAttribute(attr_list, 0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                const_cast<DWORD*>(&opt), sizeof(opt), nullptr, nullptr);
        }

        ULONGLONG mitig[2] = {};
        if (opts.noWin32k) {
            mitig[0] = PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
            UpdateProcThreadAttribute(attr_list, 0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                mitig, sizeof(mitig), nullptr, nullptr);
        }

        if (opts.noChildProcess) {
            // Prevent the sandboxed process from spawning child processes.
            // Important for MCP servers that should not be able to escape via
            // a sub-process (e.g. shell injection → CreateProcess).
            const DWORD childPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
            UpdateProcThreadAttribute(attr_list, 0,
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                const_cast<DWORD*>(&childPolicy), sizeof(DWORD), nullptr, nullptr);
        }

        // ── Explicit handle list — restrict inheritance to stdio only ────────
        // Without this, ALL inheritable handles in the parent (file handles,
        // pipe handles, DPAPI key handles) would be visible inside the AC child.
        // PROC_THREAD_ATTRIBUTE_HANDLE_LIST limits inheritance to exactly these
        // three: stdin/stdout/stderr. Non-inheritable handles are unaffected.
        HANDLE inherit_handles[3] = {};
        DWORD  inherit_count = 0;
        inherit_handles[inherit_count++] = stdin_read;
        inherit_handles[inherit_count++] = stdout_write;
        inherit_handles[inherit_count++] = stderr_write;
        UpdateProcThreadAttribute(attr_list, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherit_handles, inherit_count * sizeof(HANDLE), nullptr, nullptr);

        // ── Build command line ───────────────────────────────────────────────
        std::string cmdline_u8 = opts.run;
        for (const auto& a : opts.args) { cmdline_u8 += ' '; cmdline_u8 += a; }
        std::wstring cmdline = toWide(cmdline_u8);
        std::wstring cwd = toWide(opts.cwd);

        STARTUPINFOEXW si = {};
        si.StartupInfo.cb = sizeof(si);
        si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput  = stdin_read;
        si.StartupInfo.hStdOutput = stdout_write;
        si.StartupInfo.hStdError  = stderr_write;
        si.lpAttributeList = attr_list;
        PROCESS_INFORMATION pi = {};
        // CREATE_SUSPENDED: assign the process to the Job before it (or any
        // child it spawns) starts running, so the whole tree is captured.
        const DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
                          | CREATE_SUSPENDED;

        const BOOL launched = CreateProcessW(
            nullptr, cmdline.data(), nullptr, nullptr, TRUE,
            flags, nullptr, cwd.empty() ? nullptr : cwd.c_str(),
            reinterpret_cast<LPSTARTUPINFOW>(&si), &pi);
        const DWORD launch_err = launched ? 0 : GetLastError();

        DeleteProcThreadAttributeList(attr_list);
        HeapFree(GetProcessHeap(), 0, attr_list);
        // Parent never writes to sandboxed stdin; closing the write end gives the
        // child EOF and avoids inheriting caller-specific console/pipe handles.
        close_if_valid(stdin_write);
        close_if_valid(stdin_read);
        close_if_valid(stdout_write);
        close_if_valid(stderr_write);

        if (!launched) {
            m_lastError = launch_err;
            res.error = "CreateProcessW failed (Win32 " + std::to_string(launch_err) + ")";
            goto cleanup_caps;
        }

        const bool assigned_to_job =
            job && AssignProcessToJobObject(job, pi.hProcess) != 0;

        // ── Inject volume-query shim before main thread runs ──────────────────
        // A new remote thread calls LoadLibraryW, which runs DllMain while
        // pi.hThread is still suspended.  InstallHooks() then patches the IAT
        // of the main executable so GetVolumeInformationW / GetDiskFreeSpaceExW
        // return synthetic data instead of "Access is denied."
        if (!shim_path.empty()) {
            const bool injected = inject_dll(pi.hProcess, shim_path);
            pm::log::debug_lazy("sandbox_ac", [&] {
                return std::string("spawn: shim inject ") +
                       (injected ? "ok" : "failed (non-fatal)"); });
        }

        ResumeThread(pi.hThread);
        // Publish the job for external abort() now that the child is live.
        if (assigned_to_job) {
            std::lock_guard<std::mutex> lk(g_active_jobs_mu);
            g_active_jobs.insert(job);
        }

        res.launched = true;
        res.pid      = pi.dwProcessId;
        pm::log::debug_lazy("sandbox_ac", [&] {
            return "spawn: launched pid=" + std::to_string(pi.dwProcessId) +
                   " assignedToJob=" + (assigned_to_job ? "1" : "0"); });

        std::mutex out_mtx, err_mtx;
        std::atomic<bool> stop_pipe_readers{false};
        std::thread stdout_thread(read_pipe_streaming, stdout_read,
                                  std::ref(res.stdoutText), std::ref(out_mtx),
                                  std::string("stdout"), std::cref(opts.onOutputChunk),
                                  std::cref(stop_pipe_readers));
        std::thread stderr_thread(read_pipe_streaming, stderr_read,
                                  std::ref(res.stderrText), std::ref(err_mtx),
                                  std::string("stderr"), std::cref(opts.onOutputChunk),
                                  std::cref(stop_pipe_readers));

        // ── Wait: poll loop so timeout AND cooperative cancel are honoured ────
        // A single blocking WaitForSingleObject(timeoutMs) would ignore cancel
        // and block the whole timeout; instead we slice the wait and re-check.
        namespace chr = std::chrono;
        constexpr DWORD k_poll_ms = 100;
        const auto deadline = opts.timeoutMs > 0
            ? chr::steady_clock::now() + chr::milliseconds(opts.timeoutMs)
            : chr::steady_clock::time_point::max();

        for (;;) {
            DWORD slice = k_poll_ms;
            if (opts.timeoutMs > 0) {
                const long long left = chr::duration_cast<chr::milliseconds>(
                    deadline - chr::steady_clock::now()).count();
                if (left <= 0) { res.timedOut = true; break; }
                slice = static_cast<DWORD>(std::min<long long>(k_poll_ms, left));
            }
            const DWORD wait = WaitForSingleObject(pi.hProcess, slice);
            if (wait == WAIT_OBJECT_0) {
                // The wait slice is coarser than a 1ms budget. An exit observed
                // after the deadline is still a timeout.
                if (opts.timeoutMs > 0 && chr::steady_clock::now() >= deadline)
                    res.timedOut = true;
                break;
            }
            if (opts.onCancelCheck && opts.onCancelCheck()) { // cooperative stop
                res.cancelled = true;
                break;
            }
        }

        pm::log::debug_lazy("sandbox_ac", [&] {
            return std::string("spawn: wait done timedOut=") + (res.timedOut ? "1" : "0") +
                   " cancelled=" + (res.cancelled ? "1" : "0"); });

        if (res.timedOut || res.cancelled) {
            // Tree-kill: reaps the shell plus any grandchildren (e.g. a spawned
            // powershell/Start-Sleep). Falls back to the single process when the
            // Job could not be created.
            if (assigned_to_job) TerminateJobObject(job, res.cancelled ? 130 : 1);
            else                 TerminateProcess(pi.hProcess, res.cancelled ? 130 : 1);
            WaitForSingleObject(pi.hProcess, 3000);
        } else {
            DWORD exit_code = 0;
            GetExitCodeProcess(pi.hProcess, &exit_code);
            res.exitCode = static_cast<int>(exit_code);
            // Captured sandbox execution owns the whole job. Reap background
            // descendants that outlived the shell root before joining readers.
            if (assigned_to_job)
                (void)TerminateJobObject(job, 0);
        }

        // Unpublish before closing the handle so abort() never races a dead job.
        if (assigned_to_job) {
            std::lock_guard<std::mutex> lk(g_active_jobs_mu);
            g_active_jobs.erase(job);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        pm::log::debug_lazy("sandbox_ac", [] { return "spawn: joining pipe readers…"; });
        stop_pipe_readers.store(true, std::memory_order_release);
        if (stdout_thread.joinable()) stdout_thread.join();
        if (stderr_thread.joinable()) stderr_thread.join();
        pm::log::debug_lazy("sandbox_ac", [] { return "spawn: readers joined"; });
        close_if_valid(stdout_read);
        close_if_valid(stderr_read);
        res.ok = res.launched && !res.timedOut && !res.cancelled && res.exitCode == 0;
    }

cleanup_caps:
    // ── Free capability SIDs allocated by DeriveCapabilitySidsFromName ────────
    for (PSID* arr : cap_group_ptr_arrays) LocalFree(arr);
    for (PSID* arr : cap_ptr_arrays)       LocalFree(arr);
    cap_group_ptr_arrays.clear();
    cap_ptr_arrays.clear();

    close_if_valid(stdout_write);
    close_if_valid(stderr_write);
    close_if_valid(stdin_write);
    close_if_valid(stdin_read);
    close_if_valid(stdout_read);
    close_if_valid(stderr_read);
    // Defensive: ensure the abort registry never points at a job we are about
    // to close (the normal path already cleared it after the wait loop).
    if (job) {
        std::lock_guard<std::mutex> lk(g_active_jobs_mu);
        g_active_jobs.erase(job);
    }
    // KILL_ON_JOB_CLOSE: closing the last handle terminates any process still
    // assigned to the Job, guaranteeing no leaked sandboxed survivors.
    close_if_valid(job);

    // ── Revoke paths after process exits ─────────────────────────────────────
    for (const auto& pg : opts.paths) {
        const DWORD rc = revokePathImpl(toWide(pg.path), sid, pg.propagation);
        SandboxPathGrantResult rr;
        rr.path   = pg.path;
        rr.access = pg.access;
        rr.ok     = (rc == ERROR_SUCCESS);
        if (!rr.ok) rr.error = "Win32 " + std::to_string(rc);
        res.revokedPaths.push_back(std::move(rr));

        // Physically remove ephemeral dirs (e.g. the scratch temp dir) after the
        // ACE is revoked so no orphaned directories accumulate under %TEMP%.
        if (pg.deleteOnRevoke && !pg.path.empty())
            RemoveDirectoryW(toWide(pg.path).c_str());
    }

    // ── Revoke shim DLL exec grant ────────────────────────────────────────────
    if (!shim_path.empty())
        revokePathImpl(shim_path, sid, GrantPropagation::NodeOnly);

    // ── Profile cleanup ───────────────────────────────────────────────────────
    if (!opts.retain) {
        deleteProfile(opts.moniker);
    }

    return res;
}

} // namespace pm::security

#endif // _WIN32
