// pm_sb_shim.cpp — Volume-query shim DLL for Windows AppContainer sandboxes.
//
// AppContainer (AC / LPAC) denies access to volume device objects
// (\Device\HarddiskVolumeN).  Shell built-ins like `dir`, `vol`, and `tree`
// call GetVolumeInformationW / GetDiskFreeSpaceExW to print headers, which
// then fail with "Access is denied." even when the working directory is
// fully granted.
//
// This DLL is injected into the sandboxed child via WriteProcessMemory +
// CreateRemoteThread before the main thread is resumed.
//
// Strategy: two layers to catch all call sites
//   1. INLINE HOOK on kernelbase.dll exports — catches callers that use
//      GetProcAddress at runtime or import directly from kernelbase.  On
//      Win10+, kernel32.dll forwards all three APIs to kernelbase, so one
//      patch covers both DLLs.  A 12-byte x64 absolute-indirect JMP
//      (FF 25 00 00 00 00 <qword addr>) is written at the function entry so
//      any call site, direct or indirect, reaches our fake handler.
//   2. IAT PATCH on the main EXE — cheap belt-and-suspenders for modules
//      that import at link time from either kernel32.dll or kernelbase.dll.
//
// Design: ref/chromium/sandbox/win/src/process_mitigations_win32k_interception.cc
//   (same "target-side fake response" pattern, no broker IPC needed).

#include <Windows.h>

// ── Fake implementations ──────────────────────────────────────────────────────

static BOOL WINAPI FakeGetVolumeInformationW(
    LPCWSTR /*lpRootPathName*/,
    LPWSTR  lpVolumeNameBuffer,    DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber,
    LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags,
    LPWSTR  lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    if (lpVolumeNameBuffer && nVolumeNameSize > 0)
        lstrcpynW(lpVolumeNameBuffer, L"Sandbox", static_cast<int>(nVolumeNameSize));
    if (lpVolumeSerialNumber)
        *lpVolumeSerialNumber = 0xDEADBEEFu;
    if (lpMaximumComponentLength)
        *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags)
        *lpFileSystemFlags = FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS
                           | FILE_CASE_SENSITIVE_SEARCH;
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 0)
        lstrcpynW(lpFileSystemNameBuffer, L"NTFS", static_cast<int>(nFileSystemNameSize));
    return TRUE;
}

static BOOL WINAPI FakeGetVolumeInformationA(
    LPCSTR  /*lpRootPathName*/,
    LPSTR   lpVolumeNameBuffer,    DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber,
    LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags,
    LPSTR   lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    if (lpVolumeNameBuffer && nVolumeNameSize > 0)
        lstrcpynA(lpVolumeNameBuffer, "Sandbox", static_cast<int>(nVolumeNameSize));
    if (lpVolumeSerialNumber)
        *lpVolumeSerialNumber = 0xDEADBEEFu;
    if (lpMaximumComponentLength)
        *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags)
        *lpFileSystemFlags = FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS
                           | FILE_CASE_SENSITIVE_SEARCH;
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 0)
        lstrcpynA(lpFileSystemNameBuffer, "NTFS", static_cast<int>(nFileSystemNameSize));
    return TRUE;
}

static BOOL WINAPI FakeGetDiskFreeSpaceExW(
    LPCWSTR         /*lpDirectoryName*/,
    PULARGE_INTEGER lpFreeBytesAvailableToCaller,
    PULARGE_INTEGER lpTotalNumberOfBytes,
    PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
    const ULONGLONG k10GB  = 10ULL  * 1024ULL * 1024ULL * 1024ULL;
    const ULONGLONG k100GB = 100ULL * 1024ULL * 1024ULL * 1024ULL;
    if (lpFreeBytesAvailableToCaller) lpFreeBytesAvailableToCaller->QuadPart = k10GB;
    if (lpTotalNumberOfBytes)         lpTotalNumberOfBytes->QuadPart         = k100GB;
    if (lpTotalNumberOfFreeBytes)     lpTotalNumberOfFreeBytes->QuadPart     = k10GB;
    return TRUE;
}

static BOOL WINAPI FakeGetDiskFreeSpaceExA(
    LPCSTR          /*lpDirectoryName*/,
    PULARGE_INTEGER lpFreeBytesAvailableToCaller,
    PULARGE_INTEGER lpTotalNumberOfBytes,
    PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
    return FakeGetDiskFreeSpaceExW(nullptr,
        lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
}

static BOOL WINAPI FakeGetDiskFreeSpaceW(
    LPCWSTR /*lpRootPathName*/,
    LPDWORD lpSectorsPerCluster,
    LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters,
    LPDWORD lpTotalNumberOfClusters)
{
    if (lpSectorsPerCluster)     *lpSectorsPerCluster     = 8;
    if (lpBytesPerSector)        *lpBytesPerSector        = 4096;
    if (lpNumberOfFreeClusters)  *lpNumberOfFreeClusters  = 2621440u;   // ~10 GB
    if (lpTotalNumberOfClusters) *lpTotalNumberOfClusters = 26214400u;  // ~100 GB
    return TRUE;
}

static BOOL WINAPI FakeGetDiskFreeSpaceA(
    LPCSTR  /*lpRootPathName*/,
    LPDWORD lpSectorsPerCluster,
    LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters,
    LPDWORD lpTotalNumberOfClusters)
{
    return FakeGetDiskFreeSpaceW(nullptr, lpSectorsPerCluster, lpBytesPerSector,
        lpNumberOfFreeClusters, lpTotalNumberOfClusters);
}

// ── Layer 1: Inline hook (12-byte x64 absolute-indirect JMP) ─────────────────
// Writes FF 25 00 00 00 00 <8-byte absolute addr> at fn_addr.
// This catches callers that use GetProcAddress, delay-load, or are in modules
// not yet loaded at injection time.  Triggers copy-on-write on the page so the
// patch is process-local; does not affect other processes sharing the mapping.
static void InlineHook(void* fn_addr, void* replacement) {
    if (!fn_addr || !replacement) return;
    auto* p = static_cast<BYTE*>(fn_addr);
    DWORD old_prot = 0;
    if (!VirtualProtect(p, 12, PAGE_EXECUTE_READWRITE, &old_prot)) return;
    p[0] = 0xFF; p[1] = 0x25;                          // jmp [rip+0]
    p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
    *reinterpret_cast<ULONGLONG*>(p + 6) =
        reinterpret_cast<ULONGLONG>(replacement);       // absolute target
    VirtualProtect(p, 12, old_prot, &old_prot);
}

// ── Layer 2: IAT patch (main EXE's import table) ──────────────────────────────
// Belt-and-suspenders for modules that imported at link time and whose IAT
// is still pointing at the real implementation.
static void PatchModuleIAT(HMODULE hMod, LPCSTR dllName, LPCSTR funcName,
                            void* replacement) {
    if (!hMod) return;
    auto* base = reinterpret_cast<BYTE*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        if (lstrcmpiA(reinterpret_cast<LPCSTR>(base + desc->Name), dllName) != 0)
            continue;
        DWORD oft_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                 : desc->FirstThunk;
        auto* orig = reinterpret_cast<IMAGE_THUNK_DATA*>(base + oft_rva);
        auto* iat  = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        for (; orig->u1.AddressOfData; ++orig, ++iat) {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                base + static_cast<DWORD>(orig->u1.AddressOfData));
            if (lstrcmpiA(reinterpret_cast<LPCSTR>(ibn->Name), funcName) != 0)
                continue;
            DWORD old_prot = 0;
            VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old_prot);
            iat->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&iat->u1.Function, sizeof(void*), old_prot, &old_prot);
        }
    }
}

static void InstallHooks() {
    // Patch actual implementations in KERNELBASE.dll (the canonical home on
    // Win10+; kernel32.dll forwards to it, so one patch covers both).
    HMODULE hKB = GetModuleHandleW(L"kernelbase.dll");
    if (hKB) {
        struct { LPCSTR name; void* fake; } funcs[] = {
            { "GetVolumeInformationW", reinterpret_cast<void*>(FakeGetVolumeInformationW) },
            { "GetVolumeInformationA", reinterpret_cast<void*>(FakeGetVolumeInformationA) },
            { "GetDiskFreeSpaceExW",   reinterpret_cast<void*>(FakeGetDiskFreeSpaceExW)   },
            { "GetDiskFreeSpaceExA",   reinterpret_cast<void*>(FakeGetDiskFreeSpaceExA)   },
            { "GetDiskFreeSpaceW",     reinterpret_cast<void*>(FakeGetDiskFreeSpaceW)     },
            { "GetDiskFreeSpaceA",     reinterpret_cast<void*>(FakeGetDiskFreeSpaceA)     },
        };
        for (const auto& f : funcs)
            InlineHook(reinterpret_cast<void*>(GetProcAddress(hKB, f.name)), f.fake);
    }

    // Also patch IAT of the main executable as belt-and-suspenders.
    HMODULE hExe = GetModuleHandleW(nullptr);
    static const char* const kDlls[] = { "kernel32.dll", "kernelbase.dll" };
    struct { LPCSTR name; void* fake; } iat_funcs[] = {
        { "GetVolumeInformationW", reinterpret_cast<void*>(FakeGetVolumeInformationW) },
        { "GetVolumeInformationA", reinterpret_cast<void*>(FakeGetVolumeInformationA) },
        { "GetDiskFreeSpaceExW",   reinterpret_cast<void*>(FakeGetDiskFreeSpaceExW)   },
        { "GetDiskFreeSpaceExA",   reinterpret_cast<void*>(FakeGetDiskFreeSpaceExA)   },
        { "GetDiskFreeSpaceW",     reinterpret_cast<void*>(FakeGetDiskFreeSpaceW)     },
        { "GetDiskFreeSpaceA",     reinterpret_cast<void*>(FakeGetDiskFreeSpaceA)     },
    };
    for (const char* dll : kDlls)
        for (const auto& f : iat_funcs)
            PatchModuleIAT(hExe, dll, f.name, f.fake);
}

// ── DLL entry point ───────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        InstallHooks();
    }
    return TRUE;
}
