#pragma once
//
// pm::security::antihack — runtime tamper telemetry.
//
// Scope (docs/security/dehack.md): the four "obvious and urgent" runtime
// integrity signals — debugger presence, inline DLL hooks on sensitive system
// exports, loaded-module provenance, and private executable memory. Gated by
// FEATURE_ANTI_HACKING (default ON).
//
// Design intent (see dehack.md "Priority rule"): these are *signals*, not a
// security boundary. `run()` collects evidence and returns a structured report;
// the caller decides what to do with it (log, downgrade capabilities, surface a
// warning). Nothing here terminates the process or corrupts state on its own.
//
// Portability: only the Windows backend produces meaningful signals. On other
// platforms every scan returns an empty (clean) result so call sites compile
// and behave uniformly.
//

#include <string>
#include <vector>

#ifndef FEATURE_ANTI_HACKING
#  define FEATURE_ANTI_HACKING 1
#endif

namespace pm::security::antihack {

enum class Category : int {
    Debugger = 0,  ///< debugger attached / debug flags set
    DllHook,       ///< inline hook on a system export
    Module,        ///< loaded-module provenance anomaly
    Memory,        ///< private executable memory anomaly
};

enum class Severity : int {
    Info = 0,  ///< informational snapshot, not an anomaly
    Low,       ///< weak signal, common false-positive source
    Medium,    ///< notable, worth auditing
    High,      ///< strong tamper signal
    Critical,  ///< near-certain tampering / active instrumentation
};

/// A single observation. `detected == false` rows are kept for Info snapshots
/// (e.g. "module count = 87") so the report doubles as a baseline.
struct Signal {
    Category    category = Category::Debugger;
    std::string name;                       ///< stable id, e.g. "debugger.peb_being_debugged"
    bool        detected = false;           ///< true => anomaly present
    Severity    severity = Severity::Info;
    std::string detail;                     ///< human-readable explanation
    std::string locus;                      ///< module!export, address, or path (optional)
};

/// Which scans `run()` performs and how broadly.
struct ScanOptions {
    bool debugger  = true;
    bool dll_hooks = true;
    bool modules   = true;
    bool memory    = true;

    /// Modules whose sensitive exports are checked for inline hooks. Empty =>
    /// the built-in default set (ntdll, kernel32, kernelbase).
    std::vector<std::string> hook_modules;

    /// When true, the memory scan allocates a PAGE_EXECUTE_READWRITE page first
    /// so the RWX detector has a deterministic positive (test harness only).
    bool memory_self_test_rwx = false;
};

/// Aggregated result of a scan pass. Counters mirror the per-category telemetry
/// described in dehack.md so suites can assert on them directly.
struct Report {
    std::vector<Signal> signals;

    int debugger_detected = 0;
    int dll_hook_detected = 0;
    int module_detected   = 0;
    int memory_detected   = 0;

    int modules_total = 0;  ///< total loaded modules observed (snapshot size)

    [[nodiscard]] bool     any_detected() const noexcept;
    [[nodiscard]] int      detected_count() const noexcept;
    [[nodiscard]] Severity max_severity() const noexcept;
};

// ── individual scans ─────────────────────────────────────────────────────────
// Each appends zero or more Signals. Safe to call repeatedly.

std::vector<Signal> scan_debugger();
std::vector<Signal> scan_dll_hooks(const std::vector<std::string>& modules = {});
std::vector<Signal> scan_modules();
std::vector<Signal> scan_memory(bool self_test_rwx = false);

/// Run the enabled scans and aggregate into a Report (recomputing counters).
Report run(const ScanOptions& opts = {});

// ── helpers ──────────────────────────────────────────────────────────────────

[[nodiscard]] const char* to_string(Category) noexcept;
[[nodiscard]] const char* to_string(Severity) noexcept;

/// True when FEATURE_ANTI_HACKING is compiled in *and* the platform backend can
/// produce signals (Windows). Lets call sites / probes report capability.
[[nodiscard]] bool available() noexcept;

} // namespace pm::security::antihack
