#include "cli_cancel.hpp"

#include "logging/pm_log.hpp"

#if !defined(_WIN32)
#  include <csignal>
#endif
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace media::cli {

static std::atomic<bool> g_cancel{false};

// Listener registry — append-only, fired exactly once per cancel transition by
// the watcher thread spawned in install_cli_interrupt_handlers().
//
// IMPORTANT: Use Construct-On-First-Use (Meyers singleton) for the mutex and
// vector. Static initialisers in other translation units (e.g. the
// CancelListenerRegistrar in path_tool_executor.cpp) call register_cancel_listener
// at namespace-scope dynamic init, and their relative order vs. these globals
// is unspecified across TUs. Without the singleton wrappers, calling
// push_back / lock on zero-initialised storage before C++ runs the real
// constructors silently corrupts state on Windows DLL boundaries.
static std::mutex& listeners_mu() {
    static std::mutex m;
    return m;
}
static std::vector<std::function<void()>>& listeners() {
    static std::vector<std::function<void()>> v;
    return v;
}
static std::atomic<bool> g_watcher_started{false};

// Per-thread opt-out depth. When > 0 the current thread ignores the global
// cancel latch (see ScopedIgnoreGlobalCancel). Used by isolated worker threads
// (voice-delegated agent runs) that carry their own per-run cancel channel and
// must not be killed by a stale global flag left by an unrelated cancel.
static thread_local int tl_ignore_global_cancel = 0;
static thread_local std::function<bool()> tl_cancel_predicate;
// Guard against reentrant cancel_requested() while evaluating
// tl_cancel_predicate. Agent turns install a predicate that may call back into
// xblox/io.cancelled(), whose ExecutionOptions.cancel_requested polls
// cli::cancel_requested() again — without this guard that cycle overflows the
// stack. On reentry only the process-global latch is consulted.
static thread_local int tl_cancel_predicate_depth = 0;

namespace { void fire_all_listeners() noexcept; }

bool cancel_requested() noexcept
{
    if (tl_cancel_predicate && tl_cancel_predicate_depth == 0) {
        ++tl_cancel_predicate_depth;
        bool cancelled = false;
        try {
            cancelled = tl_cancel_predicate();
        } catch (...) {
            // Cancellation checks must never unwind through networking/process
            // callbacks. Treat a broken host predicate as not-cancelled.
        }
        --tl_cancel_predicate_depth;
        if (cancelled) return true;
    }
    return tl_ignore_global_cancel <= 0
        && g_cancel.load(std::memory_order_acquire);
}

ScopedIgnoreGlobalCancel::ScopedIgnoreGlobalCancel() noexcept
{
    ++tl_ignore_global_cancel;
}

ScopedIgnoreGlobalCancel::~ScopedIgnoreGlobalCancel() noexcept
{
    if (tl_ignore_global_cancel > 0) --tl_ignore_global_cancel;
}

ScopedCancelPredicate::ScopedCancelPredicate(std::function<bool()> predicate)
    : previous_(std::move(tl_cancel_predicate))
{
    if (previous_ && predicate) {
        tl_cancel_predicate =
            [outer = previous_, inner = std::move(predicate)]() {
                return outer() || inner();
            };
    } else if (predicate) {
        tl_cancel_predicate = std::move(predicate);
    } else {
        tl_cancel_predicate = previous_;
    }
}

ScopedCancelPredicate::~ScopedCancelPredicate()
{
    tl_cancel_predicate = std::move(previous_);
}

void request_cancel() noexcept
{
    const bool was = g_cancel.exchange(true, std::memory_order_acq_rel);
    if (!was) {
        logger::trace("[cancel] request_cancel → g_cancel=true (transition)");
        // The persistent watcher also observes the transition, but fire here too
        // so listeners run promptly even before the next 50 ms poll tick. Listeners
        // are required to be idempotent, so the possible double-fire is harmless.
        fire_all_listeners();
    } else {
        logger::trace("[cancel] request_cancel → g_cancel already true");
    }
}

void test_request_cancel()
{
    const bool was = g_cancel.exchange(true, std::memory_order_acq_rel);
    if (!was)
        logger::trace("[cancel] test_request_cancel → g_cancel=true (transition)");
    else
        logger::trace("[cancel] test_request_cancel → g_cancel already true");
}

void test_clear_cancel()
{
    const bool was = g_cancel.exchange(false, std::memory_order_acq_rel);
    if (was)
        logger::trace("[cancel] test_clear_cancel → g_cancel=false (reset)");
}

void register_cancel_listener(std::function<void()> fn)
{
    if (!fn) return;
    std::lock_guard<std::mutex> lk(listeners_mu());
    listeners().push_back(std::move(fn));
    logger::trace("[cancel] register_cancel_listener → total=" + std::to_string(listeners().size()));
}

namespace {

void fire_all_listeners() noexcept
{
    std::vector<std::function<void()>> copy;
    {
        std::lock_guard<std::mutex> lk(listeners_mu());
        copy = listeners();
    }
    logger::trace("[cancel] fire_all_listeners → n=" + std::to_string(copy.size()));
    for (std::size_t i = 0; i < copy.size(); ++i) {
        try {
            logger::trace("[cancel]   listener[" + std::to_string(i) + "] enter");
            copy[i]();
            logger::trace("[cancel]   listener[" + std::to_string(i) + "] exit");
        } catch (...) {
            logger::trace("[cancel]   listener[" + std::to_string(i) + "] threw (swallowed)");
        }
    }
}

// Persistent edge-triggered watcher. Polls g_cancel every 50 ms and fires
// listeners on every false → true transition. After firing it waits for
// g_cancel to flip back to false (via test_clear_cancel from the next
// chat / agent run) so we don't re-fire continuously while it remains set.
//
// Earlier one-shot version was a time bomb: after the first cancel the
// watcher exited and any subsequent POSIX SIGINT (signal handler can't
// safely fire listeners itself) would never propagate to abort_active_*.
void start_cancel_watcher_once() noexcept
{
    bool expected = false;
    if (!g_watcher_started.compare_exchange_strong(expected, true))
        return;
    logger::trace("[cancel] watcher thread starting");
    std::thread([] {
        bool last_seen = false;
        for (;;) {
            const bool now = g_cancel.load(std::memory_order_acquire);
            if (now && !last_seen) {
                logger::trace("[cancel] watcher saw false→true transition");
                fire_all_listeners();
                logger::trace("[cancel] watcher done firing listeners (awaiting reset)");
            } else if (!now && last_seen) {
                logger::trace("[cancel] watcher saw true→false reset (re-armed)");
            }
            last_seen = now;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }).detach();
}

} // namespace

#if defined(_WIN32)

#  include <windows.h>

static BOOL WINAPI win_ctrl_handler(DWORD type)
{
    const bool was = g_cancel.exchange(true, std::memory_order_acq_rel);
    logger::trace("[cancel] win_ctrl_handler type=" + std::to_string(type)
                  + (was ? " (g_cancel already true)" : " → g_cancel=true"));
    // CTRL_CLOSE_EVENT: console window closing — return TRUE so we get ~5 s to
    // unwind; callers must observe cancel_requested() and exit promptly.
    // Windows console handlers run on a dedicated thread, so it is safe to
    // invoke listeners directly here (no async-signal-safety constraints).
    // The watcher thread also fires; listeners must therefore be idempotent.
    if (!was) fire_all_listeners();
    return TRUE;
}

static void win_console_detach_watchdog() noexcept
{
    if (GetConsoleWindow() == nullptr)
        return;
    std::thread([] {
        while (!g_cancel.load(std::memory_order_acquire)) {
            if (GetConsoleWindow() == nullptr) {
                logger::trace("[cancel] console detach detected → g_cancel=true");
                g_cancel.store(true, std::memory_order_release);
                fire_all_listeners();
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }).detach();
}

void install_cli_interrupt_handlers() noexcept
{
    g_cancel.store(false, std::memory_order_release);
    if (GetConsoleWindow() == nullptr)
        (void)AttachConsole(ATTACH_PARENT_PROCESS);
    (void)SetConsoleCtrlHandler(win_ctrl_handler, TRUE);
    win_console_detach_watchdog();
    start_cancel_watcher_once();
    logger::trace("[cancel] install_cli_interrupt_handlers (Windows)");
}

#else

static void on_sigint(int)
{
    // POSIX signal handler: only async-signal-safe operations allowed.
    // Listeners are fired from the watcher thread to avoid undefined behavior.
    g_cancel.store(true, std::memory_order_release);
}

void install_cli_interrupt_handlers() noexcept
{
    g_cancel.store(false, std::memory_order_release);
    // Use sigaction with SA_RESETHAND=no and SA_RESTART=no (SA_INTERRUPT on BSD).
    // Without SA_INTERRUPT, blocking syscalls (mach_msg, kevent, CFRunLoopRunInMode)
    // would restart after the signal handler returns and never wake the run loop.
    struct sigaction sa{};
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
#if defined(SA_INTERRUPT)
    sa.sa_flags = SA_INTERRUPT;
#else
    sa.sa_flags = 0; // POSIX: no SA_RESTART → same effect
#endif
    sigaction(SIGINT, &sa, nullptr);
    start_cancel_watcher_once();
    logger::trace("[cancel] install_cli_interrupt_handlers (POSIX)");
}

#endif

} // namespace media::cli
