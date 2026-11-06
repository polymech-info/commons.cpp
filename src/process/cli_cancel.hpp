#pragma once
//
// Shared Ctrl+C (SIGINT) / console interrupt flag for long-running CLI work
// (batch resume, `llm agent` tool calls). Install once in main; tools check
// between I/O-bound steps and yield briefly so the handler can run.
//
#include <atomic>
#include <functional>
#include <thread>

namespace media::cli {

/// True after the user requested interrupt (console Ctrl+C, POSIX SIGINT).
///
/// Honours a per-thread opt-out (see ScopedIgnoreGlobalCancel): threads that run
/// an *isolated* unit of work with their own cancel channel (e.g. a voice-
/// delegated agent run) return false here even while the global flag is set, so a
/// stale latch left by an unrelated cancel cannot pre-emptively kill them.
[[nodiscard]] bool cancel_requested() noexcept;

/// RAII opt-out from the process-global cancel latch for the *current thread*.
/// While one or more of these are live, cancel_requested() ignores the global
/// flag on that thread but still honours ScopedCancelPredicate. Nestable. The
/// work must carry its own cancellation channel.
class ScopedIgnoreGlobalCancel {
public:
    ScopedIgnoreGlobalCancel() noexcept;
    ~ScopedIgnoreGlobalCancel() noexcept;
    ScopedIgnoreGlobalCancel(const ScopedIgnoreGlobalCancel&)            = delete;
    ScopedIgnoreGlobalCancel& operator=(const ScopedIgnoreGlobalCancel&) = delete;
};

/// Add a per-thread cancellation predicate to cancel_requested().
///
/// Agent turns use this to propagate their per-run cancel_signal into blocking
/// tools and child-process runners that already poll cancel_requested(). This is
/// independent of ScopedIgnoreGlobalCancel: ignoring the process-global latch
/// never suppresses this per-run predicate. Nestable; an inner predicate is ORed
/// with the predicate that was active when it was installed.
class ScopedCancelPredicate {
public:
    explicit ScopedCancelPredicate(std::function<bool()> predicate);
    ~ScopedCancelPredicate();
    ScopedCancelPredicate(const ScopedCancelPredicate&)            = delete;
    ScopedCancelPredicate& operator=(const ScopedCancelPredicate&) = delete;

private:
    std::function<bool()> previous_;
};

/// Programmatically request cancellation of the current CLI work, exactly as if
/// the user had pressed Ctrl+C. Sets the shared flag and fires listeners on the
/// false→true transition. Safe to call from any thread (e.g. an IPC accept
/// thread handling a `stop`/`cancel` action). Idempotent.
void request_cancel() noexcept;

/// For tests; production uses the OS signal/console handler.
void test_request_cancel();
void test_clear_cancel();

/// Yields the current thread — call before heavy work in tight loops so Ctrl+C
/// and the interrupt flag are observed without starving the system.
inline void yield_to_interrupt() noexcept
{
    std::this_thread::yield();
}

/// SetConsoleCtrlHandler (Win) and/or SIGINT (POSIX). Call once at process start.
void install_cli_interrupt_handlers() noexcept;

/// Register a callback fired (exactly once per cancel) by a watcher thread when
/// the cancel flag flips to true. Use to abort blocking subsystem work that does
/// not poll cancel_requested() itself (TTS playback, child processes, etc.).
/// Listeners are append-only and never removed; pass idempotent, no-op-safe fns.
/// Thread-safe; can be called before or after install_cli_interrupt_handlers().
void register_cancel_listener(std::function<void()> fn);

} // namespace media::cli
