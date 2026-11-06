#include "selection_run.hpp"

#include "commands/command_control.hpp"
#include "string/string_utils.hpp"
#include "commands/command_variables.hpp"
#include "process/process_runner.hpp"
#include "logging/pm_log.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace media::commands {

// ── helpers ───────────────────────────────────────────────────────────────────

// Convert cmd_run::RunOptions (wide strings) → process::RunOptions (UTF-8).
// Mirrors command_runner.cpp::Runner::start() but for the blocking sync path:
//   • bind_to_parent = false  — CLI / context-menu callers are short-lived
//     processes; the spawned child must outlive us.
//   • mode = Sync (or Async for new-console fire-and-forget spawns).
//   • on_cancel_check wired for the poll loop.
//
// Keep in sync with Runner::start() whenever cmd_run::RunOptions gains new fields.
static media::process::RunOptions to_process_opts(
    const media::cmd_run::RunOptions& r,
    std::function<bool()>             cancel_check)
{
    using media::process::narrow_utf8;
    media::process::RunOptions p;
    p.executable         = narrow_utf8(r.executable);
    p.args.reserve(r.args.size());
    for (const auto& a : r.args)
        p.args.push_back(narrow_utf8(a));
    p.cwd                = narrow_utf8(r.cwd);
    p.use_shell          = r.externalShellMode;
    p.shell_hint         = r.shellInterpreter.empty() ? std::string("pwsh") : r.shellInterpreter;
    p.shell_command      = narrow_utf8(r.shellLine);
    p.new_console_window = r.newConsoleWindow;
    p.close_on_exit      = r.closeOnExit;
    p.close_policy       = r.closePolicy;
    p.bind_to_parent     = false;
    p.on_cancel_check    = cancel_check;
    // Stamp the originating commands.json id, then forward any caller-supplied
    // extra vars (same order as Runner::start so env semantics are consistent).
    if (!r.commandId.empty())
        p.extra_env.emplace_back("PM_IMAGE_COMMAND_ID", r.commandId);
    for (const auto& [k, v] : r.extraEnv)
        p.extra_env.emplace_back(narrow_utf8(k), narrow_utf8(v));
    append_voice_utterance_env(p.extra_env);
    p.mode = r.newConsoleWindow ? media::process::RunMode::Async
                                : media::process::RunMode::Sync;
    return p;
}

// ── Sync (CLI dispatcher, context-menu short-lived process) ──────────────────

int run_selection_sync(const SelectionRunSpec& spec, std::function<bool()> cancel_check)
{
    if (spec.items.empty() || !spec.make_opts)
        return 0;

    int last_rc = 0;
    for (std::size_t i = 0; i < spec.items.size(); ++i) {
        if (cancel_check && cancel_check()) {
            logger::trace("[selection-run] sync cancelled before item " + std::to_string(i));
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Cancelled, 0);
            break;
        }

        auto item_opts = spec.make_opts(spec.items[i]);

        // Console path — delegate to the host-supplied launcher.
        if (item_opts.runInConsole && !item_opts.consoleCommandLine.empty()
            && spec.launch_console) {
            if (const std::string unresolved =
                    media::strutil::first_variable_token(item_opts.consoleCommandLine);
                !unresolved.empty()) {
                logger::warn("[selection-run] sync item " + std::to_string(i)
                             + " refused unresolved " + unresolved
                             + (spec.commandId.empty() ? "" : " (" + spec.commandId + ")"));
                if (spec.on_status)
                    spec.on_status(i, RunItemStatus::Failed, 0);
                last_rc = 1;
                if (!spec.continue_on_failure) break;
                continue;
            }
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Running, 0);
            const bool ok = spec.launch_console(item_opts.consoleCommandLine,
                                                 item_opts.closeOnExit,
                                                 [](int) {});
            if (spec.on_status)
                spec.on_status(i, ok ? RunItemStatus::Done : RunItemStatus::Failed, 0);
            if (!ok) {
                last_rc = 1;
                if (!spec.continue_on_failure) break;
            }
            continue;
        }

        // Choose the process options: direct UTF-8 (CLI path) or converted from
        // the wide-string runner opts (ribbon/launcher path).
        media::process::RunOptions proc_opts;
        if (item_opts.use_direct) {
            proc_opts = item_opts.direct;
            if (!proc_opts.on_cancel_check && cancel_check)
                proc_opts.on_cancel_check = cancel_check;
            if (proc_opts.executable.empty() && proc_opts.shell_command.empty()) {
                logger::trace("[selection-run] sync item " + std::to_string(i) + " skipped (no executable)");
                if (spec.on_status)
                    spec.on_status(i, RunItemStatus::Skipped, 0);
                continue;
            }
        } else {
            const auto& ro = item_opts.runner;
            if (ro.executable.empty() && ro.shellLine.empty()) {
                logger::trace("[selection-run] sync item " + std::to_string(i) + " skipped (no executable)");
                if (spec.on_status)
                    spec.on_status(i, RunItemStatus::Skipped, 0);
                continue;
            }
            if (const std::string deny = media::cmd_run::validate_expanded_command(ro); !deny.empty()) {
                logger::warn("[selection-run] sync item " + std::to_string(i)
                             + " refused by expanded-command validator: " + deny);
                if (spec.on_status)
                    spec.on_status(i, RunItemStatus::Failed, 0);
                last_rc = 1;
                if (!spec.continue_on_failure) break;
                continue;
            }
            proc_opts = to_process_opts(ro, cancel_check);
        }

        if (const std::string unresolved = media::strutil::unresolved_launch_token(
                proc_opts.executable, proc_opts.args, proc_opts.shell_command, proc_opts.cwd);
            !unresolved.empty()) {
            logger::warn("[selection-run] sync item " + std::to_string(i)
                         + " refused unresolved " + unresolved
                         + (spec.commandId.empty() ? "" : " (" + spec.commandId + ")"));
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Failed, 0);
            last_rc = 1;
            if (!spec.continue_on_failure) break;
            continue;
        }

        if (spec.on_status)
            spec.on_status(i, RunItemStatus::Running, 0);

        auto res = media::process::run(proc_opts);

        if (res.cancelled) {
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Cancelled, 0);
            last_rc = 130;
            break;
        }

        const bool ok = res.ok && res.exit_code == 0;
        if (spec.on_status)
            spec.on_status(i, ok ? RunItemStatus::Done : RunItemStatus::Failed, 0);

        if (!res.ok && !res.error.empty())
            logger::warn("[selection-run] sync item " + std::to_string(i) + ": " + res.error);

        if (!ok) {
            last_rc = res.exit_code != 0 ? res.exit_code : 1;
            if (!spec.continue_on_failure) break;
        }
    }
    return last_rc;
}

// ── Async (ribbon / launcher, must NOT be called on the UI thread) ────────────
//
// We keep a shared state block that outlives this call.  The Runner watcher
// thread drives the chain: Exited/Failed for item[i] → start item[i+1].
// The state is self-freeing (shared_ptr inside the sink lambda).

namespace {

struct AsyncState {
    SelectionRunSpec            spec;
    std::size_t                 next  = 0;  // index of the next item to start
    std::uint64_t               token = 0;  // Runner subscription token
    std::uint64_t               runId = 0;  // run id of the currently running item
    bool                        consoleActive = false;
    std::atomic<bool>           cancelled{false};
    std::atomic<bool>           paused{false};
    std::function<void()>       on_complete;
    std::mutex                  mu;

    void abandon_remaining(RunItemStatus status);
    void start_next(std::shared_ptr<AsyncState> self);
    void on_event(std::shared_ptr<AsyncState> self, const media::cmd_run::RunEvent& ev);
    void on_console_exit(std::shared_ptr<AsyncState> self, std::size_t idx, int code);
};

struct BatchRegistry {
    std::mutex mu;
    std::unordered_map<std::uint64_t, std::vector<std::weak_ptr<AsyncState>>> by_batch;
};

BatchRegistry& batch_registry()
{
    static BatchRegistry reg;
    return reg;
}

std::vector<std::shared_ptr<AsyncState>> live_batch_states(std::uint64_t batchId)
{
    std::vector<std::shared_ptr<AsyncState>> live;
    if (batchId == 0)
        return live;
    auto& reg = batch_registry();
    std::lock_guard<std::mutex> lk(reg.mu);
    auto it = reg.by_batch.find(batchId);
    if (it == reg.by_batch.end())
        return live;
    for (auto& w : it->second) {
        if (auto sp = w.lock())
            live.push_back(std::move(sp));
    }
    return live;
}

void register_batch_state(std::uint64_t batchId, const std::shared_ptr<AsyncState>& state)
{
    if (batchId == 0 || !state)
        return;
    auto& reg = batch_registry();
    std::lock_guard<std::mutex> lk(reg.mu);
    reg.by_batch[batchId].push_back(state);
}

void unregister_batch_state(std::uint64_t batchId, AsyncState* raw)
{
    if (batchId == 0 || !raw)
        return;
    auto& reg = batch_registry();
    std::lock_guard<std::mutex> lk(reg.mu);
    auto it = reg.by_batch.find(batchId);
    if (it == reg.by_batch.end())
        return;
    auto& vec = it->second;
    vec.erase(std::remove_if(vec.begin(), vec.end(),
                  [raw](const std::weak_ptr<AsyncState>& w) {
                      auto sp = w.lock();
                      return !sp || sp.get() == raw;
                  }),
              vec.end());
    if (vec.empty())
        reg.by_batch.erase(it);
}

void AsyncState::abandon_remaining(RunItemStatus status)
{
    while (next < spec.items.size()) {
        const std::size_t skip = next++;
        if (spec.on_status)
            spec.on_status(skip, status, 0);
    }
}

void AsyncState::start_next(std::shared_ptr<AsyncState> self)
{
    // Called with mu already locked by the event handler, or at construction.
    while (next < spec.items.size()) {
        if (cancelled.load(std::memory_order_acquire)) {
            abandon_remaining(RunItemStatus::Cancelled);
            break;
        }
        // Hold the chain: keep subscription alive; resume_selection_batch kicks us.
        if (paused.load(std::memory_order_acquire))
            return;
        const std::size_t i = next;
        auto item_opts = spec.make_opts(spec.items[i]);
        ++next;

        // Console path: wait for the PTY's real exit before moving on.
        // Runner never sees this child, so the ribbon/toggle hub needs an
        // explicit host-side registration (refcount + Started/Exited).
        if (item_opts.runInConsole && !item_opts.consoleCommandLine.empty()
            && spec.launch_console) {
            if (const std::string unresolved =
                    media::strutil::first_variable_token(item_opts.consoleCommandLine);
                !unresolved.empty()) {
                logger::warn("[selection-run] async item " + std::to_string(i)
                             + " refused unresolved " + unresolved
                             + (spec.commandId.empty() ? "" : " (" + spec.commandId + ")"));
                if (spec.on_status)
                    spec.on_status(i, RunItemStatus::Failed, 0);
                if (!spec.continue_on_failure) {
                    abandon_remaining(RunItemStatus::Skipped);
                    break;
                }
                continue;
            }
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Running, 0);
            consoleActive = true;
            if (!spec.commandId.empty()) {
                logger::trace("[selection-run] console begin id=" + spec.commandId
                    + " item=" + std::to_string(i));
                media::command_control::external_command_begin(
                    spec.commandId, {}, "[selection-run]");
            }
            const bool accepted = spec.launch_console(
                item_opts.consoleCommandLine, item_opts.closeOnExit,
                [self, i](int code) { self->on_console_exit(self, i, code); });
            if (accepted)
                return;
            consoleActive = false;
            if (!spec.commandId.empty()) {
                logger::warn("[selection-run] console rejected id=" + spec.commandId
                    + " item=" + std::to_string(i));
                media::command_control::external_command_end(
                    spec.commandId, /*failed=*/true, "[selection-run]");
            }
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Failed, 0);
            if (!spec.continue_on_failure) {
                abandon_remaining(RunItemStatus::Skipped);
                break;
            }
            continue;
        }

        const auto& ro = item_opts.runner;
        if (ro.executable.empty() && ro.shellLine.empty()) {
            logger::trace("[selection-run] async item " + std::to_string(i) + " skipped");
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Skipped, 0);
            continue;
        }
        if (const std::string unresolved = media::strutil::unresolved_launch_token(
                ro.executable, ro.args, ro.shellLine, ro.cwd);
            !unresolved.empty()) {
            logger::warn("[selection-run] async item " + std::to_string(i)
                         + " refused unresolved " + unresolved
                         + (spec.commandId.empty() ? "" : " (" + spec.commandId + ")"));
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Failed, 0);
            if (!spec.continue_on_failure) {
                abandon_remaining(RunItemStatus::Skipped);
                break;
            }
            continue;
        }

        runId = media::cmd_run::Runner::instance().start(ro);
        if (runId == 0) {
            logger::warn("[selection-run] async item " + std::to_string(i)
                         + " runner rejected (" + spec.commandId + ")");
            if (spec.on_status)
                spec.on_status(i, RunItemStatus::Failed, 0);
            if (!spec.continue_on_failure) {
                abandon_remaining(RunItemStatus::Skipped);
                break;
            }
            continue; // try next item immediately
        }
        // Runner accepted the run — notify with the real runId so callers
        // can register a queue row keyed on it before the Exited event fires.
        if (spec.on_status)
            spec.on_status(i, RunItemStatus::Running, runId);
        // Waiting for the Exited event to chain the next item.
        return;
    }

    // All items done — unsubscribe.
    if (token != 0) {
        media::cmd_run::Runner::instance().unsubscribe(token);
        token = 0;
    }
    unregister_batch_state(spec.batchId, this);
    auto done = std::move(on_complete);
    if (done)
        done();
}

void AsyncState::on_console_exit(
    std::shared_ptr<AsyncState> self, std::size_t idx, int code)
{
    std::lock_guard<std::mutex> lk(mu);
    if (!consoleActive)
        return;
    consoleActive = false;
    const unsigned code_u = static_cast<unsigned>(code);
    const bool cancelled = code == 130 || code_u == 0xC000013Au;
    const bool ok = code == 0;
    if (!spec.commandId.empty()) {
        logger::trace("[selection-run] console end id=" + spec.commandId
            + " item=" + std::to_string(idx)
            + " code=" + std::to_string(code));
        media::command_control::external_command_end(
            spec.commandId, /*failed=*/!ok, "[selection-run]");
    }
    if (spec.on_status) {
        const RunItemStatus status = ok ? RunItemStatus::Done
            : (cancelled ? RunItemStatus::Cancelled : RunItemStatus::Failed);
        spec.on_status(idx, status, 0);
    }
    if (!ok && !spec.continue_on_failure)
        abandon_remaining(RunItemStatus::Skipped);
    start_next(self);
}

void AsyncState::on_event(std::shared_ptr<AsyncState> self,
                           const media::cmd_run::RunEvent& ev)
{
    // Filter Started BEFORE locking: Runner::start delivers this event
    // synchronously on the same thread that holds mu inside start_next.
    // Locking here would cause std::system_error (recursive non-recursive mutex).
    // Running status is already reported with the real runId in start_next.
    if (ev.phase == media::cmd_run::RunPhase::Started)
        return;

    std::lock_guard<std::mutex> lk(mu);
    if (ev.runId != runId)
        return; // not our run

    // Exited or Failed
    const std::size_t finished_idx = next > 0 ? next - 1 : 0;
    RunItemStatus status = RunItemStatus::Failed;
    if (ev.phase == media::cmd_run::RunPhase::Cancelled)
        status = RunItemStatus::Cancelled;
    else if (ev.phase == media::cmd_run::RunPhase::Exited && ev.exitCode == 0)
        status = RunItemStatus::Done;
    const bool ok = status == RunItemStatus::Done;
    if (spec.on_status)
        spec.on_status(finished_idx, status, ev.runId);

    if (!ok && !spec.continue_on_failure)
        abandon_remaining(RunItemStatus::Skipped);

    runId = 0;
    start_next(self);
}

struct SequentialScheduler {
    std::mutex mutex;
    std::unordered_set<std::string> active;
    std::unordered_map<std::string, std::deque<SelectionRunSpec>> pending;
};

SequentialScheduler& sequential_scheduler()
{
    static SequentialScheduler scheduler;
    return scheduler;
}

void start_async_spec(const SelectionRunSpec& spec, std::function<void()> on_complete);

void finish_sequential_command(const std::string& command_id)
{
    SelectionRunSpec next;
    bool has_next = false;
    {
        auto& scheduler = sequential_scheduler();
        std::lock_guard<std::mutex> lk(scheduler.mutex);
        auto queue_it = scheduler.pending.find(command_id);
        if (queue_it != scheduler.pending.end() && !queue_it->second.empty()) {
            next = std::move(queue_it->second.front());
            queue_it->second.pop_front();
            has_next = true;
            if (queue_it->second.empty())
                scheduler.pending.erase(queue_it);
        } else {
            scheduler.active.erase(command_id);
        }
    }
    if (has_next) {
        start_async_spec(next, [command_id] {
            finish_sequential_command(command_id);
        });
    }
}

void start_async_spec(const SelectionRunSpec& spec, std::function<void()> on_complete)
{
    auto state = std::make_shared<AsyncState>();
    state->spec = spec;
    state->on_complete = std::move(on_complete);
    register_batch_state(spec.batchId, state);

    // Capture a STRONG ref in the subscription so AsyncState outlives
    // run_selection_async.  The local `state` variable goes out of scope when
    // this function returns, so without a strong ref in the subscription the
    // AsyncState would be destroyed before the Exited event fires and no
    // further items would ever chain.
    //
    // Self-freeing: when all items finish, start_next calls unsubscribe(token),
    // which removes the subscription lambda and releases the captured shared_ptr.
    // emit() takes a snapshot of sinks before calling them so unsubscribing from
    // inside the callback is safe (no deadlock, no use-after-free).
    state->token = media::cmd_run::Runner::instance().subscribe(
        [state](const media::cmd_run::RunEvent& ev) {
            state->on_event(state, ev);
        });

    std::lock_guard<std::mutex> lk(state->mu);
    state->start_next(state);
    // start_next returns immediately after Runner::start for item 0.
    // The subscription (strong ref) keeps state alive until all items complete.
}

} // namespace

void run_selection_async(const SelectionRunSpec& spec)
{
    if (spec.items.empty() || !spec.make_opts)
        return;

    if (!spec.sequential) {
        for (std::size_t i = 0; i < spec.items.size(); ++i) {
            SelectionRunSpec parallel = spec;
            parallel.items = {spec.items[i]};
            // Preserve batchId so cancel_selection_batch reaches every parallel child.
            // Remap on_status idx → original item index (each child sees idx=0).
            if (spec.on_status) {
                auto orig = spec.on_status;
                parallel.on_status = [orig, i](std::size_t, RunItemStatus status,
                                               std::uint64_t runId) {
                    orig(i, status, runId);
                };
            }
            start_async_spec(parallel, {});
        }
        return;
    }

    if (spec.commandId.empty()) {
        start_async_spec(spec, {});
        return;
    }

    bool start_now = false;
    {
        auto& scheduler = sequential_scheduler();
        std::lock_guard<std::mutex> lk(scheduler.mutex);
        start_now = scheduler.active.insert(spec.commandId).second;
        if (!start_now)
            scheduler.pending[spec.commandId].push_back(spec);
    }

    if (start_now) {
        const std::string command_id = spec.commandId;
        start_async_spec(spec, [command_id] {
            finish_sequential_command(command_id);
        });
    } else {
        logger::trace("[selection-run] queued sequential command " + spec.commandId);
    }
}

void cancel_selection_batch(std::uint64_t batchId)
{
    if (batchId == 0)
        return;

    // Drop not-yet-started sequential specs waiting on the same commandId.
    {
        auto& scheduler = sequential_scheduler();
        std::lock_guard<std::mutex> lk(scheduler.mutex);
        for (auto& [cmdId, queue] : scheduler.pending) {
            (void)cmdId;
            for (auto qit = queue.begin(); qit != queue.end();) {
                if (qit->batchId == batchId) {
                    SelectionRunSpec dropped = std::move(*qit);
                    qit = queue.erase(qit);
                    if (dropped.on_status) {
                        for (std::size_t i = 0; i < dropped.items.size(); ++i)
                            dropped.on_status(i, RunItemStatus::Cancelled, 0);
                    }
                } else {
                    ++qit;
                }
            }
        }
    }

    auto live = live_batch_states(batchId);
    for (auto& state : live) {
        state->cancelled.store(true, std::memory_order_release);
        state->paused.store(false, std::memory_order_release);
        std::uint64_t rid = 0;
        {
            std::lock_guard<std::mutex> lk(state->mu);
            rid = state->runId;
        }
        if (rid != 0)
            media::cmd_run::Runner::instance().cancel(rid);
        // Kick the chain so remaining Queued items get Cancelled status when
        // the current child is already finished / console-idle.
        std::lock_guard<std::mutex> lk(state->mu);
        if (state->runId == 0 && !state->consoleActive)
            state->start_next(state);
    }
}

void pause_selection_batch(std::uint64_t batchId)
{
    for (auto& state : live_batch_states(batchId))
        state->paused.store(true, std::memory_order_release);
}

void resume_selection_batch(std::uint64_t batchId)
{
    auto live = live_batch_states(batchId);
    for (auto& state : live) {
        state->paused.store(false, std::memory_order_release);
        std::lock_guard<std::mutex> lk(state->mu);
        if (state->runId == 0 && !state->consoleActive)
            state->start_next(state);
    }
}

bool is_selection_batch_paused(std::uint64_t batchId)
{
    auto live = live_batch_states(batchId);
    for (const auto& state : live) {
        if (state->paused.load(std::memory_order_acquire))
            return true;
    }
    return false;
}

} // namespace media::commands
