#include "command_runner.hpp"
#include "json/json_utils.hpp"
#include "fs/path_sanitizer.hpp"
#include "command_finish.hpp"
#include "command_variables.hpp"
#include "process/process_runner.hpp"
#include "string/string_utils.hpp"
#include "llm/tools/run/RunValidators.hpp"

#include <nlohmann/json.hpp>

#include "constants.hpp"
#include "logging/pm_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwctype>
#include <deque>
#include <filesystem>
#include <iterator>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

namespace media::cmd_run {

namespace {

struct FinishNotify {
    bool play_sound = false;
    bool notify_ui  = false;
    bool notify_tts = false;
    bool open_file = false;
    bool open_in_new_instance = false;
    bool child_reports = false;
    std::string label;
    std::string description;
};

struct Run {
    std::uint64_t runId = 0;
    unsigned      cmdId = 0;
    std::string   commandId;
    unsigned long pid   = 0;
    std::int64_t  startedUnixMs = 0;
    std::atomic<bool> terminated{false};
    std::atomic<bool> child_reported{false};
    FinishNotify finish;
    media::process::ClosePolicy closePolicy = media::process::ClosePolicy::Default;
};

bool args_look_like_xblox(const RunOptions& opt)
{
    for (const auto& a : opt.args) {
        if (a == L"xblox")
            return true;
    }
    return false;
}

bool looks_like_our_cli(const RunOptions& opt)
{
    if (opt.executable.empty())
        return false;
    try {
        std::wstring name = std::filesystem::path(opt.executable).filename().wstring();
        std::wstring want = pm::brand::k_exe_basename_cli_w;
        if (name.size() != want.size())
            return false;
        for (std::size_t i = 0; i < name.size(); ++i) {
            const auto a = static_cast<unsigned>(name[i]);
            const auto b = static_cast<unsigned>(want[i]);
            if (std::towlower(static_cast<std::wint_t>(a))
                != std::towlower(static_cast<std::wint_t>(b)))
                return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

FinishNotify resolve_run_finish(const RunOptions& opt)
{
    auto prefs = media::commands::resolve_finish_notify(opt.commandId);
    FinishNotify out;
    out.play_sound = prefs.play_sound;
    out.notify_ui  = prefs.notify_ui;
    out.notify_tts = prefs.notify_tts;
    out.open_file = prefs.open_file;
    out.open_in_new_instance = prefs.open_in_new_instance;
    out.label      = prefs.label;
    out.description = prefs.description;
    out.child_reports = args_look_like_xblox(opt) || looks_like_our_cli(opt);
    return out;
}

void stamp_run_notify_env(media::process::RunOptions& po, const FinishNotify& finish)
{
    po.extra_env.emplace_back("PM_IMAGE_NOTIFY_SOUND", finish.play_sound ? "1" : "0");
    po.extra_env.emplace_back("PM_IMAGE_NOTIFY_UI", finish.notify_ui ? "1" : "0");
    po.extra_env.emplace_back("PM_IMAGE_NOTIFY_TTS", finish.notify_tts ? "1" : "0");
    po.extra_env.emplace_back("PM_IMAGE_OPEN_FILE", finish.open_file ? "1" : "0");
    po.extra_env.emplace_back("PM_IMAGE_OPEN_IN_NEW_INSTANCE", finish.open_in_new_instance ? "1" : "0");
    media::commands::append_voice_utterance_env(po.extra_env);
}

void emit_command_finish(const Run& run, bool ok, unsigned long exit_code, const std::string& error)
{
    if (run.finish.child_reports)
        return;
    if (!run.finish.play_sound && !run.finish.notify_ui && !run.finish.notify_tts
        && !run.finish.open_file && !run.finish.open_in_new_instance)
        return;
    media::commands::CommandFinishEvent ev;
    ev.command_id  = run.commandId;
    ev.label       = run.finish.label;
    ev.description = run.finish.description;
    ev.ok          = ok;
    ev.exit_code   = static_cast<int>(exit_code);
    ev.error       = error;
    ev.play_sound  = run.finish.play_sound;
    ev.notify_ui   = run.finish.notify_ui;
    ev.notify_tts  = run.finish.notify_tts;
    ev.open_file   = run.finish.open_file;
    ev.open_in_new_instance = run.finish.open_in_new_instance;
    media::commands::notify_command_finished(ev);
}

struct PendingRun {
    std::uint64_t runId = 0;
    RunOptions    options;
    std::int64_t  startedUnixMs = 0;
};

struct ClosedRun {
    std::uint64_t runId = 0;
    unsigned      cmdId = 0;
    std::string   commandId;
    unsigned long pid   = 0;
    bool          child_reported = false;
};

struct State {
    std::mutex                                       mu;
    std::unordered_map<std::uint64_t, std::shared_ptr<Run>> runs;
    std::unordered_map<std::uint64_t, Sink>          sinks;
    std::unordered_set<std::string>                  sequentialActive;
    std::unordered_map<std::string, std::deque<PendingRun>> pending;
    std::deque<ClosedRun>                            closed;
    std::atomic<std::uint64_t>                       nextRunId{1};
    std::atomic<std::uint64_t>                       nextSinkToken{1};
};

State& state()
{
    static State s;
    return s;
}

void remember_closed_locked(const Run& run)
{
    ClosedRun closed;
    closed.runId          = run.runId;
    closed.cmdId          = run.cmdId;
    closed.commandId      = run.commandId;
    closed.pid            = run.pid;
    closed.child_reported = run.child_reported.load(std::memory_order_acquire);
    state().closed.push_back(std::move(closed));
    while (state().closed.size() > 32)
        state().closed.pop_front();
}

std::int64_t now_unix_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void emit(const RunEvent& ev)
{
    std::vector<Sink> snapshot;
    {
        std::scoped_lock lk(state().mu);
        snapshot.reserve(state().sinks.size());
        for (auto& [_, s] : state().sinks)
            snapshot.push_back(s);
    }
    for (auto& s : snapshot) {
        try { s(ev); }
        catch (const std::exception& e) {
            logger::warn(std::string("[cmd_run] sink threw: ") + e.what());
        } catch (...) {
            logger::warn("[cmd_run] sink threw non-std exception");
        }
    }
}

void emit_cancelled_pending(const PendingRun& pending)
{
    RunEvent ev{};
    ev.phase = RunPhase::Cancelled;
    ev.runId = pending.runId;
    ev.cmdId = pending.options.cmdId;
    ev.commandId = pending.options.commandId;
    ev.error = "cancelled before start";
    emit(ev);
}

std::uint64_t start_reserved(const RunOptions& opt, std::uint64_t run_id,
                             std::int64_t started_unix_ms);

void finish_sequential(const std::string& command_id)
{
    if (command_id.empty())
        return;
    PendingRun next;
    bool has_next = false;
    {
        std::scoped_lock lk(state().mu);
        auto pending_it = state().pending.find(command_id);
        if (pending_it != state().pending.end() && !pending_it->second.empty()) {
            next = std::move(pending_it->second.front());
            pending_it->second.pop_front();
            has_next = true;
            if (pending_it->second.empty())
                state().pending.erase(pending_it);
        } else {
            state().sequentialActive.erase(command_id);
        }
    }
    if (has_next)
        (void)start_reserved(next.options, next.runId, next.startedUnixMs);
}

std::uint64_t start_reserved(const RunOptions& opt, std::uint64_t run_id,
                             std::int64_t started_unix_ms)
{
    const bool sequential = opt.sequential && !opt.commandId.empty();
    media::process::RunOptions po;
    po.mode               = media::process::RunMode::Async;
    po.new_console_window = opt.newConsoleWindow;
    po.close_on_exit      = opt.closeOnExit;
    po.close_policy       = opt.closePolicy;
    po.command_id         = opt.commandId;
    po.cmd_id             = opt.cmdId;
    po.augment_path       = true;

#if defined(_WIN32)
    if (opt.externalShellMode && !opt.shellLine.empty()) {
        po.use_shell     = true;
        po.shell_hint    = opt.shellInterpreter.empty() ? std::string("pwsh") : opt.shellInterpreter;
        po.shell_command = media::process::narrow_utf8(opt.shellLine);
    } else if (!opt.executable.empty()) {
        po.executable = media::process::narrow_utf8(opt.executable);
        for (const auto& a : opt.args)
            po.args.push_back(media::process::narrow_utf8(a));
    } else {
        return 0;
    }
    if (!opt.cwd.empty())
        po.cwd = media::process::narrow_utf8(opt.cwd);
    for (const auto& [k, v] : opt.extraEnv) {
        po.extra_env.emplace_back(media::process::narrow_utf8(k),
                                  media::process::narrow_utf8(v));
    }
#else
    (void)opt;
    (void)run_id;
    (void)started_unix_ms;
    logger::warn("[cmd_run] start: non-Win32 platform, no spawn support");
    if (sequential)
        finish_sequential(opt.commandId);
    return 0;
#endif

    auto run = std::make_shared<Run>();
    run->runId     = run_id;
    run->cmdId     = opt.cmdId;
    run->commandId = opt.commandId;
    run->startedUnixMs = started_unix_ms;
    run->finish    = resolve_run_finish(opt);
    run->closePolicy = opt.closePolicy;
    stamp_run_notify_env(po, run->finish);

    std::weak_ptr<Run> weak_run = run;
    po.on_exit = [weak_run, sequential](
        std::uint64_t /*pr_run_id*/, unsigned long pid, int exit_code) {
        auto r = weak_run.lock();
        if (!r) return;
        const bool terminated = r->terminated.load(std::memory_order_acquire);
        if (terminated)
            r->child_reported.store(true, std::memory_order_release);
        const bool already = r->child_reported.load(std::memory_order_acquire);
        {
            std::scoped_lock lk(state().mu);
            state().runs.erase(r->runId);
            remember_closed_locked(*r);
        }
        RunEvent ev{};
        ev.runId     = r->runId;
        ev.cmdId     = r->cmdId;
        ev.commandId = r->commandId;
        ev.pid       = pid;
        if (terminated) {
            ev.phase = RunPhase::Cancelled;
            logger::info("[cmd_run] cancelled id=" + r->commandId
                + " exit=" + std::to_string(exit_code)
                + " pid=" + std::to_string(pid));
            emit(ev);
            if (sequential)
                finish_sequential(r->commandId);
            return;
        }
        ev.phase = RunPhase::Exited;
        if (already) {
            logger::info("[cmd_run] exited (already reported) id=" + r->commandId
                + " exit=" + std::to_string(exit_code)
                + " pid=" + std::to_string(pid));
            if (sequential)
                finish_sequential(r->commandId);
            return;
        }
        const bool ok = r->finish.child_reports
            ? media::commands::command_child_process_succeeded(exit_code)
            : media::commands::command_exit_succeeded(exit_code);
        ev.exitCode = ok ? 0ul : static_cast<unsigned long>(exit_code);
        logger::info("[cmd_run] exited id=" + r->commandId
            + " exit=" + std::to_string(exit_code)
            + " ok=" + std::string(ok ? "1" : "0")
            + " pid=" + std::to_string(pid));
        emit_command_finish(*r, ok, ev.exitCode, {});
        emit(ev);
        if (sequential)
            finish_sequential(r->commandId);
    };

    auto res = media::process::run(po);
    if (!res.ok) {
        RunEvent ev{};
        ev.phase     = RunPhase::Failed;
        ev.runId     = run->runId;
        ev.cmdId     = opt.cmdId;
        ev.commandId = opt.commandId;
        ev.error     = res.error;
        logger::warn("[cmd_run] ProcessRunner failed: " + opt.commandId + " " + res.error);
        emit_command_finish(*run, false, 0, res.error);
        emit(ev);
        if (sequential)
            finish_sequential(opt.commandId);
        return 0;
    }

    run->pid = static_cast<unsigned long>(res.pid);
    {
        std::scoped_lock lk(state().mu);
        state().runs.emplace(run->runId, run);
    }

    RunEvent ev{};
    ev.phase     = RunPhase::Started;
    ev.runId     = run->runId;
    ev.cmdId     = run->cmdId;
    ev.commandId = run->commandId;
    ev.pid       = run->pid;
    emit(ev);
    return run->runId;
}

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

Runner& Runner::instance() noexcept
{
    static Runner s_runner;
    return s_runner;
}

Runner::Runner()  = default;
Runner::~Runner() = default;

bool user_data_marks_agent_authored(const std::string& userDataJson)
{
    if (userDataJson.empty())
        return false;
    const auto ud = media::json::try_parse(userDataJson);
    return ud.is_object() && ud.value("createdBy", std::string{}) == "create_command";
}

std::string validate_expanded_command(const RunOptions& opt)
{
    if (!opt.validateExpanded)
        return {};
    std::string line;
    if (opt.externalShellMode) {
        line = media::process::narrow_utf8(opt.shellLine);
    } else {
        line = media::process::narrow_utf8(opt.executable);
        for (const auto& a : opt.args) {
            line += ' ';
            line += media::process::narrow_utf8(a);
        }
    }
    const auto vr = media::llm::run::validate_command(
        line, opt.externalShellMode ? opt.shellInterpreter : std::string{});
    if (vr.tier == media::llm::run::ValidationTier::Deny)
        return vr.reason;
    return {};
}

std::uint64_t Runner::start(const RunOptions& opt)
{
    if ((opt.externalShellMode && opt.shellLine.empty()) ||
        (!opt.externalShellMode && opt.executable.empty())) {
        logger::warn("[cmd_run] start rejected: empty executable and shellLine ("
                     + opt.commandId + ")");
        return 0;
    }
    if (const std::string unresolved = media::strutil::unresolved_launch_token(
            opt.executable, opt.args, opt.shellLine, opt.cwd);
        !unresolved.empty()) {
        logger::warn("[cmd_run] start refused: unresolved " + unresolved
                     + " (" + opt.commandId + ")");
        return 0;
    }
    if (const std::string deny = validate_expanded_command(opt); !deny.empty()) {
        logger::warn("[cmd_run] start refused by expanded-command validator ("
                     + opt.commandId + "): " + deny);
        return 0;
    }
    const std::uint64_t run_id =
        state().nextRunId.fetch_add(1, std::memory_order_relaxed);
    const std::int64_t started_unix_ms = now_unix_ms();
    if (opt.sequential && !opt.commandId.empty()) {
        std::scoped_lock lk(state().mu);
        if (!state().sequentialActive.insert(opt.commandId).second) {
            state().pending[opt.commandId].push_back(
                PendingRun{run_id, opt, started_unix_ms});
            logger::trace("[cmd_run] queued sequential id=" + opt.commandId
                          + " runId=" + std::to_string(run_id));
            return run_id;
        }
    }
    return start_reserved(opt, run_id, started_unix_ms);
}

bool Runner::cancel(std::uint64_t runId)
{
    PendingRun pending;
    bool pending_found = false;
    {
        std::scoped_lock lk(state().mu);
        for (auto pending_it = state().pending.begin();
             pending_it != state().pending.end() && !pending_found;) {
            auto& queue = pending_it->second;
            const auto it = std::find_if(
                queue.begin(), queue.end(),
                [runId](const PendingRun& item) { return item.runId == runId; });
            if (it != queue.end()) {
                pending = std::move(*it);
                queue.erase(it);
                pending_found = true;
            }
            if (queue.empty())
                pending_it = state().pending.erase(pending_it);
            else
                ++pending_it;
        }
    }
    if (pending_found) {
        emit_cancelled_pending(pending);
        return true;
    }

#if defined(_WIN32)
    std::shared_ptr<Run> run;
    {
        std::scoped_lock lk(state().mu);
        auto it = state().runs.find(runId);
        if (it == state().runs.end())
            return false;
        run = it->second;
    }
    if (run->pid == 0 || run->terminated.exchange(true))
        return false;
    media::process::terminate_process_tree(static_cast<DWORD>(run->pid));
    return true;
#else
    (void)runId;
    return false;
#endif
}

std::size_t Runner::cancel_by_cmd_id(unsigned cmdId)
{
    if (cmdId == 0) return 0;
    std::vector<std::uint64_t> ids;
    std::vector<PendingRun> pending;
    {
        std::scoped_lock lk(state().mu);
        for (auto& [rid, run] : state().runs) {
            if (run->cmdId == cmdId) ids.push_back(rid);
        }
        for (auto pending_it = state().pending.begin();
             pending_it != state().pending.end();) {
            auto& queue = pending_it->second;
            for (auto it = queue.begin(); it != queue.end();) {
                if (it->options.cmdId == cmdId) {
                    pending.push_back(std::move(*it));
                    it = queue.erase(it);
                } else {
                    ++it;
                }
            }
            if (queue.empty())
                pending_it = state().pending.erase(pending_it);
            else
                ++pending_it;
        }
    }
    std::size_t n = 0;
    for (auto rid : ids) if (cancel(rid)) ++n;
    for (const auto& item : pending) emit_cancelled_pending(item);
    return n + pending.size();
}

std::size_t Runner::cancel_by_command_id(const std::string& commandId)
{
    if (commandId.empty()) return 0;
    std::vector<std::uint64_t> ids;
    std::vector<PendingRun> pending;
    {
        std::scoped_lock lk(state().mu);
        for (auto& [rid, run] : state().runs) {
            if (run->commandId == commandId) ids.push_back(rid);
        }
        if (auto it = state().pending.find(commandId); it != state().pending.end()) {
            pending.assign(std::make_move_iterator(it->second.begin()),
                           std::make_move_iterator(it->second.end()));
            state().pending.erase(it);
        }
    }
    std::size_t n = 0;
    for (auto rid : ids) if (cancel(rid)) ++n;
    for (const auto& item : pending) emit_cancelled_pending(item);
    return n + pending.size();
}

std::size_t Runner::stop_by_command_id(const std::string& commandId,
                                       unsigned grace_ms)
{
    if (commandId.empty()) return 0;
    struct Tracked {
        std::uint64_t runId = 0;
        unsigned long pid   = 0;
    };
    std::vector<Tracked> tracked;
    {
        std::scoped_lock lk(state().mu);
        for (auto& [rid, run] : state().runs) {
            if (run->commandId == commandId && run->pid != 0)
                tracked.push_back(Tracked{rid, run->pid});
        }
    }
    if (tracked.empty()) return 0;

#if defined(_WIN32)
    const DWORD wait_ms = grace_ms;
    std::size_t killed = 0;
    for (const auto& t : tracked) {
        HANDLE h = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, static_cast<DWORD>(t.pid));
        if (!h) {
            // Process already gone or inaccessible — treat as exited.
            continue;
        }
        const DWORD wr = ::WaitForSingleObject(h, wait_ms);
        ::CloseHandle(h);
        if (wr == WAIT_OBJECT_0) {
            logger::info("[cmd_run] graceful exit after stop commandId=" +
                         commandId + " pid=" + std::to_string(t.pid));
            continue;
        }
        logger::warn("[cmd_run] grace elapsed (" + std::to_string(grace_ms) +
                     "ms); hard-kill commandId=" + commandId +
                     " pid=" + std::to_string(t.pid));
        if (cancel(t.runId)) ++killed;
    }
    return killed;
#else
    (void)grace_ms;
    std::size_t n = 0;
    for (const auto& t : tracked) if (cancel(t.runId)) ++n;
    return n;
#endif
}

std::size_t Runner::cancel_all()
{
    std::vector<std::uint64_t> ids;
    std::vector<PendingRun> pending;
    {
        std::scoped_lock lk(state().mu);
        ids.reserve(state().runs.size());
        for (auto& [rid, run] : state().runs) {
            // persist outlives the window. CloseWithOwner and the bind-to-parent
            // default are the runs WM_CLOSE is meant to stop.
            if (run->closePolicy == media::process::ClosePolicy::Persist) {
                logger::info("[cmd_run] leave running on shutdown id=" + run->commandId
                    + " pid=" + std::to_string(run->pid));
                continue;
            }
            ids.push_back(rid);
        }
        for (auto pending_it = state().pending.begin();
             pending_it != state().pending.end();) {
            auto& queue = pending_it->second;
            for (auto it = queue.begin(); it != queue.end();) {
                if (it->options.closePolicy == media::process::ClosePolicy::Persist) {
                    ++it;
                    continue;
                }
                pending.push_back(std::move(*it));
                it = queue.erase(it);
            }
            if (queue.empty())
                pending_it = state().pending.erase(pending_it);
            else
                ++pending_it;
        }
    }
    std::size_t n = 0;
    for (auto rid : ids) if (cancel(rid)) ++n;
    for (const auto& item : pending) emit_cancelled_pending(item);
    return n + pending.size();
}

bool Runner::is_running(unsigned cmdId) const
{
    if (cmdId == 0) return false;
    std::scoped_lock lk(state().mu);
    for (auto& [_, run] : state().runs)
        if (run->cmdId == cmdId) return true;
    for (const auto& [_, queue] : state().pending)
        for (const auto& item : queue)
            if (item.options.cmdId == cmdId) return true;
    return false;
}

bool Runner::is_running(const std::string& commandId) const
{
    if (commandId.empty()) return false;
    std::scoped_lock lk(state().mu);
    if (state().sequentialActive.count(commandId) != 0)
        return true;
    for (auto& [_, run] : state().runs)
        if (run->commandId == commandId) return true;
    return false;
}

std::size_t Runner::active_count() const
{
    std::scoped_lock lk(state().mu);
    std::size_t pending = 0;
    for (const auto& [_, queue] : state().pending)
        pending += queue.size();
    return state().runs.size() + pending;
}

std::vector<std::uint64_t> Runner::active_runs() const
{
    std::vector<std::uint64_t> out;
    std::scoped_lock lk(state().mu);
    std::size_t pending_count = 0;
    for (const auto& [_, queue] : state().pending)
        pending_count += queue.size();
    out.reserve(state().runs.size() + pending_count);
    for (auto& [rid, _] : state().runs) out.push_back(rid);
    for (const auto& [_, queue] : state().pending)
        for (const auto& item : queue) out.push_back(item.runId);
    return out;
}

ActiveRunSnapshot Runner::active_snapshot() const
{
    ActiveRunSnapshot out;
    out.capturedUnixMs = now_unix_ms();
    std::scoped_lock lk(state().mu);
    std::size_t pending_count = 0;
    for (const auto& [_, queue] : state().pending)
        pending_count += queue.size();
    out.rows.reserve(state().runs.size() + pending_count);
    for (const auto& [_, run] : state().runs) {
        out.rows.push_back(ActiveRunRow{
            run->runId,
            run->cmdId,
            run->commandId,
            run->pid,
            run->startedUnixMs,
        });
    }
    for (const auto& [_, queue] : state().pending) {
        for (const auto& item : queue) {
            out.rows.push_back(ActiveRunRow{
                item.runId,
                item.options.cmdId,
                item.options.commandId,
                0,
                item.startedUnixMs,
            });
        }
    }
    std::sort(out.rows.begin(), out.rows.end(),
              [](const ActiveRunRow& a, const ActiveRunRow& b) {
                  return a.runId < b.runId;
              });
    return out;
}

void Runner::apply_reported_exit(const std::string& commandId, bool ok, int exit_code)
{
    if (commandId.empty())
        return;
    std::vector<std::shared_ptr<Run>> hits;
    {
        std::scoped_lock lk(state().mu);
        for (auto& [_, run] : state().runs) {
            if (run->commandId != commandId)
                continue;
            if (run->child_reported.exchange(true, std::memory_order_acq_rel))
                continue;
            hits.push_back(run);
        }
    }
    if (hits.empty()) {
        ClosedRun late{};
        bool found = false;
        {
            std::scoped_lock lk(state().mu);
            for (auto it = state().closed.rbegin(); it != state().closed.rend(); ++it) {
                if (it->commandId != commandId || it->child_reported)
                    continue;
                it->child_reported = true;
                late = *it;
                found = true;
                break;
            }
        }
        if (!found) {
            logger::debug("[cmd_run] reported exit ignored id=" + commandId
                + " ok=" + std::string(ok ? "1" : "0")
                + " exit=" + std::to_string(exit_code));
            return;
        }
        const unsigned long reported = ok ? 0ul
            : static_cast<unsigned long>(exit_code == 0 ? 1 : exit_code);
        logger::info("[cmd_run] late child report id=" + commandId
            + " ok=" + std::string(ok ? "1" : "0")
            + " exit=" + std::to_string(exit_code)
            + " runId=" + std::to_string(late.runId));
        RunEvent ev{};
        ev.phase     = RunPhase::Exited;
        ev.runId     = late.runId;
        ev.cmdId     = late.cmdId;
        ev.commandId = late.commandId;
        ev.pid       = late.pid;
        ev.exitCode  = reported;
        emit(ev);
        return;
    }
    const unsigned long reported = ok ? 0ul
        : static_cast<unsigned long>(exit_code == 0 ? 1 : exit_code);
    for (const auto& r : hits) {
        logger::info("[cmd_run] child reported id=" + commandId
            + " ok=" + std::string(ok ? "1" : "0")
            + " exit=" + std::to_string(exit_code)
            + " runId=" + std::to_string(r->runId));
        emit_command_finish(*r, ok, reported, {});
        RunEvent ev{};
        ev.phase     = RunPhase::Exited;
        ev.runId     = r->runId;
        ev.cmdId     = r->cmdId;
        ev.commandId = r->commandId;
        ev.pid       = r->pid;
        ev.exitCode  = reported;
        emit(ev);
    }
}

std::uint64_t Runner::subscribe(Sink sink)
{
    if (!sink) return 0;
    const std::uint64_t tok = state().nextSinkToken.fetch_add(1, std::memory_order_relaxed);
    std::scoped_lock lk(state().mu);
    state().sinks.emplace(tok, std::move(sink));
    return tok;
}

void Runner::unsubscribe(std::uint64_t token)
{
    if (token == 0) return;
    std::scoped_lock lk(state().mu);
    state().sinks.erase(token);
}

} // namespace media::cmd_run
