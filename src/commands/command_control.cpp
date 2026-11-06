#include "command_control.hpp"

#include "command_runner.hpp"
#include "logger/logger.h"
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
#include "cmd_ipc.hpp"
#include <nlohmann/json.hpp>
#endif

#include <atomic>
#include <algorithm>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace media::command_control {

namespace {

std::mutex& state_sink_mutex()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::uint64_t, StateSink>& state_sinks()
{
    static std::unordered_map<std::uint64_t, StateSink> sinks;
    return sinks;
}

std::atomic<std::uint64_t> g_state_sink_counter{0};

struct ExternalEntry {
    int                   count = 0;
    std::function<void()> cancel;
};

std::mutex& external_mutex()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, ExternalEntry>& external_commands()
{
    static std::unordered_map<std::string, ExternalEntry> entries;
    return entries;
}

bool external_command_active(const std::string& commandId)
{
    std::scoped_lock lk(external_mutex());
    auto it = external_commands().find(commandId);
    return it != external_commands().end() && it->second.count > 0;
}

void emit_state(const StateEvent& ev)
{
    std::vector<StateSink> sinks;
    {
        std::scoped_lock lk(state_sink_mutex());
        sinks.reserve(state_sinks().size());
        for (const auto& [_, sink] : state_sinks())
            sinks.push_back(sink);
    }
    const char* phase = "started";
    switch (ev.phase) {
        case StateEvent::Phase::Started: phase = "started"; break;
        case StateEvent::Phase::Exited:  phase = "exited"; break;
        case StateEvent::Phase::Failed:  phase = "failed"; break;
    }
    logger::info("[command-control] emit phase=" + std::string(phase)
        + " id=" + ev.commandId
        + " running=" + std::string(ev.running ? "1" : "0")
        + " sinks=" + std::to_string(sinks.size()));
    for (const auto& sink : sinks) {
        if (!sink)
            continue;
        try {
            sink(ev);
        } catch (...) {
            // State-event subscribers are diagnostic/fanout surfaces; a bad
            // listener must not break command stop handling.
        }
    }
}

} // namespace

void notify_command_started(const std::string& commandId, const std::string& logPrefix)
{
    if (commandId.empty())
        return;
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;
    logger::trace(prefix + " state started id=" + commandId);
    emit_state(StateEvent{
        StateEvent::Phase::Started,
        commandId,
        true,
    });
}

void notify_command_exited(const std::string& commandId, const std::string& logPrefix)
{
    if (commandId.empty())
        return;
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;
    logger::trace(prefix + " state exited id=" + commandId);
    emit_state(StateEvent{
        StateEvent::Phase::Exited,
        commandId,
        false,
    });
}

void notify_command_failed(const std::string& commandId, const std::string& logPrefix)
{
    if (commandId.empty())
        return;
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;
    logger::trace(prefix + " state failed id=" + commandId);
    emit_state(StateEvent{
        StateEvent::Phase::Failed,
        commandId,
        false,
    });
}

void external_command_begin(const std::string& commandId, std::function<void()> cancel, const std::string& logPrefix)
{
    if (commandId.empty())
        return;
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;

    bool first = false;
    {
        std::scoped_lock lk(external_mutex());
        auto& entry = external_commands()[commandId];
        entry.cancel = std::move(cancel);
        first = (++entry.count == 1);
    }
    logger::info(prefix + " external begin id=" + commandId + (first ? " (started)" : " (nested)"));
    if (first)
        notify_command_started(commandId, prefix);
}

void external_command_end(const std::string& commandId, bool failed, const std::string& logPrefix)
{
    if (commandId.empty())
        return;
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;

    bool last = false;
    bool found = false;
    {
        std::scoped_lock lk(external_mutex());
        auto it = external_commands().find(commandId);
        if (it != external_commands().end()) {
            found = true;
            if (--it->second.count <= 0) {
                external_commands().erase(it);
                last = true;
            }
        }
    }
    if (!found) {
        // Console PTY completion can land after IPC/stop already cleared the
        // host-side registration. That is expected, not a leak.
        logger::info(prefix + " external end without begin id=" + commandId);
        return;
    }
    logger::info(prefix + " external end id=" + commandId + (last ? " (stopped)" : " (nested)"));
    if (last) {
        if (failed)
            notify_command_failed(commandId, prefix);
        else
            notify_command_exited(commandId, prefix);
    }
}

ActivitySnapshot activity_snapshot()
{
    ActivitySnapshot out;
    auto runner = media::cmd_run::Runner::instance().active_snapshot();
    out.capturedUnixMs = runner.capturedUnixMs;
    out.runner = std::move(runner.rows);

    {
        std::scoped_lock lk(external_mutex());
        out.external.reserve(external_commands().size());
        for (const auto& [command_id, entry] : external_commands()) {
            if (entry.count <= 0)
                continue;
            out.external.push_back(ExternalActivityRow{
                command_id,
                static_cast<std::size_t>(entry.count),
                static_cast<bool>(entry.cancel),
            });
        }
    }
    std::sort(out.external.begin(), out.external.end(),
              [](const ExternalActivityRow& a, const ExternalActivityRow& b) {
                  return a.commandId < b.commandId;
              });

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    for (const auto& descriptor : media::cmd_ipc::list_instances()) {
        RunIpcActivityRow row;
        row.id = descriptor.id;
        row.kind = media::cmd_ipc::kind_str(descriptor.kind);
        row.pid = descriptor.pid;
        row.cwd = descriptor.cwd;
        row.endpoint = descriptor.endpoint;
        row.transport = descriptor.transport;
        row.startedUnixMs = descriptor.started_unix_ms;
        row.label = descriptor.label;
        row.cmdline = descriptor.cmdline;
        row.commandId = descriptor.command_id;

        nlohmann::json reply;
        std::string err;
        if (media::cmd_ipc::send_action(
                descriptor, "run_ids", {}, reply, err, 500)) {
            if (reply.value("type", std::string{}) == "error") {
                row.runIdsError =
                    reply.value("error", std::string{"run_ids failed"});
            } else if (const auto ids = reply.find("ids");
                       ids != reply.end() && ids->is_array()) {
                for (const auto& value : *ids) {
                    if (value.is_number_unsigned()) {
                        row.runIds.push_back(value.get<std::uint64_t>());
                    } else if (value.is_number_integer()) {
                        const auto id = value.get<std::int64_t>();
                        if (id > 0)
                            row.runIds.push_back(static_cast<std::uint64_t>(id));
                    }
                }
            } else {
                row.runIdsError = "run_ids reply missing ids";
            }
        } else {
            row.runIdsError = err.empty() ? "run_ids failed" : std::move(err);
        }
        std::sort(row.runIds.begin(), row.runIds.end());
        out.runIpc.push_back(std::move(row));
    }
    std::sort(out.runIpc.begin(), out.runIpc.end(),
              [](const RunIpcActivityRow& a, const RunIpcActivityRow& b) {
                  return a.id < b.id;
              });
#endif

    return out;
}

bool is_command_running(const std::string& commandId)
{
    if (commandId.empty())
        return false;

    if (media::cmd_run::Runner::instance().is_running(commandId)) {
        return true;
    }

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.command_id == commandId) {
            return true;
        }
    }
#endif

    if (external_command_active(commandId)) {
        return true;
    }

    return false;
}

StopResult stop_command_by_id(const std::string& commandId, const std::string& logPrefix)
{
    StopResult result{};
    if (commandId.empty())
        return result;

    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;
    logger::info(prefix + " stop begin id=" + commandId);

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    for (const auto& inst : media::cmd_ipc::list_instances()) {
        if (inst.command_id != commandId)
            continue;

        nlohmann::json reply;
        std::string    err;
        if (media::cmd_ipc::send_action(inst, "stop", {}, reply, err, 2000)) {
            result.ipc_stopped = true;
            logger::trace(prefix + " ipc stop sent id=" + commandId + " -> " + inst.id);
        } else {
            logger::warn(prefix + " ipc stop failed id=" + commandId + " -> " + inst.id + ": " + err);
        }
    }
#endif

    // IPC ack only means cancel was requested. MF video Finalize (and similar
    // teardown) needs wall time — wait for a graceful exit before hard-kill.
    // Without this, short recordings often leave a ~80-byte MP4 with no moov.
    if (result.ipc_stopped) {
        result.runner_cancelled =
            media::cmd_run::Runner::instance().stop_by_command_id(commandId, 8000);
        logger::warn(prefix + " runner stop-after-ipc id=" + commandId +
                     " hard_killed=" + std::to_string(result.runner_cancelled));
    } else {
        result.runner_cancelled =
            media::cmd_run::Runner::instance().cancel_by_command_id(commandId);
        logger::trace(prefix + " runner cancel id=" + commandId +
                      " terminated=" + std::to_string(result.runner_cancelled));
    }

    // Fall through to engine-managed (xblox etc.) commands when Runner/IPC had
    // nothing to cancel. The engine signals its own Exited via
    // external_command_end as the run unwinds, so we must not emit it here.
    if (!result.ipc_stopped && result.runner_cancelled == 0) {
        std::function<void()> cancel;
        {
            std::scoped_lock lk(external_mutex());
            auto it = external_commands().find(commandId);
            if (it != external_commands().end())
                cancel = it->second.cancel;
        }
        if (cancel) {
            logger::info(prefix + " external cancel id=" + commandId);
            try {
                cancel();
            } catch (...) {
                // Best-effort: a faulty cancel must not break stop handling.
            }
            result.external_cancelled = true;
        }
    }

    if (result.ipc_stopped || result.runner_cancelled > 0) {
        // Drop any host-side console/external registration so
        // is_command_running() matches the Exited we just published. The
        // PTY completion callback may still call external_command_end().
        {
            std::scoped_lock lk(external_mutex());
            if (external_commands().erase(commandId) > 0)
                logger::info(prefix + " external forget after stop id=" + commandId);
        }
        notify_command_exited(commandId, prefix);
    } else if (result.external_cancelled) {
        logger::info(prefix + " external stop requested id=" + commandId);
    } else {
        logger::info(prefix + " stop no-op id=" + commandId);
    }

    return result;
}

void stop_all_external(const std::string& logPrefix)
{
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;
    std::vector<std::pair<std::string, std::function<void()>>> cancels;
    {
        std::scoped_lock lk(external_mutex());
        cancels.reserve(external_commands().size());
        for (auto& [id, entry] : external_commands()) {
            if (entry.cancel)
                cancels.emplace_back(id, entry.cancel);
        }
    }
    logger::info(prefix + " stop-all-external count=" + std::to_string(cancels.size()));
    for (auto& [id, cancel] : cancels) {
        logger::info(prefix + " external cancel id=" + id);
        try {
            cancel();
        } catch (...) {
        }
    }
}

void stop_command_by_id_async(std::string commandId, std::string logPrefix)
{
    if (commandId.empty())
        return;
    const std::string prefix = logPrefix.empty() ? std::string{"[command-control]"} : logPrefix;
    logger::info(prefix + " stop async queued id=" + commandId);
    std::thread([id = std::move(commandId), prefix = std::move(logPrefix)]() {
        (void)stop_command_by_id(id, prefix);
    }).detach();
}

std::uint64_t subscribe_state(StateSink sink)
{
    const std::uint64_t token = ++g_state_sink_counter;
    std::scoped_lock lk(state_sink_mutex());
    state_sinks()[token] = std::move(sink);
    logger::trace("[command-control] subscribe state token=" + std::to_string(token)
        + " sinks=" + std::to_string(state_sinks().size()));
    return token;
}

void unsubscribe_state(std::uint64_t token)
{
    if (token == 0)
        return;
    std::scoped_lock lk(state_sink_mutex());
    state_sinks().erase(token);
    logger::trace("[command-control] unsubscribe state token=" + std::to_string(token)
        + " sinks=" + std::to_string(state_sinks().size()));
}

} // namespace media::command_control
