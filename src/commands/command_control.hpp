#pragma once

#include "command_runner.hpp"

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace media::command_control {

struct StopResult {
    bool        ipc_stopped = false;
    std::size_t runner_cancelled = 0;
    bool        external_cancelled = false;

    bool stopped() const noexcept { return ipc_stopped || runner_cancelled > 0 || external_cancelled; }
};

bool is_command_running(const std::string& commandId);
StopResult stop_command_by_id(const std::string& commandId, const std::string& logPrefix = {});
void stop_command_by_id_async(std::string commandId, std::string logPrefix = {});

struct StateEvent {
    enum class Phase { Started, Exited, Failed };
    Phase       phase = Phase::Started;
    std::string commandId;
    bool        running = false;
};

using StateSink = std::function<void(const StateEvent&)>;

std::uint64_t subscribe_state(StateSink sink);
void          unsubscribe_state(std::uint64_t token);

/// Publish lifecycle for commands that do not run through cmd_run::Runner
/// (for example mmap/session-backed app commands). Runner-backed commands emit
/// their own lifecycle and should not call these helpers.
void notify_command_started(const std::string& commandId, const std::string& logPrefix = {});
void notify_command_exited(const std::string& commandId, const std::string& logPrefix = {});
void notify_command_failed(const std::string& commandId, const std::string& logPrefix = {});

/// Register a command that runs inside a self-managed engine (one that does not
/// use cmd_run::Runner or cmd_ipc, e.g. the xblox block runtime) so the rest of
/// the hub can see and stop it. Reference-counted per id: lifecycle is emitted on
/// the 0<->1 transitions (Started on begin, Exited/Failed on the matching end),
/// is_command_running() reports the id active while the count is positive, and
/// stop_command_by_id() invokes the supplied cancel. The cancel is best-effort
/// and may be coarser than a single command (an engine may only be able to
/// cancel its whole run); the engine is expected to call external_command_end()
/// when the run unwinds. Calls must be balanced.
void external_command_begin(const std::string& commandId, std::function<void()> cancel, const std::string& logPrefix = {});
void external_command_end(const std::string& commandId, bool failed = false, const std::string& logPrefix = {});
/// Best-effort cancel of every engine-managed command (voice listen, in-process
/// xblox, ...). Copies callbacks under the lock, then invokes them outside it.
/// Engines still call `external_command_end()` as they unwind.
void stop_all_external(const std::string& logPrefix = {});

struct ExternalActivityRow {
    std::string commandId;
    std::size_t count = 0;
    bool        cancellable = false;
};

/// Secret-free view of a live run-IPC descriptor plus its advertised run IDs.
/// runIdsError is populated when the descriptor was discoverable but its
/// read-only run_ids action could not be queried.
struct RunIpcActivityRow {
    std::string                id;
    std::string                kind;
    std::int64_t               pid = 0;
    std::string                cwd;
    std::string                endpoint;
    std::string                transport;
    std::int64_t               startedUnixMs = 0;
    std::string                label;
    std::string                cmdline;
    std::string                commandId;
    std::vector<std::uint64_t> runIds;
    std::string                runIdsError;
};

struct ActivitySnapshot {
    std::int64_t                    capturedUnixMs = 0;
    std::vector<cmd_run::ActiveRunRow> runner;
    std::vector<ExternalActivityRow> external;
    std::vector<RunIpcActivityRow>   runIpc;
};

/// Return a point-in-time, read-only view of all shared command activity known
/// to this process. With FEATURE_COMMAND_IPC_NEXT disabled, runIpc is empty.
ActivitySnapshot activity_snapshot();

} // namespace media::command_control
