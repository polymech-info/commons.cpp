#pragma once
// installer/journal/journal.hpp — run sidecar for resumable installs.

#include "installer/events.hpp"
#include "installer/manifest.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace pm::installer {

enum class PackageJournalStatus {
    Pending,
    Running,
    Done,
    FailedTransient,
    FailedPermanent,
    Parked,
    Skipped,
};

const char* journal_status_token(PackageJournalStatus s) noexcept;

struct JournalState {
    std::string manifest_hash;
    std::string manifest_path;
    nlohmann::json packages = nlohmann::json::object(); // id → {status, verb, attempts, error, …}
};

// SHA-256 hex over canonical manifest JSON (sorted keys, no whitespace).
std::string manifest_content_hash(const Manifest& manifest);

// Load journal state from `<journal_dir>/<hash>.json`.  Returns empty optional
// when absent or corrupt.
std::optional<JournalState> load_journal(const std::string& journal_dir,
                                           const std::string& manifest_hash);

// Persist journal state atomically (write temp + rename).
bool save_journal(const std::string& journal_dir, const JournalState& state, std::string& err);

// Append one JSON line to `<journal_dir>/<hash>.jsonl`.
void append_journal_event(const std::string& journal_dir,
                          const std::string& manifest_hash,
                          const nlohmann::json& event);

PackageJournalStatus status_from_token(std::string_view token);

bool journal_should_skip(PackageJournalStatus status, bool resume, bool force_retry_permanent);

} // namespace pm::installer
