#include "installer/journal/journal.hpp"

#include <filesystem>
#include <fstream>
#include <picosha2.h>

namespace pm::installer {

namespace fs = std::filesystem;

const char* journal_status_token(PackageJournalStatus s) noexcept
{
    switch (s) {
    case PackageJournalStatus::Pending:           return "pending";
    case PackageJournalStatus::Running:           return "running";
    case PackageJournalStatus::Done:              return "done";
    case PackageJournalStatus::FailedTransient:    return "failed_transient";
    case PackageJournalStatus::FailedPermanent:   return "failed_permanent";
    case PackageJournalStatus::Parked:            return "parked";
    case PackageJournalStatus::Skipped:           return "skipped";
    }
    return "pending";
}

PackageJournalStatus status_from_token(std::string_view token)
{
    if (token == "done")               return PackageJournalStatus::Done;
    if (token == "running")            return PackageJournalStatus::Running;
    if (token == "failed_transient")   return PackageJournalStatus::FailedTransient;
    if (token == "failed_permanent")   return PackageJournalStatus::FailedPermanent;
    if (token == "parked")             return PackageJournalStatus::Parked;
    if (token == "skipped")            return PackageJournalStatus::Skipped;
    return PackageJournalStatus::Pending;
}

bool journal_should_skip(PackageJournalStatus status, bool resume, bool force_retry_permanent)
{
    if (!resume)
        return false;
    if (status == PackageJournalStatus::Done)
        return true;
    if (status == PackageJournalStatus::FailedPermanent && !force_retry_permanent)
        return true;
    return false;
}

static nlohmann::json manifest_to_canonical_json(const Manifest& manifest)
{
    nlohmann::json pkgs = nlohmann::json::array();
    for (const auto& p : manifest.packages) {
        pkgs.push_back({
            {"id", p.id},
            {"type", p.type},
            {"verb", effective_verb(p)},
            {"on_exist", static_cast<int>(p.on_exist)},
        });
    }
    return {{"version", manifest.version}, {"packages", std::move(pkgs)}};
}

std::string manifest_content_hash(const Manifest& manifest)
{
    const std::string canonical = manifest_to_canonical_json(manifest).dump();
    return picosha2::hash256_hex_string(canonical);
}

static fs::path journal_state_path(const std::string& journal_dir, const std::string& hash)
{
    return fs::path(journal_dir) / (hash + ".json");
}

static fs::path journal_log_path(const std::string& journal_dir, const std::string& hash)
{
    return fs::path(journal_dir) / (hash + ".jsonl");
}

std::optional<JournalState> load_journal(const std::string& journal_dir,
                                         const std::string& manifest_hash)
{
    if (journal_dir.empty())
        return std::nullopt;
    const fs::path path = journal_state_path(journal_dir, manifest_hash);
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return std::nullopt;
    try {
        const auto j = nlohmann::json::parse(in);
        JournalState st;
        st.manifest_hash = j.value("manifest_hash", manifest_hash);
        st.manifest_path = j.value("manifest_path", std::string{});
        if (j.contains("packages") && j["packages"].is_object())
            st.packages = j["packages"];
        return st;
    } catch (...) {
        return std::nullopt;
    }
}

bool save_journal(const std::string& journal_dir, const JournalState& state, std::string& err)
{
    err.clear();
    if (journal_dir.empty())
        return true;
    std::error_code ec;
    fs::create_directories(journal_dir, ec);
    const fs::path final_path = journal_state_path(journal_dir, state.manifest_hash);
    const fs::path tmp_path   = final_path.string() + ".part";
    nlohmann::json j = {
        {"manifest_hash", state.manifest_hash},
        {"manifest_path", state.manifest_path},
        {"packages", state.packages},
    };
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "journal write failed: " + tmp_path.string();
            return false;
        }
        out << j.dump(2);
    }
    fs::rename(tmp_path, final_path, ec);
    if (ec) {
        err = "journal rename failed: " + ec.message();
        fs::remove(tmp_path, ec);
        return false;
    }
    return true;
}

void append_journal_event(const std::string& journal_dir,
                          const std::string& manifest_hash,
                          const nlohmann::json& event)
{
    if (journal_dir.empty())
        return;
    std::error_code ec;
    fs::create_directories(journal_dir, ec);
    std::ofstream out(journal_log_path(journal_dir, manifest_hash),
                      std::ios::binary | std::ios::app);
    if (!out)
        return;
    out << event.dump() << '\n';
}

} // namespace pm::installer
