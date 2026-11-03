#include "installer/events.hpp"

namespace pm::installer {

const char* error_class_token(ErrorClass c) noexcept
{
    switch (c) {
    case ErrorClass::Transient: return "transient";
    case ErrorClass::Permanent: return "permanent";
    case ErrorClass::None:      break;
    }
    return "";
}

nlohmann::json PackageResult::to_json() const
{
    nlohmann::json j = {
        {"id", id},
        {"verb", verb},
        {"ok", ok},
        {"files_copied", files_copied},
        {"files_skipped", files_skipped},
        {"bytes_written", bytes_written},
        {"duration_ms", duration_ms},
    };
    if (!error.empty())
        j["error"] = error;
    if (error_class != ErrorClass::None)
        j["error_class"] = error_class_token(error_class);
    if (!skip_reason.empty())
        j["skip_reason"] = skip_reason;
    if (verb == "shell") {
        j["exit_code"] = exit_code;
        if (!stdout_text.empty())
            j["stdout"] = stdout_text;
        if (!stderr_text.empty())
            j["stderr"] = stderr_text;
        if (timed_out)
            j["timed_out"] = true;
        if (cancelled)
            j["cancelled"] = true;
    }
    return j;
}

nlohmann::json ManifestResult::to_json() const
{
    nlohmann::json pkgs = nlohmann::json::array();
    for (const auto& p : packages)
        pkgs.push_back(p.to_json());
    return {
        {"ok", ok},
        {"cancelled", cancelled},
        {"timed_out", timed_out},
        {"total_copied", total_copied},
        {"total_skipped", total_skipped},
        {"packages", std::move(pkgs)},
    };
}

} // namespace pm::installer
