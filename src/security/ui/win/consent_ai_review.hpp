#pragma once
//
// pm::security::ui — convert a SecurityAgent review JSON (the schema produced by
// media::llm::agent::security_review) into the dialog-facing AiConsentReview
// struct. Kept out of ConsentDlg.hpp so that header stays free of nlohmann/json;
// hosts (pm-image-security authorize, the agent CLI --consent-ui win32) include
// this to wire ConsentUiOptions::runAiReview.
//
// Windows-only (mirrors ConsentDlg): the consent dialog only exists on Win32.
//

#include "security/ui/win/ConsentDlg.hpp"
#include "security/types.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace pm::security::ui {

inline Risk parse_risk_token(const std::string& s, Risk fallback = Risk::Medium) {
    if (s == "low")      return Risk::Low;
    if (s == "medium")   return Risk::Medium;
    if (s == "high")     return Risk::High;
    if (s == "critical") return Risk::Critical;
    return fallback;
}

inline GrantLifetime parse_lifetime_token(const std::string& s, GrantLifetime fallback = GrantLifetime::Once) {
    if (s == "once")            return GrantLifetime::Once;
    if (s == "session")         return GrantLifetime::Session;
    if (s == "task")            return GrantLifetime::Task;
    if (s == "permanent")       return GrantLifetime::Permanent;
    if (s == "until_timestamp") return GrantLifetime::UntilTimestamp;
    return fallback;
}

/// Build an AiConsentReview from the normalized review JSON. @p ok reflects
/// media::llm::agent::security_review::ReviewResult::ok; @p error_msg carries
/// the failure text when !ok.
inline AiConsentReview ai_review_from_json(const nlohmann::json& review,
                                           bool ok,
                                           const std::string& error_msg = {}) {
    AiConsentReview r;
    r.ok    = ok;
    r.error = !ok;

    if (!ok) {
        r.reason = error_msg.empty()
            ? std::string("AI security review failed; human approval remains required.")
            : error_msg;
        // Still surface any partial fields the reviewer returned.
    }

    if (review.is_object()) {
        r.assessedRisk = parse_risk_token(review.value("assessedRisk", std::string{}), Risk::Medium);
        r.riskRaised   = review.value("riskRaised", false);

        if (r.reason.empty())
            r.reason = review.value("reason", std::string{});

        if (review.contains("notes") && review["notes"].is_array()) {
            for (const auto& n : review["notes"])
                if (n.is_string()) r.notes.push_back(n.get<std::string>());
        }

        nlohmann::json rec = review.value("recommendation", nlohmann::json::object());
        if (!rec.is_object()) rec = nlohmann::json::object();
        r.decision = rec.value("decision", review.value("decision", std::string{}));
        const std::string lt = rec.value("lifetime", std::string{});
        if (!lt.empty()) r.lifetime = parse_lifetime_token(lt);
        r.scope          = rec.value("scope", std::string{});
        r.sandboxBackend = rec.value("sandboxBackend", std::string{});
    }

    return r;
}

} // namespace pm::security::ui
