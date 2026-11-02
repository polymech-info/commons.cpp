#pragma once

#include <string_view>

namespace pm::security::ui::i18n {

struct Strings {
    const wchar_t* window_title;
    const wchar_t* risk_label;
    const wchar_t* risk_was;         // " (was %s)" style — built manually
    const wchar_t* tool_label;
    const wchar_t* action_label;
    const wchar_t* why_label;
    const wchar_t* goal_label;
    const wchar_t* resource_label;
    const wchar_t* command_label;
    const wchar_t* scope_label;
    const wchar_t* scope_hint;
    const wchar_t* sandbox_checkbox;
    // Allow buttons (short labels for the 2×2 grid)
    const wchar_t* btn_allow_once;
    const wchar_t* btn_allow_session;
    const wchar_t* btn_allow_task;
    const wchar_t* btn_allow_always;
    const wchar_t* btn_ai_auto_once;
    const wchar_t* btn_ai_auto_session;
    const wchar_t* btn_ai_auto_always;
    // Bottom row
    const wchar_t* btn_deny;
    const wchar_t* btn_settings;
    // AI review section
    const wchar_t* ai_title;
    const wchar_t* ai_review_btn;
    const wchar_t* ai_reviewing;
    const wchar_t* ai_apply;
    const wchar_t* ai_applied;
    const wchar_t* ai_recommend;     // "Recommended:"
    const wchar_t* ai_raised;        // "AI raised risk"
    const wchar_t* ai_was;           // "was"
    // Tooltips / sub-labels for the allow buttons
    const wchar_t* tip_once;
    const wchar_t* tip_session;
    const wchar_t* tip_task;
    const wchar_t* tip_always;
    const wchar_t* tip_ai_auto;
    const wchar_t* tip_review;
    // Risk / action *values* (the field labels are risk_label / action_label).
    const wchar_t* risk_low;
    const wchar_t* risk_medium;
    const wchar_t* risk_high;
    const wchar_t* risk_critical;
    const wchar_t* action_read;
    const wchar_t* action_write;
    const wchar_t* action_delete;
    const wchar_t* action_execute;
    const wchar_t* action_network;
    const wchar_t* action_upload;
    const wchar_t* action_download;
    const wchar_t* action_git_push;
    const wchar_t* action_publish;
    const wchar_t* action_protocol;
    const wchar_t* unknown_tool;
    // Heading: title_allow_pre + action + title_allow_post  ("Allow write?")
    const wchar_t* title_allow_pre;
    const wchar_t* title_allow_post;
    // possible-risk line: risk_badge_pre + risk value + risk_badge_post
    const wchar_t* risk_badge_pre;
    const wchar_t* risk_badge_post;
    const wchar_t* decision_allow;
    const wchar_t* decision_deny;
    const wchar_t* decision_ask;
    const wchar_t* intent_web_command;
    const wchar_t* intent_web_command_from_pre;
};

/// Returns the locale-matched string table. Unknown or empty tags fall back to English.
/// Only the first two BCP-47 characters are examined; "de-AT", "es-419", etc. all match.
[[nodiscard]] const Strings& strings_for(std::string_view lang);

} // namespace pm::security::ui::i18n
