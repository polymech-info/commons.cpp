#pragma once

#include <string_view>

namespace media::command_finish_i18n {

struct Strings {
    const char* command_finished;
    const char* finished_suffix;
    const char* command_failed;
    const char* failed_suffix;
    const char* command_title;
    const char* exit_prefix;
    const char* more_suffix;
    const wchar_t* more_suffix_w;
};

[[nodiscard]] const Strings& strings_for(std::string_view display_language);
[[nodiscard]] const Strings& current();

} // namespace media::command_finish_i18n
