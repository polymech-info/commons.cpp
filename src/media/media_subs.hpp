#pragma once

#include <cctype>
#include "fs/path_sanitizer.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include "string/string_utils.hpp"

namespace pm::viewer {

struct MediaSubPrefs {
    std::string slang;
    std::string sub_auto = "exact";
    std::string sid = "auto";
    std::vector<std::string> extra_files;
};


inline std::string_view trim_sv(std::string_view text)
{
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())))
        text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.remove_suffix(1);
    return text;
}

inline std::string first_slang_token(std::string_view slang)
{
    const auto comma = slang.find(',');
    return media::strutil::lower_ascii(std::string(trim_sv(comma == std::string_view::npos ? slang : slang.substr(0, comma))));
}

inline bool slang_is_app(std::string_view raw)
{
    const std::string t = media::strutil::lower_ascii(std::string(trim_sv(raw)));
    return t.empty() || t == "app" || t == "auto" || t == "ui";
}

inline bool slang_is_none(std::string_view raw)
{
    const std::string t = media::strutil::lower_ascii(std::string(trim_sv(raw)));
    return t == "none" || t == "off" || t == "os";
}

inline std::string resolve_slang(std::string_view requested, std::string_view display_language)
{
    if (slang_is_none(requested))
        return {};
    if (slang_is_app(requested))
        return media::strutil::lower_ascii(std::string(trim_sv(display_language)));
    return media::strutil::lower_ascii(std::string(trim_sv(requested)));
}

inline std::vector<std::string> slang_file_tags(std::string_view slang)
{
    const std::string primary = first_slang_token(slang);
    if (primary.empty())
        return {};
    std::vector<std::string> tags{primary};
    if (primary == "de") {
        tags.push_back("deu");
        tags.push_back("ger");
    } else if (primary == "en") {
        tags.push_back("eng");
    } else if (primary == "es") {
        tags.push_back("spa");
    } else if (primary == "fr") {
        tags.push_back("fra");
        tags.push_back("fre");
    } else if (primary == "it") {
        tags.push_back("ita");
    } else if (primary == "zh") {
        tags.push_back("chi");
        tags.push_back("zho");
    } else if (primary == "ar") {
        tags.push_back("ara");
    }
    return tags;
}

inline bool looks_like_remote_media(std::string_view path)
{
    return path.size() >= 8
        && (path.compare(0, 7, "http://") == 0 || path.compare(0, 8, "https://") == 0);
}

inline std::vector<std::string> sibling_subtitle_candidates(
    std::string_view media_utf8, std::string_view slang)
{
    if (media_utf8.empty() || looks_like_remote_media(media_utf8))
        return {};
    const auto tags = slang_file_tags(slang);
    if (tags.empty())
        return {};
    const std::filesystem::path file{std::string(media_utf8)};
    const std::filesystem::path dir = file.parent_path();
    const std::string stem = media::path::path_to_utf8(file.stem());
    if (stem.empty())
        return {};
    static constexpr const char* kExt[] = {".srt", ".vtt", ".ass", ".ssa"};
    std::vector<std::string> out;
    for (const auto& tag : tags) {
        for (const char* ext : kExt) {
            out.push_back(media::path::path_to_utf8((dir / (stem + "." + tag + ext))));
            out.push_back(media::path::path_to_utf8((dir / (stem + "_" + tag + ext))));
        }
    }
    return out;
}

inline std::vector<std::string> existing_sibling_subtitles(
    std::string_view media_utf8, std::string_view slang)
{
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& cand : sibling_subtitle_candidates(media_utf8, slang)) {
        if (std::filesystem::is_regular_file(std::filesystem::path{cand}, ec))
            out.push_back(cand);
    }
    return out;
}

inline MediaSubPrefs default_sub_prefs(std::string_view display_language, std::string_view media_utf8)
{
    MediaSubPrefs prefs;
    prefs.slang = media::strutil::lower_ascii(std::string(trim_sv(display_language)));
    prefs.sub_auto = "exact";
    prefs.sid = "auto";
    if (prefs.sid != "no")
        prefs.extra_files = existing_sibling_subtitles(media_utf8, prefs.slang);
    return prefs;
}

inline MediaSubPrefs finish_sub_prefs(MediaSubPrefs prefs, std::string_view media_utf8)
{
    if (prefs.sid == "no") {
        prefs.sub_auto = "no";
        prefs.slang.clear();
        prefs.extra_files.clear();
        return prefs;
    }
    if (prefs.sub_auto.empty())
        prefs.sub_auto = "exact";
    if (prefs.sid.empty())
        prefs.sid = "auto";
    if (prefs.extra_files.empty())
        prefs.extra_files = existing_sibling_subtitles(media_utf8, prefs.slang);
    return prefs;
}

inline std::optional<MediaSubPrefs>& pending_sub_prefs_slot()
{
    static std::optional<MediaSubPrefs> slot;
    return slot;
}

inline void set_pending_sub_prefs(MediaSubPrefs prefs)
{
    pending_sub_prefs_slot() = std::move(prefs);
}

inline std::optional<MediaSubPrefs> take_pending_sub_prefs()
{
    auto& slot = pending_sub_prefs_slot();
    std::optional<MediaSubPrefs> out = std::move(slot);
    slot.reset();
    return out;
}

} // namespace pm::viewer
