#pragma once

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

namespace pm::viewer {

// W3C Media Fragments temporal NPT only. Rejects mpv-only forms (%, chapter #N, from-end).
struct MediaNptRange {
    double start_seconds = 0;
    std::optional<double> end_seconds;

    friend bool operator==(const MediaNptRange&, const MediaNptRange&) = default;
};

inline bool media_npt_is_valid(const MediaNptRange& span)
{
    if (!std::isfinite(span.start_seconds) || span.start_seconds < 0)
        return false;
    if (!span.end_seconds)
        return true;
    return std::isfinite(*span.end_seconds) && *span.end_seconds > span.start_seconds;
}

inline std::string_view media_fragment_without_hash(std::string_view fragment)
{
    if (!fragment.empty() && fragment.front() == '#')
        fragment.remove_prefix(1);
    return fragment;
}

inline bool media_fragment_starts_with_t(std::string_view fragment)
{
    fragment = media_fragment_without_hash(fragment);
    return fragment.size() >= 2 && fragment[0] == 't' && fragment[1] == '=';
}

inline bool parse_npt_clock(std::string_view text, double& out)
{
    out = 0;
    if (text.empty() || text.size() > 64)
        return false;
    if (text.front() == '-' || text.front() == '+' || text.front() == '%')
        return false;
    if (text.find_first_of("%#") != std::string_view::npos)
        return false;

    auto parse_nonneg = [](std::string_view part, double& value, bool integer_only) {
        if (part.empty() || part.front() == '-' || part.front() == '+')
            return false;
        if (integer_only && part.find('.') != std::string_view::npos)
            return false;
        const std::string tmp(part);
        char* end = nullptr;
        value = std::strtod(tmp.c_str(), &end);
        return end == tmp.c_str() + tmp.size() && std::isfinite(value) && value >= 0;
    };

    const auto c1 = text.find(':');
    if (c1 == std::string_view::npos) {
        double seconds = 0;
        if (!parse_nonneg(text, seconds, false))
            return false;
        out = seconds;
        return true;
    }

    const auto c2 = text.find(':', c1 + 1);
    if (c2 != std::string_view::npos && text.find(':', c2 + 1) != std::string_view::npos)
        return false;

    double hours = 0;
    double minutes = 0;
    double seconds = 0;
    if (c2 == std::string_view::npos) {
        if (!parse_nonneg(text.substr(0, c1), minutes, true)
            || !parse_nonneg(text.substr(c1 + 1), seconds, false)
            || seconds >= 60.0) {
            return false;
        }
    } else {
        if (!parse_nonneg(text.substr(0, c1), hours, true)
            || !parse_nonneg(text.substr(c1 + 1, c2 - c1 - 1), minutes, true)
            || !parse_nonneg(text.substr(c2 + 1), seconds, false)
            || minutes >= 60.0 || seconds >= 60.0) {
            return false;
        }
    }
    out = hours * 3600.0 + minutes * 60.0 + seconds;
    return std::isfinite(out);
}

inline std::optional<MediaNptRange> parse_npt_range(std::string_view text)
{
    if (text.size() >= 4) {
        const unsigned char a = static_cast<unsigned char>(text[0] | 0x20);
        const unsigned char b = static_cast<unsigned char>(text[1] | 0x20);
        const unsigned char c = static_cast<unsigned char>(text[2] | 0x20);
        if (a == 'n' && b == 'p' && c == 't' && text[3] == ':')
            text.remove_prefix(4);
    }
    if (text.empty())
        return std::nullopt;

    const auto comma = text.find(',');
    if (comma != std::string_view::npos && text.find(',', comma + 1) != std::string_view::npos)
        return std::nullopt;

    MediaNptRange span;
    const std::string_view start = text.substr(0, comma);
    if (start.empty()) {
        span.start_seconds = 0;
    } else if (!parse_npt_clock(start, span.start_seconds)) {
        return std::nullopt;
    }

    if (comma != std::string_view::npos) {
        const std::string_view end = text.substr(comma + 1);
        if (!end.empty()) {
            double end_seconds = 0;
            if (!parse_npt_clock(end, end_seconds))
                return std::nullopt;
            span.end_seconds = end_seconds;
        }
    }
    if (!media_npt_is_valid(span))
        return std::nullopt;
    return span;
}

inline std::string format_npt_seconds(double seconds)
{
    if (!std::isfinite(seconds) || seconds < 0)
        seconds = 0;
    char buf[64];
    if (seconds == std::floor(seconds) && seconds < 1e12) {
        std::snprintf(buf, sizeof(buf), "%.0f", seconds);
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "%.6f", seconds);
    std::string out = buf;
    while (out.size() > 1 && out.back() == '0')
        out.pop_back();
    if (!out.empty() && out.back() == '.')
        out.pop_back();
    return out;
}

inline std::string format_mpv_span_options(const MediaNptRange& span)
{
    std::string out = "start=" + format_npt_seconds(span.start_seconds);
    if (span.end_seconds)
        out += ",end=" + format_npt_seconds(*span.end_seconds);
    return out;
}

struct MediaPathSplit {
    std::string path;
    std::optional<MediaNptRange> media;
};

inline MediaPathSplit split_media_temporal_path(std::string_view path)
{
    MediaPathSplit out;
    out.path = std::string(path);
    const auto hash = path.rfind('#');
    if (hash == std::string_view::npos || hash == 0)
        return out;
    const std::string_view fragment = path.substr(hash);
    if (!media_fragment_starts_with_t(fragment))
        return out;
    const auto parsed = parse_npt_range(media_fragment_without_hash(fragment).substr(2));
    if (!parsed)
        return out;
    out.path.assign(path.substr(0, hash));
    out.media = parsed;
    return out;
}

} // namespace pm::viewer
