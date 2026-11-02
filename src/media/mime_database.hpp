#pragma once

#include "media/probe.hpp"

#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace media::probe {

struct MimeDatabaseOptions {
    // Optional path to file(1)'s magic/Magdir source directory. Empty uses dev/runtime candidates.
    std::filesystem::path magic_source_dir;
};

struct MimeTypeEntry {
    std::string mime_type;
    MediaKind kind = MediaKind::Unknown;
    std::vector<std::string> extensions;
    std::vector<std::filesystem::path> sources;
};

struct MimeDatabaseResult {
    bool ok = false;
    std::string error;
    std::filesystem::path source_dir;
    std::vector<MimeTypeEntry> entries;
};

std::string lower_ascii(std::string_view value);
std::string normalize_extension(std::string_view value);
std::vector<std::string> split_magic_extensions(std::string_view value);

MediaKind classify_media(std::string_view mime_type,
                         const std::vector<std::string>& extensions = {});

bool wildcard_match(std::string_view pattern, std::string_view value);

MimeDatabaseResult load_mime_database(const MimeDatabaseOptions& options = {});
std::vector<MimeTypeEntry> filter_mime_entries(const std::vector<MimeTypeEntry>& entries,
                                               std::string_view pattern,
                                               std::string_view kind = {},
                                               std::string_view extension = {});

} // namespace media::probe
