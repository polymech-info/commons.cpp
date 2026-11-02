#pragma once

#include "media/media_kind.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace media::probe {

using MediaKind = ::media::MediaKind;

struct ProbeOptions {
    // Optional explicit magic.mgc path. Empty uses packaged/default lookup.
    std::filesystem::path magic_database;
};

struct ProbeResult {
    bool ok = false;
    MediaKind kind = MediaKind::Unknown;
    std::string content_type;
    std::vector<std::string> extensions;
    std::string preferred_extension;
    std::string error;
    std::filesystem::path magic_database;
};

/// Same filesystem gate `probe_file` uses before opening libmagic (`pm-file-tool`).
/// Directories are not probeable; zip/cab shell "folders" are regular files here.
enum class PathEntity : std::uint8_t {
    Missing,
    Directory,
    RegularFile,
    Other,
};

/// Filesystem entity kind shared with `probe_file`'s pre-magic validation
/// (`pm-file-tool` only accepts regular files; directories are never probed).
[[nodiscard]] inline PathEntity classify_path_entity(
    const std::filesystem::path& path) noexcept
{
    if (path.empty()) {
        return PathEntity::Missing;
    }
    std::error_code ec;
    const std::filesystem::file_status st =
        std::filesystem::status(path, ec);
    if (ec || !std::filesystem::exists(st)) {
        return PathEntity::Missing;
    }
    if (std::filesystem::is_directory(st)) {
        return PathEntity::Directory;
    }
    if (std::filesystem::is_regular_file(st)) {
        return PathEntity::RegularFile;
    }
    return PathEntity::Other;
}

/// Source images above this are refused before decode. The vision preview is a
/// separate, much smaller JPEG.
inline constexpr std::uintmax_t k_max_image_bytes = 512ull * 1024ull * 1024ull;

/// False when `path` is not a regular file or is larger than `k_max_image_bytes`.
inline bool image_within_byte_limit(const std::filesystem::path& path, std::string& error)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        error = "not a file";
        return false;
    }
    const std::uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        error = "cannot read image size";
        return false;
    }
    if (size > k_max_image_bytes) {
        error = "image exceeds 512 MB";
        return false;
    }
    return true;
}

std::string_view media_kind_name(MediaKind kind) noexcept;

ProbeResult probe_file(const std::filesystem::path& path, const ProbeOptions& options = {});
ProbeResult probe_buffer(std::string_view bytes,
                         std::string_view display_name = {},
                         const ProbeOptions& options = {});

} // namespace media::probe
