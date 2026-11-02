#pragma once

#include <cstdint>
#include <filesystem>
#include <string_view>

namespace media::exclude {

/**
 * Name-only match, same list as the VFS listing filter (`exclude-default.ts`).
 * Dot-names are excluded. Comparison is case-insensitive.
 */
bool is_default_excluded(std::string_view name);
bool is_default_excluded(const std::filesystem::path& name);

/** One file. Larger files are skipped; the rest of the batch still uploads. */
inline constexpr std::uint64_t k_max_upload_file_bytes = 5ull * 1024ull * 1024ull;
/** One share, aligned with the pro VFS home quota (`VFS_QUOTA_DEFAULT_MB` = 100). */
inline constexpr std::uint64_t k_max_upload_batch_bytes = 100ull * 1024ull * 1024ull;

} // namespace media::exclude
