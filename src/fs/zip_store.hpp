#pragma once

#include <filesystem>
#include <string>

namespace media::zip_store {

// Write a directory tree as a stored-only ZIP (same format as settings archive export).
bool write_stored_zip(const std::filesystem::path& zip_path,
                      const std::filesystem::path& root_dir,
                      std::string& err);

// Extract a stored-only ZIP into out_dir (zip-slip safe).
bool extract_stored_zip(const std::filesystem::path& zip_path,
                        const std::filesystem::path& out_dir,
                        std::string& err);

} // namespace media::zip_store
