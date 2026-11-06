#pragma once

#include "app_exe_directory.hpp"

#include <filesystem>
#include <vector>

namespace media::app {

#ifndef POLYMECH_APP_TANIT_VIEWER
#define POLYMECH_APP_TANIT_VIEWER 0
#endif

inline std::filesystem::path find_dist_shared_file(const std::filesystem::path& filename)
{
    std::vector<std::filesystem::path> candidates;
    append_dist_shared_candidates(candidates, exe_parent_directory(), filename);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(p, ec) && !ec)
            return p;
    }
    return {};
}

inline std::filesystem::path app_features_manifest_filename()
{
#if POLYMECH_APP_TANIT_VIEWER
    return L"features-viewer.json";
#else
    return L"features.json";
#endif
}

inline std::filesystem::path find_app_features_manifest()
{
    return find_dist_shared_file(app_features_manifest_filename());
}

inline std::filesystem::path find_dist_bundle_file(
    const std::filesystem::path& app_stem, const std::filesystem::path& filename)
{
    std::vector<std::filesystem::path> candidates;
    append_dist_bundle_candidates(candidates, exe_parent_directory(), app_stem, filename);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(p, ec) && !ec)
            return p;
    }
    return {};
}

} // namespace media::app
