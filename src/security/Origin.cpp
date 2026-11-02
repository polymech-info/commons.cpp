#include "security/Origin.hpp"

#include "host/services.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>

namespace pm::security {

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// Basename without directory, lowercased, with any trailing extension removed
/// (so "Tanit.exe", "TANIT.EXE" and "/x/tanit" all key to "tanit").
std::string stem_key(std::string_view binaryNameOrPath) {
    std::filesystem::path p(binaryNameOrPath);
    std::string stem = p.has_filename() ? p.stem().string() : std::string(binaryNameOrPath);
    return lower(stem);
}

} // namespace

Origin resolve_origin(std::string_view binaryNameOrPath) {
    const std::string key = stem_key(binaryNameOrPath);
    for (const auto& e : pm::commons::host::origin_entries()) {
        if (key == stem_key(e.binary)) {
            return Origin{e.id, e.binary, e.display, e.kind, /*firstParty=*/true};
        }
    }
    // Unknown / third-party: keep the observed basename for audit provenance.
    std::filesystem::path p(binaryNameOrPath);
    std::string base = p.has_filename() ? p.filename().string() : std::string(binaryNameOrPath);
    Origin o;
    o.id = base.empty() ? "unknown" : "external:" + base;
    o.binaryName = base;
    o.displayName = base.empty() ? "Unknown" : base;
    o.kind = OriginKind::Unknown;
    o.firstParty = false;
    return o;
}

std::vector<Origin> known_origins() {
    std::vector<Origin> out;
    const auto& entries = pm::commons::host::origin_entries();
    out.reserve(entries.size());
    for (const auto& e : entries)
        out.push_back(Origin{e.id, e.binary, e.display, e.kind, /*firstParty=*/true});
    return out;
}

Origin current_process_origin() {
    const std::filesystem::path exe = pm::commons::host::exe_executable();
    if (!exe.empty())
        return resolve_origin(exe.string());
    return resolve_origin(std::string_view{});
}

} // namespace pm::security
