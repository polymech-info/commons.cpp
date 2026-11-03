#include "installer/runtime.hpp"

#include "installer/engine.hpp"
#include "installer/host.hpp"

#include "host/services.hpp"
#include "logging/pm_log.hpp"

#include <chrono>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace pm::installer {
namespace {

namespace fs = std::filesystem;

std::string stamp_file_name(const fs::path& manifest_path)
{
    auto sanitize = [](std::string s) {
        for (char& c : s) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if ((uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z')
                || (uc >= '0' && uc <= '9') || c == '-' || c == '_')
                continue;
            c = '_';
        }
        return s;
    };
    const std::string parent = sanitize(manifest_path.parent_path().filename().string());
    const std::string stem = sanitize(manifest_path.stem().string());
    if (parent.empty())
        return stem + ".stamp";
    return parent + "__" + stem + ".stamp";
}

fs::path ttl_stamp_path(const fs::path& manifest_path)
{
    return pm::commons::host::config_dir() / "cache" / "manifest-ttl" / stamp_file_name(manifest_path);
}

bool stamp_is_fresh(const fs::path& stamp, std::int64_t ttl_sec)
{
    if (ttl_sec <= 0)
        return false;
    std::ifstream in(stamp);
    if (!in)
        return false;
    std::int64_t then = 0;
    in >> then;
    if (!in || then <= 0)
        return false;
    const auto now = static_cast<std::int64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    return (now - then) < ttl_sec;
}

void write_stamp(const fs::path& stamp)
{
    std::error_code ec;
    fs::create_directories(stamp.parent_path(), ec);
    std::ofstream out(stamp, std::ios::trunc);
    if (!out)
        return;
    const auto now = static_cast<std::int64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    out << now << "\n";
}

std::string first_package_error(const ManifestResult& result)
{
    for (const auto& pkg : result.packages) {
        if (!pkg.ok && !pkg.error.empty())
            return pkg.id + ": " + pkg.error;
    }
    if (result.timed_out)
        return "timeout";
    if (result.cancelled)
        return "cancelled";
    return "manifest failed";
}

void fill_service_session(RunOptions& options, VariableMap& vars, bool attach_bearer)
{
    const std::string base = host::resolve_cms_base(options.service_server_url);
    if (options.service_server_url.empty())
        options.service_server_url = base;

    const auto it = vars.find("DEFAULT_VFS_SERVER");
    if (it == vars.end() || it->second.empty())
        vars["DEFAULT_VFS_SERVER"] = base;

    if (!attach_bearer) {
        options.service_bearer.clear();
        return;
    }
    if (options.service_bearer.empty()) {
        std::string err;
        std::string bearer;
        if (host::read_access_token(bearer, err) && !bearer.empty())
            options.service_bearer = std::move(bearer);
    }
}

} // namespace

ManifestRunResult run_manifest(const ManifestRunRequest& req) noexcept
{
    ManifestRunResult out;
    try {
        fs::path path(req.path);
        if (path.empty()) {
            out.error = "manifest path is empty";
            return out;
        }

        const fs::path install_root = req.install_root.empty()
            ? pm::commons::host::exe_parent_directory()
            : fs::path(req.install_root);
        if (!path.is_absolute())
            path = install_root / path;

        std::error_code ec;
        if (!fs::is_regular_file(path, ec) || ec) {
            out.skipped_missing = true;
            if (!req.forgiving)
                out.error = "manifest not found: " + path.string();
            else
                pm::log::debug("manifest-run", "manifest not found: " + path.string());
            return out;
        }

        std::string load_err;
        const auto manifest = load_manifest(path.string(), &load_err);
        if (!manifest) {
            out.error = load_err.empty() ? ("manifest load failed: " + path.string()) : load_err;
            pm::log::warn("manifest-run", out.error);
            return out;
        }

        const bool forgiving = req.forgiving || manifest->forgiving;
        const std::int64_t ttl = req.ttl_sec >= 0 ? req.ttl_sec : manifest->ttl_sec;
        const fs::path stamp = ttl_stamp_path(path);
        if (stamp_is_fresh(stamp, ttl)) {
            out.skipped_ttl = true;
            pm::log::debug("manifest-run", "ttl fresh, skip " + path.string());
            return out;
        }

        std::string verr;
        auto vars = host::make_bundle_variables(install_root.string(), &verr);
        if (!verr.empty()) {
            out.error = verr;
            if (forgiving)
                pm::log::warn("manifest-run", path.filename().string() + ": " + verr);
            return out;
        }
        for (const auto& kv : req.variables)
            vars[kv.first] = kv.second;

        RunOptions options = req.options;
        fill_service_session(options, vars, !manifest->auth_none);

        out.manifest = execute_manifest(*manifest, vars, options);
        out.ran = true;
        if (!out.manifest.ok) {
            out.error = first_package_error(out.manifest);
            if (forgiving)
                pm::log::warn("manifest-run", path.filename().string() + ": " + out.error);
            return out;
        }

        if (ttl > 0)
            write_stamp(stamp);
        pm::log::info("manifest-run",
                      path.filename().string()
                          + " copied=" + std::to_string(out.manifest.total_copied)
                          + " skipped=" + std::to_string(out.manifest.total_skipped));
        return out;
    } catch (const std::exception& ex) {
        out.error = ex.what();
        pm::log::warn("manifest-run", std::string("exception: ") + ex.what());
        return out;
    } catch (...) {
        out.error = "unknown exception";
        pm::log::warn("manifest-run", "exception: unknown");
        return out;
    }
}

} // namespace pm::installer
