#include "media/probe.hpp"
#include "media/mime_database.hpp"
#include "host/services.hpp"

#include <magic.h>

#include <cerrno>
#include <fstream>
#include <cstdlib>
#include <memory>
#include <system_error>
#include <type_traits>
#include <vector>

namespace fs = std::filesystem;

namespace media::probe {
namespace {

#ifndef MAGIC_EXTENSION
#define MAGIC_EXTENSION 0x1000000
#endif

struct MagicCloser {
    void operator()(magic_t cookie) const noexcept
    {
        if (cookie)
            magic_close(cookie);
    }
};

using MagicCookie = std::unique_ptr<std::remove_pointer_t<magic_t>, MagicCloser>;

bool existing_file(const fs::path& path)
{
    std::error_code ec;
    return !path.empty() && fs::is_regular_file(path, ec);
}

void push_if_file(std::vector<fs::path>& out, fs::path path)
{
    if (existing_file(path))
        out.push_back(std::move(path));
}

std::vector<fs::path> magic_database_candidates(const ProbeOptions& options)
{
    std::vector<fs::path> candidates;
    push_if_file(candidates, options.magic_database);

    if (const char* env = std::getenv("PM_MAGIC_MGC"); env && *env)
        push_if_file(candidates, fs::path(env));
    if (const char* env = std::getenv("MAGIC"); env && *env)
        push_if_file(candidates, fs::path(env));

    const fs::path exe_dir = pm::commons::host::exe_parent_directory();
    if (!exe_dir.empty()) {
        push_if_file(candidates, exe_dir / "magic.mgc");
        push_if_file(candidates, exe_dir.parent_path() / "shared" / "magic.mgc");
    }

    std::error_code ec;
    const fs::path cwd = fs::current_path(ec);
    if (!ec) {
        push_if_file(candidates, cwd / "magic.mgc");
        push_if_file(candidates, cwd / "dist" / "shared" / "magic.mgc");
    }

    const std::string magic_db = pm::commons::host::magic_database_path();
    if (!magic_db.empty())
        push_if_file(candidates, fs::path(magic_db));

    return candidates;
}

MagicCookie open_magic(const ProbeOptions& options, ProbeResult& result, int flags)
{
    MagicCookie cookie(magic_open(flags));
    if (!cookie) {
        result.error = "magic_open failed";
        return {};
    }

    for (const fs::path& candidate : magic_database_candidates(options)) {
        const std::string db = candidate.string();
        if (magic_load(cookie.get(), db.c_str()) == 0) {
            result.magic_database = candidate;
            return cookie;
        }
    }

    if (magic_load(cookie.get(), nullptr) == 0)
        return cookie;

    if (const char* err = magic_error(cookie.get()); err && *err)
        result.error = err;
    else
        result.error = "could not load magic database";
    return {};
}

bool assign_magic_value(MagicCookie& cookie, const char* value, std::string& out, std::string& error)
{
    if (!value || !*value) {
        if (const char* err = magic_error(cookie.get()); err && *err)
            error = err;
        else
            error = "libmagic returned no value";
        return false;
    }

    out = value;
    return true;
}

std::string path_string_for_error(const fs::path& path)
{
    try {
        return path.string();
    } catch (...) {
        return "<path conversion failed>";
    }
}

bool validate_probe_file(const fs::path& path, ProbeResult& result)
{
    if (path.empty()) {
        result.error = "empty path";
        return false;
    }

    const PathEntity entity = classify_path_entity(path);
    if (entity == PathEntity::Missing) {
        result.error =
            "file does not exist: " + path_string_for_error(path);
        return false;
    }
    if (entity != PathEntity::RegularFile) {
        result.error =
            "not a regular file: " + path_string_for_error(path);
        return false;
    }

    errno = 0;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        result.error = "could not open file for probing";
        if (errno != 0)
            result.error += ": " + std::error_code(errno, std::generic_category()).message();
        result.error += ": " + path_string_for_error(path);
        return false;
    }

    return true;
}

void finish_result(ProbeResult& result)
{
    result.content_type = lower_ascii(result.content_type);
    result.extensions = split_magic_extensions(result.preferred_extension.empty()
        ? std::string_view{}
        : std::string_view(result.preferred_extension));
    result.preferred_extension = result.extensions.empty() ? std::string{} : result.extensions.front();
    result.kind = classify_media(result.content_type, result.extensions);
    result.ok = !result.content_type.empty();
}

} // namespace

ProbeResult probe_file(const fs::path& path, const ProbeOptions& options)
{
    ProbeResult result;
    if (!validate_probe_file(path, result))
        return result;

    MagicCookie mime_cookie = open_magic(options, result, MAGIC_MIME_TYPE);
    if (!mime_cookie)
        return result;

    const std::string file = path_string_for_error(path);
    if (file == "<path conversion failed>") {
        result.error = "could not convert path for probing";
        return result;
    }

    const char* mime_value = nullptr;
    try {
        mime_value = magic_file(mime_cookie.get(), file.c_str());
    } catch (const std::exception& e) {
        result.error = std::string("libmagic failed while probing file: ") + e.what();
        return result;
    } catch (...) {
        result.error = "libmagic failed while probing file";
        return result;
    }
    if (!assign_magic_value(mime_cookie, mime_value, result.content_type, result.error))
        return result;

    ProbeResult ext_open;
    MagicCookie ext_cookie = open_magic(options, ext_open, MAGIC_EXTENSION);
    if (ext_cookie) {
        std::string ext_value;
        std::string ext_error;
        const char* ext_raw = nullptr;
        try {
            ext_raw = magic_file(ext_cookie.get(), file.c_str());
        } catch (...) {
            ext_raw = nullptr;
        }
        if (assign_magic_value(ext_cookie, ext_raw, ext_value, ext_error))
            result.preferred_extension = ext_value;
    }

    finish_result(result);
    return result;
}

ProbeResult probe_buffer(std::string_view bytes, std::string_view, const ProbeOptions& options)
{
    ProbeResult result;
    MagicCookie mime_cookie = open_magic(options, result, MAGIC_MIME_TYPE);
    if (!mime_cookie)
        return result;

    if (!assign_magic_value(mime_cookie, magic_buffer(mime_cookie.get(), bytes.data(), bytes.size()), result.content_type, result.error))
        return result;

    ProbeResult ext_open;
    MagicCookie ext_cookie = open_magic(options, ext_open, MAGIC_EXTENSION);
    if (ext_cookie) {
        std::string ext_value;
        std::string ext_error;
        if (assign_magic_value(ext_cookie, magic_buffer(ext_cookie.get(), bytes.data(), bytes.size()), ext_value, ext_error))
            result.preferred_extension = ext_value;
    }

    finish_result(result);
    return result;
}

} // namespace media::probe
