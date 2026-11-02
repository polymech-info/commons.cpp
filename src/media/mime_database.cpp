#include "media/mime_database.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <system_error>

namespace fs = std::filesystem;

namespace media::probe {
namespace {

bool starts_with(std::string_view value, std::string_view prefix)
{
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::string trim_ascii(std::string_view value)
{
    const auto is_ws = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    std::size_t b = 0;
    while (b < value.size() && is_ws(static_cast<unsigned char>(value[b])))
        ++b;
    std::size_t e = value.size();
    while (e > b && is_ws(static_cast<unsigned char>(value[e - 1])))
        --e;
    return std::string(value.substr(b, e - b));
}

std::string directive_value(std::string_view line, std::string_view marker)
{
    std::string t = trim_ascii(line);
    if (!starts_with(t, marker))
        return {};
    return trim_ascii(std::string_view(t).substr(marker.size()));
}

bool is_top_level_magic_rule(std::string_view line)
{
    const std::string trimmed = trim_ascii(line);
    if (trimmed.empty())
        return false;
    const char c = trimmed.front();
    return c != '>' && c != '#' && c != '!' && c != '&' &&
           !std::isspace(static_cast<unsigned char>(c));
}

void push_unique(std::vector<std::string>& out, std::string value)
{
    if (value.empty())
        return;
    if (std::find(out.begin(), out.end(), value) == out.end())
        out.push_back(std::move(value));
}

void push_unique_path(std::vector<fs::path>& out, fs::path value)
{
    if (value.empty())
        return;
    if (std::find(out.begin(), out.end(), value) == out.end())
        out.push_back(std::move(value));
}

bool has_ext(const std::vector<std::string>& extensions, std::string_view ext)
{
    const std::string normalized = normalize_extension(ext);
    return std::find(extensions.begin(), extensions.end(), normalized) != extensions.end();
}

bool has_any_ext(const std::vector<std::string>& extensions, std::initializer_list<std::string_view> values)
{
    for (std::string_view value : values) {
        if (has_ext(extensions, value))
            return true;
    }
    return false;
}

bool mime_is(std::string_view mime, std::string_view value)
{
    return lower_ascii(mime) == lower_ascii(value);
}

bool mime_starts_with(std::string_view mime, std::string_view prefix)
{
    return starts_with(lower_ascii(mime), lower_ascii(prefix));
}

bool is_code_mime(std::string_view mime)
{
    return mime_is(mime, "application/javascript") ||
           mime_is(mime, "application/typescript") ||
           mime_is(mime, "text/javascript") ||
           mime_is(mime, "text/x-asm") ||
           mime_is(mime, "text/x-c") ||
           mime_is(mime, "text/x-c++") ||
           mime_is(mime, "text/x-c++hdr") ||
           mime_is(mime, "text/x-c++src") ||
           mime_is(mime, "text/x-chdr") ||
           mime_is(mime, "text/x-csrc") ||
           mime_is(mime, "text/x-fortran") ||
           mime_is(mime, "text/x-java") ||
           mime_is(mime, "text/x-php") ||
           mime_is(mime, "text/x-rust") ||
           mime_is(mime, "text/x-go");
}

bool is_text_like_for_source_extension(std::string_view mime)
{
    return mime_starts_with(mime, "text/") ||
           mime_is(mime, "application/json") ||
           mime_is(mime, "application/xml") ||
           mime_is(mime, "application/x-yaml") ||
           mime_is(mime, "application/octet-stream");
}

std::vector<fs::path> magic_source_candidates(const MimeDatabaseOptions& options)
{
    std::vector<fs::path> candidates;
    const auto push_dir = [&candidates](fs::path path) {
        std::error_code ec;
        if (!path.empty() && fs::is_directory(path, ec))
            candidates.push_back(std::move(path));
    };

    push_dir(options.magic_source_dir);
    if (const char* env = std::getenv("PM_MAGIC_MAGDIR"); env && *env)
        push_dir(fs::path(env));
    if (const char* env = std::getenv("PM_FILE_MAGDIR"); env && *env)
        push_dir(fs::path(env));

    std::error_code ec;
    const fs::path cwd = fs::current_path(ec);
    if (!ec) {
        push_dir(cwd / "packages" / "file" / "magic" / "Magdir");
        push_dir(cwd / ".." / "packages" / "file" / "magic" / "Magdir");
    }
    return candidates;
}

} // namespace

std::string_view media_kind_name(MediaKind kind) noexcept
{
    switch (kind) {
    case MediaKind::Image: return "image";
    case MediaKind::Video: return "video";
    case MediaKind::Audio: return "audio";
    case MediaKind::Document: return "document";
    case MediaKind::Code: return "code";
    case MediaKind::Script: return "script";
    case MediaKind::Archive: return "archive";
    case MediaKind::Font: return "font";
    case MediaKind::Model3D: return "model3d";
    case MediaKind::Text: return "text";
    case MediaKind::Binary: return "binary";
    case MediaKind::Unknown: return "unknown";
    }
    return "unknown";
}

std::string lower_ascii(std::string_view value)
{
    std::string out(value);
    for (char& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

std::string normalize_extension(std::string_view value)
{
    std::string ext = lower_ascii(trim_ascii(value));
    while (!ext.empty() && ext.front() == '*')
        ext.erase(ext.begin());
    if (ext == "???")
        return {};
    if (!ext.empty() && ext.front() != '.')
        ext.insert(ext.begin(), '.');
    return ext == "." ? std::string{} : ext;
}

std::vector<std::string> split_magic_extensions(std::string_view value)
{
    std::vector<std::string> out;
    std::size_t b = 0;
    while (b <= value.size()) {
        const std::size_t e = value.find_first_of("/,; \t\r\n", b);
        const std::string part = normalize_extension(value.substr(b, e == std::string_view::npos ? e : e - b));
        push_unique(out, part);
        if (e == std::string_view::npos)
            break;
        b = e + 1;
    }
    return out;
}

MediaKind classify_media(std::string_view mime_type, const std::vector<std::string>& extensions)
{
    const std::string mime = lower_ascii(trim_ascii(mime_type));
    if (mime.empty())
        return extensions.empty() ? MediaKind::Unknown : MediaKind::Binary;

    if (mime_starts_with(mime, "image/")) return MediaKind::Image;
    if (mime_starts_with(mime, "video/")) return MediaKind::Video;
    if (mime_starts_with(mime, "audio/")) return MediaKind::Audio;
    if (mime_starts_with(mime, "font/")) return MediaKind::Font;
    if (is_code_mime(mime)) return MediaKind::Code;

    if (is_text_like_for_source_extension(mime) &&
        has_any_ext(extensions, {".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".mjs", ".cjs", ".py", ".rb", ".pl", ".lua", ".tcl"}))
        return MediaKind::Script;
    if (is_text_like_for_source_extension(mime) &&
        has_any_ext(extensions, {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".inl", ".cs", ".go", ".rs", ".java", ".kt", ".swift", ".ts", ".tsx", ".jsx", ".php", ".css", ".scss", ".sql", ".json", ".jsonl", ".xml", ".html", ".htm", ".yaml", ".yml", ".toml"}))
        return MediaKind::Code;
    if (has_any_ext(extensions, {".stl", ".obj", ".gltf", ".glb", ".ply", ".step", ".stp", ".stpz",
                                 ".dxf", ".scad", ".3ds", ".amf", ".3mf", ".dae", ".fbx", ".fcstd",
                                 ".iges", ".igs", ".brep", ".brp", ".vrml", ".wrl",
                                 ".usd", ".usda", ".usdc", ".usdz", ".vtk", ".vtp"}))
        return MediaKind::Model3D;

    if (mime_is(mime, "application/pdf") || mime_is(mime, "application/rtf") ||
        mime_is(mime, "application/postscript") || mime_is(mime, "application/epub+zip") ||
        mime_starts_with(mime, "application/vnd.ms-") ||
        mime_starts_with(mime, "application/vnd.openxmlformats-officedocument.") ||
        mime_starts_with(mime, "application/vnd.oasis.opendocument.") ||
        mime_starts_with(mime, "application/vnd.apple.") ||
        has_any_ext(extensions, {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".epub"}))
        return MediaKind::Document;

    if (mime_is(mime, "application/zip") || mime_is(mime, "application/gzip") ||
        mime_is(mime, "application/x-tar") || mime_is(mime, "application/x-7z-compressed") ||
        mime_is(mime, "application/x-rar") || mime_is(mime, "application/x-iso9660-image") ||
        mime_is(mime, "application/x-iso9660") ||
        has_any_ext(extensions, {".zip", ".gz", ".tgz", ".tar", ".7z", ".rar", ".bz2", ".xz", ".iso"}))
        return MediaKind::Archive;

    if (mime_starts_with(mime, "text/") || mime_is(mime, "application/json") ||
        mime_is(mime, "application/xml") || mime_is(mime, "application/x-yaml"))
        return MediaKind::Text;

    if (mime_is(mime, "application/octet-stream") || mime_starts_with(mime, "application/x-executable") ||
        mime_starts_with(mime, "application/x-sharedlib") || mime_starts_with(mime, "application/x-msdownload"))
        return MediaKind::Binary;

    return mime_starts_with(mime, "application/") ? MediaKind::Binary : MediaKind::Unknown;
}

bool wildcard_match(std::string_view pattern, std::string_view value)
{
    const std::string p = lower_ascii(pattern.empty() ? "*" : pattern);
    const std::string v = lower_ascii(value);
    std::size_t pi = 0, vi = 0, star = std::string::npos, match = 0;
    while (vi < v.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == v[vi])) {
            ++pi;
            ++vi;
        } else if (pi < p.size() && p[pi] == '*') {
            star = pi++;
            match = vi;
        } else if (star != std::string::npos) {
            pi = star + 1;
            vi = ++match;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*')
        ++pi;
    return pi == p.size();
}

MimeDatabaseResult load_mime_database(const MimeDatabaseOptions& options)
{
    MimeDatabaseResult result;
    const auto candidates = magic_source_candidates(options);
    for (const fs::path& candidate : candidates) {
        result.source_dir = candidate;
        std::map<std::string, MimeTypeEntry> by_mime;

        std::error_code ec;
        for (fs::recursive_directory_iterator it(candidate, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec)) {
            if (!it->is_regular_file(ec))
                continue;

            std::ifstream in(it->path(), std::ios::binary);
            if (!in)
                continue;

            std::string current_mime;
            std::string line;
            while (std::getline(in, line)) {
                const std::string trimmed = trim_ascii(line);
                if (trimmed.empty() || trimmed[0] == '#')
                    continue;
                if (is_top_level_magic_rule(trimmed))
                    current_mime.clear();
                if (const std::string mime = lower_ascii(directive_value(trimmed, "!:mime")); !mime.empty()) {
                    current_mime = mime;
                    auto& entry = by_mime[current_mime];
                    entry.mime_type = current_mime;
                    push_unique_path(entry.sources, it->path());
                    continue;
                }
                if (current_mime.empty())
                    continue;
                if (const std::string ext_value = directive_value(trimmed, "!:ext"); !ext_value.empty()) {
                    auto& entry = by_mime[current_mime];
                    entry.mime_type = current_mime;
                    for (const auto& ext : split_magic_extensions(ext_value))
                        push_unique(entry.extensions, ext);
                    push_unique_path(entry.sources, it->path());
                }
            }
        }

        if (ec) {
            result.error = ec.message();
            return result;
        }

        for (auto& [_, entry] : by_mime) {
            entry.kind = classify_media(entry.mime_type, entry.extensions);
            result.entries.push_back(std::move(entry));
        }
        result.ok = true;
        return result;
    }

    result.error = "could not find file(1) magic/Magdir source directory";
    return result;
}

std::vector<MimeTypeEntry> filter_mime_entries(const std::vector<MimeTypeEntry>& entries,
                                               std::string_view pattern,
                                               std::string_view kind,
                                               std::string_view extension)
{
    const std::string pat = pattern.empty() ? "*" : std::string(pattern);
    const std::string wanted_kind = lower_ascii(kind);
    const std::string wanted_ext = normalize_extension(extension);
    std::vector<MimeTypeEntry> out;

    for (const auto& entry : entries) {
        if (!wanted_kind.empty() && wanted_kind != media_kind_name(entry.kind))
            continue;
        if (!wanted_ext.empty() && !has_ext(entry.extensions, wanted_ext))
            continue;

        bool matched = wildcard_match(pat, entry.mime_type) ||
                       wildcard_match(pat, media_kind_name(entry.kind));
        if (!matched) {
            for (const auto& ext : entry.extensions) {
                if (wildcard_match(pat, ext) || wildcard_match(pat, ext.substr(1))) {
                    matched = true;
                    break;
                }
            }
        }
        if (matched)
            out.push_back(entry);
    }
    return out;
}

} // namespace media::probe
