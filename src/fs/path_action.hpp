#pragma once
//
// path_action — delete a file permanently or send it to the Recycle Bin.
// Header-only so CLI / GUI / xblox can call it without an extra lib TU.
//
#include <cctype>
#include "fs/path_sanitizer.hpp"
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include "string/string_utils.hpp"
#endif

namespace media {

enum class PathActionKind {
    None       = 0,
    Delete     = 1, // permanent unlink
    RecycleBin = 2, // Windows Recycle Bin (FOF_ALLOWUNDO)
};

struct PathActionResult {
    bool        ok = false;
    bool        dry_run = false;
    PathActionKind kind = PathActionKind::None;
    std::string path;
    std::string error;
};

inline const char* path_action_kind_name(PathActionKind kind) noexcept
{
    switch (kind) {
    case PathActionKind::None:       return "none";
    case PathActionKind::Delete:     return "delete";
    case PathActionKind::RecycleBin: return "recyclebin";
    }
    return "none";
}

/// Accepts none | delete | recyclebin | recycle | trash. Empty → None.
inline bool parse_path_action(const std::string& text, PathActionKind& out,
                              std::string* error = nullptr)
{
    if (error)
        error->clear();
    std::string t = text;
    while (!t.empty() && std::isspace(static_cast<unsigned char>(t.front())))
        t.erase(t.begin());
    while (!t.empty() && std::isspace(static_cast<unsigned char>(t.back())))
        t.pop_back();
    t = media::strutil::lower_ascii(std::move(t));

    if (t.empty() || t == "none" || t == "list") {
        out = PathActionKind::None;
        return true;
    }
    if (t == "delete" || t == "unlink" || t == "remove") {
        out = PathActionKind::Delete;
        return true;
    }
    if (t == "recyclebin" || t == "recycle" || t == "trash") {
        out = PathActionKind::RecycleBin;
        return true;
    }
    if (error)
        *error = "path_action: unknown action '" + text + "' (none|delete|recyclebin)";
    return false;
}

#if defined(_WIN32)
inline bool path_action_recycle_win32(const std::filesystem::path& file, std::string& error)
{
    std::wstring w = file.lexically_normal().wstring();
    for (wchar_t& c : w) {
        if (c == L'/')
            c = L'\\';
    }
    if (w.empty()) {
        error = "path_action: empty path";
        return false;
    }

    std::vector<wchar_t> from(w.begin(), w.end());
    from.push_back(L'\0');
    from.push_back(L'\0');

    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = from.data();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    const int rc = SHFileOperationW(&op);
    if (rc != 0 || op.fAnyOperationsAborted) {
        error = "path_action: Recycle Bin failed (code " + std::to_string(rc) + ")";
        return false;
    }
    return true;
}
#endif

/// No-op when kind is None. `dry_run` reports success without touching disk.
inline PathActionResult apply_path_action(const std::string& path,
                                          PathActionKind kind,
                                          bool dry_run = false)
{
    PathActionResult r;
    r.kind = kind;
    r.path = path;
    r.dry_run = dry_run;

    if (kind == PathActionKind::None) {
        r.ok = true;
        return r;
    }
    if (path.empty()) {
        r.error = "path_action: empty path";
        return r;
    }

    std::error_code ec;
    const std::filesystem::path file = media::path::path_from_utf8(path);
    if (!std::filesystem::is_regular_file(file, ec) || ec) {
        r.error = "path_action: not a regular file";
        return r;
    }

    if (dry_run) {
        r.ok = true;
        return r;
    }

    if (kind == PathActionKind::Delete) {
        std::filesystem::remove(file, ec);
        if (ec) {
            r.error = "path_action: delete failed: " + ec.message();
            return r;
        }
        r.ok = true;
        return r;
    }

#if defined(_WIN32)
    r.ok = path_action_recycle_win32(file, r.error);
#else
    r.error = "path_action: recyclebin is only supported on Windows; use delete";
#endif
    return r;
}

} // namespace media
