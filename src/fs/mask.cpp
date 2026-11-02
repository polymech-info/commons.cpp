#include "fs/mask.hpp"

#include "fs/path_sanitizer.hpp"
#include "fs/dir_pattern.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

namespace pm::filters {
namespace {

namespace fs = std::filesystem;

std::string generic_of(const fs::path& path)
{
    std::string out = media::path::path_to_generic_utf8(path);
    if (out.size() >= 2 && out[1] == ':')
        out[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(out[0])));
    while (out.size() > 3 && out.back() == '/')
        out.pop_back();
    return out;
}

std::string relative_to(std::string_view root, std::string_view path)
{
    if (path.size() < root.size())
        return {};
#if defined(_WIN32)
    for (std::size_t i = 0; i < root.size(); ++i) {
        const auto ca = static_cast<unsigned char>(root[i]);
        const auto cb = static_cast<unsigned char>(path[i]);
        if (std::tolower(ca) != std::tolower(cb))
            return {};
    }
#else
    if (path.compare(0, root.size(), root) != 0)
        return {};
#endif
    if (path.size() == root.size())
        return {};
    if (path[root.size()] != '/')
        return {};
    return std::string(path.substr(root.size() + 1));
}

struct Slot {
    bool present = false;
    std::uintmax_t size = 0;
    fs::file_time_type mtime{};
    PatternList list;
};

std::mutex g_mu;
std::unordered_map<std::string, Slot> g_cache;

PatternList load_dir(const fs::path& dir, const char* name)
{
    const std::string key = generic_of(dir) + "\n" + name;
    const fs::path file = dir / name;
    std::error_code ec;
    const bool present = fs::is_regular_file(file, ec) && !ec;
    const auto mtime = present ? fs::last_write_time(file, ec) : fs::file_time_type{};
    const auto size = present ? fs::file_size(file, ec) : 0;
    std::lock_guard lock(g_mu);
    Slot& slot = g_cache[key];
    if (slot.present == present && slot.size == size && slot.mtime == mtime)
        return slot.list;
    slot.present = present;
    slot.size = size;
    slot.mtime = mtime;
    slot.list = {};
    if (!present)
        return slot.list;
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        slot.present = false;
        return {};
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string text = buf.str();
    if (text.size() > 1024 * 1024)
        return slot.list;
    slot.list = parse_gitignore(text);
    return slot.list;
}

bool has_git_dir(const fs::path& dir)
{
    std::error_code ec;
    return fs::is_directory(dir / ".git", ec) && !ec;
}

} // namespace

const char* mask_file_name(MaskKind kind) noexcept
{
    switch (kind) {
    case MaskKind::Gitignore:
        return ".gitignore";
    case MaskKind::Ignore:
        return ".ignore";
    case MaskKind::None:
        break;
    }
    return nullptr;
}

bool parse_mask_kind(std::string_view text, MaskKind& out)
{
    if (text == "gitignore" || text == ".gitignore") {
        out = MaskKind::Gitignore;
        return true;
    }
    if (text == "ignore" || text == ".ignore") {
        out = MaskKind::Ignore;
        return true;
    }
    if (text == "none" || text == "off") {
        out = MaskKind::None;
        return true;
    }
    return false;
}

bool is_ignored_named(std::string_view path, bool is_dir, std::string_view file_name)
{
    if (file_name.empty() || path.empty())
        return false;
    if (path.find("://") != std::string_view::npos)
        return false;

    const std::string name(file_name);
    std::error_code ec;
    const fs::path raw = media::path::path_from_utf8(path);
    fs::path abs = fs::absolute(raw, ec);
    if (ec)
        abs = raw;
    const std::string full = generic_of(abs);
    fs::path cursor = abs.parent_path();
    for (int depth = 0; depth < 64 && !cursor.empty(); ++depth) {
        const PatternList list = load_dir(cursor, name.c_str());
        const std::string rel = relative_to(generic_of(cursor), full);
        if (!rel.empty()) {
            if (const PathPattern* hit = last_match(list, rel, is_dir))
                return (hit->flags & PatternNegative) == 0;
        }
        if (has_git_dir(cursor))
            break;
        const fs::path parent = cursor.parent_path();
        if (parent == cursor)
            break;
        cursor = parent;
    }
    return false;
}

bool is_ignored(std::string_view path, bool is_dir, MaskKind kind)
{
    const char* name = mask_file_name(kind);
    if (name == nullptr)
        return false;
    return is_ignored_named(path, is_dir, name);
}

} // namespace pm::filters
