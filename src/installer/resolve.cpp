#include "installer/resolve.hpp"

#include "installer/host.hpp"
#include "installer/vfs/vfs_spec.hpp"

#include "fs/glob_paths.hpp"

#include <algorithm>
#include <filesystem>
#include <string_view>

namespace pm::installer {

namespace fs = std::filesystem;

namespace {

constexpr const char* k_os =
#if defined(_WIN32)
    "win32";
#elif defined(__APPLE__)
    "darwin";
#else
    "linux";
#endif

struct TypeSubdirEntry { std::string_view type; std::string_view subdir; };
constexpr TypeSubdirEntry k_type_subdirs[] = {
    {"app-assets",          "assets"},
    {"app-extensions",      "extensions"},
    {"app-extensions:zip",  "extensions"},
    {"skills",              "skills"},
    {"mcp-settings",        "mcp"},
    {"commands",            "commands"},
    {"settings",            "settings"},
    {"prompts",             "prompts"},
    {"models",              "models"},
    {"docs",                "docs"},
    {"service-embeddings",  "service-embeddings"},
    {"gpo",                 "gpo"},
    {"gpo defaults/templates", "gpo"},
    {"sessions",            "sessions"},
    {"memories",            "memories"},
    {"model cache",         "model-cache"},
    {"model-cache",         "model-cache"},
    {"file assocs",         "file-assocs"},
    {"file-assocs",         "file-assocs"},
    {"keys/certs",          "keys"},
    {"keys",                "keys"},
    {"permissions",         "permissions"},
    {"chat-presets",        "chat-presets"},
    {"user-embeddings",     "user-embeddings"},
    {"codebase-memory",     "codebase-memory"},
};

std::string resolve_relative_to_var(const char* var_name,
                                    const std::string& raw,
                                    const VariableMap& vars,
                                    std::string* err)
{
    const auto it = vars.find(var_name);
    if (it == vars.end() || it->second.empty()) {
        if (err) *err = std::string(var_name) + " not set";
        return {};
    }
    const std::string rel = host::resolve_variables(raw, vars, err);
    return rel.empty() ? it->second : (fs::path(it->second) / rel).string();
}

} // namespace

const char* current_os_token() noexcept { return k_os; }

std::string type_subdir(const std::string& type)
{
    for (const auto& e : k_type_subdirs)
        if (e.type == type) return std::string(e.subdir);
    // Fallback: sanitize the type string itself.
    std::string s = type;
    std::replace(s.begin(), s.end(), ':', '-');
    std::replace(s.begin(), s.end(), '/', '-');
    std::replace(s.begin(), s.end(), ' ', '-');
    return s;
}

bool matches_pattern(const std::string& filename, const std::string& pattern)
{
    if (pattern.empty() || pattern == "**" || pattern == "**/*")
        return true;

    const auto star = pattern.find('*');
    if (star == std::string::npos)
        return filename == pattern; // exact match

    // "*.ext"  or  "prefix*suffix" style
    const std::string prefix = pattern.substr(0, star);
    const std::string suffix = pattern.substr(star + 1);

    if (!prefix.empty() && filename.rfind(prefix, 0) != 0)
        return false;
    if (!suffix.empty()) {
        if (suffix.size() > filename.size()) return false;
        if (filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0)
            return false;
    }
    return true;
}

bool matches_path_pattern(const std::string& rel_path, const std::string& pattern)
{
    if (pattern.empty() || pattern == "**" || pattern == "**/*")
        return true;

    const bool path_glob = pattern.find('/') != std::string::npos
                        || pattern.find("**") != std::string::npos;
    if (path_glob) {
        std::string norm = rel_path;
        std::replace(norm.begin(), norm.end(), '\\', '/');
        return media::path_matches_path_glob(norm, pattern);
    }

    const auto slash = rel_path.find_last_of("/\\");
    const std::string name = slash == std::string::npos
        ? rel_path : rel_path.substr(slash + 1);
    return matches_pattern(name, pattern);
}

namespace {

bool path_needs_glob_expand(const std::string& s)
{
    return media::has_glob_tokens(s) || s.find("**") != std::string::npos;
}

std::string glob_rel_base_dir(const std::string& pattern)
{
    std::string pat = pattern;
    std::replace(pat.begin(), pat.end(), '\\', '/');
    const std::size_t first_glob = pat.find_first_of("*?");
    const std::size_t base_end =
        pat.rfind('/', first_glob == std::string::npos ? std::string::npos : first_glob);
    if (base_end == std::string::npos)
        return ".";
    return pat.substr(0, base_end);
}

fs::path common_prefix_path(const std::vector<fs::path>& paths)
{
    if (paths.empty())
        return {};
    fs::path common = paths.front();
    for (std::size_t i = 1; i < paths.size(); ++i) {
        const fs::path& cur = paths[i];
        fs::path        next;
        auto            it_a = common.begin();
        auto            it_b = cur.begin();
        for (; it_a != common.end() && it_b != cur.end(); ++it_a, ++it_b) {
            if (*it_a != *it_b)
                break;
            next /= *it_a;
        }
        common = next;
        if (common.empty())
            break;
    }
    return common;
}

std::string resolve_raw_source_path(const Package& pkg,
                                    const VariableMap& vars,
                                    std::string* err)
{
    using pm::installer::host::resolve_variables;
    const std::string raw = pkg.source.path;
    switch (pkg.source.kind) {
    case SourceKind::DistReleaseBundle:
    case SourceKind::LocalDirCustom:
    case SourceKind::VfsRemote:
        return resolve_variables(raw, vars, err);
    case SourceKind::VfsPublicVersioned:
        return resolve_relative_to_var("VFS_PUBLIC_DIR", raw, vars, err);
    case SourceKind::VfsPrivateUser:
        return resolve_relative_to_var("VFS_USER_DIR", raw, vars, err);
    case SourceKind::CustomStore:
        if (err) *err = "source kind 'custom-store' is not yet implemented";
        return {};
    }
    return {};
}

} // namespace

std::string glob_path_prefix(const std::string& pattern)
{
    return glob_rel_base_dir(pattern);
}

std::string resolve_manifest_dependency_path(const std::string& raw,
                                             const std::string& parent_manifest_path,
                                             const VariableMap& vars,
                                             std::string* err)
{
    using pm::installer::host::resolve_variables;

    if (raw.empty()) {
        if (err) *err = "dependency path is empty";
        return {};
    }

    std::string resolve_err;
    std::string resolved = resolve_variables(raw, vars, &resolve_err);
    if (!resolve_err.empty()) {
        if (err) *err = resolve_err;
        return {};
    }
    if (resolved.empty()) {
        if (err) *err = "dependency path is empty after variable expansion: " + raw;
        return {};
    }

    std::error_code ec;
    fs::path p = fs::u8path(resolved);
    if (!p.is_absolute()) {
        fs::path base = fs::u8path(parent_manifest_path).parent_path();
        if (base.empty())
            base = ".";
        p = base / p;
    }
    fs::path canon = fs::weakly_canonical(p, ec);
    if (ec)
        canon = fs::absolute(p, ec).lexically_normal();
    return canon.string();
}

bool resolve_source(const Package& pkg,
                    const VariableMap& vars,
                    ResolvedSource& out,
                    std::string* err)
{
    out = {};

    if (!pkg.source.paths.empty()) {
        std::vector<std::string> files;
        std::vector<fs::path>    bases;
        std::string              first_path;

        for (const auto& raw : pkg.source.paths) {
            if (raw.empty())
                continue;
            std::string resolve_err;
            std::string path = host::resolve_variables(raw, vars, &resolve_err);
            if (!resolve_err.empty()) {
                if (err) *err = resolve_err;
                return false;
            }
            if (path.empty())
                continue;
            if (first_path.empty())
                first_path = path;
            if (vfs_spec::is_vfs_url(path)) {
                if (err) *err = "array sources do not support vfs:// URLs: " + path;
                return false;
            }

            if (path_needs_glob_expand(path)) {
                std::string gerr;
                std::vector<std::string> matches = media::expand_input_paths(path, gerr);
                if (!matches.empty()) {
                    files.insert(files.end(), matches.begin(), matches.end());
                }
                std::string base = glob_rel_base_dir(path);
                std::error_code ec;
                fs::path        base_abs = fs::absolute(fs::path(base), ec);
                bases.push_back(ec ? fs::path(base) : base_abs.lexically_normal());
                continue;
            }

            std::error_code ec;
            const fs::path p(path);
            if (!fs::exists(p, ec) || ec) {
                if (err) *err = "source path not found: " + path;
                return false;
            }
            if (fs::is_directory(p, ec) && !ec) {
                for (fs::recursive_directory_iterator it(p, ec), end; !ec && it != end; it.increment(ec)) {
                    if (it->is_regular_file(ec) && !ec)
                        files.push_back(it->path().string());
                }
                bases.push_back(fs::absolute(p, ec).lexically_normal());
                continue;
            }
            if (fs::is_regular_file(p, ec) && !ec) {
                const fs::path abs = fs::absolute(p, ec);
                files.push_back(abs.string());
                bases.push_back(abs.parent_path().lexically_normal());
                continue;
            }
        }

        out.path    = first_path;
        out.files   = std::move(files);
        out.globbed = true;
        const fs::path common = common_prefix_path(bases);
        out.rel_base = common.empty() ? std::string{} : common.lexically_normal().string();
        return true;
    }

    out.path = resolve_raw_source_path(pkg, vars, err);
    if (out.path.empty()) {
        if (err && err->empty())
            *err = "source path is empty";
        return false;
    }

    if (vfs_spec::is_vfs_url(out.path)) {
        vfs_spec::ParsedVfsUrl spec;
        if (!vfs_spec::parse_vfs_url(out.path, spec, err))
            return false;
        if (spec.server.empty()) {
            const auto it = vars.find("DEFAULT_VFS_SERVER");
            if (it == vars.end() || it->second.empty()) {
                if (err) *err = "DEFAULT_VFS_SERVER required for vfs:// URLs without a host "
                                  "(set via installer --config JSON)";
                return false;
            }
            out.vfs_server = it->second;
        } else {
            out.vfs_server = spec.server;
        }
        out.vfs_mount     = spec.mount;
        out.path          = spec.remote_path;
        out.globbed       = spec.globbed;
        out.is_vfs        = true;
        return true;
    }

    if (pkg.source.kind == SourceKind::VfsRemote) {
        out.globbed = path_needs_glob_expand(out.path);
        return true;
    }

    if (!path_needs_glob_expand(out.path)) {
        std::error_code ec;
        const fs::path p(out.path);
        if (fs::exists(p, ec) && !ec) {
            if (fs::is_directory(p, ec) && !ec)
                return true;
            if (fs::is_regular_file(p, ec) && !ec) {
                const fs::path abs = fs::absolute(p, ec);
                out.files.push_back(abs.string());
                out.rel_base = abs.parent_path().string();
                return true;
            }
        }
        if (err) *err = "source path not found: " + out.path;
        return false;
    }

    out.globbed = true;
    std::string gerr;
    out.files = media::expand_input_paths(out.path, gerr);
    if (out.files.empty()) {
        if (err) *err = gerr.empty() ? "source glob matched no files" : gerr;
        return false;
    }

    out.rel_base = glob_rel_base_dir(out.path);
    std::error_code ec;
    const fs::path base = fs::absolute(fs::path(out.rel_base), ec);
    if (!ec && !base.empty())
        out.rel_base = base.lexically_normal().string();
    return true;
}

std::string resolve_source_path(const Package& pkg,
                                const VariableMap& vars,
                                std::string* err)
{
    ResolvedSource src;
    if (!resolve_source(pkg, vars, src, err))
        return {};
    return src.path;
}

bool constraints_satisfied(const PackageConstraints& c)
{
    if (!c.os.empty()) {
        const bool os_ok = std::any_of(c.os.begin(), c.os.end(),
            [](const std::string& o) { return o == k_os; });
        if (!os_ok) return false;
    }
    // subscription and min_version checks require runtime data — not wired yet.
    return true;
}

std::string resolve_target_path(const Package& pkg,
                                const VariableMap& vars,
                                std::string* err)
{
    using pm::installer::host::resolve_variables;

    const std::string subdir = type_subdir(pkg.type);

    switch (pkg.target.kind) {
    case TargetKind::DefaultRoaming: {
        const auto it = vars.find("APP_DATA");
        if (it == vars.end() || it->second.empty()) {
            if (err) *err = "APP_DATA not set";
            return {};
        }
        return (fs::path(it->second) / subdir).string();
    }
    case TargetKind::Vfs: {
        const auto it = vars.find("VFS_USER_DIR");
        if (it == vars.end() || it->second.empty()) {
            if (err) *err = "VFS_USER_DIR not set";
            return {};
        }
        return (fs::path(it->second) / subdir).string();
    }
    case TargetKind::VfsRemote:
        // Remote directory prefix inside the mount; may legitimately be empty
        // (mount root).
        return resolve_variables(pkg.target.path, vars, err);
    case TargetKind::LocalDirCustom:
    case TargetKind::Unc: {
        if (pkg.target.path.empty()) {
            if (err) *err = "target.path is required for kind '" +
                            std::string(pkg.target.kind == TargetKind::Unc ? "unc" : "local-dir-custom") + "'";
            return {};
        }
        return resolve_variables(pkg.target.path, vars, err);
    }
    }
    return {};
}

namespace {

#if defined(_WIN32)
std::string shell_quote_arg(const std::string& arg)
{
    std::string out = "\"";
    for (char ch : arg) {
        if (ch == '"' || ch == '\\')
            out.push_back('\\');
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}
#else
std::string shell_quote_arg(const std::string& arg)
{
    std::string out = "'";
    for (char ch : arg) {
        if (ch == '\'')
            out += "'\\''";
        else
            out.push_back(ch);
    }
    out.push_back('\'');
    return out;
}
#endif

std::string build_argv_command(const std::string& exe, const std::vector<std::string>& args)
{
    if (exe.empty())
        return {};
    std::string line = shell_quote_arg(exe);
    for (const auto& arg : args) {
        line.push_back(' ');
        line += shell_quote_arg(arg);
    }
    return line;
}

} // namespace

bool resolve_shell_action(const Package& pkg,
                          const VariableMap& vars,
                          PackageShell& out,
                          std::string* err)
{
    using pm::installer::host::resolve_variables;

    out = pkg.shell;

    if (out.command.empty() && !pkg.source.path.empty())
        out.command = pkg.source.path;
    if (out.cwd.empty() && !pkg.target.path.empty())
        out.cwd = pkg.target.path;

    std::string resolve_err;
    if (!out.command.empty())
        out.command = resolve_variables(out.command, vars, &resolve_err);
    if (!resolve_err.empty()) {
        if (err) *err = resolve_err;
        return false;
    }

    if (!out.cwd.empty()) {
        out.cwd = resolve_variables(out.cwd, vars, &resolve_err);
        if (!resolve_err.empty()) {
            if (err) *err = resolve_err;
            return false;
        }
    }

    if (out.mode == "argv") {
        std::string exe = out.command;
        std::vector<std::string> resolved_args;
        resolved_args.reserve(out.args.size());
        for (const auto& arg : out.args) {
            resolved_args.push_back(resolve_variables(arg, vars, &resolve_err));
            if (!resolve_err.empty()) {
                if (err) *err = resolve_err;
                return false;
            }
        }
        out.command = build_argv_command(exe, resolved_args);
    }

    if (out.command.empty()) {
        if (err) *err = "shell command is empty";
        return false;
    }
    return true;
}

} // namespace pm::installer
