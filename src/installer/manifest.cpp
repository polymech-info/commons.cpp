#include "installer/manifest.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>

namespace pm::installer {

namespace {

SourceKind parse_source_kind(std::string_view s)
{
    if (s == "dist-release-bundle")  return SourceKind::DistReleaseBundle;
    if (s == "vfs-public-versioned") return SourceKind::VfsPublicVersioned;
    if (s == "vfs-private-user")     return SourceKind::VfsPrivateUser;
    if (s == "local-dir-custom")     return SourceKind::LocalDirCustom;
    if (s == "vfs-remote")           return SourceKind::VfsRemote;
    if (s == "custom-store")         return SourceKind::CustomStore;
    return SourceKind::DistReleaseBundle;
}

TargetKind parse_target_kind(std::string_view s)
{
    if (s == "default-roaming")  return TargetKind::DefaultRoaming;
    if (s == "local-dir-custom") return TargetKind::LocalDirCustom;
    if (s == "vfs")              return TargetKind::Vfs;
    if (s == "vfs-remote")       return TargetKind::VfsRemote;
    if (s == "unc")              return TargetKind::Unc;
    return TargetKind::DefaultRoaming;
}

OnExist parse_on_exist(std::string_view s)
{
    if (s == "overwrite")        return OnExist::Overwrite;
    if (s == "update-if-newer")  return OnExist::UpdateIfNewer;
    if (s == "error")            return OnExist::Error;
    return OnExist::Skip; // "skip" is the default
}

PackageVfsDownload parse_vfs_download(const nlohmann::json& j)
{
    PackageVfsDownload o;
    if (j.contains("progress") && j["progress"].is_boolean()) {
        o.progress_set = true;
        o.progress     = j["progress"].get<bool>();
    }
    if (j.contains("resume") && j["resume"].is_boolean()) {
        o.resume_set = true;
        o.resume     = j["resume"].get<bool>();
    }
    if (j.contains("retries") && j["retries"].is_number_integer()) {
        o.retries_set = true;
        o.retries     = j["retries"].get<int>();
    }
    if (j.contains("endpoint") && j["endpoint"].is_string()) {
        o.endpoint_set = true;
        o.endpoint     = j["endpoint"].get<std::string>();
    }
    return o;
}

PackageSource parse_source(const nlohmann::json& j)
{
    PackageSource s;
    if (j.contains("kind") && j["kind"].is_string())
        s.kind = parse_source_kind(j["kind"].get<std::string>());
    if (j.contains("path")) {
        if (j["path"].is_string()) {
            s.path = j["path"].get<std::string>();
        } else if (j["path"].is_array()) {
            for (const auto& v : j["path"]) {
                if (v.is_string())
                    s.paths.push_back(v.get<std::string>());
            }
        }
    }
    if (j.contains("pattern") && j["pattern"].is_string())
        s.pattern = j["pattern"].get<std::string>();
    if (j.contains("exclude")) {
        if (j["exclude"].is_string()) {
            s.exclude.push_back(j["exclude"].get<std::string>());
        } else if (j["exclude"].is_array()) {
            for (const auto& v : j["exclude"])
                if (v.is_string()) s.exclude.push_back(v.get<std::string>());
        }
    }
    if (j.contains("mount") && j["mount"].is_string())
        s.mount = j["mount"].get<std::string>();
    return s;
}

PackageTarget parse_target(const nlohmann::json& j)
{
    PackageTarget t;
    if (j.contains("kind") && j["kind"].is_string())
        t.kind = parse_target_kind(j["kind"].get<std::string>());
    if (j.contains("path") && j["path"].is_string())
        t.path = j["path"].get<std::string>();
    if (j.contains("mount") && j["mount"].is_string())
        t.mount = j["mount"].get<std::string>();
    return t;
}

PackageConstraints parse_constraints(const nlohmann::json& j)
{
    PackageConstraints c;
    auto read_list = [&](const char* key, std::vector<std::string>& out) {
        if (!j.contains(key) || !j[key].is_array()) return;
        for (const auto& v : j[key])
            if (v.is_string()) out.push_back(v.get<std::string>());
    };
    read_list("os",           c.os);
    read_list("subscription", c.subscription);
    if (j.contains("min_version") && j["min_version"].is_string())
        c.min_version = j["min_version"].get<std::string>();
    return c;
}

PackageShell parse_shell(const nlohmann::json& j)
{
    PackageShell s;
    if (j.contains("command") && j["command"].is_string())
        s.command = j["command"].get<std::string>();
    if (j.contains("cwd") && j["cwd"].is_string())
        s.cwd = j["cwd"].get<std::string>();
    if (j.contains("shell") && j["shell"].is_string())
        s.shell = j["shell"].get<std::string>();
    if (j.contains("mode") && j["mode"].is_string())
        s.mode = j["mode"].get<std::string>();
    if (j.contains("timeout_ms") && j["timeout_ms"].is_number_integer())
        s.timeout_ms = j["timeout_ms"].get<int>();
    if (j.contains("args") && j["args"].is_array()) {
        for (const auto& arg : j["args"]) {
            if (arg.is_string())
                s.args.push_back(arg.get<std::string>());
        }
    }
    return s;
}

PackageSign parse_sign(const nlohmann::json& j)
{
    PackageSign s;
    auto str = [&](const char* key, std::string& out) {
        if (j.contains(key) && j[key].is_string())
            out = j[key].get<std::string>();
    };
    str("uri",        s.uri);
    str("type",       s.doc_type);
    str("trust",      s.trust);
    str("provider",   s.provider);
    str("signer",     s.signer);
    str("version",    s.version);
    // "source" (string) is the preferred key; "config_dir" is the legacy alias.
    if (j.contains("source") && j["source"].is_string())
        s.config_dir = j["source"].get<std::string>();
    else
        str("config_dir", s.config_dir);
    str("key_dir",    s.key_dir);
    if (j.contains("mask")) {
        if (j["mask"].is_string()) {
            s.mask = j["mask"].get<std::string>();
        } else if (j["mask"].is_array()) {
            std::string joined;
            for (const auto& v : j["mask"]) {
                if (!v.is_string()) continue;
                if (!joined.empty()) joined.push_back(',');
                joined += v.get<std::string>();
            }
            s.mask = std::move(joined);
        }
    }
    if (j.contains("verify") && j["verify"].is_boolean())
        s.verify = j["verify"].get<bool>();
    if (j.contains("encrypt") && j["encrypt"].is_boolean())
        s.encrypt = j["encrypt"].get<bool>();
    if (j.contains("strip_keys") && j["strip_keys"].is_boolean())
        s.strip_keys = j["strip_keys"].get<bool>();
    if (j.contains("deleteSource") && j["deleteSource"].is_boolean())
        s.delete_source = j["deleteSource"].get<bool>();
    return s;
}

// A before/after hook is an ordinary verb package: it carries a verb, optional
// source (standalone use), and the sign/encrypt option bag.  `sign_defaults` is
// merged JSON-level by the caller before this runs (hook keys win).
std::string trim_copy(std::string s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    return s;
}

std::int64_t parse_ttl_seconds(const nlohmann::json& v)
{
    if (v.is_number_integer())
        return std::max<std::int64_t>(0, v.get<std::int64_t>());
    if (v.is_number_unsigned())
        return static_cast<std::int64_t>(v.get<std::uint64_t>());
    if (!v.is_string())
        return 0;

    std::string s = trim_copy(v.get<std::string>());
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (s.empty())
        return 0;

    std::size_t i = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])))
        ++i;
    if (i == 0)
        return 0;

    std::int64_t n = 0;
    try {
        n = std::stoll(s.substr(0, i));
    } catch (...) {
        return 0;
    }
    if (n < 0)
        return 0;

    std::string unit = trim_copy(s.substr(i));
    if (unit.empty() || unit == "s" || unit == "sec" || unit == "secs"
        || unit == "second" || unit == "seconds")
        return n;
    if (unit == "m" || unit == "min" || unit == "mins" || unit == "minute" || unit == "minutes")
        return n * 60;
    if (unit == "h" || unit == "hr" || unit == "hrs" || unit == "hour" || unit == "hours")
        return n * 3600;
    if (unit == "d" || unit == "day" || unit == "days")
        return n * 86400;
    return 0;
}

Package parse_hook(const nlohmann::json& j)
{
    Package h;
    if (j.contains("id") && j["id"].is_string())
        h.id = j["id"].get<std::string>();
    if (j.contains("verb") && j["verb"].is_string())
        h.verb = j["verb"].get<std::string>();
    if (j.contains("source") && j["source"].is_object())
        h.source = parse_source(j["source"]);
    h.sign = parse_sign(j);
    return h;
}

} // namespace

std::string effective_verb(const Package& pkg)
{
    if (!pkg.verb.empty())
        return pkg.verb;
    if (pkg.target.kind == TargetKind::VfsRemote)
        return "vfs_push";
    if (pkg.source.kind == SourceKind::VfsRemote)
        return "vfs_pull";
    return "copy";
}

std::optional<Manifest> parse_manifest(const nlohmann::json& j,
                                       const std::string&    source_path,
                                       std::string*          err)
{
    try {
        if (!j.is_object()) {
            if (err) *err = "manifest must be a JSON object";
            return std::nullopt;
        }

        Manifest m;
        m.manifest_path = source_path;

        if (j.contains("version") && j["version"].is_number_integer())
            m.version = j["version"].get<int>();
        if (j.contains("ttl"))
            m.ttl_sec = parse_ttl_seconds(j["ttl"]);
        if (j.contains("forgiving") && j["forgiving"].is_boolean())
            m.forgiving = j["forgiving"].get<bool>();
        if (j.contains("auth") && j["auth"].is_string()) {
            const std::string auth = j["auth"].get<std::string>();
            m.auth_none = auth == "none" || auth == "public";
        }

        // Top-level manifest dependencies (run before any packages).
        auto read_dep_array = [&](const char* key, std::vector<std::string>& out) {
            if (!j.contains(key) || !j[key].is_array()) return;
            for (const auto& v : j[key])
                if (v.is_string() && !v.get<std::string>().empty())
                    out.push_back(v.get<std::string>());
        };
        read_dep_array("dependencies", m.dependencies_);
        read_dep_array("requires",     m.dependencies_);

        // Support: full "packages" array, single-package shorthand, or deps-only (no packages).
        const nlohmann::json* pkg_list = nullptr;
        nlohmann::json        single_wrap;
        if (j.contains("packages") && j["packages"].is_array()) {
            pkg_list = &j["packages"];
        } else if (j.contains("id") && j.contains("type")) {
            // Single-package shorthand: the root object IS the package.
            single_wrap = nlohmann::json::array({j});
            pkg_list = &single_wrap;
        } else if (!m.dependencies_.empty()) {
            // Deps-only manifest: no packages needed.
            return m;
        } else {
            if (err) *err = "manifest must contain a 'packages' array or be a single package object";
            return std::nullopt;
        }

        for (const auto& item : *pkg_list) {
            if (!item.is_object()) continue;
            Package pkg;
            if (item.contains("id") && item["id"].is_string())
                pkg.id = item["id"].get<std::string>();
            if (item.contains("type") && item["type"].is_string())
                pkg.type = item["type"].get<std::string>();
            if (item.contains("description") && item["description"].is_string())
                pkg.description = item["description"].get<std::string>();
            if (item.contains("verb") && item["verb"].is_string())
                pkg.verb = item["verb"].get<std::string>();
            if (item.contains("source")) {
                if (item["source"].is_object()) {
                    pkg.source = parse_source(item["source"]);
                } else if (item["source"].is_array()) {
                    pkg.source.kind = SourceKind::LocalDirCustom;
                    for (const auto& v : item["source"]) {
                        if (v.is_string())
                            pkg.source.paths.push_back(v.get<std::string>());
                    }
                }
            }
            if (item.contains("target") && item["target"].is_object())
                pkg.target = parse_target(item["target"]);
            if (item.contains("shell") && item["shell"].is_object())
                pkg.shell = parse_shell(item["shell"]);
            if (item.contains("vfs_download") && item["vfs_download"].is_object())
                pkg.vfs_download = parse_vfs_download(item["vfs_download"]);
            if (item.contains("on_exist") && item["on_exist"].is_string())
                pkg.on_exist = parse_on_exist(item["on_exist"].get<std::string>());
            if (item.contains("clear") && item["clear"].is_boolean())
                pkg.clear = item["clear"].get<bool>();
            if (item.contains("optional") && item["optional"].is_boolean())
                pkg.optional = item["optional"].get<bool>();
            if (item.contains("constraints") && item["constraints"].is_object())
                pkg.constraints = parse_constraints(item["constraints"]);
            auto read_dep_list = [&](const char* key) {
                if (!item.contains(key) || !item[key].is_array())
                    return;
                for (const auto& r : item[key]) {
                    if (!r.is_string())
                        continue;
                    const std::string v = r.get<std::string>();
                    if (v.empty())
                        continue;
                    pkg.dependencies_.push_back(v);
                }
            };
            read_dep_list("dependencies");
            read_dep_list("requires");

            // sign/encrypt options on a standalone sign package.
            if (item.contains("sign") && item["sign"].is_object())
                pkg.sign = parse_sign(item["sign"]);
            else if (pkg.verb == "sign" || pkg.verb == "encrypt")
                pkg.sign = parse_sign(item);

            // before/after hooks: merge package-level sign_defaults JSON-level
            // (hook keys win), then parse.  mask/source are never defaulted.
            nlohmann::json sign_defaults = nlohmann::json::object();
            if (item.contains("sign_defaults") && item["sign_defaults"].is_object())
                sign_defaults = item["sign_defaults"];
            auto read_hooks = [&](const char* key, std::vector<Package>& out) {
                if (!item.contains(key) || !item[key].is_array())
                    return;
                for (const auto& h : item[key]) {
                    if (!h.is_object())
                        continue;
                    nlohmann::json eff = sign_defaults;
                    eff.update(h);
                    out.push_back(parse_hook(eff));
                }
            };
            read_hooks("before", pkg.before_);
            read_hooks("after", pkg.after_);

            m.packages.push_back(std::move(pkg));
        }

        return m;
    } catch (const std::exception& ex) {
        if (err) *err = std::string("manifest parse error: ") + ex.what();
        return std::nullopt;
    }
}

std::optional<Manifest> load_manifest(const std::string& path, std::string* err)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (err) *err = "cannot open manifest: " + path;
        return std::nullopt;
    }
    try {
        const auto j = nlohmann::json::parse(f);
        return parse_manifest(j, path, err);
    } catch (const std::exception& ex) {
        if (err) *err = std::string("JSON parse error in '") + path + "': " + ex.what();
        return std::nullopt;
    }
}

} // namespace pm::installer
