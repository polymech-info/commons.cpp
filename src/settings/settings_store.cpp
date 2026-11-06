#include "settings/settings_store.hpp"
#include "fs/path_sanitizer.hpp"

#if !defined(_WIN32)

#include "process/app_exe_directory.hpp"
#include "settings/chat_settings_schema.hpp"
#include "settings/settings_portable.hpp"
#include "ui_defaults.hpp"

#include <cstdlib>
#include <fstream>
#include <functional>
#include <mutex>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace media::settings {

fs::path get_config_dir()
{
    fs::path dir = media::portable_settings::settings_pixelwiz_profile_dir();
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

fs::path default_branded_config_dir()
{
    return media::portable_settings::settings_pixelwiz_profile_dir();
}

fs::path get_models_dir()
{
    return media::ui_defaults::effective_models_dir();
}

fs::path get_temp_dir()
{
    const fs::path dir = get_config_dir() / "temp";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

fs::path get_logs_dir()
{
    const fs::path dir = get_config_dir() / "logs";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

fs::path get_embedding_models_dir()
{
    const fs::path exe = media::app::exe_parent_directory();
    if (exe.empty())
        return {};
    std::vector<fs::path> candidates;
    media::app::append_bundled_models_candidates(candidates, exe);
    std::error_code ec;
    for (const auto& candidate : candidates) {
        if (!fs::is_directory(candidate, ec) || ec)
            continue;
        const fs::path canon = fs::weakly_canonical(candidate, ec);
        if (!ec && !canon.empty())
            return canon;
    }
    return {};
}

fs::path get_user_desktop_dir()
{
    const char* home = std::getenv("HOME");
    if (!home || !*home)
        return {};
    return media::path::path_from_utf8(home) / "Desktop";
}

void set_config_dir_override(const fs::path& dir)
{
    media::portable_settings::set_profile_dir_override(dir);
}

void maybe_auto_set_config_dir_from_exe_roaming()
{
    std::error_code ec;
    const fs::path profile_json = media::portable_settings::settings_pixelwiz_profile_json_path();
    if (fs::is_regular_file(profile_json, ec) && !ec)
        return;
    const fs::path bundled = media::app::exe_bundled_roaming_directory();
    if (bundled.empty())
        return;
    const fs::path bundled_settings = bundled / "settings.json";
    if (!fs::is_regular_file(bundled_settings, ec) || ec)
        return;
    media::portable_settings::set_profile_dir_override(bundled);
}

fs::path get_settings_json_path()
{
    return media::portable_settings::settings_pixelwiz_profile_json_path();
}

fs::path get_command_json_path()
{
    return get_config_dir() / "commands.json";
}

fs::path get_daemon_json_path()
{
    return get_config_dir() / "daemon.json";
}

fs::path command_cache_watch_path()
{
    return get_command_json_path();
}

fs::path get_settings_effective_read_path()
{
    return get_settings_json_path();
}

bool has_settings_read_path_override()
{
    return false;
}

bool load_settings_utf8(std::string& out_json, std::string& err_out)
{
    out_json.clear();
    err_out.clear();
    json root;
    if (!media::portable_settings::read_settings_profile_json(root, err_out))
        return false;
    out_json = root.dump();
    return true;
}

bool load_settings_root(SettingsRootSnapshot& out_root, std::string& err_out)
{
    out_root.reset();
    json root;
    if (!media::portable_settings::read_settings_profile_json(root, err_out))
        return false;
    if (!root.is_object())
        root = json::object();
    out_root = std::make_shared<const json>(std::move(root));
    return true;
}

bool save_settings_utf8(const std::string& utf8_json, std::string& err_out)
{
    err_out.clear();
    try {
        json root = json::parse(utf8_json.empty() ? "{}" : utf8_json);
        if (!root.is_object()) {
            err_out = "settings JSON root must be an object";
            return false;
        }
        return media::portable_settings::write_settings_profile_json(root, err_out);
    } catch (const std::exception& e) {
        err_out = std::string("settings JSON parse: ") + e.what();
        return false;
    }
}

bool load_command_json_utf8(std::string& out_json, std::string& err_out)
{
    out_json.clear();
    err_out.clear();
    const fs::path p = get_command_json_path();
    std::error_code ec;
    if (!fs::is_regular_file(p, ec) || ec)
        return true;
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        err_out = "failed to read " + media::path::path_to_utf8(p);
        return false;
    }
    out_json.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool save_command_json_utf8(const std::string& utf8_json, std::string& err_out)
{
    err_out.clear();
    const fs::path p = get_command_json_path();
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    if (ec) {
        err_out = "create_directories: " + ec.message();
        return false;
    }
    // Write to a sibling temp file and rename over the target so a crash or a
    // concurrent reader never observes a truncated document.
    const fs::path tmp = p.parent_path()
        / (media::path::path_to_utf8(p.filename()) + ".tmp-" + std::to_string(static_cast<unsigned long>(::getpid())));
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err_out = "failed to write " + media::path::path_to_utf8(tmp);
            return false;
        }
        out << utf8_json;
        out.flush();
        if (!out.good()) {
            err_out = "short write " + media::path::path_to_utf8(tmp);
            out.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
    fs::rename(tmp, p, ec);
    if (ec) {
        err_out = "atomic replace failed for " + media::path::path_to_utf8(p) + ": " + ec.message();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

std::mutex& command_document_mutex()
{
    static std::mutex m;
    return m;
}

bool update_command_json_utf8(const std::function<bool(std::string& utf8_json, std::string& err)>& mutate,
                              std::string& err_out)
{
    std::lock_guard<std::mutex> lock(command_document_mutex());
    std::string doc;
    if (!load_command_json_utf8(doc, err_out))
        return false;
    if (!mutate(doc, err_out))
        return false;
    return save_command_json_utf8(doc, err_out);
}

bool export_settings_file(const fs::path& path, bool encrypted, std::string& err_out)
{
    if (encrypted) {
        err_out = "--encrypted local-profile export is only supported on Windows; use --archive or plaintext export";
        return false;
    }
    json root;
    if (!media::portable_settings::read_profile_direct(root, err_out))
        return false;
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        err_out = "create_directories: " + ec.message();
        return false;
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        err_out = "failed to write " + media::path::path_to_utf8(path);
        return false;
    }
    out << root.dump(2);
    return out.good();
}

bool import_settings_file(const fs::path& path, std::string& err_out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err_out = "failed to read " + media::path::path_to_utf8(path);
        return false;
    }
    try {
        json root;
        in >> root;
        if (!root.is_object()) {
            err_out = "settings JSON root must be an object";
            return false;
        }
        return media::portable_settings::write_settings_profile_json(root, err_out);
    } catch (const std::exception& e) {
        err_out = std::string("settings JSON parse: ") + e.what();
        return false;
    }
}

bool load_subtree(const std::string& key, json& out, std::string& err)
{
    out = json();
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    if (root->contains(key))
        out = (*root)[key];
    return true;
}

bool mutate_settings_root(const char* /*context*/, const SettingsRootMutator& mutator, std::string& err)
{
    json root;
    if (!media::portable_settings::read_settings_profile_json(root, err))
        return false;
    if (!root.is_object())
        root = json::object();
    if (!mutator(root, err))
        return false;
    return media::portable_settings::write_settings_profile_json(root, err);
}

bool save_subtree(const std::string& key, const json& value, std::string& err)
{
    return mutate_settings_root(
        "save_subtree",
        [&](json& root, std::string&) {
            root[key] = value;
            return true;
        },
        err);
}

bool merge_subtree_object(const std::string& key, const json& fields, std::string& err)
{
    if (!fields.is_object()) {
        err = "merge_subtree_object fields must be object";
        return false;
    }
    json current;
    if (!load_subtree(key, current, err))
        return false;
    if (!current.is_object())
        current = json::object();
    for (auto it = fields.begin(); it != fields.end(); ++it)
        current[it.key()] = it.value();
    return save_subtree(key, current, err);
}

bool load_providers(ProviderMap& out, std::string& err)
{
    return media::portable_settings::load_providers(out, err);
}

bool save_providers(const ProviderMap& providers, std::string& err)
{
    json root;
    if (!media::portable_settings::read_settings_profile_json(root, err))
        return false;
    if (!root.is_object())
        root = json::object();
    json jp = json::object();
    for (const auto& kv : providers) {
        json row = json::object();
        if (!kv.second.api_key.empty()) row["api_key"] = kv.second.api_key;
        if (!kv.second.base_url.empty()) row["base_url"] = kv.second.base_url;
        if (!kv.second.default_model.empty()) row["default_model"] = kv.second.default_model;
        jp[kv.first] = std::move(row);
    }
    root["providers"] = std::move(jp);
    root.erase("active_provider");
    return media::portable_settings::write_settings_profile_json(root, err);
}

bool load_chat_provider(ChatProviderSettings& out, std::string& err)
{
    return media::portable_settings::load_chat_provider(out, err);
}

bool save_chat_provider(const ChatProviderSettings& s, std::string& err)
{
    json root;
    if (!media::portable_settings::read_settings_profile_json(root, err))
        return false;
    if (!root.is_object())
        root = json::object();
    root["chat"] = media::settings_schema::chat_provider_settings_json(s);
    return media::portable_settings::write_settings_profile_json(root, err);
}

bool load_bookmarks(std::vector<BookmarkItem>& out, std::string& err)
{
    out.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::bookmarks, j, err))
        return false;
    if (!j.is_object() || !j.contains("items") || !j["items"].is_array())
        return true;
    for (const auto& el : j["items"]) {
        if (!el.is_object())
            continue;
        if (!el.contains("kind") || !el["kind"].is_string())
            continue;
        if (!el.contains("path") || !el["path"].is_string())
            continue;
        BookmarkItem item;
        item.kind = el["kind"].get<std::string>();
        item.path = el["path"].get<std::string>();
        if (item.kind.empty() || item.path.empty())
            continue;
        if (el.contains("node_kind") && el["node_kind"].is_string())
            item.node_kind = el["node_kind"].get<std::string>();
        if (el.contains("label") && el["label"].is_string())
            item.label = el["label"].get<std::string>();
        if (el.contains("searchable") && el["searchable"].is_boolean())
            item.searchable = el["searchable"].get<bool>();
        if (el.contains("share") && el["share"].is_boolean())
            item.share = el["share"].get<bool>();
        out.push_back(std::move(item));
    }
    return true;
}

bool save_bookmarks(const std::vector<BookmarkItem>& items, std::string& err)
{
    json arr = json::array();
    for (const auto& item : items) {
        if (item.kind.empty() || item.path.empty())
            continue;
        json row{{"kind", item.kind}, {"path", item.path}};
        if (!item.node_kind.empty())
            row["node_kind"] = item.node_kind;
        if (!item.label.empty())
            row["label"] = item.label;
        row["searchable"] = item.searchable;
        row["share"] = item.share;
        arr.push_back(std::move(row));
    }
    return save_subtree(SettingsSubtreeKeys::bookmarks,
                        json{{"version", 1}, {"items", std::move(arr)}},
                        err);
}

bool load_visited_files(std::vector<VisitedFileEntry>& out, std::string& err)
{
    out.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::visited_files, j, err))
        return false;
    if (!j.is_object() || !j.contains("items") || !j["items"].is_array())
        return true;
    for (const auto& el : j["items"]) {
        if (!el.is_object())
            continue;
        if (!el.contains("path") || !el["path"].is_string())
            continue;
        VisitedFileEntry row;
        row.path = el["path"].get<std::string>();
        if (row.path.empty())
            continue;
        if (el.contains("visited_at") && el["visited_at"].is_string())
            row.visited_at = el["visited_at"].get<std::string>();
        if (el.contains("workbench") && el["workbench"].is_string())
            row.workbench = el["workbench"].get<std::string>();
        out.push_back(std::move(row));
        if (out.size() >= 50u)
            break;
    }
    return true;
}

bool save_visited_files(const std::vector<VisitedFileEntry>& items, std::string& err)
{
    json arr = json::array();
    for (const auto& row : items) {
        if (row.path.empty())
            continue;
        arr.push_back(json{
            {"path", row.path},
            {"visited_at", row.visited_at},
            {"workbench", row.workbench},
        });
        if (arr.size() >= 50u)
            break;
    }
    return save_subtree(SettingsSubtreeKeys::visited_files,
                        json{{"version", 1}, {"items", std::move(arr)}},
                        err);
}

bool load_command_palette_recent(std::vector<std::string>& out, std::string& err)
{
    out.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::command_palette_recent, j, err))
        return false;
    if (!j.is_object() || !j.contains("items") || !j["items"].is_array())
        return true;
    for (const auto& el : j["items"]) {
        if (el.is_string()) {
            const std::string id = el.get<std::string>();
            if (!id.empty())
                out.push_back(id);
        }
    }
    return true;
}

bool save_command_palette_recent(const std::vector<std::string>& ids, std::string& err)
{
    json arr = json::array();
    for (const auto& id : ids) {
        if (id.empty())
            continue;
        arr.push_back(id);
    }
    return save_subtree(SettingsSubtreeKeys::command_palette_recent,
                        json{{"version", 1}, {"items", std::move(arr)}},
                        err);
}

static void cap_xblox_artifact_items(json& doc)
{
    if (!doc.is_object() || !doc.contains("items") || !doc["items"].is_array())
        return;
    auto& items = doc["items"];
    if (items.size() <= k_xblox_artifacts_max_entries)
        return;
    json kept = json::array();
    for (std::size_t i = 0; i < k_xblox_artifacts_max_entries; ++i)
        kept.push_back(items[i]);
    items = std::move(kept);
}

bool load_xblox_artifacts(nlohmann::json& out, std::string& err)
{
    out = json::object();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::xblox_artifacts, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    if (!j.is_object()) {
        err = "load_xblox_artifacts: root must be an object";
        return false;
    }
    out = std::move(j);
    if (out.contains("items") && out["items"].is_array()
        && out["items"].size() > k_xblox_artifacts_max_entries) {
        cap_xblox_artifact_items(out);
        std::string save_err;
        (void)save_xblox_artifacts(out, save_err);
    }
    return true;
}

bool save_xblox_artifacts(const nlohmann::json& doc, std::string& err)
{
    err.clear();
    if (!doc.is_object()) {
        err = "save_xblox_artifacts: doc must be an object";
        return false;
    }
    json capped = doc;
    cap_xblox_artifact_items(capped);
    return save_subtree(SettingsSubtreeKeys::xblox_artifacts, capped, err);
}

namespace {

std::string artifact_path_key(std::string path)
{
    while (!path.empty() && (path.back() == '\\' || path.back() == '/'))
        path.pop_back();
    return path;
}

} // namespace

bool append_xblox_artifact_entries(const nlohmann::json& entries,
                                   std::string& err,
                                   std::size_t max_entries)
{
    err.clear();
    if (!entries.is_array() || entries.empty())
        return true;
    if (max_entries == 0 || max_entries > k_xblox_artifacts_max_entries)
        max_entries = k_xblox_artifacts_max_entries;

    json doc;
    if (!load_xblox_artifacts(doc, err))
        return false;
    if (!doc.is_object())
        doc = json::object();
    json items = (doc.contains("items") && doc["items"].is_array()) ? doc["items"] : json::array();

    std::unordered_set<std::string> seen;
    json                            merged = json::array();

    auto push_row = [&](json row) {
        if (!row.is_object())
            return;
        if (!row.contains("path") || !row["path"].is_string())
            return;
        const std::string key = artifact_path_key(row["path"].get<std::string>());
        if (key.empty() || !seen.insert(key).second)
            return;
        merged.push_back(std::move(row));
    };

    for (auto it = entries.rbegin(); it != entries.rend(); ++it)
        push_row(*it);
    for (const auto& row : items)
        push_row(row);

    while (max_entries > 0 && merged.size() > max_entries)
        merged.erase(merged.end() - 1);

    if (!entries.empty() && merged.empty()) {
        err = "append_xblox_artifact_entries: merge dropped all incoming rows";
        return false;
    }

    doc["version"] = 1;
    doc["items"]   = std::move(merged);
    return save_xblox_artifacts(doc, err);
}

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
void settings_ipc_on_server_start(::media::cmd_ipc::InstanceDescriptor&) {}
void settings_ipc_on_server_stop() {}
nlohmann::json settings_ipc_handle(const nlohmann::json& req)
{
    return {
        {"type", "error"},
        {"error", "settings ipc owner is Windows-only"},
        {"action", req.value("action", std::string{})},
    };
}
nlohmann::json settings_ipc_status_json()
{
    return {{"owner", false}, {"active", false}};
}
#endif

} // namespace media::settings

#endif
