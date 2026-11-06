#if !defined(FEATURE_MCP_CLIENT)
#define FEATURE_MCP_CLIENT 1
#endif

#include "core/settings_archive.hpp"
#include "fs/path_sanitizer.hpp"

#include "core/settings_store.hpp"
#include "core/settings_portable.hpp"
#include "fs/zip_store.hpp"
#include "logger/logger.h"
#include "security/security_defaults.hpp"

#if FEATURE_MCP_CLIENT
#include "llm/mcp_config.hpp"
#endif

#if !defined(FEATURE_SECURE_STORAGE)
#define FEATURE_SECURE_STORAGE 0
#endif
#if FEATURE_SECURE_STORAGE
#include "storage/secure_storage.hpp"
#endif

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstring>
#include <cwctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

#ifndef FEATURE_MCP_CLIENT
#define FEATURE_MCP_CLIENT 1
#endif

namespace {

namespace fs = std::filesystem;

bool starts_with_web_ci(std::wstring s)
{
    if (s.size() < 3)
        return false;
    for (auto& c : s)
        c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
    return s.rfind(L"web", 0) == 0;
}

bool archive_skip_top_level(const fs::path& rel)
{
    if (rel.empty())
        return false;
    auto it = rel.begin();
    if (it == rel.end())
        return false;
    return starts_with_web_ci(it->wstring());
}

bool archive_skip_file(const fs::path& rel)
{
    if (archive_skip_top_level(rel))
        return true;
    return rel == fs::path(L".settings-key.dat") || rel == fs::path(L".cloud_storage_key");
}

std::wstring archive_process_id_fragment()
{
#if defined(_WIN32)
    return std::to_wstring(::GetCurrentProcessId());
#else
    return L"pid";
#endif
}

fs::path make_settings_archive_temp_dir(const wchar_t* leaf)
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    fs::path p = fs::temp_directory_path()
        / (std::wstring(L"pm-image-settings-") + leaf + L"-"
           + archive_process_id_fragment() + L"-" + std::to_wstring(ticks));
    return p;
}

fs::path settings_profile_dir()
{
    return media::settings::get_config_dir();
}

bool export_profile_settings_json(const fs::path& path, std::string& err)
{
#if defined(_WIN32)
    return media::settings::export_settings_file(path, false, err);
#else
    nlohmann::json root;
    if (!media::portable_settings::read_profile_direct(root, err))
        return false;
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        err = "create settings export directory: " + ec.message();
        return false;
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "cannot open " + media::path::path_to_utf8(path);
        return false;
    }
    out << root.dump(2);
    if (!out.good()) {
        err = "write failed: " + media::path::path_to_utf8(path);
        return false;
    }
    return true;
#endif
}

bool import_profile_settings_json(const fs::path& path, std::string& err)
{
#if defined(_WIN32)
    return media::settings::import_settings_file(path, err);
#else
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + media::path::path_to_utf8(path);
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    nlohmann::json root;
    try {
        root = nlohmann::json::parse(raw);
    } catch (const std::exception& e) {
        err = std::string("JSON parse: ") + e.what();
        return false;
    }
    if (!root.is_object()) {
        err = "root must be a JSON object";
        return false;
    }
    if (!media::portable_settings::write_settings_profile_json(root, err))
        return false;
#if defined(__APPLE__)
    std::string sync_err;
    if (!media::portable_settings::merge_settings_import_into_codeedit_prefs(root, sync_err))
        logger::warn("settings import --archive: " + sync_err + " (portable profile was written)");
#endif
    return true;
#endif
}

bool copy_profile_to_archive_stage(const fs::path& stage, std::string& err)
{
    const fs::path profile = settings_profile_dir();
    std::error_code ec;
    fs::create_directories(stage, ec);
    if (ec) {
        err = "create archive staging directory: " + ec.message();
        return false;
    }

    const fs::path staged_settings = stage / "settings.json";
    if (!export_profile_settings_json(staged_settings, err))
        return false;

    for (fs::recursive_directory_iterator it(profile, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate profile: " + ec.message();
            return false;
        }
        const fs::path rel = fs::relative(it->path(), profile, ec);
        if (ec || rel.empty()) {
            ec.clear();
            continue;
        }
        if (archive_skip_top_level(rel)) {
            if (it->is_directory(ec))
                it.disable_recursion_pending();
            ec.clear();
            continue;
        }
        if (archive_skip_file(rel) || rel == media::path::path_from_utf8("settings.json"))
            continue;

        const fs::path dst = stage / rel;
        if (it->is_directory(ec)) {
            fs::create_directories(dst, ec);
        } else if (it->is_regular_file(ec)) {
            fs::create_directories(dst.parent_path(), ec);
            if (!ec)
                fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec);
        }
        if (ec) {
            err = "stage archive entry " + media::path::path_to_utf8(rel) + ": " + ec.message();
            return false;
        }
    }
    return true;
}

bool write_utf8_plaintext(const fs::path& path, const std::string& utf8, std::string& err)
{
    err.clear();
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "cannot open " + media::path::path_to_utf8(path);
        return false;
    }
    if (!utf8.empty())
        out.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!out.good()) {
        err = "write failed: " + media::path::path_to_utf8(path);
        return false;
    }
    return true;
}

bool mcp_config_missing_error(const std::string& err)
{
    if (err.empty())
        return true;
    if (err.find("not found") != std::string::npos)
        return true;
    if (err.find("document not found") != std::string::npos)
        return true;
    if (err == "profile config directory unknown")
        return true;
    return false;
}

bool stage_mcp_tree(const fs::path& profile, const fs::path& stage, std::string& err)
{
    err.clear();
    std::error_code ec;
    for (const fs::path candidate : {profile / "mcp.json", profile / "mcp-servers.json"}) {
        if (!fs::is_regular_file(candidate, ec) || ec)
            continue;
        const fs::path rel = candidate.filename();
        if (rel == media::path::path_from_utf8("mcp.json"))
            continue;
        fs::create_directories((stage / rel).parent_path(), ec);
        fs::copy_file(candidate, stage / rel, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            err = "stage " + media::path::path_to_utf8(rel) + ": " + ec.message();
            return false;
        }
    }
    const fs::path mcps_dir = profile / "mcps";
    if (!fs::is_directory(mcps_dir, ec))
        return true;
    for (fs::recursive_directory_iterator it(mcps_dir, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate mcps: " + ec.message();
            return false;
        }
        const fs::path rel = media::path::path_from_utf8("mcps") / fs::relative(it->path(), mcps_dir, ec);
        if (ec || rel.empty()) {
            ec.clear();
            continue;
        }
        const fs::path dst = stage / rel;
        if (it->is_directory(ec)) {
            fs::create_directories(dst, ec);
        } else if (it->is_regular_file(ec)) {
            fs::create_directories(dst.parent_path(), ec);
            if (!ec)
                fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec);
        }
        if (ec) {
            err = "stage " + media::path::path_to_utf8(rel) + ": " + ec.message();
            return false;
        }
    }
    return true;
}

#if FEATURE_MCP_CLIENT
bool stage_mcp_config(const fs::path& profile, const fs::path& stage, std::string& err)
{
    err.clear();
    nlohmann::json mcp;
    std::string load_err;
    if (!media::llm::mcp::load_mcp_config(profile, mcp, load_err)) {
        if (mcp_config_missing_error(load_err))
            return stage_mcp_tree(profile, stage, err);
        err = load_err;
        return false;
    }
    if (!write_utf8_plaintext(stage / "mcp.json", mcp.dump(2), err))
        return false;
    return stage_mcp_tree(profile, stage, err);
}
#endif

bool prompt_uri_to_filename(const std::string& uri, std::string& filename)
{
    constexpr const char k_prefix[] = "pm://config/prompts/";
    if (uri.rfind(k_prefix, 0) != 0)
        return false;
    filename = uri.substr(sizeof(k_prefix) - 1);
    return !filename.empty() && filename.find("..") == std::string::npos;
}

#if FEATURE_SECURE_STORAGE
bool read_file_for_prompt_import(const fs::path& path, std::string& out, std::string& err)
{
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + media::path::path_to_utf8(path);
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool stage_prompts_secure(const fs::path& profile, const fs::path& stage, std::string& err)
{
    err.clear();
    const fs::path prompts_stage = stage / "prompts";
    std::error_code ec;
    fs::create_directories(prompts_stage, ec);

    const auto paths = pm::storage::resolve_storage_paths(profile);
    const auto listed = pm::storage::list_documents(paths);
    if (!listed.ok && !listed.error.empty()) {
        err = listed.error;
        return false;
    }

    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {
        pm::model::TrustLevel::Builtin,
        pm::model::TrustLevel::SignedVendor,
        pm::model::TrustLevel::UserLocal,
    };

    for (const auto& meta : listed.items) {
        std::string filename;
        if (!prompt_uri_to_filename(meta.uri, filename))
            continue;
        const auto loaded = pm::storage::load_document(paths, meta.uri, policy);
        if (!loaded.ok)
            continue;
        const std::string text(reinterpret_cast<const char*>(loaded.document.data.data()),
                               loaded.document.data.size());
        if (!write_utf8_plaintext(prompts_stage / filename, text, err))
            return false;
    }
    return true;
}

bool import_prompt_file_secure(const fs::path& profile, const fs::path& src, const std::string& filename, std::string& err)
{
    err.clear();
    std::string text;
    if (!read_file_for_prompt_import(src, text, err))
        return false;
    pm::storage::PutDocumentRequest req;
    req.uri = std::string("pm://config/prompts/") + filename;
    req.type = pm::model::ResourceType::PromptTemplate;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = "1";
    req.provider = "user";
    req.signer_id = "local-prompts";
    req.encrypt = true;
    req.replace_vendor_seed = true;
    req.data.assign(text.begin(), text.end());
    const auto paths = pm::storage::resolve_storage_paths(profile);
    const auto stored = pm::storage::put_document(paths, req);
    if (!stored.ok) {
        err = stored.error;
        return false;
    }
    const auto signed_doc = pm::storage::sign_document(paths, req.uri);
    if (!signed_doc.ok) {
        err = signed_doc.error;
        return false;
    }
    return true;
}
#endif

bool stage_prompts_plain(const fs::path& profile, const fs::path& stage, std::string& err)
{
    err.clear();
    const fs::path plain_prompts = profile / "prompts";
    std::error_code ec;
    if (!fs::is_directory(plain_prompts, ec))
        return true;
    const fs::path prompts_stage = stage / "prompts";
    for (fs::directory_iterator it(plain_prompts, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate prompts: " + ec.message();
            return false;
        }
        if (!it->is_regular_file(ec))
            continue;
        if (it->path().extension() != ".md")
            continue;
        const fs::path dst = prompts_stage / it->path().filename();
        if (fs::exists(dst, ec))
            continue;
        fs::create_directories(dst.parent_path(), ec);
        fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            err = "stage prompt " + media::path::path_to_utf8(it->path().filename()) + ": " + ec.message();
            return false;
        }
    }
    return true;
}

bool stage_prompts(const fs::path& profile, const fs::path& stage, std::string& err)
{
#if FEATURE_SECURE_STORAGE
    if (!stage_prompts_secure(profile, stage, err))
        return false;
#endif
    return stage_prompts_plain(profile, stage, err);
}

bool import_prompts(const fs::path& extract, const fs::path& profile, std::string& err)
{
    err.clear();
    const fs::path prompts_root = extract / "prompts";
    std::error_code ec;
    if (!fs::is_directory(prompts_root, ec))
        return true;
    for (fs::directory_iterator it(prompts_root, ec), end; it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate prompt backup: " + ec.message();
            return false;
        }
        if (!it->is_regular_file(ec) || it->path().extension() != ".md")
            continue;
        const std::string filename = media::path::path_to_utf8(it->path().filename());
#if FEATURE_SECURE_STORAGE
        if (!import_prompt_file_secure(profile, it->path(), filename, err))
            return false;
#else
        const fs::path dst = profile / "prompts" / filename;
        fs::create_directories(dst.parent_path(), ec);
        fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            err = "import prompt " + filename + ": " + ec.message();
            return false;
        }
#endif
    }
    return true;
}

#if FEATURE_SECURE_STORAGE
bool stage_home_page_secure(const fs::path& profile, const fs::path& stage, std::string& err)
{
    err.clear();
    const auto paths = pm::storage::resolve_storage_paths(profile);
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {
        pm::model::TrustLevel::Builtin,
        pm::model::TrustLevel::SignedVendor,
        pm::model::TrustLevel::UserLocal,
    };
    const auto loaded = pm::storage::load_document(paths, pm::security::k_home_page_document_uri, policy);
    if (!loaded.ok)
        return true;
    const std::string text(reinterpret_cast<const char*>(loaded.document.data.data()),
                           loaded.document.data.size());
    return write_utf8_plaintext(stage / pm::security::k_home_page_filename, text, err);
}

bool import_home_page_secure(const fs::path& profile, const fs::path& src, std::string& err)
{
    err.clear();
    std::string text;
    if (!read_file_for_prompt_import(src, text, err))
        return false;
    pm::storage::PutDocumentRequest req;
    req.uri = pm::security::k_home_page_document_uri;
    req.type = pm::model::ResourceType::Page;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = "1";
    req.provider = "user";
    req.signer_id = "local-pages";
    req.encrypt = true;
    req.replace_vendor_seed = true;
    req.data.assign(text.begin(), text.end());
    const auto paths = pm::storage::resolve_storage_paths(profile);
    const auto stored = pm::storage::put_document(paths, req);
    if (!stored.ok) {
        err = stored.error;
        return false;
    }
    const auto signed_doc = pm::storage::sign_document(paths, req.uri);
    if (!signed_doc.ok) {
        err = signed_doc.error;
        return false;
    }
    return true;
}
#endif

bool stage_home_page_plain(const fs::path& profile, const fs::path& stage, std::string& err)
{
    err.clear();
    const fs::path src = profile / pm::security::k_home_page_filename;
    const fs::path dst = stage / pm::security::k_home_page_filename;
    std::error_code ec;
    if (!fs::is_regular_file(src, ec) || ec)
        return true;
    if (fs::exists(dst, ec))
        return true;
    fs::create_directories(dst.parent_path(), ec);
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        err = "stage home.page: " + ec.message();
        return false;
    }
    return true;
}

bool stage_home_page(const fs::path& profile, const fs::path& stage, std::string& err)
{
#if FEATURE_SECURE_STORAGE
    if (!stage_home_page_secure(profile, stage, err))
        return false;
#endif
    return stage_home_page_plain(profile, stage, err);
}

bool import_home_page(const fs::path& extract, const fs::path& profile, std::string& err)
{
    err.clear();
    const fs::path src = extract / pm::security::k_home_page_filename;
    std::error_code ec;
    if (!fs::is_regular_file(src, ec) || ec)
        return true;
#if FEATURE_SECURE_STORAGE
    return import_home_page_secure(profile, src, err);
#else
    const fs::path dst = profile / pm::security::k_home_page_filename;
    fs::create_directories(dst.parent_path(), ec);
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        err = "import home.page: " + ec.message();
        return false;
    }
    return true;
#endif
}

bool copy_tree_into_profile(const fs::path& root, const fs::path& profile, const fs::path& rel_prefix, std::string& err)
{
    err.clear();
    const fs::path src_root = root / rel_prefix;
    std::error_code ec;
    if (!fs::exists(src_root, ec))
        return true;
    for (fs::recursive_directory_iterator it(src_root, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate backup tree: " + ec.message();
            return false;
        }
        const fs::path rel = rel_prefix / fs::relative(it->path(), src_root, ec);
        if (ec || rel.empty()) {
            ec.clear();
            continue;
        }
        const fs::path dst = profile / rel;
        if (it->is_directory(ec)) {
            fs::create_directories(dst, ec);
        } else if (it->is_regular_file(ec)) {
            fs::create_directories(dst.parent_path(), ec);
            if (!ec)
                fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec);
        }
        if (ec) {
            err = "import " + media::path::path_to_utf8(rel) + ": " + ec.message();
            return false;
        }
    }
    return true;
}

bool stage_config_backup(const fs::path& stage, const media::settings_archive::ConfigBackupOptions& options, std::string& err)
{
    err.clear();
    const fs::path profile = settings_profile_dir();
    std::error_code ec;
    fs::create_directories(stage, ec);
    if (ec) {
        err = "create config backup staging directory: " + ec.message();
        return false;
    }

    if (!export_profile_settings_json(stage / "settings.json", err))
        return false;

    if (options.include_commands) {
        std::string commands_json;
        if (!media::settings::load_command_json_utf8(commands_json, err))
            return false;
        if (!commands_json.empty()) {
            if (!write_utf8_plaintext(stage / "commands.json", commands_json, err))
                return false;
        }
    }

    if (options.include_mcp) {
#if FEATURE_MCP_CLIENT
        if (!stage_mcp_config(profile, stage, err))
            return false;
#else
        if (!stage_mcp_tree(profile, stage, err))
            return false;
#endif
    }

    if (options.include_prompts && !stage_prompts(profile, stage, err))
        return false;
    if (options.include_home_page && !stage_home_page(profile, stage, err))
        return false;
    return true;
}

bool export_config_backup_zip_impl(const fs::path& out, const media::settings_archive::ConfigBackupOptions& options, std::string& err)
{
    const fs::path stage = make_settings_archive_temp_dir(L"config-export");
    struct Cleanup {
        fs::path p;
        ~Cleanup() { std::error_code ec; fs::remove_all(p, ec); }
    } cleanup{stage};

    if (!stage_config_backup(stage, options, err))
        return false;

    std::error_code ec;
    fs::create_directories(out.parent_path(), ec);
    if (ec) {
        err = "create config backup output directory: " + ec.message();
        return false;
    }
    return media::zip_store::write_stored_zip(out, stage, err);
}

bool import_config_backup_zip_impl(const fs::path& zip_path, std::string& err)
{
    const fs::path extract = make_settings_archive_temp_dir(L"config-import");
    struct Cleanup {
        fs::path p;
        ~Cleanup() { std::error_code ec; fs::remove_all(p, ec); }
    } cleanup{extract};

    std::error_code ec;
    fs::create_directories(extract, ec);
    if (ec) {
        err = "create config backup extraction directory: " + ec.message();
        return false;
    }
    if (!media::zip_store::extract_stored_zip(zip_path, extract, err))
        return false;

    const fs::path profile = settings_profile_dir();
    fs::create_directories(profile, ec);
    if (ec) {
        err = "create profile directory: " + ec.message();
        return false;
    }

    const fs::path settings_path = extract / "settings.json";
    if (!fs::is_regular_file(settings_path, ec) || ec) {
        err = "config backup missing settings.json";
        return false;
    }
    if (!import_profile_settings_json(settings_path, err))
        return false;

    const fs::path commands_path = extract / "commands.json";
    if (fs::is_regular_file(commands_path, ec) && !ec) {
        std::ifstream in(commands_path, std::ios::binary);
        if (!in) {
            err = "cannot open " + media::path::path_to_utf8(commands_path);
            return false;
        }
        const std::string commands_json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (!media::settings::save_command_json_utf8(commands_json, err))
            return false;
    }

    if (!copy_tree_into_profile(extract, profile, "mcps", err))
        return false;

#if FEATURE_MCP_CLIENT
    const fs::path mcp_path = extract / "mcp.json";
    if (fs::is_regular_file(mcp_path, ec) && !ec) {
        std::ifstream in(mcp_path, std::ios::binary);
        if (!in) {
            err = "cannot open " + media::path::path_to_utf8(mcp_path);
            return false;
        }
        nlohmann::json mcp;
        try {
            in >> mcp;
        } catch (const std::exception& e) {
            err = std::string("JSON parse: ") + e.what();
            return false;
        }
        if (!media::llm::mcp::save_mcp_config(profile, mcp, err))
            return false;
    }
#else
    for (const char* name : {"mcp.json", "mcp-servers.json"}) {
        const fs::path src = extract / name;
        if (!fs::is_regular_file(src, ec) || ec)
            continue;
        fs::copy_file(src, profile / name, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            err = std::string("import ") + name + ": " + ec.message();
            return false;
        }
    }
#endif

    if (!import_prompts(extract, profile, err))
        return false;
    if (!import_home_page(extract, profile, err))
        return false;
    return true;
}

bool export_settings_archive_zip_impl(const fs::path& out, std::string& err)
{
    const fs::path stage = make_settings_archive_temp_dir(L"export");
    struct Cleanup {
        fs::path p;
        ~Cleanup() { std::error_code ec; fs::remove_all(p, ec); }
    } cleanup{stage};

    if (!copy_profile_to_archive_stage(stage, err))
        return false;

    std::error_code ec;
    fs::create_directories(out.parent_path(), ec);
    if (ec) {
        err = "create archive output directory: " + ec.message();
        return false;
    }

    return media::zip_store::write_stored_zip(out, stage, err);
}

bool file_starts_with(const fs::path& path, const char* magic, std::size_t n, bool& matched, std::string& err)
{
    matched = false;
    err.clear();
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        err = "failed to read " + media::path::path_to_utf8(path);
        return false;
    }
    char buf[8]{};
    if (n > sizeof buf)
        n = sizeof buf;
    ifs.read(buf, static_cast<std::streamsize>(n));
    if (static_cast<std::size_t>(ifs.gcount()) < n)
        return true;
    matched = std::memcmp(buf, magic, n) == 0;
    return true;
}

bool import_settings_archive_zip_impl(const fs::path& zip_path, std::string& err)
{
    bool is_pmbackup = false;
    if (!file_starts_with(zip_path, "PMBK", 4, is_pmbackup, err))
        return false;
    if (is_pmbackup) {
        err = "This file is an encrypted .pmbackup. Use Import encrypted backup, not Import profile archive.";
        return false;
    }

    const fs::path extract = make_settings_archive_temp_dir(L"import");
    struct Cleanup {
        fs::path p;
        ~Cleanup() { std::error_code ec; fs::remove_all(p, ec); }
    } cleanup{extract};

    std::error_code ec;
    fs::create_directories(extract, ec);
    if (ec) {
        err = "create archive extraction directory: " + ec.message();
        return false;
    }

    if (!media::zip_store::extract_stored_zip(zip_path, extract, err))
        return false;

    const fs::path root = extract;
    const fs::path profile = settings_profile_dir();
    fs::create_directories(profile, ec);
    if (ec) {
        err = "create profile directory: " + ec.message();
        return false;
    }

    bool imported_settings = false;
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate archive payload: " + ec.message();
            return false;
        }
        const fs::path rel = fs::relative(it->path(), root, ec);
        if (ec || rel.empty()) {
            ec.clear();
            continue;
        }
        if (archive_skip_top_level(rel)) {
            if (it->is_directory(ec))
                it.disable_recursion_pending();
            ec.clear();
            continue;
        }
        if (archive_skip_file(rel))
            continue;

        if (rel == media::path::path_from_utf8("settings.json") && it->is_regular_file(ec)) {
            if (!import_profile_settings_json(it->path(), err))
                return false;
            imported_settings = true;
            continue;
        }

        const fs::path dst = profile / rel;
        if (it->is_directory(ec)) {
            fs::create_directories(dst, ec);
        } else if (it->is_regular_file(ec)) {
            fs::create_directories(dst.parent_path(), ec);
            if (!ec)
                fs::copy_file(it->path(), dst, fs::copy_options::overwrite_existing, ec);
        }
        if (ec) {
            err = "import archive entry " + media::path::path_to_utf8(rel) + ": " + ec.message();
            return false;
        }
    }
    if (!imported_settings)
        logger::warn("settings import --archive: archive did not contain settings.json");
    return true;
}

} // namespace

namespace media::settings_archive {

bool export_settings_archive_zip(const std::filesystem::path& out, std::string& err)
{
    return export_settings_archive_zip_impl(out, err);
}

bool import_settings_archive_zip(const std::filesystem::path& zip_path, std::string& err)
{
    return import_settings_archive_zip_impl(zip_path, err);
}

bool export_config_backup_zip(const std::filesystem::path& out,
                              const ConfigBackupOptions& options,
                              std::string& err)
{
    return export_config_backup_zip_impl(out, options, err);
}

bool import_config_backup_zip(const std::filesystem::path& zip_path, std::string& err)
{
    return import_config_backup_zip_impl(zip_path, err);
}

} // namespace media::settings_archive
