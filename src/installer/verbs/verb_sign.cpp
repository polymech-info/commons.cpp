// installer/verbs/verb_sign.cpp — the "sign" and "encrypt" verbs.
//
// Both operate over a working set of files (a hook's input_files, a standalone
// glob's source_files, or a walked source directory), filtered by the sign
// `mask`, resolving their pm:// uri and options per file against the first-class
// source vocabulary (${SRC_FILE}, ${SRC_REL}, …) — so signing is fully
// variable-driven and user-customizable.
//
//   sign    — vendor seed: plaintext allowed, publisher-signed (SignedVendor).
//   encrypt — user-local at-rest: encrypted, unsigned (UserLocal).
//
// Compiled and registered only under FEATURE_SECURE_STORAGE.

#include "installer/verb.hpp"
#include "installer/verb_registry.hpp"
#include "installer/resolve.hpp"
#include "installer/host.hpp"
#include "logging/pm_log.hpp"
#include "model/resource_types.hpp"
#include "storage/secure_storage.hpp"

#include <filesystem>
#include <fstream>
#include <unordered_set>
#include <vector>

namespace pm::installer {

namespace {

namespace fs = std::filesystem;

using pm::installer::host::resolve_variables;

std::string trim(const std::string& s)
{
    const auto b = s.find_first_not_of(" \t");
    if (b == std::string::npos)
        return {};
    const auto e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// mask is a comma-separated list of path globs; empty => match everything.
bool mask_allows(const std::string& rel, const std::string& mask)
{
    if (mask.empty())
        return true;
    std::size_t start = 0;
    while (start <= mask.size()) {
        const std::size_t comma = mask.find(',', start);
        const std::string glob =
            trim(mask.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (!glob.empty() && matches_path_pattern(rel, glob))
            return true;
        if (comma == std::string::npos)
            break;
        start = comma + 1;
    }
    return false;
}

// Infer the resource type from the resolved uri filename ("auto"/empty type).
pm::model::ResourceType infer_type(const std::string& uri)
{
    const std::size_t slash = uri.find_last_of('/');
    const std::string name = slash == std::string::npos ? uri : uri.substr(slash + 1);
    if (name == "commands.json") return pm::model::ResourceType::CommandConfig;
    if (name == "settings.json") return pm::model::ResourceType::SettingsProfile;
    if (name == "mcp.json")      return pm::model::ResourceType::McpConfig;
    const std::size_t dot = name.find_last_of('.');
    const std::string ext = dot == std::string::npos ? std::string{} : name.substr(dot + 1);
    if (ext == "md")   return pm::model::ResourceType::PromptTemplate;
    if (ext == "page") return pm::model::ResourceType::Page;
    if (ext == "json") return pm::model::ResourceType::SettingsProfile;
    return pm::model::ResourceType::Unknown;
}

bool read_bytes(const fs::path& path, std::vector<std::uint8_t>& out, std::string& err)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot read file: " + path.string();
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

std::string resolve_or(const std::string& raw, const VariableMap& vars,
                       const std::string& fallback = {})
{
    if (raw.empty())
        return fallback;
    std::string err;
    std::string v = resolve_variables(raw, vars, &err);
    if (v.empty())
        return fallback;
    return v;
}

// Build the working set of absolute file paths + the rel_base used for ${SRC_REL}
// and mask matching.
std::vector<std::string> gather_inputs(const VerbContext& ctx, std::string& rel_base)
{
    rel_base = !ctx.source_rel_base.empty() ? ctx.source_rel_base : ctx.source_path;

    if (!ctx.input_files.empty())
        return ctx.input_files;
    if (!ctx.source_files.empty())
        return ctx.source_files;

    std::vector<std::string> files;
    if (!ctx.source_path.empty()) {
        std::error_code ec;
        const fs::path root(ctx.source_path);
        if (fs::is_directory(root, ec) && !ec) {
            for (fs::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
                if (it->is_regular_file(ec) && !ec)
                    files.push_back(it->path().string());
            }
        } else if (fs::is_regular_file(root, ec) && !ec) {
            files.push_back(root.string());
        }
    }
    return files;
}

// Shared runner for both verbs.  `encrypt_mode` picks encrypt-at-rest vs sign.
void run_sign_like(const VerbContext& ctx, PackageResult& result, bool encrypt_mode)
{
    if (!ctx.package || !ctx.vars) {
        result.ok          = false;
        result.error       = "internal: missing sign context";
        result.error_class = ErrorClass::Permanent;
        return;
    }

    const PackageSign& opt = ctx.package->sign;

    std::string rel_base;
    const std::vector<std::string> inputs = gather_inputs(ctx, rel_base);
    if (inputs.empty()) {
        result.ok          = false;
        result.error       = std::string(encrypt_mode ? "encrypt" : "sign") + ": no input files";
        result.error_class = ErrorClass::Permanent;
        return;
    }

    const std::string default_trust = encrypt_mode ? "user-local" : "signed-vendor";
    std::unordered_set<std::string> stores;
    std::vector<std::string>        signed_sources; // for delete_source cleanup

    int signed_count = 0;
    for (const auto& file_s : inputs) {
        const fs::path file_path(file_s);

        // rel for mask + ${SRC_REL}.
        std::error_code rel_ec;
        fs::path        rel = rel_base.empty()
            ? file_path.filename()
            : fs::relative(file_path, fs::path(rel_base), rel_ec);
        std::string rel_s = (!rel_ec && !rel.empty()) ? rel.generic_string()
                                                       : file_path.filename().generic_string();
        if (rel_s.rfind("..", 0) == 0)
            rel_s = file_path.filename().generic_string();

        if (!mask_allows(rel_s, opt.mask)) {
            ++result.files_skipped;
            continue;
        }

        // Per-file variable scope: base vars + first-class ${SRC_*}/${SRC_REL}.
        VariableMap vars = *ctx.vars;
        host::apply_source_file_variables(vars, file_s, {}, rel_base);

        const std::string uri = resolve_or(opt.uri, vars);
        if (uri.empty()) {
            result.ok          = false;
            result.error       = "sign: uri empty for " + rel_s;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        const std::string trust_s    = resolve_or(opt.trust, vars, default_trust);
        const std::string provider_s = resolve_or(opt.provider, vars, "polymech");
        const std::string signer_s   = resolve_or(opt.signer, vars, "polymech-dist-ed25519");
        const std::string version_s  = resolve_or(opt.version, vars, "1");
        const std::string type_raw   = resolve_or(opt.doc_type, vars);

        std::string config_s = resolve_or(opt.config_dir, vars, rel_base);
        if (config_s.empty())
            config_s = file_path.parent_path().string();

        pm::log::trace_lazy("installer", [&]{
            return std::string(encrypt_mode ? "encrypt" : "sign") + ": " + uri + " <- " + file_s;
        });
        if (ctx.events && ctx.events->on_file)
            ctx.events->on_file(ctx.package->id, rel_s);

        if (ctx.dry_run) {
            ++signed_count;
            continue;
        }

        std::vector<std::uint8_t> bytes;
        if (!read_bytes(file_path, bytes, result.error)) {
            result.ok          = false;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        pm::model::ResourceType type = (type_raw.empty() || type_raw == "auto")
            ? infer_type(uri)
            : pm::model::resource_type_from_string(type_raw);

        pm::storage::PutDocumentRequest req;
        req.uri                  = uri;
        req.type                 = type;
        req.trust                = pm::model::trust_level_from_string(trust_s);
        req.version              = version_s;
        req.provider             = provider_s;
        req.signer_id            = signer_s;
        req.encrypt              = encrypt_mode;
        req.allow_plaintext_seed = !encrypt_mode;
        req.data                 = std::move(bytes);

        const pm::storage::StoragePaths paths = pm::storage::resolve_storage_paths(fs::u8path(config_s));
        std::string layout_err;
        if (!pm::storage::ensure_storage_layout(paths, layout_err)) {
            result.ok          = false;
            result.error       = layout_err.empty() ? "sign: storage layout failed" : layout_err;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        const auto stored = pm::storage::put_document(paths, req);
        if (!stored.ok) {
            result.ok          = false;
            result.error       = stored.error.empty() ? "sign: put_document failed" : stored.error;
            result.error_class = ErrorClass::Permanent;
            return;
        }

        if (!encrypt_mode) {
            const auto signed_doc = pm::storage::sign_document(paths, uri);
            if (!signed_doc.ok) {
                result.ok          = false;
                result.error       = signed_doc.error.empty() ? "sign: sign_document failed" : signed_doc.error;
                result.error_class = ErrorClass::Permanent;
                return;
            }
        }

        if (opt.verify) {
            pm::storage::DocumentLoadPolicy policy;
            policy.require_signature           = !encrypt_mode;
            policy.require_encryption          = encrypt_mode;
            policy.allow_vendor_seed_plaintext = !encrypt_mode;
            policy.allowed_trust               = {req.trust};
            const auto verified = pm::storage::verify_document(paths, uri, policy);
            const bool sig_ok = encrypt_mode ? verified.ok : (verified.ok && verified.signature_valid);
            if (!sig_ok) {
                result.ok          = false;
                result.error       = verified.error.empty() ? "sign: verify failed" : verified.error;
                result.error_class = ErrorClass::Permanent;
                return;
            }
        }

        stores.insert(fs::u8path(config_s).lexically_normal().string());
        if (opt.delete_source)
            signed_sources.push_back(file_s);
        ++signed_count;
    }

    // Strip private keys from every store touched (once, after all files).
    if (!ctx.dry_run && opt.strip_keys) {
        for (const auto& dir_s : stores) {
            const pm::storage::StoragePaths paths = pm::storage::resolve_storage_paths(fs::u8path(dir_s));
            std::error_code ec;
            fs::remove(paths.local_signing_key, ec);
            ec.clear();
            fs::remove(paths.local_encryption_key, ec);
            ec.clear();
            fs::remove_all(paths.keys, ec);
        }
    }

    // Remove plain-text source files now that they are safely in the store.
    if (!ctx.dry_run && opt.delete_source) {
        for (const auto& src : signed_sources) {
            std::error_code ec;
            fs::remove(fs::path(src), ec);
        }
    }

    result.ok           = true;
    result.files_copied = signed_count;
}

class SignVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "sign"; }
    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        run_sign_like(ctx, result, /*encrypt_mode=*/false);
    }
};

class EncryptVerb final : public IVerb {
public:
    const char* name() const noexcept override { return "encrypt"; }
    void execute(const VerbContext& ctx, PackageResult& result) override
    {
        run_sign_like(ctx, result, /*encrypt_mode=*/true);
    }
};

} // namespace

void register_sign_verbs(VerbRegistry& reg)
{
    reg.register_verb(std::make_unique<SignVerb>());
    reg.register_verb(std::make_unique<EncryptVerb>());
}

} // namespace pm::installer
