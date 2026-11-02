#include "storage/secure_storage.hpp"
#include "policy/app_policy.hpp"
#include "storage/bundle_pub_key.hpp"

#include "core/resource_uri.hpp"
#include "logging/pm_log.hpp"
#include "model/resource_schema.hpp"

#include <cstdlib>

#include <sodium.h>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <system_error>
#include <thread>

namespace fs = std::filesystem;

namespace pm::storage {

namespace {

using json = nlohmann::json;
constexpr const char* k_signature_schema = "pm.resource.signature.v1";
constexpr const char* k_package_schema = "pm.resource.package.v1";
constexpr std::uint8_t k_document_encrypted_magic[] = {'P', 'M', 'D', '1'};

std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::ostringstream os;
    os << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return os.str();
}

std::string utc_expiry_default() {
    const auto now = std::chrono::system_clock::now();
    const auto expires = now + std::chrono::hours(24 * 365);
    const std::time_t t = std::chrono::system_clock::to_time_t(expires);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::ostringstream os;
    os << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return os.str();
}

bool read_bytes(const fs::path& path, std::vector<std::uint8_t>& out, std::string& err) {
    out.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open file: " + path.string();
        return false;
    }
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size < 0) {
        err = "failed to stat file: " + path.string();
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(size));
    if (!out.empty())
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (!in.good() && !in.eof()) {
        err = "failed to read file: " + path.string();
        return false;
    }
    return true;
}

bool write_bytes_atomic(const fs::path& path, const std::vector<std::uint8_t>& data, std::string& err) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        err = "failed to create directory: " + path.parent_path().string();
        return false;
    }

    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            err = "failed to open temp file: " + tmp.string();
            return false;
        }
        if (!data.empty())
            out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out.good()) {
            err = "failed to write temp file: " + tmp.string();
            return false;
        }
    }

#if defined(_WIN32)
    // Same-directory MoveFileEx is atomic on NTFS: a reader opens either the
    // old file or the new one. ReplaceFileW unlinks the destination first, so
    // a settings import's concurrent load sees "failed to open" settings.json.doc.
    const std::wstring dest_w = path.wstring();
    const std::wstring tmp_w = tmp.wstring();
    if (!MoveFileExW(tmp_w.c_str(), dest_w.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        err = "failed to move temp file into place: " + path.string();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
#else
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "failed to move temp file into place: " + path.string();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
#endif
}

bool write_text_atomic(const fs::path& path, const std::string& text, std::string& err) {
    return write_bytes_atomic(path, std::vector<std::uint8_t>(text.begin(), text.end()), err);
}

std::string b64(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) return {};
    std::string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

bool b64_decode(const std::string& text, std::vector<std::uint8_t>& out, std::string& err) {
    out.assign(text.size(), 0);
    size_t actual = 0;
    if (sodium_base642bin(out.data(), out.size(), text.c_str(), text.size(),
                          nullptr, &actual, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        err = "base64 decode failed";
        return false;
    }
    out.resize(actual);
    return true;
}

json empty_index() {
    return json{{"schema", pm::model::k_uri_index_schema}, {"resources", json::object()}};
}

json empty_doc_index() {
    return json{{"schema", pm::model::k_doc_index_schema}, {"documents", json::object()}};
}

bool load_index(const StoragePaths& paths, json& out, std::string& err) {
    out = empty_index();
    if (!fs::exists(paths.uri_index))
        return true;
    std::ifstream in(paths.uri_index, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open URI index";
        return false;
    }
    try {
        in >> out;
    } catch (const std::exception& e) {
        err = std::string("failed to parse URI index: ") + e.what();
        return false;
    }
    if (!out.is_object() || out.value("schema", std::string{}) != pm::model::k_uri_index_schema)
        out = empty_index();
    if (!out.contains("resources") || !out["resources"].is_object())
        out["resources"] = json::object();
    return true;
}

bool save_index(const StoragePaths& paths, const json& index, std::string& err) {
    return write_text_atomic(paths.uri_index, index.dump(2), err);
}

bool load_doc_index(const StoragePaths& paths, json& out, std::string& err) {
    out = empty_doc_index();
    if (!fs::exists(paths.doc_index))
        return true;
    std::ifstream in(paths.doc_index, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open document index";
        return false;
    }
    try {
        in >> out;
    } catch (const std::exception& e) {
        err = std::string("failed to parse document index: ") + e.what();
        return false;
    }
    if (!out.is_object() || out.value("schema", std::string{}) != pm::model::k_doc_index_schema)
        out = empty_doc_index();
    if (!out.contains("documents") || !out["documents"].is_object())
        out["documents"] = json::object();
    return true;
}

bool save_doc_index(const StoragePaths& paths, const json& index, std::string& err) {
    return write_text_atomic(paths.doc_index, index.dump(2), err);
}

bool read_json_file(const fs::path& path, json& out, std::string& err);

fs::path blob_path(const StoragePaths& paths, const std::string& digest) {
    const std::string prefix = digest.size() >= 2 ? digest.substr(0, 2) : "xx";
    return paths.blobs / "sha256" / prefix / digest;
}

fs::path manifest_path(const StoragePaths& paths, const std::string& digest) {
    return paths.manifests / (digest + ".json");
}

fs::path signature_path(const StoragePaths& paths, const std::string& digest) {
    return paths.manifests / (digest + ".json.sig");
}

fs::path documents_dir(const StoragePaths& paths) {
    return paths.root / "documents";
}

std::string document_slug(const pm::core::ResourceUri& parsed) {
    if (parsed.type == "config") {
        std::string out;
        out.reserve(parsed.name.size());
        std::string segment;
        auto flush_segment = [&]() {
            if (!out.empty())
                out.push_back('/');
            if (segment.empty() || segment == "." || segment == "..") {
                out.push_back('_');
            } else {
                out += segment;
            }
            segment.clear();
        };
        for (char c : parsed.name) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (c == '/') {
                flush_segment();
            } else if (std::isalnum(uc) || c == '-' || c == '_' || c == '.') {
                segment.push_back(c);
            } else {
                segment.push_back('_');
            }
        }
        flush_segment();
        return out.empty() ? "_" : out;
    }

    std::string out;
    out.reserve(parsed.type.size() + 2 + parsed.name.size());
    auto append = [&](char c) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalnum(uc) || c == '-' || c == '_')
            out.push_back(c);
        else
            out.push_back('_');
    };
    for (char c : parsed.type)
        append(c);
    out += "__";
    for (char c : parsed.name)
        append(c);
    return out;
}

fs::path document_blob_path(const StoragePaths& paths, const std::string& slug) {
    return documents_dir(paths) / (slug + ".doc");
}

fs::path document_meta_path(const StoragePaths& paths, const std::string& slug) {
    return documents_dir(paths) / (slug + ".doc.meta");
}

fs::path document_signature_path(const StoragePaths& paths, const std::string& slug) {
    return documents_dir(paths) / (slug + ".doc.sig");
}

pm::model::ResourceType expected_type_for_uri(const pm::core::ResourceUri& parsed) {
    if (parsed.type == "config") {
        if (parsed.name == "settings.json") return pm::model::ResourceType::SettingsProfile;
        if (parsed.name == "zitadel-oauth.json") return pm::model::ResourceType::OAuthCredentials;
        if (parsed.name == "commands.json") return pm::model::ResourceType::CommandConfig;
        if (parsed.name == "mcp.json" || parsed.name == "mcp-servers.json") return pm::model::ResourceType::McpConfig;
        if (parsed.name.rfind("prompts/", 0) == 0) return pm::model::ResourceType::PromptTemplate;
        if (parsed.name.size() >= 5
            && parsed.name.compare(parsed.name.size() - 5, 5, ".page") == 0)
            return pm::model::ResourceType::Page;
        return pm::model::ResourceType::Unknown;
    }
    if (parsed.type == "settings") return pm::model::ResourceType::SettingsProfile;
    if (parsed.type == "command-config") return pm::model::ResourceType::CommandConfig;
    if (parsed.type == "mcp-config") return pm::model::ResourceType::McpConfig;
    if (parsed.type == "prompt-template") return pm::model::ResourceType::PromptTemplate;
    if (parsed.type == "page") return pm::model::ResourceType::Page;
    if (parsed.type == "prompt") return pm::model::ResourceType::Prompt;
    if (parsed.type == "session") return pm::model::ResourceType::SessionTranscript;
    if (parsed.type == "session-memory") return pm::model::ResourceType::SessionMemory;
    if (parsed.type == "session-artifact") return pm::model::ResourceType::SessionArtifact;
    if (parsed.type == "session-log") return pm::model::ResourceType::SessionLog;
    return pm::model::ResourceType::Unknown;
}

bool is_session_document_type(pm::model::ResourceType type) {
    return type == pm::model::ResourceType::SessionTranscript ||
           type == pm::model::ResourceType::SessionMemory ||
           type == pm::model::ResourceType::SessionArtifact ||
           type == pm::model::ResourceType::SessionLog;
}

int trust_rank(pm::model::TrustLevel trust) {
    switch (trust) {
    case pm::model::TrustLevel::Builtin: return 5;
    case pm::model::TrustLevel::SignedVendor: return 4;
    case pm::model::TrustLevel::PeerSigned: return 3;
    case pm::model::TrustLevel::UserLocal: return 2;
    case pm::model::TrustLevel::Workspace: return 1;
    case pm::model::TrustLevel::Untrusted: return 0;
    }
    return 0;
}

bool trust_allowed(pm::model::TrustLevel trust, const DocumentLoadPolicy& policy) {
    if (policy.allowed_trust.empty())
        return true;
    for (const auto allowed : policy.allowed_trust) {
        if (allowed == trust)
            return true;
    }
    return false;
}

bool is_vendor_seed_plaintext(const pm::model::ResourceMeta& meta) {
    return !meta.encrypted &&
        (meta.trust == pm::model::TrustLevel::SignedVendor ||
         meta.trust == pm::model::TrustLevel::Builtin);
}

bool validate_document_policy(const pm::model::ResourceMeta& meta,
                              const DocumentLoadPolicy& policy,
                              std::string& err) {
    if (!trust_allowed(meta.trust, policy)) {
        err = "document trust is not allowed by policy";
        return false;
    }
    if (policy.require_encryption && !meta.encrypted) {
        if (!(policy.allow_vendor_seed_plaintext && is_vendor_seed_plaintext(meta))) {
            err = "document encryption required by policy";
            return false;
        }
    }
    return true;
}

SignerPinCode load_local_signing_public_key(const StoragePaths& paths,
                                             std::vector<std::uint8_t>& public_key,
                                             std::string* unwrap_detail);
bool vendor_document_keypair(std::vector<std::uint8_t>& public_key,
                             std::vector<std::uint8_t>& secret_key,
                             std::string& err);

SignerPinCode signer_matches_anchor(const StoragePaths& paths,
                                    pm::model::TrustLevel trust,
                                    const std::string& signer_public_key_b64,
                                    std::string* unwrap_detail) {
    if (trust != pm::model::TrustLevel::UserLocal &&
        trust != pm::model::TrustLevel::SignedVendor &&
        trust != pm::model::TrustLevel::Builtin)
        return SignerPinCode::Ok;

    std::vector<std::uint8_t> anchor;
    if (trust == pm::model::TrustLevel::UserLocal) {
        const SignerPinCode loaded = load_local_signing_public_key(paths, anchor, unwrap_detail);
        if (loaded != SignerPinCode::Ok)
            return loaded;
    } else {
        anchor.assign(std::begin(pm::storage::bundle::k_bundle_signing_public_key_ed25519),
                      std::end(pm::storage::bundle::k_bundle_signing_public_key_ed25519));
    }
    if (signer_public_key_b64 != b64(anchor)) {
        return trust == pm::model::TrustLevel::UserLocal
                   ? SignerPinCode::ProfileSignerMismatch
                   : SignerPinCode::VendorSignerMismatch;
    }
    return SignerPinCode::Ok;
}

bool verify_document_signature_file(const StoragePaths& paths,
                                    const std::string& slug,
                                    pm::model::TrustLevel trust,
                                    bool require_signature,
                                    bool& signed_manifest,
                                    bool& signature_valid,
                                    std::string& signer_public_key,
                                    SignerPinCode& signer_pin,
                                    std::string& err) {
    signed_manifest = false;
    signature_valid = false;
    signer_public_key.clear();
    signer_pin = SignerPinCode::Ok;
    const fs::path sig_path = document_signature_path(paths, slug);
    if (!fs::exists(sig_path)) {
        if (require_signature) {
            err = "document signature required by policy";
            return false;
        }
        return true;
    }
    signed_manifest = true;
    std::vector<std::uint8_t> manifest_bytes;
    if (!read_bytes(document_meta_path(paths, slug), manifest_bytes, err))
        return false;
    json sig_doc;
    if (!read_json_file(sig_path, sig_doc, err))
        return false;
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> signature;
    if (!b64_decode(sig_doc.value("publicKey", std::string{}), public_key, err) ||
        !b64_decode(sig_doc.value("signature", std::string{}), signature, err))
        return false;
    signer_public_key = sig_doc.value("publicKey", std::string{});
    signature_valid =
        public_key.size() == crypto_sign_PUBLICKEYBYTES &&
        signature.size() == crypto_sign_BYTES &&
        crypto_sign_verify_detached(signature.data(),
                                    manifest_bytes.data(),
                                    static_cast<unsigned long long>(manifest_bytes.size()),
                                    public_key.data()) == 0;
    if (!signature_valid) {
        err = "document signature invalid";
        return false;
    }
    std::string unwrap_detail;
    signer_pin = signer_matches_anchor(paths, trust, signer_public_key, &unwrap_detail);
    if (signer_pin != SignerPinCode::Ok) {
        signature_valid = false;
        err = unwrap_detail.empty() ? signer_pin_message(signer_pin) : unwrap_detail;
        return false;
    }
    return true;
}

json manifest_json(const pm::model::ResourceMeta& meta) {
    return json{
        {"schema", pm::model::k_resource_manifest_schema},
        {"version", pm::model::k_resource_manifest_version},
        {"expires", utc_expiry_default()},
        {"resources", json::array({pm::model::resource_meta_to_json(meta)})},
    };
}

json document_manifest_json(const pm::model::ResourceMeta& meta) {
    return json{
        {"schema", pm::model::k_document_manifest_schema},
        {"version", 1},
        {"document", pm::model::resource_meta_to_json(meta)},
    };
}

bool meta_for_uri(const StoragePaths& paths, const std::string& uri, pm::model::ResourceMeta& meta, std::string& err) {
    json index;
    if (!load_index(paths, index, err))
        return false;
    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(uri, parsed, err))
        return false;
    const auto it = index["resources"].find(parsed.canonical);
    if (it == index["resources"].end()) {
        err = "resource not found: " + parsed.canonical;
        return false;
    }
    if (!pm::model::resource_meta_from_json(*it, meta)) {
        err = "resource metadata is invalid";
        return false;
    }
    return true;
}

SignerPinCode load_local_signing_public_key(const StoragePaths& paths,
                                             std::vector<std::uint8_t>& public_key,
                                             std::string* unwrap_detail) {
    public_key.clear();
    if (unwrap_detail)
        unwrap_detail->clear();
    if (sodium_init() < 0)
        return SignerPinCode::ProfileKeyUnreadable;
    if (!fs::exists(paths.local_signing_key))
        return SignerPinCode::ProfileKeyMissing;
    std::string err;
    std::vector<std::uint8_t> secret_key;
    std::vector<std::uint8_t> wrapped;
    if (!read_bytes(paths.local_signing_key, wrapped, err))
        return SignerPinCode::ProfileKeyUnreadable;
    if (!unwrap_local_secret(wrapped, secret_key, err)) {
        // A refused Hello/PIN prompt is the reason the key stayed locked.
        // Keep that text; other unwrap failures stay the generic pin message.
        if (unwrap_detail && err.find("confirmation required") != std::string::npos)
            *unwrap_detail = err;
        return SignerPinCode::ProfileKeyUnwrapFailed;
    }
    if (secret_key.size() != crypto_sign_SECRETKEYBYTES) {
        sodium_memzero(secret_key.data(), secret_key.size());
        return SignerPinCode::ProfileKeyInvalid;
    }
    public_key.assign(crypto_sign_PUBLICKEYBYTES, 0);
    crypto_sign_ed25519_sk_to_pk(public_key.data(), secret_key.data());
    sodium_memzero(secret_key.data(), secret_key.size());
    return SignerPinCode::Ok;
}

bool vendor_document_keypair(std::vector<std::uint8_t>& public_key,
                             std::vector<std::uint8_t>& secret_key,
                             std::string& err) {
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    const char* seed_text = std::getenv("PM_BUNDLE_SIGNING_SEED_HEX");
    if (!seed_text || std::strlen(seed_text) != 64) {
        err = "vendor document signing requires PM_BUNDLE_SIGNING_SEED_HEX";
        return false;
    }
    unsigned char seed[crypto_sign_SEEDBYTES];
    if (sodium_hex2bin(seed, sizeof seed, seed_text, 64, nullptr, nullptr, nullptr) != 0) {
        err = "PM_BUNDLE_SIGNING_SEED_HEX is not valid hex";
        return false;
    }
    public_key.assign(crypto_sign_PUBLICKEYBYTES, 0);
    secret_key.assign(crypto_sign_SECRETKEYBYTES, 0);
    const int key_rc = crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed);
    sodium_memzero(seed, sizeof seed);
    if (key_rc != 0) {
        err = "crypto_sign_seed_keypair failed";
        return false;
    }
    std::vector<std::uint8_t> expect(std::begin(pm::storage::bundle::k_bundle_signing_public_key_ed25519),
                                     std::end(pm::storage::bundle::k_bundle_signing_public_key_ed25519));
    if (public_key != expect) {
        sodium_memzero(secret_key.data(), secret_key.size());
        err = "PM_BUNDLE_SIGNING_SEED_HEX does not match the compiled vendor public key";
        return false;
    }
    return true;
}

bool load_or_create_signing_key(const StoragePaths& paths,
                                std::vector<std::uint8_t>& public_key,
                                std::vector<std::uint8_t>& secret_key,
                                std::string& err) {
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    public_key.assign(crypto_sign_PUBLICKEYBYTES, 0);
    secret_key.assign(crypto_sign_SECRETKEYBYTES, 0);
    if (fs::exists(paths.local_signing_key)) {
        std::vector<std::uint8_t> wrapped;
        if (!read_bytes(paths.local_signing_key, wrapped, err))
            return false;
        if (!unwrap_local_secret(wrapped, secret_key, err))
            return false;
        if (secret_key.size() != crypto_sign_SECRETKEYBYTES) {
            err = "local signing key has invalid length";
            return false;
        }
        crypto_sign_ed25519_sk_to_pk(public_key.data(), secret_key.data());
        return true;
    }

    // Do not call crypto_sign_keypair(): that name is also exported by
    // libssh's bundled ed25519, and /FORCE:MULTIPLE in pm-media.dll can bind
    // the libssh copy (uninitialized mbedTLS CTR_DRBG -> AES-NI AV).
    unsigned char seed[crypto_sign_SEEDBYTES];
    randombytes_buf(seed, sizeof seed);
    const int key_rc = crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed);
    sodium_memzero(seed, sizeof seed);
    if (key_rc != 0) {
        err = "crypto_sign_seed_keypair failed";
        return false;
    }
    std::vector<std::uint8_t> wrapped;
    if (!wrap_local_secret(secret_key, wrapped, err))
        return false;
    return write_bytes_atomic(paths.local_signing_key, wrapped, err);
}

bool write_document_signature_for_slug(const StoragePaths& paths,
                                       const std::string& slug,
                                       std::string& public_key_b64,
                                       std::string& signature_b64,
                                       std::string& err) {
    std::vector<std::uint8_t> manifest_bytes;
    if (!read_bytes(document_meta_path(paths, slug), manifest_bytes, err))
        return false;
    pm::model::TrustLevel trust = pm::model::TrustLevel::UserLocal;
    json manifest;
    pm::model::ResourceMeta meta;
    if (read_json_file(document_meta_path(paths, slug), manifest, err) &&
        pm::model::resource_meta_from_json(manifest.value("document", json::object()), meta))
        trust = meta.trust;
    err.clear();
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> secret_key;
    const bool vendor = trust == pm::model::TrustLevel::SignedVendor ||
                        trust == pm::model::TrustLevel::Builtin;
    if (vendor) {
        if (!vendor_document_keypair(public_key, secret_key, err))
            return false;
    } else if (!load_or_create_signing_key(paths, public_key, secret_key, err)) {
        return false;
    }
    std::vector<std::uint8_t> signature(crypto_sign_BYTES, 0);
    crypto_sign_detached(signature.data(),
                         nullptr,
                         manifest_bytes.data(),
                         static_cast<unsigned long long>(manifest_bytes.size()),
                         secret_key.data());
    sodium_memzero(secret_key.data(), secret_key.size());
    public_key_b64 = b64(public_key);
    signature_b64 = b64(signature);
    const json sig_doc{
        {"schema", k_signature_schema},
        {"algorithm", "ed25519"},
        {"publicKey", public_key_b64},
        {"signature", signature_b64},
    };
    return write_text_atomic(document_signature_path(paths, slug),
                             pm::model::canonical_json_dump(sig_doc),
                             err);
}

bool ensure_wrapped_random_key(const fs::path& path, std::size_t bytes, std::string& err);

bool load_or_create_encryption_key(const StoragePaths& paths,
                                   std::vector<std::uint8_t>& key,
                                   std::string& err) {
    if (!ensure_wrapped_random_key(paths.local_encryption_key, crypto_secretbox_KEYBYTES, err))
        return false;
    std::vector<std::uint8_t> wrapped;
    if (!read_bytes(paths.local_encryption_key, wrapped, err))
        return false;
    if (!unwrap_local_secret(wrapped, key, err))
        return false;
    if (key.size() != crypto_secretbox_KEYBYTES) {
        err = "local encryption key has invalid length";
        return false;
    }
    return true;
}

bool encrypt_document_bytes(const StoragePaths& paths,
                            const std::vector<std::uint8_t>& plaintext,
                            std::vector<std::uint8_t>& encoded,
                            std::string& err) {
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    std::vector<std::uint8_t> key;
    if (!load_or_create_encryption_key(paths, key, err))
        return false;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    std::vector<std::uint8_t> cipher(plaintext.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(cipher.data(),
                              plaintext.empty() ? nullptr : plaintext.data(),
                              static_cast<unsigned long long>(plaintext.size()),
                              nonce,
                              key.data()) != 0) {
        err = "crypto_secretbox_easy failed";
        return false;
    }
    encoded.clear();
    encoded.reserve(sizeof(k_document_encrypted_magic) + sizeof nonce + cipher.size());
    encoded.insert(encoded.end(), std::begin(k_document_encrypted_magic), std::end(k_document_encrypted_magic));
    encoded.insert(encoded.end(), nonce, nonce + sizeof nonce);
    encoded.insert(encoded.end(), cipher.begin(), cipher.end());
    return true;
}

bool decrypt_document_bytes(const StoragePaths& paths,
                            const std::vector<std::uint8_t>& encoded,
                            std::vector<std::uint8_t>& plaintext,
                            std::string& err) {
    plaintext.clear();
    if (encoded.size() < sizeof(k_document_encrypted_magic) + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES ||
        std::memcmp(encoded.data(), k_document_encrypted_magic, sizeof(k_document_encrypted_magic)) != 0) {
        err = "encrypted document is invalid";
        return false;
    }
    std::vector<std::uint8_t> key;
    if (!load_or_create_encryption_key(paths, key, err))
        return false;
    const std::uint8_t* nonce = encoded.data() + sizeof(k_document_encrypted_magic);
    const std::uint8_t* cipher = nonce + crypto_secretbox_NONCEBYTES;
    const std::size_t cipher_len = encoded.size() - sizeof(k_document_encrypted_magic) - crypto_secretbox_NONCEBYTES;
    plaintext.resize(cipher_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plaintext.data(),
                                   cipher,
                                   static_cast<unsigned long long>(cipher_len),
                                   nonce,
                                   key.data()) != 0) {
        err = "crypto_secretbox_open_easy failed (wrong key or corrupt document)";
        return false;
    }
    return true;
}

bool ensure_wrapped_random_key(const fs::path& path, std::size_t bytes, std::string& err) {
    if (fs::exists(path))
        return true;
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    std::vector<std::uint8_t> plain(bytes, 0);
    randombytes_buf(plain.data(), plain.size());
    std::vector<std::uint8_t> wrapped;
    if (!wrap_local_secret(plain, wrapped, err))
        return false;
    return write_bytes_atomic(path, wrapped, err);
}

bool read_json_file(const fs::path& path, json& out, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open JSON file: " + path.string();
        return false;
    }
    try {
        in >> out;
    } catch (const std::exception& e) {
        err = std::string("failed to parse JSON file: ") + e.what();
        return false;
    }
    return true;
}

} // namespace

const char* signer_pin_code_name(SignerPinCode code) {
    switch (code) {
    case SignerPinCode::Ok: return "ok";
    case SignerPinCode::ProfileKeyMissing: return "profile_key_missing";
    case SignerPinCode::ProfileKeyUnreadable: return "profile_key_unreadable";
    case SignerPinCode::ProfileKeyUnwrapFailed: return "profile_key_unwrap_failed";
    case SignerPinCode::ProfileKeyInvalid: return "profile_key_invalid";
    case SignerPinCode::ProfileSignerMismatch: return "profile_signer_mismatch";
    case SignerPinCode::VendorSignerMismatch: return "vendor_signer_mismatch";
    }
    return "ok";
}

const char* signer_pin_message(SignerPinCode code) {
    switch (code) {
    case SignerPinCode::Ok:
        return "";
    case SignerPinCode::ProfileKeyMissing:
        return "Profile signing key is missing. Documents signed for this profile cannot be checked.";
    case SignerPinCode::ProfileKeyUnreadable:
        return "Profile signing key could not be read.";
    case SignerPinCode::ProfileKeyUnwrapFailed:
        return "Profile signing key could not be unlocked.";
    case SignerPinCode::ProfileKeyInvalid:
        return "Profile signing key is corrupt.";
    case SignerPinCode::ProfileSignerMismatch:
        return "Document was not signed by this profile's signing key.";
    case SignerPinCode::VendorSignerMismatch:
        return "Document was not signed by the vendor key.";
    }
    return "";
}

StoragePaths resolve_storage_paths(const fs::path& config_dir) {
    StoragePaths p;
    p.root = config_dir / "resources";
    p.manifests = p.root / "manifests";
    p.blobs = p.root / "blobs";
    p.indexes = p.root / "indexes";
    p.keys = p.root / "keys";
    p.uri_index = p.indexes / "uri-index.json";
    p.doc_index = p.indexes / "doc-index.json";
    p.local_signing_key = p.keys / "local-signing-key.pme1";
    p.local_encryption_key = p.keys / "local-encryption-key.pme1";
    return p;
}

namespace {

fs::path encryption_key_backup_path(const StoragePaths& paths) {
    fs::path bak = paths.local_encryption_key;
    bak.concat(".bak");
    return bak;
}

} // namespace

bool replace_local_encryption_key(const StoragePaths& paths,
                                  std::vector<std::uint8_t>& previous_wrapped,
                                  std::string& err) {
    previous_wrapped.clear();
    std::error_code ec;
    if (fs::is_regular_file(paths.local_encryption_key, ec) && !ec) {
        if (!read_bytes(paths.local_encryption_key, previous_wrapped, err))
            return false;
        if (!write_bytes_atomic(encryption_key_backup_path(paths), previous_wrapped, err))
            return false;
        fs::remove(paths.local_encryption_key, ec);
        if (ec) {
            err = "failed to remove encryption key: " + ec.message();
            return false;
        }
    }
    if (!ensure_wrapped_random_key(paths.local_encryption_key, crypto_secretbox_KEYBYTES, err)) {
        if (!previous_wrapped.empty()) {
            std::string restore_err;
            write_bytes_atomic(paths.local_encryption_key, previous_wrapped, restore_err);
        }
        return false;
    }
    return true;
}

bool restore_local_encryption_key(const StoragePaths& paths,
                                  const std::vector<std::uint8_t>& previous_wrapped,
                                  std::string& err) {
    if (previous_wrapped.empty()) {
        std::error_code ec;
        fs::remove(paths.local_encryption_key, ec);
        if (ec) {
            err = "failed to remove encryption key: " + ec.message();
            return false;
        }
        return true;
    }
    return write_bytes_atomic(paths.local_encryption_key, previous_wrapped, err);
}

void discard_replaced_encryption_key_backup(const StoragePaths& paths) {
    std::error_code ec;
    fs::remove(encryption_key_backup_path(paths), ec);
}

bool ensure_storage_layout(const StoragePaths& paths, std::string& err) {
    std::error_code ec;
    fs::create_directories(paths.manifests, ec);
    if (ec) { err = "failed to create manifests directory"; return false; }
    fs::create_directories(paths.blobs / "sha256", ec);
    if (ec) { err = "failed to create blobs directory"; return false; }
    fs::create_directories(documents_dir(paths), ec);
    if (ec) { err = "failed to create documents directory"; return false; }
    fs::create_directories(paths.indexes, ec);
    if (ec) { err = "failed to create indexes directory"; return false; }
    fs::create_directories(paths.keys, ec);
    if (ec) { err = "failed to create keys directory"; return false; }
    (void)harden_storage_dir(paths.root);
    if (!ensure_wrapped_random_key(paths.local_encryption_key, crypto_secretbox_KEYBYTES, err))
        return false;
    return true;
}

std::string sha256_hex(const std::vector<std::uint8_t>& bytes) {
    if (sodium_init() < 0)
        return {};
    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(
        digest,
        bytes.empty() ? nullptr : bytes.data(),
        static_cast<unsigned long long>(bytes.size()));
    char hex[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), digest, sizeof(digest));
    return std::string(hex);
}

StoreResult put_resource(const StoragePaths& paths, const PutResourceRequest& request) {
    StoreResult result;
    std::string err;
    if (!ensure_storage_layout(paths, err)) {
        result.error = err;
        return result;
    }

    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(request.uri, parsed, err)) {
        result.error = err;
        return result;
    }
    if (request.data.empty()) {
        result.error = "resource data is empty";
        return result;
    }

    const std::string digest = sha256_hex(request.data);
    if (digest.empty()) {
        result.error = "failed to compute sha256 digest";
        return result;
    }

    const fs::path blob = blob_path(paths, digest);
    if (!fs::exists(blob) && !write_bytes_atomic(blob, request.data, err)) {
        result.error = err;
        return result;
    }

    json index;
    if (!load_index(paths, index, err)) {
        result.error = err;
        return result;
    }

    const std::string now = utc_now();
    pm::model::ResourceMeta meta;
    meta.uri = parsed.canonical;
    meta.type = request.type;
    meta.trust = request.trust;
    meta.digest = {"sha256", digest};
    meta.version = request.version;
    meta.provider = request.provider;
    meta.signer_id = request.signer_id;
    meta.bundle_id = request.bundle_id;
    meta.created_at = now;
    meta.updated_at = now;
    meta.encrypted = request.encrypted;
    meta.size_bytes = static_cast<std::uint64_t>(request.data.size());

    if (const auto existing = index["resources"].find(meta.uri);
        existing != index["resources"].end() && existing->is_object()) {
        pm::model::ResourceMeta old_meta;
        if (pm::model::resource_meta_from_json(*existing, old_meta) && !old_meta.created_at.empty())
            meta.created_at = old_meta.created_at;
    }

    index["resources"][meta.uri] = pm::model::resource_meta_to_json(meta);
    if (!save_index(paths, index, err)) {
        result.error = err;
        return result;
    }

    const fs::path out_manifest_path = manifest_path(paths, digest);
    if (!write_text_atomic(out_manifest_path, pm::model::canonical_json_dump(manifest_json(meta)), err)) {
        result.error = err;
        return result;
    }

    result.ok = true;
    result.meta = std::move(meta);
    return result;
}

LoadResult load_resource(const StoragePaths& paths, const std::string& uri) {
    LoadResult result;
    std::string err;
    json index;
    if (!load_index(paths, index, err)) {
        result.error = err;
        return result;
    }

    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(uri, parsed, err)) {
        result.error = err;
        return result;
    }

    const auto it = index["resources"].find(parsed.canonical);
    if (it == index["resources"].end()) {
        result.error = "resource not found: " + parsed.canonical;
        return result;
    }
    if (!pm::model::resource_meta_from_json(*it, result.resource.meta)) {
        result.error = "resource metadata is invalid";
        return result;
    }

    if (!read_bytes(blob_path(paths, result.resource.meta.digest.hex), result.resource.data, err)) {
        result.error = err;
        return result;
    }
    result.ok = true;
    return result;
}

ListResult list_resources(const StoragePaths& paths) {
    ListResult result;
    std::string err;
    json index;
    if (!load_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    for (const auto& item : index["resources"].items()) {
        pm::model::ResourceMeta meta;
        if (pm::model::resource_meta_from_json(item.value(), meta))
            result.items.push_back(std::move(meta));
    }
    result.ok = true;
    return result;
}

VerifyResult verify_resource(const StoragePaths& paths, const std::string& uri) {
    VerifyResult result;
    LoadResult loaded = load_resource(paths, uri);
    if (!loaded.ok) {
        result.error = loaded.error;
        return result;
    }
    result.meta = loaded.resource.meta;
    result.actual_digest = sha256_hex(loaded.resource.data);
    result.ok = !result.actual_digest.empty() && result.actual_digest == result.meta.digest.hex;
    if (!result.ok) {
        result.error = "digest mismatch";
        return result;
    }

    const fs::path sig_path = signature_path(paths, result.meta.digest.hex);
    if (!fs::exists(sig_path))
        return result;

    result.signed_manifest = true;
    std::string err;
    std::vector<std::uint8_t> manifest_bytes;
    if (!read_bytes(manifest_path(paths, result.meta.digest.hex), manifest_bytes, err)) {
        result.ok = false;
        result.error = err;
        return result;
    }
    json sig_doc;
    if (!read_json_file(sig_path, sig_doc, err)) {
        result.ok = false;
        result.error = err;
        return result;
    }
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> signature;
    if (!b64_decode(sig_doc.value("publicKey", std::string{}), public_key, err) ||
        !b64_decode(sig_doc.value("signature", std::string{}), signature, err)) {
        result.ok = false;
        result.error = err;
        return result;
    }
    result.signer_public_key = sig_doc.value("publicKey", std::string{});
    result.signature_valid =
        public_key.size() == crypto_sign_PUBLICKEYBYTES &&
        signature.size() == crypto_sign_BYTES &&
        crypto_sign_verify_detached(signature.data(),
                                    manifest_bytes.data(),
                                    static_cast<unsigned long long>(manifest_bytes.size()),
                                    public_key.data()) == 0;
    result.ok = result.signature_valid;
    if (!result.ok)
        result.error = "manifest signature invalid";
    return result;
}

SignResult sign_resource_manifest(const StoragePaths& paths, const std::string& uri) {
    SignResult result;
    std::string err;
    if (!ensure_storage_layout(paths, err)) {
        result.error = err;
        return result;
    }
    if (!meta_for_uri(paths, uri, result.meta, err)) {
        result.error = err;
        return result;
    }
    std::vector<std::uint8_t> manifest_bytes;
    if (!read_bytes(manifest_path(paths, result.meta.digest.hex), manifest_bytes, err)) {
        result.error = err;
        return result;
    }
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> secret_key;
    if (!load_or_create_signing_key(paths, public_key, secret_key, err)) {
        result.error = err;
        return result;
    }
    std::vector<std::uint8_t> signature(crypto_sign_BYTES, 0);
    crypto_sign_detached(signature.data(),
                         nullptr,
                         manifest_bytes.data(),
                         static_cast<unsigned long long>(manifest_bytes.size()),
                         secret_key.data());
    result.public_key = b64(public_key);
    result.signature = b64(signature);
    const json sig_doc{
        {"schema", k_signature_schema},
        {"algorithm", "ed25519"},
        {"publicKey", result.public_key},
        {"signature", result.signature},
    };
    if (!write_text_atomic(signature_path(paths, result.meta.digest.hex),
                           pm::model::canonical_json_dump(sig_doc),
                           err)) {
        result.error = err;
        return result;
    }
    result.ok = true;
    return result;
}

PackageResult export_resource_package(const StoragePaths& paths,
                                      const std::string& uri,
                                      const fs::path& package_path) {
    PackageResult result;
    std::string err;
    if (!meta_for_uri(paths, uri, result.meta, err)) {
        result.error = err;
        return result;
    }
    json manifest;
    if (!read_json_file(manifest_path(paths, result.meta.digest.hex), manifest, err)) {
        result.error = err;
        return result;
    }
    json signature = nullptr;
    const fs::path sig_path = signature_path(paths, result.meta.digest.hex);
    if (fs::exists(sig_path) && !read_json_file(sig_path, signature, err)) {
        result.error = err;
        return result;
    }
    std::vector<std::uint8_t> data;
    if (!read_bytes(blob_path(paths, result.meta.digest.hex), data, err)) {
        result.error = err;
        return result;
    }
    const json pkg{
        {"schema", k_package_schema},
        {"version", 1},
        {"manifest", manifest},
        {"signature", signature},
        {"blob", {
            {"algorithm", "sha256"},
            {"hex", result.meta.digest.hex},
            {"dataBase64", b64(data)},
        }},
    };
    if (!write_text_atomic(package_path, pm::model::canonical_json_dump(pkg), err)) {
        result.error = err;
        return result;
    }
    result.package_path = package_path;
    result.ok = true;
    return result;
}

PackageResult import_resource_package(const StoragePaths& paths,
                                      const fs::path& package_path) {
    PackageResult result;
    std::string err;
    if (!ensure_storage_layout(paths, err)) {
        result.error = err;
        return result;
    }
    json pkg;
    if (!read_json_file(package_path, pkg, err)) {
        result.error = err;
        return result;
    }
    if (!pkg.is_object() || pkg.value("schema", std::string{}) != k_package_schema) {
        result.error = "unsupported resource package schema";
        return result;
    }
    const json manifest = pkg.value("manifest", json::object());
    if (!manifest.is_object() || manifest.value("schema", std::string{}) != pm::model::k_resource_manifest_schema ||
        !manifest.contains("resources") || !manifest["resources"].is_array() ||
        manifest["resources"].empty()) {
        result.error = "resource package manifest is invalid";
        return result;
    }
    if (!pm::model::resource_meta_from_json(manifest["resources"][0], result.meta)) {
        result.error = "resource package metadata is invalid";
        return result;
    }
    std::vector<std::uint8_t> data;
    const json blob = pkg.value("blob", json::object());
    if (!blob.is_object() || blob.value("hex", std::string{}) != result.meta.digest.hex ||
        !b64_decode(blob.value("dataBase64", std::string{}), data, err)) {
        result.error = err.empty() ? "resource package blob is invalid" : err;
        return result;
    }
    const std::string actual = sha256_hex(data);
    if (actual != result.meta.digest.hex) {
        result.error = "resource package blob digest mismatch";
        return result;
    }
    if (!write_bytes_atomic(blob_path(paths, result.meta.digest.hex), data, err)) {
        result.error = err;
        return result;
    }
    if (!write_text_atomic(manifest_path(paths, result.meta.digest.hex),
                           pm::model::canonical_json_dump(manifest),
                           err)) {
        result.error = err;
        return result;
    }
    if (pkg.contains("signature") && pkg["signature"].is_object()) {
        if (!write_text_atomic(signature_path(paths, result.meta.digest.hex),
                               pm::model::canonical_json_dump(pkg["signature"]),
                               err)) {
            result.error = err;
            return result;
        }
    }
    json index;
    if (!load_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    index["resources"][result.meta.uri] = pm::model::resource_meta_to_json(result.meta);
    if (!save_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    result.package_path = package_path;
    result.ok = true;
    return result;
}

DocumentResult put_document(const StoragePaths& paths, const PutDocumentRequest& request) {
    DocumentResult result;
    std::string err;
    if (!ensure_storage_layout(paths, err)) {
        result.error = err;
        return result;
    }

    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(request.uri, parsed, err)) {
        result.error = err;
        return result;
    }
    const pm::model::ResourceType expected_type = expected_type_for_uri(parsed);
    if (expected_type == pm::model::ResourceType::Unknown || request.type != expected_type) {
        result.error = "document type does not match URI namespace";
        return result;
    }
    if (request.data.empty()) {
        result.error = "document data is empty";
        return result;
    }
    if (!request.encrypt) {
        const bool vendor_seed =
            request.allow_plaintext_seed &&
            (request.trust == pm::model::TrustLevel::SignedVendor ||
             request.trust == pm::model::TrustLevel::Builtin);
        const bool session_plaintext =
            request.allow_plaintext_seed &&
            request.trust == pm::model::TrustLevel::UserLocal &&
            is_session_document_type(request.type);
        if ((request.type == pm::model::ResourceType::SettingsProfile ||
             request.type == pm::model::ResourceType::OAuthCredentials) &&
            !vendor_seed) {
            result.error = request.type == pm::model::ResourceType::OAuthCredentials
                               ? "oauth credential documents must be encrypted"
                               : "settings profile documents must be encrypted";
            return result;
        }
        if (!vendor_seed && !session_plaintext) {
            result.error = "plaintext documents require explicit vendor seed mode";
            return result;
        }
    }

    json index;
    if (!load_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }

    const std::string slug = document_slug(parsed);
    const auto existing = index["documents"].find(parsed.canonical);
    pm::model::ResourceMeta old_meta;
    const bool has_old_meta = existing != index["documents"].end() && existing->is_object() &&
        pm::model::resource_meta_from_json(existing->value("meta", json::object()), old_meta);
    // `.cloud_storage_key` only decrypts the pmbackup envelope. Restore still
    // writes UserLocal, which is allowed over UserLocal and rejected over a
    // higher rank. replace_vendor_seed is the explicit take-ownership path
    // (profile restore, user save): encrypted UserLocal may replace a
    // SignedVendor / Builtin seed. PeerSigned and every other downgrade stay
    // rejected, including a plain `storage doc put`.
    const bool replace_vendor_seed =
        has_old_meta &&
        request.replace_vendor_seed &&
        request.encrypt &&
        request.trust == pm::model::TrustLevel::UserLocal &&
        (old_meta.trust == pm::model::TrustLevel::SignedVendor ||
         old_meta.trust == pm::model::TrustLevel::Builtin);
    if (has_old_meta && !replace_vendor_seed &&
        trust_rank(request.trust) < trust_rank(old_meta.trust)) {
        result.error = "document trust downgrade rejected";
        return result;
    }

    std::vector<std::uint8_t> stored = request.data;
    if (request.encrypt && !encrypt_document_bytes(paths, request.data, stored, err)) {
        result.error = err;
        return result;
    }

    if (!write_bytes_atomic(document_blob_path(paths, slug), stored, err)) {
        result.error = err;
        return result;
    }

    const std::string now = utc_now();
    pm::model::ResourceMeta meta;
    meta.uri = parsed.canonical;
    meta.type = request.type;
    meta.trust = request.trust;
    meta.digest = {"sha256", sha256_hex(request.data)};
    meta.version = request.version.empty() ? "1" : request.version;
    meta.provider = request.provider.empty() ? "user" : request.provider;
    meta.signer_id = request.signer_id;
    meta.bundle_id = "document";
    meta.created_at = has_old_meta && !old_meta.created_at.empty() ? old_meta.created_at : now;
    meta.updated_at = now;
    meta.encrypted = request.encrypt;
    meta.size_bytes = static_cast<std::uint64_t>(request.data.size());
    if (meta.digest.hex.empty()) {
        result.error = "failed to compute sha256 digest";
        return result;
    }

    if (!write_text_atomic(document_meta_path(paths, slug),
                           pm::model::canonical_json_dump(document_manifest_json(meta)),
                           err)) {
        result.error = err;
        return result;
    }

    // Sign before the shared index commit. Two instances racing on
    // doc-index.json must not leave a rewritten document unsigned — load
    // reads meta+sig from disk and only uses the index for the slug.
    std::string public_key_b64;
    std::string signature_b64;
    if (!write_document_signature_for_slug(paths, slug, public_key_b64, signature_b64, err)) {
        result.error = err.empty() ? "failed to sign document after put" : err;
        return result;
    }

    index["documents"][meta.uri] = {
        {"slug", slug},
        {"meta", pm::model::resource_meta_to_json(meta)},
    };
    if (!save_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }

    result.ok = true;
    result.meta = std::move(meta);
    return result;
}

LoadDocumentResult load_document(const StoragePaths& paths, const std::string& uri) {
    DocumentLoadPolicy policy;
#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    if (pm::policy::policy_require_encryption()) policy.require_encryption = true;
    if (pm::policy::policy_require_signing())    policy.require_signature  = true;
#endif
    return load_document(paths, uri, policy);
}

LoadDocumentResult load_document(const StoragePaths& paths,
                                 const std::string& uri,
                                 const DocumentLoadPolicy& policy) {
    LoadDocumentResult result;
    std::string err;
    json index;
    if (!load_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }

    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(uri, parsed, err)) {
        result.error = err;
        return result;
    }
    const auto it = index["documents"].find(parsed.canonical);
    if (it == index["documents"].end() || !it->is_object()) {
        result.error = "document not found: " + parsed.canonical;
        return result;
    }
    const std::string slug = it->value("slug", std::string{});
    if (slug.empty()) {
        result.error = "document index entry is invalid";
        return result;
    }

    json manifest;
    if (!read_json_file(document_meta_path(paths, slug), manifest, err)) {
        result.error = err;
        return result;
    }
    if (!manifest.is_object() || manifest.value("schema", std::string{}) != pm::model::k_document_manifest_schema ||
        !pm::model::resource_meta_from_json(manifest.value("document", json::object()), result.document.meta)) {
        result.error = "document metadata is invalid";
        return result;
    }
    if (result.document.meta.uri != parsed.canonical ||
        result.document.meta.type != expected_type_for_uri(parsed)) {
        result.error = "document metadata does not match requested URI";
        return result;
    }
    if (!validate_document_policy(result.document.meta, policy, err)) {
        result.error = err;
        return result;
    }

    bool signed_manifest = false;
    bool signature_valid = false;
    std::string signer_public_key;
    if (!verify_document_signature_file(paths,
                                        slug,
                                        result.document.meta.trust,
                                        policy.require_signature,
                                        signed_manifest,
                                        signature_valid,
                                        signer_public_key,
                                        result.signer_pin,
                                        err)) {
        result.error = err;
        return result;
    }

    std::vector<std::uint8_t> stored;
    if (!read_bytes(document_blob_path(paths, slug), stored, err)) {
        result.error = err;
        return result;
    }
    if (result.document.meta.encrypted) {
        if (!decrypt_document_bytes(paths, stored, result.document.data, err)) {
            result.error = err;
            return result;
        }
    } else {
        result.document.data = std::move(stored);
    }
    const std::string actual = sha256_hex(result.document.data);
    if (actual.empty() || actual != result.document.meta.digest.hex) {
        result.error = "document digest mismatch";
        return result;
    }

    result.ok = true;
    return result;
}

static bool is_transient_document_io_error(const std::string& err) {
    if (err.empty())
        return false;
    // put_document replaces the blob, then the meta. A reader in that window
    // either misses settings.json.doc or hashes the new plaintext against the
    // previous digest. Both clear on the next attempt once the put finishes.
    return err == "document signature required by policy"
        || err == "document signature invalid"
        || err == "document digest mismatch"
        || err == "failed to open document index"
        || err.rfind("failed to open file:", 0) == 0
        || err.rfind("failed to read file:", 0) == 0
        || err.rfind("failed to stat file:", 0) == 0
        || err.rfind("failed to open JSON file:", 0) == 0
        || err.rfind("failed to parse JSON file:", 0) == 0
        || err.rfind("failed to parse document index:", 0) == 0;
}

LoadDocumentResult load_or_import_seed_document(const StoragePaths& paths,
                                                const std::string& uri,
                                                const DocumentLoadPolicy& profile_policy) {
    // Happy path: already have an encrypted UserLocal (or other profile) copy.
    // A concurrent put rewrites .sig / doc-index via temp+replace, so a reader can
    // miss the file for a few milliseconds. Retry those errors before giving up.
    LoadDocumentResult result;
    for (int attempt = 0; attempt < 4; ++attempt) {
        result = load_document(paths, uri, profile_policy);
        if (result.ok)
            return result;
        if (!is_transient_document_io_error(result.error) || attempt == 3)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    // A failed multi-instance put can rewrite meta/blob and drop the .sig
    // before the index commit. Re-sign UserLocal docs so settings recover.
    if (result.error == "document signature required by policy"
        || result.error == "document signature invalid") {
        const auto signed_doc = sign_document(paths, uri);
        if (signed_doc.ok) {
            auto retried = load_document(paths, uri, profile_policy);
            if (retried.ok) {
                pm::log::warn_lazy("storage", [&] {
                    return "re-signed unsigned document: " + uri;
                });
                return retried;
            }
        }
    }
    // Attempt to find a signed vendor seed in the same store and auto-import it.
    DocumentLoadPolicy seed_policy;
    seed_policy.require_signature           = true;
    seed_policy.allow_vendor_seed_plaintext = true;
    seed_policy.allowed_trust = {pm::model::TrustLevel::SignedVendor,
                                 pm::model::TrustLevel::Builtin};

    const auto verified = verify_document(paths, uri, seed_policy);
    if (!verified.ok)
        return result;  // no valid seed; propagate original error

    const auto seed = load_document(paths, uri, seed_policy);
    if (!seed.ok)
        return result;

    // Re-store as UserLocal + encrypted with the machine's local key.
    // replace_vendor_seed lets this overwrite the verified seed in place.
    PutDocumentRequest req;
    req.uri       = seed.document.meta.uri;
    req.type      = seed.document.meta.type;
    req.trust     = pm::model::TrustLevel::UserLocal;
    req.version   = seed.document.meta.version.empty() ? "1" : seed.document.meta.version;
    req.provider  = seed.document.meta.provider.empty() ? "vendor-seed" : seed.document.meta.provider;
    req.signer_id = verified.signer_public_key.empty()
        ? seed.document.meta.signer_id
        : ("vendor:" + verified.signer_public_key);
    req.encrypt   = true;
    req.replace_vendor_seed = true;
    req.data      = seed.document.data;

    const auto stored = put_document(paths, req);
    if (!stored.ok) {
        pm::log::warn_lazy("storage", [&]{
            return "seed import failed for " + uri + ": " + stored.error;
        });
        return result;  // import failed; propagate original error
    }

    sign_document(paths, uri);  // best-effort local sign

    pm::log::info_lazy("storage", [&]{
        return "seed import ok: " + uri + " (vendor -> UserLocal+encrypted)";
    });

    return load_document(paths, uri, profile_policy);
}

ListResult list_documents(const StoragePaths& paths) {
    ListResult result;
    std::string err;
    json index;
    if (!load_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    for (const auto& item : index["documents"].items()) {
        if (!item.value().is_object())
            continue;
        pm::model::ResourceMeta meta;
        if (pm::model::resource_meta_from_json(item.value().value("meta", json::object()), meta))
            result.items.push_back(std::move(meta));
    }
    result.ok = true;
    return result;
}

VerifyDocumentResult verify_document(const StoragePaths& paths, const std::string& uri) {
    DocumentLoadPolicy policy;
#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    if (pm::policy::policy_require_encryption()) policy.require_encryption = true;
    if (pm::policy::policy_require_signing())    policy.require_signature  = true;
#endif
    return verify_document(paths, uri, policy);
}

VerifyDocumentResult verify_document(const StoragePaths& paths,
                                     const std::string& uri,
                                     const DocumentLoadPolicy& policy) {
    VerifyDocumentResult result;
    std::string err;
    json index;
    if (!load_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(uri, parsed, err)) {
        result.error = err;
        return result;
    }
    const auto it = index["documents"].find(parsed.canonical);
    if (it == index["documents"].end() || !it->is_object()) {
        result.error = "document not found: " + parsed.canonical;
        return result;
    }
    const std::string slug = it->value("slug", std::string{});
    LoadDocumentResult loaded = load_document(paths, uri, policy);
    if (!loaded.ok) {
        result.error = loaded.error;
        result.signer_pin = loaded.signer_pin;
        return result;
    }
    result.meta = loaded.document.meta;
    result.signer_pin = loaded.signer_pin;
    result.actual_digest = sha256_hex(loaded.document.data);
    result.ok = !result.actual_digest.empty() && result.actual_digest == result.meta.digest.hex;
    if (!result.ok) {
        result.error = "document digest mismatch";
        return result;
    }

    if (!verify_document_signature_file(paths,
                                        slug,
                                        result.meta.trust,
                                        policy.require_signature,
                                        result.signed_manifest,
                                        result.signature_valid,
                                        result.signer_public_key,
                                        result.signer_pin,
                                        err)) {
        if (!policy.require_signature && !result.signed_manifest && err.empty())
            return result;
        result.ok = false;
        result.error = err;
        return result;
    }
    result.ok = result.signed_manifest ? result.signature_valid : result.ok;
    return result;
}

SignResult sign_document(const StoragePaths& paths, const std::string& uri) {
    SignResult result;
    std::string err;
    json index;
    if (!ensure_storage_layout(paths, err) || !load_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(uri, parsed, err)) {
        result.error = err;
        return result;
    }
    const auto it = index["documents"].find(parsed.canonical);
    if (it == index["documents"].end() || !it->is_object()) {
        result.error = "document not found: " + parsed.canonical;
        return result;
    }
    const std::string slug = it->value("slug", std::string{});
    json manifest;
    if (!read_json_file(document_meta_path(paths, slug), manifest, err) ||
        !pm::model::resource_meta_from_json(manifest.value("document", json::object()), result.meta)) {
        result.error = err.empty() ? "document metadata is invalid" : err;
        return result;
    }
    if (!write_document_signature_for_slug(paths, slug, result.public_key, result.signature, err)) {
        result.error = err;
        return result;
    }
    result.ok = true;
    return result;
}

DocumentResult delete_document(const StoragePaths& paths, const std::string& uri) {
    DocumentResult result;
    std::string err;
    json index;
    if (!load_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    pm::core::ResourceUri parsed;
    if (!pm::core::parse_resource_uri(uri, parsed, err)) {
        result.error = err;
        return result;
    }
    const auto it = index["documents"].find(parsed.canonical);
    if (it == index["documents"].end() || !it->is_object()) {
        result.error = "document not found: " + parsed.canonical;
        return result;
    }
    const std::string slug = it->value("slug", std::string{});
    if (pm::model::resource_meta_from_json(it->value("meta", json::object()), result.meta)) {
        // Keep meta for the JSON result.
    }
    std::error_code ec;
    fs::remove(document_blob_path(paths, slug), ec);
    ec.clear();
    fs::remove(document_meta_path(paths, slug), ec);
    ec.clear();
    fs::remove(document_signature_path(paths, slug), ec);
    index["documents"].erase(parsed.canonical);
    if (!save_doc_index(paths, index, err)) {
        result.error = err;
        return result;
    }
    result.ok = true;
    return result;
}

std::optional<std::filesystem::file_time_type>
document_write_time(const StoragePaths& paths, const std::string& uri)
{
    pm::core::ResourceUri parsed;
    std::string err;
    if (!pm::core::parse_resource_uri(uri, parsed, err))
        return std::nullopt;
    const std::string slug = document_slug(parsed);
    std::error_code ec;
    const auto meta = document_meta_path(paths, slug);
    auto ft = fs::last_write_time(meta, ec);
    if (!ec)
        return ft;
    ec.clear();
    const auto blob = document_blob_path(paths, slug);
    ft = fs::last_write_time(blob, ec);
    if (!ec)
        return ft;
    return std::nullopt;
}

} // namespace pm::storage
