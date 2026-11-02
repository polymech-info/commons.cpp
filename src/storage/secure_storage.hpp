#pragma once

#include "model/resource_types.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace pm::storage {

enum class SecretProtectionMode {
    PlatformDefault,
    WindowsDpapi,
    WindowsHelloTpm,
    MockWindowsHello,
};

struct SecretProtectionPolicy {
    SecretProtectionMode mode = SecretProtectionMode::PlatformDefault;
    std::string key_name;
    bool require_user_confirmation = true;
};

struct StoragePaths {
    std::filesystem::path root;
    std::filesystem::path manifests;
    std::filesystem::path blobs;
    std::filesystem::path indexes;
    std::filesystem::path keys;
    std::filesystem::path uri_index;
    std::filesystem::path doc_index;
    std::filesystem::path local_signing_key;
    std::filesystem::path local_encryption_key;
};

struct PutResourceRequest {
    std::string uri;
    pm::model::ResourceType type = pm::model::ResourceType::Unknown;
    pm::model::TrustLevel trust = pm::model::TrustLevel::UserLocal;
    std::string version = "1";
    std::string provider = "user";
    std::string signer_id;
    std::string bundle_id = "local";
    bool encrypted = false;
    std::vector<std::uint8_t> data;
};

struct StoredResource {
    pm::model::ResourceMeta meta;
    std::vector<std::uint8_t> data;
};

struct PutDocumentRequest {
    std::string uri;
    pm::model::ResourceType type = pm::model::ResourceType::Unknown;
    pm::model::TrustLevel trust = pm::model::TrustLevel::UserLocal;
    std::string version = "1";
    std::string provider = "user";
    std::string signer_id;
    bool encrypt = true;
    bool allow_plaintext_seed = false;
    /// User restore or save may replace a SignedVendor / Builtin seed with an
    /// encrypted UserLocal document. A normal put still rejects that downgrade.
    bool replace_vendor_seed = false;
    std::vector<std::uint8_t> data;
};

struct DocumentLoadPolicy {
    bool require_signature = false;
    bool require_encryption = false;
    bool allow_vendor_seed_plaintext = false;
    std::vector<pm::model::TrustLevel> allowed_trust;
};

struct StoredDocument {
    pm::model::ResourceMeta meta;
    std::vector<std::uint8_t> data;
};

struct StoreResult {
    bool ok = false;
    std::string error;
    pm::model::ResourceMeta meta;
};

struct LoadResult {
    bool ok = false;
    std::string error;
    StoredResource resource;
};

struct ListResult {
    bool ok = false;
    std::string error;
    std::vector<pm::model::ResourceMeta> items;
};

// Why a document signature was accepted or rejected against its trust anchor.
// User-local documents must match local-signing-key.pme1. Vendor and builtin
// documents must match the compiled vendor public key.
enum class SignerPinCode {
    Ok = 0,
    ProfileKeyMissing,
    ProfileKeyUnreadable,
    ProfileKeyUnwrapFailed,
    ProfileKeyInvalid,
    ProfileSignerMismatch,
    VendorSignerMismatch,
};

const char* signer_pin_code_name(SignerPinCode code);
const char* signer_pin_message(SignerPinCode code);

struct VerifyResult {
    bool ok = false;
    std::string error;
    pm::model::ResourceMeta meta;
    std::string actual_digest;
    bool signed_manifest = false;
    bool signature_valid = false;
    std::string signer_public_key;
    SignerPinCode signer_pin = SignerPinCode::Ok;
};

struct SignResult {
    bool ok = false;
    std::string error;
    pm::model::ResourceMeta meta;
    std::string public_key;
    std::string signature;
};

struct PackageResult {
    bool ok = false;
    std::string error;
    pm::model::ResourceMeta meta;
    std::filesystem::path package_path;
};

struct DocumentResult {
    bool ok = false;
    std::string error;
    pm::model::ResourceMeta meta;
};

struct LoadDocumentResult {
    bool ok = false;
    std::string error;
    StoredDocument document;
    SignerPinCode signer_pin = SignerPinCode::Ok;
};

using VerifyDocumentResult = VerifyResult;

StoragePaths resolve_storage_paths(const std::filesystem::path& config_dir);
bool ensure_storage_layout(const StoragePaths& paths, std::string& err);
bool harden_storage_dir(const std::filesystem::path& dir);
bool wrap_local_secret(const std::vector<std::uint8_t>& plaintext,
                       std::vector<std::uint8_t>& wrapped,
                       std::string& err);
bool unwrap_local_secret(const std::vector<std::uint8_t>& wrapped,
                         std::vector<std::uint8_t>& plaintext,
                         std::string& err);
bool wrap_local_secret_with_policy(const std::vector<std::uint8_t>& plaintext,
                                   std::vector<std::uint8_t>& wrapped,
                                   const SecretProtectionPolicy& policy,
                                   std::string& err);
bool unwrap_local_secret_with_policy(const std::vector<std::uint8_t>& wrapped,
                                     std::vector<std::uint8_t>& plaintext,
                                     const SecretProtectionPolicy& policy,
                                     std::string& err);
SecretProtectionPolicy default_secret_protection_policy();

/// Challenge the user according to the active protection policy.
/// - PlatformDefault / WindowsDpapi: always returns true (DPAPI is the protection layer,
///   no interactive challenge is needed — pass through).
/// - MockWindowsHello: checks PM_SECURE_STORAGE_MOCK_HELLO_CONFIRM env var.
/// - WindowsHelloTpm: performs a real Windows Hello biometric/PIN challenge.
/// On non-Windows platforms always returns true (no platform mechanism available).
bool verify_user_presence(const SecretProtectionPolicy& policy, std::string& err);
/// Convenience: verify against the current default_secret_protection_policy().
bool verify_user_presence(std::string& err);

std::string sha256_hex(const std::vector<std::uint8_t>& bytes);

StoreResult put_resource(const StoragePaths& paths, const PutResourceRequest& request);
LoadResult load_resource(const StoragePaths& paths, const std::string& uri);
ListResult list_resources(const StoragePaths& paths);
VerifyResult verify_resource(const StoragePaths& paths, const std::string& uri);
SignResult sign_resource_manifest(const StoragePaths& paths, const std::string& uri);
PackageResult export_resource_package(const StoragePaths& paths,
                                      const std::string& uri,
                                      const std::filesystem::path& package_path);
PackageResult import_resource_package(const StoragePaths& paths,
                                      const std::filesystem::path& package_path);

DocumentResult put_document(const StoragePaths& paths, const PutDocumentRequest& request);
LoadDocumentResult load_document(const StoragePaths& paths, const std::string& uri);
LoadDocumentResult load_document(const StoragePaths& paths,
                                 const std::string& uri,
                                 const DocumentLoadPolicy& policy);
/// Try to load the document with `policy`.  On failure, look for a signed
/// vendor seed (SignedVendor / Builtin, plaintext, signature-verified) in the
/// same store and auto-import it: re-encrypt with the machine's local key,
/// store as UserLocal, sign locally, then reload with `policy`.
/// On first run this converts a distributed vendor seed into a machine-local
/// encrypted document transparently.  Subsequent calls skip the import path.
LoadDocumentResult load_or_import_seed_document(const StoragePaths& paths,
                                                const std::string& uri,
                                                const DocumentLoadPolicy& policy);
/// Last-write time of the stored document meta (or blob). Cheap cache key;
/// empty when the URI is missing or unreadable.
std::optional<std::filesystem::file_time_type>
document_write_time(const StoragePaths& paths, const std::string& uri);
ListResult list_documents(const StoragePaths& paths);
VerifyDocumentResult verify_document(const StoragePaths& paths, const std::string& uri);
VerifyDocumentResult verify_document(const StoragePaths& paths,
                                     const std::string& uri,
                                     const DocumentLoadPolicy& policy);
SignResult sign_document(const StoragePaths& paths, const std::string& uri);
DocumentResult delete_document(const StoragePaths& paths, const std::string& uri);

/// Replace local-encryption-key.pme1 with a new random key.
/// `previous_wrapped` receives the old wrapped key (empty when none existed).
/// A copy is also written beside the key as `local-encryption-key.pme1.bak`.
/// On failure the previous key file is put back.
bool replace_local_encryption_key(const StoragePaths& paths,
                                  std::vector<std::uint8_t>& previous_wrapped,
                                  std::string& err);
bool restore_local_encryption_key(const StoragePaths& paths,
                                  const std::vector<std::uint8_t>& previous_wrapped,
                                  std::string& err);
void discard_replaced_encryption_key_backup(const StoragePaths& paths);

} // namespace pm::storage
