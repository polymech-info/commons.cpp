#pragma once

#include "model/resource_types.hpp"

#include <nlohmann/json.hpp>

namespace pm::model {

inline constexpr const char* k_resource_manifest_schema = "pm.resource.bundle.v1";
inline constexpr int k_resource_manifest_version = 1;
inline constexpr const char* k_vendor_bundle_schema = "pm.resource.vendor-bundle.v1";
inline constexpr const char* k_user_share_schema = "pm.resource.user-share.v1";
inline constexpr const char* k_uri_index_schema = "resource-uri-index-1";
inline constexpr const char* k_document_manifest_schema = "pm.resource.document.v1";
inline constexpr const char* k_doc_index_schema = "resource-document-index-1";

inline std::string canonical_json_dump(const nlohmann::json& j) {
    return j.dump();
}

inline nlohmann::json resource_meta_to_json(const ResourceMeta& meta) {
    return nlohmann::json{
        {"uri", meta.uri},
        {"type", to_string(meta.type)},
        {"trust", to_string(meta.trust)},
        {"digest", {{"algorithm", meta.digest.algorithm}, {"hex", meta.digest.hex}}},
        {"version", meta.version},
        {"provider", meta.provider},
        {"signerId", meta.signer_id},
        {"bundleId", meta.bundle_id},
        {"createdAt", meta.created_at},
        {"updatedAt", meta.updated_at},
        {"encrypted", meta.encrypted},
        {"sizeBytes", meta.size_bytes},
    };
}

inline bool resource_meta_from_json(const nlohmann::json& j, ResourceMeta& out) {
    if (!j.is_object()) return false;
    out = {};
    out.uri = j.value("uri", std::string{});
    out.type = resource_type_from_string(j.value("type", std::string{}));
    out.trust = trust_level_from_string(j.value("trust", std::string{}));
    if (const auto it = j.find("digest"); it != j.end() && it->is_object()) {
        out.digest.algorithm = it->value("algorithm", std::string{"sha256"});
        out.digest.hex = it->value("hex", std::string{});
    }
    out.version = j.value("version", std::string{});
    out.provider = j.value("provider", std::string{});
    out.signer_id = j.value("signerId", std::string{});
    out.bundle_id = j.value("bundleId", std::string{});
    out.created_at = j.value("createdAt", std::string{});
    out.updated_at = j.value("updatedAt", std::string{});
    out.encrypted = j.value("encrypted", false);
    out.size_bytes = j.value("sizeBytes", static_cast<std::uint64_t>(0));
    return !out.uri.empty() && !out.digest.hex.empty();
}

} // namespace pm::model
