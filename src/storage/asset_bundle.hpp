#pragma once

// All-in-one web app bundle (`*.pmbundle`).
//
// POC container for the P9 "web app bundle / pfs backed" work in
// docs/security/ss-todos.md. A bundle is a single, all-in-one archive blob:
// the whole web app directory (chat.html + sibling JS chunks + .wasm + assets)
// packed into ONE file that the secure-storage layer signs / verifies as a
// single `pm://app/<name>` resource.
//
// Format: store-only (uncompressed, method 0) ZIP. ZIP is what PhysicsFS mounts
// natively, so the SAME bytes verified here can later be served at runtime via
// PHYSFS_mountMemory() + a WebView2 / WKURLSchemeHandler request handler. This
// POC ships a small built-in ZIP reader so `bundle serve` can emulate a web
// engine resolving one sub-path request without linking PhysFS into the CLI.

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace pm::storage::bundle {

struct BundleEntry {
    std::string path;                  ///< forward-slash relative path inside the bundle
    std::vector<std::uint8_t> data;    ///< raw bytes
};

/// Lightweight index entry — points into the original zip buffer (no copy).
struct BundleEntryRef {
    std::string path;
    std::size_t data_offset = 0;
    std::uint32_t data_size = 0;
};

/// Parsed, CRC-validated bundle index. Build once (e.g. at load) and reuse for
/// every subresource request instead of re-scanning the central directory.
struct ParsedBundle {
    std::vector<BundleEntryRef> entries;
    std::unordered_map<std::string, std::size_t> index_by_path;
};

/// Map a bundle entry path to a web Content-Type (extension based).
std::string content_type_for_path(const std::string& path);

/// Pack every regular file under `dir` (recursively) into a store-only ZIP.
/// Entry paths are forward-slash, relative to `dir`, sorted for determinism.
bool pack_directory(const std::filesystem::path& dir,
                    std::vector<std::uint8_t>& out_zip,
                    std::string& err);

/// Parse a store-only ZIP image: validate CRCs over zip slices, build an index
/// that references the original buffer (no entry payload copies).
bool parse_bundle(const std::vector<std::uint8_t>& zip,
                  ParsedBundle& out_parsed,
                  std::string& err);

/// Same as parse_bundle but skips per-entry CRC validation.
/// Safe to use when the caller has already verified an Ed25519 signature over
/// the entire blob — the signature authenticates every byte, making per-entry
/// CRC checks redundant.
bool parse_bundle_trusted(const std::vector<std::uint8_t>& zip,
                          ParsedBundle& out_parsed,
                          std::string& err);

/// Parse a store-only ZIP image into entries (uncompressed entries only).
/// Copies each entry's bytes into `out_entries` after CRC validation.
bool read_entries(const std::vector<std::uint8_t>& zip,
                  std::vector<BundleEntry>& out_entries,
                  std::string& err);

/// Resolve a single request path using a cached `ParsedBundle` index.
bool find_entry(const ParsedBundle& parsed,
                const std::vector<std::uint8_t>& zip,
                const std::string& request_path,
                std::vector<std::uint8_t>& out_data,
                std::string& err);

/// Resolve a single request path (leading '/' optional) to its bytes.
/// Parses the zip on every call — prefer the `ParsedBundle` overload for hot paths.
bool find_entry(const std::vector<std::uint8_t>& zip,
                const std::string& request_path,
                std::vector<std::uint8_t>& out_data,
                std::string& err);

/// Extract every entry under `out_dir` (creates parent dirs). Refuses paths
/// that escape `out_dir` (zip-slip guard).
bool unpack_to_dir(const std::vector<std::uint8_t>& zip,
                   const std::filesystem::path& out_dir,
                   std::string& err);

// ── Detached Ed25519 signatures over the whole bundle blob ────────────────
// The signature is a raw 64-byte crypto_sign_detached() output, shipped beside
// the bundle as `<name>.pmbundle.sig`. Authenticity is pinned at the call site
// (the public key, not the file), so a tampered bundle — or one signed by a key
// the build does not trust — fails verification before any byte is served.

/// Sign `data` with the keypair derived from a 32-byte Ed25519 `seed`.
/// Writes the 64-byte detached signature to `out_sig`.
bool sign_detached(const std::vector<std::uint8_t>& data,
                   const std::uint8_t seed[32],
                   std::vector<std::uint8_t>& out_sig,
                   std::string& err);

/// Verify a 64-byte detached signature over `data` against a pinned 32-byte
/// Ed25519 public key. Returns false (with `err`) on any mismatch.
bool verify_detached(const std::vector<std::uint8_t>& data,
                     const std::vector<std::uint8_t>& sig,
                     const std::uint8_t public_key[32],
                     std::string& err);

} // namespace pm::storage::bundle
