#include "storage/asset_bundle.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <system_error>

#include <sodium.h>

namespace fs = std::filesystem;

namespace pm::storage::bundle {

namespace {

// ── CRC-32 (IEEE 802.3, poly 0xEDB88320) ──────────────────────────────────
std::uint32_t crc32_bytes(const std::uint8_t* data, std::size_t len) {
    static std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

std::uint16_t get_u16(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint16_t>(b[off] | (b[off + 1] << 8));
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& b, std::size_t off) {
    return static_cast<std::uint32_t>(b[off]) |
           (static_cast<std::uint32_t>(b[off + 1]) << 8) |
           (static_cast<std::uint32_t>(b[off + 2]) << 16) |
           (static_cast<std::uint32_t>(b[off + 3]) << 24);
}

constexpr std::uint32_t kLocalSig = 0x04034b50u;
constexpr std::uint32_t kCentralSig = 0x02014b50u;
constexpr std::uint32_t kEocdSig = 0x06054b50u;
// DOS date 1980-01-01, time 00:00 — keeps strict ZIP readers (incl. PhysFS) happy.
constexpr std::uint16_t kDosTime = 0;
constexpr std::uint16_t kDosDate = 0x0021;

bool read_file_bytes(const fs::path& path, std::vector<std::uint8_t>& out, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        err = "failed to open file: " + path.string();
        return false;
    }
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    out.resize(size > 0 ? static_cast<std::size_t>(size) : 0);
    if (!out.empty())
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return true;
}

bool is_path_safe(const std::string& rel) {
    if (rel.empty() || rel.front() == '/' || rel.front() == '\\')
        return false;
    if (rel.find("..") != std::string::npos)
        return false;
    if (rel.size() >= 2 && rel[1] == ':') // drive-letter absolute
        return false;
    return true;
}

} // namespace

std::string content_type_for_path(const std::string& path) {
    auto ends_with = [&](const char* ext) {
        const std::size_t n = std::strlen(ext);
        return path.size() >= n && path.compare(path.size() - n, n, ext) == 0;
    };
    if (ends_with(".html") || ends_with(".htm")) return "text/html; charset=utf-8";
    if (ends_with(".js") || ends_with(".mjs"))   return "text/javascript; charset=utf-8";
    if (ends_with(".css"))                       return "text/css; charset=utf-8";
    if (ends_with(".wasm"))                      return "application/wasm";
    if (ends_with(".json") || ends_with(".map")) return "application/json; charset=utf-8";
    if (ends_with(".svg"))                       return "image/svg+xml";
    if (ends_with(".png"))                       return "image/png";
    if (ends_with(".jpg") || ends_with(".jpeg")) return "image/jpeg";
    if (ends_with(".webp"))                      return "image/webp";
    if (ends_with(".woff2"))                     return "font/woff2";
    if (ends_with(".woff"))                      return "font/woff";
    if (ends_with(".txt"))                       return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

bool pack_directory(const fs::path& dir,
                    std::vector<std::uint8_t>& out_zip,
                    std::string& err) {
    out_zip.clear();
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec) {
        err = "bundle source is not a directory: " + dir.string();
        return false;
    }

    struct PendingEntry {
        std::string name;
        std::vector<std::uint8_t> data;
    };
    std::vector<PendingEntry> entries;
    for (fs::recursive_directory_iterator it(dir, ec), end; it != end && !ec; it.increment(ec)) {
        if (!it->is_regular_file(ec) || ec)
            continue;
        const fs::path rel = fs::relative(it->path(), dir, ec);
        if (ec) {
            err = "failed to relativize bundle entry";
            return false;
        }
        PendingEntry pe;
        pe.name = rel.generic_string();
        if (!read_file_bytes(it->path(), pe.data, err))
            return false;
        entries.push_back(std::move(pe));
    }
    if (entries.empty()) {
        err = "bundle source directory has no files";
        return false;
    }
    std::sort(entries.begin(), entries.end(),
              [](const PendingEntry& a, const PendingEntry& b) { return a.name < b.name; });

    struct CdRecord {
        std::string name;
        std::uint32_t crc;
        std::uint32_t size;
        std::uint32_t local_offset;
    };
    std::vector<CdRecord> cd;
    cd.reserve(entries.size());

    for (const auto& e : entries) {
        const std::uint32_t local_offset = static_cast<std::uint32_t>(out_zip.size());
        const std::uint32_t crc = crc32_bytes(e.data.data(), e.data.size());
        const std::uint32_t size = static_cast<std::uint32_t>(e.data.size());
        put_u32(out_zip, kLocalSig);
        put_u16(out_zip, 20);          // version needed
        put_u16(out_zip, 0);           // flags
        put_u16(out_zip, 0);           // method = store
        put_u16(out_zip, kDosTime);
        put_u16(out_zip, kDosDate);
        put_u32(out_zip, crc);
        put_u32(out_zip, size);        // compressed
        put_u32(out_zip, size);        // uncompressed
        put_u16(out_zip, static_cast<std::uint16_t>(e.name.size()));
        put_u16(out_zip, 0);           // extra len
        out_zip.insert(out_zip.end(), e.name.begin(), e.name.end());
        out_zip.insert(out_zip.end(), e.data.begin(), e.data.end());
        cd.push_back({e.name, crc, size, local_offset});
    }

    const std::uint32_t cd_start = static_cast<std::uint32_t>(out_zip.size());
    for (const auto& r : cd) {
        put_u32(out_zip, kCentralSig);
        put_u16(out_zip, 20);          // version made by
        put_u16(out_zip, 20);          // version needed
        put_u16(out_zip, 0);           // flags
        put_u16(out_zip, 0);           // method = store
        put_u16(out_zip, kDosTime);
        put_u16(out_zip, kDosDate);
        put_u32(out_zip, r.crc);
        put_u32(out_zip, r.size);      // compressed
        put_u32(out_zip, r.size);      // uncompressed
        put_u16(out_zip, static_cast<std::uint16_t>(r.name.size()));
        put_u16(out_zip, 0);           // extra len
        put_u16(out_zip, 0);           // comment len
        put_u16(out_zip, 0);           // disk number start
        put_u16(out_zip, 0);           // internal attrs
        put_u32(out_zip, 0);           // external attrs
        put_u32(out_zip, r.local_offset);
        out_zip.insert(out_zip.end(), r.name.begin(), r.name.end());
    }
    const std::uint32_t cd_size = static_cast<std::uint32_t>(out_zip.size()) - cd_start;

    put_u32(out_zip, kEocdSig);
    put_u16(out_zip, 0);               // disk number
    put_u16(out_zip, 0);               // disk with cd
    put_u16(out_zip, static_cast<std::uint16_t>(cd.size()));
    put_u16(out_zip, static_cast<std::uint16_t>(cd.size()));
    put_u32(out_zip, cd_size);
    put_u32(out_zip, cd_start);
    put_u16(out_zip, 0);               // comment len
    return true;
}

bool read_entries(const std::vector<std::uint8_t>& zip,
                  std::vector<BundleEntry>& out_entries,
                  std::string& err) {
    out_entries.clear();
    if (zip.size() < 22) {
        err = "bundle is too small to be a zip archive";
        return false;
    }
    // Locate End Of Central Directory (scan backward; no zip comment expected).
    std::size_t eocd = std::string::npos;
    const std::size_t min_pos = zip.size() >= (22 + 65535) ? zip.size() - (22 + 65535) : 0;
    for (std::size_t i = zip.size() - 22; ; --i) {
        if (get_u32(zip, i) == kEocdSig) {
            eocd = i;
            break;
        }
        if (i == min_pos)
            break;
    }
    if (eocd == std::string::npos) {
        err = "bundle end-of-central-directory not found";
        return false;
    }
    const std::uint16_t total = get_u16(zip, eocd + 10);
    const std::uint32_t cd_size = get_u32(zip, eocd + 12);
    const std::uint32_t cd_off = get_u32(zip, eocd + 16);
    if (static_cast<std::size_t>(cd_off) + cd_size > zip.size()) {
        err = "bundle central directory is out of range";
        return false;
    }

    std::size_t p = cd_off;
    for (std::uint16_t n = 0; n < total; ++n) {
        if (p + 46 > zip.size() || get_u32(zip, p) != kCentralSig) {
            err = "bundle central directory record is corrupt";
            return false;
        }
        const std::uint16_t method = get_u16(zip, p + 10);
        const std::uint32_t crc = get_u32(zip, p + 16);
        const std::uint32_t comp_size = get_u32(zip, p + 20);
        const std::uint32_t name_len = get_u16(zip, p + 28);
        const std::uint16_t extra_len = get_u16(zip, p + 30);
        const std::uint16_t comment_len = get_u16(zip, p + 32);
        const std::uint32_t local_off = get_u32(zip, p + 42);
        if (p + 46 + name_len > zip.size()) {
            err = "bundle central directory name is out of range";
            return false;
        }
        std::string name(reinterpret_cast<const char*>(zip.data() + p + 46), name_len);

        if (method != 0) {
            err = "bundle entry is compressed (POC supports store-only): " + name;
            return false;
        }
        // Locate the data via the local header.
        if (static_cast<std::size_t>(local_off) + 30 > zip.size() || get_u32(zip, local_off) != kLocalSig) {
            err = "bundle local header is corrupt: " + name;
            return false;
        }
        const std::uint16_t l_name = get_u16(zip, local_off + 26);
        const std::uint16_t l_extra = get_u16(zip, local_off + 28);
        const std::size_t data_off = static_cast<std::size_t>(local_off) + 30 + l_name + l_extra;
        if (data_off + comp_size > zip.size()) {
            err = "bundle entry data is out of range: " + name;
            return false;
        }
        BundleEntry be;
        be.path = name;
        be.data.assign(zip.begin() + data_off, zip.begin() + data_off + comp_size);
        const std::uint32_t actual = crc32_bytes(be.data.data(), be.data.size());
        if (actual != crc) {
            err = "bundle entry CRC mismatch: " + name;
            return false;
        }
        out_entries.push_back(std::move(be));
        p += 46 + name_len + extra_len + comment_len;
    }
    return true;
}

static bool parse_bundle_impl(const std::vector<std::uint8_t>& zip,
                               ParsedBundle& out_parsed,
                               std::string& err,
                               bool skip_crc) {
    out_parsed.entries.clear();
    out_parsed.index_by_path.clear();
    if (zip.size() < 22) {
        err = "bundle is too small to be a zip archive";
        return false;
    }
    std::size_t eocd = std::string::npos;
    const std::size_t min_pos = zip.size() >= (22 + 65535) ? zip.size() - (22 + 65535) : 0;
    for (std::size_t i = zip.size() - 22; ; --i) {
        if (get_u32(zip, i) == kEocdSig) { eocd = i; break; }
        if (i == min_pos) break;
    }
    if (eocd == std::string::npos) {
        err = "bundle end-of-central-directory not found";
        return false;
    }
    const std::uint16_t total  = get_u16(zip, eocd + 10);
    const std::uint32_t cd_size = get_u32(zip, eocd + 12);
    const std::uint32_t cd_off  = get_u32(zip, eocd + 16);
    if (static_cast<std::size_t>(cd_off) + cd_size > zip.size()) {
        err = "bundle central directory is out of range";
        return false;
    }
    out_parsed.entries.reserve(total);
    out_parsed.index_by_path.reserve(total);
    std::size_t p = cd_off;
    for (std::uint16_t n = 0; n < total; ++n) {
        if (p + 46 > zip.size() || get_u32(zip, p) != kCentralSig) {
            err = "bundle central directory record is corrupt";
            return false;
        }
        const std::uint16_t method      = get_u16(zip, p + 10);
        const std::uint32_t crc         = get_u32(zip, p + 16);
        const std::uint32_t comp_size   = get_u32(zip, p + 20);
        const std::uint32_t name_len    = get_u16(zip, p + 28);
        const std::uint16_t extra_len   = get_u16(zip, p + 30);
        const std::uint16_t comment_len = get_u16(zip, p + 32);
        const std::uint32_t local_off   = get_u32(zip, p + 42);
        if (p + 46 + name_len > zip.size()) {
            err = "bundle central directory name is out of range";
            return false;
        }
        std::string name(reinterpret_cast<const char*>(zip.data() + p + 46), name_len);
        if (method != 0) {
            err = "bundle entry is compressed (POC supports store-only): " + name;
            return false;
        }
        if (static_cast<std::size_t>(local_off) + 30 > zip.size() || get_u32(zip, local_off) != kLocalSig) {
            err = "bundle local header is corrupt: " + name;
            return false;
        }
        const std::uint16_t l_name  = get_u16(zip, local_off + 26);
        const std::uint16_t l_extra = get_u16(zip, local_off + 28);
        const std::size_t data_off  = static_cast<std::size_t>(local_off) + 30 + l_name + l_extra;
        if (data_off + comp_size > zip.size()) {
            err = "bundle entry data is out of range: " + name;
            return false;
        }
        if (!skip_crc) {
            const std::uint32_t actual = crc32_bytes(zip.data() + data_off, comp_size);
            if (actual != crc) {
                err = "bundle entry CRC mismatch: " + name;
                return false;
            }
        }
        const std::size_t idx = out_parsed.entries.size();
        out_parsed.index_by_path.emplace(name, idx);
        out_parsed.entries.push_back({std::move(name), data_off, comp_size});
        p += 46 + name_len + extra_len + comment_len;
    }
    return true;
}

bool parse_bundle(const std::vector<std::uint8_t>& zip,
                  ParsedBundle& out_parsed,
                  std::string& err) {
    return parse_bundle_impl(zip, out_parsed, err, false);
}

bool parse_bundle_trusted(const std::vector<std::uint8_t>& zip,
                          ParsedBundle& out_parsed,
                          std::string& err) {
    return parse_bundle_impl(zip, out_parsed, err, true);
}

bool find_entry(const ParsedBundle& parsed,
                const std::vector<std::uint8_t>& zip,
                const std::string& request_path,
                std::vector<std::uint8_t>& out_data,
                std::string& err) {
    std::string want = request_path;
    while (!want.empty() && (want.front() == '/' || want.front() == '\\'))
        want.erase(want.begin());
    for (char& c : want) if (c == '\\') c = '/';
    if (want.empty()) { err = "empty request path"; return false; }
    const auto it = parsed.index_by_path.find(want);
    if (it == parsed.index_by_path.end()) {
        err = "not found in bundle: " + want;
        return false;
    }
    const BundleEntryRef& ref = parsed.entries[it->second];
    out_data.assign(zip.begin() + ref.data_offset,
                    zip.begin() + ref.data_offset + ref.data_size);
    return true;
}

bool find_entry(const std::vector<std::uint8_t>& zip,
                const std::string& request_path,
                std::vector<std::uint8_t>& out_data,
                std::string& err) {
    std::string want = request_path;
    while (!want.empty() && (want.front() == '/' || want.front() == '\\'))
        want.erase(want.begin());
    for (char& c : want)
        if (c == '\\') c = '/';
    if (want.empty()) {
        err = "empty request path";
        return false;
    }
    std::vector<BundleEntry> entries;
    if (!read_entries(zip, entries, err))
        return false;
    for (auto& e : entries) {
        if (e.path == want) {
            out_data = std::move(e.data);
            return true;
        }
    }
    err = "not found in bundle: " + want;
    return false;
}

bool unpack_to_dir(const std::vector<std::uint8_t>& zip,
                   const fs::path& out_dir,
                   std::string& err) {
    std::vector<BundleEntry> entries;
    if (!read_entries(zip, entries, err))
        return false;
    std::error_code ec;
    fs::create_directories(out_dir, ec);
    for (const auto& e : entries) {
        if (!is_path_safe(e.path)) {
            err = "unsafe bundle entry path rejected: " + e.path;
            return false;
        }
        const fs::path dest = out_dir / fs::path(e.path);
        fs::create_directories(dest.parent_path(), ec);
        std::ofstream out(dest, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            err = "failed to write bundle entry: " + dest.string();
            return false;
        }
        if (!e.data.empty())
            out.write(reinterpret_cast<const char*>(e.data.data()), static_cast<std::streamsize>(e.data.size()));
    }
    return true;
}

bool sign_detached(const std::vector<std::uint8_t>& data,
                   const std::uint8_t seed[32],
                   std::vector<std::uint8_t>& out_sig,
                   std::string& err) {
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        err = "crypto_sign_seed_keypair failed";
        return false;
    }
    out_sig.assign(crypto_sign_BYTES, 0);
    unsigned long long siglen = 0;
    const int rc = crypto_sign_detached(out_sig.data(), &siglen,
                                        data.data(), data.size(), sk);
    sodium_memzero(sk, sizeof(sk));
    if (rc != 0 || siglen != crypto_sign_BYTES) {
        err = "crypto_sign_detached failed";
        out_sig.clear();
        return false;
    }
    return true;
}

bool verify_detached(const std::vector<std::uint8_t>& data,
                     const std::vector<std::uint8_t>& sig,
                     const std::uint8_t public_key[32],
                     std::string& err) {
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    if (sig.size() != crypto_sign_BYTES) {
        err = "signature has wrong length (" + std::to_string(sig.size()) + ")";
        return false;
    }
    if (crypto_sign_verify_detached(sig.data(), data.data(), data.size(), public_key) != 0) {
        err = "signature verification failed";
        return false;
    }
    return true;
}

} // namespace pm::storage::bundle
