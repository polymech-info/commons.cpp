#include "fs/zip_store.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace media::zip_store {

namespace {

namespace fs = std::filesystem;

void write_u16(std::ostream& out, std::uint16_t v)
{
    const unsigned char b[2] = {
        static_cast<unsigned char>(v & 0xffu),
        static_cast<unsigned char>((v >> 8) & 0xffu),
    };
    out.write(reinterpret_cast<const char*>(b), sizeof(b));
}

void write_u32(std::ostream& out, std::uint32_t v)
{
    const unsigned char b[4] = {
        static_cast<unsigned char>(v & 0xffu),
        static_cast<unsigned char>((v >> 8) & 0xffu),
        static_cast<unsigned char>((v >> 16) & 0xffu),
        static_cast<unsigned char>((v >> 24) & 0xffu),
    };
    out.write(reinterpret_cast<const char*>(b), sizeof(b));
}

std::uint16_t read_u16(const unsigned char* p)
{
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t read_u32(const unsigned char* p)
{
    return static_cast<std::uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

std::uint32_t crc32_bytes(const unsigned char* data, size_t len)
{
    static std::uint32_t table[256]{};
    static bool ready = false;
    if (!ready) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = true;
    }
    std::uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < len; ++i)
        c = table[(c ^ data[i]) & 0xffu] ^ (c >> 8);
    return c ^ 0xffffffffu;
}

std::vector<unsigned char> read_file_bytes(const fs::path& path, std::string& err)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path.string();
        return {};
    }
    in.seekg(0, std::ios::end);
    const auto n = in.tellg();
    if (n < 0) {
        err = "cannot size " + path.string();
        return {};
    }
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> bytes(static_cast<size_t>(n));
    if (!bytes.empty())
        in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in.good() && !in.eof()) {
        err = "read failed: " + path.string();
        return {};
    }
    return bytes;
}

std::string path_to_zip_name(const fs::path& rel)
{
    auto u8 = rel.generic_u8string();
#if defined(__cpp_char8_t)
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
#else
    return std::string(u8.begin(), u8.end());
#endif
}

fs::path zip_name_to_path(const std::string& name)
{
#if defined(__cpp_char8_t)
    std::u8string u8(reinterpret_cast<const char8_t*>(name.data()), name.size());
    return fs::path(u8);
#else
    return fs::u8path(name);
#endif
}

struct ZipEntry {
    std::string name;
    std::vector<unsigned char> data;
    std::uint32_t crc = 0;
    std::uint32_t offset = 0;
};

bool safe_archive_relative_path(const fs::path& rel)
{
    if (rel.empty() || rel.is_absolute())
        return false;
    for (const auto& part : rel) {
        if (part == "." || part == "..")
            return false;
    }
    return true;
}

} // namespace

bool write_stored_zip(const fs::path& zip_path, const fs::path& root, std::string& err)
{
    std::vector<ZipEntry> entries;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) {
            err = "enumerate archive stage: " + ec.message();
            return false;
        }
        if (!it->is_regular_file(ec)) {
            ec.clear();
            continue;
        }
        const fs::path rel = fs::relative(it->path(), root, ec);
        if (ec || rel.empty()) {
            ec.clear();
            continue;
        }
        ZipEntry e;
        e.name = path_to_zip_name(rel);
        if (e.name.empty() || e.name.size() > 0xffffu) {
            err = "archive entry name too long: " + rel.string();
            return false;
        }
        e.data = read_file_bytes(it->path(), err);
        if (!err.empty())
            return false;
        if (e.data.size() > 0xffffffffu) {
            err = "archive entry too large for ZIP32: " + rel.string();
            return false;
        }
        e.crc = crc32_bytes(e.data.data(), e.data.size());
        entries.push_back(std::move(e));
    }

    fs::create_directories(zip_path.parent_path(), ec);
    if (ec) {
        err = "create archive output directory: " + ec.message();
        return false;
    }
    std::ofstream out(zip_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "cannot open archive for write: " + zip_path.string();
        return false;
    }

    constexpr std::uint16_t dos_time = 0;
    constexpr std::uint16_t dos_date = (1u << 5) | 1u;
    for (auto& e : entries) {
        const auto pos = out.tellp();
        if (pos < 0 || static_cast<std::uint64_t>(pos) > 0xffffffffull) {
            err = "archive too large for ZIP32";
            return false;
        }
        e.offset = static_cast<std::uint32_t>(pos);
        write_u32(out, 0x04034b50u);
        write_u16(out, 20);
        write_u16(out, 0x0800u);
        write_u16(out, 0);
        write_u16(out, dos_time);
        write_u16(out, dos_date);
        write_u32(out, e.crc);
        write_u32(out, static_cast<std::uint32_t>(e.data.size()));
        write_u32(out, static_cast<std::uint32_t>(e.data.size()));
        write_u16(out, static_cast<std::uint16_t>(e.name.size()));
        write_u16(out, 0);
        out.write(e.name.data(), static_cast<std::streamsize>(e.name.size()));
        if (!e.data.empty())
            out.write(reinterpret_cast<const char*>(e.data.data()), static_cast<std::streamsize>(e.data.size()));
    }

    const auto central_start_pos = out.tellp();
    if (central_start_pos < 0 || static_cast<std::uint64_t>(central_start_pos) > 0xffffffffull) {
        err = "archive too large for ZIP32";
        return false;
    }
    const std::uint32_t central_start = static_cast<std::uint32_t>(central_start_pos);
    for (const auto& e : entries) {
        write_u32(out, 0x02014b50u);
        write_u16(out, 20);
        write_u16(out, 20);
        write_u16(out, 0x0800u);
        write_u16(out, 0);
        write_u16(out, dos_time);
        write_u16(out, dos_date);
        write_u32(out, e.crc);
        write_u32(out, static_cast<std::uint32_t>(e.data.size()));
        write_u32(out, static_cast<std::uint32_t>(e.data.size()));
        write_u16(out, static_cast<std::uint16_t>(e.name.size()));
        write_u16(out, 0);
        write_u16(out, 0);
        write_u32(out, 0); // disk number + internal attributes
        write_u32(out, 0); // external attributes
        write_u32(out, e.offset);
        out.write(e.name.data(), static_cast<std::streamsize>(e.name.size()));
    }
    const auto central_end_pos = out.tellp();
    if (central_end_pos < 0 || static_cast<std::uint64_t>(central_end_pos) > 0xffffffffull) {
        err = "archive too large for ZIP32";
        return false;
    }
    const std::uint32_t central_size = static_cast<std::uint32_t>(central_end_pos) - central_start;
    if (entries.size() > 0xffffu) {
        err = "too many archive entries for ZIP32";
        return false;
    }
    write_u32(out, 0x06054b50u);
    write_u16(out, 0);
    write_u16(out, 0);
    write_u16(out, static_cast<std::uint16_t>(entries.size()));
    write_u16(out, static_cast<std::uint16_t>(entries.size()));
    write_u32(out, central_size);
    write_u32(out, central_start);
    write_u16(out, 0);
    if (!out.good()) {
        err = "write archive failed: " + zip_path.string();
        return false;
    }
    return true;
}

bool extract_stored_zip(const fs::path& zip_path, const fs::path& out_dir, std::string& err)
{
    const std::vector<unsigned char> zip = read_file_bytes(zip_path, err);
    if (!err.empty())
        return false;
    if (zip.size() < 22) {
        err = "ZIP file too small";
        return false;
    }

    size_t eocd = std::string::npos;
    const size_t min_pos = zip.size() > (0xffffu + 22u) ? zip.size() - (0xffffu + 22u) : 0;
    for (size_t p = zip.size() - 22; p + 4 <= zip.size() && p >= min_pos; --p) {
        if (read_u32(zip.data() + p) == 0x06054b50u) {
            eocd = p;
            break;
        }
        if (p == 0)
            break;
    }
    if (eocd == std::string::npos) {
        err = "ZIP end-of-central-directory not found";
        return false;
    }
    const std::uint16_t entries = read_u16(zip.data() + eocd + 10);
    const std::uint32_t cd_size = read_u32(zip.data() + eocd + 12);
    const std::uint32_t cd_off = read_u32(zip.data() + eocd + 16);
    if (static_cast<std::uint64_t>(cd_off) + cd_size > zip.size()) {
        err = "ZIP central directory out of range";
        return false;
    }

    std::error_code ec;
    fs::create_directories(out_dir, ec);
    if (ec) {
        err = "create archive extraction directory: " + ec.message();
        return false;
    }

    size_t p = cd_off;
    for (std::uint16_t i = 0; i < entries; ++i) {
        if (p + 46 > zip.size() || read_u32(zip.data() + p) != 0x02014b50u) {
            err = "invalid ZIP central directory entry";
            return false;
        }
        const std::uint16_t flags = read_u16(zip.data() + p + 8);
        const std::uint16_t method = read_u16(zip.data() + p + 10);
        const std::uint32_t crc = read_u32(zip.data() + p + 16);
        const std::uint32_t comp_size = read_u32(zip.data() + p + 20);
        const std::uint32_t uncomp_size = read_u32(zip.data() + p + 24);
        const std::uint16_t name_len = read_u16(zip.data() + p + 28);
        const std::uint16_t extra_len = read_u16(zip.data() + p + 30);
        const std::uint16_t comment_len = read_u16(zip.data() + p + 32);
        const std::uint32_t local_off = read_u32(zip.data() + p + 42);
        if ((flags & 0x0008u) != 0 || method != 0 || comp_size != uncomp_size) {
            err = "unsupported ZIP entry (only stored entries without data descriptors are supported)";
            return false;
        }
        if (p + 46u + name_len + extra_len + comment_len > zip.size()) {
            err = "ZIP central directory entry out of range";
            return false;
        }
        const std::string name(reinterpret_cast<const char*>(zip.data() + p + 46), name_len);
        p += 46u + name_len + extra_len + comment_len;
        if (name.empty() || name.back() == '/')
            continue;
        const fs::path rel = zip_name_to_path(name);
        if (!safe_archive_relative_path(rel)) {
            err = "unsafe ZIP entry path: " + name;
            return false;
        }
        if (local_off + 30u > zip.size() || read_u32(zip.data() + local_off) != 0x04034b50u) {
            err = "invalid ZIP local header";
            return false;
        }
        const std::uint16_t local_name_len = read_u16(zip.data() + local_off + 26);
        const std::uint16_t local_extra_len = read_u16(zip.data() + local_off + 28);
        const size_t data_off = static_cast<size_t>(local_off) + 30u + local_name_len + local_extra_len;
        if (data_off + comp_size > zip.size()) {
            err = "ZIP entry data out of range";
            return false;
        }
        const unsigned char* data = zip.data() + data_off;
        if (crc32_bytes(data, comp_size) != crc) {
            err = "ZIP CRC mismatch for " + name;
            return false;
        }
        const fs::path dst = out_dir / rel;
        fs::create_directories(dst.parent_path(), ec);
        if (ec) {
            err = "create archive entry directory: " + ec.message();
            return false;
        }
        std::ofstream out(dst, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "cannot write archive entry: " + dst.string();
            return false;
        }
        if (comp_size)
            out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(comp_size));
        if (!out.good()) {
            err = "write archive entry failed: " + dst.string();
            return false;
        }
    }
    return true;
}

} // namespace media::zip_store
