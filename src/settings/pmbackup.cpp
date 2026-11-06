#include "settings/pmbackup.hpp"
#include "fs/path_sanitizer.hpp"

#include "settings/settings_archive.hpp"
#include "settings/settings_store.hpp"
#include "logging/pm_log.hpp"

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace {

namespace fs = std::filesystem;

constexpr char k_pmbackup_magic[4] = {'P', 'M', 'B', 'K'};
constexpr std::uint8_t k_pmbackup_version_keyfile = 1;
constexpr std::uint8_t k_pmbackup_version_passphrase = 2;

bool ensure_sodium(std::string& err)
{
    static bool done = false;
    if (done)
        return true;
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    done = true;
    return true;
}

bool read_file_bytes(const fs::path& path, std::vector<std::uint8_t>& out, std::string& err)
{
    out.clear();
    err.clear();
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        err = "failed to read " + media::path::path_to_utf8(path);
        return false;
    }
    ifs.seekg(0, std::ios::end);
    const auto sz = static_cast<std::size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz)
        ifs.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    if (!ifs.good() && !ifs.eof()) {
        err = "failed to read " + media::path::path_to_utf8(path);
        return false;
    }
    return true;
}

bool write_file_bytes_atomic(const fs::path& path, const std::uint8_t* data, std::size_t len, std::string& err)
{
    err.clear();
    std::error_code ec;
    if (path.has_parent_path())
        fs::create_directories(path.parent_path(), ec);
    const fs::path tmp = media::path::path_to_utf8(path) + ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            err = "failed to write " + media::path::path_to_utf8(tmp);
            return false;
        }
        if (len)
            ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
        if (!ofs.good()) {
            err = "failed to write " + media::path::path_to_utf8(tmp);
            return false;
        }
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "rename failed: " + ec.message();
        return false;
    }
#if !defined(_WIN32)
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
    return true;
}

void restrict_key_file_permissions(const fs::path& path)
{
#if !defined(_WIN32)
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
    (void)path;
}

std::filesystem::path pmbackup_temp_zip_path(const char* tag)
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
#if defined(_WIN32)
    return fs::temp_directory_path()
        / (std::wstring(L"pmbackup-") + std::to_wstring(static_cast<unsigned long long>(::GetCurrentProcessId()))
           + L"-" + std::to_wstring(static_cast<long long>(ticks)) + L".zip");
#else
    (void)tag;
    return fs::temp_directory_path() / ("pmbackup-" + std::to_string(ticks) + ".zip");
#endif
}

bool load_key_bytes(const fs::path& key_path, std::vector<std::uint8_t>& key32, std::string& err)
{
    key32.clear();
    err.clear();
    std::vector<std::uint8_t> raw;
    if (!read_file_bytes(key_path, raw, err))
        return false;
    if (raw.size() != crypto_secretbox_KEYBYTES) {
        err = "cloud storage key has invalid length (expected 32 bytes)";
        return false;
    }
    key32 = std::move(raw);
    return true;
}

bool derive_passphrase_key(const std::string& passphrase,
                           const unsigned char* salt,
                           std::vector<std::uint8_t>& key32,
                           std::string& err)
{
    key32.clear();
    err.clear();
    if (passphrase.empty()) {
        err = "passphrase is empty";
        return false;
    }
    key32.resize(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(key32.data(), key32.size(), passphrase.c_str(), passphrase.size(), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13)
        != 0) {
        err = "passphrase key derivation failed";
        key32.clear();
        return false;
    }
    return true;
}

bool encrypt_with_key(const std::vector<std::uint8_t>& key32,
                      const std::vector<std::uint8_t>& plain,
                      std::uint8_t version,
                      const unsigned char* salt_or_null,
                      std::vector<std::uint8_t>& out,
                      std::string& err)
{
    out.clear();
    err.clear();
    if (key32.size() != crypto_secretbox_KEYBYTES) {
        err = "invalid encryption key length";
        return false;
    }
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    std::vector<std::uint8_t> cipher(plain.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(cipher.data(), plain.data(), plain.size(), nonce, key32.data()) != 0) {
        err = "crypto_secretbox_easy failed";
        return false;
    }
    out.reserve(sizeof(k_pmbackup_magic) + 1 + crypto_secretbox_NONCEBYTES + cipher.size()
                + (version == k_pmbackup_version_passphrase ? crypto_pwhash_SALTBYTES : 0));
    out.insert(out.end(), std::begin(k_pmbackup_magic), std::end(k_pmbackup_magic));
    out.push_back(version);
    if (version == k_pmbackup_version_passphrase) {
        if (!salt_or_null) {
            err = "missing passphrase salt";
            return false;
        }
        out.insert(out.end(), salt_or_null, salt_or_null + crypto_pwhash_SALTBYTES);
    }
    out.insert(out.end(), nonce, nonce + sizeof nonce);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return true;
}

bool decrypt_blob(const std::vector<std::uint8_t>& key32,
                  const std::vector<std::uint8_t>& blob,
                  std::vector<std::uint8_t>& plain,
                  std::string& err)
{
    plain.clear();
    err.clear();
    if (key32.size() != crypto_secretbox_KEYBYTES) {
        err = "invalid decryption key length";
        return false;
    }
    if (blob.size() < sizeof(k_pmbackup_magic) + 1 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES
        || std::memcmp(blob.data(), k_pmbackup_magic, sizeof(k_pmbackup_magic)) != 0) {
        err = "not a valid pmbackup file";
        return false;
    }
    const std::uint8_t version = blob[sizeof(k_pmbackup_magic)];
    std::size_t header_len = sizeof(k_pmbackup_magic) + 1;
    if (version == k_pmbackup_version_passphrase)
        header_len += crypto_pwhash_SALTBYTES;
    header_len += crypto_secretbox_NONCEBYTES;
    if (blob.size() < header_len + crypto_secretbox_MACBYTES) {
        err = "pmbackup ciphertext truncated";
        return false;
    }
    if (version != k_pmbackup_version_keyfile && version != k_pmbackup_version_passphrase) {
        err = "unsupported pmbackup version";
        return false;
    }
    const std::uint8_t* nonce = blob.data() + header_len - crypto_secretbox_NONCEBYTES;
    const std::uint8_t* cipher = blob.data() + header_len;
    const std::size_t cipher_len = blob.size() - header_len;
    plain.resize(cipher_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plain.data(), cipher, cipher_len, nonce, key32.data()) != 0) {
        err = "pmbackup decrypt failed (wrong key/passphrase or corrupt file)";
        return false;
    }
    return true;
}

bool read_pmbackup_version(const std::vector<std::uint8_t>& blob, std::uint8_t& version, std::string& err)
{
    err.clear();
    if (blob.size() < sizeof(k_pmbackup_magic) + 1
        || std::memcmp(blob.data(), k_pmbackup_magic, sizeof(k_pmbackup_magic)) != 0) {
        err = "not a valid pmbackup file";
        return false;
    }
    version = blob[sizeof(k_pmbackup_magic)];
    if (version != k_pmbackup_version_keyfile && version != k_pmbackup_version_passphrase) {
        err = "unsupported pmbackup version";
        return false;
    }
    return true;
}

} // namespace

namespace media::pmbackup {

namespace {

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
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

} // namespace

std::string profile_backup_filename_now()
{
    char buf[32]{};
#if defined(_WIN32)
    SYSTEMTIME st{};
    GetLocalTime(&st);
    sprintf_s(buf, "%04u-%02u-%02u-%02u%s", static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
              static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour), k_profile_backup_suffix);
#else
    const std::time_t now = std::time(nullptr);
    std::tm local_tm{};
#if defined(_POSIX_VERSION)
    localtime_r(&now, &local_tm);
#else
    local_tm = *std::localtime(&now);
#endif
    std::strftime(buf, sizeof buf, "%Y-%m-%d-%H", &local_tm);
    std::string out(buf);
    out += k_profile_backup_suffix;
    return out;
#endif
    return buf;
}

bool is_timestamped_profile_backup_filename(const std::string& filename)
{
    const std::string suffix = k_profile_backup_suffix;
    if (filename.size() != 13 + suffix.size())
        return false;
    if (filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0)
        return false;
    const auto dash = [&](std::size_t pos) { return filename[pos] == '-'; };
    if (!is_digit(filename[0]) || !is_digit(filename[1]) || !is_digit(filename[2]) || !is_digit(filename[3]))
        return false;
    if (!dash(4))
        return false;
    if (!is_digit(filename[5]) || !is_digit(filename[6]))
        return false;
    if (!dash(7))
        return false;
    if (!is_digit(filename[8]) || !is_digit(filename[9]))
        return false;
    if (!dash(10))
        return false;
    if (!is_digit(filename[11]) || !is_digit(filename[12]))
        return false;
    return true;
}

std::string select_newest_profile_backup_filename(const std::vector<std::string>& filenames)
{
    std::string newest_ts;
    bool has_legacy = false;
    for (const auto& name : filenames) {
        if (name == k_profile_backup_legacy_filename) {
            has_legacy = true;
            continue;
        }
        if (!is_timestamped_profile_backup_filename(name))
            continue;
        if (newest_ts.empty() || name > newest_ts)
            newest_ts = name;
    }
    if (!newest_ts.empty())
        return newest_ts;
    if (has_legacy)
        return k_profile_backup_legacy_filename;
    return {};
}

fs::path cloud_storage_key_path(const fs::path& config_dir)
{
    return config_dir / k_cloud_storage_key_name;
}

fs::path resolve_cloud_storage_key_path(const fs::path& config_dir, const fs::path& override_key)
{
    if (!override_key.empty()) {
        std::error_code ec;
        const fs::path abs = fs::absolute(override_key, ec);
        return ec ? override_key : abs;
    }
    return cloud_storage_key_path(config_dir);
}

bool load_or_create_cloud_storage_key_at(const fs::path& key_path, std::string& err)
{
    err.clear();
    if (!ensure_sodium(err))
        return false;
    if (key_path.empty()) {
        err = "cloud storage key path is empty";
        return false;
    }

    std::vector<std::uint8_t> key32;
    if (fs::exists(key_path)) {
        if (!load_key_bytes(key_path, key32, err))
            return false;
        return true;
    }

    key32.resize(crypto_secretbox_KEYBYTES);
    randombytes_buf(key32.data(), key32.size());
    std::error_code ec;
    if (key_path.has_parent_path())
        fs::create_directories(key_path.parent_path(), ec);
    if (!write_file_bytes_atomic(key_path, key32.data(), key32.size(), err))
        return false;
    restrict_key_file_permissions(key_path);
    logger::info("created cloud storage key: " + media::path::path_to_utf8(key_path));
    return true;
}

bool load_cloud_storage_key_at(const fs::path& key_path, std::string& err)
{
    err.clear();
    if (!ensure_sodium(err))
        return false;
    if (key_path.empty()) {
        err = "cloud storage key path is empty";
        return false;
    }
    if (!fs::is_regular_file(key_path)) {
        err = "cloud storage key not found: " + media::path::path_to_utf8(key_path);
        return false;
    }
    std::vector<std::uint8_t> key32;
    if (!load_key_bytes(key_path, key32, err))
        return false;
    return true;
}

bool load_or_create_cloud_storage_key(const fs::path& config_dir, std::string& err)
{
    return load_or_create_cloud_storage_key_at(cloud_storage_key_path(config_dir), err);
}

bool load_cloud_storage_key(const fs::path& config_dir, std::string& err)
{
    const fs::path key_path = cloud_storage_key_path(config_dir);
    if (!fs::is_regular_file(key_path)) {
        err = "cloud storage key not found: copy " + std::string(k_cloud_storage_key_name)
              + " from the source machine into " + media::path::path_to_utf8(config_dir);
        return false;
    }
    return load_cloud_storage_key_at(key_path, err);
}

bool export_cloud_storage_key_file(const fs::path& dest, std::string& err, const fs::path& config_dir_in)
{
    err.clear();
    if (dest.empty()) {
        err = "destination path is empty";
        return false;
    }
    const fs::path config_dir = config_dir_in.empty() ? media::settings::get_config_dir() : config_dir_in;
    const fs::path key_path = cloud_storage_key_path(config_dir);
    if (!load_or_create_cloud_storage_key_at(key_path, err))
        return false;
    std::vector<std::uint8_t> key32;
    if (!load_key_bytes(key_path, key32, err))
        return false;
    if (!write_file_bytes_atomic(dest, key32.data(), key32.size(), err)) {
        sodium_memzero(key32.data(), key32.size());
        return false;
    }
    sodium_memzero(key32.data(), key32.size());
    restrict_key_file_permissions(dest);
    return true;
}

bool import_cloud_storage_key_file(const fs::path& src, std::string& err, const fs::path& config_dir_in)
{
    err.clear();
    if (src.empty()) {
        err = "source path is empty";
        return false;
    }
    std::vector<std::uint8_t> key32;
    if (!load_key_bytes(src, key32, err))
        return false;
    const fs::path config_dir = config_dir_in.empty() ? media::settings::get_config_dir() : config_dir_in;
    const fs::path key_path = cloud_storage_key_path(config_dir);
    if (!write_file_bytes_atomic(key_path, key32.data(), key32.size(), err)) {
        sodium_memzero(key32.data(), key32.size());
        return false;
    }
    sodium_memzero(key32.data(), key32.size());
    restrict_key_file_permissions(key_path);
    logger::info("imported cloud storage key: " + media::path::path_to_utf8(key_path));
    return true;
}

bool regenerate_cloud_storage_key(std::string& err, const fs::path& config_dir_in)
{
    err.clear();
    if (!ensure_sodium(err))
        return false;
    const fs::path config_dir = config_dir_in.empty() ? media::settings::get_config_dir() : config_dir_in;
    const fs::path key_path = cloud_storage_key_path(config_dir);
    std::vector<std::uint8_t> key32(crypto_secretbox_KEYBYTES);
    randombytes_buf(key32.data(), key32.size());
    if (!write_file_bytes_atomic(key_path, key32.data(), key32.size(), err)) {
        sodium_memzero(key32.data(), key32.size());
        return false;
    }
    sodium_memzero(key32.data(), key32.size());
    restrict_key_file_permissions(key_path);
    logger::info("regenerated cloud storage key: " + media::path::path_to_utf8(key_path));
    return true;
}

bool export_profile_pmbackup(const fs::path& out, std::string& err, const PmbackupOptions& options)
{
    err.clear();
    if (!ensure_sodium(err))
        return false;

    const bool use_passphrase = !options.passphrase.empty();
    std::vector<std::uint8_t> key32;
    unsigned char salt[crypto_pwhash_SALTBYTES]{};
    if (use_passphrase) {
        randombytes_buf(salt, sizeof salt);
        if (!derive_passphrase_key(options.passphrase, salt, key32, err))
            return false;
    } else {
        const fs::path config_dir = media::settings::get_config_dir();
        const fs::path key_path = resolve_cloud_storage_key_path(config_dir, options.cloud_storage_key_override);
        if (!load_or_create_cloud_storage_key_at(key_path, err))
            return false;
        if (!load_key_bytes(key_path, key32, err))
            return false;
    }

    const fs::path temp_zip = pmbackup_temp_zip_path("export");
    struct Cleanup {
        fs::path p;
        ~Cleanup()
        {
            std::error_code ec;
            fs::remove(p, ec);
        }
    } cleanup_zip{temp_zip};

    if (!media::settings_archive::export_config_backup_zip(temp_zip, options.content, err))
        return false;

    std::vector<std::uint8_t> zip_bytes;
    if (!read_file_bytes(temp_zip, zip_bytes, err))
        return false;

    std::vector<std::uint8_t> encrypted;
    const std::uint8_t version = use_passphrase ? k_pmbackup_version_passphrase : k_pmbackup_version_keyfile;
    if (!encrypt_with_key(key32, zip_bytes, version, use_passphrase ? salt : nullptr, encrypted, err))
        return false;

    sodium_memzero(key32.data(), key32.size());

    std::error_code ec;
    if (out.has_parent_path())
        fs::create_directories(out.parent_path(), ec);
    if (!write_file_bytes_atomic(out, encrypted.data(), encrypted.size(), err))
        return false;
    return true;
}

bool import_profile_pmbackup(const fs::path& backup_path, std::string& err, const PmbackupOptions& options)
{
    err.clear();
    if (!ensure_sodium(err))
        return false;

    bool is_zip = false;
    if (!file_starts_with(backup_path, "PK", 2, is_zip, err))
        return false;
    if (is_zip) {
        err = "This file is a ZIP profile archive. Use Import profile archive, not Import encrypted backup.";
        return false;
    }

    std::vector<std::uint8_t> blob;
    if (!read_file_bytes(backup_path, blob, err))
        return false;

    std::uint8_t version = 0;
    if (!read_pmbackup_version(blob, version, err))
        return false;

    std::vector<std::uint8_t> key32;
    if (version == k_pmbackup_version_passphrase) {
        if (options.passphrase.empty()) {
            err = "pmbackup is passphrase-protected; provide the passphrase";
            return false;
        }
        if (blob.size() < sizeof(k_pmbackup_magic) + 1 + crypto_pwhash_SALTBYTES) {
            err = "pmbackup passphrase header truncated";
            return false;
        }
        const unsigned char* salt = blob.data() + sizeof(k_pmbackup_magic) + 1;
        if (!derive_passphrase_key(options.passphrase, salt, key32, err))
            return false;
    } else {
        const fs::path config_dir = media::settings::get_config_dir();
        const fs::path key_path = resolve_cloud_storage_key_path(config_dir, options.cloud_storage_key_override);
        if (!load_cloud_storage_key_at(key_path, err))
            return false;
        if (!load_key_bytes(key_path, key32, err))
            return false;
    }

    std::vector<std::uint8_t> zip_bytes;
    if (!decrypt_blob(key32, blob, zip_bytes, err))
        return false;
    sodium_memzero(key32.data(), key32.size());

    const fs::path temp_zip = pmbackup_temp_zip_path("import");
    if (!write_file_bytes_atomic(temp_zip, zip_bytes.data(), zip_bytes.size(), err))
        return false;
    struct Cleanup {
        fs::path p;
        ~Cleanup()
        {
            std::error_code ec;
            fs::remove(p, ec);
        }
    } cleanup_zip{temp_zip};

    if (!media::settings_archive::import_config_backup_zip(temp_zip, err))
        return false;
    return true;
}

} // namespace media::pmbackup
