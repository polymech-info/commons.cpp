#include "lan/pair_store.hpp"

#include "commands/batch_queue.hpp"
#include "string/string_utils.hpp"

#include <nlohmann/json.hpp>
#include <picosha2.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <system_error>

#if defined(_WIN32)
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <bcrypt.h>
#    if defined(_MSC_VER)
#        pragma comment(lib, "bcrypt.lib")
#    endif
#endif

namespace pm::lan {
namespace {

/// The widest network a grant may name: `10.0.0.0/8`, `127.0.0.0/8`.
constexpr int k_min_grant_prefix = 8;

/// Edits in this process are serialized. A second process only reads.
std::mutex& store_mutex()
{
    static std::mutex mu;
    return mu;
}

bool random_bytes(std::uint8_t* out, std::size_t n)
{
#if defined(_WIN32)
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG));
#else
    std::ifstream in("/dev/urandom", std::ios::binary);
    if (!in)
        return false;
    in.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(n));
    return in.gcount() == static_cast<std::streamsize>(n);
#endif
}

std::string sha256_hex(std::string_view text)
{
    return picosha2::hash256_hex_string(std::string(text));
}

bool same_bytes(std::string_view a, std::string_view b) noexcept
{
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    const std::size_t n = a.size() < b.size() ? a.size() : b.size();
    for (std::size_t i = 0; i < n; ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

bool parse_ipv4(std::string_view text, std::uint32_t& out) noexcept
{
    std::uint32_t value = 0;
    int parts = 0;
    std::size_t i = 0;
    while (i < text.size()) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        std::uint32_t part = 0;
        int digits = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            part = part * 10 + static_cast<std::uint32_t>(text[i] - '0');
            if (++digits > 3 || part > 255)
                return false;
            ++i;
        }
        value = (value << 8) | part;
        ++parts;
        if (i == text.size())
            break;
        if (text[i] != '.' || parts == 4)
            return false;
        ++i;
        if (i == text.size())
            return false;
    }
    if (parts != 4)
        return false;
    out = value;
    return true;
}

bool parse_cidr(std::string_view cidr, std::uint32_t& net, std::uint32_t& mask) noexcept
{
    const auto slash = cidr.find('/');
    if (slash == std::string_view::npos || slash + 1 >= cidr.size() || cidr.size() - slash > 3)
        return false;
    int len = 0;
    for (std::size_t i = slash + 1; i < cidr.size(); ++i) {
        if (cidr[i] < '0' || cidr[i] > '9')
            return false;
        len = len * 10 + (cidr[i] - '0');
    }
    if (len > 32)
        return false;
    std::uint32_t address = 0;
    if (!parse_ipv4(cidr.substr(0, slash), address))
        return false;
    mask = len == 0 ? 0u : 0xFFFFFFFFu << (32 - len);
    net = address & mask;
    return true;
}

std::string format_ipv4(std::uint32_t value)
{
    char buf[20];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (value >> 24) & 255u, (value >> 16) & 255u,
                  (value >> 8) & 255u, value & 255u);
    return buf;
}

Trust parse_trust(const std::string& text) noexcept
{
    if (text == "paired")
        return Trust::Paired;
    if (text == "verifying")
        return Trust::Verifying;
    // An unknown word must not read as paired.
    return Trust::Revoked;
}

nlohmann::json grant_json(const Grant& grant)
{
    return {
        {"revision", grant.revision},
        {"vfs", vfs_grant_name(grant.vfs)},
        {"audio", grant.audio},
        {"video", grant.video},
        {"networks", grant.networks},
    };
}

Grant grant_from(const nlohmann::json& node)
{
    Grant grant;
    if (!node.is_object())
        return grant;
    if (node.contains("revision") && node["revision"].is_number_integer())
        grant.revision = (std::max)(1, node["revision"].get<int>());
    if (node.contains("vfs") && node["vfs"].is_string())
        (void)parse_vfs_grant(node["vfs"].get<std::string>(), grant.vfs);
    if (node.contains("networks") && node["networks"].is_array()) {
        for (const auto& row : node["networks"]) {
            if (row.is_string() && cidr_valid(row.get<std::string>()))
                grant.networks.push_back(row.get<std::string>());
        }
    }
    return grant;
}

std::string text_of(const nlohmann::json& row, const char* key)
{
    return row.contains(key) && row[key].is_string() ? row[key].get<std::string>() : std::string{};
}

bool read_rows(const std::filesystem::path& file, std::vector<Peer>& out, std::string& err)
{
    out.clear();
    std::error_code ec;
    if (!std::filesystem::exists(file, ec))
        return true;
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        err = "could not open the pair file";
        return false;
    }
    const nlohmann::json doc = nlohmann::json::parse(in, nullptr, false);
    if (!doc.is_object() || !doc.contains("devices") || !doc["devices"].is_array()) {
        err = "the pair file is not valid";
        return false;
    }
    for (const auto& row : doc["devices"]) {
        if (!row.is_object())
            continue;
        Peer peer;
        peer.id = text_of(row, "id");
        if (!peer_id_valid(peer.id))
            continue;
        peer.name = text_of(row, "name");
        peer.peer_fp = text_of(row, "peer_fp");
        peer.tls_fp = text_of(row, "tls_fp");
        peer.token_sha256 = text_of(row, "token_sha256");
        peer.trust = parse_trust(text_of(row, "trust"));
        peer.outbound = grant_from(row.contains("outbound") ? row["outbound"] : nlohmann::json{});
        peer.created = text_of(row, "created");
        peer.last_seen = text_of(row, "last_seen");
        out.push_back(std::move(peer));
    }
    return true;
}

bool write_rows(const std::filesystem::path& file, const std::vector<Peer>& rows, std::string& err)
{
    nlohmann::json devices = nlohmann::json::array();
    for (const auto& peer : rows) {
        devices.push_back({
            {"id", peer.id},
            {"name", peer.name},
            {"peer_fp", peer.peer_fp},
            {"tls_fp", peer.tls_fp},
            {"token_sha256", peer.token_sha256},
            {"trust", trust_name(peer.trust)},
            {"outbound", grant_json(peer.outbound)},
            {"created", peer.created},
            {"last_seen", peer.last_seen},
        });
    }
    std::error_code ec;
    if (!file.parent_path().empty())
        std::filesystem::create_directories(file.parent_path(), ec);
    std::filesystem::path tmp = file;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "could not write the pair file";
            return false;
        }
        out << nlohmann::json{{"version", 1}, {"devices", std::move(devices)}}.dump(2);
        if (!out) {
            err = "could not write the pair file";
            return false;
        }
    }
    std::filesystem::rename(tmp, file, ec);
#if defined(_WIN32)
    // Windows refuses to replace a file that a reader holds open. A listener
    // reads this file for each request, for a few milliseconds.
    for (int attempt = 0; ec && attempt < 20; ++attempt) {
        ::Sleep(10);
        ec.clear();
        std::filesystem::rename(tmp, file, ec);
    }
#endif
    if (ec) {
        std::filesystem::remove(tmp, ec);
        err = "could not replace the pair file";
        return false;
    }
    return true;
}

Peer* row_of(std::vector<Peer>& rows, std::string_view id)
{
    for (auto& row : rows)
        if (row.id == id)
            return &row;
    return nullptr;
}

} // namespace

const char* trust_name(Trust trust) noexcept
{
    switch (trust) {
    case Trust::Verifying: return "verifying";
    case Trust::Paired:    return "paired";
    case Trust::Revoked:   return "revoked";
    }
    return "revoked";
}

const char* vfs_grant_name(VfsGrant grant) noexcept
{
    switch (grant) {
    case VfsGrant::Off:   return "off";
    case VfsGrant::Read:  return "read";
    case VfsGrant::Write: return "write";
    }
    return "off";
}

bool parse_vfs_grant(std::string_view text, VfsGrant& out) noexcept
{
    if (text == "off") {
        out = VfsGrant::Off;
        return true;
    }
    if (text == "read") {
        out = VfsGrant::Read;
        return true;
    }
    if (text == "write") {
        out = VfsGrant::Write;
        return true;
    }
    return false;
}

bool cidr_valid(std::string_view cidr) noexcept
{
    std::uint32_t net = 0;
    std::uint32_t mask = 0;
    return parse_cidr(cidr, net, mask);
}

bool cidr_contains(std::string_view cidr, std::string_view ipv4) noexcept
{
    std::uint32_t net = 0;
    std::uint32_t mask = 0;
    std::uint32_t address = 0;
    if (!parse_cidr(cidr, net, mask) || !parse_ipv4(ipv4, address))
        return false;
    return (address & mask) == net;
}

std::string cidr_of(std::string_view ipv4, int prefix_len)
{
    std::uint32_t address = 0;
    if (prefix_len < 0 || prefix_len > 32 || !parse_ipv4(ipv4, address))
        return {};
    const std::uint32_t mask = prefix_len == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix_len);
    return format_ipv4(address & mask) + "/" + std::to_string(prefix_len);
}

bool network_granted(const Grant& grant, std::string_view local_ipv4) noexcept
{
    for (const auto& cidr : grant.networks)
        if (cidr_contains(cidr, local_ipv4))
            return true;
    return false;
}

std::string derive_peer_id(std::string_view key)
{
    return sha256_hex(key).substr(0, 16);
}

bool peer_id_valid(std::string_view id) noexcept
{
    if (id.empty() || id.size() > 64)
        return false;
    for (unsigned char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

PairStore::PairStore(std::filesystem::path file, std::size_t max_peers)
    : file_(std::move(file)), max_peers_(max_peers == 0 ? 1 : max_peers)
{
}

bool PairStore::load(std::vector<Peer>& out, std::string& err) const
{
    return read_rows(file_, out, err);
}

bool PairStore::find(std::string_view id, Peer& out, std::string& err) const
{
    std::vector<Peer> rows;
    if (!read_rows(file_, rows, err))
        return false;
    const Peer* row = row_of(rows, id);
    if (!row) {
        err = "this device is not paired";
        return false;
    }
    out = *row;
    return true;
}

bool PairStore::ensure_peer(std::string_view id, std::string_view name, std::string_view tls_fp,
                            Peer& out, std::string& err) const
{
    if (!peer_id_valid(id)) {
        err = "the device id is not valid";
        return false;
    }
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    if (!read_rows(file_, rows, err))
        return false;
    const std::string now = media::utc_now_iso8601();
    if (Peer* row = row_of(rows, id)) {
        const std::string label = media::strutil::clip_text(name, 80);
        const std::string fp = media::strutil::clip_text(tls_fp, 128);
        if (!label.empty())
            row->name = label;
        if (!fp.empty())
            row->tls_fp = fp;
        row->last_seen = now;
        out = *row;
        return write_rows(file_, rows, err);
    }
    if (rows.size() >= max_peers_) {
        // A revoked row gives up its place. A paired one never does.
        const auto revoked = std::find_if(rows.begin(), rows.end(), [](const Peer& row) {
            return row.trust == Trust::Revoked;
        });
        if (revoked == rows.end()) {
            err = "this device is already paired with " + std::to_string(max_peers_) + " others";
            return false;
        }
        rows.erase(revoked);
    }
    Peer peer;
    peer.id = std::string(id);
    peer.name = media::strutil::clip_text(name, 80);
    peer.tls_fp = media::strutil::clip_text(tls_fp, 128);
    peer.trust = Trust::Paired;
    peer.created = now;
    peer.last_seen = now;
    rows.push_back(peer);
    if (!write_rows(file_, rows, err))
        return false;
    out = std::move(peer);
    return true;
}

bool PairStore::issue_token(std::string_view id, std::string& token, std::string& err) const
{
    token.clear();
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    if (!read_rows(file_, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row || row->trust != Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    std::array<std::uint8_t, 32> raw{};
    if (!random_bytes(raw.data(), raw.size())) {
        err = "no random source for a pair token";
        return false;
    }
    std::string fresh = "tn1_" + media::strutil::base64url(raw.data(), raw.size());
    row->token_sha256 = sha256_hex(fresh);
    row->last_seen = media::utc_now_iso8601();
    if (!write_rows(file_, rows, err))
        return false;
    token = std::move(fresh);
    return true;
}

bool PairStore::set_grant(std::string_view id, VfsGrant vfs, const std::vector<std::string>& networks,
                          Peer& out, std::string& err) const
{
    std::vector<std::string> clean;
    for (const auto& cidr : networks) {
        if (!cidr_valid(cidr)) {
            err = "\"" + media::strutil::clip_text(cidr, 40) + "\" is not a network like 192.168.1.0/24";
            return false;
        }
        // A grant names a network. `0.0.0.0/0` would name all of them.
        if (std::stoi(cidr.substr(cidr.find('/') + 1)) < k_min_grant_prefix) {
            err = "\"" + media::strutil::clip_text(cidr, 40) + "\" is wider than one network";
            return false;
        }
        if (std::find(clean.begin(), clean.end(), cidr) == clean.end())
            clean.push_back(cidr);
    }
    if (clean.size() > 16) {
        err = "at most 16 networks per device";
        return false;
    }
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    if (!read_rows(file_, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row || row->trust != Trust::Paired) {
        err = "this device is not paired";
        return false;
    }
    if (row->outbound.vfs != vfs || row->outbound.networks != clean) {
        row->outbound.vfs = vfs;
        row->outbound.networks = std::move(clean);
        ++row->outbound.revision;
        if (!write_rows(file_, rows, err))
            return false;
    }
    out = *row;
    return true;
}

bool PairStore::revoke(std::string_view id, std::string& err) const
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    if (!read_rows(file_, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row) {
        err = "this device is not paired";
        return false;
    }
    if (row->trust == Trust::Revoked)
        return true;
    row->trust = Trust::Revoked;
    row->outbound.vfs = VfsGrant::Off;
    row->outbound.networks.clear();
    ++row->outbound.revision;
    return write_rows(file_, rows, err);
}

bool PairStore::repair(std::string_view id, Peer& out, std::string& err) const
{
    std::lock_guard<std::mutex> lock(store_mutex());
    std::vector<Peer> rows;
    if (!read_rows(file_, rows, err))
        return false;
    Peer* row = row_of(rows, id);
    if (!row) {
        err = "this device is not paired";
        return false;
    }
    if (row->trust != Trust::Paired) {
        row->trust = Trust::Paired;
        row->token_sha256.clear();
        row->outbound.vfs = VfsGrant::Off;
        row->outbound.networks.clear();
        ++row->outbound.revision;
        row->last_seen = media::utc_now_iso8601();
        if (!write_rows(file_, rows, err))
            return false;
    }
    out = *row;
    return true;
}

Access PairStore::authorize(std::string_view token) const
{
    Access access;
    if (token.size() < 8 || token.size() > 256 || token.substr(0, 4) != "tn1_")
        return access;
    std::vector<Peer> rows;
    std::string err;
    if (!read_rows(file_, rows, err))
        return access;
    const std::string hash = sha256_hex(token);
    for (const auto& row : rows) {
        if (row.token_sha256.empty() || !same_bytes(row.token_sha256, hash))
            continue;
        access.peer = row;
        access.verdict = row.trust == Trust::Paired ? Verdict::Paired : Verdict::Revoked;
        return access;
    }
    return access;
}

bool PairStore::any_peer_on(std::string_view local_ipv4) const
{
    std::vector<Peer> rows;
    std::string err;
    if (!read_rows(file_, rows, err))
        return false;
    for (const auto& row : rows) {
        if (row.trust == Trust::Paired && network_granted(row.outbound, local_ipv4))
            return true;
    }
    return false;
}

} // namespace pm::lan
