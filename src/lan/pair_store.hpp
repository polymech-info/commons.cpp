#pragma once

// Pair rows for one device, and the grant check a listener runs per request.
//
// One row is one peer. `outbound` is what this device allows that peer to do
// with this device's folders. This file is the authority for that. The token
// proves who the peer is. It does not carry the grant.
//
// Only the device that owns the file edits it. No route calls the edit
// functions. A new row grants nothing: vfs is off and no network is named.
//
// The file is read on every authorize, so an edit applies to the next
// request. A write is a temp file and a rename.

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace pm::lan {

enum class Trust { Verifying, Paired, Revoked };
enum class VfsGrant { Off, Read, Write };

[[nodiscard]] const char* trust_name(Trust trust) noexcept;
[[nodiscard]] const char* vfs_grant_name(VfsGrant grant) noexcept;
[[nodiscard]] bool parse_vfs_grant(std::string_view text, VfsGrant& out) noexcept;

struct Grant {
    /// Counts local edits. The order of two grants is this number, not a clock.
    int revision = 1;
    VfsGrant vfs = VfsGrant::Off;
    std::string audio = "off";
    std::string video = "off";
    /// IPv4 networks (`192.168.1.0/24`) this peer may reach this device on.
    /// Empty means none. A network that appears later is not added.
    std::vector<std::string> networks;
};

struct Peer {
    std::string id;
    std::string name;
    /// Ed25519 pairing fingerprint. Empty until a host links that identity.
    std::string peer_fp;
    /// SPKI SHA-256 of the peer's TLS listener, when this device dials it.
    std::string tls_fp;
    /// SHA-256 of the `tn1_` token the peer presents. Empty until one is issued.
    std::string token_sha256;
    Trust trust = Trust::Paired;
    Grant outbound;
    std::string created;
    std::string last_seen;
};

enum class Verdict {
    /// No row holds this token. HTTP 401.
    Unknown,
    /// The row is revoked. HTTP 401.
    Revoked,
    /// The peer is known. The grant decides the rest.
    Paired,
};

struct Access {
    Verdict verdict = Verdict::Unknown;
    Peer peer;
};

/// `a.b.c.d/n`, n from 0 to 32.
[[nodiscard]] bool cidr_valid(std::string_view cidr) noexcept;
[[nodiscard]] bool cidr_contains(std::string_view cidr, std::string_view ipv4) noexcept;
/// The network part of @p ipv4 under @p prefix_len, as `a.b.c.d/n`. Empty on bad input.
[[nodiscard]] std::string cidr_of(std::string_view ipv4, int prefix_len);
/// True when @p local_ipv4, the address the request arrived on, is inside a granted network.
[[nodiscard]] bool network_granted(const Grant& grant, std::string_view local_ipv4) noexcept;

/// Stable row id for a peer known by a fingerprint or an address: 16 hex of its SHA-256.
[[nodiscard]] std::string derive_peer_id(std::string_view key);
[[nodiscard]] bool peer_id_valid(std::string_view id) noexcept;

class PairStore {
public:
    explicit PairStore(std::filesystem::path file, std::size_t max_peers = 16);

    [[nodiscard]] const std::filesystem::path& file() const noexcept { return file_; }

    /// A missing file is an empty list.
    bool load(std::vector<Peer>& out, std::string& err) const;
    bool find(std::string_view id, Peer& out, std::string& err) const;

    /// Adds the row when it is missing: paired, vfs off, no network, revision 1.
    /// An existing row keeps its trust and its grant.
    bool ensure_peer(std::string_view id, std::string_view name, std::string_view tls_fp,
                     Peer& out, std::string& err) const;

    /// Replaces the token hash and returns the plaintext once. The grant stays.
    bool issue_token(std::string_view id, std::string& token, std::string& err) const;

    /// Local edit. The revision moves only when something changed.
    bool set_grant(std::string_view id, VfsGrant vfs, const std::vector<std::string>& networks,
                   Peer& out, std::string& err) const;

    /// The token stops working. The row stays so the UI can name the peer.
    bool revoke(std::string_view id, std::string& err) const;

    /// A revoked row becomes paired again with nothing granted and no token.
    bool repair(std::string_view id, Peer& out, std::string& err) const;

    [[nodiscard]] Access authorize(std::string_view token) const;

    /// True when a paired peer was granted the network @p local_ipv4 is on.
    [[nodiscard]] bool any_peer_on(std::string_view local_ipv4) const;

private:
    std::filesystem::path file_;
    std::size_t max_peers_;
};

} // namespace pm::lan
