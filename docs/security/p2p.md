# C++ P2P Secure Chat + File Exchange

Goal: user-owned keys, direct P2P where possible, server-blind E2EE.

## Stack

- Transport: WebRTC DataChannel
- Signaling: small HTTPS/WebSocket rendezvous server
- NAT traversal: ICE + STUN
- Fallback relay: TURN
- Identity keys: Ed25519 or OpenPGP
- Session crypto: Noise / Double Ratchet
- File crypto: XChaCha20-Poly1305
- Hashing: BLAKE3
- Optional groups: MLS

## C++ libs

- WebRTC: libwebrtc / libdatachannel
- Crypto: libsodium
- OpenPGP: librnp
- Hashing: BLAKE3
- TLS/HTTP/WebSocket server: Boost.Beast / uWebSockets / ixwebsocket
- Storage: SQLite

## Design

```text
User identity key
  ↓ signs
Device key
  ↓ signs
Ephemeral session key
  ↓ Noise handshake
Shared session secret
  ↓ ratchet
Per-message keys

```

## Server role

Server stores only:

* user id
* public identity key
* device public keys
* online presence
* WebRTC offers/answers
* ICE candidates

Server must never store:

* private keys
* session keys
* plaintext messages
* plaintext files

## Chat flow

1. Alice fetches Bob public identity/device key.
2. Alice verifies fingerprint or TOFU trust.
3. Alice creates ephemeral key.
4. Alice signs ephemeral key with device key.
5. WebRTC signaling exchanges offer/answer/ICE.
6. Noise/ratchet establishes session keys.
7. Messages are encrypted before WebRTC send.

## File flow

1. Generate random file key.
2. Split file into chunks.
3. Encrypt each chunk with XChaCha20-Poly1305.
4. Hash chunks with BLAKE3.
5. Create signed manifest:

   * filename
   * mime
   * size
   * chunk size
   * chunk hashes
   * encrypted file key per recipient
6. Send manifest + chunks over DataChannel.
7. Receiver verifies signature + hashes.

## P2P behavior

```text
Try direct UDP via ICE/STUN
Fallback to TURN relay if NAT/firewall blocks direct
No router config required in normal cases
```

## Security rules

* Do not invent crypto.
* Do not rely only on WebRTC DTLS for app secrecy.
* Encrypt above WebRTC.
* Private keys never leave device.
* Long-term keys authenticate only.
* Session keys are ephemeral and rotated.
* Files use separate random content keys.
* Server is relay/discovery only.

## Recommended MVP

* libdatachannel
* libsodium
* BLAKE3
* Ed25519 identity/device keys
* Noise-style session handshake
* encrypted chunked file transfer
* simple WebSocket rendezvous server
* TURN fallback
