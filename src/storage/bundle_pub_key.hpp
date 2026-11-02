#pragma once

// Pinned Ed25519 public key that signed web app bundles (*.pmbundle) must verify
// against before the runtime serves them. The matching private seed lives OUTSIDE
// the shipped binary; `scripts/web-app-bundle.mjs` passes it to
// `pm-image-security storage bundle sign` at pack time.
//
// DEV KEY — rotate for production. To rotate: generate a new Ed25519 keypair,
// replace the 32 bytes below with the public key, and feed the new seed to the
// signing step (PM_BUNDLE_SIGNING_SEED_HEX). Anyone holding the seed can sign a
// bundle this build will trust, so keep the production seed offline.
//
// seed (dev): 5d4d5a094870ef85a8bf534e82dd9589f1d33b08437f69ba6d806004c4a22686

namespace pm::storage::bundle {

inline constexpr unsigned char k_bundle_signing_public_key_ed25519[32] = {
    0x48, 0xe2, 0xc3, 0x4b, 0x96, 0x71, 0x63, 0xe6, 0x0d, 0xf9, 0x64, 0x2b, 0xfa, 0x56, 0x2f, 0x9a,
    0xc8, 0x45, 0xd4, 0xf5, 0x2a, 0xa0, 0x54, 0x75, 0xd1, 0x32, 0xcf, 0x14, 0xa7, 0x5f, 0xb7, 0xda
};

} // namespace pm::storage::bundle
