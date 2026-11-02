# Secure Storage Todos

Investigation sources: `docs/security/storage.md`, `docs/security/todos.md`,
`src/core/settings_runtime.hpp`, and `src/llm/agent_feature.cpp`.

## Summary

The first implementation should be minimal and library-first:

- No SQLite.
- First targets: prompt templates and `commands.json`.
- Migrate `commands.json` loading first, then prompts such as
  `system-prompt.md` and planner prompt files used by `agent_feature.cpp`.
- Put URL/URI/schema/model primitives in `src/core` or `src/model`.
- Put storage implementation in `src/storage`.
- Expose storage through one public header, with OS-specific implementations
  such as `_win.cpp`, `_osx.cpp`, and `_linux.cpp`.
- Extend `pm-image-security.exe` first for signing, import, export, and tests.
  Later wire the same library into `tanit-cli.exe`, WebView UI, and Win32 UI.

Keep three responsibilities separate:

- **Core/model primitives**: URI parsing, schema constants, metadata structs,
  trust enums, digest records, and portable JSON shape.
- **Storage library**: bytes, manifests, signatures, import/export packages,
  local secure keys, and content-addressed files.
- **SecurityGateway**: decides whether a verified resource may be used as a
  prompt, template, command definition, script, MCP manifest, or imported peer
  resource.

Current gaps:

- `docs/security/storage.md` has the right resource model, but the concrete
  target layout should be `src/core` or `src/model` plus `src/storage`, not a
  separate `src/resource` module.
- `src/security/CryptoStore.*` has a useful backend shape, but storage should
  not depend on the security gateway internals. Reuse ideas or shared helpers
  only where it keeps boundaries clean.
- Windows `settings.json` is already encrypted (`PME1`) with a libsodium key
  protected by DPAPI. That is useful for preferences and secrets, but shared
  resources should move through signed storage packages.
- `commands.json` is currently plaintext and loaded directly. Treat it as the
  first migration target for signed, digest-verified loading.
- ZITADEL is useful for online identity, org/team membership, entitlement,
  bundle download authorization, role claims, trusted-sender sync, revocation
  checks, and license/account binding. It is not the local integrity root.

## Minimal Target

Use one canonical resource identity:

```text
pm://<type>/<name>
```

Every loaded resource must carry:

```text
uri
type
trust
sha256 digest
version
provider
signer id
bundle id
created/updated time
encrypted flag
```

First resource types:

- `PromptTemplate`
- `CommandConfig`
- `Prompt`

Trust levels for the first pass:

- `Builtin`: compiled or installed with the app.
- `SignedVendor`: signed by PolyMech or an allowed vendor key.
- `UserLocal`: created by the current user and stored locally.
- `PeerSigned`: received from another user and verified against an imported
  user identity key.
- `Workspace`: project-local, visible, never auto-elevated.
- `Untrusted`: parsed but not eligible for privileged use.

Signing should cover the manifest; individual blobs are covered by digest inside
that manifest. The signing input must be stable:

```text
manifest -> canonical JSON -> Ed25519 signature
```

Encryption should cover private user blobs and user-to-user transfers. Do not
make encryption imply trust: imported encrypted content still needs signature
verification and gateway policy. Trust downgrade is mandatory:

```text
PeerSigned != SignedVendor
```

## Target Layout

Core/model files:

```text
src/core/resource_uri.hpp
src/model/resource_schema.hpp
src/model/resource_types.hpp
```

Storage files:

```text
src/storage/secure_storage.hpp
src/storage/secure_storage.cpp
src/storage/secure_storage_win.cpp
src/storage/secure_storage_osx.cpp
src/storage/secure_storage_linux.cpp
```

`secure_storage.hpp` should be the public storage surface. Keep platform APIs
behind the OS-specific `.cpp` files.

Initial on-disk layout, without SQLite:

```text
<config>/resources/
  manifests/
    <bundle-id>.json
  blobs/
    sha256/
      aa/
        aabbcc...
  indexes/
    uri-index.json
  keys/
    local-signing-key.pme1
    local-encryption-key.pme1
```

The JSON index can be replaced later if needed. For v1, keep it transparent,
small, and easy to inspect in tests.

## Next Steps

Open priorities: P3/P4 remainders (SecurityGateway at execution, `--system-prompt
@path` policy, dual-provenance metadata), P5/P6 sharing, P8 key hardening, and
**P9 web app bundle + PFS asset signing** (see the dedicated section below —
storage already covers this without a new bundle backend).

## Status Snapshot

- [x] Added `FEATURE_SECURE_STORAGE` to `CMakePresets.json` / `CMakeLists.txt`.
- [x] Added `FEATURE_SECURE_STORAGE_WIN_HELLO` and enabled it in the main build preset.
- [x] Added core/model/storage scaffolding:
  - `src/core/resource_uri.hpp`
  - `src/model/resource_types.hpp`
  - `src/model/resource_schema.hpp`
  - `src/storage/secure_storage.hpp`
  - `src/storage/secure_storage.cpp`
  - `src/storage/secure_storage_win.cpp`
  - `src/storage/secure_storage_osx.cpp`
  - `src/storage/secure_storage_linux.cpp`
- [x] Added JSON-indexed, no-SQLite CAS storage for `pm://` resources.
- [x] Added `pm-image-security.exe storage put|get|list|verify`.
- [x] Added `storage sign|import|export` surfaces for single-resource
  `.pmbundle` packages.
- [x] Added `test:security:storage` and `test:security:storage:build`.
- [x] Added storage tests for prompt template and command config resources.
- [x] Added manifest schema/version/expiry and compact canonical JSON output.
- [x] Added CAS blob tamper test.
- [x] Implemented manifest Ed25519 signing and verification.
- [x] Added wrapped local key blobs:
  - `local-signing-key.pme1`
  - `local-encryption-key.pme1`
- [x] Implemented single-resource `.pmbundle` JSON import/export.
- [x] Verified P0-P2 with `npm run test:security:storage`: 42 passed, 0 failed.
- [x] Migrated `settings.json` loading to secure storage API (`pm://config/settings.json`).
- [x] Migrated `commands.json` loading to secure storage API (`pm://config/commands.json`).
- [x] Migrated `mcp.json` loading to secure storage API (`pm://config/mcp.json`).
- [x] Migrated ZITADEL OAuth token bundle to secure storage (`pm://config/zitadel-oauth.json`, `OAuthCredentials`, encrypted + signed; legacy plaintext auto-imported on read).
- [x] Implemented `pm://config/prompts/*.md` URI scheme for prompt template editor resources.
- [x] Editor save wiring: `vweb_classify_secure_save_target` + `vweb_operation_allowed` inside
  `handle_vw_save_file` — all editor Ctrl+S / Save paths require operation guard.
- [x] Windows Hello / TPM verification for sensitive import/export and update operations
  via `verify_user_presence()` + `VerificationSessionCache` (10-minute TTL reuse).
- [x] Operation guard session TTL: 10-minute window so repeated edits do not re-prompt.
- [x] `BackupSettingsPanel.tsx` UI for settings/commands/mcp export, import, and restore.
- [x] `import-plain.sh` script for seeding vendor assets into the profile storage.
- [x] `docs/public/v1.0/settings.md` updated with all new URI paths.
- [x] `docs/public/v1.0/signing.md` created — end-user encryption and signing guide.

#### GPO × Secure Storage (cross-cutting)

- [x] `Security.ForceVerificationProtector` read from HKLM-only policy stack inside
  `verify_user_presence()`; overrides env var before falling back to compiled default.
- [x] `Security.RequireEncryption` and `Security.RequireSigning` applied at the
  `load_document` / `verify_document` no-policy overloads in `secure_storage.cpp`;
  upgrading the default open policy to org-enforced closed policy without touching callers.
- [x] `editor_save_allowed()` GPO guard in `handle_vw_save_file` — `UI.DisablePromptEditor`,
  `UI.DisableCommandEditor`, `UI.DisableMcpEditor` block backend writes independently of
  the frontend `window.GPO_SETTINGS` check.

### P0 - Freeze The Contract

- [x] Define URI parsing in `src/core`, not `src/storage`.
- [x] Define resource enums, metadata, manifest schema constants, and JSON
  helpers in `src/model`.
- [x] Define `secure_storage.hpp` with a small API:
  - load by URI;
  - import package;
  - export package;
  - sign manifest;
  - verify resource/package;
  - put local resource;
  - list metadata.
- [x] Add bundle manifest version and expiry now:

```json
{
  "schema": "pm.resource.bundle.v1",
  "version": 1,
  "expires": "2027-01-01T00:00:00Z"
}
```

- [x] Pick crypto primitives for v1:
  - signatures: Ed25519 via libsodium;
  - digests: SHA-256 first, optional BLAKE3 later;
  - local key wrapping: DPAPI on Windows for `.pme1` blobs;
  - local encryption: reserved `local-encryption-key.pme1` for blob encryption;
  - user-to-user package encryption remains P6.
- [x] Declare that storage never authorizes execution or prompt use; it only
  verifies and returns typed resources with provenance.

### P1 - Build Storage Without SQLite

- [x] Implement content-addressed storage under the config dir:
  `resources/blobs/sha256/<prefix>/<digest>`.
- [x] Implement `uri-index.json` as the first URI to metadata mapping.
- [x] Use atomic write patterns for manifests, index files, and blobs.
- [x] Add local secure key support:
  - Windows: DPAPI-protected key material;
  - macOS/Linux: owner-only storage root with the same `.pme1` API surface;
  - Keychain / Secret Service backend replacement remains a hardening follow-up.
- [x] Reserve only wrapped local key blob paths (`*.pme1`), never raw signing or
  encryption key paths.
- [x] Refuse to expose private encrypted resource writes in v1; no private blob
  persistence path exists until the encryption key path is fully enforced.
- [x] Add storage directory hardening:
  - Windows: root creation and DPAPI-wrapped key blobs for secrets;
  - macOS/Linux: owner-only `0700` storage root.

### P2 - `pm-image-security.exe` CLI Surface

- [x] Extend the existing `pm-image-security.exe` target after the library code
  lands.
- [x] Add subcommands for the storage MVP:
  - `storage put`;
  - `storage get`;
  - `storage list`;
  - `storage verify`;
  - `storage sign`;
  - `storage import`;
  - `storage export`.
- [x] Emit one JSON object per command, matching the style of
  `tests/orchestrator/test-security.mjs`.
- [x] Extend `package.json` with focused basics:
  - `test:security:storage`;
  - `test:security:storage:build`.
- [x] Extend `test-security.mjs` with storage suites before adding UI or main CLI
  integration.

### How File Import And Signing Works Today

The first storage slice is file-oriented and resource-oriented. A source file is
not trusted by path or filename. It is imported as bytes under a canonical
`pm://` URI, hashed into the content-addressed blob store, described by a
manifest, and optionally signed.

For the `commands.json` migration, the canonical resource is:

```text
pm://config/commands.json
```

The same flow applies to `mcp.json` and `settings.json`:

```text
pm://config/mcp.json
pm://config/settings.json
```

And to prompt templates:

```text
pm://config/prompts/system-prompt.md
pm://config/prompts/planner-prompt.md
pm://config/prompts/<name>.md
```

The current local import/sign flow is:

```powershell
pm-image-security.exe --config-dir <profile> storage put `
  --uri pm://config/commands.json `
  --file <profile>\commands.json `
  --type command-config `
  --trust user-local `
  --provider user `
  --bundle local

pm-image-security.exe --config-dir <profile> storage sign `
  --uri pm://config/commands.json

pm-image-security.exe --config-dir <profile> storage verify `
  --uri pm://config/commands.json
```

`storage put` writes:

```text
<profile>/resources/
  blobs/sha256/<first-two-hex>/<sha256>
  manifests/<sha256>.json
  indexes/uri-index.json
```

The manifest records the resource URI, type, trust, SHA-256 digest, version,
provider, signer id, bundle id, timestamps, encryption flag, and byte size. The
manifest JSON is compact canonical JSON so the signed bytes are stable.

`storage sign` signs the manifest, not the raw `commands.json` file. The raw file
is protected indirectly because the signed manifest contains the SHA-256 digest
for the CAS blob. Verification therefore checks:

```text
blob bytes -> SHA-256 == manifest digest
manifest bytes + signature + public key -> Ed25519 valid
```

There is no X.509 certificate in the MVP. The "cert" equivalent today is an
Ed25519 public key embedded in the detached signature document:

```text
<profile>/resources/manifests/<sha256>.json.sig
```

That signature document has this shape:

```json
{
  "schema": "pm.resource.signature.v1",
  "algorithm": "ed25519",
  "publicKey": "<base64-ed25519-public-key>",
  "signature": "<base64-ed25519-signature>"
}
```

The matching private signing key is local-only:

```text
<profile>/resources/keys/local-signing-key.pme1
```

On Windows, `local-signing-key.pme1` is wrapped with DPAPI. On macOS/Linux, the
same `.pme1` file surface exists under an owner-only storage root until the
Keychain / Secret Service hardening pass replaces it. The raw private key should
never be written to disk.

`storage export` creates a single-resource `.pmbundle` JSON package containing:

```text
schema = pm.resource.package.v1
version = 1
manifest = canonical resource manifest
signature = detached signature document, when present
blob = { algorithm: sha256, hex, dataBase64 }
```

`storage import` reads that package, verifies the blob digest against the
manifest metadata, writes the CAS blob and manifest into the destination
profile, preserves the detached signature when present, and updates
`uri-index.json`. Import does not make the resource authorized for execution.
The command loader still needs to require a valid signed manifest, declared
`CommandConfig` type, acceptable trust, and SecurityGateway approval for
execution-capable fields such as `shellLine`.

Future vendor/user sharing will add real trust anchors:

- Vendor packages should pin PolyMech/vendor root or target public keys in
  built-in data or signed settings metadata.
- User-to-user packages should carry sender identity and key fingerprint, then
  import as `PeerSigned`, never as `SignedVendor`.
- X.509 / Authenticode may be useful for installer or binary provenance, but
  resource package integrity currently uses Ed25519 manifest signatures.

### Default Encryption / Decryption Policy

Signing answers authenticity and integrity. Encryption answers local
confidentiality. Treat them as separate checks:

```text
verify signature + digest = may this document be trusted as intact?
decrypt document          = may this profile read the plaintext bytes?
SecurityGateway           = may this verified document cause an action?
```

Default policy for the named secure document API:

```text
pm://config/settings.json                  encrypted=true, signed=true
pm://config/zitadel-oauth.json             encrypted=true, signed=true  (OAuthCredentials; no plaintext profile copy)
pm://config/commands.json                  encrypted=true, signed=true
pm://config/prompts/system-prompt.md       encrypted=true, signed=true
pm://config/prompts/planner-prompt.md      encrypted=true, signed=true
pm://config/prompts/realtime-prompt.md     encrypted=true, signed=true
pm://config/prompts/mode-<name>.md         encrypted=true, signed=true
```

That means user/profile copies of settings, commands, and prompts should be
encrypted by default. The plaintext exists only at the API boundary after
`load_document` succeeds. The app should not keep raw `commands.json` or prompt
Markdown files as authoritative runtime inputs once P3/P4 are wired.

Release/vendor seed assets need one extra rule: do not ship a reusable
decryption key in `dist/data`. If a seed asset is encrypted, it must either be
re-encrypted into the user's profile on install/first run with that profile's
`local-encryption-key.pme1`, or it must stay plaintext-but-signed in the
distributable seed. For first implementation, prefer:

```text
dist/data vendor seed  = signed, plaintext, no private/decrypt keys shipped
profile runtime copy   = encrypted + signed with local profile keys
```

This keeps the installer seed inspectable and avoids creating a global decrypt
secret. It still gives runtime tamper protection because the app verifies the
vendor signature before importing or mounting the seed, then uses encrypted
secure documents in the profile.

### User Verification Policy

User verification and privilege elevation are separate policy layers from
encryption and signing. The storage layer protects bytes; the security layer
decides when a human must confirm intent through the platform verifier and when
an operation must be routed through an elevated/admin broker.

Compiled defaults are exposed by:

```text
pm-image-security verification defaults
```

The JSON-compatible defaults live in `src/security_defaults.hpp` and
`src/security_defaults.cpp` so UI settings, CLI probes, GPO template generation,
and tests can share one operation-policy vocabulary.

Initial operation defaults:

```text
operation                            verification    privilege
settings.load                        none            none
settings.save                        none            none
settings.update                      none            none
settings.importPlain                 local_unlock    none
settings.exportPlain                 local_unlock    none
settings.exportEncrypted             presence        none
asset.load                           none            none
asset.save                           none            none
asset.update                         presence        none
asset.importPlain                    local_unlock    none
asset.exportPlain                    local_unlock    none
asset.importVendorSeed               presence        none
asset.importUntrusted                local_unlock    none
asset.exportBundle                   presence        none
asset.signSharedBundle               local_unlock    none
asset.installMachineWide             local_unlock    admin_required
localSigningKey.export               export_secret   none
permissions.grant.ReadSsh            local_unlock    none
permissions.grant.ExecutePowerShell  local_unlock    none
permissions.grant.ProgramFilesWrite  local_unlock    admin_required
service.install                      strong          admin_required
registry.writeHklm                   strong          admin_required
```

Future UI settings should expose these as overrideable policy values under
`security.operationPolicies`. The app should ask the platform provider for
verification only for explicit sensitive actions; normal startup/settings reads
must not show Windows Hello prompts. Admin elevation should be routed separately
through UAC or a signed broker and must not be implied by successful Windows
Hello verification.

#### Encryption / Decryption Todos

- [x] Make `storage doc put` encryption-on by default for every document type;
  require explicit `--no-encrypt` only for release seed generation and tests.
- [x] Add a `--encrypt` flag alias for clarity, even if encryption is already the
  default, so scripts can state intent.
- [x] Require `encrypt=true` for `pm://config/settings.json` at the CLI and library
  validation layer; reject plaintext settings documents.
- [x] Decide whether `CommandConfig` and `PromptTemplate` may ever be plaintext in
  profile storage. Default answer: no, plaintext is allowed only for signed
  vendor seed assets under `dist/data`.
- [x] Add a seed import command or library helper:

  ```text
  import signed plaintext vendor document
  -> verify vendor signature + digest
  -> write encrypted profile document
  -> sign as UserLocal or preserve vendor provenance in metadata
  ```

- [ ] Preserve both provenance fields after seed import:
  - original vendor signer/public key/digest;
  - local profile signer/public key/digest for the encrypted runtime copy.
  - Current CLI import returns `seedMeta` and stores the vendor public key in the
    encrypted profile document signer field; a richer dual-provenance metadata
    schema is still open.
- [x] Add loader policy flags:
  - `require_signature`;
  - `require_encryption`;
  - `allowed_trust`;
  - `allow_vendor_seed_plaintext`.
- [x] Verify signed document metadata before decrypting when
  `require_signature=true`; then decrypt and check plaintext SHA-256 against the
  signed manifest digest.
- [ ] Ensure `load_document` zeroizes plaintext buffers for settings/API-key
  documents after callers parse them where practical.
- [x] Add tests in `test-secure-storage.mjs`:
  - settings plaintext document is rejected;
  - command config defaults to encrypted;
  - prompt templates default to encrypted;
  - `--no-encrypt` is accepted only for explicit seed/test cases;
  - encrypted document tampering fails before use;
  - seed plaintext import produces encrypted profile document.
- [x] Update `scripts/assets/sign-assets.sh` or its replacement so release seed
  generation is explicit about plaintext vendor seed documents and never ships
  `resources/keys/*`.

### P3 - Migrate `commands.json`

- [x] Add a storage-backed loader that resolves command configs through
  `pm://config/commands.json`.
- [x] Preserve existing `commands.json` behavior behind a compatibility fallback
  while migration tests are being written.
- [x] Verify digest, manifest signature, declared schema, and trust before using
  command definitions.
- [ ] Split command config usage by capability:
  - `CommandConfig/data-only` can load after signature verification;
  - `CommandConfig/shellLine` must pass SecurityGateway at use time.
- [~] Add tests that tampered command configs are rejected before command lookup
  and execution.
  - CAS blob tamper fails `storage verify`. ✅
  - Command lookup/execution rejection is pending until SecurityGateway is wired.

### P4 - Migrate Prompt Templates And Prompts

- [x] Add prompt template resources such as:

```text
pm://config/prompts/system-prompt.md
pm://config/prompts/planner-prompt.md
```

- [x] URI scheme `pm://config/prompts/*.md` implemented and mapped in
  `vweb_classify_secure_save_target`; editor Ctrl+S routes through operation guard.
- [x] `agent_commons.cpp` loads prompt files via `load_document(paths, uri, policy)`
  with `require_signature=true` / `require_encryption=true`.
- [ ] Route `--system-prompt @path` CLI flag through storage/resource policy instead of
  direct raw file loading.
- [ ] Keep override/null semantics intact for existing CLI and API callers.
- [ ] Include provenance in prompt metadata so prompt assembly can report
  resource URI, digest, trust, and source path/package.

### P5 - Vendor To Users

- [~] Create a `.pmbundle` layout with manifest JSON, detached signatures, and
  content-addressed blobs.
  - Single-resource JSON `.pmbundle` (one manifest + one blob) via
    `storage export|import|sign`: done (P0–P2).
  - Multi-blob content-addressed container: still open (see P9 note; not required
    to sign single HTML / opaque `assets.pfs` blobs).
- [ ] Pin PolyMech/vendor root keys in built-in data or signed settings
  metadata.
- [~] Verify bundle signatures and digest maps before mounting.
  - `pm://` documents: `load_document` / `storage verify` with
    `require_signature` (and encryption where policy says so): done.
  - WebView HTML / `assets.pfs` mount-time verify: still open (P9).
- [ ] Bind security grants to resource or bundle digest, signer, and policy
  version so updates invalidate stale grants.
- [ ] Add CI checks for unsigned, hash-mismatched, expired, or unmanifested
  resources.

### P6 - User To User

Portable **encrypted settings sync** (done, separate from peer-signed share
packages): `.pmbackup` + `.cloud_storage_key` (or passphrase v2), Settings UI
Advanced key export/import/generate, cloud VFS upload/download via `/api/vfs/get`,
and CLI `settings key|cloud` / `settings export|import --pmbackup`. That path
encrypts a profile backup; it is **not** a signed `PeerSigned` resource package.

- [~] Create a local user signing identity stored in secure storage, with export
  and rotation UX.
  - Profile keys `local-signing-key.pme1` / `local-encryption-key.pme1`: done.
  - End-user export/rotation UX for the *signing* identity: still open.
- [~] Implement a share package:
  - Single-resource signed `.pmbundle` export/import: done.
  - Full peer share package still open:
  - signed manifest;
  - content-addressed blobs;
  - optional encrypted content key per recipient;
  - sender identity and key fingerprint;
  - creation time and expiry.
- [ ] On import, verify signature first, then decrypt if addressed to this user,
  then classify as `PeerSigned` rather than `SignedVendor`.
- [ ] Never promote imported peer resources to vendor trust, even when the peer
  identity is known through ZITADEL.
- [ ] Never auto-enable imported scripts, MCP manifests, policies, tools, or
  shell commands. Import should stage them and ask through the SecurityGateway
  when first used.

### P7 - Later Integration

- [ ] After `pm-image-security.exe` tests are green, add read-only integration to
  `tanit-cli.exe`.
- [ ] Add WebView UI for import/export/sign/verify once CLI behavior is stable.
- [ ] Add Win32 UI affordances for local user identity, trusted senders, package
  import, and provenance display.
- [ ] Keep provider API keys in the existing encrypted settings store or a
  dedicated secret store; do not put credentials in shareable resource bundles.
- [ ] Keep ZITADEL as online identity and entitlement:

```text
ZITADEL = who is this user/org?
Resource manifest signature = is this package authentic?
SecurityGateway = may this verified resource be used now?
```

## Threat Model And Local Key Hardening (No TPM)

This section records the realistic security posture for resource signing on a
single-user desktop, why same-user tampering cannot be fully prevented locally,
and the chosen hardening path. TPM/Hello-backed keys and remote/home-call
signing are explicitly out of scope. The conclusion: this design defends against
resource tampering for the large majority of realistic attacks, at the cost of
meaningful implementation effort. It is a deliberate "good enough, no server"
posture, not an absolute guarantee.

### Trust Layers

Keep app-binary trust and resource trust as separate cryptographic systems:

```text
Authenticode / MSIX  = "this binary/installer is from PolyMech"  (Windows verifies)
Resource signature   = "this asset is from vendor or this profile" (app verifies)
SecurityGateway      = "this verified asset may execute now"       (app authorizes)
```

App code signing (see `docs/win32/win4-signing-msix.md`) protects the binary and
the installer payload in transit. It does not protect roaming-profile resources
after install, so the app still verifies `pm://` resources at load time.

### Honest Goals

```text
Goal                                          Achievable locally?
integrity (detect corruption / tamper)        yes
provenance (vendor vs user-local)             yes
vendor trust-anchor pinning                   yes (embedded, Authenticode-protected)
downgrade prevention (vendor -> user-local)   yes
execution authorization                       yes (SecurityGateway)
defeat same-user malware completely           no  (out of scope)
```

### Why Same-User Tampering Cannot Be Fully Prevented

"Only our binary may sign" and "ensure is human" are enforced inside the same
trust domain the attacker shares. A same-user attacker does not go through the
human-gated UI; they operate beneath it:

```text
1. Steal the key       read local-signing-key.pme1 -> CryptUnprotectData (same user)
2. Signing oracle      drive/inject our own signer; key never needs extracting
3. Inherit authority   inject code into our process; patch out the is-human check
4. Skip signing        exploit any plaintext fallback or trust downgrade
```

Embedded-key obfuscation and the is-human gate raise cost; they are not a
boundary. The real escalation barrier is the SecurityGateway at execution time.

### Chosen Approach: Derive, Don't Store

Do not store a raw signing key and do not embed a static key blob (a static blob
is a shared global secret: extract once, forge everywhere). Instead derive the
Ed25519 seed at sign time and mix in per-machine + self-integrity inputs so the
embedded material alone is useless:

```text
seed = Argon2id(
  salt    = per-install random (only this is persisted),
  input   = embedded_pepper      // scattered + delayed-read from the binary
          || self_text_hash      // BLAKE2b of our own .text section
          || machine_binding     // MachineGuid + volume serial
)
keypair = crypto_sign_seed_keypair(seed)   // deterministic
```

- `embedded_pepper`: static extraction is expensive; never resident as one blob.
- `self_text_hash`: patching the binary to disable checks changes the seed, so
  forged signatures stop validating (ties to `dehack.md` P1.2).
- `machine_binding`: copying the binary elsewhere yields a different key.
- `salt`: useless without the exact binary on the exact machine.

### Delayed Spread Reads

Minimize key lifetime and material locality:

```text
- Split pepper into N fragments in different sections/objects, non-adjacent.
- Read fragments at staggered call sites, never all in one function.
- Reassemble the seed just-in-time inside one short critical section.
- Hold it only in a guarded, locked buffer for the single sign call.
- Zeroize immediately (sodium_memzero); sodium_malloc/sodium_mlock guarded pages.
- Recompute per signature; never cache the derived key; never page to disk.
```

All primitives exist in libsodium (already a dependency): `crypto_pwhash`
(Argon2id), `crypto_generichash` (BLAKE2b), `crypto_sign_seed_keypair`,
`sodium_malloc` / `sodium_mlock` / `sodium_memzero`.

### Residual Risk (Accepted)

```text
- Memory dump during the sign window       -> key exposed on that machine
- Our-binary-as-oracle                     -> no extraction needed
- Code injection after checks pass         -> rides our authority
```

This is acceptable because user-local trust is low-value: it asserts "edited in
this profile/binary," not "safe to execute." Execution-capable fields always go
through the gateway regardless of a valid signature.

### P8 - Local Key Hardening Todos

Tied to the current `src/storage/secure_storage.*` API.

- [ ] Add a seed-derivation function (Argon2id) that replaces the stored raw key
  behind `local_signing_key`; persist only the per-install `salt` (optionally
  still DPAPI-wrapped via `wrap_local_secret` / `unwrap_local_secret`).
- [ ] Change `sign_resource_manifest` to derive the seed just-in-time, sign, then
  zeroize; remove any long-lived `secret_key` buffer.
- [ ] Hold derived material only in `sodium_malloc` guarded, `sodium_mlock`ed
  buffers; `sodium_memzero` immediately after each sign.
- [ ] Add build-time embedding of a scattered `embedded_pepper` with staggered,
  non-adjacent reads (no single function assembles the full input).
- [ ] Mix `self_text_hash` (BLAKE2b of our `.text`) and `machine_binding`
  (MachineGuid + volume serial) into the derivation input.
- [ ] Enforce no-plaintext-fallback and no trust downgrade in the loader: an
  unsigned or `vendor -> user-local` downgraded resource is rejected, not
  silently accepted (closes attack path 4).
- [ ] Keep execution authorization in `SecurityGateway` regardless of signature
  validity; signature is integrity, not permission (see `dehack.md` P0.4).
- [ ] Pin the vendor public key as a compiled constant inside the
  Authenticode-signed binary; never read the trust anchor from the profile.
- [ ] Link process-integrity hardening from `dehack.md` (P0.1 DLL search, P0.6
  sidecar mitigations, P1.2 module snapshot) to raise the injection/oracle cost.
- [ ] Record the accepted residual risk in code comments and tests so the posture
  stays honest and is not over-trusted as anti-malware.

### Effort Note

This hardening is high-effort relative to its marginal benefit over the simpler
DPAPI-wrapped local key. The simpler model already gives integrity, provenance,
downgrade prevention, and gateway-gated execution. Treat the derive-and-scatter
work as an optional uplift to be scheduled deliberately, not a prerequisite for
the P3/P4 migrations.

## P9 - Web App Bundle And PFS Asset Signing

Covers signing and load-time verification of the shipped WebView2 UI bundles and
the shared asset archive. This is a vendor → client integrity problem: the assets
ship inside the install, run after install, and sit next to the exe in a
user-writable `dist/shared`. It reuses the existing single-resource signed-seed
flow (the `commands.json` vendor model) rather than introducing a new container.

### Does Storage Already Support Bundles? (PFS Backend?)

Short answer: there is no multi-file bundle backend yet, and the PhysicsFS
archive is not part of secure storage.

```text
.pmbundle           = single-resource JSON package (one manifest + one blob)
                      import/export only — NOT a multi-file container
assets.pfs (PhysFS) = read-only multi-file archive mounted via PHYSFS_mount;
                      unsigned, unverified, separate from src/storage
P5 ".pmbundle layout with ... content-addressed blobs" = still unchecked (multi-blob)
```

Implication for the web UI:

- `dist/shared/chat.html`, `settings.html`, and `xblox.html` are each a **single
  self-contained HTML** file. Webpack + `HtmlInlineScriptPlugin` inline all
  JS/CSS, and production uses `inline-source-map`, so there is no sidecar `.js`
  or `.map`. Each file is one blob, so it maps directly onto the existing
  single-resource API. No new multi-blob bundle format is required to sign the
  web UI.
- `assets.pfs` is itself a single file on disk (the archive). It can be signed as
  one opaque blob and verified before `PHYSFS_mount`, even though its *contents*
  are many files. Per-entry CAS inside the archive is only needed if we later
  want to verify individual icons — that is the P5 multi-blob work, not a
  prerequisite here.

Conclusion: do **not** build a new bundle backend for this slice. Sign each HTML
and the `.pfs` as single `SignedVendor` resources, exactly like the
`commands.json` vendor seed.

### Current Load Path (Unverified)

```text
ChatWebResource.cpp (read_utf8_file_next_to_exe):
  load_chat_web_html()     -> dist/shared/chat.html
  load_settings_web_html() -> dist/shared/settings.html
  load_xblox_web_html()    -> dist/shared/xblox.html
CSettingsWebView.cpp:
  shared_assets_pfs()      -> dist/shared/assets.pfs, PHYSFS_mount(..., "/", 1)
```

None of these check a digest or signature.

### How The Bytes Reach The Engine (Verification Chokepoints)

This is the interesting part: the web engine is **never** fed from `RT_RCDATA`,
and the two platforms feed it differently. Verification must hook the point where
trusted bytes enter the engine, not a fixed resource section.

Windows / WebView2 — two feeding modes (`ChatWebPanel.cpp::EnsureNavigated`):

```text
A. virtual-host file (preferred; localStorage persists)
   load_*_web_html() -> write bytes to %LOCALAPPDATA%/<vendor>/<app>/chat-web/chat.html
   -> SetVirtualHostNameToFolderMapping(<vhost>, folder, ALLOW)
   -> Navigate("https://<vhost>/chat.html")
   Settings: CWebViewOptions{ localFolder, vhostName="pm-settings.localhost", url }.

B. NavigateToString fallback (in-memory; localStorage does NOT survive restart)
   load_*_web_html() -> NavigateToString(html)   // no disk file at all
```

Mode A writes the bundle into a **user-writable** folder and serves it from disk
via a fake-https origin; the on-disk copy is a cache, not a trust root. Mode B is
actually the cleanest for integrity (verified bytes go straight into the engine),
but loses persistent `localStorage`.

Single chokepoint: both modes start from `load_chat_web_html()` /
`load_settings_web_html()` / `load_xblox_web_html()`
(`install_chat_web_virtual_host(webview, deferredHtml)` is called with the loader
result). Verify inside those loaders → both A and B are gated, and the writable
vhost copy is always rewritten from verified bytes on every launch (never trusted
in place).

macOS / WKWebView — different again (osx repo: `PolymechWebChatView.swift`,
`PmChatLocalMediaSchemeHandler.swift`; see `docs/backup/vfs-ex.md`). WKWebView
cannot map a fake https host to a folder like WebView2, so it uses:

```text
loadHTMLString(html, baseURL:)        // in-memory, ≈ NavigateToString
loadFileURL(_, allowingReadAccessTo:) // file URL + scoped read of one directory
WKURLSchemeHandler ("pmasset:" / app) // native handler returns bytes per request
```

The `WKURLSchemeHandler` is the natural verification point on macOS: the native
handler can verify the bundle digest/signature once and serve verified bytes for
the document and every subresource, the same way the C++ loader gates the
WebView2 feed. App Store sandbox rules (no arbitrary `file:` reads) make the
scheme-handler path preferable to `loadFileURL` for anything outside the
container.

Takeaway: verification lives in the **platform byte-source** (C++ `load_*_web_html`
on Windows, the `WKURLSchemeHandler` / load call on macOS), not in any embedded
resource. The signed manifests + pinned key are the shared cross-platform trust
data; only the feed mechanism differs.

### Proposed Resource Model

Add two resource types and canonical URIs:

```text
ResourceType::WebAppBundle   "web-app-bundle"   pm://app/chat.html
                                                pm://app/settings.html
                                                pm://app/xblox.html
ResourceType::AssetArchive   "asset-archive"    pm://asset/shared.pfs
```

These are public UI assets with no secrets, so the vendor-seed rule applies:

```text
dist/shared seed   = signed, plaintext, no private/decrypt keys shipped
trust level        = SignedVendor (pinned vendor key, no user-local downgrade)
encrypted          = false (no confidentiality requirement for shipped UI)
```

Trust here is integrity/provenance only; a verified bundle is still not
authorized to do anything the SecurityGateway would otherwise gate.

### Sign At Build, Verify At Load

Build (extend `scripts/assets/sign-assets.sh`), for each of `chat.html`,
`settings.html`, `xblox.html`, `assets.pfs`:

```text
pm-image-security --config-dir dist/data storage doc put \
  --uri <pm uri> --file dist/shared/<file> \
  --type <web-app-bundle|asset-archive> --trust signed-vendor \
  --provider polymech --signer polymech-dist-ed25519 --no-encrypt --seed-plaintext
pm-image-security --config-dir dist/data storage doc sign   --uri <pm uri>
pm-image-security --config-dir dist/data storage doc verify --uri <pm uri> \
  --require-signature --allow-vendor-seed-plaintext --allow-trust signed-vendor
# then strip resources/keys/*.pme1 — never ship private keys (same as today)
```

Load (C++):

```text
load_chat_web_html(): read bytes -> sha256 -> compare to signed manifest digest
  -> verify Ed25519 signature against the pinned vendor public key
  -> only then return HTML; otherwise hard-fail with a clear UI error
     (no silent raw-byte fallback)
mount assets.pfs: verify the .pfs blob digest + signature BEFORE PHYSFS_mount
```

### Open Questions

- Manifest delivery (no `RT_RCDATA`): ship the signed manifests as plain files in
  a read-only `resources/` tree next to the exe / in the app bundle, alongside
  `dist/shared`. They are the same signed-seed artifacts the `sign-assets.sh`
  step already emits, so the same files work on Windows and macOS. The trust
  anchor is the **pinned key**, not where the manifest sits.
- The pinned vendor public key must be a compiled constant (see P8), never read
  from the profile or from `dist/shared`. This is the only piece that must live
  inside the OS-verified binary (Authenticode / macOS code signature).
- Failure UX: hard-fail the panel, or show a degraded read-only banner when a
  bundle fails verification.
- macOS: confirm whether chat/settings are fed via `loadHTMLString` or a
  `WKURLSchemeHandler`; the latter lets the native side gate every subresource
  and is the better verification seam under the App Store sandbox.

### P9 Todos

- [x] Add `ResourceType::WebAppBundle` and `ResourceType::AssetArchive` to
  `src/model/resource_types.hpp` (plus string round-trips). _(POC)_
- [x] Define the `pm://app/<name>.pmbundle` resource (all-in-one signed archive);
  `pm://asset/shared.pfs` still TBD. _(POC)_
- [ ] Extend `sign-assets.sh` to sign all `dist/shared/*.html` and `assets.pfs`
  as `SignedVendor` plaintext seeds; never ship `resources/keys/*`.
- [ ] Ship signed manifests as plain read-only files next to `dist/shared` (no
  `RT_RCDATA`); pin only the vendor public key in the binary.
- [ ] Windows: verify digest + signature inside `load_chat_web_html` /
  `load_settings_web_html` / `load_xblox_web_html` before returning bytes — gates
  both the vhost-file (A) and `NavigateToString` (B) feeds; hard-fail on mismatch.
- [ ] Windows: rewrite the `chat-web/chat.html` vhost copy from verified bytes on
  every launch; never trust the existing copy in the writable LOCALAPPDATA folder.
- [ ] macOS: gate the WKWebView feed (`loadHTMLString` or `WKURLSchemeHandler`)
  with the same digest/signature check against the shared signed manifest.
- [ ] Verify the `assets.pfs` blob before `PHYSFS_mount`; refuse to mount on
  mismatch (icons fall back to the on-disk `vendor/tabler-icons` tree).
- [x] Add `test:secure-storage` cases for bundles: pack/sign/verify/serve/unpack
  round-trip plus a tampered archive refused before serving. _(POC — `suiteAssetBundle`)_
- [ ] (Deferred / P5) Build a real multi-blob `.pmbundle` container only if we
  need per-entry verification inside `assets.pfs`; single-blob signing covers v1.

### POC Status (landed)

A working proof-of-concept for the all-in-one `*.pmbundle` flow is in tree and
green under `npm run test:secure-storage`.

- `ResourceType::WebAppBundle` / `ResourceType::AssetArchive` added to
  `src/model/resource_types.hpp` (with `web-app-bundle` / `asset-archive`
  string round-trips). `storage put --type asset-archive` accepts them.
- `src/storage/asset_bundle.{hpp,cpp}` — the bundle container. A `*.pmbundle`
  is a **store-only (uncompressed) ZIP**: one all-in-one blob holding the whole
  built web app (`index.html` + sibling JS chunks + `.wasm` + nested assets).
  Store-only ZIP is what **PhysicsFS mounts natively**, so the exact bytes
  verified here can later be mounted at runtime with `PHYSFS_mountMemory()` and
  served to WebView2 / a `WKURLSchemeHandler` unchanged. The POC ships a small
  built-in ZIP reader (CRC-32 checked) so `serve` can emulate a single web-engine
  subresource request without linking PhysFS into the CLI yet. Zip-slip is
  rejected on unpack.
- The bundle is signed/verified as a **single resource blob** by the existing
  secure-storage layer (`put_resource` + `sign_resource_manifest` +
  `verify_resource`) — no new crypto. `bundle serve --uri` runs the
  digest + Ed25519 signature check *before* returning any bytes.
- `pm-image-security storage bundle` subcommands:
  - `pack   --dir <built-app> --file chat.pmbundle`
  - `list   --uri pm://app/chat.pmbundle | --file chat.pmbundle`
  - `serve  --uri … | --file … --path /index.html`  (emulates a webview request;
    returns content-type, byte length, sha256, and UTF-8 body for text entries)
  - `unpack --uri … | --file … --out <dir>`
- Fixture: `tests/fixtures/webbundle/chat/` (`index.html`, `app.js`,
  `assets/styles.css`); the test injects a binary `app.wasm` to cover the
  non-text / `application/wasm` path.
- `tests/orchestrator/test-secure-storage.mjs` → `suiteAssetBundle` proves:
  pack (4 entries incl. nested + wasm) → store as `asset-archive` → sign →
  verified `serve` of `/index.html` (signature checked) → `list` → `unpack`
  round-trip → **tampered blob is refused before serving** (`digest mismatch`).

Remaining to graduate from POC: swap the in-CLI ZIP reader for
`PHYSFS_mountMemory` on the verified bytes, wire the per-platform load seams
(the `load_*_web_html` / `WKURLSchemeHandler` chokepoints above), and add the
build-time `pack`+`sign` step to `sign-assets.sh`.

## First Vertical Slice

Implement in this order:

```text
1. [x] `pm://config/commands.json`
2. [x] signed manifest + CAS blob
3. [x] `pm-image-security.exe storage verify`
4. [x] storage-backed `commands.json` loader (in-app + editor)
5. [x] tamper test
6. [x] `pm://config/prompts/system-prompt.md`
7. [x] `pm://config/settings.json` — settings.json migrated
8. [x] `pm://config/mcp.json` — mcp.json migrated
9. [x] editor save wiring (vw_save_file → operation guard)
10. [x] Windows Hello verification for import/export/update
11. [x] BackupSettingsPanel UI
12. [ ] `--system-prompt @path` through storage policy (P4 remainder)
13. [ ] SecurityGateway at execution for shellLine commands (P3 remainder)
14. [ ] dual-provenance metadata after seed import (P3 remainder)
15. [ ] sign `dist/shared/{chat,settings,xblox}.html` + `assets.pfs` (P9)
16. [ ] verify web bundle digest/signature in `load_*_web_html` before load (P9)
17. [ ] verify `assets.pfs` blob before `PHYSFS_mount` (P9)
```

## Resources

<https://theupdateframework.github.io/specification/v1.0.33/>
