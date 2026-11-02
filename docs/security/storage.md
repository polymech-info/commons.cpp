https://theupdateframework.github.io/specification/v1.0.33/

# Resource VFS (Secure Resource Store)

## Goal

Provide a single resource pipeline for all application assets:

* prompts
* scripts
* templates
* workflows
* MCP manifests
* tool schemas
* AI agents
* policies
* command definitions
* snippets
* UI layouts
* icons/images
* localization
* documentation

while providing:

* immutable built-in resources
* signed vendor bundles
* encrypted user resources
* workspace overlays
* provenance tracking
* versioning
* integrity verification
* trust-aware loading

The Resource VFS is **not** a security boundary.

The SecurityGateway decides whether a resource may be used.

The Resource VFS guarantees:

* identity
* integrity
* provenance
* storage
* versioning

---

# High level architecture

```text
                 Resource URI

                        │
                        ▼

               ResourceResolver

                        │

        ┌───────────────┼────────────────┐

        ▼               ▼                ▼

 Builtin Provider   Bundle Provider   User Provider

        │               │                │

        ▼               ▼                ▼

      Resource Objects (typed)

                        │

                        ▼

                Resource Policy

                        │

                        ▼

               Prompt Assembler /
             Script Loader / Schema Loader
```

---

# Resource URI

Everything is addressed via URI.

Never via raw filesystem paths.

Examples:

```text
pm://prompt/system/main

pm://prompt/security/tool-gateway

pm://agent/default

pm://script/python/extract_tables

pm://template/report/default

pm://schema/tool/image.resize

pm://policy/default

pm://workflow/office/import
```

Providers map URIs to physical storage.

---

# Trust levels

```cpp
enum class TrustLevel
{
    Builtin,
    SignedVendor,
    User,
    Workspace,
    Remote,
    Untrusted
};
```

Trust is attached to every resource.

Not inferred from location.

---

# Resource types

```cpp
enum class ResourceType
{
    Prompt,

    Script,

    Template,

    ToolSchema,

    McpManifest,

    Policy,

    Workflow,

    Agent,

    Json,

    Markdown,

    Binary,

    Image,

    Localization,

    Unknown
};
```

---

# Resource metadata

```cpp
struct ResourceMeta
{
    ResourceUri uri;

    ResourceType type;

    TrustLevel trust;

    std::string version;

    std::string digest;

    std::string signer;

    std::string provider;

    bool mutable;

    bool encrypted;

    bool compressed;
};
```

---

# Resource object

```cpp
struct Resource
{
    ResourceMeta meta;

    std::vector<uint8_t> data;
};
```

---

# Resource providers

## Builtin

Compiled resources.

```text
resources.rc

cmrc

embedded blobs

incbin
```

Immutable.

Always trusted.

---

## Signed Bundle

Single distributable package.

Example:

```text
polymech-core.bundle

office.bundle

vision.bundle

python.bundle
```

Contains

```text
manifest

signatures

resources

metadata
```

---

## User Provider

Private editable resources.

Stored in SQLite.

Encrypted.

Typical contents:

```text
custom prompts

private agents

notes

templates

macros
```

---

## Workspace Provider

Project-local resources.

Example:

```text
.polymech/

.prompts/

.agents/

.templates/
```

Lower trust.

Visible to user.

Never automatically elevated.

---

## Remote Provider

Future.

Downloads signed bundles.

No executable content automatically enabled.

---

# Bundle format

Single file.

```text
core.bundle

    manifest.json

    signatures/

    blobs/

    metadata/
```

Resources referenced by digest.

No mutable filenames.

---

# Content-addressable storage

Internally:

```text
sha256/

    aa/

       aabbcc...

    ff/

       ff9988...
```

Every resource identified by digest.

Benefits:

* deduplication
* immutable objects
* integrity
* caching
* rollback detection

---

# Overlay order

```
Builtin

↓

Vendor Bundle

↓

User

↓

Workspace

↓

Runtime
```

Policy determines which layers may override.

Security resources never overridden.

---

# Resource policy

Example rules:

```text
SystemPrompt

Builtin

SignedVendor

--------------------

DeveloperPrompt

Builtin

SignedVendor

--------------------

ToolSchema

Builtin

SignedVendor

--------------------

Template

Builtin

SignedVendor

User

Workspace

--------------------

Script

SignedVendor

User

Workspace

Ask before execution

--------------------

MCP Manifest

Never trusted automatically
```

---

# Prompt assembly

Do not concatenate strings.

Instead:

```cpp
struct PromptSegment
{
    ResourceMeta meta;

    std::string text;
};

struct Prompt
{
    std::vector<PromptSegment> segments;
};
```

Every segment carries provenance.

---

# Resource pipeline

```
Resolve URI

↓

Locate provider

↓

Load resource

↓

Verify digest

↓

Verify signature

↓

Decrypt (optional)

↓

Decompress

↓

Validate schema

↓

Apply policy

↓

Return typed resource
```

---

# Security pipeline

```
LLM

↓

SecurityGateway

↓

Resource Policy

↓

Resource VFS

↓

Typed Resource

↓

Prompt Assembler
```

The LLM never directly opens files.

---

# Encryption

Builtin resources

```text
not encrypted

signed
```

User resources

```text
DPAPI protected master key

↓

libsodium

↓

SQLite blobs
```

Workspace resources

```text
plaintext

optional signatures

optional encryption
```

---

# Signatures

Builtin bundles

```text
Ed25519

or

Authenticode manifest
```

Every bundle contains:

```text
resource digest

bundle digest

signature

version
```

Runtime verifies before mounting.

---

# Resource permissions

The VFS does not authorize use.

Example:

```
Resource exists

↓

Resource verified

↓

SecurityGateway asks:

May this resource be used
as a System Prompt?

↓

yes/no
```

---

# Versioning

Resources are immutable.

New version:

```text
pm://prompt/system/main

version

2.1.0

digest

new sha256
```

Old versions remain addressable.

---

# Caching

Cache by digest.

```
sha256

↓

already present

↓

reuse
```

No filename-based cache.

---

# Resource invalidation

Invalidate cache if:

* digest mismatch
* signature mismatch
* schema version mismatch
* bundle revoked
* trust downgraded

---

# Public API

```cpp
class ResourceManager
{
public:

    Resource resolve(ResourceUri);

    Resource open(ResourceHandle);

    std::vector<ResourceMeta> list(ResourcePrefix);

    bool verify(ResourceHandle);

    bool exists(ResourceUri);
};
```

---

# Providers

```cpp
IResourceProvider

    BuiltinProvider

    BundleProvider

    UserProvider

    WorkspaceProvider

    RemoteProvider
```

---

# Storage

Builtin

```
compiled
```

Vendor

```
.bundle
```

User

```
SQLite

encrypted blobs
```

Workspace

```
filesystem
```

Runtime

```
memory
```

---

# Security goals

* no raw prompt loading from arbitrary paths
* immutable shipped resources
* signed bundles
* encrypted private resources
* provenance-aware prompt assembly
* content-addressable caching
* typed resources
* policy-controlled usage
* reproducible resource resolution
* provider abstraction
* cross-platform implementation

---

# Suggested implementation

```
src/resource/

    ResourceManager.*

    ResourceResolver.*

    ResourcePolicy.*

    ResourceUri.*

    ResourceBundle.*

    ResourceManifest.*

    ResourceCas.*

    ResourceCache.*

    ResourceProvider.*

    providers/

        BuiltinProvider.*

        BundleProvider.*

        UserProvider.*

        WorkspaceProvider.*

        RemoteProvider.*

    crypto/

        ResourceSignature.*

        ResourceDigest.*

        ResourceEncryption.*

    prompt/

        PromptAssembler.*

        PromptSegment.*

    schema/

        ResourceValidator.*
```

---

# Future extensions

* OCI-style bundle manifests
* Delta bundle updates
* Bundle dependency graph
* Multiple vendor roots
* Enterprise policy bundles
* Signed plugin packages
* Package repository
* Transparency log for bundle signatures
* Remote synchronization
* Cross-device encrypted user resource replication

----------------------------


Below is a concrete raw-md implementation skeleton. TUF maps nicely here: **Root signs trust anchors, Targets signs resource digests, Snapshot prevents mix-and-match, Timestamp prevents stale bundle use**. TUF defines those four top-level roles and threshold signatures; OCI-style layouts are useful for `index.json` + content-addressed `blobs/sha256/...`; libsodium gives you Ed25519 signing primitives. ([theupdateframework.github.io][1])

````markdown
# Secure Resource VFS — C++ Classes + TUF-inspired Design

## Core idea

Do not load prompts/scripts/policies by raw path.

Everything goes through:

```txt
ResourceUri
  ↓
ResourceManager
  ↓
TufVerifier
  ↓
ResourcePolicy
  ↓
TypedResource
````

Resource trust comes from:

```txt
digest
signature
role metadata
expiry
version
origin
declared resource type
```

Not from filename.

---

## Storage layout

```txt
resources/
  tuf/
    root.json
    timestamp.json
    snapshot.json
    targets.json

  blobs/
    sha256/
      aa/
        aabbcc...

  indexes/
    resource-index.sqlite

  user/
    user-resources.sqlite
```

Optional bundle format:

```txt
polymech-core.pmbundle
  tuf/root.json
  tuf/timestamp.json
  tuf/snapshot.json
  tuf/targets.json
  blobs/sha256/...
```

---

# Class layout

```txt
src/resource/
  ResourceUri.hpp
  ResourceTypes.hpp
  ResourceManager.hpp/.cpp
  ResourceResolver.hpp/.cpp
  ResourcePolicy.hpp/.cpp
  ResourceIndex.hpp/.cpp
  ResourceCas.hpp/.cpp
  ResourceBundle.hpp/.cpp
  ResourceProvider.hpp

src/resource/providers/
  BuiltinResourceProvider.hpp/.cpp
  TufBundleProvider.hpp/.cpp
  UserDbResourceProvider.hpp/.cpp
  WorkspaceResourceProvider.hpp/.cpp
  RemoteResourceProvider.hpp/.cpp

src/resource/tuf/
  TufTypes.hpp
  TufRoot.hpp/.cpp
  TufTargets.hpp/.cpp
  TufSnapshot.hpp/.cpp
  TufTimestamp.hpp/.cpp
  TufVerifier.hpp/.cpp
  TufRepository.hpp/.cpp
  TufKeyStore.hpp/.cpp

src/resource/crypto/
  Digest.hpp/.cpp
  SignatureVerifier.hpp/.cpp
  SodiumEd25519Verifier.hpp/.cpp
  ResourceEncryption.hpp/.cpp
  WinDpapiCrypto.cpp

src/resource/prompt/
  PromptAssembler.hpp/.cpp
  PromptSegment.hpp

src/resource/schema/
  ResourceSchemaValidator.hpp/.cpp
```

---

# Basic enums

```cpp
enum class TrustLevel {
    Builtin,
    SignedVendor,
    UserLocal,
    Workspace,
    Remote,
    Untrusted
};

enum class ResourceType {
    Prompt,
    Script,
    Template,
    Policy,
    ToolSchema,
    McpManifest,
    Workflow,
    Agent,
    Json,
    Markdown,
    Binary,
    Image,
    Unknown
};

enum class ResourceUse {
    SystemPrompt,
    DeveloperPrompt,
    UserPromptAddon,
    ToolSchema,
    McpManifest,
    Policy,
    ScriptExecution,
    TemplateRender,
    UiAsset,
    DataOnly
};

enum class ResourceProviderKind {
    Builtin,
    TufBundle,
    UserDb,
    Workspace,
    Remote
};
```

---

# ResourceUri

```cpp
class ResourceUri {
public:
    static std::expected<ResourceUri, ResourceError> parse(std::string_view text);

    std::string_view scheme() const;   // pm, builtin, user, workspace, bundle
    std::string_view path() const;     // prompt/system/main
    std::string canonical() const;

    bool isBuiltin() const;
    bool isUser() const;
    bool isWorkspace() const;
};
```

Example URIs:

```txt
pm://prompt/system/main
pm://prompt/security/tool-gateway
pm://script/python/extract-tables
pm://schema/tool/image.resize
pm://policy/default
```

---

# Resource metadata

```cpp
struct ResourceDigest {
    std::string algorithm; // sha256, blake3
    std::string hex;
};

struct ResourceMeta {
    ResourceUri uri;
    ResourceType type;
    TrustLevel trust;
    ResourceProviderKind provider;

    std::string version;
    ResourceDigest digest;

    std::string signerId;
    std::string bundleId;
    std::string bundleVersion;

    bool mutableResource = false;
    bool encrypted = false;
    bool compressed = false;

    std::chrono::system_clock::time_point createdAt;
};
```

---

# Resource object

```cpp
struct Resource {
    ResourceMeta meta;
    std::vector<std::byte> data;
};
```

---

# Resource request

```cpp
struct ResourceRequest {
    ResourceUri uri;
    ResourceUse use;

    TrustLevel minimumTrust = TrustLevel::Builtin;

    std::string profile;       // dev, oem, end_user
    std::string workspaceId;
    std::string sessionId;

    bool allowUserOverride = false;
    bool allowWorkspace = false;
};
```

---

# ResourceManager

```cpp
class ResourceManager {
public:
    std::expected<Resource, ResourceError>
    load(const ResourceRequest& request);

    std::expected<ResourceMeta, ResourceError>
    stat(const ResourceUri& uri);

    std::vector<ResourceMeta>
    list(std::string_view prefix);

    void mountProvider(std::unique_ptr<IResourceProvider> provider);

private:
    ResourceResolver resolver_;
    ResourcePolicy policy_;
    ResourceSchemaValidator validator_;
};
```

---

# Provider interface

```cpp
class IResourceProvider {
public:
    virtual ~IResourceProvider() = default;

    virtual ResourceProviderKind kind() const = 0;
    virtual TrustLevel trustLevel() const = 0;

    virtual bool canResolve(const ResourceUri& uri) const = 0;

    virtual std::expected<ResourceMeta, ResourceError>
    stat(const ResourceUri& uri) = 0;

    virtual std::expected<Resource, ResourceError>
    load(const ResourceUri& uri) = 0;
};
```

---

# Builtin provider

Compiled or embedded app resources.

```cpp
class BuiltinResourceProvider final : public IResourceProvider {
public:
    explicit BuiltinResourceProvider(BuiltinResourceTable table);

    bool canResolve(const ResourceUri& uri) const override;

    std::expected<ResourceMeta, ResourceError>
    stat(const ResourceUri& uri) override;

    std::expected<Resource, ResourceError>
    load(const ResourceUri& uri) override;

private:
    BuiltinResourceTable table_;
};
```

Rules:

```txt
immutable
highest trust
cannot be overridden for SystemPrompt/Policy/ToolSchema
```

---

# TUF bundle provider

```cpp
class TufBundleProvider final : public IResourceProvider {
public:
    explicit TufBundleProvider(std::filesystem::path bundlePath,
                               TufVerifier& verifier,
                               ResourceCas& cas);

    std::expected<void, ResourceError> mount();

    bool canResolve(const ResourceUri& uri) const override;

    std::expected<ResourceMeta, ResourceError>
    stat(const ResourceUri& uri) override;

    std::expected<Resource, ResourceError>
    load(const ResourceUri& uri) override;

private:
    std::filesystem::path bundlePath_;
    TufVerifier& verifier_;
    ResourceCas& cas_;
    ResourceIndex index_;
};
```

Mount flow:

```txt
open bundle
load root.json
load timestamp.json
load snapshot.json
load targets.json
verify TUF chain
index target resources
expose resources by URI
```

---

# User DB provider

Encrypted editable resources.

```cpp
class UserDbResourceProvider final : public IResourceProvider {
public:
    UserDbResourceProvider(std::filesystem::path dbPath,
                           ResourceEncryption& encryption);

    std::expected<Resource, ResourceError>
    load(const ResourceUri& uri) override;

    std::expected<void, ResourceError>
    save(ResourceMeta meta, std::span<const std::byte> plaintext);

    std::expected<void, ResourceError>
    remove(const ResourceUri& uri);

private:
    sqlite3* db_ = nullptr;
    ResourceEncryption& encryption_;
};
```

Use for:

```txt
custom prompts
private templates
user agents
local notes
private scripts
```

Not trusted for:

```txt
SystemPrompt
Policy
ToolSchema
```

unless explicitly allowed in dev mode.

---

# Workspace provider

```cpp
class WorkspaceResourceProvider final : public IResourceProvider {
public:
    explicit WorkspaceResourceProvider(std::filesystem::path workspaceRoot);

    std::expected<Resource, ResourceError>
    load(const ResourceUri& uri) override;

private:
    std::filesystem::path workspaceRoot_;

    std::expected<std::filesystem::path, ResourceError>
    resolveSafePath(const ResourceUri& uri) const;
};
```

Workspace resources are always lower trust.

They may suggest behavior but cannot replace core security resources.

---

# ResourcePolicy

```cpp
class ResourcePolicy {
public:
    std::expected<void, ResourceError>
    authorize(const ResourceRequest& request, const ResourceMeta& meta) const;

private:
    bool canUseAsSystemPrompt(const ResourceMeta& meta) const;
    bool canUseAsPolicy(const ResourceMeta& meta) const;
    bool canUseAsToolSchema(const ResourceMeta& meta) const;
    bool canExecuteScript(const ResourceRequest& request,
                          const ResourceMeta& meta) const;
};
```

Suggested rules:

```cpp
bool ResourcePolicy::canUseAsSystemPrompt(const ResourceMeta& m) const {
    return m.trust == TrustLevel::Builtin ||
           m.trust == TrustLevel::SignedVendor;
}

bool ResourcePolicy::canUseAsPolicy(const ResourceMeta& m) const {
    return m.trust == TrustLevel::Builtin ||
           m.trust == TrustLevel::SignedVendor;
}

bool ResourcePolicy::canUseAsToolSchema(const ResourceMeta& m) const {
    return m.trust == TrustLevel::Builtin ||
           m.trust == TrustLevel::SignedVendor;
}
```

---

# Resource CAS

```cpp
class ResourceCas {
public:
    explicit ResourceCas(std::filesystem::path root);

    std::expected<ResourceDigest, ResourceError>
    put(std::span<const std::byte> data);

    std::expected<std::vector<std::byte>, ResourceError>
    get(const ResourceDigest& digest);

    bool contains(const ResourceDigest& digest) const;

    std::expected<void, ResourceError>
    verify(const ResourceDigest& digest);

private:
    std::filesystem::path root_;
};
```

Layout:

```txt
cas/sha256/aa/aabbcc...
```

---

# TUF types

## TufKey

```cpp
struct TufKey {
    std::string keyId;
    std::string keyType;      // ed25519
    std::string scheme;       // ed25519
    std::vector<std::byte> publicKey;
};
```

## TufSignature

```cpp
struct TufSignature {
    std::string keyId;
    std::vector<std::byte> signature;
};
```

## TufRole

```cpp
struct TufRole {
    std::string name;         // root, targets, snapshot, timestamp
    std::vector<std::string> keyIds;
    uint32_t threshold = 1;
};
```

## TufSignedEnvelope

```cpp
template<class T>
struct TufSignedEnvelope {
    std::vector<TufSignature> signatures;
    T signedPayload;
    std::vector<std::byte> canonicalJson;
};
```

---

# TUF metadata classes

## Root

```cpp
struct TufRoot {
    uint32_t version;
    std::chrono::system_clock::time_point expires;

    std::unordered_map<std::string, TufKey> keys;
    std::unordered_map<std::string, TufRole> roles;
};
```

Root answers:

```txt
Which keys are trusted?
Which keys may sign each role?
How many signatures are required?
```

---

## Timestamp

```cpp
struct TufTimestamp {
    uint32_t version;
    std::chrono::system_clock::time_point expires;

    ResourceDigest snapshotDigest;
    uint64_t snapshotLength;
};
```

Timestamp answers:

```txt
What is the latest snapshot?
Is metadata stale?
```

---

## Snapshot

```cpp
struct TufSnapshotMeta {
    ResourceDigest digest;
    uint64_t length;
    uint32_t version;
};

struct TufSnapshot {
    uint32_t version;
    std::chrono::system_clock::time_point expires;

    std::unordered_map<std::string, TufSnapshotMeta> meta;
};
```

Snapshot answers:

```txt
Which exact targets metadata files are valid?
Prevents mix-and-match attacks.
```

---

## Targets

```cpp
struct TufTargetCustom {
    ResourceUri uri;
    ResourceType type;
    TrustLevel trust;

    std::string version;
    std::string mediaType;

    bool executable = false;
    bool mutableResource = false;
};

struct TufTarget {
    std::string path;
    ResourceDigest digest;
    uint64_t length;
    TufTargetCustom custom;
};

struct TufTargets {
    uint32_t version;
    std::chrono::system_clock::time_point expires;

    std::unordered_map<std::string, TufTarget> targets;
};
```

Targets answers:

```txt
Which resource digests are trusted?
What type/use/trust does each resource have?
```

---

# TufVerifier

```cpp
class TufVerifier {
public:
    explicit TufVerifier(TufKeyStore& keyStore,
                         SignatureVerifier& sigs,
                         Clock& clock);

    std::expected<TufRepository, ResourceError>
    verifyRepository(const TufMetadataSet& metadata);

    std::expected<void, ResourceError>
    verifyRoot(const TufSignedEnvelope<TufRoot>& root);

    std::expected<void, ResourceError>
    verifyTimestamp(const TufSignedEnvelope<TufTimestamp>& timestamp,
                    const TufRoot& root);

    std::expected<void, ResourceError>
    verifySnapshot(const TufSignedEnvelope<TufSnapshot>& snapshot,
                   const TufTimestamp& timestamp,
                   const TufRoot& root);

    std::expected<void, ResourceError>
    verifyTargets(const TufSignedEnvelope<TufTargets>& targets,
                  const TufSnapshot& snapshot,
                  const TufRoot& root);

private:
    TufKeyStore& keyStore_;
    SignatureVerifier& signatures_;
    Clock& clock_;

    bool verifyThreshold(std::string_view roleName,
                         std::span<const TufSignature> signatures,
                         std::span<const std::byte> canonicalJson,
                         const TufRoot& root);
};
```

Verification order:

```txt
root
timestamp
snapshot
targets
target blobs
```

---

# Signature verifier

```cpp
class SignatureVerifier {
public:
    virtual ~SignatureVerifier() = default;

    virtual bool verifyEd25519(std::span<const std::byte> publicKey,
                               std::span<const std::byte> message,
                               std::span<const std::byte> signature) = 0;
};

class SodiumEd25519Verifier final : public SignatureVerifier {
public:
    bool verifyEd25519(std::span<const std::byte> publicKey,
                       std::span<const std::byte> message,
                       std::span<const std::byte> signature) override;
};
```

libsodium call:

```cpp
crypto_sign_verify_detached(sig, msg, msgLen, publicKey);
```

---

# Key store

```cpp
class TufKeyStore {
public:
    std::expected<void, ResourceError>
    loadPinnedRootKeys(std::span<const std::byte> embeddedRootJson);

    bool isPinnedRoot(const TufRoot& root) const;

    std::expected<void, ResourceError>
    rotateRoot(const TufSignedEnvelope<TufRoot>& newRoot);

private:
    std::vector<TufKey> pinnedRootKeys_;
};
```

Root keys should be compiled into the app or shipped as an Authenticode-signed built-in resource.

---

# Resource bundle

```cpp
class ResourceBundle {
public:
    static std::expected<ResourceBundle, ResourceError>
    open(std::filesystem::path path);

    std::expected<TufMetadataSet, ResourceError>
    loadMetadata();

    std::expected<std::vector<std::byte>, ResourceError>
    loadBlob(const ResourceDigest& digest);

private:
    std::filesystem::path path_;
};
```

---

# TUF metadata set

```cpp
struct TufMetadataSet {
    TufSignedEnvelope<TufRoot> root;
    TufSignedEnvelope<TufTimestamp> timestamp;
    TufSignedEnvelope<TufSnapshot> snapshot;
    TufSignedEnvelope<TufTargets> targets;
};
```

---

# TUF repository result

```cpp
struct TufRepository {
    TufRoot root;
    TufTimestamp timestamp;
    TufSnapshot snapshot;
    TufTargets targets;

    std::unordered_map<ResourceUri, TufTarget> index;
};
```

---

# Resource index

```cpp
class ResourceIndex {
public:
    void add(const TufTarget& target);

    std::optional<TufTarget>
    find(const ResourceUri& uri) const;

    std::vector<ResourceMeta>
    list(std::string_view prefix) const;

private:
    std::unordered_map<std::string, TufTarget> byUri_;
};
```

---

# Prompt assembler

```cpp
class PromptAssembler {
public:
    explicit PromptAssembler(ResourceManager& resources);

    std::expected<AssembledPrompt, ResourceError>
    buildSystemPrompt(const PromptBuildRequest& request);

private:
    ResourceManager& resources_;
};
```

```cpp
struct PromptSegment {
    ResourceMeta meta;
    std::string text;
};

struct AssembledPrompt {
    std::vector<PromptSegment> segments;

    std::string renderForModel() const;
};
```

Render with provenance boundaries:

```txt
<segment uri="pm://prompt/system/main" trust="Builtin" sha256="...">
...
</segment>
```

Never let MCP descriptions enter privileged segments.

---

# Resource encryption

```cpp
class ResourceEncryption {
public:
    std::expected<std::vector<std::byte>, ResourceError>
    encrypt(ResourceUri uri,
            ResourceType type,
            std::span<const std::byte> plaintext);

    std::expected<std::vector<std::byte>, ResourceError>
    decrypt(ResourceUri uri,
            ResourceType type,
            std::span<const std::byte> ciphertext);
};
```

Use:

```txt
DPAPI → protects local master key
libsodium → encrypts blobs
SQLite → stores encrypted user resources
```

AAD:

```txt
uri
resource_type
schema_version
app_id
profile
```

---

# SQLite user resource schema

```sql
CREATE TABLE user_resources (
    uri TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    version TEXT,
    digest TEXT NOT NULL,
    trust TEXT NOT NULL,
    aad TEXT NOT NULL,
    encrypted_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

---

# Loading flow

```cpp
auto res = resourceManager.load({
    .uri = ResourceUri::parse("pm://prompt/security/tool-gateway").value(),
    .use = ResourceUse::SystemPrompt,
    .minimumTrust = TrustLevel::Builtin,
    .profile = "end_user"
});
```

Internally:

```txt
resolve URI
select provider
load metadata
verify digest
verify signature / TUF chain
decrypt if needed
validate schema/type
apply ResourcePolicy
return Resource
```

---

# Bundle build tool

Add CLI:

```txt
pm-resource pack
pm-resource sign
pm-resource verify
pm-resource list
pm-resource inspect
```

Example:

```bash
pm-resource pack ./resources --out polymech-core.pmbundle
pm-resource sign polymech-core.pmbundle --role targets --key targets.key
pm-resource verify polymech-core.pmbundle
```

---

# Minimal v1 implementation

Implement first:

```txt
ResourceUri
ResourceMeta
ResourceManager
BuiltinResourceProvider
UserDbResourceProvider
ResourcePolicy
ResourceCas
Digest
SodiumEd25519Verifier
TufRoot
TufTargets
TufVerifier
PromptAssembler
```

Skip initially:

```txt
delegated targets
remote updates
delta bundles
timestamp server
transparency log
```

---

# P0 rules

Hard fail if:

```txt
SystemPrompt comes from User/Workspace/Remote
Policy comes from User/Workspace/Remote
ToolSchema comes from MCP tool description
bundle signature invalid
target digest mismatch
metadata expired
snapshot references unknown target metadata
user override attempts to loosen policy
```

---

# External references

* TUF specification: [https://theupdateframework.github.io/specification/latest/](https://theupdateframework.github.io/specification/latest/)
* OCI Image Layout: [https://specs.opencontainers.org/image-spec/image-layout/](https://specs.opencontainers.org/image-spec/image-layout/)
* libsodium signatures: [https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures)

```
```

[1]: https://theupdateframework.github.io/specification/latest/?utm_source=chatgpt.com "The Update Framework Specification"


------------------------------------------

background 
Fair. There isn’t a perfect “C++ secure resource platform” off the shelf. The better answer is: **don’t look for a VFS library; use a package/store model.**

For your case — prompts, scripts, schemas, tool defs, templates, policies — the closest solid architecture is:

```txt
OCI-ish bundles + manifest + CAS + encrypted user overlay
```

Not PhysicsFS.

## Better building blocks

### 1. OCI image/layout ideas

Use the **OCI image layout model**: manifest, blobs, digests, media types. You do not need Docker. OCI Image Spec defines content-addressed blobs and manifests with media types/digests. ([llvm.org][1])

Your package:

```txt
bundle/
  index.json
  blobs/sha256/<hash>
```

Resources are addressed by digest, not mutable path.

Example media types:

```txt
application/x-polymech.prompt+markdown
application/x-polymech.tool-schema+json
application/x-polymech.policy+json
application/x-polymech.script+python
application/x-polymech.template+mustache
```

### 2. CAS core

LLVM’s CAS docs describe the useful property: immutable objects identified by content, good for deduplication and reliable computation inputs. ([llvm.org][1])

That maps well to prompts/scripts:

```txt
resource name → manifest entry → sha256 digest → blob
```

Never trust “latest file named security.md”.

Trust:

```txt
security/main.md @ sha256:abc...
signed by vendor
type = system_prompt
```

### 3. TUF-style update thinking

For updates, borrow from **The Update Framework** model: signed metadata, roles, expiry, rollback protection. You do not need full TUF v1, but steal the concepts.

```txt
root key
targets metadata
snapshot version
timestamp/expiry
resource digests
```

## Recommended custom stack

```txt
libpm_resource
  ├─ PmBundleReader       // OCI-ish layout or single .pmbundle
  ├─ PmCasStore           // blobs by sha256
  ├─ PmManifestVerifier   // signatures, expiry, rollback
  ├─ PmResourceIndex      // uri/type/version → digest
  ├─ PmEncryptedOverlay   // SQLite + DPAPI/libsodium
  ├─ PmPromptAssembler
  └─ PmResourcePolicy
```

## Storage layout

```txt
%LOCALAPPDATA%/PolyMech/resources/
  cas/
    sha256/
      ab/
        abcdef...
  bundles/
    builtin.bundle
    vendor.bundle
  overlays/
    user.sqlite
    workspace.sqlite
```

Single-file shipping option:

```txt
polymech-core.pmbundle
```

Internally:

```txt
manifest.cbor
signatures/
blobs/
```

Use CBOR/MessagePack if you want compact; JSON is fine for v1.

## Why this beats VFS

A VFS answers:

```txt
open("/prompts/system.md")
```

You need:

```txt
Can this exact resource, from this origin, with this signature, be used as a system prompt?
```

So your API should be:

```cpp
ResourceHandle h = resources.resolve({
  .uri = "pm://prompt/security/tool-gateway",
  .use = ResourceUse::SystemPrompt,
  .minTrust = TrustLevel::Builtin
});
```

not:

```cpp
readFile("prompts/security/tool-gateway.md");
```

## Minimal v1

Use:

```txt
SQLite
libsodium
DPAPI on Windows
zstd optional
nlohmann/json or simdjson
SHA-256/BLAKE3
Ed25519 signatures via libsodium
```

libsodium gives you Ed25519 signatures and secretbox/aead primitives, so it fits your existing `WinDpapiCrypto.cpp`.

## Key rule

Core prompts/policies/scripts should be:

```txt
content-addressed
typed
signed
versioned
immutable
provenance-tagged
```

User/workspace resources should be:

```txt
editable
encrypted if private
lower trust
never eligible for SystemPrompt/SecurityPolicy unless explicitly signed
```

So yes: custom is justified here. Not huge custom VFS — a **typed signed resource store**.

[1]: https://llvm.org/docs/ContentAddressableStorage.html?utm_source=chatgpt.com "Content Addressable Storage"


