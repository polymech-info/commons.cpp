#include "security/ResourceClassifier.hpp"
#include "net/uri.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace pm::security {

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Executable / script extensions that ShellExecute would *run* rather than open.
// Kept narrow here; the authoritative list lives in src/file_extensions.hpp and
// should migrate behind ExtensionRiskDelegate (see docs/security/todos.md).
bool is_executable_ext(std::string_view ext_lower) {
    static constexpr const char* kExec[] = {
        ".exe", ".com", ".scr", ".cpl", ".msi", ".msix", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".sh", ".bash", ".py", ".dll", ".jar",
    };
    for (const char* e : kExec)
        if (ext_lower == e) return true;
    return false;
}

// App-specific active / markup formats that can trigger code execution or
// embed scripts and warrant a Medium or High baseline.
bool is_high_risk_ext(std::string_view ext_lower) {
    // xblox = Tanit automation format (can execute agent actions)
    static constexpr const char* kHigh[] = {
        ".xblox", ".page",
    };
    for (const char* e : kHigh)
        if (ext_lower == e) return true;
    return false;
}

bool is_medium_risk_ext(std::string_view ext_lower) {
    static constexpr const char* kMedium[] = {
        ".html", ".htm", ".xhtml", ".svg",
    };
    for (const char* e : kMedium)
        if (ext_lower == e) return true;
    return false;
}

// Extract the lowercase file extension from a URI path component.
// e.g. "tanit://view/vfs/models/test/pic.png" → ".png"
// Hardened against: query/fragment suffixes, percent-encoded dots/slashes,
// backslash separators, and Windows trailing dot/space tricks ("evil.exe. ").
std::string ext_from_uri(std::string_view uri) {
    const auto parsed = pm::uri::parse_uri(uri);
    const std::string_view encoded_path = parsed ? std::string_view(parsed->path) : uri;
    const auto decoded = pm::uri::percent_decode(encoded_path);
    if (!decoded)
        return {};
    std::string path = *decoded;
    std::replace(path.begin(), path.end(), '\\', '/');

    const auto slash = path.rfind('/');
    std::string name = slash != std::string::npos ? path.substr(slash + 1) : path;

    // Windows ignores trailing dots and spaces when resolving names.
    while (!name.empty() && (name.back() == '.' || name.back() == ' '))
        name.pop_back();

    const auto dot = name.rfind('.');
    if (dot == std::string::npos || dot == 0) return {};
    std::string ext = name.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext;
}

} // namespace

// ── Default delegates ─────────────────────────────────────────────────────────

bool DefaultSecretPatternDelegate::isSecret(const ResourceTarget& target) const {
    const std::string full = lower(PathSecurity::normalizeForMatch(target.path));
    const std::string base = lower(target.path.filename().string());

    for (const char* const* g = k_secret_basename_globs; *g; ++g) {
        if (PathSecurity::globMatch(base, *g)) return true;
    }
    for (const char* const* d = k_high_risk_dir_fragments; *d; ++d) {
        if (full.find(*d) != std::string::npos) return true;
    }
    return false;
}

Risk DefaultExtensionRiskDelegate::riskForResource(const ResourceTarget& target) const {
    const bool uri_only = target.path.empty() && target.extension.empty()
                          && !target.uri.empty();
    std::string ext = lower(!target.extension.empty()
                                ? target.extension
                                : target.path.extension().string());
    if (ext.empty() && !target.uri.empty())
        ext = ext_from_uri(target.uri);  // fall back to URI path component
    if (!ext.empty() && ext.front() != '.') ext.insert(ext.begin(), '.');

    if (is_executable_ext(ext) || is_high_risk_ext(ext)) return Risk::High;
    if (is_medium_risk_ext(ext))                         return Risk::Medium;

    // Fail closed for remote/URI targets with no recognisable extension: the
    // content type is unknown until fetched, so it cannot be assumed benign.
    // Local extensionless paths (Makefile, LICENSE, folders) stay Low.
    if (uri_only && ext.empty()) return Risk::Medium;
    return Risk::Low;
}

// ── ResourceClassifier ────────────────────────────────────────────────────────

ResourceClassifier::ResourceClassifier()
    : secret_(std::make_shared<DefaultSecretPatternDelegate>()),
      extRisk_(std::make_shared<DefaultExtensionRiskDelegate>()) {}

ResourceClassifier::~ResourceClassifier() = default;

void ResourceClassifier::setSecretDelegate(std::shared_ptr<SecretPatternDelegate> d) {
    if (d) secret_ = std::move(d);
}

void ResourceClassifier::setExtensionRiskDelegate(std::shared_ptr<ExtensionRiskDelegate> d) {
    if (d) extRisk_ = std::move(d);
}

ClassificationResult ResourceClassifier::classify(
    const ResourceTarget& target,
    Action action,
    const std::optional<CanonicalPath>& workspaceRoot) const {

    ClassificationResult result;

    // 1) Base risk from the resource type.
    result.risk = extRisk_->riskForResource(target);

    // 2) Secret/credential detection → at least High, flagged.
    if (secret_->isSecret(target)) {
        result.isSecret = true;
        result.risk = max_risk(result.risk, Risk::High);
        result.signals.emplace_back("matches known secret/credential pattern");
    }

    // 3) Workspace containment.
    if (workspaceRoot && !workspaceRoot->empty() && !target.path.empty()) {
        const CanonicalPath child = paths_.canonicalize(target.path);
        if (!paths_.isInside(child, *workspaceRoot)) {
            result.outsideWorkspace = true;
            result.risk = max_risk(result.risk, Risk::Medium);
            result.signals.emplace_back("resolves outside the workspace root");
        } else {
            // Flag files placed directly in the workspace root (no subdirectory).
            // Writing bare filenames like "notes.md" to a broad folder_hint root
            // (e.g. Desktop) is almost always an LLM navigation error and should
            // require consent the same way out-of-workspace writes do.
            const std::filesystem::path parent = target.path.parent_path();
            if (!parent.empty()) {
                const CanonicalPath canonical_parent = paths_.canonicalize(parent);
                if (paths_.isInside(*workspaceRoot, canonical_parent) &&
                    paths_.isInside(canonical_parent, *workspaceRoot)) {
                    result.atWorkspaceRoot = true;
                    result.signals.emplace_back("write target is directly in workspace root (no subdirectory)");
                }
            }
        }
    }

    // 4) Action weighting: writes > reads; execute/network/upload are highest.
    switch (action) {
        case Action::Delete:
        case Action::Execute:
        case Action::Upload:
        case Action::Publish:
        case Action::GitPush:
            result.risk = max_risk(result.risk, Risk::High);
            result.signals.emplace_back("high-impact action");
            break;
        case Action::Write:
        case Action::Network:
        case Action::Download:
            result.risk = max_risk(result.risk, Risk::Medium);
            break;
        case Action::Read:
        default:
            break;
    }

    // TODO(security, Phase 2): MIME sniffing, content secret-scan, OS-protected
    // dir detection (isOsProtected), gitignore/project metadata, workspace-trust.
    return result;
}

} // namespace pm::security
