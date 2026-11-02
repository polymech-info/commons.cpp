#pragma once

/// Universal JSON field iterator / transformer (C++ port of @polymech/commons
/// + kbot async-iterator). Path selection uses vendored jq (`path(...)`), not
/// jsonpath-plus. An LLM agent (or any callable) is just a Transformer option.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace media::async_iterator {

/// Transform one string leaf. `path` is a JSON Pointer-ish location
/// (e.g. "/items/0/name"). On failure set `err` and return {}.
using Transformer = std::function<std::string(const std::string& input,
                                              const std::string& path,
                                              std::string& err)>;

using ErrorCallback = std::function<void(const std::string& path,
                                         const std::string& value,
                                         const std::string& error)>;

/// Return true to transform `input` at `path`.
using FilterCallback = std::function<bool(const std::string& input,
                                          const std::string& path)>;

using OnTransformCallback = std::function<std::string(const std::string& path,
                                                      const std::string& value)>;
using OnTransformedCallback = std::function<std::string(const std::string& path,
                                                        const std::string& value)>;
/// Fired just before each leaf transform (done is 1-based).
using ProgressCallback = std::function<void(int done, int total, const std::string& path)>;

/// Build a Transformer from per-mapping options (prompt, model, …). LLM agent
/// wiring plugs in here; the core stays transformer-agnostic.
using TransformerFactory = std::function<Transformer(const nlohmann::json& options)>;

struct NetworkOptions {
    int throttle_delay_ms = 0;   ///< min spacing between transform starts
    int concurrent_tasks  = 1;   ///< max in-flight transforms (>=1)
    int max_retries       = 1;   ///< attempts per leaf (>=1)
    int retry_delay_ms    = 0;   ///< base backoff between retries
    /// Abort the run after N consecutive leaf failures (0 = off). A leaf that
    /// exhausts its retries counts as one failure; a success resets the streak.
    /// Unprocessed leaves are marked skipped (not errors) when the run aborts.
    int abort_after_consecutive_errors = 0;
};

struct FieldMapping {
    std::string path;                          ///< jq filter, e.g. `.items[].name`
    std::optional<std::string> target_path;    ///< nullopt = in-place; else sibling key
    /// When true, transformer output must be a JSON object. Keys overwrite
    /// matching siblings on the leaf's parent (no deep-merge). `target_path`
    /// is ignored in this mode.
    bool merge_json = false;
    /// With merge_json: these keys must be present as non-empty strings or the
    /// leaf is retried (not merged). Empty = any non-empty object is accepted.
    std::vector<std::string> merge_keys;
    nlohmann::json options = nlohmann::json::object(); ///< opaque; passed to factory
};

struct TransformStats {
    int matched     = 0;
    int transformed = 0;
    int skipped     = 0;
    int errors      = 0;
    int cache_hits  = 0;     ///< identical-input cache hits (when enabled)
    std::int64_t collect_ms = 0;
    std::int64_t transform_ms = 0;
    std::int64_t apply_ms = 0;
    /// True when the run was aborted early by abort_after_consecutive_errors.
    bool aborted = false;
    /// Consecutive-failure count at the moment of abort (0 if not aborted).
    int aborted_after_errors = 0;
};

struct Options {
    NetworkOptions network;
    ErrorCallback error_callback;
    FilterCallback filter_callback;
    OnTransformCallback on_transform;
    OnTransformedCallback on_transformed;
    TransformerFactory transformer_factory;
    Transformer transform; ///< used when factory is empty / mapping has no options
    ProgressCallback progress_callback;
    /// Cache transform results keyed by input string (shared across leaves).
    /// Useful for repeated labels in commands.json-style docs.
    bool cache_identical_inputs = true;
};

/// Defaults: skip numbers/bools/empty strings; uppercase transform when unset.
Options default_options(Options overrides = {});

bool is_number_string(std::string_view s) noexcept;
bool is_boolean_string(std::string_view s) noexcept;
bool is_nonempty_string(std::string_view s) noexcept;

FilterCallback default_string_filter();

/// Uppercase transformer (deterministic probe / fixture).
Transformer uppercase_transformer();

/// Prefix transformer: `"[" + prefix + "] " + input`.
Transformer prefix_transformer(std::string prefix);

/// Build a prompt-shaped transformer: calls `llm` with
/// `prompt_template + "\n\nText to transform: \"…\""`.
Transformer make_prompt_transformer(std::string prompt_template, Transformer llm);

/// Trim whitespace and a single pair of wrapping quotes from LLM leaf output.
std::string sanitize_leaf_output(std::string value);

/// Parse transformer text as a JSON object. Accepts optional ``` / ```json fences
/// and pulls the first balanced `{...}` out of wrapping prose.
bool parse_json_object_response(std::string_view raw,
                                nlohmann::json& out,
                                std::string& err);

/// Resolve jq `path` matches on `obj` and apply `transform` (or per-mapping
/// factory). Mutates `obj` in place. Returns false only on hard setup errors
/// (bad jq, missing transformer); per-leaf failures go through error_callback.
bool transform_object(nlohmann::json& obj,
                      const std::string& path,
                      const Options& options,
                      TransformStats* stats = nullptr,
                      std::string* err = nullptr);

bool transform_mappings(nlohmann::json& obj,
                        const std::vector<FieldMapping>& mappings,
                        const Options& options,
                        TransformStats* stats = nullptr,
                        std::string* err = nullptr);

/// Iterator handle mirroring kbot `createIterator`.
class Iterator {
public:
    Iterator(nlohmann::json& obj, Options options);

    bool transform(const std::vector<FieldMapping>& mappings,
                   TransformStats* stats = nullptr,
                   std::string* err = nullptr);

    nlohmann::json& data() noexcept { return obj_; }
    const nlohmann::json& data() const noexcept { return obj_; }

private:
    nlohmann::json& obj_;
    Options options_;
};

Iterator create_iterator(nlohmann::json& obj, Options options = {});

/// One string leaf matched by a jq filter (e.g. `.items[].text`).
struct StringLeaf {
    std::string pointer;   ///< JSON Pointer, e.g. "/items/0/text"
    nlohmann::json path_keys; ///< jq path key array
    std::string value;
};

/// Collect string leaves at `jq_filter` without transforming. Requires FEATURE_JQ.
bool collect_string_leaves(const nlohmann::json& obj,
                           const std::string& jq_filter,
                           std::vector<StringLeaf>& out,
                           std::string* err = nullptr);

/// Any JSON value matched by a jq filter (object, array, or scalar).
struct JsonNode {
    std::string pointer;
    nlohmann::json path_keys;
    nlohmann::json value;
};

/// Collect every value at `jq_filter`. Requires FEATURE_JQ.
bool collect_nodes(const nlohmann::json& obj,
                   const std::string& jq_filter,
                   std::vector<JsonNode>& out,
                   std::string* err = nullptr);

/// Set `key` on the object at `path_keys` (the matched node itself).
bool assign_node_key(nlohmann::json& root,
                     const nlohmann::json& path_keys,
                     const std::string& key,
                     const nlohmann::json& value,
                     std::string* err = nullptr);

/// Set `key` on the parent object of the node at `path_keys`.
bool assign_parent_key(nlohmann::json& root,
                       const nlohmann::json& path_keys,
                       const std::string& key,
                       const nlohmann::json& value,
                       std::string* err = nullptr);

} // namespace media::async_iterator
