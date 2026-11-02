#include "async_iterator.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#ifndef FEATURE_JQ
#define FEATURE_JQ 0
#endif

#if FEATURE_JQ
extern "C" {
#  include "jq.h"
#  include "jv.h"
}
#endif

namespace media::async_iterator {
namespace {

using clock = std::chrono::steady_clock;

#if FEATURE_JQ

void jq_err_cb(void* data, jv msg)
{
    auto* err = reinterpret_cast<std::string*>(data);
    if (jv_get_kind(msg) == JV_KIND_STRING)
        *err += jv_string_value(msg);
    jv_free(msg);
}

jv nlohmann_to_jv(const nlohmann::json& j)
{
    switch (j.type()) {
        case nlohmann::json::value_t::null:
            return jv_null();
        case nlohmann::json::value_t::boolean:
            return j.get<bool>() ? jv_true() : jv_false();
        case nlohmann::json::value_t::number_integer:
            return jv_number(static_cast<double>(j.get<std::int64_t>()));
        case nlohmann::json::value_t::number_unsigned:
            return jv_number(static_cast<double>(j.get<std::uint64_t>()));
        case nlohmann::json::value_t::number_float:
            return jv_number(j.get<double>());
        case nlohmann::json::value_t::string: {
            const std::string& s = j.get_ref<const std::string&>();
            return jv_string_sized(s.c_str(), static_cast<int>(s.size()));
        }
        case nlohmann::json::value_t::array: {
            jv arr = jv_array_sized(static_cast<int>(j.size()));
            for (const auto& item : j)
                arr = jv_array_append(arr, nlohmann_to_jv(item));
            return arr;
        }
        case nlohmann::json::value_t::object: {
            jv obj = jv_object();
            for (const auto& [key, val] : j.items()) {
                obj = jv_object_set(obj,
                                    jv_string_sized(key.c_str(), static_cast<int>(key.size())),
                                    nlohmann_to_jv(val));
            }
            return obj;
        }
        default:
            return jv_null();
    }
}

nlohmann::json jv_to_nlohmann(jv v)
{
    switch (jv_get_kind(v)) {
        case JV_KIND_NULL:
            jv_free(v);
            return nullptr;
        case JV_KIND_FALSE:
            jv_free(v);
            return false;
        case JV_KIND_TRUE:
            jv_free(v);
            return true;
        case JV_KIND_NUMBER: {
            const double d = jv_number_value(v);
            jv_free(v);
            return d;
        }
        case JV_KIND_STRING: {
            std::string s(jv_string_value(v));
            jv_free(v);
            return s;
        }
        case JV_KIND_ARRAY: {
            nlohmann::json arr = nlohmann::json::array();
            const int len = jv_array_length(jv_copy(v));
            for (int i = 0; i < len; ++i)
                arr.push_back(jv_to_nlohmann(jv_array_get(jv_copy(v), i)));
            jv_free(v);
            return arr;
        }
        case JV_KIND_OBJECT: {
            nlohmann::json obj = nlohmann::json::object();
            for (int i = jv_object_iter(v); jv_object_iter_valid(v, i); i = jv_object_iter_next(v, i)) {
                jv key = jv_object_iter_key(v, i);
                jv val = jv_object_iter_value(v, i);
                obj[jv_string_value(key)] = jv_to_nlohmann(val);
                jv_free(key);
            }
            jv_free(v);
            return obj;
        }
        default:
            jv_free(v);
            return nullptr;
    }
}

std::string normalize_path_filter(std::string expr)
{
    if (!expr.empty() && expr.front() == '$')
        expr.erase(expr.begin());

    std::string rewritten;
    rewritten.reserve(expr.size());
    for (std::size_t i = 0; i < expr.size(); ++i) {
        if (expr[i] == '[' && i + 2 < expr.size() && expr[i + 1] == '*' && expr[i + 2] == ']') {
            rewritten += "[]";
            i += 2;
        } else {
            rewritten.push_back(expr[i]);
        }
    }
    expr = std::move(rewritten);

    if (expr.empty())
        expr = ".";
    if (expr.front() != '.' && expr.front() != '[')
        expr.insert(expr.begin(), '.');
    return expr;
}

bool collect_paths(const nlohmann::json& input,
                   const std::string& filter,
                   nlohmann::json& path_arrays,
                   std::string& err)
{
    err.clear();
    const std::string expr = normalize_path_filter(filter);

    std::string program;
    if (expr.rfind("[path(", 0) == 0)
        program = expr;
    else if (expr.rfind("path(", 0) == 0)
        program = "[" + expr + "]";
    else
        program = "[path(" + expr + ")]";

    jq_state* jq = jq_init();
    if (!jq) {
        err = "jq_init failed";
        return false;
    }

    std::string compile_err;
    jq_set_error_cb(jq, jq_err_cb, &compile_err);
    if (!jq_compile(jq, program.c_str())) {
        err = compile_err.empty() ? ("jq compile error: " + program) : compile_err;
        jq_teardown(&jq);
        return false;
    }

    jq_set_error_cb(jq, jq_err_cb, &err);
    jv jv_input = nlohmann_to_jv(input);
    jq_start(jq, jv_input, 0);

    bool ok = false;
    for (;;) {
        jv jv_result = jq_next(jq);
        if (!jv_is_valid(jv_result)) {
            jv msg = jv_invalid_get_msg(jv_copy(jv_result));
            if (jv_get_kind(msg) == JV_KIND_STRING && err.empty()) {
                err = "jq: ";
                err += jv_string_value(msg);
            }
            jv_free(msg);
            jv_free(jv_result);
            break;
        }
        path_arrays = jv_to_nlohmann(jv_result);
        ok = true;
        break;
    }

    jq_teardown(&jq);

    if (!ok && err.empty())
        err = "jq returned no value for filter: " + program;
    if (!ok || !err.empty())
        return false;
    if (!path_arrays.is_array()) {
        err = "collect_paths expected a JSON array of path arrays";
        return false;
    }
    return true;
}

#endif // FEATURE_JQ

void trim_inplace(std::string& s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
}

std::string pointer_from_keys(const nlohmann::json& keys)
{
    if (!keys.is_array())
        return {};
    std::string out;
    out.reserve(keys.size() * 8);
    for (const auto& k : keys) {
        out.push_back('/');
        if (k.is_string()) {
            for (char ch : k.get_ref<const std::string&>()) {
                if (ch == '~')
                    out += "~0";
                else if (ch == '/')
                    out += "~1";
                else
                    out.push_back(ch);
            }
        } else if (k.is_number_integer() || k.is_number_unsigned()) {
            out += std::to_string(k.get<std::int64_t>());
        } else if (k.is_number_float()) {
            out += std::to_string(static_cast<std::int64_t>(k.get<double>()));
        }
    }
    return out.empty() ? "/" : out;
}

nlohmann::json* walk_mutable(nlohmann::json& root, const nlohmann::json& keys, bool create_missing)
{
    if (!keys.is_array())
        return nullptr;
    nlohmann::json* cur = &root;
    for (const auto& k : keys) {
        if (!cur)
            return nullptr;
        if (k.is_string()) {
            const std::string& key = k.get_ref<const std::string&>();
            if (!cur->is_object()) {
                if (!create_missing)
                    return nullptr;
                *cur = nlohmann::json::object();
            }
            auto it = cur->find(key);
            if (it == cur->end()) {
                if (!create_missing)
                    return nullptr;
                it = cur->emplace(key, nullptr).first;
            }
            cur = &(*it);
        } else if (k.is_number_integer() || k.is_number_unsigned() || k.is_number_float()) {
            const auto idx = static_cast<std::size_t>(
                k.is_number_float() ? k.get<double>() : k.get<std::int64_t>());
            if (!cur->is_array()) {
                if (!create_missing)
                    return nullptr;
                *cur = nlohmann::json::array();
            }
            if (idx >= cur->size()) {
                if (!create_missing)
                    return nullptr;
                while (cur->size() <= idx)
                    cur->push_back(nullptr);
            }
            cur = &(*cur)[idx];
        } else {
            return nullptr;
        }
    }
    return cur;
}

const nlohmann::json* walk_const(const nlohmann::json& root, const nlohmann::json& keys)
{
    return walk_mutable(const_cast<nlohmann::json&>(root), keys, false);
}

nlohmann::json* parent_at(nlohmann::json& root, const nlohmann::json& path_keys)
{
    nlohmann::json parent_keys = path_keys;
    if (!parent_keys.empty())
        parent_keys.erase(parent_keys.size() - 1);
    return walk_mutable(root, parent_keys, false);
}

bool default_filter_impl(const std::string& input, const std::string& /*path*/)
{
    return is_nonempty_string(input) && !is_number_string(input) && !is_boolean_string(input);
}

struct WorkItem {
    nlohmann::json path_keys;
    std::string pointer;
    std::string input;
    std::optional<std::string> target_key;
    bool merge_json = false;
    std::vector<std::string> merge_keys;
};

struct LeafResult {
    bool ok = false;
    bool skipped = false;
    bool cache_hit = false;
    bool merge_json = false;
    std::string out;
    nlohmann::json merge_obj;
    std::string err;
};

class Throttle {
public:
    explicit Throttle(int interval_ms) : interval_(std::max(0, interval_ms)) {}

    void wait_turn()
    {
        if (interval_ <= 0)
            return;
        std::unique_lock<std::mutex> lk(mu_);
        const auto now = clock::now();
        if (next_ok_ > now)
            cv_.wait_until(lk, next_ok_);
        next_ok_ = clock::now() + std::chrono::milliseconds(interval_);
    }

private:
    int interval_ = 0;
    std::mutex mu_;
    std::condition_variable cv_;
    clock::time_point next_ok_{};
};

// Coalesces identical inputs: followers wait on the leader's result.
class ResultCache {
public:
    explicit ResultCache(bool enabled) : enabled_(enabled) {}

    struct Slot {
        std::mutex mu;
        std::condition_variable cv;
        bool ready = false;
        bool ok = false;
        std::string value;
        std::string err;
    };

    struct Lease {
        std::shared_ptr<Slot> slot;
        bool leader = true;
    };

    Lease begin(const std::string& key)
    {
        if (!enabled_)
            return {std::make_shared<Slot>(), true};

        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(key);
        if (it != map_.end())
            return {it->second, false};

        auto slot = std::make_shared<Slot>();
        map_.emplace(key, slot);
        return {std::move(slot), true};
    }

    static void wait(const std::shared_ptr<Slot>& slot)
    {
        std::unique_lock<std::mutex> lk(slot->mu);
        slot->cv.wait(lk, [&] { return slot->ready; });
    }

    static void finish(const std::shared_ptr<Slot>& slot, bool ok, std::string value, std::string err = {})
    {
        {
            std::lock_guard<std::mutex> lk(slot->mu);
            slot->ok = ok;
            slot->value = std::move(value);
            slot->err = std::move(err);
            slot->ready = true;
        }
        slot->cv.notify_all();
    }

private:
    bool enabled_ = false;
    std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<Slot>> map_;
};

bool merge_json_keys_ok(const nlohmann::json& obj,
                        const std::vector<std::string>& keys,
                        std::string& err)
{
    if (keys.empty())
        return true;
    for (const auto& k : keys) {
        const auto it = obj.find(k);
        if (it == obj.end() || !it->is_string()) {
            err = "merge_json: missing string key '" + k + "'";
            return false;
        }
        if (!is_nonempty_string(it->get_ref<const std::string&>())) {
            err = "merge_json: empty string for key '" + k + "'";
            return false;
        }
    }
    return true;
}

LeafResult from_cache_slot(const ResultCache::Slot& slot, bool merge_json)
{
    LeafResult r;
    r.ok = slot.ok;
    r.out = slot.value;
    r.err = slot.err;
    r.cache_hit = true;
    r.merge_json = merge_json;
    if (r.ok && merge_json) {
        std::string perr;
        if (!parse_json_object_response(r.out, r.merge_obj, perr)) {
            r.ok = false;
            r.err = perr.empty() ? "cached merge_json payload invalid" : perr;
        }
    }
    return r;
}

LeafResult transform_one(const WorkItem& item,
                         const Options& options,
                         const Transformer& xf,
                         Throttle& throttle,
                         ResultCache& cache,
                         int max_retries)
{
    LeafResult r;
    if (options.filter_callback && !options.filter_callback(item.input, item.pointer)) {
        r.skipped = true;
        return r;
    }

    std::string value = item.input;
    if (options.on_transform) {
        try {
            value = options.on_transform(item.pointer, value);
        } catch (...) {
        }
    }

    auto lease = cache.begin(value);
    if (!lease.leader) {
        ResultCache::wait(lease.slot);
        return from_cache_slot(*lease.slot, item.merge_json);
    }

    std::string last_err;
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        if (attempt > 0 && options.network.retry_delay_ms > 0) {
            const int backoff = options.network.retry_delay_ms * (1 << std::min(attempt - 1, 4));
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }
        throttle.wait_turn();

        std::string err;
        try {
            std::string out = xf(value, item.pointer, err);
            if (!err.empty()) {
                last_err = std::move(err);
                continue;
            }
            if (options.on_transformed) {
                try {
                    out = options.on_transformed(item.pointer, out);
                } catch (...) {
                }
            }

            if (item.merge_json) {
                nlohmann::json obj;
                if (!parse_json_object_response(out, obj, err)) {
                    last_err = err.empty() ? "merge_json: response is not a JSON object" : err;
                    continue;
                }
                if (obj.empty()) {
                    last_err = "merge_json: empty JSON object";
                    continue;
                }
                if (!merge_json_keys_ok(obj, item.merge_keys, err)) {
                    last_err = err.empty() ? "merge_json: required keys missing" : err;
                    continue;
                }
                out = obj.dump();
                ResultCache::finish(lease.slot, true, out);
                r.ok = true;
                r.merge_json = true;
                r.merge_obj = std::move(obj);
                r.out = std::move(out);
                return r;
            }

            out = sanitize_leaf_output(std::move(out));
            ResultCache::finish(lease.slot, true, out);
            r.ok = true;
            r.out = std::move(out);
            return r;
        } catch (const std::exception& ex) {
            last_err = ex.what();
        } catch (...) {
            last_err = "unknown transform error";
        }
    }

    ResultCache::finish(lease.slot, false, {}, last_err);
    r.err = std::move(last_err);
    return r;
}

void report_error(const Options& options,
                  TransformStats& st,
                  const WorkItem& item,
                  const std::string& message)
{
    st.errors += 1;
    if (options.error_callback)
        options.error_callback(item.pointer, item.input, message);
}

bool apply_results(nlohmann::json& obj,
                   const std::vector<WorkItem>& items,
                   const std::vector<LeafResult>& results,
                   const Options& options,
                   TransformStats& st)
{
    const auto t0 = clock::now();
    for (std::size_t i = 0; i < items.size(); ++i) {
        const auto& item = items[i];
        const auto& r = results[i];
        st.matched += 1;

        if (r.skipped) {
            st.skipped += 1;
            continue;
        }
        if (r.cache_hit)
            st.cache_hits += 1;
        if (!r.ok) {
            report_error(options, st, item, r.err);
            continue;
        }

        if (item.merge_json) {
            nlohmann::json* parent = parent_at(obj, item.path_keys);
            if (!parent || !parent->is_object()) {
                report_error(options, st, item, "merge_json parent is not an object");
                continue;
            }
            if (!r.merge_obj.is_object()) {
                report_error(options, st, item, "merge_json payload missing");
                continue;
            }
            for (auto it = r.merge_obj.begin(); it != r.merge_obj.end(); ++it)
                (*parent)[it.key()] = it.value();
            st.transformed += 1;
            continue;
        }

        if (item.target_key) {
            nlohmann::json* parent = parent_at(obj, item.path_keys);
            if (!parent || !parent->is_object()) {
                report_error(options, st, item, "target_path parent is not an object");
                continue;
            }
            (*parent)[*item.target_key] = r.out;
        } else {
            nlohmann::json* leaf = walk_mutable(obj, item.path_keys, false);
            if (!leaf) {
                report_error(options, st, item, "path vanished");
                continue;
            }
            *leaf = r.out;
        }
        st.transformed += 1;
    }
    st.apply_ms = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count();
    return true;
}

bool run_work_items(nlohmann::json& obj,
                    std::vector<WorkItem> items,
                    const Options& options,
                    const Transformer& xf,
                    TransformStats* stats,
                    std::string* /*err*/)
{
    TransformStats local;
    TransformStats& st = stats ? *stats : local;

    if (items.empty())
        return true;

    const int concurrency = std::max(1, options.network.concurrent_tasks);
    const int max_retries = std::max(1, options.network.max_retries);
    const int abort_after = std::max(0, options.network.abort_after_consecutive_errors);
    Throttle throttle(options.network.throttle_delay_ms);
    ResultCache cache(options.cache_identical_inputs);
    std::vector<LeafResult> results(items.size());
    std::vector<uint8_t> processed(items.size(), 0);

    const auto t0 = clock::now();
    const int total = static_cast<int>(items.size());
    std::atomic<int> started{0};
    auto mark_start = [&](std::size_t i) {
        processed[i] = 1;
        if (!options.progress_callback)
            return;
        const int n = started.fetch_add(1, std::memory_order_relaxed) + 1;
        options.progress_callback(n, total, items[i].pointer);
    };
    if (concurrency <= 1 || items.size() <= 1) {
        int consecutive = 0;
        for (std::size_t i = 0; i < items.size(); ++i) {
            mark_start(i);
            results[i] = transform_one(items[i], options, xf, throttle, cache, max_retries);
            if (results[i].ok) {
                consecutive = 0;
            } else {
                ++consecutive;
                if (abort_after > 0 && consecutive >= abort_after) {
                    st.aborted = true;
                    st.aborted_after_errors = consecutive;
                    for (std::size_t j = i + 1; j < items.size(); ++j)
                        results[j].skipped = true;
                    break;
                }
            }
        }
    } else {
        const auto workers_n = static_cast<int>(
            std::min<std::size_t>(static_cast<std::size_t>(concurrency), items.size()));
        std::atomic<std::size_t> next{0};
        std::atomic<int> consecutive{0};
        std::atomic<bool> abort_flag{false};
        std::vector<std::thread> workers;
        workers.reserve(static_cast<std::size_t>(workers_n));
        for (int w = 0; w < workers_n; ++w) {
            workers.emplace_back([&] {
                for (;;) {
                    if (abort_flag.load(std::memory_order_relaxed))
                        break;
                    const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
                    if (i >= items.size())
                        break;
                    mark_start(i);
                    results[i] = transform_one(items[i], options, xf, throttle, cache, max_retries);
                    if (results[i].ok) {
                        consecutive.store(0, std::memory_order_relaxed);
                    } else {
                        const int e = consecutive.fetch_add(1, std::memory_order_relaxed) + 1;
                        if (abort_after > 0 && e >= abort_after)
                            abort_flag.store(true, std::memory_order_relaxed);
                    }
                }
            });
        }
        for (auto& th : workers)
            th.join();
        if (abort_flag.load()) {
            st.aborted = true;
            st.aborted_after_errors = consecutive.load();
            for (std::size_t j = 0; j < items.size(); ++j)
                if (!processed[j])
                    results[j].skipped = true;
        }
    }
    st.transform_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count();

    apply_results(obj, items, results, options, st);
    return true;
}

bool collect_work(nlohmann::json& obj,
                  const FieldMapping& mapping,
                  const Options& options,
                  Transformer& xf_inout,
                  std::vector<WorkItem>& out,
                  std::string* err)
{
#if !FEATURE_JQ
    if (err)
        *err = "async_iterator requires FEATURE_JQ (vendored libjq)";
    return false;
#else
    nlohmann::json paths;
    std::string local_err;
    if (!collect_paths(obj, mapping.path, paths, local_err)) {
        if (err)
            *err = local_err;
        return false;
    }

    if (options.transformer_factory) {
        Transformer built = options.transformer_factory(mapping.options);
        if (built)
            xf_inout = std::move(built);
    }
    if (!xf_inout) {
        if (err)
            *err = "async_iterator: no transformer configured";
        return false;
    }

    out.reserve(out.size() + paths.size());
    for (std::size_t i = 0; i < paths.size(); ++i) {
        nlohmann::json keys = std::move(paths[i]);
        if (!keys.is_array() || keys.empty())
            continue;
        const nlohmann::json* leaf = walk_const(obj, keys);
        if (!leaf || !leaf->is_string())
            continue;

        WorkItem w;
        w.path_keys = std::move(keys);
        w.pointer = pointer_from_keys(w.path_keys);
        w.input = leaf->get_ref<const std::string&>();
        w.merge_json = mapping.merge_json;
        w.merge_keys = mapping.merge_keys;
        if (!mapping.merge_json)
            w.target_key = mapping.target_path;
        out.push_back(std::move(w));
    }
    return true;
#endif
}

} // namespace

bool is_number_string(std::string_view s) noexcept
{
    if (s.empty())
        return false;
    std::size_t i = 0;
    if (s[0] == '-' || s[0] == '+')
        ++i;
    if (i >= s.size())
        return false;
    bool saw_digit = false;
    bool saw_dot = false;
    for (; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (std::isdigit(c)) {
            saw_digit = true;
            continue;
        }
        if (c == '.' && !saw_dot) {
            saw_dot = true;
            continue;
        }
        return false;
    }
    return saw_digit;
}

bool is_boolean_string(std::string_view s) noexcept
{
    if (s.size() == 4) {
        return (s[0] == 't' || s[0] == 'T') && (s[1] == 'r' || s[1] == 'R') &&
               (s[2] == 'u' || s[2] == 'U') && (s[3] == 'e' || s[3] == 'E');
    }
    if (s.size() == 5) {
        return (s[0] == 'f' || s[0] == 'F') && (s[1] == 'a' || s[1] == 'A') &&
               (s[2] == 'l' || s[2] == 'L') && (s[3] == 's' || s[3] == 'S') &&
               (s[4] == 'e' || s[4] == 'E');
    }
    return false;
}

bool is_nonempty_string(std::string_view s) noexcept
{
    for (char ch : s) {
        if (!std::isspace(static_cast<unsigned char>(ch)))
            return true;
    }
    return false;
}

FilterCallback default_string_filter()
{
    return default_filter_impl;
}

Options default_options(Options overrides)
{
    Options o = std::move(overrides);
    if (!o.filter_callback)
        o.filter_callback = default_string_filter();
    if (!o.transform)
        o.transform = uppercase_transformer();
    if (o.network.concurrent_tasks < 1)
        o.network.concurrent_tasks = 1;
    if (o.network.max_retries < 1)
        o.network.max_retries = 1;
    return o;
}

Transformer uppercase_transformer()
{
    return [](const std::string& input, const std::string&, std::string& err) {
        err.clear();
        std::string out = input;
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        return out;
    };
}

Transformer prefix_transformer(std::string prefix)
{
    return [p = std::move(prefix)](const std::string& input, const std::string&, std::string& err) {
        err.clear();
        std::string out;
        out.reserve(p.size() + input.size() + 3);
        out += '[';
        out += p;
        out += "] ";
        out += input;
        return out;
    };
}

Transformer make_prompt_transformer(std::string prompt_template, Transformer llm)
{
    return [prompt = std::move(prompt_template),
            llm = std::move(llm)](const std::string& input, const std::string& path, std::string& err) {
        if (!llm) {
            err = "llm transformer not configured";
            return std::string{};
        }
        std::string shaped;
        shaped.reserve(prompt.size() + input.size() + 32);
        shaped += prompt;
        shaped += "\n\nText to transform: \"";
        shaped += input;
        shaped += '"';
        return llm(shaped, path, err);
    };
}

std::string sanitize_leaf_output(std::string value)
{
    trim_inplace(value);
    if (value.size() >= 2) {
        const char a = value.front();
        const char b = value.back();
        if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
            value = value.substr(1, value.size() - 2);
            trim_inplace(value);
        }
    }
    return value;
}

namespace {

std::string snippet_for_err(std::string_view s, std::size_t max_n = 160)
{
    std::string out;
    out.reserve(std::min(s.size(), max_n + 3));
    for (unsigned char c : s) {
        if (out.size() >= max_n) {
            out += "...";
            break;
        }
        if (c == '\n' || c == '\r' || c == '\t')
            out.push_back(' ');
        else if (c < 0x20)
            continue;
        else
            out.push_back(static_cast<char>(c));
    }
    return out;
}

// First balanced {...} so models that wrap JSON in prose still parse.
bool extract_json_object_span(std::string_view s, std::string& obj, std::string& err)
{
    const auto start = s.find('{');
    if (start == std::string_view::npos) {
        err = "merge_json: no JSON object in response; got: " + snippet_for_err(s);
        return false;
    }
    int depth = 0;
    bool in_str = false;
    bool escape = false;
    for (std::size_t i = start; i < s.size(); ++i) {
        const char c = s[i];
        if (in_str) {
            if (escape)
                escape = false;
            else if (c == '\\')
                escape = true;
            else if (c == '"')
                in_str = false;
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == '{')
            depth += 1;
        else if (c == '}') {
            depth -= 1;
            if (depth == 0) {
                obj.assign(s.substr(start, i - start + 1));
                return true;
            }
        }
    }
    err = "merge_json: unterminated JSON object; got: " + snippet_for_err(s);
    return false;
}

} // namespace

bool parse_json_object_response(std::string_view raw, nlohmann::json& out, std::string& err)
{
    err.clear();
    std::string s(raw);
    trim_inplace(s);

    if (s.size() >= 3 && s.compare(0, 3, "```") == 0) {
        const auto nl = s.find('\n');
        s.erase(0, nl != std::string::npos ? nl + 1 : 3);
        trim_inplace(s);
        if (s.size() >= 3 && s.compare(s.size() - 3, 3, "```") == 0) {
            s.erase(s.size() - 3);
            trim_inplace(s);
        }
    }

    if (s.empty()) {
        err = "merge_json: empty response";
        return false;
    }

    std::string span;
    if (!extract_json_object_span(s, span, err))
        return false;

    nlohmann::json parsed = nlohmann::json::parse(span, nullptr, false);
    if (parsed.is_discarded()) {
        err = "merge_json: response is not valid JSON; got: " + snippet_for_err(s);
        return false;
    }
    if (!parsed.is_object()) {
        err = "merge_json: response JSON must be an object; got: " + snippet_for_err(span);
        return false;
    }
    out = std::move(parsed);
    return true;
}

bool transform_object(nlohmann::json& obj,
                      const std::string& path,
                      const Options& options,
                      TransformStats* stats,
                      std::string* err)
{
    FieldMapping m;
    m.path = path;
    return transform_mappings(obj, {m}, options, stats, err);
}

bool transform_mappings(nlohmann::json& obj,
                        const std::vector<FieldMapping>& mappings,
                        const Options& options,
                        TransformStats* stats,
                        std::string* err)
{
    Options opts = default_options(options);
    Transformer xf = opts.transform;
    std::vector<WorkItem> items;

    const auto t0 = clock::now();
    for (const auto& m : mappings) {
        if (!collect_work(obj, m, opts, xf, items, err))
            return false;
    }
    if (stats) {
        stats->collect_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - t0).count();
    }
    return run_work_items(obj, std::move(items), opts, xf, stats, err);
}

Iterator::Iterator(nlohmann::json& obj, Options options)
    : obj_(obj)
    , options_(default_options(std::move(options)))
{
}

bool Iterator::transform(const std::vector<FieldMapping>& mappings,
                         TransformStats* stats,
                         std::string* err)
{
    return transform_mappings(obj_, mappings, options_, stats, err);
}

Iterator create_iterator(nlohmann::json& obj, Options options)
{
    return Iterator(obj, std::move(options));
}

bool collect_string_leaves(const nlohmann::json& obj,
                           const std::string& jq_filter,
                           std::vector<StringLeaf>& out,
                           std::string* err)
{
#if !FEATURE_JQ
    if (err)
        *err = "collect_string_leaves requires FEATURE_JQ";
    return false;
#else
    out.clear();
    nlohmann::json paths;
    std::string local_err;
    if (!collect_paths(obj, jq_filter, paths, local_err)) {
        if (err)
            *err = local_err;
        return false;
    }
    out.reserve(paths.size());
    for (std::size_t i = 0; i < paths.size(); ++i) {
        nlohmann::json keys = std::move(paths[i]);
        if (!keys.is_array() || keys.empty())
            continue;
        const nlohmann::json* leaf = walk_const(obj, keys);
        if (!leaf || !leaf->is_string())
            continue;
        StringLeaf sl;
        sl.path_keys = std::move(keys);
        sl.pointer = pointer_from_keys(sl.path_keys);
        sl.value = leaf->get_ref<const std::string&>();
        out.push_back(std::move(sl));
    }
    return true;
#endif
}

bool collect_nodes(const nlohmann::json& obj,
                   const std::string& jq_filter,
                   std::vector<JsonNode>& out,
                   std::string* err)
{
#if !FEATURE_JQ
    if (err)
        *err = "collect_nodes requires FEATURE_JQ";
    return false;
#else
    out.clear();
    nlohmann::json paths;
    std::string local_err;
    if (!collect_paths(obj, jq_filter, paths, local_err)) {
        if (err)
            *err = local_err;
        return false;
    }
    out.reserve(paths.size());
    for (std::size_t i = 0; i < paths.size(); ++i) {
        nlohmann::json keys = std::move(paths[i]);
        if (!keys.is_array())
            continue;
        const nlohmann::json* node = walk_const(obj, keys);
        if (!node)
            continue;
        JsonNode sl;
        sl.path_keys = std::move(keys);
        sl.pointer = pointer_from_keys(sl.path_keys);
        sl.value = *node;
        out.push_back(std::move(sl));
    }
    return true;
#endif
}

bool assign_node_key(nlohmann::json& root,
                     const nlohmann::json& path_keys,
                     const std::string& key,
                     const nlohmann::json& value,
                     std::string* err)
{
#if !FEATURE_JQ
    if (err)
        *err = "assign_node_key requires FEATURE_JQ";
    return false;
#else
    if (key.empty()) {
        if (err)
            *err = "assign_node_key: empty key";
        return false;
    }
    nlohmann::json* node = walk_mutable(root, path_keys, false);
    if (!node || !node->is_object()) {
        if (err)
            *err = "assign_node_key: selected node is not an object";
        return false;
    }
    (*node)[key] = value;
    return true;
#endif
}

bool assign_parent_key(nlohmann::json& root,
                       const nlohmann::json& path_keys,
                       const std::string& key,
                       const nlohmann::json& value,
                       std::string* err)
{
#if !FEATURE_JQ
    if (err)
        *err = "assign_parent_key requires FEATURE_JQ";
    return false;
#else
    if (key.empty()) {
        if (err)
            *err = "assign_parent_key: empty key";
        return false;
    }
    nlohmann::json* parent = parent_at(root, path_keys);
    if (!parent || !parent->is_object()) {
        if (err)
            *err = "assign_parent_key: parent is not an object";
        return false;
    }
    (*parent)[key] = value;
    return true;
#endif
}

} // namespace media::async_iterator
