#include "string/string_utils.hpp"

#include "fs/path_sanitizer.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <mutex>
#include <unordered_set>

namespace media::strutil {

namespace {

std::string normalize_selection_path(const std::string& path)
{
    std::string normalized = media::path::normalize_local_path(path, true);
    return normalized.empty() ? path : normalized;
}

std::wstring normalize_selection_path(const std::wstring& path)
{
#if defined(_WIN32)
    std::wstring normalized = media::path::normalize_local_path_w(path, true);
    return normalized.empty() ? path : normalized;
#else
    const auto u8 = std::filesystem::path(path).u8string();
    const std::string utf8(reinterpret_cast<const char*>(u8.data()), u8.size());
    const std::string normalized = media::path::normalize_local_path(utf8, true);
    if (normalized.empty())
        return path;
    return std::filesystem::u8path(normalized).wstring();
#endif
}

template<typename Char>
std::vector<std::basic_string<Char>> normalize_command_args_impl(
    const std::vector<std::basic_string<Char>>& raw,
    const std::vector<std::basic_string<Char>>& selection,
    const Char* selection_token)
{
    using Str = std::basic_string<Char>;
    const Str token(selection_token);
    std::vector<Str> out;
    out.reserve(raw.size() + selection.size());
    for (const Str& arg : raw) {
        if (arg != token) {
            out.push_back(arg);
            continue;
        }
        if (selection.empty()) {
            out.push_back(arg);
            continue;
        }
        for (const Str& path : selection) {
            if (!path.empty())
                out.push_back(normalize_selection_path(path));
        }
    }
    return out;
}

} // namespace

std::vector<std::string> normalize_command_args(
    const std::vector<std::string>& args,
    const std::vector<std::string>& selection_paths)
{
    return normalize_command_args_impl<char>(args, selection_paths, "${CURRENT_SELECTION}");
}

std::vector<std::wstring> normalize_command_args(
    const std::vector<std::wstring>& args,
    const std::vector<std::wstring>& selection_paths)
{
    return normalize_command_args_impl<wchar_t>(args, selection_paths, L"${CURRENT_SELECTION}");
}

std::string lower_ascii(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string trim(std::string s)
{
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> tokenize(const std::string& text)
{
    std::vector<std::string> out;
    std::string cur;
    for (unsigned char c : lower_ascii(text)) {
        const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z');
        if (alnum || c == '-' || c == '_') {
            cur.push_back(static_cast<char>(c));
        } else if (!cur.empty()) {
            out.push_back(std::move(cur));
            cur.clear();
        }
    }
    if (!cur.empty())
        out.push_back(std::move(cur));
    return out;
}

std::string stem(std::string t)
{
    auto ends_with = [&](const char* suf) {
        const std::string s = suf;
        return t.size() > s.size() + 2 && t.compare(t.size() - s.size(), s.size(), s) == 0;
    };
    if (ends_with("ings")) t.erase(t.size() - 4);
    else if (ends_with("ing")) t.erase(t.size() - 3);
    else if (ends_with("ed")) t.erase(t.size() - 2);
    else if (ends_with("es")) t.erase(t.size() - 2);
    else if (t.size() > 3 && t.back() == 's' && t[t.size() - 2] != 's') t.pop_back();
    return t;
}

double fuzz_ratio(const std::string& a, const std::string& b)
{
    if (a == b) return 1.0;
    if (a.empty() || b.empty()) return 0.0;
    constexpr std::size_t kMaxLen = 64;
    if (a.size() > kMaxLen || b.size() > kMaxLen)
        return 0.0;
    const std::size_t m = a.size(), n = b.size();
    const std::size_t longest = std::max(m, n);
    const std::size_t gap = longest - std::min(m, n);
    if (gap * 100 > longest * 18)
        return 0.0;
    std::vector<std::size_t> prev(n + 1), cur(n + 1);
    for (std::size_t j = 0; j <= n; ++j) prev[j] = j;
    for (std::size_t i = 1; i <= m; ++i) {
        cur[0] = i;
        for (std::size_t j = 1; j <= n; ++j) {
            const std::size_t cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
        }
        std::swap(prev, cur);
    }
    const double dist = static_cast<double>(prev[n]);
    const double maxlen = static_cast<double>(std::max(m, n));
    return 1.0 - dist / maxlen;
}

std::vector<std::string> glossary_expand(const std::string& token)
{
    static const std::vector<std::vector<std::string>> groups = {
        {"camera", "webcam"},
        {"mic", "microphone"},
        {"photo", "snapshot", "still"},
        {"md", "markdown"},
    };
    for (const auto& grp : groups) {
        if (std::find(grp.begin(), grp.end(), token) != grp.end())
            return grp;
    }
    return {token};
}

bool is_stop_word(const std::string& t)
{
    static const std::unordered_set<std::string> stop = {
        "the", "a", "an", "to", "for", "of", "and", "or", "with", "in", "on",
        "cli", "command", "commands", "pm", "image", "pmimage", "tool", "exe",
        "please", "how", "do", "i", "use", "run",
    };
    return stop.count(t) != 0;
}

bool token_matches(const std::vector<std::string>& hay_tokens,
                   const std::string& full_hay,
                   const std::string& qtok)
{
    (void)full_hay;
    for (const auto& variant : glossary_expand(qtok)) {
        for (const auto& h : hay_tokens) {
            if (h == variant)
                return true;
        }
        const std::string vs = stem(variant);
        for (const auto& h : hay_tokens) {
            const std::string hs = stem(h);
            if (hs == vs)
                return true;
            if (vs.size() >= 4 && fuzz_ratio(vs, hs) >= 0.82)
                return true;
        }
    }
    return false;
}

double match_score(const std::string& haystack, const std::string& query)
{
    const auto raw_tokens = tokenize(query);
    if (raw_tokens.empty())
        return 0.0;
    const std::string hay = lower_ascii(haystack);
    const auto hay_tokens = tokenize(hay);

    std::vector<std::string> tokens;
    std::unordered_set<std::string> seen;
    for (const auto& t : raw_tokens) {
        if (is_stop_word(t) || !seen.insert(t).second)
            continue;
        tokens.push_back(t);
    }
    if (tokens.empty()) {
        seen.clear();
        for (const auto& t : raw_tokens) {
            if (!seen.insert(t).second)
                continue;
            tokens.push_back(t);
        }
    }

    int matched = 0;
    for (const auto& token : tokens)
        if (token_matches(hay_tokens, hay, token))
            ++matched;
    return static_cast<double>(matched) / static_cast<double>(tokens.size());
}

bool matches_query(const std::string& haystack, const std::string& query)
{
    return match_score(haystack, query) >= 0.5;
}

namespace {

bool is_variable_name_char(char c) noexcept
{
    return (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9')
        || c == '_' || c == ':';
}

template<typename Char>
std::string first_variable_token_impl(std::basic_string_view<Char> input)
{
    for (std::size_t pos = 0; pos + 3 < input.size(); ++pos) {
        if (input[pos] != static_cast<Char>('$') || input[pos + 1] != static_cast<Char>('{'))
            continue;
        std::size_t i = pos + 2;
        if (i >= input.size())
            break;
        const auto first = static_cast<unsigned>(input[i]);
        if (first > 127 || !is_variable_name_char(static_cast<char>(first)))
            continue;
        ++i;
        while (i < input.size()) {
            const auto cu = static_cast<unsigned>(input[i]);
            if (cu > 127 || !is_variable_name_char(static_cast<char>(cu)))
                break;
            ++i;
        }
        if (i >= input.size() || input[i] != static_cast<Char>('}'))
            continue;
        std::string token;
        token.reserve(i - pos + 1);
        for (std::size_t k = pos; k <= i; ++k)
            token.push_back(static_cast<char>(input[k]));
        return token;
    }
    return {};
}

template<typename View, typename Arg>
std::string unresolved_launch_token_impl(
    View executable,
    const std::vector<Arg>& args,
    View shell,
    View cwd,
    View open_path,
    View open_url)
{
    if (auto token = first_variable_token_impl<typename View::value_type>(executable); !token.empty())
        return token;
    for (const auto& arg : args) {
        if (auto token = first_variable_token_impl<typename View::value_type>(arg); !token.empty())
            return token;
    }
    if (auto token = first_variable_token_impl<typename View::value_type>(shell); !token.empty())
        return token;
    if (auto token = first_variable_token_impl<typename View::value_type>(cwd); !token.empty())
        return token;
    if (auto token = first_variable_token_impl<typename View::value_type>(open_path); !token.empty())
        return token;
    return first_variable_token_impl<typename View::value_type>(open_url);
}

} // namespace

std::string first_variable_token(std::string_view input)
{
    return first_variable_token_impl<char>(input);
}

std::string first_variable_token(std::wstring_view input)
{
    return first_variable_token_impl<wchar_t>(input);
}

std::string unresolved_launch_token(
    std::string_view executable,
    const std::vector<std::string>& args,
    std::string_view shell,
    std::string_view cwd,
    std::string_view open_path,
    std::string_view open_url)
{
    return unresolved_launch_token_impl(executable, args, shell, cwd, open_path, open_url);
}

std::string unresolved_launch_token(
    std::wstring_view executable,
    const std::vector<std::wstring>& args,
    std::wstring_view shell,
    std::wstring_view cwd,
    std::wstring_view open_path,
    std::wstring_view open_url)
{
    return unresolved_launch_token_impl(executable, args, shell, cwd, open_path, open_url);
}

bool has_variable_tokens(const std::string& input)
{
    return !first_variable_token(std::string_view(input)).empty();
}

std::optional<std::string> whole_variable_token(const std::string& input)
{
    const std::string token = first_variable_token(std::string_view(input));
    if (token.empty() || token.size() != input.size() || token.size() < 4)
        return std::nullopt;
    return trim(token.substr(2, token.size() - 3));
}

std::string substitute_variables(const std::string& input,
                                 const VariableResolver& resolve,
                                 bool* changed_out)
{
    if (changed_out)
        *changed_out = false;
    if (input.empty() || !resolve)
        return input;

    if (const auto whole = whole_variable_token(input)) {
        if (auto value = resolve(*whole)) {
            if (changed_out)
                *changed_out = true;
            return *value;
        }
        return input;
    }

    std::string result;
    result.reserve(input.size());
    bool changed = false;

    // Do not use `.*` here: ECMAScript std::regex does not let `.` cross
    // newlines, so a multiline prompt containing ${...} was returned entirely
    // untouched. Scan tokens directly so command strings and prompt templates
    // share the same substitution behavior.
    std::size_t pos = 0;
    while (pos < input.size()) {
        const std::size_t open = input.find("${", pos);
        if (open == std::string::npos) {
            result.append(input, pos, std::string::npos);
            break;
        }
        result.append(input, pos, open - pos);

        const std::size_t close = input.find('}', open + 2);
        if (close == std::string::npos) {
            result.append(input, open, std::string::npos);
            break;
        }

        const std::string name = input.substr(open + 2, close - (open + 2));
        const bool valid_name = !name.empty()
            && std::all_of(name.begin(), name.end(), [](unsigned char ch) {
                return (ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '_' || ch == ':';
            });
        if (!valid_name) {
            result.append(input, open, close - open + 1);
        } else if (auto value = resolve(name)) {
            result += *value;
            changed = true;
        } else {
            result += "${" + name + "}";
        }
        pos = close + 1;
    }

    if (changed_out)
        *changed_out = changed;
    return result;
}

#if (defined(FEATURE_LLAMA) && FEATURE_LLAMA) \
    || (defined(FEATURE_COMMAND_LLAMA_INFERENCE) && FEATURE_COMMAND_LLAMA_INFERENCE)

namespace {
std::mutex       g_embed_mutex;
EmbedMatchFn     g_embed_fn;
} // namespace

void set_embed_backend(EmbedMatchFn fn)
{
    std::lock_guard<std::mutex> lk(g_embed_mutex);
    g_embed_fn = std::move(fn);
}

bool has_embed_backend()
{
    std::lock_guard<std::mutex> lk(g_embed_mutex);
    return static_cast<bool>(g_embed_fn);
}

float embed_match_score(const std::string& query, const std::string& haystack)
{
    EmbedMatchFn fn;
    {
        std::lock_guard<std::mutex> lk(g_embed_mutex);
        fn = g_embed_fn;
    }
    return fn ? fn(query, haystack) : -1.f;
}

#endif // FEATURE_LLAMA || FEATURE_COMMAND_LLAMA_INFERENCE

} // namespace media::strutil
