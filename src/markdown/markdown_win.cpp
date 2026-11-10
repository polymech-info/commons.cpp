#if !defined(_WIN32)
#error markdown_win.cpp loads anydoc.dll and is Windows-only. Android uses its own loader.
#endif

#include "markdown/markdown.hpp"

#include "anydoc.h"

#include <fstream>
#include <utility>
#include <vector>
#include "fs/path_sanitizer.hpp"

namespace media::markdown {
namespace {

struct DllString {
    char* p = nullptr;
    DllString() = default;
    ~DllString() { anydoc_string_free(p); }
    DllString(const DllString&) = delete;
    DllString& operator=(const DllString&) = delete;
    std::string str() const { return p ? std::string(p) : std::string(); }
};

Result from_status(int status, DllString& text, DllString& error)
{
    Result result;
    result.status = static_cast<Status>(status);
    if (result.ok())
        result.text = text.str();
    else
        result.error = error.str().empty() ? "conversion failed" : error.str();
    return result;
}

} // namespace

const char* version()
{
    const char* v = anydoc_version();
    return v ? v : "";
}

std::optional<Format> format_from_name(std::string_view name)
{
    if (name.empty())
        return Format::Detect;
    const std::string owned(name);
    const int code = anydoc_format_from_extension(owned.c_str());
    if (code == 0)
        return std::nullopt;
    return static_cast<Format>(code);
}

Result to_markdown(const std::filesystem::path& path, Format format)
{
    if (format == Format::Detect) {
        const std::string utf8 = media::path::path_to_utf8(path);
        DllString text;
        DllString error;
        const int status = anydoc_to_markdown(utf8.c_str(), &text.p, &error.p);
        return from_status(status, text, error);
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        Result result;
        result.status = Status::Io;
        result.error = "could not read " + media::path::path_to_utf8(path);
        return result;
    }
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
    return to_markdown(bytes.data(), bytes.size(), format);
}

Result to_markdown(const std::uint8_t* bytes, std::size_t len, Format format)
{
    DllString text;
    DllString error;
    const int status = anydoc_to_markdown_bytes(
        bytes, len, static_cast<int>(format), &text.p, &error.p);
    return from_status(status, text, error);
}

} // namespace media::markdown
