#pragma once

// Document to Markdown. Callers share this result type.
//
// Windows loads anydoc.dll from markdown_win.cpp. That file is compiled into
// the host image when FEATURE_COMMAND_MARKDOWN is on. It is not part of
// pm-commons-lib. Android does not compile it: the phone has its own loader.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace media::markdown {

enum class Status : int {
    Ok = 0,
    Unsupported = 1,
    NeedsOcr = 2,
    Malformed = 3,
    Encrypted = 4,
    ResourceLimit = 5,
    MissingPart = 6,
    Io = 7,
    Panic = 8,
    Invalid = 9,
};

enum class Format : int {
    Detect = 0,
    Doc = 1,
    Docx = 2,
    Odt = 3,
    Pdf = 4,
    Ppt = 5,
    Pptx = 6,
    Rtf = 7,
    Epub = 8,
    Excel = 9,
    Ods = 10,
    Odp = 11,
    Csv = 12,
};

struct Result {
    Status status = Status::Ok;
    std::string text;
    std::string error;

    bool ok() const { return status == Status::Ok; }
};

const char* version();

// Empty name is Detect. Unknown names are nullopt.
std::optional<Format> format_from_name(std::string_view name);

Result to_markdown(const std::filesystem::path& path, Format format = Format::Detect);
Result to_markdown(const std::uint8_t* bytes, std::size_t len, Format format = Format::Detect);

} // namespace media::markdown
