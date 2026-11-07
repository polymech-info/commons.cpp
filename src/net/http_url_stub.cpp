#include "string/string_utils.hpp"

#include <string>

namespace media {

// Used when Boost.URL is not in this build. The Tanit image compiles the
// parser in uri.cpp instead, so this file stays out of that link.
bool is_http_url(const std::string& s)
{
    return strutil::starts_with_ascii_ci(s, "http://") ||
           strutil::starts_with_ascii_ci(s, "https://");
}

} // namespace media
