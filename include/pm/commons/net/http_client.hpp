#pragma once

// Optional HTTP(S) client (`pm-commons-net`). Pin-before-bearer. No CMS paths,
// no peer grants, no automatic mutation retries.

#include "pm/commons/net/http_types.hpp"

#include <filesystem>

namespace pm::commons::net {

/// Buffered request/response.
[[nodiscard]] Response request(const Request& req);

/// Stream response body into @p dest (directories created as needed).
[[nodiscard]] Response request_to_file(const Request& req, const std::filesystem::path& dest,
                                       FileOptions options = {});

/// Stream response body through @p options.on_body. Does not buffer the body.
[[nodiscard]] Response request_stream(const Request& req, StreamOptions options);

} // namespace pm::commons::net
