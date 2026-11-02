#pragma once

#include <filesystem>
#include <string>

namespace media {

/// Call curl_global_init once (thread-safe via std::once_flag).
void ensure_curl_global();

bool is_http_url(const std::string &s);

/** Derive filename (last path segment) for single-file output when input is a URL. */
std::string url_suggested_filename(const std::string &url);

/** Fill template variables from a URL path (for `${SRC_DIR}` / `${SRC_NAME}` / `${SRC_FILE_EXT}`). */
void url_template_variables(const std::string &url, std::string &src_dir, std::string &src_name, std::string &src_ext);

/**
 * Download URL to a temp file (binary). Follows redirects (max_redirects).
 * CURLOPT_TIMEOUT applies to the whole operation (seconds).
 */
bool fetch_url_to_file(const std::string &url, const std::filesystem::path &dest, int timeout_sec, int max_redirects,
                       std::string &err_out);

} // namespace media
