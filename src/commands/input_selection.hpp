#pragma once

#include <string>
#include <vector>

namespace media {

/**
 * Unified CLI/UI description of input files/folders: one or more roots, each optionally
 * combined with a relative glob under that root (`root` + `glob_under` → one pattern for
 * `expand_input_paths`).
 */
class InputSelection {
public:
    struct Entry {
        /** File path, directory, URL, or full glob — or the root when `glob_under` is set. */
        std::string spec;
        /** If non-empty, `spec` must be a directory; matching files = `spec` / `glob_under`. */
        std::string glob_under;
    };

    void clear();
    void add(Entry e);
    /** One CLI `--src` per entry (no `glob_under`; use `add` for that). */
    void add_from_cli_src_list(const std::vector<std::string> &src_args);

    bool validate(std::string &err_out) const;

    /**
     * Resolves every entry to absolute file paths or a single URL. Merges, deduplicates, sorts.
     * @param log When true, logs per-entry counts via `logger::info`.
     */
    std::vector<std::string> resolve(std::string &err_out, bool log) const;

    /** Build the `input_spec` string expected by `pair_resize_paths` / `resize_batch`. */
    static std::string to_expand_spec(const std::vector<std::string> &resolved, std::string &err_out);

    const std::vector<Entry> &entries() const { return entries_; }

private:
    std::vector<Entry> entries_;
};

} // namespace media
