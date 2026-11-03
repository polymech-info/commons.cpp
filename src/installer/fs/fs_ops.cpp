#include "installer/fs/fs_ops.hpp"
#include "installer/host.hpp"
#include "installer/resolve.hpp"

#include <filesystem>
#include <fstream>
#include <functional>

namespace pm::installer::fs_ops {

namespace fs = std::filesystem;
namespace host = pm::installer::host;

namespace {

// Same defaults as CLI `cp` / TransferDestDlg: .gitignore mask + include/exclude globs.
// Walk + filter live in vfs/operations/copy (collect_copy_at), not a parallel walker.
host::CopyFilter make_copy_filter(const std::string& pattern,
                                    const std::vector<std::string>& exclude,
                                    bool skip_vcs)
{
    host::CopyFilter filter;
    filter.exclude = exclude;
    filter.skip_vcs = skip_vcs;
    if (!pattern.empty() && pattern != "**" && pattern != "**/*" && pattern != "*")
        filter.include.push_back(pattern);
    return filter;
}

bool aborted(const std::function<AbortReason()>& should_abort,
             CopyStats& stats,
             std::string& err,
             ErrorClass& err_class)
{
    if (!should_abort)
        return false;
    const AbortReason ar = should_abort();
    if (ar == AbortReason::None)
        return false;
    stats.aborted = ar;
    err = ar == AbortReason::TimedOut ? "timeout" : "cancelled";
    err_class = ErrorClass::Transient;
    return true;
}

bool apply_on_exist(OnExist on_exist,
                    const std::string& src,
                    const std::string& dest,
                    CopyStats& stats,
                    std::string& err,
                    ErrorClass& err_class)
{
    const host::DestInfo st = host::dest_stat(dest);
    if (!st.ok || !st.exists)
        return true;
    switch (on_exist) {
    case OnExist::Skip:
        ++stats.files_skipped;
        return false;
    case OnExist::Error:
        err = "file already exists: " + dest;
        err_class = ErrorClass::Permanent;
        return false;
    case OnExist::UpdateIfNewer: {
        const host::DestInfo src_st = host::dest_stat(src);
        if (src_st.ok && src_st.mtime <= st.mtime) {
            ++stats.files_skipped;
            return false;
        }
        return true;
    }
    case OnExist::Overwrite:
    default:
        return true;
    }
}

std::string rel_for_callback(const std::string& src, const std::string& root)
{
    std::error_code ec;
    const fs::path rel = fs::relative(fs::path(src), fs::path(root), ec);
    if (ec || rel.empty())
        return host::leaf_name(src);
    return rel.generic_string();
}

bool run_collected(const host::CollectResult& collected,
                   const std::string& src_root_for_rel,
                   const CopyTreeOptions* tree_opts,
                   const CopyFilesOptions* files_opts,
                   CopyStats& stats,
                   std::string& err,
                   ErrorClass& err_class)
{
    if (!collected.err.empty()) {
        err = collected.err;
        err_class = ErrorClass::Permanent;
        return false;
    }
    for (const auto& fault : collected.faults) {
        if (fault.not_found)
            continue;
        err = fault.detail.empty() ? ("collect failed: " + fault.src) : fault.detail;
        err_class = ErrorClass::Permanent;
        return false;
    }

    const auto& should_abort = tree_opts ? tree_opts->should_abort : files_opts->should_abort;
    const auto& on_file = tree_opts ? tree_opts->on_file : files_opts->on_file;
    const bool dry_run = tree_opts ? tree_opts->dry_run : files_opts->dry_run;
    const OnExist on_exist = tree_opts ? tree_opts->on_exist : files_opts->on_exist;

    for (const auto& node : collected.nodes) {
        if (aborted(should_abort, stats, err, err_class))
            return false;

        if (node.is_dir) {
            if (dry_run)
                continue;
            const auto made = host::ensure_dir(node.dest);
            if (!made.ok) {
                err = made.err.empty() ? ("mkdir failed: " + node.dest) : made.err;
                err_class = ErrorClass::Permanent;
                return false;
            }
            continue;
        }

        if (!apply_on_exist(on_exist, node.src, node.dest, stats, err, err_class)) {
            if (!err.empty())
                return false;
            continue;
        }

        const std::string rel = rel_for_callback(node.src, src_root_for_rel);
        if (on_file)
            on_file(rel);

        if (dry_run) {
            ++stats.files_copied;
            continue;
        }

        std::function<bool()> cancel;
        if (should_abort) {
            cancel = [&] {
                return should_abort() != AbortReason::None;
            };
        }
        const auto copied = host::copy_file(node.src, node.dest, cancel);
        if (copied.cancelled) {
            stats.aborted = AbortReason::Cancelled;
            err = "cancelled";
            err_class = ErrorClass::Transient;
            return false;
        }
        if (!copied.ok) {
            err = "copy failed: " + node.dest
                + (copied.err.empty() ? std::string{} : (" — " + copied.err));
            err_class = ErrorClass::Permanent;
            return false;
        }
        stats.bytes_written += copied.bytes;
        stats.written_files.push_back(node.dest);
        ++stats.files_copied;
    }
    return true;
}

} // namespace

bool write_file_atomic(const std::string& path, const void* data, size_t size, std::string& err)
{
    std::error_code ec;
    const fs::path dst(path);
    const fs::path tmp = dst.parent_path() / (dst.filename().string() + ".part");
    fs::create_directories(dst.parent_path(), ec);
    if (ec) {
        err = "mkdir failed: " + dst.parent_path().string() + " — " + ec.message();
        return false;
    }
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "open failed: " + tmp.string();
            return false;
        }
        out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!out) {
            err = "write failed: " + tmp.string();
            fs::remove(tmp, ec);
            return false;
        }
    }
    fs::rename(tmp, dst, ec);
    if (ec) {
        err = "rename failed: " + dst.string() + " — " + ec.message();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

bool read_file(const std::string& path, std::string& out, std::string& err)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "open failed: " + path;
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (!in && !in.eof()) {
        err = "read failed: " + path;
        return false;
    }
    return true;
}

bool copy_tree(const CopyTreeOptions& opts, CopyStats& stats,
               std::string& err, ErrorClass& err_class)
{
    err.clear();
    err_class = ErrorClass::None;
    stats = {};

    std::error_code ec;
    const fs::path src_root(opts.source_dir);
    if (!fs::exists(src_root, ec) || ec) {
        err = "source path not found: " + opts.source_dir;
        err_class = ErrorClass::Permanent;
        return false;
    }
    if (!fs::is_directory(src_root, ec) || ec) {
        err = "source is not a directory: " + opts.source_dir;
        err_class = ErrorClass::Permanent;
        return false;
    }

    // Merge contents into target_dir (installer layout). CLI `cp folder dest/`
    // uses collect_copy_nodes (adds the folder leaf under dest); staging must not.
    const auto filter = make_copy_filter(opts.pattern, opts.exclude, opts.skip_vcs);
    const host::CollectResult collected =
        host::collect_copy_at(opts.source_dir, opts.target_dir, filter);
    return run_collected(collected, opts.source_dir, &opts, nullptr, stats, err, err_class);
}

bool copy_files(const CopyFilesOptions& opts, CopyStats& stats,
                std::string& err, ErrorClass& err_class)
{
    err.clear();
    err_class = ErrorClass::None;
    stats = {};

    if (opts.source_files.empty()) {
        err = "copy_files: empty source list";
        err_class = ErrorClass::Permanent;
        return false;
    }

    const auto filter = make_copy_filter(opts.pattern, opts.exclude, opts.skip_vcs);
    const std::string rel_root = opts.rel_base.empty() ? "." : opts.rel_base;

    for (const auto& src_s : opts.source_files) {
        if (aborted(opts.should_abort, stats, err, err_class))
            return false;

        if (!host::filter_accepts(src_s, false, filter)) {
            ++stats.files_skipped;
            continue;
        }

        std::error_code ec;
        fs::path rel = fs::relative(fs::path(src_s), fs::path(rel_root), ec);
        if (ec || rel.empty()) {
            ec.clear();
            rel = fs::path(src_s).filename();
        }
        const fs::path dst = fs::path(opts.target_dir) / rel;
        const host::CollectResult collected =
            host::collect_copy_at(src_s, dst.string(), filter);
        if (!run_collected(collected, rel_root, nullptr, &opts, stats, err, err_class))
            return false;
    }
    return true;
}

} // namespace pm::installer::fs_ops
