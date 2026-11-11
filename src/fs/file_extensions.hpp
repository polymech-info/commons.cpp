#pragma once
//
// Central extension predicates and preview limits for pm-image (dialogs, queue scan,
// Explorer, FileViewer, ViewerWebPanel, chat context). Replaces the former split headers
// `helpers/image_exts.hpp`, `helpers/text_exts.hpp`, `helpers/viewer_3d_exts.hpp`,
// and `helpers/viewer_documents_exts.hpp`.
//

// features.h lives in src/win/ui_next (UI targets only); CLI-only targets get
// FEATURE_* via compile definitions instead.
#if __has_include("features.h")
    #include "features.h"
#endif
#include "media/probe.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace pmui {

inline bool kind_is_or_descends_from(media::MediaKind actual, media::MediaKind wanted) noexcept
{
    if (actual == wanted)
        return true;

    switch (wanted) {
    case media::MediaKind::Text:
        return actual == media::MediaKind::Code || actual == media::MediaKind::Script;
    case media::MediaKind::Code:
        return actual == media::MediaKind::Script;
    default:
        return false;
    }
}

inline bool any_kind_matches(media::MediaKind actual, std::initializer_list<media::MediaKind> wanted) noexcept
{
    for (media::MediaKind kind : wanted) {
        if (kind_is_or_descends_from(actual, kind))
            return true;
    }
    return false;
}

inline bool any_kind_matches(media::MediaKind actual, const std::vector<media::MediaKind>& wanted) noexcept
{
    for (media::MediaKind kind : wanted) {
        if (kind_is_or_descends_from(actual, kind))
            return true;
    }
    return false;
}

inline bool isKindOf(const std::filesystem::path& path,
                     media::MediaKind wanted,
                     const media::probe::ProbeOptions& options = {})
{
    const auto result = media::probe::probe_file(path, options);
    return result.ok && kind_is_or_descends_from(result.kind, wanted);
}

inline bool isKindOf(const std::filesystem::path& path,
                     std::initializer_list<media::MediaKind> wanted,
                     const media::probe::ProbeOptions& options = {})
{
    const auto result = media::probe::probe_file(path, options);
    return result.ok && any_kind_matches(result.kind, wanted);
}

inline bool isKindOf(const std::filesystem::path& path,
                     const std::vector<media::MediaKind>& wanted,
                     const media::probe::ProbeOptions& options = {})
{
    const auto result = media::probe::probe_file(path, options);
    return result.ok && any_kind_matches(result.kind, wanted);
}

inline bool isKindOf(std::string_view bytes,
                     media::MediaKind wanted,
                     std::string_view display_name = {},
                     const media::probe::ProbeOptions& options = {})
{
    const auto result = media::probe::probe_buffer(bytes, display_name, options);
    return result.ok && kind_is_or_descends_from(result.kind, wanted);
}

inline bool isKindOf(std::string_view bytes,
                     std::initializer_list<media::MediaKind> wanted,
                     std::string_view display_name = {},
                     const media::probe::ProbeOptions& options = {})
{
    const auto result = media::probe::probe_buffer(bytes, display_name, options);
    return result.ok && any_kind_matches(result.kind, wanted);
}

inline bool isKindOf(std::string_view bytes,
                     const std::vector<media::MediaKind>& wanted,
                     std::string_view display_name = {},
                     const media::probe::ProbeOptions& options = {})
{
    const auto result = media::probe::probe_buffer(bytes, display_name, options);
    return result.ok && any_kind_matches(result.kind, wanted);
}

inline bool isKindOf(const std::uint8_t* data,
                     std::size_t len,
                     media::MediaKind wanted,
                     std::string_view display_name = {},
                     const media::probe::ProbeOptions& options = {})
{
    const auto bytes = std::string_view(reinterpret_cast<const char*>(data), len);
    return isKindOf(bytes, wanted, display_name, options);
}

inline bool isKindOf(const std::uint8_t* data,
                     std::size_t len,
                     std::initializer_list<media::MediaKind> wanted,
                     std::string_view display_name = {},
                     const media::probe::ProbeOptions& options = {})
{
    const auto bytes = std::string_view(reinterpret_cast<const char*>(data), len);
    return isKindOf(bytes, wanted, display_name, options);
}

inline bool isKindOf(const std::uint8_t* data,
                     std::size_t len,
                     const std::vector<media::MediaKind>& wanted,
                     std::string_view display_name = {},
                     const media::probe::ProbeOptions& options = {})
{
    const auto bytes = std::string_view(reinterpret_cast<const char*>(data), len);
    return isKindOf(bytes, wanted, display_name, options);
}

// ── Text / source / config ───────────────────────────────────────────────────
// Known text extensions (no exhaustive list; covers our docs + common code).

inline bool is_text_ext(std::wstring_view ext)
{
    return ext == L".txt"  || ext == L".md"   || ext == L".markdown" ||
           ext == L".log"  || ext == L".csv"  || ext == L".tsv"      ||
           ext == L".json" || ext == L".jsonl"|| ext == L".ndjson"   || ext == L".xblox" || ext == L".page" ||
           ext == L".xml"  || ext == L".html" || ext == L".htm"      ||
           ext == L".css"  || ext == L".scss" || ext == L".less"     ||
           ext == L".js"   || ext == L".jsx"  || ext == L".mjs"      || ext == L".cjs"  ||
           ext == L".ts"   || ext == L".tsx"  ||
           ext == L".cpp"  || ext == L".cxx"  || ext == L".cc"       || ext == L".c"    ||
           ext == L".h"    || ext == L".hpp"  || ext == L".hxx"      || ext == L".inl"  ||
           ext == L".py"   || ext == L".rb"   || ext == L".rs"       || ext == L".go"   ||
           ext == L".java" || ext == L".kt"   || ext == L".swift"    || ext == L".cs"   ||
           ext == L".sh"   || ext == L".bash" || ext == L".zsh"      ||
           ext == L".ps1"  || ext == L".cmd"  || ext == L".bat"      ||
           ext == L".yaml" || ext == L".yml"  || ext == L".toml"     || ext == L".ini"  ||
           ext == L".conf" || ext == L".cfg"  || ext == L".env"      ||
           ext == L".sql"  || ext == L".dot"  || ext == L".gv"       ||
           ext == L".svg"  || ext == L".rss"  || ext == L".atom"     ||
           ext == L".diff" || ext == L".patch"|| ext == L".gitignore" ||
           ext == L".gitattributes" || ext == L".editorconfig"       ||
           ext == L".cmake"|| ext == L".dockerfile";
}

inline bool is_markdown_ext(std::wstring_view ext)
{
    return ext == L".md" || ext == L".markdown" || ext == L".mdx";
}

inline bool is_office_document_ext(std::wstring_view ext)
{
    return ext == L".docx" || ext == L".xlsx" || ext == L".pptx";
}

inline bool is_vector_ingest_text_ext(std::wstring_view ext)
{
    return ext == L".txt" || is_markdown_ext(ext)
        || ext == L".csv" || ext == L".json"
        || ext == L".yaml" || ext == L".yml";
}

/// Cheap binary probe: true if @p len bytes contain a NUL (unsafe for EDIT preview).
inline bool looks_like_binary(const std::uint8_t* data, std::size_t len)
{
    for (std::size_t i = 0; i < len; ++i)
        if (data[i] == 0) return true;
    return false;
}

/// Regular file whose first bytes do not look binary (NUL sniff, up to 4 KiB).
inline bool regular_file_sniffs_as_plaintext(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path p(path_w);
    if (!fs::is_regular_file(p, ec) || ec)
        return false;
    const auto fname = p.filename().wstring();
    if (fname.empty() || fname == L"." || fname == L"..")
        return false;

    const std::uintmax_t sz = fs::file_size(p, ec);
    if (ec)
        return false;
    if (sz == 0)
        return true;

    std::ifstream ifs(p, std::ios::binary);
    if (!ifs)
        return false;

    constexpr std::size_t kCap = 4096;
    const std::size_t n = static_cast<std::size_t>((std::min)(sz, static_cast<std::uintmax_t>(kCap)));
    std::vector<std::uint8_t> buf(n);
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n)))
        return false;
    return !looks_like_binary(buf.data(), buf.size());
}

/// Extensionless regular file: first bytes must not look binary.
inline bool extensionless_regular_file_sniffs_as_plaintext(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path p(path_w);
    if (!fs::is_regular_file(p, ec) || ec)
        return false;
    if (!p.extension().empty())
        return false;
    return regular_file_sniffs_as_plaintext(path_w);
}

// ── Standard web/screen images + camera RAW ───────────────────────────────────

inline bool is_standard_image_ext(std::wstring_view ext)
{
    return ext == L".jpg"  || ext == L".jpeg" || ext == L".jpe"  ||
           ext == L".jfif" || ext == L".jf"   ||
           ext == L".png"  || ext == L".webp" ||
           ext == L".tif"  || ext == L".tiff" ||
           ext == L".bmp"  || ext == L".gif"  ||
           ext == L".avif" || ext == L".heic";
}

inline bool is_browser_image_ext(std::wstring_view ext)
{
    return ext == L".svg"  || ext == L".jpg"  || ext == L".jpeg" ||
           ext == L".png"  || ext == L".gif"  || ext == L".webp" ||
           ext == L".bmp"  || ext == L".avif" || ext == L".ico";
}

inline bool is_raw_ext(std::wstring_view ext)
{
    return ext == L".arw"  ||   // Sony
           ext == L".cr2"  ||   // Canon (older)
           ext == L".cr3"  ||   // Canon (newer)
           ext == L".nef"  ||   // Nikon
           ext == L".nrw"  ||   // Nikon (compact)
           ext == L".dng"  ||   // Adobe DNG / Leica / Hasselblad
           ext == L".orf"  ||   // Olympus / OM System
           ext == L".rw2"  ||   // Panasonic / Leica
           ext == L".raf"  ||   // Fujifilm
           ext == L".pef"  ||   // Pentax
           ext == L".srw"  ||   // Samsung
           ext == L".x3f"  ||   // Sigma Foveon
           ext == L".3fr"  ||   // Hasselblad
           ext == L".mef"  ||   // Mamiya
           ext == L".mrw";      // Minolta / Konica-Minolta
}

inline bool is_image_ext(std::wstring_view ext)
{
    if (is_standard_image_ext(ext)) return true;
#ifdef FEATURE_RAW_PREVIEW
    if (is_raw_ext(ext)) return true;
#endif
    return false;
}

inline const wchar_t* image_dialog_filter()
{
#ifdef FEATURE_RAW_PREVIEW
    return
        L"Images (*.jpg;*.jpeg;*.png;*.webp;*.tif;*.tiff;*.bmp;*.gif;*.avif;*.heic"
        L";*.arw;*.cr2;*.cr3;*.nef;*.nrw;*.dng;*.orf;*.rw2;*.raf;*.pef)\0"
        L"*.jpg;*.jpeg;*.png;*.webp;*.tif;*.tiff;*.bmp;*.gif;*.avif;*.heic"
        L";*.arw;*.cr2;*.cr3;*.nef;*.nrw;*.dng;*.orf;*.rw2;*.raf;*.pef\0"
        L"RAW Files (*.arw;*.cr2;*.cr3;*.nef;*.nrw;*.dng;*.orf;*.rw2;*.raf;*.pef)\0"
        L"*.arw;*.cr2;*.cr3;*.nef;*.nrw;*.dng;*.orf;*.rw2;*.raf;*.pef\0"
        L"All Files (*.*)\0*.*\0\0";
#else
    return
        L"Images (*.jpg;*.jpeg;*.png;*.webp;*.tif;*.tiff;*.bmp;*.gif;*.avif;*.heic)\0"
        L"*.jpg;*.jpeg;*.png;*.webp;*.tif;*.tiff;*.bmp;*.gif;*.avif;*.heic\0"
        L"All Files (*.*)\0*.*\0\0";
#endif
}

// ── 3D mesh / CAD / OpenSCAD source (WebView2 viewer-next) ───────────────────
// Keep in sync with `ThreeDViewer.tsx` loaders.

inline bool is_viewer_3d_ext(std::wstring_view ext)
{
    return ext == L".stl" || ext == L".obj" || ext == L".gltf" || ext == L".glb" || ext == L".ply"
        || ext == L".3ds" || ext == L".3mf" || ext == L".amf" || ext == L".dae" || ext == L".fbx"
        || ext == L".step" || ext == L".stp" || ext == L".stpz" || ext == L".iges" || ext == L".igs"
        || ext == L".brep" || ext == L".brp" || ext == L".fcstd"
        || ext == L".usd" || ext == L".usda" || ext == L".usdc" || ext == L".usdz"
        || ext == L".vrml" || ext == L".wrl" || ext == L".vtk" || ext == L".vtp"
        || ext == L".dxf" || ext == L".scad"
#if defined(FEATURE_3D_NATIVE_VIEWER) && FEATURE_3D_NATIVE_VIEWER && defined(PM_HAS_OPENSWX)
        || ext == L".sldprt" || ext == L".sldasm" || ext == L".slddrw"
#endif
#if defined(FEATURE_3D_NATIVE_VIEWER) && FEATURE_3D_NATIVE_VIEWER && defined(PM_HAS_PARASOLID)
        || ext == L".x_t" || ext == L".x_b" || ext == L".xt" || ext == L".xb"
#endif
        ;
}

inline std::uintmax_t viewer_3d_max_bytes_for_ext(std::wstring_view ext)
{
    if (ext == L".stl")
        return 8ull * 1024 * 1024;
    if (ext == L".fcstd")
        return 256ull * 1024 * 1024;
    return 35ull * 1024 * 1024;
}

// ── HTML (viewer-next iframe, base URL = parent folder) ─────────────────────

inline bool is_html_ext(std::wstring_view ext)
{
    return ext == L".html" || ext == L".htm";
}

// ── PDF / spreadsheet / hosted text fetch limits (viewer-next) ──────────────

inline bool is_viewer_pdf_ext(std::wstring_view ext)
{
    return ext == L".pdf";
}

inline bool is_viewer_spreadsheet_ext(std::wstring_view ext)
{
    return ext == L".csv" || ext == L".xls" || ext == L".xlsx";
}

inline bool is_viewer_officecli_ext(std::wstring_view ext)
{
#if defined(FEATURE_OFFICECLI_VIEWER) && FEATURE_OFFICECLI_VIEWER
    return ext == L".docx" || ext == L".xlsx" || ext == L".pptx"
        || ext == L".odt" || ext == L".ods" || ext == L".odp";
#else
    (void)ext;
    return false;
#endif
}

inline bool is_viewer_page_ext(std::wstring_view ext)
{
    return ext == L".page";
}

/// Audio preview in WebView2 + viewer-next (`FEATURE_VIEWER_WEB`).
/// WaveSurfer uses the browser's media decoders, so actual codec support is
/// determined by the installed WebView2 runtime.
inline bool is_audio_ext(std::wstring_view ext)
{
    return ext == L".mp3"  || ext == L".wav"  || ext == L".wave" || ext == L".flac" ||
           ext == L".m4a"  || ext == L".aac"  || ext == L".ogg"  || ext == L".oga"  ||
           ext == L".opus" || ext == L".weba" || ext == L".aiff" || ext == L".aif";
}

inline std::uintmax_t viewer_audio_max_bytes() noexcept
{
    // WaveSurfer decodes the complete file to draw the waveform. Keep the
    // native bridge transfer and decoded PCM allocation bounded.
    return 200ull * 1024 * 1024;
}

/// Video preview in WebView2 + viewer-next (`FEATURE_VIEWER_WEB`). Keep in sync with `VideoViewerPane.tsx` extensions.
inline bool is_video_ext(std::wstring_view ext)
{
    return ext == L".mp4"  || ext == L".m4v"  || ext == L".webm" || ext == L".mov"  ||
           ext == L".mkv"  || ext == L".avi"  || ext == L".wmv"  || ext == L".ogv"  ||
           ext == L".mpg"  || ext == L".mpeg" || ext == L".ts"   ||
           ext == L".m2ts" || ext == L".mts"  || ext == L".3gp"  || ext == L".3g2" ||
           ext == L".m3u8" || ext == L".mpd";
}

/// Extension routed to image / audio / video / PDF / sheet / 3D / HTML preview (not text sniff fallback).
inline bool is_specialized_preview_ext(std::wstring_view ext)
{
    return is_image_ext(ext) || is_browser_image_ext(ext) || is_audio_ext(ext) || is_video_ext(ext)
        || is_viewer_pdf_ext(ext) || is_viewer_spreadsheet_ext(ext) || is_viewer_3d_ext(ext)
        || is_viewer_officecli_ext(ext) || is_html_ext(ext) || is_viewer_page_ext(ext);
}

/// FileViewer centre pane: specialized preview or markdown. CAD/compound
/// embedded previews are `is_embedded_preview_viewer_ext`. Path-level
/// Explorer gates should use `is_centre_preview_path` (same as OpenFile).
inline bool is_file_viewer_preview_ext(std::wstring_view ext)
{
    if (is_specialized_preview_ext(ext) || is_markdown_ext(ext))
        return true;
#if defined(FEATURE_XBLOX) && FEATURE_XBLOX
    if (ext == L".xblox")
        return true;
#endif
    return false;
}

/// Rasters FileViewer already decodes — file-panel tiles use the shell thumb cache.
inline bool is_cheap_raster_ext(std::wstring_view ext)
{
    return is_image_ext(ext) || ext == L".heif" || ext == L".jxl";
}

/// Native CAD / BIM the centre viewer does not open, but the file itself carries
/// an embedded preview bitmap (OLE, ZIP PNG, or format-specific stream).
inline bool is_native_cad_document_ext(std::wstring_view ext)
{
    return ext == L".sldprt" || ext == L".sldasm" || ext == L".slddrw"
        || ext == L".ipt" || ext == L".iam"
        || ext == L".par" || ext == L".psm" || ext == L".asm" || ext == L".dft"
        || ext == L".max"
        || ext == L".rvt" || ext == L".rfa"
        || ext == L".3dm"
        || ext == L".dwg" || ext == L".dwf"
        || ext == L".blend"
        || ext == L".skp"
        || ext == L".f3d";
}

/// ZIP / OLE compound documents with a preview stream. Broader than officecli
/// (pptx, classic Office, ODF, Visio, PSD, EPUB, …).
inline bool is_compound_document_preview_ext(std::wstring_view ext)
{
    if (is_office_document_ext(ext))
        return true;
    return ext == L".doc" || ext == L".xls" || ext == L".ppt"
        || ext == L".docm" || ext == L".xlsm" || ext == L".pptm"
        || ext == L".odt" || ext == L".ods" || ext == L".odp" || ext == L".odg"
        || ext == L".vsd" || ext == L".vsdx"
        || ext == L".pub" || ext == L".msg" || ext == L".one"
        || ext == L".epub"
        || ext == L".psd" || ext == L".psb"
        || ext == L".ora" || ext == L".kra";
}

/// File-panel embedded thumb: FileViewer-regulated binary/document/media types,
/// plus native CAD / compound docs. Not cheap rasters (cache) or text/HTML.
inline bool is_embedded_preview_ext(std::wstring_view ext)
{
    if (ext.empty() || is_cheap_raster_ext(ext))
        return false;
    if (is_audio_ext(ext) || is_video_ext(ext)
        || is_viewer_pdf_ext(ext)
        || is_viewer_officecli_ext(ext)
        || is_viewer_3d_ext(ext))
        return true;
    if (is_viewer_spreadsheet_ext(ext) && ext != L".csv")
        return true;
    return is_native_cad_document_ext(ext)
        || is_compound_document_preview_ext(ext);
}

/// FileViewer has no mesh/Office/PDF surface for these — show the same
/// embedded bitmap the file-panel tiles extract (SolidWorks, PSD, …).
inline bool is_embedded_preview_viewer_ext(std::wstring_view ext)
{
    if (ext.empty() || is_cheap_raster_ext(ext))
        return false;
    if (is_specialized_preview_ext(ext))
        return false;
    return is_native_cad_document_ext(ext)
        || is_compound_document_preview_ext(ext);
}

/// Editor (Monaco / "edit") eligibility — deliberately permissive.
///
/// The editor has **no extension allow-list** and **no hard size cap**: if the
/// bytes sniff as text (no NUL in the first 4 KiB) we let the user edit them,
/// even when a richer previewer would normally claim the file (SVG, DXF/SCAD,
/// ASCII STL, `.xblox`, markdown, JSON, …). This is the foundation for "edit
/// anything that isn't binary". Binary files are excluded for now (a hex editor
/// may lift that later). Zero-byte / new files are eligible.
///
/// Mirror of `isEditorEligibleHostStatus()` in
/// `apps/viewer-next/src/bridge/resolveHostedTextSource.ts` — keep the two in
/// sync (the host is authoritative; the web derives a hint from it).
// Editor eligibility is probe-driven, NOT an extension allow-list: any regular
// file whose first bytes sniff as plaintext is editable (SVG, DXF/SCAD, JSON,
// markdown-as-source, unknown extensions, …) with no size cap. The legacy
// `is_text_ext` / `is_text_preview_eligible_for_path` allow-lists still gate the
// cheap read-only *preview* fast-paths, but must never be used to *deny* editing.
// TODO(hex-editor): binaries are excluded here; a future hex/binary editor would
// add its own eligibility predicate (and a distinct viewer kind) rather than
// relaxing this one.
inline bool is_editor_eligible(const std::wstring& path_w)
{
    // ssh:// is not a local regular file — sniffing CreateFile/ifstream fails
    // and the viewer shell hides "Open in editor". Use the leaf extension.
    if (path_w.size() >= 6
        && (path_w[0] == L's' || path_w[0] == L'S')
        && (path_w[1] == L's' || path_w[1] == L'S')
        && (path_w[2] == L'h' || path_w[2] == L'H')
        && path_w[3] == L':' && path_w[4] == L'/' && path_w[5] == L'/') {
        namespace fs = std::filesystem;
        std::wstring ext = fs::path(path_w).extension().wstring();
        for (auto& c : ext)
            c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
        if (is_text_ext(ext) || is_markdown_ext(ext) || is_html_ext(ext))
            return true;
        std::wstring fname = fs::path(path_w).filename().wstring();
        for (auto& c : fname)
            c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
        return fname.size() > 1 && fname[0] == L'.' && is_text_ext(fname);
    }
    return regular_file_sniffs_as_plaintext(path_w);
}

/// Inline-transfer ceiling for the editor. The editor is meant to be "no size
/// cap" relative to the read-only previewers' 5 MB text limit, but the centre
/// web panel still ships the bytes inline (JSON `postMessage`), so we keep a
/// generous-but-bounded ceiling to avoid pathological memory on a stray
/// multi-GB file. 64 MiB comfortably covers source trees, logs, big JSON.
inline std::uintmax_t viewer_editor_max_bytes() noexcept
{
    return 64ull * 1024 * 1024;
}

/// Known text extension, or unknown extension + plaintext sniff (after specialized preview types).
inline bool is_text_preview_eligible_for_path(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    const fs::path p(path_w);
    std::wstring ext = p.extension().wstring();
    for (auto& c : ext)
        c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
    if (is_text_ext(ext))
        return true;
    // Dot-named files (`.env`, `.gitignore`): `extension()` is often empty; the
    // basename itself is listed in `is_text_ext` (e.g. L".gitignore", L".env").
    std::wstring fname = p.filename().wstring();
    for (auto& c : fname)
        c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
    if (fname.size() > 1 && fname[0] == L'.' && fname != L".."
        && is_text_ext(fname)) {
        return true;
    }
    if (is_specialized_preview_ext(ext))
        return false;
    return regular_file_sniffs_as_plaintext(path_w);
}

/// ISO BMFF (`ftyp` at byte offset 4): MP4 / M4V / MOV family, including extensionless files the Shell still types as video.
inline bool sniff_iso_bmff_ftyp_at_file_start(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path p(path_w);
    if (!fs::is_regular_file(p, ec) || ec)
        return false;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz < 12)
        return false;
    std::ifstream in(p, std::ios::binary);
    unsigned char b[12];
    if (!in.read(reinterpret_cast<char*>(b), 12))
        return false;
    return std::memcmp(b + 4, "ftyp", 4) == 0;
}

/// Explorer + centre preview: known video extension, or extensionless file that still begins like MP4/MOV.
inline bool is_video_preview_eligible_for_path(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    std::wstring ext = fs::path(path_w).extension().wstring();
    for (auto& c : ext)
        c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
    if (is_video_ext(ext))
        return true;
    if (!ext.empty())
        return false;
    return sniff_iso_bmff_ftyp_at_file_start(path_w);
}

/// `archive:<file>!/<member>`. The member name is what the viewer types.
inline bool is_archive_member_uri(const std::wstring& path_w)
{
    if (path_w.size() < 10)
        return false;
    for (int i = 0; i < 8; ++i) {
        wchar_t c = path_w[static_cast<size_t>(i)];
        if (c >= L'A' && c <= L'Z')
            c = static_cast<wchar_t>(c - L'A' + L'a');
        if (c != L"archive:"[i])
            return false;
    }
    return path_w.find(L"!/") != std::wstring::npos;
}

inline std::wstring archive_member_leaf(const std::wstring& path_w)
{
    const auto bang = path_w.rfind(L"!/");
    if (bang == std::wstring::npos)
        return {};
    std::wstring inner = path_w.substr(bang + 2);
    while (!inner.empty() && (inner.back() == L'/' || inner.back() == L'\\'))
        inner.pop_back();
    const auto slash = inner.find_last_of(L"/\\");
    if (slash != std::wstring::npos)
        inner = inner.substr(slash + 1);
    return inner;
}

/// Same types `CFileViewer::OpenFile` / `centre_preview_kind_for_path_ws` claim.
/// Explorer selection gates must use this — not a partial image/text/3D list —
/// or CAD/compound embedded previews never reach the centre pane.
inline bool is_centre_preview_path(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    const std::wstring named = is_archive_member_uri(path_w)
        ? archive_member_leaf(path_w)
        : path_w;
    if (named.empty())
        return false;
    std::wstring ext = fs::path(named).extension().wstring();
    for (auto& c : ext)
        c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
    if (is_file_viewer_preview_ext(ext) || is_embedded_preview_viewer_ext(ext))
        return true;
    if (is_video_preview_eligible_for_path(named))
        return true;
    return is_text_preview_eligible_for_path(named);
}

/// Max preview bytes using full path (handles extensionless BMFF video vs extensionless text sniff).
inline std::uintmax_t viewer_document_max_bytes_for_path_w(const std::wstring& path_w)
{
    namespace fs = std::filesystem;
    std::wstring ext = fs::path(path_w).extension().wstring();
    for (auto& c : ext)
        c = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c)));
    if (ext == L".pdf")
        return 48ull * 1024 * 1024;
    if (is_audio_ext(ext))
        return viewer_audio_max_bytes();
    if (is_video_ext(ext) || (ext.empty() && sniff_iso_bmff_ftyp_at_file_start(path_w)))
        return 512ull * 1024 * 1024;
    if (is_viewer_page_ext(ext))
        return 5ull * 1024 * 1024;
    if (is_text_preview_eligible_for_path(path_w))
        return 5ull * 1024 * 1024;
    return 32ull * 1024 * 1024;
}

inline std::uintmax_t viewer_document_max_bytes_for_ext(std::wstring_view ext)
{
    if (ext == L".pdf")
        return 48ull * 1024 * 1024;
    if (is_audio_ext(ext))
        return viewer_audio_max_bytes();
    if (is_video_ext(ext))
        return 512ull * 1024 * 1024;
    if (is_text_ext(ext) || is_viewer_page_ext(ext) || ext.empty())
        return 5ull * 1024 * 1024;
    if (is_specialized_preview_ext(ext))
        return 32ull * 1024 * 1024;
    // Unknown extension: assume text sniff fallback limit until LoadText re-checks the path.
    return 5ull * 1024 * 1024;
}

// ── Explorer shell-registration extension tables ─────────────────────────────
// Classic cascade: PerceivedType buckets (`image` / `video` / `audio` / `text` /
// `document`) plus `k_explorer_leftover_*` for types Windows does not tag.
// The full `k_explorer_*_exts` lists stay the Open-with / residue-purge surface.
// Runtime mime (`media::probe`) still classifies file contents for viewers.
//
// Sync notes:
// - k_explorer_image_exts ⊂ is_image_ext domain (web formats + arw; full RAW
//   list and .heic are intentionally not context-menu targets today).
// - k_explorer_video_exts must match is_video_ext above.
// - k_explorer_text_exts ≈ is_text_ext ∪ pdf/xls(x) ∪ is_viewer_3d_ext (the
//   preview-only Chat/Workbench/Viewer surface, minus AV).
// - k_explorer_audio_exts is broader than is_audio_ext: WMA and MIDI remain
//   Explorer command targets but are not browser-previewable.

inline constexpr const char* k_explorer_image_exts[] = {
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif",
    "jpe", "jfif", "avif", "arw"};

inline constexpr const char* k_explorer_video_exts[] = {
    "mp4", "m4v", "webm", "mov", "mkv", "avi", "wmv", "ogv", "mpg", "mpeg",
    "ts", "m2ts", "mts", "3gp", "3g2"};

inline constexpr const char* k_explorer_audio_exts[] = {
    "mp3", "wav", "flac", "m4a", "aac", "opus", "wma", "aiff", "aif", "oga", "ogg",
    "mid", "midi"};

// Schema token `text` (pm://types/ext.text/1). Mirrors is_text_ext: markdown,
// code, and other plain-text files. Not k_explorer_text_exts — that Explorer
// bucket also contains PDF, office, and 3D.
inline constexpr const char* k_schema_text_exts[] = {
    "txt", "md", "markdown", "log", "csv", "tsv",
    "json", "jsonl", "ndjson", "xblox", "page",
    "xml", "html", "htm", "css", "scss", "less",
    "js", "jsx", "mjs", "cjs", "ts", "tsx",
    "cpp", "cxx", "cc", "c", "h", "hpp", "hxx", "inl",
    "py", "rb", "rs", "go", "java", "kt", "swift", "cs",
    "sh", "bash", "zsh", "ps1", "cmd", "bat",
    "yaml", "yml", "toml", "ini", "conf", "cfg", "env",
    "sql", "dot", "gv", "svg", "rss", "atom",
    "diff", "patch", "gitignore", "gitattributes", "editorconfig",
    "cmake", "dockerfile"};

inline constexpr const char* k_explorer_text_exts[] = {
    "pdf", "docx", "pptx", "md", "markdown", "txt", "log", "csv", "tsv", "xls", "xlsx",
    "json", "jsonl", "ndjson", "xblox", "page", "xml", "html", "htm", "css", "scss", "less",
    "js", "jsx", "mjs", "cjs", "ts", "tsx", "cpp", "cxx", "cc", "c", "h", "hpp", "hxx", "inl",
    "py", "rb", "rs", "go", "java", "kt", "swift", "cs", "sh", "bash", "zsh", "ps1", "cmd", "bat",
    "yaml", "yml", "toml", "ini", "conf", "cfg", "env", "sql", "dot", "gv", "svg", "diff", "patch",
    "gitignore", "gitattributes", "editorconfig", "cmake", "dockerfile",
    "stl", "obj", "gltf", "glb", "ply", "step", "stp", "stpz", "fcstd", "dxf", "scad",
    "3ds", "amf", "3mf", "dae", "fbx", "iges", "igs", "brep", "brp", "vrml", "wrl",
    "usd", "usda", "usdc", "usdz", "vtk", "vtp"};

// Types that usually have no PerceivedType (or a useless one). One lowercase
// `SystemFileAssociations\.{ext}` each — not the three case variants.
inline constexpr const char* k_explorer_leftover_image_exts[] = {
    "arw", "avif",
};
inline constexpr const char* k_explorer_leftover_text_exts[] = {
    "pdf", "docx", "pptx", "xls", "xlsx", "md", "markdown",
    "json", "jsonl", "ndjson", "xblox", "page",
    "stl", "obj", "gltf", "glb", "ply", "step", "stp", "stpz", "fcstd", "dxf", "scad",
    "3ds", "amf", "3mf", "dae", "fbx", "iges", "igs", "brep", "brp", "vrml", "wrl",
    "usd", "usda", "usdc", "usdz", "vtk", "vtp",
};

// ── Search type→glob map (mirrors rg --type) ─────────────────────────────────

struct SearchTypeGlobEntry {
    const char* name;
    const char* globs[9]; // null-terminated; up to 8 patterns per type
};

inline constexpr SearchTypeGlobEntry k_search_type_globs[] = {
    {"c",      {"*.c", "*.h"}},
    {"cpp",    {"*.cpp", "*.cxx", "*.cc", "*.c++", "*.h", "*.hpp", "*.hxx", "*.h++"}},
    {"cs",     {"*.cs"}},
    {"css",    {"*.css", "*.scss", "*.sass", "*.less"}},
    {"go",     {"*.go"}},
    {"html",   {"*.html", "*.htm", "*.xhtml"}},
    {"java",   {"*.java"}},
    {"js",     {"*.js", "*.mjs", "*.cjs"}},
    {"json",   {"*.json", "*.jsonc"}},
    {"kotlin", {"*.kt", "*.kts"}},
    {"md",     {"*.md", "*.markdown"}},
    {"py",     {"*.py", "*.pyi"}},
    {"rs",     {"*.rs"}},
    {"ruby",   {"*.rb", "*.rake"}},
    {"rust",   {"*.rs"}},
    {"sh",     {"*.sh", "*.bash", "*.zsh", "*.fish"}},
    {"swift",  {"*.swift"}},
    {"ts",     {"*.ts", "*.tsx", "*.mts", "*.cts"}},
    {"toml",   {"*.toml"}},
    {"txt",    {"*.txt"}},
    {"xml",    {"*.xml", "*.xsl", "*.xsd", "*.svg"}},
    {"yaml",   {"*.yaml", "*.yml"}},
    {nullptr,  {}},
};

// ── Sensitive path prefixes (LLM FS guard deny list) ─────────────────────────
// Normalized to forward slashes. On Windows both path and pattern are lowercased
// before comparison. Glob patterns use ** / * / ? (see path_matches_path_glob).
// Null-terminated.

inline constexpr const char* k_sensitive_path_prefixes[] = {
    // ===== UNIX system paths =====
    "/etc/",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/",
    "/root/",
    "/var/lib/",
    "/var/run/secrets/",
    "/proc/",
    "/sys/",

    // ===== Generic secrets mounts =====
    "/run/secrets/",
    "/mnt/secrets/",
    "/secrets/",

    // ===== Portable user / app secrets (any prefix: /home/…, /Users/…, /export/home/…, any drive on Windows) =====
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.config/gcloud/**",
    "**/.aws/**",
    "**/.kube/**",
    "**/.docker/**",
    "**/.local/share/keyrings/**",
    // cloud / vendor CLI credential stores
    "**/.azure/**",
    "**/.oci/**",
    "**/.config/gh/**",            // GitHub CLI tokens
    "**/.config/doctl/**",         // DigitalOcean
    "**/.config/git/**",           // git config / credential store
    "**/.config/openstack/**",
    "**/.netlify/**",
    "**/.vercel/**",
    "**/.cargo/**",                // crates.io tokens (credentials.toml)
    "**/.gem/**",                  // rubygems credentials
    "**/.bundle/**",
    "**/.composer/**",             // packagist / composer auth.json
    "**/.m2/**",                   // maven settings.xml (server passwords)
    "**/.terraform.d/**",
    "**/.vault-token",

    // ===== Developer credential / token files (basenames anywhere) =====
    "**/.npmrc",                   // npm auth tokens
    "**/.yarnrc",
    "**/.yarnrc.yml",
    "**/.pnpmrc",
    "**/.git-credentials",
    "**/.gitconfig",
    "**/.netrc",
    "**/_netrc",
    "**/.pgpass",
    "**/.my.cnf",                  // MySQL client password
    "**/.htpasswd",
    "**/.pypirc",                  // PyPI upload tokens
    "**/.boto",                    // AWS / GCS legacy creds
    "**/.s3cfg",                   // s3cmd creds
    "**/.terraformrc",
    "**/credentials",              // bare AWS-style credentials file
    "**/credentials.toml",
    "**/auth.json",
    "**/*.tfstate",                // terraform state often embeds secrets
    "**/*.tfstate.backup",
    "**/secring.gpg",

    // macOS user Library (under any home root; case as on disk — Unix paths are not lowercased)
    "**/Library/Keychains/**",
    "**/Library/Application Support/CloudDocs/**",
    "**/Library/Application Support/com.apple.TCC/**",
    "**/Library/Containers/**",
    "**/.zsh_history",
    "**/.bash_history",

    // ===== Windows portable (lowercase; matches any drive letter) =====
    "**/windows/system32/config/",
    "**/windows/system32/drivers/etc/hosts",
    "**/users/*/appdata/roaming/microsoft/credentials/**",
    "**/users/*/appdata/local/microsoft/credentials/**",
    "**/users/*/appdata/roaming/microsoft/protect/**",
    "**/users/*/appdata/roaming/microsoft/crypto/**",
    "**/users/*/appdata/roaming/microsoft/vault/**",
    "**/users/*/ntuser.dat",
    "**/Google/Chrome/**",
    "**/Mozilla/Firefox/**",

    // ===== Project-level =====
    "**/.git/**",
    "**/.env*",
    "**/node_modules/**",

    // ===== Sensitive basenames anywhere =====
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.crt",
    "**/*.der",
    "**/*.csr",
    "**/*.env",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/known_hosts",
    "**/authorized_keys",
    "**/wallet.dat",
    "**/*.kdbx",
    "**/*.sqlite",
    "**/*.sqlite3",
    "**/*.sqlite-wal",
    "**/*.sqlite-shm",
    "**/*.db-shm",
    "**/*.db-wal",
    "**/*.db",
    "**/*.mdb",
    "**/*.accdb",
    "**/*.duckdb",
    "**/*.realm",
    "**/*.fdb",
    "**/*.sql",
    "**/*.dump",
    "**/*.backup",
    "**/*.bak",
    "**/*.ndjson",
    "**/*.parquet",
    "**/*.orc",
    "**/*.avro",
    "**/*.bson",
    "**/cookies.sqlite",
    "**/Login Data",
    "**/Web Data",
    "**/NTUSER.DAT",
    "**/config.json",
    "**/credentials.json",
    "**/secrets.json",

    // common dev seed / migration / fixture filenames
    "**/seed.sql",
    "**/seeds.sql",
    "**/seed.json",
    "**/seeds.json",
    "**/seed.yaml",
    "**/seed.yml",
    "**/seeds.yaml",
    "**/seeds.yml",
    "**/seed.ts",
    "**/seed.js",
    "**/seed.mjs",
    "**/seed.cjs",
    "**/seeds.ts",
    "**/seeds.js",
    "**/fixtures.sql",
    "**/.seed.sql",

    nullptr,
};

// ── Artifact role extension groups (narrow, used by agent_memory_artifacts) ───

inline constexpr const char* k_cad_drawing_exts[] = {
    ".dxf", ".dwg", ".dwf",
};

inline constexpr const char* k_model_3d_exts[] = {
    ".scad", ".stl", ".obj", ".ply", ".glb", ".gltf",
    ".step", ".stp", ".stpz", ".iges", ".igs", ".brep", ".brp",
    ".3ds", ".amf", ".3mf", ".dae", ".fbx", ".fcstd", ".vrml", ".wrl",
    ".usd", ".usda", ".usdc", ".usdz", ".vtk", ".vtp",
};

inline constexpr const char* k_source_code_exts[] = {
    ".cpp", ".hpp", ".h",   ".c",   ".cc",  ".cxx",
    ".py",  ".js",  ".ts",  ".tsx", ".rs",  ".go",
    ".java", ".kt", ".swift", ".rb", ".sh",  ".ps1", ".lua",
};

// ── Shell open guard ─────────────────────────────────────────────────────────
// Extensions that ShellExecute "open" would run rather than display.
// Used by open_path / open_user_file to block LLM-injected executable paths.

inline constexpr std::wstring_view k_shell_open_blocked_exts[] = {
    // Windows executables & launchers
    L".exe", L".com", L".pif", L".scr", L".cpl", L".msc",
    L".msi", L".msp", L".msix", L".appx", L".application",
    // shortcuts & jump targets
    L".lnk", L".url", L".scf",
    // scripts (Windows)
    L".bat", L".cmd", L".ps1", L".psm1", L".psd1",
    L".vbs", L".vbe", L".wsf", L".wsh", L".hta",
    L".reg", L".inf",
    // scripts (cross-platform)
    L".sh", L".bash", L".zsh", L".fish", L".ksh", L".csh",
    L".py", L".pyw", L".pl", L".rb", L".lua", L".php",
    L".js", L".jse", L".mjs", L".cjs", L".ts",
    // libraries & bytecode that shellexec can launch indirectly
    L".dll", L".jar",
};

// ── LLM glob filter ───────────────────────────────────────────────────────────
// Extensions blocked from file-read / glob enumeration by the LLM agent.
// Mirrors pm-pics `exclude-default.ts` binary/media/archive entries.

inline constexpr const char* k_llm_glob_blocked_exts[] = {
    ".png",  ".apng", ".jpg",  ".jpeg", ".jpe",  ".jfif", ".gif",  ".webp", ".bmp",
    ".tif",  ".tiff", ".ico",  ".heic", ".heif", ".avif", ".jxl",  ".psd",
    ".exr",  ".hdr",  ".raw",  ".cr2",  ".nef",  ".orf",  ".sr2",  ".dng",
    ".exe",  ".dll",  ".sys",  ".msi",  ".com",  ".cab",  ".so",   ".dylib",
    ".bundle", ".lib", ".a",   ".o",    ".obj",  ".pdb",  ".ilk",  ".exp",
    ".zip",  ".7z",   ".rar",  ".tar",  ".gz",   ".bz2",  ".xz",   ".zst",
    ".apk",  ".ipa",  ".wasm",
    ".woff", ".woff2", ".ttf", ".otf",  ".eot",
    ".mp3",  ".mp4",  ".m4a",  ".webm", ".mov",  ".avi",  ".mkv",  ".flac",
    ".pdf",
};

// Lowercase folder/file names excluded from glob enumeration by the LLM agent.
// Mirrors pm-pics `exclude-default.ts` non-dot entries (dot-prefix handled separately).
inline constexpr const char* k_llm_glob_exclude_names[] = {
    "__macosx",
    "__pycache__",
    "bower_components",
    "cmake_install.cmake",
    "cmakecache.txt",
    "cmakefiles",
    "cmakescripts",
    "compile_commands.json",
    "coverage",
    "debug",
    "desktop.ini",
    "ehthumbs.db",
    "ipch",
    "node_modules",
    "npm-debug.log",
    "out",
    "release",
    "target",
    "testresults",
    "thumbs.db",
    "venv",
    "vfs-settings.json",
    "x64",
    "x86",
    "yarn-debug.log",
    "yarn-error.log",
};

// ── LLM write guard ───────────────────────────────────────────────────────────
// Allowlisted media extensions for LLM `write_file` / image tool output paths.

inline constexpr const char* k_llm_write_allowed_media_exts[] = {
    // raster / vector images
    ".jpg",  ".jpeg", ".jpe",  ".jfif", ".png",  ".apng", ".webp", ".gif",  ".bmp",
    ".tif",  ".tiff", ".ico",  ".heic", ".heif", ".avif", ".jxl",  ".svg",
    ".psd",  ".exr",  ".hdr",  ".tga",  ".pcx",  ".wbmp",
    // RAW stills
    ".arw",  ".cr2",  ".cr3",  ".nef",  ".nrw",  ".dng",  ".orf",  ".rw2",
    ".raf",  ".pef",  ".srw",  ".x3f",  ".3fr",  ".mef",  ".mrw",  ".raw",
    // video
    ".mp4",  ".m4v",  ".mkv",  ".webm", ".mov",  ".avi",  ".wmv",  ".flv",
    ".mpg",  ".mpeg", ".m2ts", ".mts",  ".ts",   ".ogv",  ".3gp",  ".3g2",
    // audio
    ".mp3",  ".wav",  ".flac", ".ogg",  ".opus", ".m4a",  ".aac",  ".wma",
    ".aiff", ".aif",  ".alac",
};

// Extensions blocked as write targets for LLM tools (scripts, executables, macro Office, disk images, …).
// Null-terminated; iterate with:  for (const char* const* p = k_llm_write_blocked_exts; *p; ++p)
inline constexpr const char* k_llm_write_blocked_exts[] = {
    // shells & scripts
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh", ".tcsh",
    ".py", ".pyw", ".pl", ".pm", ".rb", ".lua", ".php",
    ".js", ".jse", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts", ".jsx", ".vue", ".svelte",
    ".rs", ".go", ".java", ".class", ".cs", ".fs", ".fsx",
    ".gradle", ".groovy", ".scala", ".kt", ".kts", ".swift",
    ".r", ".R", ".dart", ".nim", ".ex", ".exs",
    ".tcl", ".awk", ".hta", ".msc", ".reg", ".inf",
    ".vbs", ".vbe", ".wsf", ".wsh",
    // Windows executables & installers
    ".exe", ".dll", ".msi", ".scr", ".com", ".pif", ".cpl", ".hta", ".msc",
    ".reg", ".lnk", ".url", ".scf", ".inf", ".application",
    // JVM / packages
    ".jar", ".war", ".ear",
    // OS packages
    ".deb", ".rpm", ".dmg", ".pkg", ".app",
    // macro-enabled Office (plain documents and OpenDocument are writable)
    ".docm", ".dotm",
    ".xlsm", ".xlsb", ".xltm",
    ".pptm", ".potm",
    // disk images (archives such as .zip / .7z / .tar.gz are writable)
    ".iso", ".img", ".vhd", ".vhdx", ".wim",
    // databases & data dumps (often credentials or bulk PII)
    ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb",
    ".duckdb", ".realm", ".fdb",
    ".sql", ".dump", ".backup", ".bak",
    ".ndjson", ".parquet", ".orc", ".avro", ".bson",
    // other risky / opaque binary carriers
    ".wasm", ".apk", ".ipa", ".msix", ".appx",
    nullptr,
};

// Script/batch extensions that get a specific recovery hint in write-deny messages.
// Null-terminated.
inline constexpr const char* k_llm_write_script_exts[] = {
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh", ".tcsh",
    ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".reg", ".inf",
    nullptr,
};

// Absolute path prefixes that must not receive files from LLM write tools.
// Null-terminated.  Windows drive letter 'C:' is retargeted at runtime to match
// the path under test (Windows drive letter follows the path being checked).
inline constexpr const char* k_llm_write_blocked_abs_prefixes[] = {
#if defined(_WIN32)
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\",
#endif
    "/bin/",
    "/sbin/",
    "/boot/",
    "/lib/",
    "/lib64/",
    "/usr/bin/",
    "/usr/sbin/",
    "/etc/",
    "/root/",
    nullptr,
};

// ── Search: default excluded directories ─────────────────────────────────────
// Folder names skipped during recursive file search (mirrors rg defaults + build dirs).

inline constexpr const char* k_search_default_exclude_dirs[] = {
    ".git", ".svn", ".hg",
    "node_modules", ".npm", ".yarn",
    ".cache", ".turbo", ".next", ".nuxt", ".parcel-cache", ".angular", ".svelte-kit",
    "__pycache__", ".venv", "venv", ".eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "target",
    "coverage", ".nyc_output",
    ".terraform", ".vagrant", "bower_components",
    "CMakeFiles", "CMakeScripts",
    "out", "dist", "build", "bin", "obj", "vendor", ".tox",
    ".vs", "Debug", "Release", "x64", "x86", "ipch", "packages", "TestResults",
};

} // namespace pmui

