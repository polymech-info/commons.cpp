#include "security/ui/win/ConsentDlg.hpp"
#include "security/ui/win/ConsentDlg_i18n.hpp"

#if defined(_WIN32)

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "Uxtheme.lib")
#pragma comment(lib, "Shell32.lib")

namespace pm::security::ui {

namespace {

// ── utf8 <-> wide ────────────────────────────────────────────────────────────

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

// ── palette ────────────────────────────────────────────────────────────────

struct Palette {
    COLORREF window_bg, window_fg, control_bg, control_fg, subtle, sep;
    // Owner-drawn button surfaces
    COLORREF btn_bg, btn_hover, btn_pressed, btn_border;
    COLORREF accent, accent_hover, accent_pressed, accent_fg;
    // AI review panel + risk banner
    COLORREF panel_bg, panel_border;
    bool dark;
};

Palette make_palette(bool dark) {
    const COLORREF surface = dark ? 0x00232323u : 0x00F3F4F5u;
    if (dark)
        return Palette{
            surface, RGB(238, 238, 238),
            RGB(42, 42, 42), RGB(238, 238, 238),
            RGB(160, 160, 160), RGB(64, 64, 64),
            RGB(56, 56, 56), RGB(74, 74, 74), RGB(46, 46, 46), RGB(92, 92, 92),
            RGB(0, 120, 215), RGB(32, 140, 230), RGB(0, 100, 190), RGB(255, 255, 255),
            RGB(40, 40, 40), RGB(72, 72, 72),
            true
        };
    return Palette{
        surface, RGB(16, 16, 16),
        RGB(255, 255, 255), RGB(16, 16, 16),
        RGB(105, 105, 105), RGB(214, 214, 214),
        RGB(251, 251, 251), RGB(241, 241, 241), RGB(228, 228, 228), RGB(198, 198, 198),
        RGB(0, 120, 215), RGB(0, 103, 192), RGB(0, 90, 168), RGB(255, 255, 255),
        RGB(245, 245, 245), RGB(214, 214, 214),
        false
    };
}

COLORREF risk_fg(Risk r, bool dark) {
    switch (r) {
    case Risk::Low:      return dark ? RGB(120, 210, 120) : RGB(22, 128, 22);
    case Risk::Medium:   return dark ? RGB(225, 190, 80)  : RGB(158, 110, 0);
    case Risk::High:     return dark ? RGB(240, 150, 60)  : RGB(185, 80, 0);
    case Risk::Critical: return dark ? RGB(245, 100, 100) : RGB(185, 20, 20);
    }
    return dark ? RGB(200, 200, 200) : RGB(60, 60, 60);
}

COLORREF risk_strip(Risk r, bool /*dark*/) {
    switch (r) {
    case Risk::Low:      return RGB(40, 167, 69);
    case Risk::Medium:   return RGB(255, 168, 0);
    case Risk::High:     return RGB(220, 100, 0);
    case Risk::Critical: return RGB(200, 20, 20);
    }
    return RGB(120, 120, 120);
}

// pctA% of a blended over (100-pctA)% of b.
COLORREF mix(COLORREF a, COLORREF b, int pctA) {
    const int inv = 100 - pctA;
    return RGB((GetRValue(a) * pctA + GetRValue(b) * inv) / 100,
               (GetGValue(a) * pctA + GetGValue(b) * inv) / 100,
               (GetBValue(a) * pctA + GetBValue(b) * inv) / 100);
}

// Soft, risk-tinted fill for the prominent risk chip — a light wash of the
// strip colour over the window background (mirrors the WebView RiskBadge).
COLORREF risk_badge_bg(Risk r, bool dark) {
    const COLORREF strip = risk_strip(r, dark);
    const COLORREF base  = dark ? 0x00232323u : 0x00F3F4F5u;
    return mix(strip, base, dark ? 26 : 16);
}

const wchar_t* risk_value(Risk r, const i18n::Strings& tr) {
    switch (r) {
    case Risk::Low:      return tr.risk_low;
    case Risk::Medium:   return tr.risk_medium;
    case Risk::High:     return tr.risk_high;
    case Risk::Critical: return tr.risk_critical;
    }
    return L"?";
}

const wchar_t* action_value(Action a, const i18n::Strings& tr) {
    switch (a) {
    case Action::Read:             return tr.action_read;
    case Action::Write:            return tr.action_write;
    case Action::Delete:           return tr.action_delete;
    case Action::Execute:          return tr.action_execute;
    case Action::Network:          return tr.action_network;
    case Action::Upload:           return tr.action_upload;
    case Action::Download:         return tr.action_download;
    case Action::GitPush:          return tr.action_git_push;
    case Action::Publish:          return tr.action_publish;
    case Action::ProtocolActivate: return tr.action_protocol;
    }
    return L"?";
}

const wchar_t* decision_value(const std::string& d, const i18n::Strings& tr) {
    std::string k = d;
    for (char& c : k) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    if (k == "allow") return tr.decision_allow;
    if (k == "deny")  return tr.decision_deny;
    if (k == "ask")   return tr.decision_ask;
    return nullptr;
}

std::wstring heading_for(const ConsentRequest& cr, const i18n::Strings& tr) {
    return std::wstring(tr.title_allow_pre) + action_value(cr.request.action, tr)
         + tr.title_allow_post;
}

std::wstring goal_display(const std::string& goal, const i18n::Strings& tr) {
    if (goal.empty()) return {};
    if (goal == "Run a command from a page")
        return tr.intent_web_command;
    constexpr const char kFrom[] = "Run a command from ";
    if (goal.size() > sizeof(kFrom) - 1
        && goal.compare(0, sizeof(kFrom) - 1, kFrom) == 0)
        return std::wstring(tr.intent_web_command_from_pre)
             + widen(goal.substr(sizeof(kFrom) - 1));
    return widen(goal);
}

int risk_rank(Risk r) { return static_cast<int>(r); }

// ── control IDs (stable; referenced by UIA tests via AutomationId) ───────────
constexpr int IDC_ALLOW_ONCE    = 1101;
constexpr int IDC_ALLOW_SESSION = 1102;
constexpr int IDC_ALLOW_TASK    = 1103;
// 1104 was "Open settings" (removed).
constexpr int IDC_ALLOW_ALWAYS  = 1105;
constexpr int IDC_AI_AUTO_ONCE    = 1106;
constexpr int IDC_AI_AUTO_SESSION = 1107;
constexpr int IDC_AI_AUTO_ALWAYS  = 1108;
constexpr int IDC_SCOPE_EDIT    = 1110;
constexpr int IDC_SANDBOX_CHECK = 1111;
constexpr int IDC_RISK_STATIC   = 1120;
constexpr int IDC_RISKRAISE_STATIC = 1121;
constexpr int IDC_AI_REVIEW     = 1130;   // "Review with AI"
constexpr int IDC_AI_APPLY      = 1131;   // "Apply recommendation"
constexpr int IDC_AI_REASON     = 1132;   // review reason (read-only edit)
constexpr int IDC_AI_TITLE      = 1133;   // "AI security review" panel header
constexpr int IDC_AI_RECOMMEND  = 1134;   // "Recommended: …" panel line
constexpr int IDC_DENY          = IDCANCEL;

constexpr UINT WM_APP_REVIEW_DONE = WM_APP + 1;

// ── async review channel (shared between the dialog and its worker thread) ───
struct ReviewChannel {
    std::mutex        mu;
    AiConsentReview   result;
    std::atomic<bool> alive{true};   // false once the dialog is destroyed
};

// ── state ─────────────────────────────────────────────────────────────────────

struct ConsentDlgState {
    const ConsentRequest*   req  = nullptr;
    const ConsentUiOptions* opts = nullptr;
    const i18n::Strings*    tr   = nullptr;
    Palette  pal{};
    ConsentResult result{};   // safe default = Deny

    HFONT baseFont   = nullptr;
    HFONT titleFont  = nullptr;
    HFONT subtleFont = nullptr;
    HFONT riskFont   = nullptr;   // bold, for the prominent risk chip
    HBRUSH hDlgBg    = nullptr;
    HBRUSH hCtlBg    = nullptr;
    HBRUSH hPanelBg  = nullptr;
    HBRUSH hRiskBg   = nullptr;   // risk-tinted chip fill (recreated per rebuild)
    HWND   hScope    = nullptr;
    HWND   hSandbox  = nullptr;
    HWND   hTT       = nullptr;   // tooltip control (WS_POPUP; not a child)

    // Editable state persisted across rebuilds.
    std::wstring scopeText;
    bool sandboxChecked = false;
    bool aiReviewApplied = false;

    // Risk (base + effective after review promotion) for strip/label paint.
    Risk risk = Risk::Medium;           // original
    Risk effectiveRisk = Risk::Medium;  // max(original, review.assessedRisk)

    // AI review lifecycle.
    bool showReviewSection = false;
    bool reviewing = false;
    bool reviewDone = false;
    AiConsentReview review{};
    std::shared_ptr<ReviewChannel> chan;

    // Painted panel rectangle (AI review) — set during rebuild.
    RECT aiPanelRc{0, 0, 0, 0};
    int stripH = 0;
};

// ── helpers ───────────────────────────────────────────────────────────────────

int dpi_of(HWND h) {
    UINT d = 96;
    if (h && ::IsWindow(h)) d = ::GetDpiForWindow(h);
    return (int)(d ? d : 96);
}

int measure_h(HDC dc, const std::wstring& s, int w) {
    if (s.empty()) return 0;
    RECT r{0, 0, w, 0};
    ::DrawTextW(dc, s.c_str(), -1, &r, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    return (int)(r.bottom - r.top);
}

void apply_dark_titlebar(HWND h, bool dark) {
    const BOOL v = dark ? TRUE : FALSE;
    if (FAILED(::DwmSetWindowAttribute(h, 20, &v, sizeof(v))))
        ::DwmSetWindowAttribute(h, 19, &v, sizeof(v));
}

HWND mk_static(HWND parent, const std::wstring& text, int x, int y, int w, int h,
               DWORD extra = 0, int id = -1) {
    return ::CreateWindowExW(0, L"STATIC", text.c_str(),
        WS_CHILD | WS_VISIBLE | extra,
        x, y, w, h, parent,
        (HMENU)(UINT_PTR)(id < 0 ? 0 : id), ::GetModuleHandleW(nullptr), nullptr);
}

// Owner-drawn flat button subclass — tracks hover so WM_DRAWITEM can highlight.
LRESULT CALLBACK obtn_subclass(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    switch (m) {
    case WM_MOUSEMOVE:
        if (!::GetPropW(h, L"pmHot")) {
            ::SetPropW(h, L"pmHot", (HANDLE)1);
            TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, h, 0};
            ::TrackMouseEvent(&tme);
            ::InvalidateRect(h, nullptr, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        ::RemovePropW(h, L"pmHot");
        ::InvalidateRect(h, nullptr, FALSE);
        break;
    case WM_NCDESTROY:
        ::RemovePropW(h, L"pmHot");
        ::RemoveWindowSubclass(h, obtn_subclass, 1);
        break;
    default: break;
    }
    return ::DefSubclassProc(h, m, wp, lp);
}

HWND mk_obutton(HWND parent, const std::wstring& text, int x, int y, int w, int h,
                int id, bool defBtn = false) {
    HWND b = ::CreateWindowExW(0, L"BUTTON", text.c_str(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW | (defBtn ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON),
        x, y, w, h, parent,
        (HMENU)(UINT_PTR)id, ::GetModuleHandleW(nullptr), nullptr);
    ::SetWindowSubclass(b, obtn_subclass, 1, 0);
    return b;
}

void draw_owner_button(ConsentDlgState* st, const DRAWITEMSTRUCT* di) {
    const bool hot      = ::GetPropW(di->hwndItem, L"pmHot") != nullptr;
    const bool pressed  = (di->itemState & ODS_SELECTED) != 0;
    const bool disabled = (di->itemState & ODS_DISABLED) != 0;
    const bool focus    = (di->itemState & ODS_FOCUS) != 0;
    const int  id       = (int)di->CtlID;
    const bool primary  = (id == IDC_AI_APPLY);
    const bool isDefault = (id == IDCANCEL);
    const Palette& p = st->pal;

    COLORREF bg, fg, border;
    if (primary) {
        bg     = pressed ? p.accent_pressed : (hot ? p.accent_hover : p.accent);
        fg     = p.accent_fg;
        border = p.accent;
    } else {
        bg     = pressed ? p.btn_pressed : (hot ? p.btn_hover : p.btn_bg);
        fg     = p.control_fg;
        border = isDefault ? p.accent : p.btn_border;
    }
    if (disabled) { fg = p.subtle; border = p.btn_border; }

    HDC dc = di->hDC;
    const int dpi = dpi_of(di->hwndItem);
    const int rad = ::MulDiv(6, dpi, 96);

    // Erase the whole item with the parent's background first, so the pixels
    // outside the rounded rect blend into the dialog / AI panel instead of
    // showing undrawn owner-draw garbage.
    const COLORREF parentBg = (id == IDC_AI_REVIEW || id == IDC_AI_APPLY)
        ? p.panel_bg : p.window_bg;
    HBRUSH eb = ::CreateSolidBrush(parentBg);
    ::FillRect(dc, &di->rcItem, eb);
    ::DeleteObject(eb);

    HBRUSH hb = ::CreateSolidBrush(bg);
    HPEN   hp = ::CreatePen(PS_SOLID, 1, border);
    HGDIOBJ ob = ::SelectObject(dc, hb);
    HGDIOBJ op = ::SelectObject(dc, hp);
    ::RoundRect(dc, di->rcItem.left, di->rcItem.top, di->rcItem.right, di->rcItem.bottom, rad * 2, rad * 2);
    ::SelectObject(dc, ob);
    ::SelectObject(dc, op);
    ::DeleteObject(hb);
    ::DeleteObject(hp);

    wchar_t txt[256]{};
    ::GetWindowTextW(di->hwndItem, txt, 255);
    ::SetBkMode(dc, TRANSPARENT);
    ::SetTextColor(dc, fg);
    HGDIOBJ of = ::SelectObject(dc, st->baseFont);
    RECT tr = di->rcItem;
    ::DrawTextW(dc, txt, -1, &tr,
        DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    ::SelectObject(dc, of);

    if (focus && !disabled) {
        RECT fr = di->rcItem;
        const int inset = ::MulDiv(3, dpi, 96);
        ::InflateRect(&fr, -inset, -inset);
        ::DrawFocusRect(dc, &fr);
    }
}

std::wstring default_scope_for(const ConsentRequest& cr) {
    if (!cr.suggestedScope.empty())
        return widen(cr.suggestedScope);
    if (cr.request.target) {
        if (!cr.request.target->path.empty())
            return widen(cr.request.target->path.generic_string());
        if (!cr.request.target->uri.empty())
            return widen(cr.request.target->uri);
    }
    if (!cr.resourcePreview.empty()) return widen(cr.resourcePreview.front());
    return {};
}

const wchar_t* lifetime_short(GrantLifetime lt, const i18n::Strings& tr) {
    switch (lt) {
    case GrantLifetime::Once:      return tr.btn_allow_once;
    case GrantLifetime::Session:   return tr.btn_allow_session;
    case GrantLifetime::Task:      return tr.btn_allow_task;
    case GrantLifetime::Permanent: return tr.btn_allow_always;
    default: return tr.btn_allow_once;
    }
}

void finish(HWND hwnd, ConsentDlgState* st, DecisionKind kind, bool openSettings,
            GrantLifetime lt, bool aiDelegated = false) {
    st->result = ConsentResult{};
    st->result.kind = kind;
    st->result.openSettings = openSettings;
    st->result.aiDelegated = aiDelegated;
    if (kind == DecisionKind::Allow && st->opts && st->opts->makeGrant) {
        wchar_t buf[2048]{};
        if (st->hScope) ::GetWindowTextW(st->hScope, buf, (int)std::size(buf));
        std::vector<std::string> scopes;
        const std::string scope = narrow(buf);
        if (!scope.empty()) scopes.push_back(scope);
        st->result.grant = st->opts->makeGrant(st->req->request, lt, std::move(scopes));
        if (st->result.grant) {
            st->result.grant->aiDelegated = aiDelegated;
            st->result.grant->approvedBy =
                aiDelegated ? "ai:win32"
                            : (st->aiReviewApplied ? "human+ai:win32" : "human");
        }
        if (st->result.grant && st->hSandbox &&
            ::SendMessageW(st->hSandbox, BM_GETCHECK, 0, 0) == BST_CHECKED &&
            !st->req->sandboxBackends.empty()) {
            st->result.grant->sandboxBackend = st->req->sandboxBackends.front();
        }
    }
    ::EndDialog(hwnd, kind == DecisionKind::Allow ? IDOK : IDCANCEL);
}

// ── layout + control creation (idempotent; re-run when the AI section grows) ─

void rebuild(HWND hwnd, ConsentDlgState* st) {
    const ConsentRequest& cr = *st->req;
    const i18n::Strings& tr = *st->tr;

    // Capture editable state from any existing controls before we destroy them.
    if (st->hScope && ::IsWindow(st->hScope)) {
        wchar_t buf[2048]{};
        ::GetWindowTextW(st->hScope, buf, (int)std::size(buf));
        st->scopeText = buf;
    }
    if (st->hSandbox && ::IsWindow(st->hSandbox))
        st->sandboxChecked = (::SendMessageW(st->hSandbox, BM_GETCHECK, 0, 0) == BST_CHECKED);

    // Destroy previous children + tooltip.
    if (st->hTT) { ::DestroyWindow(st->hTT); st->hTT = nullptr; }
    {
        std::vector<HWND> kids;
        ::EnumChildWindows(hwnd, [](HWND h, LPARAM p) -> BOOL {
            reinterpret_cast<std::vector<HWND>*>(p)->push_back(h);
            return TRUE;
        }, reinterpret_cast<LPARAM>(&kids));
        for (HWND k : kids) ::DestroyWindow(k);
    }
    st->hScope = nullptr;
    st->hSandbox = nullptr;

    const int dpi = dpi_of(hwnd);
    auto S = [&](int v) { return ::MulDiv(v, dpi, 96); };

    // Layout constants
    const int strip    = S(4);
    const int margin   = S(16);
    const int leftPad  = strip + margin;
    const int contentW = S(560);   // wider so "Scope: [edit]" fits on one line
    const int gapY     = S(8);
    const int smallGapY = S(4);
    const int rowH     = S(20);
    const int labelH   = S(15);
    const int btnH     = S(30);
    const int subtleH  = S(14);
    const int panelPad = S(10);
    const int riskChipH = S(26);   // prominent risk chip height
    const int scopeEditH = S(24);

    // Strings — chrome + risk/action values come from the locale table
    // (same pattern as ProviderDlg). Gateway titles/possibleRisk are English
    // machine strings; the dialog rebuilds those for display.
    const std::wstring title = heading_for(cr, tr);
    std::wstring riskLine = std::wstring(tr.risk_label) + L": "
                          + risk_value(st->effectiveRisk, tr);
    if (st->reviewDone && st->review.riskRaised && st->effectiveRisk != st->risk) {
        riskLine += L"  (";
        riskLine += tr.risk_was;
        riskLine += L" ";
        riskLine += risk_value(st->risk, tr);
        riskLine += L")";
    }
    std::wstring toolLine = std::wstring(tr.tool_label) + L": ";
    if (!cr.request.tool.provider.empty())
        toolLine += widen(cr.request.tool.provider) + L" \u00b7 ";
    toolLine += cr.request.tool.toolId.empty()
        ? std::wstring(tr.unknown_tool)
        : widen(cr.request.tool.toolId);
    toolLine += L"     " + std::wstring(tr.action_label) + L": "
              + action_value(cr.request.action, tr);

    std::wstring riskRaiseLine;
    if (st->reviewDone && st->review.riskRaised) {
        riskRaiseLine = std::wstring(L"\u26a0 ") + tr.ai_raised + L": "
                        + risk_value(st->risk, tr) + L" \u2192 "
                        + risk_value(st->effectiveRisk, tr);
    }

    const std::wstring goal = goal_display(cr.userGoal, tr);
    const std::wstring why  = widen(cr.whyNeeded);
    std::wstring possibleRisk;
    {
        const std::string expected = std::string(to_string(st->risk)) + " risk";
        if (cr.possibleRisk.empty() || cr.possibleRisk == expected)
            possibleRisk = std::wstring(tr.risk_badge_pre)
                         + risk_value(st->risk, tr) + tr.risk_badge_post;
        else
            possibleRisk = widen(cr.possibleRisk);
    }
    // Build the preview rows. cmd:// execute targets show the raw command under
    // a "Command" label (the grant scope stays cmd://** — see
    // SecurityGateway::buildConsentRequest); screen:// app targets drop the
    // scheme; everything else (file paths, URLs, and the generic "key: value"
    // argument fallback for tools without a concrete target) shows under the
    // generic "Details" label.
    const wchar_t* resLabel = tr.resource_label;
    std::wstring resources;
    for (const auto& rp : cr.resourcePreview) {
        std::wstring line;
        if (rp.rfind("cmd://", 0) == 0) {
            line = widen(rp.substr(6));       // raw shell command
            resLabel = tr.command_label;
        } else if (rp.rfind("screen://", 0) == 0) {
            line = widen(rp.substr(9));       // app / window target (drop scheme)
        } else {
            line = widen(rp);
        }
        if (line.empty()) continue;           // bare screen:// (whole screen) → no detail row
        if (!resources.empty()) resources += L"\r\n";
        resources += line;
    }
    if (st->scopeText.empty()) st->scopeText = default_scope_for(cr);

    // AI review content
    std::wstring reasonText;
    std::wstring recommendLine;
    if (st->reviewDone) {
        reasonText = widen(st->review.reason);
        for (const auto& n : st->review.notes) {
            if (!reasonText.empty()) reasonText += L"\r\n";
            reasonText += L"\u2022 " + widen(n);
        }
        if (st->review.ok && !st->review.decision.empty()) {
            const wchar_t* dec = decision_value(st->review.decision, tr);
            recommendLine = std::wstring(tr.ai_recommend) + L" "
                          + (dec ? std::wstring(dec) : widen(st->review.decision));
            if (st->review.lifetime)
                recommendLine += std::wstring(L" \u00b7 ") + lifetime_short(*st->review.lifetime, tr);
        }
    }

    // Measure dynamic blocks
    HDC dc = ::GetDC(hwnd);
    HGDIOBJ oldF = ::SelectObject(dc, st->titleFont);
    const int titleH = (std::max)(measure_h(dc, title, contentW - S(22)), S(20));
    ::SelectObject(dc, st->baseFont);
    // Goal and why-needed: label + value on one row, long values get "…".
    const std::wstring goalLine = goal.empty() ? L""
        : (std::wstring(tr.goal_label) + L": " + goal);
    const std::wstring whyLine  = why.empty()  ? L""
        : (std::wstring(tr.why_label)  + L": " + why);
    const int goalH = goalLine.empty() ? 0 : rowH;
    const int whyH  = whyLine.empty()  ? 0 : rowH;
    const int possH = possibleRisk.empty() ? 0 : measure_h(dc, possibleRisk, contentW);
    int reasonH = 0;
    if (!reasonText.empty()) {
        const int innerW = contentW - panelPad * 2 - S(6);
        reasonH = (std::min)(measure_h(dc, reasonText, innerW) + S(6), S(120));
    }
    // Inline "Scope: [edit]" row — measure the label so the edit fills the rest.
    int scopeLabelW = 0;
    {
        RECT lr{0, 0, 0, 0};
        ::DrawTextW(dc, tr.scope_label, -1, &lr, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
        scopeLabelW = (int)(lr.right - lr.left) + S(8);
    }
    // Prominent risk chip — measure with the bold chip font.
    int riskChipW = 0;
    {
        ::SelectObject(dc, st->riskFont);
        RECT rr{0, 0, 0, 0};
        ::DrawTextW(dc, riskLine.c_str(), -1, &rr, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
        riskChipW = (int)(rr.right - rr.left) + S(28);   // horizontal padding both sides
        ::SelectObject(dc, st->baseFont);
    }
    ::SelectObject(dc, oldF);
    ::ReleaseDC(hwnd, dc);
    // Keep the scope edit usable even with a long localized label.
    const int scopeEditMinW = S(220);
    if (scopeLabelW > contentW - scopeEditMinW - S(8))
        scopeLabelW = contentW - scopeEditMinW - S(8);
    if (scopeLabelW < S(48)) scopeLabelW = S(48);
    if (riskChipW > contentW) riskChipW = contentW;

    const int resLines = resources.empty()
        ? 0 : (int)std::count(resources.begin(), resources.end(), L'\n') + 1;
    const int resBoxH = resLines == 0 ? 0 : (std::min)(resLines, 3) * S(17) + S(8);

    const bool showSandbox = !cr.sandboxBackends.empty();
    // AI-delegated allow buttons (AI once/session/always) are hidden for now;
    // the "Review with AI" + Apply-recommendation flow stays available.
    const bool showAiAuto  = false;

    // ── vertical layout ────────────────────────────────────────────────────
    int y = margin;
    const int yTitle = y;                    y += titleH + gapY;
    const int yRisk  = y;                    y += riskChipH + smallGapY;
    int yRiskRaise = 0;
    if (!riskRaiseLine.empty()) { yRiskRaise = y; y += rowH; }
    const int yTool  = y;                    y += rowH + gapY;

    int yGoal = 0;
    if (goalH) { yGoal = y; y += goalH + smallGapY; }
    int yWhy = 0;
    if (whyH)  { yWhy  = y; y += whyH  + smallGapY; }
    int yPoss = 0;
    if (possH) { yPoss = y; y += possH + smallGapY; }
    int yResLbl = 0, yRes = 0;
    if (resBoxH) { yResLbl = y; y += labelH; yRes = y; y += resBoxH + smallGapY; }

    // AI review panel
    int aiPanelTop = 0, aiPanelBottom = 0;
    int yAiHeader = 0, yAiReviewBtn = 0, yAiReason = 0, yAiRecommend = 0;
    if (st->showReviewSection) {
        y += smallGapY;
        aiPanelTop = y;
        const int innerTop = y + panelPad;
        yAiHeader = innerTop;
        int iy = innerTop + rowH;
        if (!st->reviewDone) {
            yAiReviewBtn = innerTop;   // button sits on the header row (right side)
            iy = innerTop + btnH;
        } else {
            if (reasonH) { yAiReason = iy; iy += reasonH + smallGapY; }
            if (!recommendLine.empty()) { yAiRecommend = iy; iy += btnH; }
        }
        aiPanelBottom = iy + panelPad;
        y = aiPanelBottom + gapY;
    }

    // Scope label + edit share one row; the guidance hint sits just below it.
    const int yScope    = y;  y += scopeEditH + smallGapY;
    const int yHint     = y;  y += subtleH + gapY * 2;
    int ySandbox = 0;
    if (showSandbox) { ySandbox = y; y += rowH + gapY; }

    // 2×2 allow grid
    const int btnGap = S(8);
    const int halfW  = (contentW - btnGap) / 2;
    const int yBtnA  = y;  y += btnH + btnGap;
    const int yBtnB  = y;  y += btnH + gapY;
    const int yBtnAi = y;
    if (showAiAuto) y += btnH + gapY;
    const int yBtnC  = y;  y += btnH;
    const int clientH = y + margin;
    const int clientW = leftPad + contentW + margin;

    st->stripH = clientH;
    if (st->showReviewSection) {
        st->aiPanelRc = RECT{ leftPad, aiPanelTop, leftPad + contentW, aiPanelBottom };
    } else {
        st->aiPanelRc = RECT{0, 0, 0, 0};
    }

    // Resize + center
    {
        RECT rc{0, 0, clientW, clientH};
        const DWORD style = (DWORD)::GetWindowLongPtrW(hwnd, GWL_STYLE);
        const DWORD ex    = (DWORD)::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        ::AdjustWindowRectEx(&rc, style, FALSE, ex);
        RECT area{};
        ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &area, 0);
        const int winW = rc.right - rc.left;
        const int winH = rc.bottom - rc.top;
        const int x = area.left + ((area.right - area.left) - winW) / 2;
        const int yy = area.top  + ((area.bottom - area.top) - winH) / 2;
        // HWND_TOPMOST (not HWND_TOP): the prompt is ownerless and often fires
        // over a full-screen console / another app's window, so it must stay
        // above everything — including across rebuilds after the AI review.
        ::SetWindowPos(hwnd, HWND_TOPMOST, x, yy, winW, winH, SWP_NOACTIVATE);
    }

    const int x0 = leftPad;

    // Lock glyph + title (title text kept pure for UIA name matching).
    mk_static(hwnd, L"\U0001F510", x0, yTitle, S(20), titleH, SS_LEFT);
    HWND hTitle = mk_static(hwnd, title, x0 + S(22), yTitle, contentW - S(22), titleH, SS_LEFT);

    // Prominent risk chip: a bold, risk-tinted pill. The window text keeps the
    // "Risk: <LEVEL>" form so UIA (and the automation tests) can still read it.
    if (st->hRiskBg) { ::DeleteObject(st->hRiskBg); st->hRiskBg = nullptr; }
    st->hRiskBg = ::CreateSolidBrush(risk_badge_bg(st->effectiveRisk, st->pal.dark));
    {
        HWND hRisk = mk_static(hwnd, riskLine, x0, yRisk, riskChipW, riskChipH,
                               SS_CENTER | SS_CENTERIMAGE, IDC_RISK_STATIC);
        ::SendMessageW(hRisk, WM_SETFONT, (WPARAM)st->riskFont, TRUE);
        ::SetPropW(hRisk, L"pmFont", (HANDLE)1);
    }
    if (!riskRaiseLine.empty())
        mk_static(hwnd, riskRaiseLine, x0, yRiskRaise, contentW, rowH, SS_LEFT, IDC_RISKRAISE_STATIC);
    mk_static(hwnd, toolLine, x0, yTool, contentW, rowH, SS_LEFT);

    if (goalH)
        mk_static(hwnd, goalLine, x0, yGoal, contentW, goalH, SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS);
    if (whyH)
        mk_static(hwnd, whyLine,  x0, yWhy,  contentW, whyH,  SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS);
    if (possH) {
        HWND hp = mk_static(hwnd, std::wstring(L"\u26a0 ") + possibleRisk, x0, yPoss, contentW, possH, SS_LEFT);
        ::SendMessageW(hp, WM_SETFONT, (WPARAM)st->subtleFont, TRUE);
        ::SetPropW(hp, L"pmFont", (HANDLE)1);
    }
    if (resBoxH) {
        mk_static(hwnd, resLabel, x0, yResLbl, contentW, labelH, SS_LEFT);
        ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", resources.c_str(),
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL |
            (resLines > 3 ? WS_VSCROLL : 0),
            x0, yRes, contentW, resBoxH, hwnd, nullptr,
            ::GetModuleHandleW(nullptr), nullptr);
    }

    // ── AI review panel ──────────────────────────────────────────────────────
    if (st->showReviewSection) {
        const int innerX = x0 + panelPad;
        const int innerW = contentW - panelPad * 2;
        mk_static(hwnd, tr.ai_title, innerX, yAiHeader, innerW - S(120), rowH, SS_LEFT, IDC_AI_TITLE);

        if (!st->reviewDone) {
            const std::wstring lbl = st->reviewing ? tr.ai_reviewing : tr.ai_review_btn;
            const int bw = S(140);
            HWND hRev = mk_obutton(hwnd, lbl, x0 + contentW - panelPad - bw, yAiReviewBtn, bw, btnH, IDC_AI_REVIEW);
            if (st->reviewing) ::EnableWindow(hRev, FALSE);
        } else {
            if (reasonH) {
                HWND hReason = ::CreateWindowExW(0, L"EDIT",
                    reasonText.c_str(),
                    WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                    innerX, yAiReason, innerW, reasonH, hwnd,
                    (HMENU)(UINT_PTR)IDC_AI_REASON, ::GetModuleHandleW(nullptr), nullptr);
                ::SendMessageW(hReason, WM_SETFONT, (WPARAM)st->subtleFont, TRUE);
                ::SetPropW(hReason, L"pmFont", (HANDLE)1);
            }
            if (!recommendLine.empty()) {
                const int bw = S(150);
                mk_static(hwnd, recommendLine, innerX, yAiRecommend + S(6), innerW - bw - S(8), labelH, SS_LEFT, IDC_AI_RECOMMEND);
                HWND hApply = mk_obutton(hwnd, st->aiReviewApplied ? tr.ai_applied : tr.ai_apply,
                    x0 + contentW - panelPad - bw, yAiRecommend, bw, btnH, IDC_AI_APPLY);
                if (st->aiReviewApplied) ::EnableWindow(hApply, FALSE);
            }
        }
    }

    // Scope — label and edit on a single row (label vertically centred to the edit).
    mk_static(hwnd, tr.scope_label, x0, yScope, scopeLabelW, scopeEditH,
              SS_LEFT | SS_CENTERIMAGE);
    const int scopeEditX = x0 + scopeLabelW + S(8);
    const int scopeEditW = contentW - scopeLabelW - S(8);
    st->hScope = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", st->scopeText.c_str(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        scopeEditX, yScope, scopeEditW, scopeEditH, hwnd,
        (HMENU)(UINT_PTR)IDC_SCOPE_EDIT, ::GetModuleHandleW(nullptr), nullptr);
    {
        HWND hHint = mk_static(hwnd, tr.scope_hint, x0, yHint, contentW, subtleH, SS_LEFT);
        ::SendMessageW(hHint, WM_SETFONT, (WPARAM)st->subtleFont, TRUE);
        ::SetPropW(hHint, L"pmFont", (HANDLE)1);
    }
    if (showSandbox) {
        st->hSandbox = ::CreateWindowExW(0, L"BUTTON", tr.sandbox_checkbox,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            x0, ySandbox, contentW, rowH, hwnd,
            (HMENU)(UINT_PTR)IDC_SANDBOX_CHECK, ::GetModuleHandleW(nullptr), nullptr);
        if (st->sandboxChecked)
            ::SendMessageW(st->hSandbox, BM_SETCHECK, BST_CHECKED, 0);
    }

    // Allow grid (2×2)
    mk_obutton(hwnd, tr.btn_allow_once,    x0,                    yBtnA, halfW, btnH, IDC_ALLOW_ONCE);
    mk_obutton(hwnd, tr.btn_allow_session, x0 + halfW + btnGap,   yBtnA, halfW, btnH, IDC_ALLOW_SESSION);
    mk_obutton(hwnd, tr.btn_allow_task,    x0,                    yBtnB, halfW, btnH, IDC_ALLOW_TASK);
    mk_obutton(hwnd, tr.btn_allow_always,  x0 + halfW + btnGap,   yBtnB, halfW, btnH, IDC_ALLOW_ALWAYS);
    if (showAiAuto) {
        const int thirdW = (contentW - btnGap * 2) / 3;
        mk_obutton(hwnd, tr.btn_ai_auto_once,    x0,                         yBtnAi, thirdW, btnH, IDC_AI_AUTO_ONCE);
        mk_obutton(hwnd, tr.btn_ai_auto_session, x0 + thirdW + btnGap,       yBtnAi, thirdW, btnH, IDC_AI_AUTO_SESSION);
        mk_obutton(hwnd, tr.btn_ai_auto_always,  x0 + (thirdW + btnGap) * 2, yBtnAi, thirdW, btnH, IDC_AI_AUTO_ALWAYS);
    }

    // Bottom row: Deny (right-aligned, default/safe choice).
    const int denyW = S(110);
    mk_obutton(hwnd, tr.btn_deny, x0 + contentW - denyW, yBtnC, denyW, btnH, IDC_DENY, /*def*/true);

    // Fonts + title font
    ::SendMessageW(hwnd, WM_SETFONT, (WPARAM)st->baseFont, TRUE);
    ::EnumChildWindows(hwnd, [](HWND h, LPARAM p) -> BOOL {
        // Do not clobber controls we already assigned a bespoke font to.
        if (!::GetPropW(h, L"pmFont"))
            ::SendMessageW(h, WM_SETFONT, (WPARAM)p, TRUE);
        return TRUE;
    }, (LPARAM)st->baseFont);
    ::SendMessageW(hTitle, WM_SETFONT, (WPARAM)st->titleFont, TRUE);

    // Dark theme on the editable/checkbox children (owner-draw buttons paint themselves).
    if (st->pal.dark) {
        ::EnumChildWindows(hwnd, [](HWND h, LPARAM) -> BOOL {
            wchar_t cls[32]{};
            ::GetClassNameW(h, cls, 31);
            if (lstrcmpiW(cls, L"EDIT") == 0 || lstrcmpiW(cls, L"BUTTON") == 0)
                ::SetWindowTheme(h, L"DarkMode_Explorer", nullptr);
            return TRUE;
        }, 0);
    }

    // Tooltips
    HWND hTT = ::CreateWindowExW(0, TOOLTIPS_CLASSW, nullptr,
        WS_POPUP | TTS_ALWAYSTIP | TTS_BALLOON, 0, 0, 0, 0,
        hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (hTT) {
        st->hTT = hTT;
        ::SendMessageW(hTT, TTM_SETMAXTIPWIDTH, 0, S(260));
        auto addTip = [&](int ctlId, const wchar_t* text) {
            HWND item = ::GetDlgItem(hwnd, ctlId);
            if (!item) return;
            TOOLINFOW ti{};
            ti.cbSize   = sizeof(ti);
            ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
            ti.hwnd     = hwnd;
            ti.uId      = (UINT_PTR)item;
            ti.lpszText = const_cast<LPWSTR>(text);
            ::SendMessageW(hTT, TTM_ADDTOOLW, 0, (LPARAM)&ti);
        };
        addTip(IDC_ALLOW_ONCE,    tr.tip_once);
        addTip(IDC_ALLOW_SESSION, tr.tip_session);
        addTip(IDC_ALLOW_TASK,    tr.tip_task);
        addTip(IDC_ALLOW_ALWAYS,  tr.tip_always);
        addTip(IDC_AI_REVIEW,     tr.tip_review);
        if (showAiAuto) {
            addTip(IDC_AI_AUTO_ONCE,    tr.tip_ai_auto);
            addTip(IDC_AI_AUTO_SESSION, tr.tip_ai_auto);
            addTip(IDC_AI_AUTO_ALWAYS,  tr.tip_ai_auto);
        }
    }

    ::SetFocus(::GetDlgItem(hwnd, IDC_DENY));
    ::InvalidateRect(hwnd, nullptr, TRUE);
}

// ── review worker ────────────────────────────────────────────────────────────

void start_review(HWND hwnd, ConsentDlgState* st) {
    if (!st->opts || !st->opts->runAiReview || st->reviewing || st->reviewDone) return;
    st->reviewing = true;
    st->chan = std::make_shared<ReviewChannel>();

    // Reflect the "Reviewing…" state on the button immediately.
    if (HWND b = ::GetDlgItem(hwnd, IDC_AI_REVIEW)) {
        ::SetWindowTextW(b, st->tr->ai_reviewing);
        ::EnableWindow(b, FALSE);
        ::InvalidateRect(b, nullptr, TRUE);
    }

    // Copy everything the worker needs so it never touches dialog-owned state.
    ConsentRequest reqCopy = *st->req;
    auto review_fn = st->opts->runAiReview;
    auto chan = st->chan;

    std::thread([hwnd, reqCopy = std::move(reqCopy), review_fn = std::move(review_fn), chan]() mutable {
        AiConsentReview r;
        try {
            r = review_fn(reqCopy);
        } catch (...) {
            r = AiConsentReview{};
            r.error = true;
            r.reason = "AI security review threw an exception.";
        }
        {
            std::lock_guard<std::mutex> lk(chan->mu);
            chan->result = std::move(r);
        }
        if (chan->alive.load(std::memory_order_acquire))
            ::PostMessageW(hwnd, WM_APP_REVIEW_DONE, 0, 0);
    }).detach();
}

void apply_recommendation(HWND hwnd, ConsentDlgState* st) {
    if (!st->reviewDone) return;
    const AiConsentReview& rv = st->review;

    if (!rv.scope.empty() && st->hScope)
        ::SetWindowTextW(st->hScope, widen(rv.scope).c_str());

    if (!rv.sandboxBackend.empty() && st->hSandbox) {
        bool offered = false;
        for (const auto& b : st->req->sandboxBackends)
            if (b == rv.sandboxBackend) { offered = true; break; }
        if (offered) {
            ::SendMessageW(st->hSandbox, BM_SETCHECK, BST_CHECKED, 0);
            st->sandboxChecked = true;
        }
    }

    st->aiReviewApplied = true;

    // A deny recommendation resolves immediately (mirrors the WebView card).
    if (rv.decision == "deny") {
        finish(hwnd, st, DecisionKind::Deny, false, GrantLifetime::Once);
        return;
    }

    // Mark the Apply button as applied + steer focus to the recommended lifetime.
    if (HWND a = ::GetDlgItem(hwnd, IDC_AI_APPLY)) {
        ::SetWindowTextW(a, st->tr->ai_applied);
        ::EnableWindow(a, FALSE);
        ::InvalidateRect(a, nullptr, TRUE);
    }
    if (rv.lifetime) {
        int id = IDC_ALLOW_SESSION;
        switch (*rv.lifetime) {
        case GrantLifetime::Once:      id = IDC_ALLOW_ONCE; break;
        case GrantLifetime::Task:      id = IDC_ALLOW_TASK; break;
        case GrantLifetime::Permanent: id = IDC_ALLOW_ALWAYS; break;
        default:                       id = IDC_ALLOW_SESSION; break;
        }
        if (HWND b = ::GetDlgItem(hwnd, id)) ::SetFocus(b);
    }
}

// ── dialog proc ───────────────────────────────────────────────────────────────

INT_PTR CALLBACK ConsentDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* st = reinterpret_cast<ConsentDlgState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {

    case WM_INITDIALOG: {
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, lp);
        st = reinterpret_cast<ConsentDlgState*>(lp);
        const ConsentRequest& cr = *st->req;
        st->risk = cr.risk;
        st->effectiveRisk = cr.risk;
        st->showReviewSection = st->opts && st->opts->runAiReview && cr.aiAutoAvailable;

        const int dpi = dpi_of(hwnd);
        st->baseFont = ::CreateFontW(-::MulDiv(9, dpi, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        st->titleFont = ::CreateFontW(-::MulDiv(13, dpi, 72), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        st->subtleFont = ::CreateFontW(-::MulDiv(8, dpi, 72), 0, 0, 0, FW_NORMAL, TRUE, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        st->riskFont = ::CreateFontW(-::MulDiv(10, dpi, 72), 0, 0, 0, FW_BOLD, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        st->hDlgBg   = ::CreateSolidBrush(st->pal.window_bg);
        st->hCtlBg   = ::CreateSolidBrush(st->pal.control_bg);
        st->hPanelBg = ::CreateSolidBrush(st->pal.panel_bg);

        apply_dark_titlebar(hwnd, st->pal.dark);
        rebuild(hwnd, st);

        // Ownerless modal fired from a CLI/realtime session: force it topmost and
        // steal foreground so it can never hide behind the console or the app the
        // agent is driving. AttachThreadInput lets SetForegroundWindow succeed even
        // though the calling thread does not currently own the foreground.
        ::SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        {
            const DWORD fg = ::GetWindowThreadProcessId(::GetForegroundWindow(), nullptr);
            const DWORD me = ::GetCurrentThreadId();
            if (fg && fg != me) ::AttachThreadInput(fg, me, TRUE);
            ::BringWindowToTop(hwnd);
            ::SetForegroundWindow(hwnd);
            ::SetActiveWindow(hwnd);
            if (fg && fg != me) ::AttachThreadInput(fg, me, FALSE);
        }
        return FALSE;
    }

    case WM_APP_REVIEW_DONE: {
        if (!st || !st->chan) return TRUE;
        {
            std::lock_guard<std::mutex> lk(st->chan->mu);
            st->review = st->chan->result;
        }
        st->reviewing = false;
        st->reviewDone = true;
        if (st->review.riskRaised || risk_rank(st->review.assessedRisk) > risk_rank(st->risk)) {
            if (risk_rank(st->review.assessedRisk) > risk_rank(st->effectiveRisk))
                st->effectiveRisk = st->review.assessedRisk;
            st->review.riskRaised = st->review.riskRaised
                || risk_rank(st->effectiveRisk) > risk_rank(st->risk);
        }
        rebuild(hwnd, st);
        return TRUE;
    }

    case WM_DRAWITEM: {
        auto* di = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if (st && di && di->CtlType == ODT_BUTTON) {
            draw_owner_button(st, di);
            return TRUE;
        }
        break;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC hdc = ::BeginPaint(hwnd, &ps);
        if (st) {
            const int dpi = dpi_of(hwnd);
            const int strip = ::MulDiv(4, dpi, 96);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);

            HBRUSH br = ::CreateSolidBrush(risk_strip(st->effectiveRisk, st->pal.dark));
            RECT stripRc{0, 0, strip, rc.bottom};
            ::FillRect(hdc, &stripRc, br);
            ::DeleteObject(br);

            // AI review panel background + border.
            if (st->showReviewSection && st->aiPanelRc.bottom > st->aiPanelRc.top) {
                const int rad = ::MulDiv(6, dpi, 96);
                HBRUSH pb = ::CreateSolidBrush(st->pal.panel_bg);
                HPEN   pp = ::CreatePen(PS_SOLID, 1, st->pal.panel_border);
                HGDIOBJ ob = ::SelectObject(hdc, pb);
                HGDIOBJ op = ::SelectObject(hdc, pp);
                ::RoundRect(hdc, st->aiPanelRc.left, st->aiPanelRc.top,
                            st->aiPanelRc.right, st->aiPanelRc.bottom, rad * 2, rad * 2);
                ::SelectObject(hdc, ob);
                ::SelectObject(hdc, op);
                ::DeleteObject(pb);
                ::DeleteObject(pp);
            }
        }
        ::EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLORDLG:
        if (st && st->hDlgBg) {
            ::SetBkColor((HDC)wp, st->pal.window_bg);
            ::SetTextColor((HDC)wp, st->pal.window_fg);
            return (INT_PTR)st->hDlgBg;
        }
        break;

    case WM_CTLCOLORSTATIC:
        if (st && st->hDlgBg) {
            HDC hdc = (HDC)wp;
            const int ctlId = ::GetDlgCtrlID((HWND)lp);
            // Risk chip: bold risk-coloured text on a risk-tinted fill.
            if (ctlId == IDC_RISK_STATIC && st->hRiskBg) {
                ::SetBkColor(hdc, risk_badge_bg(st->effectiveRisk, st->pal.dark));
                ::SetTextColor(hdc, risk_fg(st->effectiveRisk, st->pal.dark));
                return (INT_PTR)st->hRiskBg;
            }
            // The "AI raised risk" note carries the risk colour on the window bg.
            if (ctlId == IDC_RISKRAISE_STATIC) {
                ::SetBkColor(hdc, st->pal.window_bg);
                ::SetTextColor(hdc, risk_fg(st->effectiveRisk, st->pal.dark));
                return (INT_PTR)st->hDlgBg;
            }
            // AI-panel children (header/recommend line + the read-only reason
            // EDIT, which also routes here) paint on the panel background.
            if ((ctlId == IDC_AI_TITLE || ctlId == IDC_AI_RECOMMEND || ctlId == IDC_AI_REASON)
                && st->hPanelBg) {
                ::SetBkColor(hdc, st->pal.panel_bg);
                ::SetTextColor(hdc, ctlId == IDC_AI_REASON ? st->pal.subtle : st->pal.window_fg);
                return (INT_PTR)st->hPanelBg;
            }
            ::SetBkColor(hdc, st->pal.window_bg);
            ::SetTextColor(hdc, st->pal.window_fg);
            return (INT_PTR)st->hDlgBg;
        }
        break;

    case WM_CTLCOLOREDIT:
        if (st && st->hCtlBg) {
            ::SetBkColor((HDC)wp, st->pal.control_bg);
            ::SetTextColor((HDC)wp, st->pal.control_fg);
            return (INT_PTR)st->hCtlBg;
        }
        break;

    case WM_COMMAND: {
        if (!st) break;
        switch (LOWORD(wp)) {
        case IDC_ALLOW_ONCE:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Once);   return TRUE;
        case IDC_ALLOW_SESSION:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Session); return TRUE;
        case IDC_ALLOW_TASK:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Task);    return TRUE;
        case IDC_ALLOW_ALWAYS:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Permanent); return TRUE;
        case IDC_AI_AUTO_ONCE:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Once, true);   return TRUE;
        case IDC_AI_AUTO_SESSION:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Session, true); return TRUE;
        case IDC_AI_AUTO_ALWAYS:
            finish(hwnd, st, DecisionKind::Allow, false, GrantLifetime::Permanent, true); return TRUE;
        case IDC_AI_REVIEW:
            start_review(hwnd, st);   return TRUE;
        case IDC_AI_APPLY:
            apply_recommendation(hwnd, st); return TRUE;
        case IDCANCEL:
            finish(hwnd, st, DecisionKind::Deny, false, GrantLifetime::Once);
            return TRUE;
        default: break;
        }
        break;
    }

    case WM_DESTROY:
        if (st) {
            if (st->chan) st->chan->alive.store(false, std::memory_order_release);
            if (st->hTT)      { ::DestroyWindow(st->hTT); st->hTT = nullptr; }
            if (st->hDlgBg)   { ::DeleteObject(st->hDlgBg);   st->hDlgBg   = nullptr; }
            if (st->hCtlBg)   { ::DeleteObject(st->hCtlBg);   st->hCtlBg   = nullptr; }
            if (st->hPanelBg) { ::DeleteObject(st->hPanelBg); st->hPanelBg = nullptr; }
            if (st->hRiskBg)  { ::DeleteObject(st->hRiskBg);  st->hRiskBg  = nullptr; }
            if (st->baseFont)  { ::DeleteObject(st->baseFont);  st->baseFont  = nullptr; }
            if (st->titleFont) { ::DeleteObject(st->titleFont); st->titleFont = nullptr; }
            if (st->subtleFont){ ::DeleteObject(st->subtleFont);st->subtleFont= nullptr; }
            if (st->riskFont)  { ::DeleteObject(st->riskFont);  st->riskFont  = nullptr; }
        }
        break;

    case WM_CLOSE:
        if (st) finish(hwnd, st, DecisionKind::Deny, false, GrantLifetime::Once);
        else    ::EndDialog(hwnd, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// ── in-memory dialog template (no .rc) ───────────────────────────────────────

INT_PTR run_dialog(ConsentDlgState& state) {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_BAR_CLASSES};
    ::InitCommonControlsEx(&icc);

    alignas(DWORD) BYTE buf[512]{};
    auto* dlg = reinterpret_cast<DLGTEMPLATE*>(buf);
    dlg->style = DS_MODALFRAME | DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
    dlg->cdit  = 0;
    dlg->x = 0; dlg->y = 0;
    dlg->cx = 300; dlg->cy = 220;   // overridden in rebuild()

    WORD* p = reinterpret_cast<WORD*>(dlg + 1);
    *p++ = 0;  // menu
    *p++ = 0;  // class
    {
        const wchar_t* t = state.tr->window_title;
        const size_t n = wcslen(t) + 1;
        memcpy(p, t, n * sizeof(wchar_t));
        p += n;
    }
    *p++ = 9;   // font point size
    {
        const wchar_t f[] = L"Segoe UI";
        memcpy(p, f, sizeof(f));
    }

    return ::DialogBoxIndirectParamW(::GetModuleHandleW(nullptr), dlg, nullptr,
        ConsentDlgProc, reinterpret_cast<LPARAM>(&state));
}

} // namespace

// ── public API ────────────────────────────────────────────────────────────────

ConsentResult show_consent_dialog(const ConsentRequest& request,
                                  const ConsentUiOptions& opts) {
    ConsentDlgState state;
    state.req  = &request;
    state.opts = &opts;
    state.tr   = &i18n::strings_for(opts.language);
    state.pal  = make_palette(opts.dark);
    (void)run_dialog(state);
    return state.result;
}

} // namespace pm::security::ui

#endif // _WIN32
