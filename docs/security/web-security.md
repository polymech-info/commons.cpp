# Web surface security — host-bridge hardening

Status: implemented (except Mark-of-the-Web provenance and xblox origin pin,
deferred — see [Deferred](#deferred)). Host-bridge origin pinning is
**deny-by-default** (own-app vhost / loopback `*_DEV_URL` only). Inline
`commandRun` and shell-open of non-builtin files from user pages go through
the existing consent dialog.

This document records the hardening applied to the embedded WebView2 surfaces
(viewer, chat, xblox, home, settings) and the document-rendering pipeline, to
close the path by which untrusted file content could reach the native host
bridge and execute commands.

---

## Threat model

The viewer opens arbitrary user-chosen files (`.md`, `.page`, `.xblox`, HTML,
…). Rendered content runs in the same WebView2 realm as the **host bridge**
(`window.pm` / `chrome.webview.postMessage`). The bridge exposes `commandRun`,
which can launch processes (`cliCommand` → `tanit-cli`, or `externalCommand`
→ an arbitrary executable / shell line) via `CreateProcessW`.

Primary risk: **arbitrary code execution from merely opening a document.**
Concretely, markdown was rendered with `rehype-raw`, so an authored
`<script>` (or `onerror=`, `javascript:` URL) executed in the host realm and
could call:

```js
window.pm.host.rpc({ method: "commandRun",
  externalCommand: { mode: "shell", shellLine: "calc.exe & whoami" } });
```

…with no user interaction and no allowlist.

This is an automation/developer tool — running commands from trusted documents
is an intended feature. So the goal is **not** to remove command execution, but
to (a) eliminate the *silent / no-interaction* path, (b) bound the blast radius,
and (c) give admins policy control.

---

## Defense layers

| # | Layer | Stops | Default |
|---|-------|-------|---------|
| 1 | Markdown sanitization (`rehype-sanitize`) | Injected `<script>` / event handlers / `javascript:` reaching the realm | always on |
| 2 | Run gate + GPO (`Web.DisableCommandRun`, `Web.DisableExternalShell`) | Org-level lockdown of inline run / arbitrary shell | allowed (opt-in lockdown) |
| 3 | Origin pinning on web messages | Cross-origin / injected frames / browser tabs posting to the bridge | always on (deny-by-default) |
| 4 | DevTools gating | Interactive bridge use from a shipped binary's F12 console | off in production |
| 5 | ~~Content-Security-Policy on the bundle HTML~~ | Removed — nonce inject scanned/copied megabyte inlined HTML on serve with no first-paint win; markdown sanitization remains the primary XSS gate | removed |
| 6 | Consent dialog (`ConsentDelegate` / `ConsentDlg`) | Page-authored `cliCommand` / `externalCommand` (ButtonWidget) and shell-open of files outside the install tree | always on (Ask; persistable grant) |

Layers are independent; #1 is the keystone (it alone removes the no-click RCE),
the rest are defense-in-depth and policy.

---

## Per-file changes

### 1. Markdown sanitization

**`apps/viewer-next/src/viewers/markdown/MarkdownRenderer.tsx`**
- Added `rehype-sanitize` after `rehype-raw` in the rehype plugin chain.
- `rehype-raw` is kept so benign inline HTML (`<details>`, `<kbd>`, `<sub>`…)
  still renders, but every node now passes through the sanitizer, which strips
  `<script>`, event-handler attributes, and dangerous URL protocols.
- A custom schema (`markdownSanitizeSchema`) extends the GitHub default only to
  allow inline `data:` images.
- Fenced ` ```xblox ` / ` ```mermaid ` blocks are MDAST **code** nodes, not raw
  HTML, so they keep their `language-*` class and continue to render/run. The
  sanitizer does not touch them.

```tsx
rehypePlugins={[rehypeRaw, [rehypeSanitize, markdownSanitizeSchema]]}
```

**`apps/viewer-next/package.json`**
- Added dependency `rehype-sanitize` (`^6.0.0`), matching `rehype-raw@^7`.

> Note: `MarkdownRenderer.tsx` is the shared renderer source. Other apps that
> bundle it (e.g. xblox, home) pick up the change on their next embed build.

### 2. Run gate + GPO policy keys

**`src/policy/policy.cpp`** — registered two keys under a new `Web` section so
they appear in `gpo effective` and the generated ADMX:
- `Web.DisableCommandRun`
- `Web.DisableExternalShell`

Both follow the `Disable*` naming convention → builtin default `0` (allowed), so
the automation workflow is unaffected until an admin opts into lockdown.

**`src/policy/app_policy.hpp` / `app_policy.cpp`** — new accessor:

```cpp
// kind: "cli" (tanit-cli verb) | "external" (arbitrary exe / shell line)
bool web_command_run_allowed(std::string_view kind);
//   Web.DisableCommandRun=1   → blocks every inline run (cli + external)
//   Web.DisableExternalShell=1 → blocks only the arbitrary-process path
```

`build_gpo_settings()` now also emits `webDisableCommandRun` /
`webDisableExternalShell` into `window.GPO_SETTINGS`. A no-op stub is provided
for non-`FEATURE_WINDOWS_GPO` builds.

**`src/core/web_command_host.cpp`** — `run_command()` consults the gate before
starting any inline `cliCommand` / `externalCommand` process, then asks for
consent (see §7).

```cpp
const bool isExternal = request.contains("externalCommand");
if (!pm::policy::web_command_run_allowed(isExternal ? "external" : "cli")) {
    // logged + thrown back to the web caller as a policy error
}
if (!pm::security::confirm_web_command_run(fromId, request))
    throw std::runtime_error("command execution denied");
```

Curated command ids, app commands, ribbon commands, and the xblox run RPC are
unchanged — only the inline process path is gated.

### 3. Origin pinning on web messages

Trust is the **sending document** (`ICoreWebView2WebMessageReceivedEventArgs::get_Source`),
not the bus surface id (`fromId`). Shared helper:
`src/win/web/webview_bridge_origin.hpp`.

**Own-app** (full host barrel: `providerRpc`, shell open, `commandRun`, …):

- signed-bundle / folder-mapped vhost: `https://<expected_vhost>/…`
- explicit loopback HMR origin from a per-app `*_DEV_URL` env var
  (`localhost`, `127.0.0.1`, `::1`, `*.localhost`). Non-loopback values are
  ignored even if the env var is set. **Compile-gated:** shipping /
  `FEATURE_COMMAND_TEST=OFF` builds ignore these vars entirely (same gate as
  DevTools).

**Untrusted** (browser tabs, markdown-asset iframes on `pm-md.localhost`,
`about:blank` unless the surface opted into NavigateToString of first-party
HTML, random https): caption / console chrome only
(`cweb_console`, `vw_console`, min/max/close, resize). Privileged messages
are dropped and logged.

| Surface | Pin |
|---------|-----|
| `CWebView` (settings, search, perf, console, popups) | deny-by-default; vhost+bundle/folder, or `trustedDevOrigin` |
| `ChatWebPanel` | `originVhost` or `PM_CHAT_DEV_URL` (loopback) |
| `ViewerWebPanel` | served bundle vhost or `PM_VIEWER_DEV_URL` (loopback) |
| `BrowserWebPanel` | no vhost/bundle → untrusted; does not forward `providerRpc` / shell |
| xblox (`CBlockView`) | **not pinned this round** (deferred) |

Shipping binaries (`FEATURE_COMMAND_TEST=OFF`) never treat `http://localhost:PORT`
as own-app and never navigate to a `*_DEV_URL`. `allowExternalNav` on a surface
does not widen the bridge.

### 4. DevTools gating

**`src/win/web/CWebView.cpp`** — `put_AreDevToolsEnabled` is now compile-gated:

```cpp
#if defined(FEATURE_COMMAND_TEST) && FEATURE_COMMAND_TEST
    const BOOL devToolsOn = impl->opts.devToolsEnabled ? TRUE : FALSE;
#else
    const BOOL devToolsOn = FALSE;   // forced off in production
#endif
```

DevTools remain available in `FEATURE_COMMAND_TEST` builds (the automation/dev
workflow) but are forced off in shipped binaries regardless of per-surface
opts, so the bridge cannot be driven interactively from an F12 console.

### 5. Content-Security-Policy on the bundle HTML — removed

Nonce CSP (`PM_BUNDLE_CSP` / `inject_script_nonce`) was removed from
`web_bundle_host.cpp`. Stamping nonces required scanning/copying the full
inlined HTML on serve and did not help first paint; layer-1 markdown
sanitization remains the primary XSS gate.

### 5a. Local Monaco editor (no CDN)

`@monaco-editor/react` defaults to loading the Monaco AMD build from
`cdn.jsdelivr.net` at runtime, which breaks the self-contained/offline
guarantee (and formerly broke under the removed bundle CSP). This affected
every Monaco surface: settings, the viewer editor, xblox (variable builder),
and home.

**Fix — bundle Monaco from its ESM source through webpack:**

- **`apps/viewer-next/src/viewers/editor/monacoSetup.ts`** (new) — imports
  `monaco-editor` (ESM), wires `self.MonacoEnvironment.getWorker` to webpack-5
  native workers (`new Worker(new URL('monaco-editor/esm/vs/.../*.worker.js',
  import.meta.url))`), and calls `loader.config({ monaco })` so the React
  wrapper uses the bundled instance and **never fetches the CDN**.
- **`apps/viewer-next/src/viewers/editor/MonacoTextEditor.tsx`** — imports
  `./monacoSetup` for side effects. This file is the single shared entry every
  Monaco surface goes through, so the fix applies everywhere at once.

Result: Monaco core is bundled (inlined into the app HTML), and its language /
worker chunks are emitted as **same-origin** `.js`/`.ttf` assets packed into the
`.pmbundle`. All of it now resolves under `script-src 'self'`, `worker-src
'self'`, and `font-src 'self'` — no CDN, no CSP violation. The lingering
`https://cdn.jsdelivr.net/...` string in `@monaco-editor/loader` is an inert
default-config constant (never used once an instance is supplied).

**Bundle size — source maps dropped in production.** Bundling all of Monaco
(~25 MiB ESM) made the prior `inline-source-map` / `source-map` devtool inflate
each bundle massively (settings went to ~70 MiB). Since **DevTools are disabled
in production builds** (§ "DevTools off"), those maps are unusable dead weight,
so production `devtool` is now `false` for the Monaco-bundling apps
(`settings`, `xblox`, `viewer-next`; `home` was already `false`). Settings
dropped 70 MiB → 14 MiB; dev builds keep `eval-source-map`.

> All four Monaco bundles must be **rebuilt + re-signed** after this change
> (`npm run build:{settings,viewer,xblox,home}-bundle`) — older bundles still
> reference the CDN and will fail under CSP.

### 6. ADMX / ADML templates

**`scripts/generate-admx.mjs`** — added a `PM_Web` category and the two web
policies (`Web.DisableCommandRun`, `Web.DisableExternalShell`) with display
names + explain text, plus the `cat_PM_Web` string and its inclusion in the
shared category id list. Generated automatically on `npm run build:cpp`
(confirmed: 62 policies across 8 categories).

### 7. Consent for user-page commandRun / shell-open

Origin pinning does not cover **own-app user pages** (a `.page` / home widget
that uses `ButtonWidget` with inline `cliCommand` / `externalCommand`). Those
messages are already on a trusted origin. The remaining gate is the existing
consent machinery (`ConsentDelegate` / `Win32ConsentDelegate` / `ConsentDlg`),
the same dialog as `tanit://` protocol activation.

**`src/security/web_host_consent.hpp`** — `confirm_web_command_run` /
`confirm_web_shell_open`. `Actor::User` + `Action::Execute`, persist grants
via `upsert_grant`. Win32 modal only — does not reuse the chat WebView
consent card (that surface is for the LLM agent). Default **Always** for a
`.page` is the canonical file path plus `workspaceId` = that file's parent
folder, not `cmd://**`.

**`src/security/PolicyEngine.cpp`** — LIGHT: `User` + `Execute` is **Ask**
(so the dialog can appear). LLM / plugin / MCP execute stays **Deny**.

**Call sites**

- `web_command_host.cpp` `run_command` — after GPO, before process start,
  only when the request has `cliCommand` or `externalCommand`.
- `CWebViewManager` `hostShellOpenPath` / `EditDocument` / `ExploreFolder`.
- `Mainfrm_Web` `openPathDefault` / `openUrlDefault` / `openFolderInExplorer` /
  `revealPathInExplorer`.

Shell-open skips settings/chat/search/perf/console chrome and any path under
the install directory. HTTP(S) URLs always ask from a user page.

`apps/shared/widgets/ButtonWidget.tsx` is unchanged: the native RPC now
fails closed until the user allows.

---

## GPO reference (admin)

| Key (HKLM/HKCU `…\Policies\PolyMech\Web`) | Type | Default | Effect |
|---|---|---|---|
| `DisableCommandRun` | DWORD | 0 | `1` blocks all inline command execution from web surfaces (cli + external). |
| `DisableExternalShell` | DWORD | 0 | `1` blocks only the arbitrary-process / shell path; curated ids + `tanit-cli` verbs still run. |

Both default to **allowed** so the automation workflow works out of the box;
set to `1` to lock down. See `docs/public/v1.0/gpo.md` for the policy plumbing
pattern and `window.GPO_SETTINGS` exposure.

---

## Environment variables (dev / ops)

`*_DEV_URL` HMR origins are **FEATURE_COMMAND_TEST builds only** (the same
compile gate as DevTools). Store / `FEATURE_COMMAND_TEST=OFF` binaries ignore
them for both navigation and bridge trust.

| Variable | Where | Effect |
|---|---|---|
| `PM_BUNDLE_ALLOW_UNSIGNED=1` | `web_bundle_host.cpp` | (pre-existing) serve an unsigned bundle in dev. |
| `PM_CHAT_DEV_URL` | `ChatWebPanel.cpp` | HMR origin; loopback + `FEATURE_COMMAND_TEST` only. |
| `PM_VIEWER_DEV_URL` | `ViewerWebPanel.cpp` | same, viewer (`--viewer-dev` CLI too). |
| `PM_SETTINGS_DEV_URL` | `CSettingsWebView.cpp` | same, settings (`CWebViewOptions.trustedDevOrigin`). |
| `PM_SEARCH_DEV_URL` | `CSearchView.cpp` | same, search. |
| `PM_PERFUI_DEV_URL` | `CPerfView.cpp` | same, perf overlay. |
| `PM_SHELL_DEV_URL` | `CWebConsole.cpp` | same, console (`PM_CONSOLE_URL` legacy alias). |

---

## Verification

- **Builds:** `npm run build:cpp` (C++ + ADMX) and
  `apps/viewer-next` `npm run build:embed`; re-pack/sign with
  `npm run bundle:viewer` (signature verified against the pinned key).
- **Markdown:** an `.md` containing `<script>…</script>` or
  `<img onerror=…>` must render inert; ` ```xblox ` / ` ```mermaid ` fences must
  still render and run.
- **Run gate:** with `Web.DisableExternalShell=1`, an `externalCommand` from a
  web surface is rejected while `cliCommand` / curated ids still run;
  `Web.DisableCommandRun=1` rejects both.
- **Consent:** a viewer/home page `ButtonWidget` with `cliCommand` or
  `externalCommand` must show the Win32 consent dialog before the process
  starts; Deny leaves the widget in fault and does not launch. Catalog
  `id` / `appCommand` / `ribbonCommand` must not prompt. Shell-open of a
  path outside the install directory from preview/home/browser/xblox must
  prompt; settings/chat/search chrome and files under the exe directory
  must not.
- **Origin pinning:** web messages whose `Source` is not the surface vhost
  (and not the configured loopback `*_DEV_URL`) are dropped (logged
  `[cweb]` / `[chat-web]` / `[viewer-web] drop web-message from untrusted origin`).
  A page in the in-app browser must not reach `providerRpc` / `hostShellOpenPath`.
  HTML/markdown served from the markdown-assets vhost must not reach the viewer
  barrel.

---

## Conclusions

- The live hole was **not** a missing nonce. RPC nonces were never shipped;
  CSP nonces were added then removed. The shared `HandleBuiltinMessage` barrel
  had no origin allowlist, and `BrowserWebPanel` forwarded remote pages into it.
- **Origin pin + deny-by-default** is the host-bridge gate: own apps keep
  access; everything else (browser, URL-loaded HTML, markdown iframes) cannot
  call the host.
- Own-app **user pages** (viewer/home widgets using `ButtonWidget`) can still
  author `cliCommand` / `externalCommand`. That path is not a catalog command:
  it now asks through `SecurityGateway` + `Win32ConsentDelegate` (the same
  dialog as `tanit://`). LIGHT policy asks for `Actor::User` + `Execute`;
  agent/plugin execute stays deny. Catalog `id` / `appCommand` / `ribbonCommand`
  stay a `WM_COMMAND` hop and do not prompt.
- Shell-open (`hostShellOpenPath`, `openPathDefault`, …) asks for paths
  outside the install tree from preview/home/browser/xblox. Settings/chat/search
  chrome and bundled files skip. Executable-extension blocklist in
  `default_shell` still applies after consent.
- `fromId` is reply routing, not authorization. Pin `args->get_Source()`, not
  the WebView's current URL (that can lag behind an iframe / navigation).
- Dev servers stay usable without widening production: `*_DEV_URL` is ignored
  unless `FEATURE_COMMAND_TEST` is on, and even then only loopback hosts are
  trusted.
- FileViewer “open file/folder” RPCs stay on the **viewer** origin (own-app).
  Untrusted document content in an iframe does not inherit that.
- xblox still rides the shared barrel without the origin pin. Consent covers
  its inline `commandRun` / shell-open; pinning that surface remains a
  separate follow-up.

---

## Deferred

**xblox origin pin** — `CBlockView` still accepts the shared barrel without
`args->get_Source()` pinning. Apply the same `webview_bridge_origin` helper
when that surface is hardened; do not paper over it with consent dialogs.

**Mark-of-the-Web provenance gate** — distinguishing locally-authored documents
from downloaded/untrusted ones (NTFS `Zone.Identifier`, `ZoneId >= 3`) and
denying command execution for untrusted documents by default, with a
deny-by-default `Web.AllowMarkOfWebCommands` GPO, a `Web.TrustedDocumentRoots`
allowlist, and a Protected-View-style "Enable commands" banner. This is the
remaining piece for bounding the *click-driven / xblox auto-run* path on hostile
documents; #1 already removes the no-click vector. Open question to resolve
first: whether opening an `.xblox` (or a `.md` with an xblox block)
auto-executes or waits for a user action.
