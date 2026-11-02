#include "policy/policy_catalog.hpp"

#include "host/services.hpp"

#include <algorithm>
#include <cstddef>

namespace pm::policy {

namespace {

// ── Categories ─────────────────────────────────────────────────────────────────
// PM_Image is the root; everything else hangs off it. Ordered parents-first so the
// ADMX generator can emit them top-down.
const std::vector<PolicyCategory> k_categories = {
    { "PM_Image",                "",            "Tanit" },
    { "PM_Agent",                "PM_Image",    "Agent" },
    { "PM_Agent_Tools",          "PM_Agent",    "Tools" },
    { "PM_Providers",            "PM_Image",    "AI Providers" },
    { "PM_Security",             "PM_Image",    "Security" },
    { "PM_Security_Verification","PM_Security", "Verification" },
    { "PM_UI",                   "PM_Image",    "User Interface" },
    { "PM_UI_Panels",            "PM_UI",       "Panels" },
    { "PM_UI_Settings",          "PM_UI",       "Settings & Tabs" },
    { "PM_UI_Editors",           "PM_UI",       "Editors" },
    { "PM_CLI",                  "PM_Image",    "CLI Commands" },
    { "PM_Network",              "PM_Image",    "Remote Locations" },
    { "PM_Local",                "PM_Image",    "Local Inference Backends" },
    { "PM_Web",                  "PM_Image",    "Web Surfaces" },
};

PolicyEntry b(std::string key, std::string cat, std::string web, bool def_on,
              std::string disp, std::string explain) {
    PolicyEntry e;
    e.key = std::move(key);
    e.category = std::move(cat);
    e.web_key = std::move(web);
    e.type = PolicyType::Bool;
    e.default_on = def_on;
    e.display_name = std::move(disp);
    e.explain = std::move(explain);
    return e;
}

PolicyEntry hklm_bool(std::string key, std::string cat, std::string web, bool def_on,
                      std::string disp, std::string explain) {
    PolicyEntry e = b(std::move(key), std::move(cat), std::move(web), def_on,
                      std::move(disp), std::move(explain));
    e.hklm_only = true;
    return e;
}

PolicyEntry multi(std::string key, std::string cat, std::string web,
                  std::string disp, std::string explain) {
    PolicyEntry e;
    e.key = std::move(key);
    e.category = std::move(cat);
    e.web_key = std::move(web);
    e.type = PolicyType::Multi;
    e.display_name = std::move(disp);
    e.explain = std::move(explain);
    return e;
}

PolicyEntry ver(std::string key, std::string disp, std::string explain) {
    PolicyEntry e;
    e.key = std::move(key);
    e.category = "PM_Security_Verification";
    e.type = PolicyType::VerEnum;
    e.hklm_only = true;
    e.display_name = std::move(disp);
    e.explain = std::move(explain);
    return e;
}

const char* type_name(PolicyType t) {
    switch (t) {
    case PolicyType::Bool:    return "bool";
    case PolicyType::Multi:   return "multi";
    case PolicyType::Str:     return "str";
    case PolicyType::VerEnum: return "ver_enum";
    case PolicyType::EnumStr: return "enum_str";
    }
    return "bool";
}

// ── Catalog assembly ───────────────────────────────────────────────────────────

std::vector<PolicyEntry> build_catalog() {
    std::vector<PolicyEntry> c;

    // ── Agent ────────────────────────────────────────────────────────────────
    c.push_back(b("Agent.EnableMcpClient", "PM_Agent", "agent.mcpClient", true,
        "Enable MCP Client",
        "Allow the agent to connect to external MCP (Model Context Protocol) servers.\n\n"
        "When enabled (default) the agent can discover and call tools provided by MCP servers. "
        "When disabled all MCP connections are blocked regardless of user settings."));
    c.push_back(b("Agent.EnableSkills", "PM_Agent", "agent.skills", true,
        "Enable User Skills",
        "Allow the agent to load and invoke user-installed skills (SKILL.md packages).\n\n"
        "When disabled the skills tab is hidden and no skill is executed."));
    c.push_back(b("Agent.EnableComputerUse", "PM_Agent", "agent.computerUse", true,
        "Enable Computer-Use Tools",
        "Allow the agent to use screen-capture, mouse, keyboard, and in-app WebView browser-use tools.\n\n"
        "Disable this policy on shared or managed desktops where UI automation must be restricted. "
        "This is a coarse switch over the computer-use tool group and also turns off browser-use. "
        "Use Agent.EnableBrowserUse to disable WebView tools without turning off desktop computer-use."));
    c.push_back(b("Agent.EnableBrowserUse", "PM_Agent", "agent.browserUse", true,
        "Enable Browser-Use Tools",
        "Allow the agent to use in-app WebView browser-use tools "
        "(browser_read, browser_find, browser_scope, browser_click, browser_type, "
        "browser_select, browser_batch, browser_navigate).\n\n"
        "Disable to block DOM interaction in the centre browser without turning off "
        "desktop computer-use. Agent.EnableComputerUse=0 also disables these tools."));
    c.push_back(b("Agent.EnableRealtime", "PM_Agent", "agent.realtime", true,
        "Enable Real-Time Agent",
        "Allow the real-time voice agent session (continuous mic + LLM loop).\n\n"
        "When disabled the realtime toolbar button and Start/Stop/Toggle Realtime app commands are blocked. "
        "Note: CLI.EnableAudio must also be on for realtime to function."));
    c.push_back(b("Agent.SandboxMode", "PM_Agent", "agent.sandboxMode", false,
        "Enforce Sandbox Mode",
        "When enabled all agent tool calls that spawn processes run inside an AppContainer "
        "sandbox with reduced privileges.\n\n"
        "Requires Windows 10 1607 or later. AppContainer profiles are deleted on exit."));
    c.push_back(multi("Agent.AllowedMcpHosts", "PM_Agent", "",
        "Allowed MCP Hosts",
        "Restrict MCP connections to an explicit list of hostnames or URIs "
        "(one entry per line, wildcards allowed, e.g. *.corp.example.com).\n\n"
        "When empty (default) no host-level restriction is applied."));

    // ── Agent / Tools ──────────────────────────────────────────────────────────
    c.push_back(b("Agent.Tools.EnableRun", "PM_Agent_Tools", "agentTools.run", true,
        "Enable Run Tool",
        "Allow the agent to use the \"run\" tool to execute arbitrary shell commands.\n\n"
        "Disable to prevent the agent from spawning processes."));
    c.push_back(b("Agent.Tools.EnableRunSequence", "PM_Agent_Tools", "agentTools.runSequence", true,
        "Enable Run-Sequence Tool",
        "Allow the agent to use the \"run_sequence\" tool for multi-step shell pipelines."));
    c.push_back(b("Agent.Tools.EnableWriteFile", "PM_Agent_Tools", "agentTools.writeFile", true,
        "Enable Write-File Tool",
        "Allow the agent to create or overwrite files on the local filesystem."));
    c.push_back(b("Agent.Tools.EnableFileStrReplace", "PM_Agent_Tools", "agentTools.fileStrReplace", true,
        "Enable File-Str-Replace Tool",
        "Allow the agent to surgically edit existing UTF-8 files (file_str_replace)."));
    c.push_back(b("Agent.Tools.EnableFileDelete", "PM_Agent_Tools", "agentTools.fileDelete", true,
        "Enable File-Delete Tool",
        "Allow the agent to delete regular files (file_delete)."));
    c.push_back(b("Agent.Tools.EnableCreateCommand", "PM_Agent_Tools", "agentTools.createCommand", true,
        "Enable Create-Command Tool",
        "Allow the agent to create new custom ribbon commands in the application."));
    c.push_back(b("Agent.Tools.EnableComputerGroup", "PM_Agent_Tools", "agentTools.computerGroup", true,
        "Enable Computer-Group Tools",
        "Allow the agent to use computer-use tools "
        "(screenshot, mouse, keyboard, app inspection)."));
    c.push_back(b("Agent.Tools.EnableBrowserGroup", "PM_Agent_Tools", "agentTools.browserGroup", true,
        "Enable Browser-Group Tools",
        "Allow the agent to use in-app WebView browser-use tools "
        "(read, find, scope, click, type, select, batch, navigate)."));
    c.push_back(b("Agent.Tools.EnableAppCommands", "PM_Agent_Tools", "agentTools.appCommands", true,
        "Enable App-Command Tool",
        "Allow the agent to run Tanit app/UI commands on the running instance "
        "(openurl, open, browse, toggle panels, takescreenshot, etc.)."));
    c.push_back(b("Agent.Tools.EnableNetworkGroup", "PM_Agent_Tools", "agentTools.networkGroup", true,
        "Enable Network Tools",
        "Allow the agent to run remote commands over SSH and talk to MQTT brokers and Modbus devices "
        "(ssh_exec, mqtt, modbus_read, modbus_write)."));
    c.push_back(b("Agent.Tools.EnableScheduler", "PM_Agent_Tools", "agentTools.scheduler", true,
        "Enable Scheduler Tools",
        "Allow the agent to schedule future actions (schedule_at / schedule_in / schedule_every tools)."));
    c.push_back(b("Agent.Tools.EnableMemory", "PM_Agent_Tools", "agentTools.memory", true,
        "Enable Memory Tools",
        "Allow the agent to persist information between sessions using the memory tools."));
    c.push_back(multi("Agent.Tools.BlockList", "PM_Agent_Tools", "",
        "Tool Block List",
        "Deny-list of agent tool names (one per line). Tools in this list are never dispatched "
        "even if their individual Enable* flag is set."));
    c.push_back(multi("Agent.Tools.AllowList", "PM_Agent_Tools", "",
        "Tool Allow List",
        "Allow-list of agent tool names. When non-empty, only tools listed here are available; "
        "all others are implicitly blocked.\n\n"
        "Leave empty (default) to allow all tools that are not individually disabled."));

    // ── Security (HKLM-only) ─────────────────────────────────────────────────
    c.push_back(hklm_bool("Security.RequireEncryption", "PM_Security", "security.requireEncryption", true,
        "Require Encryption for Stored Assets",
        "Enforce DPAPI-backed encryption for all secure documents (settings, OAuth credentials, commands, prompts, MCP config).\n\n"
        "Disabling this policy allows plain-text storage, which is not recommended on shared or managed machines."));
    c.push_back(hklm_bool("Security.RequireSigning", "PM_Security", "security.requireSigning", true,
        "Require Signing for Stored Assets",
        "Reject assets that are not signed with the local Ed25519 signing key.\n\n"
        "When enabled any unsigned or tampered document will be rejected at load time."));
    {
        PolicyEntry e;
        e.key = "SessionStorage.Root";
        e.category = "PM_Security";
        e.web_key = "security.sessionStorage.root";
        e.type = PolicyType::Str;
        e.hklm_only = true;
        e.display_name = "Force Session Storage Location";
        e.explain =
            "Force the secure session storage root used for chat transcripts, session memory, "
            "agent logs, and session sidecars.\n\n"
            "Leave empty / Not Configured to use the compiled default under the user's app "
            "configuration directory. The path may be local or UNC; no import/export behavior "
            "is controlled by this policy.";
        c.push_back(std::move(e));
    }
    {
        PolicyEntry e;
        e.key = "Paths.TempDirectory";
        e.category = "PM_Security";
        e.web_key = "paths.tempDirectory";
        e.type = PolicyType::Str;
        e.hklm_only = true;
        e.display_name = "Force Application Temp Directory";
        e.explain =
            "Force the application-scoped temporary directory used for agent tool scratch "
            "files and implicit generated outputs (e.g. image_create defaults).\n\n"
            "Leave empty / Not Configured to use the compiled default under the user's app "
            "configuration directory (<config-dir>/temp). The path may be local or UNC.";
        c.push_back(std::move(e));
    }
    {
        PolicyEntry e;
        e.key = "Paths.DefaultFolder";
        e.category = "PM_Security";
        e.web_key = "paths.defaultFolder";
        e.type = PolicyType::Str;
        e.hklm_only = true;
        e.display_name = "Force Default Work Folder";
        e.explain =
            "Force the default Explorer work folder used when the app starts without "
            "--src or an explicit user context (e.g. Start Menu launch).\n\n"
            "Leave empty / Not Configured to use the user's default-folder mode "
            "(last visited folder or a custom path in settings). The path may be "
            "local or UNC; it must exist and must not be the application install directory.";
        c.push_back(std::move(e));
    }
    {
        PolicyEntry e;
        e.key = "SessionStorage.Protection";
        e.category = "PM_Security";
        e.web_key = "security.sessionStorage.protection";
        e.type = PolicyType::EnumStr;
        e.hklm_only = true;
        e.display_name = "Force Session Storage Protection";
        e.explain =
            "Force the protection mode for secure session documents.\n\n"
            "Signed stores readable JSON with a local document signature. Encrypted stores "
            "encrypted documents and also signs them. Encrypted with user presence is reserved "
            "for stronger local unlock flows. Plain text is intentionally not offered here.";
        e.enum_items = {
            { "signed",       "Signed" },
            { "encrypted",    "Encrypted and signed" },
            { "encrypted+up", "Encrypted with user presence and signed" },
        };
        c.push_back(std::move(e));
    }
    c.push_back(hklm_bool("SessionStorage.RequireEncryption", "PM_Security", "security.sessionStorage.requireEncryption", true,
        "Require Encryption for Sessions",
        "Require encrypted secure-storage documents for chat transcripts, session memory, "
        "agent logs, and session sidecars.\n\n"
        "When enabled this overrides user settings that request signed-only or plain session storage."));
    c.push_back(hklm_bool("SessionStorage.RequireSigning", "PM_Security", "security.sessionStorage.requireSigning", true,
        "Require Signing for Sessions",
        "Require local document signatures for chat transcripts, session memory, agent logs, "
        "and session sidecars.\n\n"
        "When enabled every session document is signed and unsigned/tampered documents are rejected."));
    c.push_back(b("Privacy.EnableClipboardContext", "PM_Security", "privacy.clipboardContext", true,
        "Allow Clipboard as a Context Source",
        "Allow the OS context service to treat clipboard files, text, images, and other Win32 "
        "clipboard formats as eligible sources for launcher commands, processors, and agents.\n\n"
        "On by default. Clipboard is never equivalent to Explorer or Desktop selection. "
        "Group Policy can still disable this for managed desktops."));
    {
        PolicyEntry e;
        e.key = "Security.ForceVerificationProtector";
        e.category = "PM_Security";
        e.type = PolicyType::EnumStr;
        e.hklm_only = true;
        e.display_name = "Force Verification Protector";
        e.explain =
            "Override the verification mechanism used for all sensitive operations.\n\n"
            "Leave Not Configured to use the compiled default (Windows Hello when available, DPAPI otherwise).";
        e.enum_items = {
            { "dpapi",         "DPAPI (no interactive challenge)" },
            { "mock-hello",    "Mock Hello (automated/CI environments only)" },
            { "windows-hello", "Windows Hello (biometric or PIN)" },
        };
        c.push_back(std::move(e));
    }

    // ── Security / Verification (HKLM-only, REG_SZ dropdown) ──────────────────
    c.push_back(ver("Security.Verification.SettingsImportPlain",
        "Verification Level: Import Settings",
        "Minimum user verification level required before importing settings from a plain file.\n\n"
        "Compiled default: local_unlock. Leave Not Configured to keep the default."));
    c.push_back(ver("Security.Verification.SettingsExportPlain",
        "Verification Level: Export Settings",
        "Minimum user verification level required before exporting settings to a plain file.\n\n"
        "Compiled default: local_unlock. Leave Not Configured to keep the default."));
    c.push_back(ver("Security.Verification.CommandConfigUpdate",
        "Verification Level: Update Commands",
        "Minimum verification required to update the command configuration in-app.\n\nCompiled default: presence."));
    c.push_back(ver("Security.Verification.CommandConfigImport",
        "Verification Level: Import Commands",
        "Minimum verification required to import commands from a plain file.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.CommandConfigExport",
        "Verification Level: Export Commands",
        "Minimum verification required to export commands to a plain file.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.McpConfigUpdate",
        "Verification Level: Update MCP Config",
        "Minimum verification required to update MCP server configuration in-app.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.McpConfigImport",
        "Verification Level: Import MCP Config",
        "Minimum verification required to import MCP configuration from a plain file.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.PromptUpdate",
        "Verification Level: Update Prompts",
        "Minimum verification required to edit or save prompt templates in-app.\n\nCompiled default: presence."));
    c.push_back(ver("Security.Verification.PromptImport",
        "Verification Level: Import Prompts",
        "Minimum verification required to import prompt templates from plain files.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.HomePageUpdate",
        "Verification Level: Update Home Page",
        "Minimum verification required to save the signed home.page dashboard in-app.\n\nCompiled default: presence."));
    c.push_back(ver("Security.Verification.HomePageImport",
        "Verification Level: Import Home Page",
        "Minimum verification required to import home.page from a plain file.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.HomePageExport",
        "Verification Level: Export Home Page",
        "Minimum verification required to export home.page as a plain file.\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.AssetImport",
        "Verification Level: Import Signed Assets",
        "Minimum verification required to import a signed asset bundle (.pmbundle).\n\nCompiled default: local_unlock."));
    c.push_back(ver("Security.Verification.OAuthCredentialsSave",
        "Verification Level: Save OAuth Credentials",
        "Minimum verification required before persisting ZITADEL OAuth tokens after login.\n\nCompiled default: presence."));
    c.push_back(ver("Security.Verification.OAuthCredentialsClear",
        "Verification Level: Clear OAuth Credentials",
        "Minimum verification required before clearing stored ZITADEL OAuth credentials (logout).\n\nCompiled default: local_unlock."));

    // ── UI / Panels ────────────────────────────────────────────────────────────
    c.push_back(b("UI.Panels.EnableExplorer", "PM_UI_Panels", "ui.panels.explorer", true,
        "Enable File Explorer Panel",
        "Show the file explorer / tree panel in the main window. Disable to hide it for all users."));
    c.push_back(b("UI.Panels.EnableSearch", "PM_UI_Panels", "ui.panels.search", true,
        "Enable Search Panel",
        "Show the search panel in the main window. Disable to hide it and block the search view toggle."));
    c.push_back(b("UI.Panels.EnableShell", "PM_UI_Panels", "ui.panels.shell", true,
        "Enable Console / Shell Panel",
        "Show the integrated shell/console panel. Disable to hide it and block the console view toggle."));
    c.push_back(b("UI.Panels.EnableRibbon", "PM_UI_Panels", "ui.panels.ribbon", true,
        "Enable Ribbon Toolbar",
        "Show the ribbon toolbar. Disable to hide it (commands remain available via keyboard shortcuts)."));
    c.push_back(b("UI.Panels.EnableQueue", "PM_UI_Panels", "ui.panels.queue", true,
        "Enable Job Queue Panel",
        "Show the batch job queue panel. Requires the queue feature to be compiled in; disable to hide it."));
    c.push_back(b("UI.Panels.EnableLog", "PM_UI_Panels", "ui.panels.log", true,
        "Enable Log Panel",
        "Show the activity log panel. Requires the log feature to be compiled in; disable to hide it."));
    c.push_back(b("UI.Panels.EnableChat", "PM_UI_Panels", "ui.panels.chat", true,
        "Enable Chat Panel",
        "Show the embedded chat panel. Requires the chat feature to be compiled in; disable to hide it."));
    c.push_back(b("UI.Panels.EnableSettings", "PM_UI_Panels", "ui.panels.settings", true,
        "Enable Settings Panel",
        "Show the settings panel. Disable to prevent users from opening application settings entirely."));

    // ── UI / Settings & tabs ─────────────────────────────────────────────────
    c.push_back(b("UI.Settings.EnableProvidersTab", "PM_UI_Settings", "ui.settings.providersTab", true,
        "Enable Providers Tab",
        "Show the Providers tab in Settings. Disable to prevent users from adding or changing AI providers."));
    c.push_back(b("UI.Settings.EnableAdvancedTab", "PM_UI_Settings", "ui.settings.advancedTab", true,
        "Enable Advanced Settings Tab",
        "Show the Advanced tab in Settings. Disable to hide advanced configuration."));
    c.push_back(b("UI.Settings.EnableChatRouter", "PM_UI_Settings", "ui.settings.chatRouter", true,
        "Enable Chat Model Router",
        "Allow users to change the active AI provider or model from the chat UI. Disable to lock the router."));
    c.push_back(multi("UI.AllowedProviders", "PM_UI_Settings", "ui.allowedProviders",
        "Allowed AI Providers",
        "Restrict the AI providers users may select (one provider id per line).\n\n"
        "Leave empty (default) to allow all configured providers."));

    // ── UI / Editors ───────────────────────────────────────────────────────────
    c.push_back(b("UI.Editors.EnablePrompt", "PM_UI_Editors", "ui.editors.prompt", true,
        "Enable Prompt Editor",
        "Allow users to view and edit prompt templates. Disable to lock the prompt editor."));
    c.push_back(b("UI.Editors.EnableCommand", "PM_UI_Editors", "ui.editors.command", true,
        "Enable Command Editor",
        "Allow users to edit custom ribbon commands. Disable to lock the command editor."));
    c.push_back(b("UI.Editors.EnableMcp", "PM_UI_Editors", "ui.editors.mcp", true,
        "Enable MCP Config Editor",
        "Allow users to edit MCP server configuration. Disable to lock the MCP editor."));
    c.push_back(b("UI.Editors.EnablePage", "PM_UI_Editors", "ui.editors.page", true,
        "Enable Home Page Editor",
        "Allow users to edit the signed home.page dashboard. Disable to lock Home page saves."));

    // ── CLI command groups ─────────────────────────────────────────────────────
    c.push_back(b("CLI.EnableSearch", "PM_CLI", "cli.search", true,
        "Enable search CLI Command",
        "Allow the \"search\" command (semantic / visual image search from the CLI). "
        "This is the CLI counterpart to the search panel governed by UI.Panels.EnableSearch; "
        "the \"find\" and \"duplicates\" discovery commands are unaffected."));
    c.push_back(b("CLI.EnableAudio", "PM_CLI", "cli.audio", true,
        "Enable Audio CLI Commands",
        "Allow the \"audio\" command group (recording, TTS, STT). Disabling also blocks the realtime agent. "
        "See also: Agent.EnableRealtime."));
    c.push_back(b("CLI.EnableVideo", "PM_CLI", "cli.video", true,
        "Enable Video CLI Commands",
        "Allow the \"video\" command group from the CLI and the in-app video capture commands."));
    c.push_back(b("CLI.EnableXblox", "PM_CLI", "cli.xblox", true,
        "Enable XBlox CLI Commands",
        "Allow the \"xblox\" command group and the block palette."));
    c.push_back(b("CLI.EnableRegisterExplorer", "PM_CLI", "cli.registerExplorer", true,
        "Enable register-explorer CLI Command",
        "Allow \"register-explorer\", which registers Windows Explorer context menus."));
    c.push_back(b("CLI.EnableRegisterStartMenu", "PM_CLI", "cli.registerStartMenu", true,
        "Enable register-startmenu CLI Command",
        "Allow \"register-startmenu\", which registers Start Menu shortcuts."));
    c.push_back(b("CLI.EnableInstaller", "PM_CLI", "cli.installer", true,
        "Enable installer CLI Command",
        "Allow the \"installer\" zip/unpacked install helper."));
    c.push_back(b("CLI.EnableSettings", "PM_CLI", "cli.settings", true,
        "Enable settings CLI Command",
        "Allow import/export of the app settings profile via the CLI \"settings\" command."));
    c.push_back(b("CLI.EnableService", "PM_CLI", "cli.service", true,
        "Enable service CLI Command",
        "Allow the \"service\" command that calls the configured Tanit web service API."));
    c.push_back(b("CLI.EnableLogin", "PM_CLI", "cli.login", true,
        "Enable login / logout CLI Commands",
        "Allow the \"login\" command (OIDC browser flow) for CLI sign-in / sign-out."));
    c.push_back(b("CLI.EnableStatus", "PM_CLI", "cli.status", true,
        "Enable status CLI Command",
        "Allow the \"status\" command that shows Tanit credits and license status."));
    c.push_back(b("CLI.EnableRunIpc", "PM_CLI", "cli.runIpc", true,
        "Enable run-ipc CLI Command",
        "Allow the \"run-ipc\" command that discovers and controls live tanit instances over the command IPC bus."));
    c.push_back(b("CLI.EnableMcpServer", "PM_CLI", "cli.mcpServer", true,
        "Enable mcp server CLI Command",
        "Allow launching the foreground MCP Streamable HTTP server via the \"mcp\" CLI command. "
        "Note: this controls the embedded server only — use Agent.EnableMcpClient for agent-side MCP client access."));
    c.push_back(b("CLI.EnableDaemon", "PM_CLI", "cli.daemon", true,
        "Enable daemon CLI Command",
        "Allow the global shortcut daemon (hotkeys, UI presets, app commands, STT, voice session)."));
    c.push_back(b("CLI.EnableAssistant", "PM_CLI", "cli.assistant", true,
        "Enable assistant CLI Command",
        "Allow the AI assistant toolbar / global shortcuts / realtime voice / UIA spy host."));
    c.push_back(b("CLI.EnableBatch", "PM_CLI", "cli.batch", true,
        "Enable batch CLI Command",
        "Allow batch session management (save / load / resume / list / discard)."));
    c.push_back(b("CLI.EnableBluetooth", "PM_CLI", "cli.bluetooth", true,
        "Enable bluetooth CLI Command",
        "Allow Bluetooth and audio-endpoint management (list, pair, connect devices)."));
    c.push_back(b("CLI.EnableMedia", "PM_CLI", "cli.media", true,
        "Enable media CLI Command",
        "Allow the experimental \"media\" type tools (file probing, libmagic MIME/extension metadata)."));
    c.push_back(hklm_bool("CLI.EnableUrlSchemes", "PM_CLI", "cli.urlSchemes", true,
        "Enable tanit:// URL Scheme Handler",
        "Allow the application to act as a registered handler for the tanit:// custom URL scheme.\n\n"
        "When enabled (default) users can register the scheme via \"tanit installer --url-schemes\" "
        "and clicking a tanit:// link in a browser or email will open the application. "
        "Disabling this policy prevents scheme registration (the installer --url-schemes flag becomes a no-op) "
        "and causes the application to reject any protocol URI passed on the command line via argv[1], "
        "silently exiting rather than processing the link.\n\n"
        "This policy is HKLM-only. User-scope hive cannot re-enable it if an administrator disables it."));

    // ── Remote locations (file panel + VFS queue + CLI) ──────────────────────
    c.push_back(b("Network.EnableSsh", "PM_Network", "network.ssh", true,
        "Enable SSH / SFTP access",
        "Allow ssh:// and sftp:// locations in the file panel, viewer, copy/move queue, "
        "XBlox fsCopy/fsMove/fsMkdir and sshExec, and tanit-cli cp/mv/mkdir/touch.\n\n"
        "When disabled the app does not connect (libssh), does not list ~/.ssh/config hosts, "
        "and refuses stored recents or --src that use those schemes."));
    c.push_back(b("Network.EnableFtp", "PM_Network", "network.ftp", true,
        "Enable FTP / FTPS access",
        "Allow ftp:// and ftps:// bookmark URLs in the file panel, viewer, copy/move queue, "
        "XBlox fsCopy/fsMove/fsMkdir, and tanit-cli cp/mv/mkdir/touch.\n\n"
        "When disabled the app does not connect (libcurl) and refuses stored recents or --src "
        "that use those schemes. Passwords already stored in a bookmark URL are not used."));

    // ── Web surfaces ───────────────────────────────────────────────────────────
    c.push_back(b("Web.EnableCommandRun", "PM_Web", "web.commandRun", true,
        "Enable command execution from web surfaces",
        "Allow embedded web views (viewer, chat, xblox, home, settings) to launch processes through the host "
        "commandRun bridge. Disable to fully lock down command execution triggered from documents and panels."));
    c.push_back(b("Web.EnableExternalShell", "PM_Web", "web.externalShell", true,
        "Enable arbitrary external/shell commands from web surfaces",
        "Allow the arbitrary-process path (externalCommand: a free executable or shell line) from web surfaces. "
        "Disable to permit only curated commands and tanit-cli verbs, bounding the blast radius of a document."));

    // ── Local inference backends ─────────────────────────────────────────────
    c.push_back(b("Local.EnableWhisper", "PM_Local", "local.whisper", true,
        "Enable local whisper.cpp speech-to-text",
        "Allow whisper.cpp on-device transcription. Cloud STT providers are unaffected. "
        "Applies to: audio CLI --provider whisper, agent mic STT, xblox audio blocks."));
    c.push_back(b("Local.EnableOnnx", "PM_Local", "local.onnx", true,
        "Enable local ONNX runtime inference",
        "Allow ONNX Runtime sessions (OCR, object detection, image classification, document layout). "
        "Applies to: onnx CLI, xblox OCR/detect/model blocks, search OCR, video detection."));
    c.push_back(b("Local.EnableLlama", "PM_Local", "local.llama", true,
        "Enable local llama.cpp inference",
        "Allow llama.cpp model loading — local text chat routing, local embedding/semantic search, VLM, and the "
        "llama CLI. Whisper is separately controlled by Enable local whisper.cpp."));

    // ── AI providers (from the live registry) ─────────────────────────────────
    {
        for (const auto& p : pm::commons::host::provider_rows()) {
            const std::string& disp = p.display_name.empty() ? p.name : p.display_name;
            PolicyEntry e = b(p.policy_key,
                              "PM_Providers", "", true,
                              "Enable " + disp + " Provider",
                              "Allow " + disp + " (" + p.name +
                              ") to appear in provider registry driven surfaces.\n\n"
                              "When disabled, policy-aware provider listings hide this provider." +
                              (p.build_enabled
                                   ? std::string{}
                                   : std::string("\n\nNote: this provider is disabled by FEATURE_PROVIDER_* in the current build.")));
            if (!e.key.empty())
                c.push_back(std::move(e));
        }
    }

    return c;
}

} // namespace

const std::vector<PolicyCategory>& policy_categories() {
    return k_categories;
}

const std::vector<PolicyEntry>& policy_catalog() {
    static const std::vector<PolicyEntry> c = build_catalog();
    return c;
}

const PolicyEntry* policy_find(std::string_view key) {
    for (const auto& e : policy_catalog())
        if (e.key == key)
            return &e;
    return nullptr;
}

nlohmann::json policy_catalog_json() {
    nlohmann::json out = nlohmann::json::object();

    nlohmann::json cats = nlohmann::json::array();
    for (const auto& cat : policy_categories())
        cats.push_back({{"id", cat.id}, {"parent", cat.parent}, {"display", cat.display}});
    out["categories"] = std::move(cats);

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& e : policy_catalog()) {
        nlohmann::json row{
            {"key", e.key},
            {"category", e.category},
            {"web_key", e.web_key},
            {"type", type_name(e.type)},
            {"hklm_only", e.hklm_only},
            {"default_on", e.default_on},
            {"display_name", e.display_name},
            {"explain", e.explain},
        };
        if (!e.enum_items.empty()) {
            nlohmann::json items = nlohmann::json::array();
            for (const auto& it : e.enum_items)
                items.push_back({{"value", it.value}, {"label", it.label}});
            row["enum_items"] = std::move(items);
        }
        arr.push_back(std::move(row));
    }
    out["policies"] = std::move(arr);
    return out;
}

const std::vector<ToolPolicyMapping>& agent_tool_policy_mappings() {
    static const std::vector<ToolPolicyMapping> m = [] {
        std::vector<ToolPolicyMapping> out;
        const auto rows = pm::commons::host::tool_rows();

        auto by_group = [&](pm::commons::host::ToolGroup g) {
            std::vector<std::string> names;
            for (const auto& row : rows)
                if (row.group == g)
                    names.push_back(row.name);
            return names;
        };
        auto single = [&](const char* name) {
            std::vector<std::string> names;
            for (const auto& row : rows)
                if (row.name == name) {
                    names.push_back(row.name);
                    break;
                }
            return names;
        };

        out.push_back({"Agent.Tools.EnableRun",           single("run")});
        out.push_back({"Agent.Tools.EnableRunSequence",   single("run_sequence")});
        out.push_back({"Agent.Tools.EnableWriteFile",     single("write_file")});
        out.push_back({"Agent.Tools.EnableFileStrReplace", single("file_str_replace")});
        out.push_back({"Agent.Tools.EnableFileDelete",    single("file_delete")});
        out.push_back({"Agent.Tools.EnableCreateCommand", single("create_command")});
        out.push_back({"Agent.Tools.EnableComputerGroup", by_group(pm::commons::host::ToolGroup::Computer)});
        out.push_back({"Agent.Tools.EnableBrowserGroup",  by_group(pm::commons::host::ToolGroup::Browser)});
        out.push_back({"Agent.Tools.EnableAppCommands",   by_group(pm::commons::host::ToolGroup::App)});
        out.push_back({"Agent.Tools.EnableNetworkGroup",  by_group(pm::commons::host::ToolGroup::Network)});
        out.push_back({"Agent.Tools.EnableScheduler",     by_group(pm::commons::host::ToolGroup::Scheduler)});
        out.push_back({"Agent.Tools.EnableMemory",        by_group(pm::commons::host::ToolGroup::Memory)});
        return out;
    }();
    return m;
}

const std::vector<std::string>& agent_tool_all_names() {
    static const std::vector<std::string> names = [] {
        std::vector<std::string> out;
        const auto rows = pm::commons::host::tool_rows();
        out.reserve(rows.size());
        for (const auto& row : rows)
            out.push_back(row.name);
        return out;
    }();
    return names;
}

} // namespace pm::policy
