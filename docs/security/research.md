
# https://medium.com/@emergentcap/hardening-claude-code-a-security-review-framework-and-the-prompt-that-does-it-for-you-c546831f2cec

https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/

https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents

https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html

https://www.aikido.dev/blog/supply-chain-attack-on-react-native-aria-ecosystem

https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage








-------------------------------------------------

# https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions


Generate Software Bill of Materials (SBOM): Instruct the AI to create and maintaining SBOMs for better visibility into your software supply chain. For example: “Generate an SBOM by using tools that support standard formats like SPDX or CycloneDX”. You can also mention provenance tracking: “Where applicable, use an attestations framework such as in-toto


The Seven Layers : not enough :)

The prompt implements a defense-in-depth approach across seven categories:

Security Assessment — Inventory your current state: processes, MCP servers, credentials, permissions, endpoint protections
Pre-Execution Gate — A PreToolUse hook that blocks dangerous commands before they execute (pipe-to-shell, destructive deletes, credential exfiltration patterns, permission bypass flags)
Supply Chain Protection — Package scanning, lifecycle script lockdown, CVE auditing
File-Level Malware Scanning — ClamAV with automated definition updates and scheduled scans
Credential Hygiene — Transcript scrubbing, snapshot pruning, credential removal from config files
MCP Server Audit — Transport type, version pinning, network exposure, and risk rating for each server
Governance — Managed settings to disable bypass-permissions mode and restrict plugin sources