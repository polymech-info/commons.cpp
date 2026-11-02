\---

title: "OWASP"

slug: "tanit-owasp"

date: "2026-11-02"

author: "PolyMech"

\---



\# Table of Contents



\- \[Tanit — OWASP Agentic Top 10 Coverage](#tanit-owasp-agentic-top-10-coverage)

&#x20; - \[How to read this](#how-to-read-this)

&#x20; - \[Coverage at a glance](#coverage-at-a-glance)

&#x20; - \[ASI01 — Agent Goal Hijack](#asi01-agent-goal-hijack)

&#x20; - \[ASI02 — Tool Misuse and Exploitation](#asi02-tool-misuse-and-exploitation)

&#x20; - \[ASI03 — Identity and Privilege Abuse](#asi03-identity-and-privilege-abuse)

&#x20; - \[ASI04 — Agentic Supply Chain Vulnerabilities](#asi04-agentic-supply-chain-vulnerabilities)

&#x20; - \[ASI05 — Unexpected Code Execution (RCE)](#asi05-unexpected-code-execution-rce)

&#x20; - \[ASI06 — Memory \& Context Poisoning](#asi06-memory-context-poisoning)

&#x20; - \[ASI07 — Insecure Inter-Agent Communication](#asi07-insecure-inter-agent-communication)

&#x20; - \[ASI08 — Cascading Failures](#asi08-cascading-failures)

&#x20; - \[ASI09 — Human-Agent Trust Exploitation](#asi09-human-agent-trust-exploitation)

&#x20; - \[ASI10 — Rogue Agents](#asi10-rogue-agents)

&#x20; - \[Summary](#summary)

&#x20; - \[References](#references)



\---



\# Tanit — OWASP Agentic Top 10 Coverage



This document walks the \[OWASP Agentic Security Initiative (ASI) Top 10](https://tanit.polymech.info/user/3bb4cfbf-318b-44d3-a9d3-35680e738421/pages/owasp-top-10-for-agentic)



chapter by chapter and maps each vector to the concrete measures implemented in

Tanit / `pm-image`. It is an internal engineering reference: it names real

components and is explicit about what is \*\*shipped\*\* versus \*\*planned\*\*.



\## How to read this



For each vector we give:



\- \*\*The risk\*\* — a one-paragraph restatement of the OWASP entry.

\- \*\*Our exposure\*\* — how the vector applies (or does not) to a native,

&#x20; single-user desktop agent rather than a distributed multi-agent mesh.

\- \*\*Our measures\*\* — the specific mechanisms that address it.

\- \*\*Gaps / roadmap\*\* — honest notes on what is not yet done.



A note on posture (shared across every chapter): Tanit 's security boundary is

the \*\*SecurityGateway\*\* — every tool call is intercepted at the tool-dispatch

seam (`agent\_factory.cpp`) and runs `classify → authorize → grant → execute`. The

gateway is compiled in by default (`FEATURE\_SECURITY\_AGENT`, default ON) as part

of `pm-media`, so both the CLI and the UI share one enforcement path. Model

output, planner output, and tool arguments are all treated as untrusted input to

that gateway.



\## Coverage at a glance



| ASI | Vector | Primary Tanit measures | State |

| --- | --- | --- | --- |

| ASI01 | Agent Goal Hijack | Untrusted-input handling, sanitizers, per-action consent, signed/locked prompts in secure storage | Shipped |

| ASI02 | Tool Misuse \& Exploitation | Gateway classify/authorize, scoped grants, run-command validators, sandbox routing, tool identity | Shipped |

| ASI03 | Identity \& Privilege Abuse | Session/task-scoped grants, lifetime-bound consent, tool-identity binding, least privilege by default | Shipped |

| ASI04 | Agentic Supply Chain | Signed+encrypted bundles (prompts/rules/MCP/tools), trust classification, native core, GPO allow/block | Partial |

| ASI05 | Unexpected Code Execution | Run validators, fs guardrails, no eval, AppContainer/LPAC sandbox, timeouts, web→native isolation | Shipped |

| ASI06 | Memory \& Context Poisoning | Encrypted+signed session memory, integrity metadata, tamper rejection, no silent re-ingestion | Shipped |

| ASI07 | Insecure Inter-Agent Comms | No open A2A mesh; MCP is policy-gated and identity-tagged; hardened host↔renderer IPC | Partial |

| ASI08 | Cascading Failures | Single-agent blast radius, per-call gateway checks, tool budgets/timeouts, audit trail | Partial |

| ASI09 | Human-Agent Trust Exploitation | Explicit consent surfaces, plain-language risk (not model rationale), preview≠effect, audit memory | Shipped |

| ASI10 | Rogue Agents | Bounded autonomy, signed audit memory, GPO kill-switch (disable tools/MCP), tamper detection | Partial |



\---



\## ASI01 — Agent Goal Hijack



\*\*The risk.\*\* Attackers redirect the agent's objectives or decision path through

prompt injection, poisoned documents, deceptive tool output, or malicious

artefacts, because the model cannot reliably separate instructions from content.



\*\*Our exposure.\*\* Tanit ingests user prompts, opened documents, markdown,

retrieved/tool output, rules, and skills — every one of these is a potential

carrier for injected instructions.



\*\*Our measures.\*\*



\- \*\*All natural-language inputs are untrusted.\*\* Documents, tool output, and web

&#x20; content are never a privileged instruction channel; they flow into the model

&#x20; as content, and any resulting \*action\* must still pass the gateway.

\- \*\*String/HTML sanitizers\*\* (`src/core/string\_sanitizers.cpp`) repair invalid

&#x20; UTF-8, strip scriptable/dangerous HTML, and normalize text before it reaches

&#x20; UI, logs, or command surfaces — closing the hidden-Unicode / bidi-marker style

&#x20; "rules file backdoor" carrier.

\- \*\*Prompts and rules are locked, signed resources.\*\* System prompts, rules, and

&#x20; templates live in signed + encrypted secure storage with a stable `pm://` URI,

&#x20; digest, and trust level, so tampering with a goal-defining prompt is

&#x20; detectable rather than silent.

\- \*\*Per-action consent on goal-changing / high-impact actions.\*\* When a proposed

&#x20; action deviates toward `Write`/`Execute` or out-of-scope resources, the gateway

&#x20; requires explicit approval (see ASI02/ASI09), so a hijacked goal cannot quietly

&#x20; execute.

\- \*\*Audit memory.\*\* Consent decisions and security reviews are stored as

&#x20; first-class session-memory items for after-the-fact review of goal drift.



\*\*Gaps / roadmap.\*\* We do not implement a signed "intent capsule" per execution

cycle, and there is no automated goal-drift baseline/alerting yet — deviation is

caught at the action gate, not by behavioral modeling.



\---



\## ASI02 — Tool Misuse and Exploitation



\*\*The risk.\*\* The agent stays within its privileges but applies a legitimate

tool unsafely — destructive calls, over-scoped reads, unsafe forwarding to a

shell, cost/loop amplification, or typosquatted tool resolution.



\*\*Our exposure.\*\* Tanit ships builtin tools (`read\_file`, `write\_file`, `run`,

image/audio/video tools, etc.) and MCP-provided tools. The `run` (shell) tool is

the highest-risk surface.



\*\*Our measures.\*\*



\- \*\*Classify → authorize at the dispatch seam.\*\* Each call becomes a typed

&#x20; `ToolRequest` with provider, `action` (Read/Write/Execute), and a

&#x20; `ResourceTarget` derived from the arguments. The gateway authorizes against the

&#x20; active security profile before execution.

\- \*\*Least agency / least privilege.\*\* Read tools default to read scope; write and

&#x20; execute actions require policy approval. Grants are the minimum needed, not the

&#x20; agent's full ambient authority.

\- \*\*Run-command validation\*\* (`src/llm/tools/run/RunValidators.cpp`) hard-denies

&#x20; dangerous patterns before a shell command executes: persistence hooks,

&#x20; environment/identity probing, secret copy/exfiltration, remote/URL mutation,

&#x20; and destructive system changes — regardless of how "legitimate" the invoking

&#x20; tool is.

\- \*\*Sandbox routing\*\* (`docs/security/sandbox.md`). Higher-risk process/MCP work

&#x20; can run inside a Windows AppContainer/LPAC sandbox with Job Object containment,

&#x20; optional network denial, and process-mitigation policies — bounding what a

&#x20; misused tool can reach.

\- \*\*Timeouts and streaming supervision\*\* (`src/llm/tools/run/RunTool.cpp`) bound

&#x20; runaway/loop-amplification execution and keep output visible instead of letting

&#x20; hidden background work continue.

\- \*\*Explicit tool identity.\*\* Tools are keyed by provider/server/tool id

&#x20; (`mcp\_<srv>\_\_<fn>`), so grants target a specific tool and typosquat/alias

&#x20; collisions do not silently inherit another tool's authority.



\*\*Gaps / roadmap.\*\* Per-tool egress allowlists and adaptive cost/rate budgeting

are not yet first-class; an MCP broker/proxy that verifies tool identity and

enforces per-tool grants out-of-process is planned (`dehack.md` P0.4).



\---



\## ASI03 — Identity and Privilege Abuse



\*\*The risk.\*\* Delegation chains, cached credentials, role inheritance, and

TOCTOU windows are exploited to escalate access or act under a borrowed identity.



\*\*Our exposure.\*\* Tanit is a single-user desktop agent, not a multi-agent

delegation network, so classic cross-agent confused-deputy scenarios largely do

not apply. The relevant risk is grant/credential scope creep within one session.



\*\*Our measures.\*\*



\- \*\*Session- and task-scoped grants.\*\* The session id (`--session` or generated

&#x20; UUID) threads into every `ToolRequest`; `Turn::task\_id` maps to `taskId`.

&#x20; Session-lifetime grants bind to the specific agent run and do not bleed across

&#x20; runs; task-lifetime grants expire with the task.

\- \*\*Lifetime-bound consent.\*\* Consent decisions carry a lifetime of

&#x20; `once | task | session` — there is no implicit "forever" grant, which limits

&#x20; privilege retention and stale-authorization (TOCTOU-style) reuse.

\- \*\*Scoped by tool/action/origin/resource path.\*\* A grant is not ambient

&#x20; authority; it is bound to a specific tool identity, action, caller origin

&#x20; (`Origin.cpp`), and resource path/URI scope.

\- \*\*Least privilege by default.\*\* Workspace-local reads proceed smoothly;

&#x20; out-of-scope file access, system changes, and execution require approval.



\*\*Gaps / roadmap.\*\* We do not issue short-lived cryptographic per-agent

credentials (mTLS/scoped tokens) or bind OAuth tokens to a signed intent —

appropriate for a multi-agent/enterprise identity fabric, largely out of scope

for the current single-user model.



\---



\## ASI04 — Agentic Supply Chain Vulnerabilities



\*\*The risk.\*\* Tools, prompts, MCP servers, models, and update channels sourced

from third parties may be malicious, compromised, or tampered with — including

runtime-composed capabilities.



\*\*Our exposure.\*\* Prompts, rules, MCP configuration, and tool specs are the

supply chain that steers the agent; the runtime also loads native dependencies.



\*\*Our measures.\*\*



\- \*\*Signed + encrypted bundles.\*\* Prompts, command config, MCP config, templates,

&#x20; and app/web bundles are stored as secure documents with integrity metadata

&#x20; (digest), trust classification, provider info, and version — so tampering with

&#x20; a prompt template or MCP descriptor is detectable, unlike the plain-file storage

&#x20; common in other AI desktop apps.

\- \*\*Native, from-scratch core.\*\* Tanit avoids bundling a Chromium+Node runtime

&#x20; and a large npm/PyPI dependency tree. This directly reduces the blast radius of

&#x20; ecosystem attacks like the September 2025 npm compromise (`chalk`/`debug`/

&#x20; `ansi-styles`) and the Electron ASAR integrity bypass (CVE-2025-55305), where

&#x20; affected apps had no per-app mitigation.

\- \*\*GPO allow/block.\*\* Administrators can disable MCP, skills, computer-use tools,

&#x20; local models, or specific providers, and allow-list/block tool names

&#x20; (`src/policy/policy\_catalog.cpp`) — a policy-level gate on which third-party

&#x20; capabilities may load at all.

\- \*\*Rules and skills are privileged inputs.\*\* Installed guidance/skill packages

&#x20; are treated as part of the agent supply chain and classified as trusted local

&#x20; resources rather than free-floating text.



\*\*Gaps / roadmap.\*\* A runtime \*\*binary manifest\*\* (SHA-256 + Authenticode +

signer allowlist) verified before DLL load / sidecar launch is designed but not

yet shipped (`dehack.md` P0.1/P0.2), and we do not yet produce SBOM/AIBOM

attestations or content-hash pinning with staged rollout/auto-rollback.



\---



\## ASI05 — Unexpected Code Execution (RCE)



\*\*The risk.\*\* Generated code, shell injection, unsafe deserialization/`eval`, or

multi-tool chains escalate into host/container compromise or sandbox escape.



\*\*Our exposure.\*\* The `run` tool and any file-writing tool are the paths from

"text" to "execution".



\*\*Our measures.\*\*



\- \*\*Run validators\*\* hard-deny shell-injection and chaining patterns

&#x20; (`RunValidators.cpp`) — e.g. the classic `... \&\& rm -rf ...` / secret-exfil /

&#x20; reverse-shell shapes — before the command reaches a shell.

\- \*\*Filesystem guardrails\*\* (`src/llm/llm\_fs\_guard.cpp`) block writes to sensitive

&#x20; paths and file types: dotfiles, credential folders, Git internals, SSH/cloud

&#x20; secrets, system directories, scripts, batch files, registry files, and archive

&#x20; payload types — cutting off "write a script then run it" and lockfile-poisoning

&#x20; style escalation.

\- \*\*No `eval`-driven agent internals.\*\* Tanit does not expose an `eval()`-backed

&#x20; memory or templating surface for model output to reach an interpreter.

\- \*\*Sandboxed execution.\*\* Risky process/MCP work is routed to AppContainer/LPAC

&#x20; with Job Object containment, restricted handles, optional network denial, and

&#x20; Windows process-mitigation policies (`sandbox.md`) — never running as an

&#x20; elevated identity by default.

\- \*\*Web → native isolation.\*\* Rendered documents and embedded web bundles cannot

&#x20; jump from content to native command execution (see ASI07 / WebView2 hardening);

&#x20; DevTools are disabled in production builds.

\- \*\*Timeouts / supervision\*\* bound execution and surface output for audit.



\*\*Gaps / roadmap.\*\* Pre-execution static analysis of generated code and a

version-controlled auto-execution allowlist are not yet implemented; DLL

search-order hardening for native loads is planned (`dehack.md` P0.1).



\---



\## ASI06 — Memory \& Context Poisoning



\*\*The risk.\*\* Adversaries corrupt stored/retrievable context (memory, summaries,

RAG stores) so future reasoning, planning, or tool use becomes biased or unsafe,

persisting across sessions.



\*\*Our exposure.\*\* Tanit persists session transcripts, agent memory/journal, and

per-run logs. If those were plain files, anything on the machine could poison

them between runs — the exact weakness we found in other AI desktop apps.



\*\*Our measures.\*\*



\- \*\*Encryption at rest + integrity.\*\* Session documents (`SessionTranscript`,

&#x20; `SessionMemory`, `SessionArtifact`, `SessionLog`) are stored \*\*encrypted and

&#x20; signed by default\*\* through secure storage, with a digest and trust level per

&#x20; document. Tampered or unsigned memory is rejected on load (verified by tests).

\- \*\*Not plain files.\*\* By default sessions no longer write legacy plaintext JSON;

&#x20; production policy does not expose plaintext session storage as a managed option

&#x20; (plaintext is test-build/dev-probe only).

\- \*\*Segmentation by session/task.\*\* Memory is bound to session/task identity;

&#x20; grants and stored context do not bleed across runs.

\- \*\*No silent self-ingestion of untrusted content as instructions.\*\* External

&#x20; content enters as untrusted data (sanitized), not as trusted long-term memory

&#x20; that later executes.

\- \*\*Queryable + prunable.\*\* The session-store library exposes `query\_store()` and

&#x20; `prune()` so memory can be inspected, quarantined, or wiped from CLI or UI.



\*\*Gaps / roadmap.\*\* We do not yet attach per-entry provenance/trust scores with

time-decay of unverified memory, and there is no anomaly detection on write

frequency. (Tanit has no shared multi-tenant vector store, so cross-tenant

bleed does not apply.)



\---



\## ASI07 — Insecure Inter-Agent Communication



\*\*The risk.\*\* In multi-agent systems, weak auth/integrity/confidentiality on

agent-to-agent messages allows interception, spoofing, replay, or protocol

downgrade.



\*\*Our exposure.\*\* Tanit does \*\*not\*\* run an open Agent2Agent (A2A) mesh or a

discovery/registry service, so most of ASI07 does not apply. The relevant

"inter-component" channels are (a) MCP connections and (b) the host↔renderer

(WebView2) bridge.



\*\*Our measures.\*\*



\- \*\*MCP is policy-gated and identity-tagged.\*\* MCP tools carry a server id and

&#x20; resolve to stable tool ids; MCP can be disabled entirely by GPO. Connections

&#x20; are not implicitly trusted peers.

\- \*\*Hardened host↔renderer IPC.\*\* The WebView bridge uses \*\*origin pinning\*\*

&#x20; (rejecting web messages from an unexpected host), a \*\*Content Security Policy\*\*

&#x20; on signed bundled HTML, and \*\*markdown sanitization\*\*, so rendered content

&#x20; cannot forge privileged host messages. DevTools are off in production.

\- \*\*No downgrade path.\*\* Web-triggered command execution can be locked down by

&#x20; GPO (block all web command runs, or only arbitrary external shell), removing the

&#x20; "coerce into a weaker mode" avenue for the web surface.



\*\*Gaps / roadmap.\*\* An out-of-process \*\*MCP broker\*\* with binary-identity

verification, per-tool grant enforcement, and signed/attested descriptors is

planned (`dehack.md` P0.4/P0.6). mTLS/PKI inter-agent attestation is out of scope

until/unless Tanit supports a multi-agent topology.



\---



\## ASI08 — Cascading Failures



\*\*The risk.\*\* A single fault (hallucination, poisoned memory, corrupted tool)

propagates and amplifies across autonomous agents into system-wide harm.



\*\*Our exposure.\*\* Cascade risk scales with the number of autonomously coupled

agents. Tanit runs a \*\*single agent for a single user\*\*, so there is no

planner→executor fan-out across a fleet and no auto-deployment cascade. The

residual risk is a local runaway loop (repeated costly/destructive calls).



\*\*Our measures.\*\*



\- \*\*Bounded blast radius by design.\*\* No inter-agent auto-delegation network means

&#x20; a fault cannot fan out to peers/tenants.

\- \*\*Per-call gateway checks.\*\* Every high-impact call is re-validated at execution

&#x20; time, so a drifting plan cannot chain unchecked actions.

\- \*\*Budgets, timeouts, and supervision\*\* on the `run` tool throttle loop

&#x20; amplification and DoS/bill-spike patterns.

\- \*\*Tamper-evident audit trail.\*\* Security decisions and session logs are stored

&#x20; as signed/encrypted memory, supporting forensic tracing of a local failure.



\*\*Gaps / roadmap.\*\* Explicit circuit-breakers/progress-caps between planning and

execution, hash-chained non-repudiation logs, and behavioral drift baselines are

not implemented (tracked conceptually in `dehack.md` P0.7). This is a lower

priority given the single-agent model.



\---



\## ASI09 — Human-Agent Trust Exploitation



\*\*The risk.\*\* Users over-trust fluent, authoritative agents and approve unsafe

actions — via missing confirmations, fake explainability, or "read-only" previews

that cause side effects.



\*\*Our exposure.\*\* Tanit asks users to approve sensitive actions, so the quality

and honesty of those prompts directly determines this risk.



\*\*Our measures.\*\*



\- \*\*Explicit consent surfaces.\*\* Sensitive actions route through a

&#x20; `RoutingConsentDelegate` to a real approval surface — a native Win32 / WebView

&#x20; consent card (`ConsentCard.tsx`) in the app, or `CliConsentDelegate` on the

&#x20; command line — with deny / allow-once / allow-for-session / scope-narrowing.

\- \*\*Plain-language risk, not model rationale.\*\* The consent surface presents the

&#x20; requested tool, action, target, risk, and scope from policy — it does not ask

&#x20; users to trust a model-generated justification for its own action.

\- \*\*Advisory AI review is fenced.\*\* When an AI security reviewer (`SecurityAgent`,

&#x20; `security-prompt.md`) is consulted, it is \*\*advisory only\*\*: it returns

&#x20; `{allow|deny, lifetime, reason}` under supplied risk/scope/lifetime ceilings and

&#x20; \*\*defaults to deny\*\* on ambiguity, secrets, scope broadening, or credentials.

&#x20; Final enforcement stays in the local policy layer, never the model.

\- \*\*Preview ≠ effect.\*\* The web/rendering surfaces are isolated so opening or

&#x20; previewing content does not trigger native side effects (see ASI05/ASI07).

\- \*\*Audit memory.\*\* Every consent decision is recorded for later review, so a

&#x20; manipulated approval is at least traceable.



\*\*Gaps / roadmap.\*\* Adaptive trust calibration (risk-scored autonomy, low-

certainty visual cues) and a one-click "flag suspicious behavior → lockdown"

control are not yet implemented.



\---



\## ASI10 — Rogue Agents



\*\*The risk.\*\* An agent deviates from its authorized scope — goal drift, workflow

hijacking, self-replication, reward hacking — and its individually-legitimate

actions become collectively harmful.



\*\*Our exposure.\*\* With one bounded agent, there is no collusion or self-

replication surface. The realistic concern is drift into unauthorized actions or

tampering that disables safeguards.



\*\*Our measures.\*\*



\- \*\*Bounded autonomy.\*\* The agent cannot exceed its scoped grants; high-impact

&#x20; actions require consent, so drift is contained at the action gate rather than

&#x20; free-running.

\- \*\*Signed, immutable-style audit memory\*\* of tool calls and decisions supports

&#x20; detection of "stealthy but individually legitimate" action sequences.

\- \*\*GPO kill-switch.\*\* Administrators can disable specific tools, MCP, skills,

&#x20; computer-use, local models, or providers, and force verification levels

&#x20; (`policy\_catalog.cpp`) — an out-of-band way to instantly cut capabilities.

\- \*\*Runtime tamper detection.\*\* The anti-hack module (`src/security/anti\_hack.\*`,

&#x20; `FEATURE\_ANTI\_HACKING`, shipped and tested) scans at startup for debuggers,

&#x20; inline API hooks (incl. `EtwEventWrite` blinding), suspicious modules, and RWX

&#x20; memory — so an attacker trying to \*disable\* the safeguards that keep the agent

&#x20; in-scope leaves tamper evidence. These are \*\*signals, not the boundary\*\*: they

&#x20; report and can downgrade capabilities, but the gateway stands on its own.



\*\*Gaps / roadmap.\*\* Signed per-agent behavioral manifests, watchdog/attestation

loops, and automated capability-downgrade-on-signal are designed but not fully

wired (`dehack.md` P1.2 "capability downgrade on signal change" is a next step).



\---



\## Summary



Tanit 's strongest, fully-shipped coverage is on the vectors that matter most for

a \*\*local single-user desktop agent\*\*: goal hijack via untrusted input (ASI01),

tool misuse (ASI02), code execution (ASI05), memory poisoning (ASI06), and human-

trust exploitation (ASI09) — anchored by one enforcement boundary (SecurityGateway),

signed+encrypted storage for every steering input, hardened execution/sandboxing,

and honest, advisory-only AI review.



The vectors that are only \*\*partially\*\* addressed (ASI04 supply chain, ASI07

inter-agent comms, ASI08 cascading failures, ASI10 rogue agents) are either

largely \*\*out of scope\*\* for a single-agent architecture (ASI07/ASI08) or depend

on the \*\*binary-manifest / MCP-broker roadmap\*\* in \[`dehack.md`](./dehack.md).

Those items are the priority order for closing the remaining gaps.



\## References



\- \[OWASP Agentic Top 10 (source vectors)](./OWASP.md)

\- \[Software protection / anti-hack roadmap](./dehack.md)

\- \[Secure session storage design](./ss-todos.md)

\- \[Web / WebView2 security](./web-security.md)

\- \[Sandbox architecture](./sandbox.md)

\- \[Security phases \& TODOs](./todos.md)

\- \[Public security overview](../public/v1.0/security/security-v1.0.md)

