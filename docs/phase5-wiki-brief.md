# Phase 5: Behavior and Defensive Interpretation — Wiki Brief

**For:** Marissa Turner
**From:** Moses (via Claude)
**Purpose:** Everything you need to write the Phase 5 "Behavior and Defensive Interpretation" section of the GitHub Wiki — the capstone analytical section. This is the synthesis phase that ties every prior phase together.

---

## Suggested Wiki Section Structure

1. **Introduction** — purpose of Phase 5; the synthetic nature of this section
2. **Complete Behavioral Narrative** — the full URSNIF kill chain in plain English
3. **Cross-Reference Against the Provided IOCs File**
4. **Comprehensive IOC Inventory**
5. **Custom Detection Signatures**
   - 5.1 YARA rules
   - 5.2 Custom Suricata rules
6. **Defensive Recommendations**
   - 6.1 Email gateway
   - 6.2 Endpoint
   - 6.3 Network
   - 6.4 General organizational hardening
7. **MITRE ATT&CK Mapping**
8. **Annotated Kill Chain Diagram**
9. **Closing Reflection**

---

## 1. Introduction

Phase 5 synthesizes the findings of Phases 1–4 into a coherent behavioral narrative, a comprehensive IOC inventory, custom detection signatures, and actionable defensive recommendations. This section does not introduce new technical analysis — it consolidates and operationalizes the analytical work already performed.

The deliverables of this phase are designed to answer the question: **"Given everything we have learned about URSNIF, what should an organization do to detect, prevent, or mitigate it?"**

---

## 2. Complete Behavioral Narrative

The URSNIF infection observed in the 2021-05-14 sample set proceeds through five distinct stages. Each stage was characterized through the analysis pipeline:

### Stage 1 — Delivery (Phase 2)

A phishing email is delivered to the target. The email exhibits multiple deception indicators: a forged "Re:" reply thread, an SPF authentication failure, a default Windows hostname in the Message-ID, and the bulk-mailer signature `MailBee.NET` in the X-Mailer header. The email originates from `109.42.114.126` and traverses the `mout.kundenserver.de` (1&1 IONOS) mail relay — a legitimate provider being abused for malspam. The sender domain (`.eu`) does not match the recipient domain (`.uk`), reinforcing the spoofing posture. A `.xlsb` attachment is included.

### Stage 2 — Exploitation / Initial Code Execution (Phase 2)

The user opens `I8m7XluZbbj10J53.xlsb`. The file is a defensively engineered Excel 4.0 (XLM) macro carrier — specifically designed to evade VBA-focused scanners by storing its macros in `.xlsb` binary streams (`xl/xld/`) rather than as VBA. When the user enables content, the workbook's `auto_open` formula at cell `$BA$13` fires. The malicious formulas use random-character function identifiers (e.g., `DFJDFJDF`, `FDJDFJKERJKJKER`) and are deliberately constructed to break automated deobfuscators. A DocuSign-themed lure pressures the user into enabling content under the false premise that the document is "encrypted."

### Stage 3 — Stage Acquisition (Phase 4 PCAP analysis)

The macro retrieves intermediate payload stages over HTTP. The provided PCAP confirms a `GET /presentation.dll` request to `docs.atu.ngr.mybluehost.me` (162.241.24.47) — the staging server. The full intermediate chain (Fattura.js → lista.js → block.dll, per the README's documented kill chain) is consistent with the network telemetry recovered from the PCAP.

### Stage 4 — Installation: `block.dll` Execution (Phases 3 and 4)

The DLL payload (`block.dll`) executes via `rundll32.exe block.dll,Pape1`. Static analysis (Phase 3) identified `Pape1` and `Riverslow` as URSNIF's non-standard exports. On invocation, control passes to `FUN_0103320c` — a custom obfuscated arithmetic function that mutates global state (`DAT_0104a008`, `DAT_0104a0d8`, etc.) used by downstream routines to derive decryption keys for runtime configuration and hash-based API resolution. The DLL imports only five Windows APIs by name; the remaining ~15+ APIs are resolved at runtime via `GetProcAddress` indirect calls (visible in Ghidra as `COMPUTED_CALL` annotations).

Phase 4 detonation confirmed the runtime model: `block.dll` performed extensive enumeration of `C:\Windows\System32` (file system reconnaissance) and the `HKCR\WOW6432Node\CLSID\` registry tree (COM CLSID hijacking reconnaissance). The malware's parent rundll32 process (PID 964) spawned a child rundll32 (PID 3788), and both processes subsequently exited from the active process list — consistent with **process injection into a benign host process** followed by loader cleanup.

Critically, **URSNIF wrote zero files to disk and made zero registry persistence entries** during five minutes of execution. This experimentally validates URSNIF's documented memory-resident operating model.

### Stage 5 — Command and Control (Phase 4 PCAP analysis)

`block.dll` initiates outbound HTTP C2 to `app.buboleinov.com` (34.95.142.247, hosted on Google Cloud). Before any C2 traffic, URSNIF performs three connectivity checks: a DNS query for `api.msn.com`, multiple queries for `go.microsoft.com`, and a public-IP discovery query to `myip.opendns.com` via OpenDNS resolvers. Once connectivity is confirmed, URSNIF transmits encoded data to its C2 host via long URL-safe-base64-style URIs separated by URL-encoded delimiters (`_2B` for `+`, `_2F` for `/`). The C2 channel uses HTTP with two distinct browser-spoofing User-Agent strings (Internet Explorer 11 and Firefox 86) — likely matched dynamically to the user's installed browsers. A secondary C2 host, `todo.faroin.at`, receives the longest encoded URIs and is the likely exfiltration endpoint.

Cover traffic in the form of `/favicon.ico` requests is interspersed with C2 to mimic normal browser behavior.

### Stage 6 — Actions on Objectives (inferred from URSNIF family behavior)

URSNIF is a banking trojan. Its documented in-memory operations include browser hooking, web injection (man-in-the-browser), form grabbing, and credential exfiltration. The encoded URIs to `todo.faroin.at` are consistent with this exfiltration pattern. The lab environment did not observe credential theft directly because the lab does not contain real banking credentials and URSNIF could not establish full C2 due to the DNS sinkhole limitation — but the family's documented behavior, combined with the PCAP's URI patterns, supports this characterization.

---

## 3. Cross-Reference Against the Provided IOCs File

The sample set includes a pre-documented IOC file (`2021-05-14-IOCs-for-Ursnif-infection.txt`) maintained by malware-traffic-analysis.net. Cross-referencing our independently derived IOCs against this file validates the analysis:

| Provided IOC | Our Status | Notes |
|---|---|---|
| `app.buboleinov.com` | ✅ Confirmed independently | Recovered from both live detonation and PCAP analysis |
| `todo.faroin.at` | ✅ Confirmed independently | Recovered from PCAP analysis |
| `docs.atu.ngr.mybluehost.me` | ✅ Confirmed independently | Recovered from PCAP analysis |
| `34.95.142.247` | ✅ Confirmed independently | Recovered from PCAP analysis |
| `162.241.24.47` | ✅ Confirmed independently | Recovered from PCAP analysis |
| `block.dll` SHA256 | ✅ Confirmed independently | Phase 2 hashing |
| `I8m7XluZbbj10J53.xlsb` SHA256 | ✅ Confirmed independently | Phase 2 hashing |

Note for Marissa: when finalizing the Wiki, **open the `2021-05-14-IOCs-for-Ursnif-infection.txt` file directly on REMnux** and walk through it line-by-line. Mark each provided IOC as: confirmed (we found it independently), missed (present in the file but we did not observe it — explain why), or novel (we found it but it's not in the file — explain its source). The table above is a starting point; the full file will have more granular IOCs.

---

## 4. Comprehensive IOC Inventory

A structured machine-readable IOC inventory is preserved in the repository at `reports/ursnif-2021-05-14/iocs.json`. The major categories are summarized below; refer to the JSON file for the complete authoritative source.

### File hashes (Phase 2)

| Artifact | MD5 | SHA-256 |
|---|---|---|
| Phishing email (.eml) | `3ecaacac670c10e573f81aef38ee1a05` | `5e2cbd4b03acc2d0fcb3764fda7f8b831fe9c0c441667a11ab1ee298869594e6` |
| XLSB dropper | `eb6e605d7d61d17694a6bb3c72ef04c0` | `60f0eb98765e693f80626a8ce9a80937036b480dffc2a65eca55fbc7ccc94d18` |
| block.dll (URSNIF payload) | `5a7c87dab250cee78ce63ac34117012b` | `8a26c32848c9ea085505359f67927d1a744ec07303ed0013e592eca6b4df4790` |
| Provided PCAP | `811fb8b5efca216dfb4d7a0ef4055a2b` | `d8121c60f63cbbab4f04b466395ced4548591fc1b29de74637eeb5dae585fd7e` |
| Provided IOCs file | `2cff80b92e5874026a2f88986f7b4041` | `c1c831e995a63ea22719f61382db7dd114723982df76ac99a1526186b5cc0b72` |

### Network — C2 domains

- `app.buboleinov.com` — primary C2 (confirmed in lab + PCAP)
- `todo.faroin.at` — secondary C2 (PCAP)
- `docs.atu.ngr.mybluehost.me` — staging server (PCAP)

### Network — C2 IP addresses

- `34.95.142.247` — primary C2 (Google Cloud)
- `162.241.24.47` — staging server (Bluehost)

### Network — behavioral fingerprints

- `api.msn.com`, `go.microsoft.com` — connectivity check
- `myip.opendns.com`, `resolver1.opendns.com` — public-IP discovery

### Network — HTTP patterns

- `GET /presentation.dll` against `docs.atu.ngr.mybluehost.me` — secondary stage download
- `GET /[long-base64-style-path]` against `app.buboleinov.com` and `todo.faroin.at` — C2 communication
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko` (IE 11 spoof)
- User-Agent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0` (Firefox 86 spoof)

### Host indicators

- `rundll32.exe` invocations targeting non-system DLLs with non-standard exports (`Pape1`, `Riverslow`)
- Self-spawned `rundll32.exe` child followed by both processes exiting (process injection signal)
- Reconnaissance reads against `HKCR\WOW6432Node\CLSID\{*}` and `HKLM\SOFTWARE\Microsoft\Ole`
- Embedded PDB path: `c:\Whether\class\156\Through\How.pdb`
- PE debug GUID: `C73B28130056411D84ED718996F219E04`

---

## 5. Custom Detection Signatures

### 5.1 YARA Rules (file-level detection)

Authored in Phase 2 and stored at `rules/yara/`:

| Rule file | Rules | Purpose |
|---|---|---|
| `ursnif-dll.yar` | `URSNIF_block_dll_2021_05_14`, `URSNIF_heuristic_section_unpacking` | Detect block.dll specifically (PDB path, export combination, debug GUID); detect generic packed-PE pattern (section vsize anomaly heuristic) |
| `ursnif-dropper.yar` | `URSNIF_xlsb_dropper_2021_05_14`, `URSNIF_xlsb_unzipped_xlm_content` | Detect raw .xlsb with XLM macros via ZIP central directory; detect unzipped .xlsb content (obfuscated XLM identifiers + DocuSign lure) |

All four rules verified against the sample artifacts during Phase 2 (with the dropper rule revised after initial verification — see Phase 2 brief Section 6 for the revision narrative).

### 5.2 Custom Suricata Rules (network-level detection)

Authored in Phase 5 and stored at `rules/suricata/custom.rules`. Twelve rules across five categories, all in the SID range `4300xxx` (CSEC 4300 course namespace):

| SID | Category | Detection target | Severity |
|---|---|---|---|
| 4300001 | DNS | `app.buboleinov.com` query | Critical |
| 4300002 | DNS | `todo.faroin.at` query | Critical |
| 4300003 | DNS | `docs.atu.ngr.mybluehost.me` query | High |
| 4300004 | DNS | `myip.opendns.com` (URSNIF behavioral) | Medium |
| 4300010 | IP | Outbound connection to `34.95.142.247` | Critical |
| 4300011 | IP | Outbound connection to `162.241.24.47` | High |
| 4300020 | HTTP | Host header `app.buboleinov.com` | Critical |
| 4300021 | HTTP | Host header `todo.faroin.at` | Critical |
| 4300022 | HTTP | `GET /presentation.dll` to staging host | Critical |
| 4300023 | HTTP | URSNIF C2 URI structural pattern (long base64 + URL-encoded delimiters) | High |
| 4300030 | HTTP UA | IE 11 spoof targeting URSNIF C2 hosts | High |
| 4300031 | HTTP UA | Firefox 86 spoof targeting URSNIF C2 hosts | High |
| 4300040 | DNS (info) | `api.msn.com` query — for SIEM correlation | Informational |

Rules are organized by detection layer (DNS → IP → HTTP host → HTTP URI → User-Agent → behavioral correlation) so that defense-in-depth is preserved if any single rule misses (e.g., due to C2 domain rotation).

---

## 6. Defensive Recommendations

These recommendations are organized by the layer at which they would intercept a URSNIF infection. They are derived directly from the IOCs and behaviors observed across Phases 1–4.

### 6.1 Email Gateway

The infection chain begins with a phishing email containing a `.xlsb` attachment. Email gateway controls offer the highest-leverage prevention point.

- **Block `.xlsb` attachments at the email gateway by default**, with allowlists for trusted internal sources only. The legitimate use of `.xlsb` (Excel Binary Workbook) in business communication is rare; the format's primary use case in 2021–2026 has been malware distribution due to its evasion of VBA-focused scanners.
- **Apply YARA rule `URSNIF_xlsb_dropper_2021_05_14`** to attachments at the gateway. The rule matches the `.xlsb` ZIP central directory entries for XLM macrosheets and is a strong content-based filter.
- **SPF / DKIM / DMARC enforcement** with `p=reject` for inbound email. The Phase 2 email analysis identified an SPF FAIL on the malicious email; an enforcing policy would have rejected it.
- **Banner external email** with a visible warning, particularly when the email purports to be a reply to an internal thread. The phishing email's `In-Reply-To` and `References` headers were forged to feign an ongoing conversation.

### 6.2 Endpoint

If the email reaches a user and they enable macros, endpoint controls become the next line of defense.

- **Disable Office macros by default via Group Policy** for all users; require explicit administrative review for any exception. Block legacy XLM (Excel 4.0) macros entirely — they have no legitimate use case in modern Office deployments.
- **Block `rundll32.exe` execution targeting DLLs in user-writable directories** (e.g., `%TEMP%`, `%APPDATA%`, `%USERPROFILE%\Downloads`). URSNIF's invocation `rundll32.exe block.dll,Pape1` from a non-system path is a high-fidelity indicator.
- **Alert on `rundll32.exe` invocations with non-standard export names** (i.e., not `DllMain`, `DllRegisterServer`, `DllInstall`, etc.). The `Pape1` and `Riverslow` exports are unusual and would be flagged.
- **Deploy YARA rule `URSNIF_block_dll_2021_05_14`** in EDR file-scanning to detect block.dll on disk before execution.
- **Monitor `HKCR\WOW6432Node\CLSID\` registry tree** for read patterns from short-lived processes (URSNIF's COM hijacking reconnaissance).
- **Application allowlisting** for executables and DLLs in business-critical environments. URSNIF cannot execute if `block.dll` is not in the allowlist.

### 6.3 Network

If the malware reaches execution, network controls intercept the C2 channel.

- **Deploy the custom Suricata rules in `rules/suricata/custom.rules`.** The rules are organized by detection layer for defense-in-depth.
- **DNS-based filtering** of the confirmed C2 domains (`app.buboleinov.com`, `todo.faroin.at`, `docs.atu.ngr.mybluehost.me`) at the recursive resolver level. Many DNS-filtering products accept domain blocklists as input.
- **TLS / HTTPS interception (or at minimum SNI inspection)** for outbound connections. URSNIF samples in the wild often use HTTPS; the 2021-05-14 sample uses HTTP, but other URSNIF builds may not.
- **Network segmentation** to isolate user workstations from internet egress except via authenticated proxies. URSNIF's outbound HTTP would be visible and blockable at the proxy.
- **Cloud-IP-reputation correlation**. The primary C2 IP (`34.95.142.247`) is on Google Cloud; the staging server is on Bluehost. Outbound connections from end-user workstations to public cloud IPs that are not part of normal business communication patterns warrant inspection.

### 6.4 General Organizational Hardening

Cross-cutting defenses that reduce overall risk surface.

- **User awareness training** specifically on social-engineering pressure tactics ("THIS DOCUMENT IS ENCRYPTED — Enable Editing → Enable Content"). The DocuSign-themed lure is a recurring URSNIF technique.
- **Privilege minimization** — users do not need local administrator rights to do most work, and reducing default privileges limits what a compromised process can do.
- **Browser hardening** to reduce form-grabbing effectiveness — encourage password managers (which type credentials into hidden fields the trojan cannot reach), enforce HSTS, and disable browser auto-fill of sensitive forms by policy.
- **Centralized log collection** of DNS queries, HTTP proxy logs, and EDR telemetry into a SIEM, with correlation rules that combine the behavioral indicators (e.g., "host queried api.msn.com AND queried any of [C2 list] within 60 seconds → escalate"). The Suricata rule `4300040` is designed as input for this kind of SIEM correlation.

---

## 7. MITRE ATT&CK Mapping

A complete machine-readable MITRE mapping is included in `iocs.json`. Summary by tactic:

| Tactic | Technique | Sub-Technique | Phase 1–4 Evidence |
|---|---|---|---|
| Initial Access | T1566 Phishing | .001 Spearphishing Attachment | Phase 2 .eml analysis |
| Execution | T1059 Command and Scripting Interpreter | .005 Visual Basic / Excel 4.0 | Phase 2 XLM auto_open at $BA$13 |
| Execution | T1218 System Binary Proxy Execution | .011 Rundll32 | Phase 4 rundll32.exe block.dll,Pape1 |
| Execution | T1129 Shared Modules | — | Phase 2 capa identification |
| Defense Evasion | T1027 Obfuscated Files or Information | — | Phase 3 FUN_0103320c arithmetic; Phase 2 XLM random function names |
| Defense Evasion | T1027.007 Dynamic API Resolution | — | Phase 2/3 GetProcAddress COMPUTED_CALL pattern |
| Defense Evasion | T1055 Process Injection | — | Phase 4 rundll32 self-spawn-and-exit |
| Defense Evasion | T1622 Debugger Evasion | — | Phase 2/3 IsDebuggerPresent import |
| Discovery | T1614 System Location Discovery | — | Phase 2 capa + country strings in .data |
| Discovery | T1083 File and Directory Discovery | — | Phase 4 ProcMon System32 enumeration |
| Discovery | T1012 Query Registry | — | Phase 4 ProcMon CLSID/OLE probing |
| Command and Control | T1071 Application Layer Protocol | .001 Web Protocols | Phase 4 PCAP HTTP C2 |
| Command and Control | T1102 Web Service | — | Phase 4 api.msn.com / myip.opendns.com |
| Command and Control | T1583 Acquire Infrastructure | .006 Web Services | Phase 4 Google Cloud + Bluehost C2 hosting |

---

## 8. Annotated Kill Chain Diagram

> Marissa: build a kill-chain diagram for the Wiki using the structure below. Suggested format: a vertical flow chart with five boxes (one per stage), each annotated with which Phase uncovered which evidence. Use any diagramming tool you prefer — draw.io, Lucidchart, or just a clean ASCII diagram if time is tight.

```
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — DELIVERY                                  [Phase 2]      │
│  Phishing email (2021-05-03-malspam-pushing-Ursnif.eml)            │
│  → Spoofed reply thread, SPF FAIL, MailBee.NET X-Mailer            │
│  → Malicious .xlsb attachment                                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ user opens attachment, enables content
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 2 — EXPLOITATION                              [Phase 2]      │
│  XLSB dropper (I8m7XluZbbj10J53.xlsb)                               │
│  → XLM auto_open at cell $BA$13                                    │
│  → Random-character function names (anti-deobfuscation)            │
│  → DocuSign-themed lure                                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ macro retrieves intermediate stages
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 3 — STAGE ACQUISITION                         [Phase 4]      │
│  HTTP GET to docs.atu.ngr.mybluehost.me (162.241.24.47)            │
│  → Downloads /presentation.dll (intermediate stage)                │
│  → Per kill chain: Fattura.js → lista.js → block.dll               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ block.dll is launched via rundll32
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 4 — INSTALLATION                              [Phases 3+4]   │
│  rundll32.exe block.dll,Pape1                                       │
│  → FUN_0103320c arms runtime config / decryption seed               │
│  → 15+ GetProcAddress COMPUTED_CALL → dynamic API resolution        │
│  → System32 enumeration + COM/OLE registry probing                  │
│  → Self-spawn-and-exit pattern (process injection)                  │
│  → Memory-resident: zero file writes, zero registry persistence     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ injected URSNIF code initiates C2
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 5 — COMMAND AND CONTROL                       [Phase 4]      │
│  Connectivity check (api.msn.com, go.microsoft.com)                 │
│  Public-IP discovery (myip.opendns.com via 208.67.222.222)         │
│  HTTP C2 → app.buboleinov.com (34.95.142.247, Google Cloud)        │
│  HTTP exfiltration → todo.faroin.at                                 │
│  → Long URL-safe-base64-style URIs (encoded payload)                │
│  → Two browser-spoofing User-Agents (IE 11, Firefox 86)             │
│  → /favicon.ico cover traffic                                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STAGE 6 — ACTIONS ON OBJECTIVES                     [inferred]     │
│  Banking trojan operations (URSNIF family behavior):                │
│  → Browser hooking, web injection, form grabbing                    │
│  → Credential exfiltration via encoded HTTP URIs                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Closing Reflection

URSNIF is a mature, defensively engineered banking trojan whose 2021-05-14 sample demonstrates the family's core operational philosophy: **defeat each layer of the analyst's toolkit at the layer where it operates.**

- VBA-focused macro scanners are defeated by XLM in `.xlsb` containers
- Automated XLM deobfuscators are defeated by malformed-token formulas
- Static IOC extractors are defeated by runtime decryption of all configuration
- Import-table analysis is defeated by `GetProcAddress` indirect-call API resolution
- Disk-based forensics is defeated by memory-resident operation
- Commercial packer detection is defeated by custom inline obfuscation
- Persistence-focused EDR is defeated by zero-write injection into a benign host process

The analysis pipeline of Phases 1–5 demonstrates that no single analytical technique was sufficient; only the layered application of static binary analysis, assembly-level code reading, dynamic execution, network capture analysis, and IOC synthesis produced the complete picture. **This layered methodology is itself the defensive recommendation:** organizations that rely on any single detection layer will miss URSNIF-class threats, and the custom YARA + custom Suricata + behavioral SIEM correlation stack proposed in Section 6 is the operationalization of that methodology for ongoing defense.

---

## Notes for Marissa

- This is the longest of the four briefs because it's the synthesis section — it ties Phases 1–4 together. **Don't try to summarize this any further; the volume is appropriate for a capstone.**
- Section 9 (Closing Reflection) is intentionally rhetorical and forward-looking. It's also the strongest paragraph in the whole report. Keep it largely intact in your prose.
- Section 8 (Kill Chain Diagram) — the ASCII version above is functional. If you have time, build a proper visual (draw.io is free, exports to PNG). If not, the ASCII version is acceptable in a Wiki page rendered in a monospace block.
- The `iocs.json` file is the authoritative IOC source for the project. All inline tables in this brief reference back to it. If anything ever needs updating, update `iocs.json` first and propagate.
- Cross-reference Section 3 against the actual provided IOCs file on REMnux before the Wiki goes final.
- The MITRE table in Section 7 is also in `iocs.json` — keep them consistent if you edit one.
