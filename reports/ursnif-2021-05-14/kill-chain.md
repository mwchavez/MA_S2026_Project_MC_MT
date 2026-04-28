# URSNIF Kill Chain — 2021-05-14 Infection

**Authors:** Moses Chavez, Marissa Turner
**Sample source:** `https://www.malware-traffic-analysis.net/2021/05/14/index.html`
**Last updated:** April 2026

This document presents the complete URSNIF infection kill chain for the 2021-05-14 sample, synthesizing findings from Phases 1–4. Each stage is annotated with the analytical phase that uncovered the corresponding evidence.

---

## 1. Stages

### Stage 1 — Delivery [Phase 2]

A phishing email (`2021-05-03-malspam-pushing-Ursnif.eml`) is delivered to the target. The email exhibits multiple deception indicators:

- Forged `Re:` reply thread with fabricated `In-Reply-To` and `References` headers
- SPF authentication FAIL — the sender domain does not designate the originating host
- Default Windows hostname (`WIN-56T8FAGBN10`) in the Message-ID, suggesting a throwaway or compromised host
- `MailBee.NET 12.0.0.615` X-Mailer header — bulk-mailing library commonly abused by spammers
- Originating IP `109.42.114.126` traverses `mout.kundenserver.de` (1&1 IONOS) — legitimate provider abused for malspam
- Sender domain `.eu`, recipient domain `.uk` — cross-domain spoofing
- Attachment: `I8m7XluZbbj10J53.xlsb` (94.3 KB)

The attachment hash, extracted from the email and computed independently, matches the standalone `.xlsb` artifact, establishing the email as the confirmed delivery vector.

### Stage 2 — Exploitation [Phase 2]

The user opens `I8m7XluZbbj10J53.xlsb`. The file is a defensively engineered Excel 4.0 (XLM) macro carrier — specifically designed to evade VBA-focused scanners by storing macros in `.xlsb` binary streams (`xl/xld/`) rather than as VBA. When the user enables content, the workbook's `auto_open` formula at cell `$BA$13` fires.

The malicious formulas use random-character function identifiers (`DFJDFJDF`, `FDJDFJKERJKJKER`) and are deliberately constructed to break automated deobfuscators (`XLMMacroDeobfuscator` failed parsing at column 368). A DocuSign-themed lure pressures the user into enabling content under the false premise that the document is "encrypted."

### Stage 3 — Stage Acquisition [Phase 4]

The macro retrieves intermediate payload stages over HTTP. The provided PCAP confirms a `GET /presentation.dll` request to `docs.atu.ngr.mybluehost.me` (`162.241.24.47`) — the staging server. The full intermediate chain (Fattura.js → lista.js → block.dll, per the documented kill chain) is consistent with the network telemetry recovered.

### Stage 4 — Installation [Phases 3 + 4]

The DLL payload (`block.dll`) executes via:

```
rundll32.exe block.dll,Pape1
```

Static analysis identified `Pape1` and `Riverslow` as URSNIF's non-standard exports. On invocation, control passes to `FUN_0103320c` — a custom obfuscated arithmetic function that mutates global state (`DAT_0104a008`, `DAT_0104a0d8`, `DAT_0104a0dc`, `DAT_0104a010`, `DAT_0104a00c`) used by downstream routines to derive decryption keys for runtime configuration and hash-based API resolution. The DLL imports only five Windows APIs by name; the remaining 15+ APIs are resolved at runtime via `GetProcAddress` indirect calls (visible in Ghidra as `COMPUTED_CALL` annotations).

Phase 4 detonation confirmed the runtime model:

- Extensive `QueryDirectory` enumeration of `C:\Windows\System32` (file system reconnaissance)
- COM/OLE registry probing of `HKCR\WOW6432Node\CLSID\` (COM CLSID hijacking reconnaissance)
- The parent `rundll32.exe` (PID 964) spawned a child `rundll32.exe` (PID 3788); both processes subsequently exited from the active process list — consistent with process injection into a benign host process followed by loader cleanup

Critically, **URSNIF wrote zero files to disk and made zero registry persistence entries** during five minutes of execution. This experimentally validates URSNIF's documented memory-resident operating model.

### Stage 5 — Command and Control [Phase 4]

`block.dll` initiates outbound HTTP C2 to `app.buboleinov.com` (`34.95.142.247`, hosted on Google Cloud). Before any C2 traffic, URSNIF performs three connectivity checks:

- DNS query for `api.msn.com` (Microsoft service used as a "do I have internet" probe)
- Multiple queries for `go.microsoft.com` (secondary check)
- Public-IP discovery via `myip.opendns.com` queried through `resolver1.opendns.com` / `208.67.222.222`

Once connectivity is confirmed, URSNIF transmits encoded data to its C2 host via long URL-safe-base64-style URIs separated by URL-encoded delimiters (`_2B` for `+`, `_2F` for `/`). The C2 channel uses HTTP with two distinct browser-spoofing User-Agent strings:

- Internet Explorer 11 spoof: `Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko`
- Firefox 86 spoof: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0`

Both User-Agents observed against the same C2 host — consistent with URSNIF's documented technique of dynamically matching its outbound C2 fingerprint to the user's installed browsers.

A secondary C2 host, `todo.faroin.at`, receives the longest encoded URIs and is the likely exfiltration endpoint. Cover traffic in the form of `/favicon.ico` requests is interspersed with C2 to mimic normal browser behavior.

### Stage 6 — Actions on Objectives [Inferred]

URSNIF is a banking trojan. Its documented in-memory operations include browser hooking, web injection (man-in-the-browser), form grabbing, and credential exfiltration. The encoded URIs to `todo.faroin.at` are consistent with this exfiltration pattern.

The lab environment did not observe credential theft directly — the lab contains no real banking credentials and URSNIF could not establish full C2 due to the DNS sinkhole limitation (see `dynamic-analysis.md` Section 8.1). The family's documented behavior, combined with the PCAP's URI patterns, supports this characterization.

---

## 2. Diagram

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
│  STAGE 6 — ACTIONS ON OBJECTIVES                     [Inferred]     │
│  Banking trojan operations (URSNIF family behavior):                │
│  → Browser hooking, web injection, form grabbing                    │
│  → Credential exfiltration via encoded HTTP URIs                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detection Opportunities by Stage

The following table maps each kill chain stage to the detection mechanism that would have intercepted the infection:

| Stage | Detection mechanism | Implemented in this project |
|---|---|---|
| 1. Delivery | Email gateway: `.xlsb` attachment block, SPF/DKIM/DMARC enforcement, content YARA rules | YARA rule `URSNIF_xlsb_dropper_2021_05_14` (`rules/yara/`) |
| 2. Exploitation | Endpoint: macro disable via Group Policy, XLM-specific blocking | Recommended in `reports/.../iocs.json` defensive recommendations |
| 3. Stage Acquisition | Network: HTTP request to staging URL | Suricata SID `4300022` (`/presentation.dll` → staging host) |
| 4. Installation | Endpoint: rundll32 + non-standard export monitoring; YARA on disk; behavior alerts on rundll32 self-spawn | YARA rule `URSNIF_block_dll_2021_05_14`; behavioral recommendations |
| 5. Command and Control | Network: DNS, IP, HTTP host, URI pattern, User-Agent rules | Suricata SIDs `4300001-4300031` (`rules/suricata/custom.rules`) |
| 6. Actions on Objectives | Endpoint: in-memory browser hook detection (out of scope for this project) | Documented as future work |

---

## 4. References

- **Source page:** `https://www.malware-traffic-analysis.net/2021/05/14/index.html`
- **Static analysis:** `reports/ursnif-2021-05-14/static-analysis.md`
- **Assembly analysis:** `reports/ursnif-2021-05-14/assembly-analysis.md`
- **Dynamic analysis:** `reports/ursnif-2021-05-14/dynamic-analysis.md`
- **IOC inventory:** `reports/ursnif-2021-05-14/iocs.json`
- **Detection rules:** `rules/suricata/custom.rules`, `rules/yara/`
