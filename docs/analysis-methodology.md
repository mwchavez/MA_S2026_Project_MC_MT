# Analysis Methodology

**Project:** CSEC 4300 — Malware Analysis (URSNIF)
**Authors:** Moses Chavez, Marissa Turner
**Last updated:** April 2026

This document describes the analytical framework that organizes the project's five-phase malware analysis pipeline. It explains *why* the project is structured the way it is, *how* each phase informs the next, and *what* threat-modeling and detection-engineering principles are applied.

---

## 1. Framework

The analysis pipeline is organized around three intersecting models:

### 1.1 Lockheed Martin Cyber Kill Chain

We map URSNIF's behavior to the kill chain stages:

1. Reconnaissance (out of scope — pre-analysis)
2. Weaponization (URSNIF developer's compilation of `block.dll`)
3. **Delivery** — phishing email
4. **Exploitation** — XLSB macro execution
5. **Installation** — `block.dll` execution and process injection
6. **Command and Control** — HTTP C2 to confirmed domains/IPs
7. **Actions on Objectives** — banking-trojan operations (browser hooking, credential theft)

### 1.2 Diamond Model

Each IOC is contextualized along four axes:

- **Adversary** — the URSNIF threat actor cluster
- **Infrastructure** — domains, IPs, hosting providers (Google Cloud, Bluehost)
- **Capability** — XLM macro evasion, runtime API resolution, process injection, in-memory operation
- **Victim** — the simulated target (a Windows endpoint user opening an email attachment)

### 1.3 MITRE ATT&CK

Specific techniques are mapped to ATT&CK throughout the analysis. The complete mapping is in `reports/ursnif-2021-05-14/iocs.json`. Major techniques include T1566.001 (Spearphishing Attachment), T1059.005 (Visual Basic / XLM), T1218.011 (Rundll32), T1027.007 (Dynamic API Resolution), T1055 (Process Injection), T1071.001 (Web Protocols).

---

## 2. Five-Phase Pipeline

Each phase has a defined scope, deliverables, and feeds the next phase. The pipeline is **deliberately layered** so that no single analytical technique is responsible for the complete picture — URSNIF is engineered to defeat individual layers, so we use multiple in series.

### 2.1 Phase 1 — Environment Setup

**Scope.** Construct the isolated three-VM lab. Validate isolation. Establish snapshot discipline.

**Output.** A reproducible analysis environment, documented in `docs/lab-setup-guide.md`.

**Why first.** No malware analysis can begin without a contained environment. Phase 1 establishes the safety baseline that the rest of the project depends on.

### 2.2 Phase 2 — Static Analysis

**Scope.** All artifacts (`.eml`, `.xlsb`, `block.dll`, `.pcap`, `IOCs.txt`) are analyzed without execution. Hashes are computed. Email headers, MIME structure, and XLM macros are parsed. The DLL's PE headers, sections, imports, exports, strings, and capabilities are extracted.

**Output.** `reports/ursnif-2021-05-14/static-analysis.md`. Initial behavioral hypotheses formed from static evidence alone.

**Why second.** Static analysis is fast, safe, and broad. It catalogs what a binary contains; the dynamic phases will reveal what it does. Static findings shape what we look for in dynamic analysis.

**Key methodological note.** Static analysis surfaced **no plaintext IOCs** in `block.dll` — no URLs, no registry paths, no User-Agents. This is itself a finding: it tells us the malware decrypts its configuration at runtime. It also predicts that Phase 4 will recover the IOCs that Phase 2 cannot.

### 2.3 Phase 3 — Assembly-Level Code Analysis

**Scope.** `block.dll` is loaded into Ghidra. Cross-references from suspicious imports identify candidate functions. Library code is triaged out using Ghidra's Function ID feature. At least one meaningful URSNIF function is selected and analyzed in plain English.

**Output.** `reports/ursnif-2021-05-14/assembly-analysis.md`. The analysis selected `FUN_0103320c` — a runtime configuration / key-derivation helper called directly from the `Pape1` export.

**Why third.** Phase 2 identifies *where* in the binary suspicious activity is concentrated (via imports, strings, capa). Phase 3 uses that to navigate efficiently to specific functions. The kickoff guide explicitly warns against exhaustive decompilation; the focus is **recognition and explanation** of patterns.

**Key methodological note.** A significant portion of `block.dll` is statically-linked Microsoft Visual C Runtime code. Following imports alone leads the analyst into MSVC functions like `_initptd`, `__crtMessageBoxA`, and `__sbh_alloc_new_region` — code that is benign Microsoft library code, not URSNIF logic. The analytical pivot: filter the function tree to `FUN_*` (Ghidra-discovered, Function-ID-unmatched) entries, then follow XREFs from the malware's exports (`Pape1`, `Riverslow`). This is a transferable technique for any statically-linked malware.

### 2.4 Phase 4 — Dynamic and Memory Analysis

**Scope.** `block.dll` is detonated in the isolated detonation VM via `rundll32.exe block.dll,Pape1`. Process Monitor, Process Explorer, and Wireshark capture host and network behavior. A memory dump of the running VM is captured via `VBoxManage debugvm`. The provided 2021-05-14 PCAP is analyzed with `tshark` to recover network IOCs that the lab environment could not surface.

**Output.** `reports/ursnif-2021-05-14/dynamic-analysis.md`. Confirmed C2 domain `app.buboleinov.com`, confirmed C2 IPs, full URI patterns, browser-spoofing User-Agent strings.

**Why fourth.** Dynamic analysis recovers what static analysis hides: the runtime-decrypted configuration, the actual API-resolution chain, the network behavior. Phase 4 also experimentally validates Phase 3 hypotheses (e.g., the prediction that URSNIF operates memory-only and writes nothing to disk was confirmed: zero `WriteFile` and zero `RegSetValue` events during five minutes of execution).

**Key methodological note.** The lab's INetSim DNS service-bind failure is documented honestly as a limitation: URSNIF could not establish full C2 in the live environment. The mitigation is the provided PCAP, which contains the original 2021 C2 traffic and is analyzed in parallel with the live capture. This dual approach — live detonation for behavior, provided PCAP for network IOCs — produces a complete picture.

### 2.5 Phase 5 — Behavior and Defensive Interpretation

**Scope.** Synthesis. All findings are aggregated into a structured IOC inventory (`iocs.json`). Custom Suricata rules are authored against the recovered network IOCs. Defensive recommendations are generated across email, endpoint, network, and organizational layers. The complete behavioral narrative — the kill chain across all five stages — is written.

**Output.** `reports/ursnif-2021-05-14/kill-chain.md`, `reports/ursnif-2021-05-14/iocs.json`, `rules/suricata/custom.rules`, the Phase 5 Wiki section.

**Why fifth.** The point of malware analysis is not to understand a single sample for its own sake — it is to operationalize the understanding into defenses. Phase 5 converts the prior phases' analytical findings into deployable detection signatures and policy recommendations.

---

## 3. Cross-Phase Validation

The pipeline is designed so that findings from one phase predict and validate findings in another:

| Prediction (from) | Validated in | Outcome |
|---|---|---|
| `.data` virtual size 264× raw size = runtime unpacking (Phase 2) | Phase 3 | Confirmed: `FUN_0103320c` arithmetic mutates global state at fixed offsets in `.data` |
| Zero plaintext IOC strings in binary (Phase 2) | Phase 4 | Confirmed: all C2 domains/URIs are constructed at runtime |
| `capa` "execute shellcode via indirect call" + "link many functions at runtime" (Phase 2) | Phase 3 | Confirmed: 15 `GetProcAddress` `COMPUTED_CALL` sites |
| `FUN_0103320c` operates entirely on in-memory globals (Phase 3) | Phase 4 | Confirmed: zero WriteFile/RegSetValue events |
| Dynamic API resolution → runtime-decrypted C2 config (Phase 3) | Phase 4 | Confirmed: PCAP shows full HTTP C2 with encoded URIs |

When a prediction was *not* validated (e.g., the lab's DNS sinkhole prevented full HTTP C2 in the live environment), the limitation is documented honestly and the gap is closed by parallel evidence (e.g., PCAP analysis recovers what the lab missed).

---

## 4. Detection Engineering

The defensive output is layered to match URSNIF's defensive engineering. URSNIF defeats individual analytical layers; defenders must therefore use multiple in series. The custom rule set is structured accordingly:

| Detection layer | Coverage | Failure mode if used alone |
|---|---|---|
| Email gateway (.xlsb block, SPF/DKIM/DMARC, YARA on attachments) | Stops the campaign before user interaction | A targeted user with allowlist exception, or a different file type, bypasses |
| Endpoint (macro disable, rundll32 monitoring, EDR YARA scan) | Stops execution after delivery | Living-off-the-land techniques bypass macro and rundll32 checks |
| Network (Suricata DNS, IP, HTTP rules) | Catches C2 even if execution succeeds | C2 infrastructure rotation invalidates static-IOC rules |
| Behavioral (SIEM correlation: connectivity check + C2 within 60s) | Catches novel infrastructure that hits the same behavioral pattern | High noise — only valuable as correlation input, not a primary alert |

The custom Suricata rules in `rules/suricata/custom.rules` cover the network layer with twelve rules across DNS, IP, HTTP host, HTTP URI, User-Agent, and behavioral correlation. The custom YARA rules in `rules/yara/` cover the email-gateway and endpoint layers.

---

## 5. Documentation Standards

The project produces three categories of documentation:

| Category | Audience | Style | Location |
|---|---|---|---|
| **Wiki briefs** | Marissa (project author) | Outline + findings + screenshot map; instructional | `docs/wiki-briefs/` |
| **Analysis reports** | Future analysts, instructor | Formal, self-contained, evidence-based | `reports/ursnif-2021-05-14/` |
| **Reference docs** | Lab reproducer | Procedural, command-level | `docs/lab-setup-guide.md`, `docs/tool-reference.md`, this file |

All numerical claims in the reports are sourced to a screenshot, a tool output, or a publicly available reference. No claim is made on memory or assumption; if a fact is asserted, it is traceable to evidence on disk.

---

## 6. Limitations and Honest Disclosures

The project is academic, not operational. Specific limitations honestly disclosed:

1. **Live DNS sinkhole did not fully bind during Phase 4.** Mitigation: PCAP analysis recovers the network IOCs.
2. **Volatility 3 was not installed during the analysis window.** Mitigation: Memory dump preserved (8.73 GB ELF on host) for offline analysis; behavioral memory observations from ProcMon documented in Phase 4.
3. **Security Onion ingested the PCAP successfully but the standard Alerts dashboard did not surface signature matches** at the PCAP's 2021 date range. Mitigation: this is documented as the rationale for Phase 5's custom Suricata rules — bundled signatures from March 2026 may have aged out for 2021 traffic, and custom rules derived from observed traffic are a more rigorous deliverable.
4. **The lab environment cannot observe credential theft directly** because no real banking credentials exist in the lab. URSNIF's banking-trojan operations are inferred from family behavior + observed URI patterns, not directly demonstrated.

These limitations do not invalidate the analysis. They are documented so that the reader knows precisely what the project demonstrates experimentally versus what it relies on documented family behavior to characterize.
