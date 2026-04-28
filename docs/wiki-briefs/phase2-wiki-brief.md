# Phase 2: Static Analysis — Wiki Brief

**For:** Marissa Turner
**From:** Moses (via Claude)
**Purpose:** Everything you need to write the Phase 2 "Static Analysis" section of the GitHub Wiki. All technical research is done — this gives you the outline, the findings, the hash/IOC tables, and the screenshot placement map. Write the prose in your voice; the facts are confirmed.

---

## Suggested Wiki Section Structure

1. **Introduction** — 1 short paragraph (goals of Phase 2, artifacts analyzed, tools used)
2. **Artifact Hash Inventory** — table (ready below)
3. **Email Analysis** (`.eml`)
4. **Excel Dropper Analysis** (`.xlsb`)
5. **DLL Payload Analysis** (`block.dll`)
6. **YARA Rule Development** (brief — point to the `rules/yara/` directory)
7. **Initial Behavioral Hypotheses**
8. **Transition to Phase 3** (1–2 sentences — "These static indicators informed the assembly-level analysis of block.dll in Phase 3.")

---

## Tools Used in Phase 2

| Tool | Purpose | VM |
|---|---|---|
| `md5sum`, `sha256sum` | Cryptographic hashing | REMnux |
| `less` / text editor | Raw email header inspection | REMnux |
| `emldump.py` | MIME structure parsing and attachment extraction | REMnux |
| `olevba` | VBA macro extraction (result: no VBA found) | REMnux |
| `oletools` | Office document structure inspection | REMnux |
| `XLMMacroDeobfuscator` | XLM (Excel 4.0) macro deobfuscation | REMnux |
| `unzip` | XLSB container structure inspection | REMnux |
| `rabin2` | PE header, section, import, export, and string extraction | REMnux |
| `capa` | Capability detection and MITRE ATT&CK mapping | REMnux |
| `file` | File type identification | REMnux |
| `yara` | File-level signature matching | REMnux |

**Rationale for REMnux-only Phase 2:** All static analysis was performed on REMnux without transferring `block.dll` to the detonation VM. This minimizes risk of accidental execution and keeps the malware contained to the analysis workstation until Phase 3 (Ghidra) and Phase 4 (detonation).

---

## Artifact Hash Inventory

| Artifact | MD5 | SHA-256 |
|---|---|---|
| `2021-05-03-malspam-pushing-Ursnif.eml` | `3ecaacac670c10e573f81aef38ee1a05` | `5e2cbd4b03acc2d0fcb3764fda7f8b831fe9c0c441667a11ab1ee298869594e6` |
| `2021-05-14-IOCs-for-Ursnif-infection.txt` | `2cff80b92e5874026a2f88986f7b4041` | `c1c831e995a63ea22719f61382db7dd114723982df76ac99a1526186b5cc0b72` |
| `2021-05-14-Ursnif-infection-traffic.pcap` | `811fb8b5efca216dfb4d7a0ef4055a2b` | `d8121c60f63cbbab4f04b466395ced4548591fc1b29de74637eeb5dae585fd7e` |
| `I8m7XluZbbj10J53.xlsb` | `eb6e605d7d61d17694a6bb3c72ef04c0` | `60f0eb98765e693f80626a8ce9a80937036b480dffc2a65eca55fbc7ccc94d18` |
| `block.dll` | `5a7c87dab250cee78ce63ac34117012b` | `8a26c32848c9ea085505359f67927d1a744ec07303ed0013e592eca6b4df4790` |

📸 **Screenshot #24** — combined `ls -la` listing and `md5sum` + `sha256sum` output for all five artifacts on REMnux. Place this screenshot next to the hash table.

---

## 3. Email Analysis (`.eml`)

### Kill chain role
**Delivery** — initial access vector.

### Methodology (1 sentence)
Raw email inspected with `less`, MIME structure parsed with `emldump.py`, and the embedded attachment extracted and hashed to verify chain of custody against the standalone `.xlsb` artifact.

### Key findings (include all of these in prose)

| Finding | Detail |
|---|---|
| **Subject line** | `Re: Your [information removed] Application` — fake "reply" prefix to simulate ongoing correspondence |
| **Date** | `Mon, 03 May 2021 17:40:08 +0300` (originating timezone = Eastern European / Russia-adjacent) |
| **From / To domain mismatch** | Sender domain `.eu`, recipient domain `.uk` — domains sanitized by the source |
| **SPF FAIL** | `Received-SPF: None ([removed].uk: [removed].eu does not designate permitted sender hosts)` — classic spoofing indicator |
| **First relay** | `mout.kundenserver.de (212.227.17.10)` — 1&1 IONOS (a legitimate German mail provider being abused for malspam) |
| **Originating host** | `109.42.114.126` via `mreue107 (212.227.15.179)` — deepest Received hop |
| **X-Mailer** | `MailBee.NET 12.0.0.615` — a bulk-mailing library commonly abused by spammers; legitimate office users rarely show this header |
| **Fake thread headers** | `In-Reply-To` and `References` point to `<1327559561.1571495916123.JavaMail.beadmin@wlogic10>` — fabricated to feign an ongoing conversation |
| **Message-ID host** | `WIN-56T8FAGBN10` — default Windows hostname pattern (indicates a compromised or throwaway Windows host as the sending machine) |
| **Attachment** | `I8m7XluZbbj10J53.xlsb`, MIME type `application/octet-stream`, 94.3 KB |
| **Chain of custody** | Attachment extracted via `emldump.py -s 3 -d ...` — hashes of the extracted attachment match the standalone .xlsb exactly (proves the .xlsb we analyzed is the same file delivered by the email) |

📸 **Screenshot #25** — `less` output showing full email headers (From/To/Subject/Date/Received chain/X-Mailer).
📸 **Screenshot #26** — `emldump.py` output showing MIME structure with the .xlsb at index 3.
📸 **Screenshot #27** — `emldump.py -s 3 | md5sum` and `| sha256sum` output confirming hash match with standalone .xlsb. *(Note: If the corrected version of this screenshot hasn't been taken yet, flag it to Moses.)*

### Conclusion statement to include
> "The phishing email exhibits multiple deception indicators consistent with a targeted malspam campaign: a forged reply thread, an SPF failure, a bulk-mailer X-Mailer header, and a default Windows hostname in the Message-ID. The embedded attachment's hash was verified to match the standalone `.xlsb` artifact, establishing the email as the confirmed delivery vector for the remainder of the infection chain."

---

## 4. Excel Dropper Analysis (`.xlsb`)

### Kill chain role
**Exploitation / Installation** — first-stage code execution via macros.

### Methodology (1 sentence)
The `.xlsb` was scanned with `olevba` and `oleid`, then its XLM macros were analyzed with `XLMMacroDeobfuscator`; finally, the OOXML ZIP container was unpacked with `unzip` to inspect its internal structure.

### Key findings (include all of these)

| Finding | Detail |
|---|---|
| **No VBA macros found** | `olevba` reported zero VBA/XLM macros on the .xlsb. This is an **evasion technique**: the malware uses Excel 4.0 (XLM) macros stored in `.xlsb` binary streams, which are invisible to VBA-focused scanners. |
| **XLM macro presence confirmed** | `XLMMacroDeobfuscator` identified an `auto_open` formula trigger at cell `$BA$13`. |
| **Deobfuscation failure (intentional)** | The deobfuscator's XLM parser failed with an `Unexpected token` error at column 368 on line 1. The malformed token `FDJDFJKERJKJKER` indicates the attacker deliberately constructed formulas that break automated deobfuscation. This is itself a high-confidence indicator of malicious intent. |
| **Random-character function names** | `DFJDFJDF`, `FDJDFJKERJKJKER` — non-meaningful identifiers designed to evade signature-based detection and string heuristics. |
| **Unencrypted container** | XLMMacroDeobfuscator reported "Unencrypted xlsb file" — no password protection. The malware relies entirely on obfuscation, not encryption, for evasion. |
| **XLM macrosheet directory** | `unzip` revealed the `xl/xld/` directory inside the container — the .xlsb equivalent of `xl/macrosheets/` in an .xlsm file. This is the definitive structural signature of XLM-macro-bearing XLSBs. |
| **Lure theme** | DocuSign-branded "PROTECT SERVICE" decoy (visible in the Excel rendering in the traffic-analysis source document) — social engineering pressure to enable content. |
| **No plaintext IOCs extractable** | Applying `strings | grep` for URLs, executables, and common command patterns against the unzipped XLM binaries returned zero results. **The URL and command payload is constructed at runtime from cell references and will only be observable during dynamic execution (Phase 4).** |

📸 **Screenshot #28** — `XLMMacroDeobfuscator` output showing the `auto_open` trigger at `$BA$13`, the malformed function names, and the parser failure.
📸 **Screenshot #29** — *(If taken — `oleid` output. Not critical; skip if not captured.)*
📸 **Screenshot #30** — `unzip` listing of the .xlsb container contents, showing the `xl/xld/` directory.

### Conclusion statement to include
> "The dropper is a defensively engineered Excel 4.0 macro carrier. It specifically evades VBA-focused scanners by using XLM macros in a .xlsb binary container, employs random-character function identifiers to defeat signatures, and constructs its formulas in a way that deliberately breaks automated deobfuscators. No plaintext payload indicators are extractable from static analysis alone; URL and command resolution is deferred to runtime, confirming the need for Phase 4 dynamic analysis."

---

## 5. DLL Payload Analysis (`block.dll`)

### Kill chain role
**Installation / C2 / Actions on Objectives** — core URSNIF payload.

### Methodology (1 sentence)
`block.dll` was analyzed on REMnux using `rabin2` (PE headers, sections, imports, exports, strings) and `capa` (capability detection and MITRE ATT&CK mapping).

### PE overview

| Field | Value |
|---|---|
| Format | PE32 DLL (GUI subsystem) |
| Architecture | x86 / i386 (32-bit) |
| File size | 312,832 bytes |
| Compile timestamp | `Thu Apr 8 00:05:51 2021` (~5 weeks before the campaign — purpose-built) |
| Compile checksum | `0x0004f9aa` |
| Signed | False |
| Stripped | False |
| Debug GUID | `C73B28130056411D84ED718996F219E04` |
| Embedded PDB path | `c:\Whether\class\156\Through\How.pdb` |
| Internal filename | `How.dll` |

### Sections

| # | Name | Raw size | Virtual size | Perms | Notes |
|---|---|---|---|---|---|
| 0 | `.text` | 0x49000 | 0x49000 | r-x | Standard code section |
| 1 | `.data` | **0x1000** | **0x108000** | rw- | **Virtual size ~264× raw size — classic runtime unpacking buffer** |
| 2 | `.rsrc` | 0x400 | 0x1000 | r-- | Resources |
| 3 | `.reloc` | 0x1e00 | 0x2000 | r-- | Relocations |

### Imports (name-based — the only APIs resolved statically)

Only **five** suspicious API imports were visible by name:

- `VirtualProtectEx` (KERNEL32)
- `VirtualAlloc` (KERNEL32)
- `GetProcAddress` (KERNEL32)
- `LoadLibraryA` (KERNEL32)
- `IsDebuggerPresent` (KERNEL32)

The presence of `GetProcAddress` + `LoadLibraryA` alongside a lack of other named API imports strongly suggests **dynamic API resolution at runtime** — URSNIF resolves the remainder of its Windows API surface via `GetProcAddress` with hashed or encrypted function names. This is confirmed by `capa` (see below).

### Exports

- `Pape1`
- `Riverslow`

Neither is a standard DLL export name (`DllMain`, `DllRegisterServer`, etc.). **The Phase 4 detonation command must invoke one of these specifically:**

```
rundll32.exe block.dll,Pape1
```

*(Try `Riverslow` as fallback if `Pape1` does not trigger expected behavior.)*

### Strings / IOC extraction result

Running `strings` + `grep` across the binary for URLs, registry paths, executable names, and common command patterns returned **zero plaintext hits**. This is consistent with URSNIF's known behavior of storing all configuration and C2 strings in an encrypted form that is only decrypted at runtime. **These IOCs will be recovered in Phase 4 (dynamic analysis and PCAP review).**

### `capa` results

**MITRE ATT&CK techniques identified:**

| Tactic | Technique |
|---|---|
| Discovery | System Location Discovery (T1614) |
| Execution | Shared Modules (T1129) |

**MBC behaviors:**

| Objective | Behavior |
|---|---|
| Memory | Allocate Memory (C0007) |
| Process | Terminate Process (C0018) |

**Capabilities:**

- Get geographical location (confirms geo-targeting / region-specific campaign logic)
- Contains PDB path
- Terminate process
- Link function at runtime on Windows (5 matches)
- Link many functions at runtime
- Execute shellcode via indirect call

The last three items — runtime linking plus indirect shellcode execution — are the static-analysis equivalent of a fingerprint for this malware family: URSNIF lifts its real capability set into memory only at runtime.

📸 **Screenshot #31** — `file block.dll` + `rabin2 -I block.dll` (PE metadata, compile timestamp, PDB path, debug GUID).
📸 **Screenshot #32** — Section table + suspicious imports list.
📸 **Screenshot #33** — Export table (`Pape1`, `Riverslow`, internal `How.dll` references).
📸 **Screenshot #34** — `capa` output (ATT&CK tactics, MBC behaviors, Capabilities table).

### Conclusion statement to include
> "Static analysis of block.dll surfaced a consistent picture of a packed, runtime-resolved banking trojan. The DLL imports only a handful of Windows APIs by name, relies on `GetProcAddress`/`LoadLibraryA` to construct the remainder of its capability surface at runtime, and stores a `.data` section whose virtual size is ~264× larger than its raw size — a classic signature of an in-memory unpacking buffer. All meaningful payload strings (URLs, registry paths, C2 configuration) are encrypted in the binary and were not recoverable without execution. The embedded PDB path `c:\\Whether\\class\\156\\Through\\How.pdb` and non-standard exports `Pape1` and `Riverslow` provide high-confidence static fingerprints that are incorporated into the custom YARA rule set."

---

## 6. YARA Rule Development

Custom YARA rules were authored based on the static indicators identified above and are stored in the repository at:

- `rules/yara/ursnif-dll.yar` — rules targeting `block.dll` (PDB path, export combination, debug GUID, section vsize heuristic)
- `rules/yara/ursnif-dropper.yar` — rules targeting the `.xlsb` dropper (raw ZIP container signatures + unzipped XLM content)

The rules were verified to match the sample artifacts on REMnux. (Moses, add your `yara` command screenshot here as **Screenshot #35** when you get a chance.)

---

## 7. Initial Behavioral Hypotheses (for the Wiki)

Based on Phase 2 static findings alone, before any code execution, the analysis team forms the following working hypotheses about URSNIF's behavior — to be validated or refined in Phases 3, 4, and 5:

1. **Macro-based initial execution.** The `.xlsb` will trigger on document open via its `auto_open` XLM formula at cell `$BA$13`, and will construct an outbound URL at runtime from obfuscated cell references.
2. **Secondary payload retrieval.** The macro is expected to retrieve and execute a JavaScript or similar intermediate stage (per the documented kill chain: `.xlsb → Fattura.js → lista.js → block.dll`).
3. **DLL loaded via rundll32.** `block.dll` will be invoked via `rundll32.exe` targeting export `Pape1` or `Riverslow`.
4. **Runtime unpacking.** On load, the DLL will allocate a large memory region (~1 MB) and unpack/decrypt its real payload into the `.data` section expansion or a freshly allocated buffer.
5. **Dynamic API resolution.** Only a minimal import surface is visible statically; the full Windows API surface (networking, process injection, crypto) is resolved via `GetProcAddress` at runtime.
6. **Anti-debug.** `IsDebuggerPresent` will be called early; additional anti-analysis checks are likely, given the sample's investment in anti-deobfuscation at the .xlsb layer.
7. **Geo-targeting.** `capa` identified System Location Discovery capability; the malware is expected to query the host's locale or geolocate itself and may tailor or abort behavior based on region.
8. **C2 communication.** Outbound HTTP(S) traffic to the URSNIF C2 infrastructure will be observable in Security Onion's Suricata/Zeek telemetry and in the provided PCAP.

---

## 8. Screenshot Mapping (Phase 2 Summary)

| # | Content | Wiki placement |
|---|---|---|
| 24 | `ls -la` + MD5/SHA256 of all 5 artifacts | Section 2 (Hash Inventory) |
| 25 | `.eml` headers (less output) | Section 3 (Email Analysis) |
| 26 | `emldump.py` MIME structure | Section 3 (Email Analysis) |
| 27 | `emldump.py -s 3` attachment hash (chain of custody) | Section 3 (Email Analysis) — flag to Moses if not yet re-taken |
| 28 | `XLMMacroDeobfuscator` output (auto_open + parser fail) | Section 4 (XLSB Analysis) |
| 29 | `oleid` + `file` output *(optional)* | Section 4 (XLSB Analysis) |
| 30 | `unzip` listing of xlsb container | Section 4 (XLSB Analysis) |
| 31 | `file` + `rabin2 -I` of block.dll | Section 5 (DLL Analysis) — PE Overview |
| 32 | `rabin2 -S` + suspicious imports | Section 5 (DLL Analysis) — Sections + Imports |
| 33 | Exports table | Section 5 (DLL Analysis) — Exports |
| 34 | `capa` output | Section 5 (DLL Analysis) — Capabilities |
| 35 | *(future)* YARA verification | Section 6 (YARA Rules) |

---

## Notes for Marissa

- Write in formal academic voice; first person plural ("we", "our analysis") is fine.
- Keep each subsection focused — the tables do the heavy lifting. Your prose should contextualize findings and call attention to what's significant.
- Screenshots are in `C:\Users\moses\UIW\malware_analysis\evidence\screenshots\`.
- If any finding here conflicts with what you see in a screenshot, flag it to Moses before writing — do not assume the brief is right if the evidence contradicts it.
- Full tool output for block.dll is archived at `~/ursnif-samples/static.txt` on REMnux if you need quote-level detail.
- For the "tools used" table and any reference to Security Onion, refer to the main README — do not duplicate information.
