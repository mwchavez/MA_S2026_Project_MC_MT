# Static Analysis Report — URSNIF (2021-05-14)

**Authors:** Moses Chavez, Marissa Turner
**Sample source:** `https://www.malware-traffic-analysis.net/2021/05/14/index.html`
**Analysis date:** April 2026
**Environment:** REMnux (Ubuntu 24.04 LTS), 4 GB RAM, on isolated analysis network.

---

## 1. Scope

This report documents Phase 2 of the URSNIF analysis pipeline: static analysis of all five artifacts in the sample set, performed without execution. The objectives were to:

- Establish cryptographic hash identity for every artifact
- Characterize the phishing email's delivery posture
- Inspect the `.xlsb` dropper's macro storage and obfuscation
- Catalog the `block.dll` payload's PE structure, imports, exports, and capabilities
- Form initial behavioral hypotheses to be validated in Phases 3 and 4

All static analysis was performed on REMnux without transferring `block.dll` to the detonation VM, minimizing the risk of accidental execution.

---

## 2. Artifact Inventory and Hashes

| Artifact | Size (bytes) | MD5 | SHA-256 |
|---|---|---|---|
| `2021-05-03-malspam-pushing-Ursnif.eml` | 134,798 | `3ecaacac670c10e573f81aef38ee1a05` | `5e2cbd4b03acc2d0fcb3764fda7f8b831fe9c0c441667a11ab1ee298869594e6` |
| `I8m7XluZbbj10J53.xlsb` | 96,582 | `eb6e605d7d61d17694a6bb3c72ef04c0` | `60f0eb98765e693f80626a8ce9a80937036b480dffc2a65eca55fbc7ccc94d18` |
| `block.dll` | 312,832 | `5a7c87dab250cee78ce63ac34117012b` | `8a26c32848c9ea085505359f67927d1a744ec07303ed0013e592eca6b4df4790` |
| `2021-05-14-Ursnif-infection-traffic.pcap` | 821,237 | `811fb8b5efca216dfb4d7a0ef4055a2b` | `d8121c60f63cbbab4f04b466395ced4548591fc1b29de74637eeb5dae585fd7e` |
| `2021-05-14-IOCs-for-Ursnif-infection.txt` | 3,786 | `2cff80b92e5874026a2f88986f7b4041` | `c1c831e995a63ea22719f61382db7dd114723982df76ac99a1526186b5cc0b72` |

---

## 3. Phishing Email (Delivery)

The email was inspected with `less` (raw), parsed with `emldump.py` (MIME structure), and the embedded attachment was extracted and hashed for chain-of-custody verification.

### 3.1 Header findings

| Field | Value | Significance |
|---|---|---|
| Subject | `Re: Your [info removed] Application` | Forged "Re:" prefix simulating an ongoing thread |
| Date | `Mon, 03 May 2021 17:40:08 +0300` | Eastern European / Russia-adjacent timezone |
| From / To domain mismatch | `.eu` → `.uk` | Cross-domain spoofing |
| `Received-SPF` | `None — does not designate permitted sender hosts` | SPF FAIL — classic spoofing indicator |
| First relay | `mout.kundenserver.de (212.227.17.10)` | 1&1 IONOS — legitimate provider abused for malspam |
| Originating IP | `109.42.114.126` | Deepest hop in the Received chain |
| `X-Mailer` | `MailBee.NET 12.0.0.615` | Bulk-mailing library; rare in legitimate office traffic |
| `In-Reply-To`, `References` | `<1327559561.1571495916123.JavaMail.beadmin@wlogic10>` | Fabricated to fake conversation continuity |
| `Message-ID` host | `WIN-56T8FAGBN10` | Default Windows hostname pattern — likely throwaway/compromised host |
| Attachment | `I8m7XluZbbj10J53.xlsb` (94.3 KB, `application/octet-stream`) | First-stage dropper |

### 3.2 Chain of custody

The attachment extracted via `emldump.py -s 3 -d ...` produced hashes matching the standalone `.xlsb` artifact exactly (MD5 `eb6e605d7d61d17694a6bb3c72ef04c0`, SHA-256 `60f0eb98765e693f80626a8ce9a80937036b480dffc2a65eca55fbc7ccc94d18`), establishing the email as the confirmed delivery vector for the dropper analyzed below.

### 3.3 Conclusion

The phishing email exhibits multiple deception indicators consistent with a targeted malspam campaign. The combination of a forged reply thread, SPF FAIL, a bulk-mailer X-Mailer header, and a default Windows hostname in the Message-ID would be detectable by a properly configured email gateway with SPF/DKIM/DMARC enforcement.

---

## 4. XLSB Dropper

The `.xlsb` was scanned with `olevba` and `oleid`, then inspected with `XLMMacroDeobfuscator` and unpacked with `unzip` for structural analysis.

### 4.1 Macro storage — XLM, not VBA

`olevba` reported **no VBA macros**. This is itself a finding: URSNIF's dropper uses Excel 4.0 (XLM) macros stored in the `.xlsb` binary streams, which are invisible to VBA-focused scanners. This is a deliberate evasion technique that defeats `olevba`-class detection out of the box.

### 4.2 XLM auto-execution trigger

`XLMMacroDeobfuscator` identified an `auto_open` formula at cell `$BA$13`. When the user enables content, this formula fires and triggers the malicious chain.

### 4.3 Anti-deobfuscation design

The deobfuscator's XLM parser failed with `Unexpected token Token('NAME', 'FDJDFJKERJKJKER') at line 1, column 368`. The malware uses random-character function identifiers (`DFJDFJDF`, `FDJDFJKERJKJKER`) and constructs formulas that deliberately break automated deobfuscation. This is a positive indicator of malicious intent — legitimate documents have no reason to defeat automated parsing.

### 4.4 Container structure

Unzipping the `.xlsb` revealed a `xl/xld/` directory — the `.xlsb` equivalent of `xl/macrosheets/` in `.xlsm` files. Presence of `xl/xld/` in a `.xlsb` is a definitive structural signature of XLM-macro-bearing XLSBs.

### 4.5 Lure

The workbook displays a DocuSign-themed "PROTECT SERVICE" page instructing the user to "Enable Editing" and "Enable Content" because "this document is encrypted." This is social engineering pressure to enable macros under false pretenses.

### 4.6 No plaintext IOCs

`strings | grep` for URLs, executables, and command patterns against the unzipped XLM binaries returned nothing. The dropper constructs its payload URL at runtime from cell references — static analysis alone cannot extract the URL, which will only be observable during dynamic execution.

---

## 5. block.dll Payload

`block.dll` was analyzed with `rabin2` (PE structure) and `capa` (capability detection mapped to MITRE ATT&CK).

### 5.1 PE overview

| Field | Value |
|---|---|
| Format | PE32 DLL (GUI subsystem) |
| Architecture | x86 / i386 (32-bit) |
| File size | 312,832 bytes |
| Compile timestamp | `Thu Apr 8 00:05:51 2021` (~5 weeks before campaign) |
| Compile checksum | `0x0004f9aa` |
| Signed | False |
| Stripped | False |
| Debug GUID | `C73B28130056411D84ED718996F219E04` |
| Embedded PDB path | `c:\Whether\class\156\Through\How.pdb` |
| Internal filename | `How.dll` |

### 5.2 Sections

| # | Name | Raw size | Virtual size | Perms | Notes |
|---|---|---|---|---|---|
| 0 | `.text` | 0x49000 | 0x49000 | r-x | Standard code section |
| 1 | `.data` | **0x1000** | **0x108000** | rw- | **Virtual size ~264× raw size — runtime unpacking buffer** |
| 2 | `.rsrc` | 0x400 | 0x1000 | r-- | Resources |
| 3 | `.reloc` | 0x1e00 | 0x2000 | r-- | Relocations |

The `.data` section's virtual-size anomaly is the static-analysis fingerprint of a runtime-allocated buffer for unpacked or decrypted content.

### 5.3 Imports

Only **five** Windows APIs are visible by name:

- `VirtualProtectEx` (KERNEL32)
- `VirtualAlloc` (KERNEL32)
- `GetProcAddress` (KERNEL32)
- `LoadLibraryA` (KERNEL32)
- `IsDebuggerPresent` (KERNEL32)

The presence of `GetProcAddress` and `LoadLibraryA` against this minimal name-based surface strongly suggests **dynamic API resolution at runtime** — URSNIF resolves the rest of its API surface via `GetProcAddress` with hashed or computed function names.

### 5.4 Exports

- `Pape1`
- `Riverslow`

Neither is a standard DLL export name (`DllMain`, `DllRegisterServer`, `DllInstall`, etc.). The Phase 4 detonation command must invoke one of these specifically:

```
rundll32.exe block.dll,Pape1
```

### 5.5 String analysis

`rabin2 -zz` followed by grep for URLs, registry keys, executable names, and common command patterns returned **zero** plaintext matches. The binary stores its configuration encrypted; static analysis alone cannot recover the C2 domains, registry keys, or User-Agent strings used at runtime.

### 5.6 Capability analysis (capa)

| Tactic | Technique |
|---|---|
| Discovery | System Location Discovery (T1614) |
| Execution | Shared Modules (T1129) |

| Capability | Significance |
|---|---|
| Get geographical location | Confirms geo-targeting / region-specific campaign logic |
| Contains PDB path | Static fingerprint |
| Terminate process | Process control |
| Link function at runtime on Windows (5 matches) | Runtime API resolution |
| Link many functions at runtime | Runtime API resolution at scale |
| Execute shellcode via indirect call | Indirect-call execution model |

These capabilities are the static-analysis equivalent of a fingerprint for this malware family — URSNIF defers the bulk of its functionality to runtime.

---

## 6. Initial Behavioral Hypotheses

The following hypotheses are formed from static evidence alone and will be validated or refined in Phases 3 and 4:

1. **Macro-based initial execution.** The `.xlsb` triggers on document open via its `auto_open` XLM formula at `$BA$13` and constructs an outbound URL at runtime from obfuscated cell references.
2. **Secondary payload retrieval.** The macro retrieves and executes a JavaScript or similar intermediate stage (per the documented kill chain: `.xlsb → Fattura.js → lista.js → block.dll`).
3. **DLL loaded via rundll32.** `block.dll` is invoked via `rundll32.exe` targeting export `Pape1` or `Riverslow`.
4. **Runtime unpacking.** On load, the DLL allocates a large memory region (~1 MB) and unpacks/decrypts its real payload.
5. **Dynamic API resolution.** Only a minimal import surface is visible statically; the full Windows API surface (networking, process injection, crypto) is resolved via `GetProcAddress` at runtime.
6. **Anti-debug.** `IsDebuggerPresent` is called early; additional anti-analysis checks are likely.
7. **Geo-targeting.** capa identified System Location Discovery; the malware queries the host's locale and may tailor or abort behavior based on region.
8. **C2 communication.** Outbound HTTP(S) traffic to URSNIF C2 infrastructure will be observable in Security Onion telemetry and in the provided PCAP.

---

## 7. YARA Rules Authored

Four YARA rules were authored from Phase 2 indicators, stored at `rules/yara/`:

| Rule | File | Purpose |
|---|---|---|
| `URSNIF_block_dll_2021_05_14` | `ursnif-dll.yar` | Detect `block.dll` via PDB path, distinctive export combination, debug GUID |
| `URSNIF_heuristic_section_unpacking` | `ursnif-dll.yar` | Generic — any PE with section vsize 16× or more larger than raw size |
| `URSNIF_xlsb_dropper_2021_05_14` | `ursnif-dropper.yar` | Detect raw `.xlsb` via ZIP central directory filename entries (`xl/xld/`) |
| `URSNIF_xlsb_unzipped_xlm_content` | `ursnif-dropper.yar` | Detect unzipped `.xlsb` content via obfuscated XLM identifiers + DocuSign lure strings |

All four rules verified to match the sample artifacts on REMnux. The `URSNIF_xlsb_dropper_2021_05_14` rule was revised after initial verification because its first draft relied on a string located inside a compressed ZIP stream (invisible to YARA on the raw file). The revision narrative is documented in the rule file's revision history.
