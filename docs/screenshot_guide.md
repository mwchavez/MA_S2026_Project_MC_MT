# Screenshot Guide for Wiki Documentation

**For:** Marissa Turner
**Created by:** Moses Chavez (via Claude project assistant)
**Last updated:** April 28, 2026 — Phases 2 through 5 added; final.
**Purpose:** Maps each numbered screenshot to its Wiki section with a brief description. Use this to place images in the correct phase sections.

---

## Phase 1: Environment Setup

### Host System & VirtualBox

| # | Description | Wiki Placement |
|---|---|---|
| 1 | Task Manager → Performance → CPU showing "Virtualization: Enabled" on the host machine. | Environment Setup — Host system readiness proof. |
| 2 | VirtualBox Extension Pack Manager showing the extension pack installed with matching version number. | Environment Setup — Hypervisor configuration. |
| 3 | VirtualBox "About" dialog showing the installed version string. | Environment Setup — Hypervisor configuration. |
| 4 | PowerShell `Get-FileHash` output showing SHA256 of the Security Onion ISO matching the vendor-published hash. | Environment Setup — Demonstrates ISO integrity verification before building the lab. |

### Network Architecture

| # | Description | Wiki Placement |
|---|---|---|
| 5 | VirtualBox Network Manager showing the host-only adapter configured at 192.168.56.1 with DHCP disabled. | Environment Setup — Management network configuration. |

### Security Onion VM

| # | Description | Wiki Placement |
|---|---|---|
| 6 | Security Onion VM Settings → Network → Adapter 1: Host-Only Adapter (management interface). | Environment Setup — Security Onion VM network configuration. |
| 7 | Security Onion VM Settings → Network → Adapter 2: Internal Network "AnalysisNet" with Promiscuous Mode "Allow All" (monitor interface). | Environment Setup — Security Onion VM network configuration. Critical — proves sensor interface is correctly configured for traffic capture. |
| 8 | Security Onion VM Settings → Network → Adapters 3 and 4 both disabled. | Environment Setup — Proves no extra network paths exist on the sensor VM. |
| 9 | Security Onion ISO boot menu with "Install Security Onion 3.0.0" highlighted. | Environment Setup — Documents which install path was selected. |

### REMnux VM

| # | Description | Wiki Placement |
|---|---|---|
| 10 | VirtualBox Import Appliance screen showing REMnux OVA settings (CPU, RAM, folder, MAC policy). | Environment Setup — REMnux VM creation. |
| 11 | REMnux VM Settings → Network → Adapter 1: Host-Only Adapter (management interface). | Environment Setup — REMnux network configuration. |
| 12 | REMnux VM Settings → Network → Adapter 2: Internal Network "AnalysisNet" with Promiscuous Mode "Allow All". | Environment Setup — REMnux network configuration. |
| 13 | REMnux VM Settings → Network → Adapter 3 disabled. | Environment Setup — Proves no extra network paths on the analysis workstation. |
| 14 | REMnux VM Settings → General → Advanced showing Shared Clipboard "Disabled" and Drag-and-Drop "Disabled". | Environment Setup — Safety controls on the analysis workstation. |

### Windows Detonation VM (FlareVM)

| # | Description | Wiki Placement |
|---|---|---|
| 15 | FlareVM Settings → Network → Adapter 1: Internal Network "AnalysisNet", Promiscuous Mode "Deny". **This is the single most important safety screenshot** — proves the detonation VM's only network path is the isolated analysis segment. | Environment Setup — Detonation VM network configuration. Highlight in safety controls section. |
| 16 | FlareVM Settings → Network → Adapter 2 disabled. | Environment Setup — Detonation VM isolation proof. |
| 17 | FlareVM Settings → Network → Adapter 3 disabled. | Environment Setup — Detonation VM isolation proof. |
| 18 | FlareVM Settings → Network → Adapter 4 disabled. | Environment Setup — Detonation VM isolation proof. |
| 19 | FlareVM Settings → General → Advanced showing Shared Clipboard "Disabled" and Drag-and-Drop "Disabled". | Environment Setup — Safety controls on detonation VM. |
| 20 | FlareVM Settings → USB showing "Enable USB Controller" unchecked. | Environment Setup — Safety controls on detonation VM. |
| 21 | FlareVM Settings → Shared Folders showing empty list (no shared folders). | Environment Setup — Safety controls on detonation VM. |
| 22 | FlareVM Settings → Storage showing `ursnif-tools.iso` mounted as the optical drive. | Environment Setup — Documents the read-only ISO transfer method used for tool installation. |
| 23 | FlareVM File Explorer showing `C:\Tools\` directory with all extracted/installed tool folders. | Environment Setup — Proves all analysis tools are installed and organized. |

### Static Analysis Artifacts

| # | Description | Wiki Placement |
|---|---|---|
| 24 | REMnux terminal showing `ls -la` output of all 5 extracted URSNIF artifacts after transfer via ISO and extraction with password. | Static Analysis — Artifact inventory and chain of custody documentation. |
| 25 | REMnux terminal showing MD5 and SHA256 hash outputs for all 5 URSNIF artifacts. | Static Analysis — File hash table (Issue 2.2). Core deliverable for Phase 2. |

---

## Unnumbered Screenshots (Supporting Evidence)

These were taken throughout the project for additional documentation. They're organized by phase and topic. Use them as supporting visuals where appropriate — they're not mapped to specific Wiki locations but add value.

### Environment Setup — Supporting

- **Security Onion install summary screen** — Shows all configuration choices (EVAL, airgap, static IP, hostname, etc.) in one place. Excellent for the SO configuration subsection.
- **Security Onion `so-status` output** — All containers running with "This onion is ready to make your adversaries cry!" message. Proves SO is fully operational.
- **Security Onion `ip a show enp0s3` and `ip a show enp0s8`** — Shows management IP (192.168.56.10/24) and monitor interface (PROMISC flag, no IP). Proves correct sensor architecture.
- **REMnux `ip a` output** — Shows both interfaces with correct static IPs (192.168.56.20 and 10.0.0.1).
- **REMnux INetSim startup output** — Shows all services starting on 10.0.0.1 (dns, http, https, smtp, etc.). Proves simulated internet is functional.
- **REMnux shared folders empty** — Settings showing no shared folder paths to host.
- **REMnux USB controller disabled** — Settings showing USB controller unchecked.
- **Host → REMnux ping** (from REMnux terminal) — 3/3 packets, 0% loss to 192.168.56.1. Management network bidirectional proof.
- **Host → REMnux ping** (from host PowerShell) — 4/4 packets, 0% loss to 192.168.56.20. Management network bidirectional proof.
- **FlareVM `ipconfig /all` output** — Shows static IP 10.0.0.100, gateway 10.0.0.1, DNS 10.0.0.1. Proves correct AnalysisNet configuration.
- **FlareVM IPv4 Properties dialog** — Shows the static IP configuration in Windows network settings.
- **FlareVM → REMnux ping** — 4/4 packets to 10.0.0.1. Proves analysis network end-to-end connectivity.
- **FlareVM isolation tests** — Four failed pings/lookups proving no internet, no home LAN, no host access, no DNS leakage. **This is one of the most important supporting screenshots for the safety controls section.**
- **Windows OOBE "No Internet" screen** — Shows Windows 10 setup confirming no network available on the detonation VM. Visual proof of isolation during OS installation.
- **Host `ipconfig` output** — Shows host network topology (Wi-Fi at 192.168.1.71, host-only at 192.168.56.1). Useful for network topology documentation.

### Tool Verification — Supporting

- **Sysinternals hash verification** — PowerShell `Get-FileHash` output.
- **7-Zip VirusTotal result** — 1/72 (Bkav AI heuristic false positive). Shows due diligence.
- **Notepad++ Authenticode signature** — Valid, signed by Don Ho / GlobalSign. Shows proper tool verification.
- **PE-bear VirusTotal result** — 0/67 clean.
- **DIE VirusTotal result + community tab** — 1/66 with VMProtect discussion. Documents the deliberate decision to include despite packing.
- **JDK Temurin hash + Authenticode** — Hash match + Valid signature from Eclipse Foundation. Gold-standard verification.
- **Ghidra hash match** — NSA-published SHA256 matches downloaded file exactly.
- **Wireshark hash + Authenticode + PGP-signed hash file** — Triple verification. Best example of thorough tool verification.
- **AnyBurn MD5 match + Authenticode** — Verification of the host-only ISO building tool.
- **AnyBurn ISO contents list** — Shows all 9 tools in the ISO before building. Documents ISO contents.
- **Mounted ISO on host (File Explorer)** — Shows the built ISO contents as a sanity check before transfer to FlareVM.

### Troubleshooting — Optional Documentation

- **VirtualBox driver cert mismatch error** — Documents the initial install failure and resolution.
- **Security Onion 16 GB RAM error** — Documents why STANDALONE was rejected in favor of EVAL.
- **Security Onion elasticfleet error** — Documents the install warning and subsequent healthy recovery.
- **Security Onion `so-setup` wrong command attempts** — Documents troubleshooting the setup re-run.

---

## Notes for Marissa

1. **Screenshots are stored in:** `C:\Users\moses\UIW\malware_analysis\evidence\screenshots\` — some are numbered (Screenshot_1.png through Screenshot_25.png), others are named descriptively (e.g., `securityonion_functional.png`, `inetsim_running.png`).

2. **Screenshots 15-21 (FlareVM isolation)** should be grouped together in a "Safety Controls" subsection. They collectively prove the detonation VM is fully locked down.

3. **The isolation test screenshot** (FlareVM failing to ping internet/host/home LAN) is arguably the single most important image in the entire Phase 1 section. Give it prominent placement.

4. **Phase 2 through 5 screenshots are now included below.** This guide is final as of April 28, 2026.

---

## Phase 2: Static Analysis

### Hashing & Email Analysis

| # | Description | Wiki Placement |
|---|---|---|
| 24 | REMnux terminal showing combined `ls -la` listing of all 5 URSNIF artifacts followed by `md5sum *` and `sha256sum *` outputs. | Static Analysis — Artifact inventory + hash table (Issue 2.2). Place beside the hash table in Section 2 of the Phase 2 brief. |
| 25 | REMnux `less` view of `2021-05-03-malspam-pushing-Ursnif.eml` showing full headers — From, To, Subject, Date, full Received chain, X-Mailer (MailBee.NET), SPF FAIL line. | Static Analysis — Email Analysis (Section 3). Primary evidence for Delivery-phase findings. |
| 26 | REMnux `emldump.py` output showing MIME structure with the `.xlsb` attachment at index 3. | Static Analysis — Email Analysis (Section 3). MIME structure reference. |
| 27 | REMnux `emldump.py -s 3 -d ... \| md5sum` and `\| sha256sum` outputs confirming the embedded attachment hash matches the standalone `.xlsb`. | Static Analysis — Email Analysis (Section 3). Chain-of-custody proof linking the email to the standalone .xlsb artifact. |

### XLSB Dropper Analysis

| # | Description | Wiki Placement |
|---|---|---|
| 28 | REMnux `XLMMacroDeobfuscator` output showing the `auto_open` trigger at cell `$BA$13`, the malformed function names (`DFJDFJDF`, `FDJDFJKERJKJKER`), and the parser failure on the malformed token. | Static Analysis — XLSB Dropper Analysis (Section 4). Primary evidence of XLM macro presence + anti-deobfuscation design. |
| 30 | REMnux terminal showing `unzip` of the `.xlsb` container with the resulting `xl/xld/` directory listing — definitive structural signature of XLM macros. | Static Analysis — XLSB Dropper Analysis (Section 4). Container structure evidence. |

*(Screenshot #29 was reserved for an `oleid` output and was ultimately not captured. Optional supporting screenshot only — skip.)*

### block.dll Static Analysis

| # | Description | Wiki Placement |
|---|---|---|
| 31 | REMnux terminal showing `file block.dll` + `rabin2 -I block.dll` output (PE32, x86 i386, compile timestamp `Thu Apr 8 00:05:51 2021`, PDB path `c:\Whether\class\156\Through\How.pdb`, debug GUID `C73B28130056411D84ED718996F219E04`). | Static Analysis — DLL Payload Analysis (Section 5). PE Overview table reference. |
| 32 | REMnux terminal showing `rabin2 -S` (sections table — note `.data` raw 0x1000 vs vsize 0x108000) + the suspicious imports list (`VirtualProtectEx`, `IsDebuggerPresent`, `VirtualAlloc`, `GetProcAddress`, `LoadLibraryA`). | Static Analysis — DLL Payload Analysis (Section 5). Sections + Imports evidence. |
| 33 | REMnux terminal showing the export table (`Pape1`, `Riverslow`, internal name `How.dll`). | Static Analysis — DLL Payload Analysis (Section 5). Exports evidence. Critical for Phase 3+4 detonation method. |
| 34 | REMnux terminal showing `capa block.dll` output (ATT&CK tactics: System Location Discovery T1614, Shared Modules T1129; MBC behaviors; Capabilities including "link many functions at runtime", "execute shellcode via indirect call"). | Static Analysis — DLL Payload Analysis (Section 5). Capability mapping evidence. |
| 35 | REMnux terminal showing successful `yara` matches against block.dll (`URSNIF_block_dll_2021_05_14`, `URSNIF_heuristic_section_unpacking`) and against the unzipped XLSB content (`URSNIF_xlsb_unzipped_xlm_content`). Captured during the Phase 2 YARA verification pass. | Static Analysis — YARA Rule Development (Section 6). Verification evidence. |

---

## Phase 3: Assembly-Level Code Analysis

### Ghidra Setup & Initial Orientation

| # | Description | Wiki Placement |
|---|---|---|
| 36 | FlareVM File Explorer showing `C:\malware\` with `block.dll` (312,832 bytes) and `I8m7XluZbbj10J53.xlsb` (96,582 bytes) — chain of custody confirmation. | Assembly-Level Analysis — Tooling and Setup (Section 3). |
| 37 | Ghidra Project Manager showing the empty `URSNIF-block-dll` project. | Assembly-Level Analysis — Tooling and Setup (Section 3). |
| 38 | Ghidra Import Results Summary — with the Windows Defender Firewall popup (Java network access) visible and being denied. Bonus safety-controls evidence. | Assembly-Level Analysis — Tooling and Setup (Section 3). Note in caption: firewall access was denied to maintain FlareVM's no-network posture. |
| 39 | Ghidra CodeBrowser after auto-analysis completes, showing the `entry` function decompiled and the Symbol Tree on the left. | Assembly-Level Analysis — Tooling and Setup (Section 3). Proves auto-analysis ran successfully. |

### Cross-Reference Analysis

| # | Description | Wiki Placement |
|---|---|---|
| 40 | Ghidra References window for `GetProcAddress` showing 16 locations (1 import pointer + 15 COMPUTED_CALL sites). | Assembly-Level Analysis — Initial Orientation (Section 4). Critical evidence for dynamic API resolution thesis. |
| 41 | Ghidra References window for `LoadLibraryA` showing 3 locations. | Assembly-Level Analysis — Initial Orientation (Section 4). |
| 42 | Ghidra References window for `VirtualAlloc` showing 3 locations. | Assembly-Level Analysis — Initial Orientation (Section 4). |

### Library Code vs URSNIF Code Triage

| # | Description | Wiki Placement |
|---|---|---|
| 43 | Ghidra Symbol Tree filtered to `FUN_*` entries, showing the substantial volume of unidentified functions in the binary. | Assembly-Level Analysis — Section 5 (Library Code vs URSNIF Code methodology). Demonstrates volume of custom (non-library) code. |
| 44 | Ghidra Defined Strings window showing day-of-week strings (Thursday, Tuesday, Wednesday), country names (united-states, united-kingdom, trinidad & tobago), and the fake "© Equalher Corporation" copyright string. | Assembly-Level Analysis — Section 4 (Initial Orientation) OR Section 8 (Findings Summary). Confirms capa's geographical-location capability finding from Phase 2. |

### Deep-Dive Function: FUN_0103320c

| # | Description | Wiki Placement |
|---|---|---|
| 46 | Ghidra Listing pane showing the `FUN_0103320c` function header with the `XREF[1]: Pape1:0103348d(c)` annotation visible — proves the function is called directly from the Pape1 export. | Assembly-Level Analysis — Section 6 (Deep-Dive Function). XREF evidence linking the function to URSNIF's runtime entry. |
| 47 | Ghidra Decompile pane showing the full C reconstruction of `FUN_0103320c` (the obfuscated arithmetic state-mutation function with operations against `DAT_0104a008`, `DAT_0104a0d8`, `DAT_0104a0dc`, `DAT_0104a010`, `DAT_0104a00c`). | Assembly-Level Analysis — Section 6 (Deep-Dive Function). Primary deliverable evidence — the decompiled function body. |
| 48 | Ghidra Listing pane showing the `FUN_0103320c` assembly listing, top portion (function header through middle of the function body). | Assembly-Level Analysis — Section 6 (Deep-Dive Function). Disassembly excerpt requirement. |
| 49 | Ghidra Listing pane showing the `FUN_0103320c` assembly listing, bottom portion (continuation through the `RET` instruction). | Assembly-Level Analysis — Section 6 (Deep-Dive Function). Disassembly excerpt continuation. |

### Packing & Obfuscation

| # | Description | Wiki Placement |
|---|---|---|
| 51 | Detect It Easy (DIE) main window showing block.dll analysis: PE32, 32-bit DLL, Microsoft Linker 9.00.21022, Microsoft Visual C/C++ 15.00.21022 (Visual Studio 2008), C++, PDB file link present, "not packed" verdict. | Assembly-Level Analysis — Section 7 (Packing/Obfuscation). Compiler fingerprint + packer verdict. |
| 52 | DIE Entropy view showing the per-section entropy diagram — total file entropy 6.13343, `.text` 6.19237, smooth distribution across the binary. | Assembly-Level Analysis — Section 7 (Packing/Obfuscation). Entropy distribution evidence supporting "not packed but heavily obfuscated" interpretation. |

*(Screenshot #50 was reserved for the Ghidra Memory Map view and ultimately not captured because the section data was already documented from Phase 2's `rabin2 -S` output and corroborated by DIE in Phase 3. Skip.)*

### Phase 3 — Note on deleted screenshots

During Phase 3, screenshots 43–48 were initially captured during the CRT-triage process (showing MSVC library functions like `__sbh_alloc_new_region`, `_initptd`, `__crtMessageBoxA`, `rand_s`). These were deleted after we identified them as Microsoft library code rather than URSNIF code, and the numbering was renumbered. The final screenshots above (#43, #44, #46, #47, #48, #49, #51, #52) reflect this clean numbering.

---

## Phase 4: Dynamic and Memory Analysis

### Pre-Detonation Preparation

| # | Description | Wiki Placement |
|---|---|---|
| 57 | FlareVM desktop showing all three monitoring tools open and configured but not yet capturing — Process Monitor, Process Explorer, and Wireshark. | Dynamic and Memory Analysis — Section 2 (Pre-Detonation Preparation). Tool staging evidence. |
| 58 | Process Monitor Filter dialog showing the `Process Name is rundll32.exe → Include` filter applied. | Dynamic and Memory Analysis — Section 2 (Pre-Detonation Preparation). Filter setup evidence. |

### Live Detonation Captures

| # | Description | Wiki Placement |
|---|---|---|
| 62 | Process Explorer during detonation showing the parent-child rundll32 lineage — `cmd.exe (5292) → rundll32.exe (964) → rundll32.exe (3788)`. | Dynamic and Memory Analysis — Section 4.1 (Process Behavior — Self-Spawn and Exit). |
| 63 | Process Monitor after capture stop — event count visible at bottom (3,307 filtered events out of 802,164 total). | Dynamic and Memory Analysis — Section 3 (Detonation Execution). Capture statistics. |
| 64 | Wireshark after capture stop — packet count visible at bottom (178 packets). | Dynamic and Memory Analysis — Section 3 (Detonation Execution). Capture statistics. |

### Network Behavior

| # | Description | Wiki Placement |
|---|---|---|
| 65 | Wireshark with `dns` display filter applied, first DNS query (`api.msn.com`) highlighted with full DNS query details visible in the bottom pane. | Dynamic and Memory Analysis — Section 4.4 (Network Behavior — DNS Probing). |
| 65b | Wireshark with `dns` filter, the `app.buboleinov.com` C2 query highlighted. The crucial "real C2 IOC" finding from live detonation. | Dynamic and Memory Analysis — Section 4.4 (Network Behavior — DNS Probing). |
| 67 | Wireshark Statistics → Protocol Hierarchy window showing the breakdown: DNS 37.1%, ICMP 26.4%, NetBIOS 5.1%, SSDP 2.2%, no HTTP, no TLS. | Dynamic and Memory Analysis — Section 4.5 (Network Behavior — Protocol Distribution). |

### "Negative" File/Registry Findings

| # | Description | Wiki Placement |
|---|---|---|
| 68 | ProcMon with the additional `WriteFile` filter applied — empty results pane. Proves URSNIF wrote zero files during 5 minutes of execution. | Dynamic and Memory Analysis — Section 4.3 (File System and Registry — A Significant Negative Finding). Critical evidence for memory-resident execution model. |
| 69 | ProcMon with the additional `RegSetValue` filter applied — empty results pane. Proves URSNIF made zero registry persistence entries. | Dynamic and Memory Analysis — Section 4.3 (File System and Registry — A Significant Negative Finding). Critical evidence for memory-resident execution model. |
| 70 | Process Monitor Process Tree (Tools → Process Tree, Ctrl+T) centered on the rundll32 lineage, showing both PIDs (964, 3788) and their lifetimes. | Dynamic and Memory Analysis — Section 4.1 (Process Behavior — Self-Spawn and Exit). |

### Memory Dump

| # | Description | Wiki Placement |
|---|---|---|
| 71 | Host PowerShell showing `VBoxManage debugvm dumpvmcore` command + `dir` verification of the resulting `flarevm-postdetonation.elf` file at 8,730,336,884 bytes (8.73 GB). | Dynamic and Memory Analysis — Section 5 (Memory Analysis Approach). Documents the memory dump capture and preservation. |

### PCAP Analysis

| # | Description | Wiki Placement |
|---|---|---|
| 72 | REMnux terminal showing successful `scp` transfer of the PCAP to Security Onion (192.168.56.10) over the management network. | Dynamic and Memory Analysis — Section 6.1 (Security Onion ingestion). |
| 73 | Security Onion console showing `sudo so-import-pcap` completion with the PCAP date range (2021-05-14 through 2021-05-15) and the assigned import identifier `811fb8b5efca216dfb4d7a0ef4055a2b`. | Dynamic and Memory Analysis — Section 6.1 (Security Onion ingestion). |
| 74 | REMnux terminal showing `tshark` DNS query output from the provided PCAP — surfaces all unique queried domains: `app.buboleinov.com`, `docs.atu.ngr.mybluehost.me`, `todo.faroin.at`, `myip.opendns.com`, `resolver1.opendns.com`, `222.222.67.208.in-addr.arpa`. | Dynamic and Memory Analysis — Section 6.2/6.3 (PCAP analysis with tshark / IOCs recovered). The C2 domain inventory. |
| 75 | REMnux terminal showing `tshark` HTTP request output — destination IPs (`162.241.24.47`, `34.95.142.247`), Host headers (`docs.atu.ngr.mybluehost.me`, `app.buboleinov.com`, `todo.faroin.at`), URI patterns (`/presentation.dll`, `/favicon.ico`, long base64-style paths), User-Agent strings (IE 11 spoof, Firefox 86 spoof). | Dynamic and Memory Analysis — Section 6.2/6.3. The HTTP IOC inventory — this is the source for Phase 5's Suricata rule authoring. |
| 76 | REMnux terminal showing `tshark` unique destination IP list — `10.5.14.1`, `10.5.14.101`, `162.241.24.47`, `208.67.222.222`, `34.95.142.247`. | Dynamic and Memory Analysis — Section 6.2/6.3. Destination IP inventory. |

### Phase 4 — Note on de-scoped screenshots

Screenshots 53–56 were initially planned to document INetSim startup, `so-status` output, the SOC empty alerts baseline, and FlareVM `ping`/`nslookup` connectivity tests. These were de-scoped during execution after the INetSim DNS service-bind limitation was discovered. **Screenshot 56** (FlareVM DNS test) is the only one of these worth retaining — it supports the Lab Limitation 1 disclosure in Section 8 of the Phase 4 brief.

Screenshots 59–61 (Wireshark interface verification, ProcExp pre-detonation, `dir C:\malware`) were planned setup-verification shots. They were not formally captured as numbered screenshots but the same content is implicitly documented by #57 (tools open) and #62/#63/#64 (active capture). Skip.

Screenshot 66 (`http` filter showing zero HTTP packets in live detonation) was not captured because the empty result is documented in #67 (Protocol Hierarchy showing 0% HTTP). Skip.

---

## Phase 5: Behavior and Defensive Interpretation

Phase 5 is a synthesis phase. It produces no new live screenshots — all evidence is referenced from Phases 1–4 above. The Phase 5 deliverables are:

- **Custom Suricata rules** at `rules/suricata/custom.rules` — referenced in the Wiki by file path, no screenshot needed unless you want to include a `cat` view of the rule file.
- **Comprehensive IOC inventory** at `reports/ursnif-2021-05-14/iocs.json` — referenced in the Wiki by file path.
- **Kill-chain diagram** — included as ASCII art in the Phase 5 brief Section 8. Marissa: build a proper visual using draw.io if time allows; otherwise the ASCII version is acceptable in a Wiki monospace block. If you build a visual, save the export as `evidence/screenshots/kill-chain-diagram.png` and number it **77** in this guide.

### Optional Phase 5 screenshot

| # | Description | Wiki Placement |
|---|---|---|
| 77 *(optional)* | Kill-chain diagram visual export (PNG or SVG) — built in draw.io, Lucidchart, or similar from the ASCII version in the Phase 5 brief Section 8. | Behavior and Defensive Interpretation — Section 8 (Annotated Kill Chain Diagram). |

---

## Final Numbering Summary

**In-use screenshots (numbered):** 1–25, 36–44, 46–49, 51–52, 57–58, 62–65, 65b, 67–76. Optional: 77.

**Skipped numbers** (documented above, do not look for these): 26, 27 *(actually exists)*, 29, 45, 50, 53, 54, 55, 56 *(optional)*, 59, 60, 61, 66.

**Unnumbered supporting screenshots:** see "Unnumbered Screenshots (Supporting Evidence)" section earlier in this guide.
