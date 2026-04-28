# Tool Reference

**Project:** CSEC 4300 — Malware Analysis (URSNIF)
**Authors:** Moses Chavez, Marissa Turner
**Last updated:** April 2026

This document catalogs every tool used in the project. For each tool: the version used, the VM it runs on, its analytical role, and (for downloaded tools) the verification method used to confirm authenticity.

---

## 1. Tool Catalog by VM

### 1.1 Tools on REMnux

REMnux ships with most static analysis tools pre-installed; this list covers the tools actively used in the project, not the full REMnux toolkit.

| Tool | Version | Role | Phase(s) |
|---|---|---|---|
| `md5sum`, `sha256sum` | (coreutils) | Cryptographic hashing of artifacts | 2 |
| `less` | (util-linux) | Raw email header inspection | 2 |
| `emldump.py` | (DidierStevens) | MIME structure parsing, attachment extraction | 2 |
| `oletools` (`olevba`, `oleid`) | 0.60+ | VBA macro extraction (returned no VBA — confirms XLM-only dropper) | 2 |
| `XLMMacroDeobfuscator` | 0.2.7 | Excel 4.0 (XLM) macro deobfuscation | 2 |
| `unzip` | (info-zip) | XLSB container structure inspection | 2 |
| `rabin2` | radare2 5.x | PE header, section, import, export, string extraction | 2 |
| `capa` | mandiant/capa 7.x | Capability detection mapped to MITRE ATT&CK | 2 |
| `yara` | 4.x | File-level signature matching against custom rules | 2 |
| `tshark` | Wireshark 4.x | Command-line PCAP analysis for IOC extraction | 4 |
| INetSim | 1.3.2 | Simulated DNS, HTTP, HTTPS, SMTP, FTP, IRC, NTP services | 4 |

### 1.2 Tools on Security Onion

| Tool | Version | Role | Phase(s) |
|---|---|---|---|
| Suricata | (bundled with SO 3.0.0) | Signature-based IDS | 1, 4 |
| Zeek | (bundled with SO 3.0.0) | Network metadata generation, protocol logging | 1, 4 |
| Elasticsearch | (bundled with SO 3.0.0) | Event indexing | 1, 4 |
| Kibana / SOC console | (bundled with SO 3.0.0) | Alert visualization, threat hunting interface | 1, 4 |
| `so-status` | (Security Onion CLI) | Container/service health verification | 1, 4 |
| `so-import-pcap` | (Security Onion CLI) | PCAP replay/ingestion through Suricata + Zeek | 4 |

### 1.3 Tools on the Windows Detonation VM

| Tool | Version | Role | Phase(s) |
|---|---|---|---|
| Sysinternals Process Monitor | latest | File/registry/process activity logging | 4 |
| Sysinternals Process Explorer | latest | Live process tree, parent-child inspection | 4 |
| Sysinternals Autoruns | latest | Persistence mechanism inspection (ad-hoc) | 4 |
| Wireshark | 4.6.4 | Live network packet capture in detonation VM | 4 |
| Npcap | (bundled with Wireshark) | Packet capture driver | 4 |
| PEStudio | (vendor latest) | PE inspection (file metadata, imports, strings) | 2, 3 |
| PE-bear | 0.7.1 | Alternative PE inspection (used as cross-reference) | 2, 3 |
| Detect It Easy (DIE) | 3.10 | Compiler/linker fingerprinting, packer detection, entropy analysis | 3 |
| Ghidra | 12.0.4 | Disassembly, decompilation, cross-reference analysis, Function ID matching | 3 |
| Eclipse Temurin JDK | 25.0.2 | Ghidra runtime dependency | 3 |
| 7-Zip | 26.00 | Archive extraction | 1, 4 |
| Notepad++ | 8.9.3 | Text inspection | (general) |

### 1.4 Tools on the Host (Windows 11)

| Tool | Version | Role | Phase(s) |
|---|---|---|---|
| Oracle VirtualBox | (current at install) | Hypervisor for all three lab VMs | 1 |
| VirtualBox Extension Pack | matching VirtualBox version | USB filtering, PXE (unused but kept for completeness) | 1 |
| AnyBurn | 6.7 | ISO image construction (host-only ISO building tool) | 1 |
| `VBoxManage debugvm` | (VirtualBox CLI) | Memory dump capture from running VMs | 4 |
| PowerShell | 7.5 | Tool verification (`Get-FileHash`, Authenticode signature checks) | 1 |
| Windows browser (Edge/Chrome) | latest | Access to Security Onion SOC console | 1, 4 |

---

## 2. Tool-Exclusion Decisions

The following tools were considered and **not** included in the lab. These decisions are documented as part of the project's security and methodology posture.

### 2.1 x64dbg (excluded)

VirusTotal flagged the official x64dbg release at 3/67 detections — including one detection that named a specific malware family (Zillya: IcedID). While these are likely false positives on a debugger, the team chose to exclude x64dbg because Ghidra 12 includes an integrated debugger that satisfies the same analytical need without introducing the verification ambiguity. This is documented as a deliberate tool-exclusion decision.

### 2.2 FlareVM Boxstarter installer (excluded)

The standard FlareVM tool deployment process uses a Boxstarter/Chocolatey installer that requires the Windows VM to have internet access during installation. The team rejected this approach because it would break the no-internet posture of the detonation VM. Instead, all FlareVM-style tools were installed individually via a read-only ISO (see Lab Setup Guide section 3.3).

### 2.3 Volatility 3 (deferred, not excluded)

Volatility 3 was not installed during the active analysis window due to time constraints. The 8.73 GB memory dump captured in Phase 4 (`flarevm-postdetonation.elf`) is preserved for future analysis. Memory-resident malware behavior is documented from ProcMon and Process Explorer observation in Phase 4 instead.

---

## 3. Tool Verification Audit Trail

All host-side tool downloads were verified before being included in the project. The verification log:

| Tool | Verification method | Result |
|---|---|---|
| Sysinternals Suite | SHA256 hash + Microsoft Authenticode signed exes | ✅ Verified |
| 7-Zip 26.00 | MD5 vendor match + VirusTotal (1/72, Bkav AI heuristic only) | ✅ Verified |
| Notepad++ 8.9.3 | Authenticode valid (Don Ho / GlobalSign) | ✅ Verified |
| PEStudio | SHA256 vendor hash match (winitor.com) | ✅ Verified |
| PE-bear 0.7.1 | VirusTotal cross-reference (0/67 clean) | ✅ Verified |
| Detect It Easy 3.10 | VirusTotal (1/66 MaxSecure susgen heuristic) + verified source (horsicq GitHub) | ✅ Verified with VMProtect packing noted |
| Eclipse Temurin JDK 25 | SHA256 vendor match + Authenticode valid (Eclipse Foundation / DigiCert) | ✅ Verified |
| Ghidra 12.0.4 | SHA256 vendor match (NSA-published in release notes) | ✅ Verified |
| Wireshark 4.6.4 | SHA256 vendor match (PGP-signed SIGNATURES file) + Authenticode valid (Wireshark Foundation / Sectigo) | ✅ Verified |
| AnyBurn 6.7 | MD5 vendor match + Authenticode valid (Power Software Ltd / SSL.com) | ✅ Verified |
| Security Onion 3.0.0 ISO | SHA256 vendor match | ✅ Verified |

The verification log is preserved on the host at `C:\Users\moses\UIW\malware_analysis\hashes.txt` (not committed to the repository).

---

## 4. Common Invocations

This section captures the exact commands used during analysis, for reproducibility.

### 4.1 Static analysis (REMnux)

```bash
# Hashing
md5sum *
sha256sum *

# Email
less 2021-05-03-malspam-pushing-Ursnif.eml
emldump.py 2021-05-03-malspam-pushing-Ursnif.eml
emldump.py -s 3 -d 2021-05-03-malspam-pushing-Ursnif.eml | md5sum
emldump.py -s 3 -d 2021-05-03-malspam-pushing-Ursnif.eml | sha256sum

# XLSB
olevba I8m7XluZbbj10J53.xlsb           # returns 'No VBA' (XLM-only)
oleid I8m7XluZbbj10J53.xlsb
xlmdeobfuscator --file I8m7XluZbbj10J53.xlsb
mkdir xlsb_unpacked && cd xlsb_unpacked && unzip ../I8m7XluZbbj10J53.xlsb

# block.dll
file block.dll
rabin2 -I block.dll
rabin2 -S block.dll
rabin2 -ii block.dll | grep -iE "VirtualAlloc|VirtualProtect|GetProcAddress|LoadLibrary|IsDebuggerPresent"
rabin2 -E block.dll
rabin2 -zz block.dll
capa block.dll

# YARA verification
yara ~/ursnif-dll.yar block.dll
yara ~/ursnif-dropper.yar I8m7XluZbbj10J53.xlsb
yara -r ~/ursnif-dropper.yar xlsb_unpacked/
```

### 4.2 INetSim startup (REMnux)

```bash
sudo /usr/bin/inetsim --bind-address=10.0.0.1
```

### 4.3 Detonation (Windows VM)

```cmd
cd C:\malware
rundll32.exe block.dll,Pape1
```

(Optional fallback: `rundll32.exe block.dll,Riverslow` if `Pape1` does not produce expected behavior.)

### 4.4 Memory dump (Host PowerShell)

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "FlareVM" dumpvmcore --filename="C:\Users\moses\UIW\malware_analysis\flarevm-postdetonation.elf"
```

### 4.5 PCAP analysis (REMnux)

```bash
# DNS query inventory
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# HTTP request inventory
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -Y "http.request" -T fields -e ip.dst -e http.host -e http.request.uri -e http.user_agent

# Destination IP inventory
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -T fields -e ip.dst | sort -u | grep -v "^$"
```

### 4.6 PCAP replay through Security Onion

```bash
# Transfer (from REMnux)
scp 2021-05-14-Ursnif-infection-traffic.pcap moses@192.168.56.10:/tmp/

# Import (from Security Onion console)
sudo so-import-pcap /tmp/2021-05-14-Ursnif-infection-traffic.pcap
```
