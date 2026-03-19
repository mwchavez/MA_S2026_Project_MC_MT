# Malware Analysis Lab: Network-Based Detection and Behavioral Analysis of URSNIF
 
## Overview
 
This project presents a virtualized malware analysis laboratory built on Security Onion, integrating network intrusion detection with static, dynamic, and assembly-level malware analysis techniques. The lab environment enables controlled detonation of malware artifacts from the URSNIF (Gozi/ISFB) banking trojan family, captures resulting network telemetry via Suricata and Zeek, and correlates observed behaviors with binary-level indicators to produce actionable detection signatures and structured intelligence reports.
 
All analysis is performed within an isolated virtual environment with no connectivity to the public internet or the host system's local network.
 
## Background
 
This work extends a prior project conducted for coursework in Intrusion Detection Systems and Digital Forensics, which focused on deploying a Security Onion sensor, capturing baseline network traffic, and authoring custom Suricata rules. The current iteration expands the scope into full-spectrum malware analysis by introducing a sandboxed detonation environment, simulated internet services, YARA-based file detection, assembly-level code analysis, and a structured analytical methodology grounded in the kill chain and diamond models.
 
## Lab Architecture
 
The lab runs on a Windows 11 desktop (32 GB RAM, 250+ GB available storage) using Oracle VirtualBox. It consists of three virtual machines operating across two isolated network segments:
 
| VM | Role | Resources | Network |
|---|---|---|---|
| **Security Onion** | Network sensor (Suricata IDS, Zeek NSM, Elasticsearch/Kibana) | 12 GB RAM, 200 GB disk | Management + Analysis (monitor) |
| **REMnux** | Linux analysis workstation, INetSim (simulated DNS/HTTP/SMTP), static analysis tools, YARA | 4 GB RAM, 40 GB disk | Management + Analysis |
| **Windows Detonation VM (FlareVM)** | Malware execution environment, dynamic and memory analysis | 8 GB RAM, 60 GB disk | Isolated Analysis |
 
### Network Topology
 
**Management Network** (VirtualBox Host-Only Adapter)
Provides administrative access to Security Onion's web interface (Kibana, SOC console) from the host machine's browser. No malware traffic traverses this network.
 
**Isolated Analysis Network** (VirtualBox Internal Network)
All detonation traffic flows exclusively on this segment. The Windows detonation VM communicates with REMnux's INetSim services (simulated DNS, HTTP, SMTP). Security Onion monitors this network via a promiscuous-mode interface. No traffic from this network is routed to the public internet or the host's local network.
 
### Safety Controls
 
The following isolation and safety measures are enforced at all times:
 
- **No bridged or NAT networking** — Detonation VM uses Internal Network adapters only; no route to the internet or host LAN exists
- **No shared folders** — VirtualBox shared folders are disabled on all VMs
- **No shared clipboard or drag-and-drop** — Bidirectional clipboard and drag-and-drop are disabled between host and guest
- **No USB passthrough** — USB controllers are disabled on the detonation VM
- **Snapshot before every detonation** — The detonation VM is reverted to a clean snapshot after each analysis run
- **Malware handling** — All samples are stored exclusively within the isolated analysis environment; no malware binaries are committed to this repository
 
## Malware Sample: URSNIF (Gozi/ISFB)
 
### Overview
 
URSNIF, also known as Gozi or ISFB, is a banking trojan first identified in 2006. Its source code was leaked on GitHub, leading to widespread proliferation and numerous variants. URSNIF is classified as a commodity banking trojan that targets financial credentials through browser injection, form grabbing, and man-in-the-browser attacks.
 
### Sample Source
 
The sample set is sourced from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net), a public repository maintained for research and educational purposes. The specific exercise is dated **2021-05-14** and documents an URSNIF infection chain.
 
### Artifact Inventory
 
| Artifact | Description | Analysis Role |
|---|---|---|
| `2021-05-03-malspam-pushing-Ursnif.eml` | Original phishing email (initial access vector) | Kill chain mapping, social engineering analysis |
| `l8m7XluZbbj10J53.xlsb` | Excel Binary Workbook with embedded macros (first-stage dropper) | Static analysis (macro inspection), Phase 2 & 3 |
| `block.dll` | URSNIF DLL payload (core malware) | Static analysis (PE headers, imports, strings), assembly-level disassembly, dynamic execution, memory analysis |
| `2021-05-14-Ursnif-infection-traffic.pcap` | Full packet capture of infection traffic | Network behavior analysis, Suricata/Zeek detection, C2 identification |
| `2021-05-14-IOCs-for-Ursnif-infection.txt` | Pre-documented indicators of compromise | Validation and cross-reference for Phase 5 |
 
### Kill Chain
 
```
Malicious Email (.eml)
    → PDF/Excel Attachment (.xlsb with macros)
        → JavaScript Dropper (Fattura.js)
            → Secondary Dropper (lista.js)
                → URSNIF DLL Payload (block.dll)
```
 
> **Note:** No live malware binaries are stored in this repository. Only sample hashes, analysis artifacts (screenshots, logs, disassembly excerpts), and sourcing metadata are documented.
 
## Analysis Methodology
 
Each artifact undergoes a structured analysis pipeline aligned with the five required project phases:
 
### Phase 1: Environment Setup
Construction of the isolated three-VM lab environment, installation and configuration of all analysis tools, and validation of network isolation and safety controls.
 
### Phase 2: Static Analysis
Extraction of file hashes (MD5, SHA-256), strings analysis, file format inspection (PE headers, import tables, section entropy for the DLL; macro extraction for the XLSB), and YARA rule matching against known URSNIF signatures.
 
### Phase 3: Assembly-Level Code Analysis
Disassembly of `block.dll` using Ghidra and/or x64dbg. Identification and documentation of meaningful code regions including loops, conditional branches, API resolution techniques, and any obfuscation or packing indicators.
 
### Phase 4: Dynamic and Memory Analysis
Controlled execution of the infection chain within the Windows detonation VM. Observation of runtime behavior including process creation, loaded modules, file system and registry modifications, and memory-resident artifacts. Network traffic captured and analyzed via Security Onion (Suricata alerts, Zeek logs).
 
### Phase 5: Behavior and Defensive Interpretation
Synthesis of all findings into a behavioral summary, comprehensive IOC list (file hashes, registry keys, network indicators), and actionable defensive recommendations including custom Suricata rules and YARA signatures.
 
## Repository Structure
 
```
├── docs/                          # Wiki and reference documentation
│   ├── lab-setup-guide.md         # Full environment build instructions
│   ├── tool-reference.md          # Tool configurations and usage notes
│   └── analysis-methodology.md   # Analytical framework documentation
│
├── rules/                         # Detection signatures
│   ├── suricata/                  # Custom Suricata rules
│   │   └── custom.rules
│   └── yara/                      # YARA rules for URSNIF indicators
│       ├── ursnif-dll.yar
│       └── ursnif-dropper.yar
│
├── reports/                       # Analysis reports
│   └── ursnif-2021-05-14/
│       ├── static-analysis.md
│       ├── assembly-analysis.md
│       ├── dynamic-analysis.md
│       ├── kill-chain.md
│       └── iocs.json
│
├── evidence/                      # Supporting artifacts (no binaries)
│   ├── screenshots/
│   ├── pcap-exports/
│   └── disassembly-excerpts/
│
├── README.md
└── LICENSE
```
 
## Tools and Technologies
 
- **Security Onion** — Network security monitoring platform (Suricata, Zeek, Elasticsearch, Kibana)
- **Suricata** — Signature-based intrusion detection and network traffic analysis
- **Zeek** — Network metadata generation and protocol logging
- **YARA** — Pattern matching for file-level malware identification
- **REMnux** — Linux-based malware analysis distribution
- **FlareVM** — Windows-based malware analysis and reverse engineering environment
- **INetSim** — Simulated internet services for safe dynamic analysis
- **Ghidra** — NSA's open-source reverse engineering and disassembly framework
- **x64dbg** — Open-source Windows debugger for dynamic binary analysis
- **Wireshark** — Network protocol analyzer
- **olevba / oletools** — Office document and macro analysis utilities
- **PEStudio / PE-bear** — Portable Executable inspection tools
- **Process Monitor / Process Explorer** — Sysinternals runtime behavior monitoring
- **Volatility** — Memory forensics framework
## Authors

- **Moses Chavez** — @mwchavez
- **Marissa Turner** — @marilturner

## Acknowledgments

This project was developed as coursework for CSEC 4300: Malware Analysis, building upon prior work completed for CIS 3370: Intrusion Detection Systems and CIS 3345: Digital Forensics at University of the Incarnate Word.

## License

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for details.
