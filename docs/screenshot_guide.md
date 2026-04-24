# Screenshot Guide for Wiki Documentation

**For:** Marissa Turner
**Created by:** Moses Chavez (via Claude project assistant)
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

4. **More screenshots are coming** from Phases 2-5 as Moses completes the analysis work. This guide will be updated.
