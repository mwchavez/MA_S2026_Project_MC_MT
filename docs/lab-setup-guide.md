# Lab Setup Guide

**Project:** CSEC 4300 — Malware Analysis (URSNIF)
**Authors:** Moses Chavez, Marissa Turner
**Last updated:** April 2026

This document provides reproducible instructions for building the three-VM URSNIF analysis lab on a Windows 11 host. It is a companion to the Phase 1 Wiki section; the Wiki contains screenshots and validation evidence, while this guide contains the reproducible procedure.

---

## 1. Host Requirements

| Resource | Requirement |
|---|---|
| Operating system | Windows 10/11, 64-bit |
| RAM | 32 GB minimum (12 GB SO + 4 GB REMnux + 8 GB Detonation + ~8 GB host headroom) |
| Storage | 250 GB minimum free (200 GB SO + 40 GB REMnux + 80 GB Detonation + working space) |
| Hardware virtualization | VT-x (Intel) or AMD-V enabled in BIOS/UEFI |
| Network | Host machine internet access required ONLY for tool downloads on the host. The lab itself runs airgapped. |

**Verification commands (host):**

```powershell
# Confirm virtualization is enabled
systeminfo | findstr /i "Virtualization"

# Confirm available RAM
wmic memorychip get capacity
```

---

## 2. Hypervisor: Oracle VirtualBox

### Installation

1. Download VirtualBox from `https://www.virtualbox.org/wiki/Downloads`
2. Verify the download against the SHA256 published on the VirtualBox site
3. Install VirtualBox
4. Download and install the matching version of the VirtualBox Extension Pack (required for USB filtering and PXE — both unused in the lab, but kept for completeness)

### Network Configuration

Two networks must exist before any VM is built:

**Management Network (Host-Only)**
1. VirtualBox Manager → File → Tools → Network Manager → Host-only Networks tab
2. Create or confirm a host-only network
3. IPv4 address: `192.168.56.1`
4. IPv4 netmask: `255.255.255.0`
5. DHCP: **disabled** (static IPs are assigned manually)

**Analysis Network (Internal)**
1. VirtualBox internal networks are created on first VM-attachment and need no Manager-level configuration
2. Subnet: `10.0.0.0/24` (assigned via static IPs on each VM)
3. Name (used in VM network adapter settings): `AnalysisNet`
4. No host adapter is attached — this network has no path to the host or the internet

---

## 3. Virtual Machine Builds

### 3.1 Security Onion (Sensor)

**Specifications:**
- OS: Oracle Linux 9.7 (Security Onion 3.0.0)
- RAM: 12 GB
- Disk: 200 GB
- CPUs: 4 (recommended)

**Network adapters:**
- Adapter 1: Host-Only Adapter (management) — interface name `enp0s3`
- Adapter 2: Internal Network "AnalysisNet", **Promiscuous Mode: Allow All** (monitor) — interface name `enp0s8`

**Static IPs:**
- Management: `192.168.56.10/24`, gateway `192.168.56.1`
- Monitor: no IP (promiscuous monitor only, bonded to `bond0`)

**Setup wizard answers (Security Onion installer):**

| Setting | Value |
|---|---|
| Node Type | EVAL (selected over STANDALONE because STANDALONE requires 16 GB RAM) |
| Airgap | Yes |
| Hostname | `securityonion` |
| Management interface | `enp0s3` |
| Monitor interface | `enp0s8` |
| Management IP | `192.168.56.10/24` |
| Gateway | `192.168.56.1` |
| DNS | `1.1.1.1` (placeholder — airgapped, never queried) |
| SOC web admin | `moses@lab.local` (password stored separately in `docs/lab-credentials.txt`) |
| Allowed analyst subnet | `192.168.56.0/24` |

**Verification:**

```bash
sudo so-status
# All services should show 'ok' — particularly so-suricata, so-zeek, so-elasticsearch, so-kibana, so-soc

ip a show enp0s3
ip a show enp0s8
# enp0s3 has 192.168.56.10
# enp0s8 has PROMISC flag and no IP
```

Web interface: `https://192.168.56.10` (accessed from host browser).

---

### 3.2 REMnux (Analysis Workstation + Simulated Internet)

**Specifications:**
- OS: REMnux on Ubuntu 24.04 LTS (OVA import)
- RAM: 4 GB
- Disk: 40 GB
- CPUs: 2

**Network adapters:**
- Adapter 1: Host-Only Adapter (management) — `enp0s3`
- Adapter 2: Internal Network "AnalysisNet", Promiscuous Mode: Allow All — `enp0s8`

**Static IPs (configured via netplan at `/etc/netplan/99-lab-static.yaml`):**
- Management: `192.168.56.20/24`, gateway `192.168.56.1`
- Analysis: `10.0.0.1/24` — gateway and DNS for the detonation VM

**INetSim configuration:**

Edit `/etc/inetsim/inetsim.conf`:

```
service_bind_address    10.0.0.1
dns_default_ip          10.0.0.1
```

Enable services: dns, http, https, smtp, smtps, pop3, pop3s, ftp, ftps, irc, ntp.

**Note on DNS service:** Ubuntu's `systemd-resolved` occupies port 53 by default and prevents INetSim from binding DNS. To free port 53:

```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

**Starting INetSim:** REMnux's `inetsim` shell function wrapper requires explicit binding. Always invoke the binary directly:

```bash
sudo /usr/bin/inetsim --bind-address=10.0.0.1
```

Original config preserved at `/etc/inetsim/inetsim.conf.original`.

---

### 3.3 Windows Detonation VM

**Specifications:**
- OS: Windows 10 Pro
- RAM: 8 GB
- Disk: 80 GB
- CPUs: 2

**Network adapters:**
- Adapter 1: **Internal Network "AnalysisNet"**, Promiscuous Mode: Deny — only adapter
- All other adapters disabled

**Static IP (configured via Windows network properties):**
- IP: `10.0.0.100/24`
- Gateway: `10.0.0.1` (REMnux)
- DNS: `10.0.0.1` (REMnux INetSim)

**Local user:** `analyst` (password stored separately in `docs/lab-credentials.txt`).

**Tool installation: ISO-mount method (no internet).**

A FlareVM-style installer was deliberately not used because it requires the detonation VM to have internet access during setup — a violation of our isolation posture. Instead:

1. On the host, download each analysis tool individually with full hash and Authenticode verification
2. Build a read-only ISO from the host containing all tools (`ursnif-tools.iso`)
3. Mount the ISO as a virtual DVD on the detonation VM
4. Install/extract tools from the mounted ISO into `C:\Tools\`

Tools installed via this method:
- Sysinternals Suite (ProcMon, ProcExp, Autoruns, etc.)
- PEStudio (portable)
- PE-bear (portable)
- Detect It Easy / DIE (portable)
- Ghidra 12.0.4
- Eclipse Temurin JDK 25 (Ghidra dependency, MSI install)
- 7-Zip
- Notepad++
- Wireshark + Npcap

**Hardening (post-install):**

```powershell
# Disable Windows Defender (Group Policy + PowerShell)
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Windows Update service
Set-Service -Name wuauserv -StartupType Disabled
```

VirtualBox VM settings (applied via Manager):
- Shared clipboard: Disabled
- Drag-and-drop: Disabled
- Shared folders: None
- USB controller: **Disabled** (PS/2 mouse used since USB is off)

---

## 4. Network Validation

The detonation VM must be incapable of reaching the public internet, the host's LAN, or the host machine itself. Every test below must fail/succeed exactly as documented.

**From the detonation VM:**

| Test | Expected result |
|---|---|
| `ping 8.8.8.8` | 100% packet loss (no internet) |
| `ping 192.168.1.254` (or your home router IP) | 100% loss (no LAN) |
| `ping 192.168.56.1` (host) | 100% loss (no host access) |
| `nslookup google.com` (against `10.0.0.1`) | Times out or returns INetSim's fake reply (DNS contained) |
| `ping 10.0.0.1` | 4/4 success (AnalysisNet reachable) |

**From the host:**

| Test | Expected result |
|---|---|
| `ping 192.168.56.10` (Security Onion) | 4/4 success |
| `ping 192.168.56.20` (REMnux) | 4/4 success |
| Browser → `https://192.168.56.10` | SOC console loads |

---

## 5. Snapshot Discipline

Each VM should have a clean baseline snapshot before any analysis activity:

| VM | Baseline snapshot name |
|---|---|
| Security Onion | `Clean Baseline - Install Complete` |
| REMnux | `Clean Baseline - INetSim Configured` |
| Detonation VM | `Post-Install - Analysis Tools Ready` |

Additional snapshots are taken at major milestones (e.g., `Phase 3 Complete - Ghidra Project Saved`, `Pre-Detonation - Phase 4`). The detonation VM is reverted to a clean snapshot after every detonation.

---

## 6. Boot Order

For analysis sessions, boot VMs in this order:

1. **REMnux first** — staging for INetSim and any sample preparation
2. **Security Onion second** — sensor must be capturing before traffic begins
3. **Detonation VM last** — detonation target

Shutdown is the reverse order, with the detonation VM reverted to its clean snapshot before powering down.

---

## 7. Sample Handling

URSNIF artifacts are obtained from `https://www.malware-traffic-analysis.net/2021/05/14/index.html`. The password-protected ZIP is transferred to REMnux via a mounted ISO (`ursnif-samples.iso`) — never extracted on the host.

Sample location on REMnux: `/home/remnux/ursnif-samples/2021-05-14-Ursnif-traffic-and-malware-and-IOCs/`

For Phase 3 and Phase 4, the `block.dll` and `.xlsb` artifacts are transferred to the detonation VM via the same `ursnif-samples.iso` mounted as a read-only optical drive.

**No malware artifact ever touches:**
- The host filesystem (other than inside an ISO container)
- A network adapter with internet routing
- A shared folder
- The clipboard

---

## 8. References

- Security Onion documentation: `https://docs.securityonion.net/en/2.4/`
- REMnux documentation: `https://docs.remnux.org/`
- INetSim documentation: `https://www.inetsim.org/`
- VirtualBox documentation: `https://www.virtualbox.org/manual/`
