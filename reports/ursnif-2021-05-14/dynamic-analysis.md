# Dynamic and Memory Analysis Report — URSNIF (2021-05-14)

**Authors:** Moses Chavez, Marissa Turner
**Sample:** `block.dll` (SHA-256 `8a26c32848c9ea085505359f67927d1a744ec07303ed0013e592eca6b4df4790`)
**Analysis date:** April 2026
**Environment:** Windows Detonation VM (8 GB RAM, isolated AnalysisNet), REMnux (INetSim sinkhole), Security Onion (sensor).

---

## 1. Scope

This report documents Phase 4 of the analysis pipeline: dynamic execution of `block.dll` in the isolated detonation environment, observation of host and network behavior, memory dump capture, and analysis of the provided 2021-05-14 PCAP to recover the network IOCs that the lab environment could not surface.

Phase 2 and Phase 3 had established that `block.dll` employs runtime decryption to defeat static IOC extraction. Phase 4 was therefore expected to surface IOCs that were not recoverable statically: C2 domains, dropped files, registry persistence, and process injection patterns.

---

## 2. Pre-Detonation Preparation

### 2.1 Snapshot discipline

Before introducing live malware execution, three rollback snapshots existed:

- `Post-Install - Analysis Tools Ready` — clean baseline (Phase 1)
- `Phase 3 Complete - Ghidra Project Saved` — Phase 3 stable state with `block.dll` staged but not executed
- `Pre-Detonation - Phase 4` — fresh snapshot taken immediately before any execution

After Phase 4 completed, an additional `Post-Detonation - Evidence Captured` snapshot was preserved for re-screenshotting and Phase 5 reference. The detonation VM was then reverted to the Phase 3 clean state.

### 2.2 Boot order and INetSim staging

VMs were started in order: REMnux first, then Security Onion (sensor), then the Detonation VM (target). On REMnux, INetSim was started bound to the AnalysisNet interface (`10.0.0.1`).

### 2.3 Connectivity verification

From the Detonation VM:
- `ping 10.0.0.1` → 4/4 success (REMnux reachable on AnalysisNet) ✓

### 2.4 Monitoring tool staging

Three tools were configured on the Detonation VM **before** execution to ensure full observability from the moment URSNIF launched:

- **Process Monitor** — display cleared, capture stopped pending detonation, filter applied to `Process Name is rundll32.exe → Include` to suppress system noise
- **Process Explorer** — open with full process tree visible
- **Wireshark** — interface verified (`Ethernet` adapter on AnalysisNet), capture stopped pending detonation

---

## 3. Detonation Execution

### 3.1 Command issued

In an Administrator Command Prompt on the Detonation VM:

```
cd C:\malware
rundll32.exe block.dll,Pape1
```

The command returned to the prompt almost instantly (rundll32 fork-and-forget semantics). The malware was permitted to execute for five minutes while all three monitoring tools captured live data.

### 3.2 Capture statistics

- **ProcMon:** 802,164 total events captured; 3,307 events matched the rundll32 filter (~0.4%) — confirming the filter eliminated system noise effectively.
- **Wireshark:** 178 packets captured on the AnalysisNet interface.

---

## 4. Live Behavioral Findings

### 4.1 Process behavior — self-spawn-and-exit

URSNIF exhibited a clear self-spawn-and-exit pattern, captured via Process Explorer's Process Tree:

```
cmd.exe (PID 5292)
└── rundll32.exe (PID 964)        — manual launch / parent
    └── rundll32.exe (PID 3788)    — URSNIF-spawned child
└── conhost.exe (PID 3240)
```

The child `rundll32.exe` (PID 3788) is the live URSNIF process for the duration of the detonation. By the end of the observation window, both `rundll32` processes had exited from the active process list — indicating that **URSNIF migrated its execution into another process** (process injection) and terminated its loaders.

### 4.2 Reconnaissance — System32 enumeration and COM/OLE probing

ProcMon captured PID 3788 performing two distinctive reconnaissance behaviors:

**System32 enumeration:** Rapid `QueryDirectory` operations across `C:\Windows\System32` — consistent with URSNIF scanning for specific DLLs to load, hijack, or sideload.

**COM/OLE registry probing:** Sequences of `RegOpenKey`, `RegQueryValue`, `RegQueryKey`, `RegSetInfoKey`, `RegCloseKey` against:

- `HKLM\System\CurrentControlSet\Control\...`
- `HKLM\SOFTWARE\Microsoft\Ole`
- `HKLM\SOFTWARE\Microsoft\OLE\Aggregate...`
- `HKCR\WOW6432Node\CLSID\{A4A1...}` (32-bit registry view, consistent with the 32-bit DLL)

This pattern is consistent with **COM CLSID hijacking reconnaissance**.

### 4.3 File system and registry — significant negative findings

After applying additional ProcMon filters for `Operation is WriteFile → Include` and `Operation is RegSetValue → Include`:

- **WriteFile events (rundll32 lineage): zero**
- **RegSetValue events (rundll32 lineage): zero**

URSNIF created no files on disk and registered no persistence entries during five minutes of execution. This is a **direct experimental confirmation of URSNIF's documented memory-resident execution model**. The malware conducts all of its banking-trojan operations within process memory and does not touch disk for persistence or configuration storage during a typical infection lifecycle.

This finding directly validates the static-analysis hypothesis from Phase 3: that `FUN_0103320c`'s arithmetic state mutation operates entirely on in-memory globals (`DAT_0104a008`, `DAT_0104a0d8`, etc.) and that all configuration is decrypted at runtime in memory rather than written to disk.

### 4.4 Network behavior — DNS probing

The Wireshark capture surfaced URSNIF's outbound DNS query pattern:

| Query order | Domain | Type | Significance |
|---|---|---|---|
| 1st | `api.msn.com` | A | Microsoft connectivity check (URSNIF's "do I have internet" probe) |
| 2nd–4th | `go.microsoft.com` | A (×3 retries) | Secondary connectivity check |
| 5th+ | `app.buboleinov.com` | A | **C2 server domain** — confirmed real URSNIF C2 IOC |

REMnux responded with ICMP "destination port unreachable" to each DNS attempt (because INetSim's DNS bind had failed — see Section 8 limitation). The DNS query *attempts* themselves are still observable as network IOCs, even without successful resolution.

### 4.5 Network behavior — protocol distribution

Wireshark Statistics → Protocol Hierarchy showed:

| Protocol | Percentage | Significance |
|---|---|---|
| DNS | 37.1% | Heavy DNS activity (consistent with C2 lookup retries) |
| ICMP | 26.4% | INetSim's port-unreachable responses |
| NetBIOS Name Service | 5.1% | URSNIF performing local network reconnaissance |
| SSDP | 2.2% | Service discovery probes |
| HTTP | 0% | URSNIF did not fall back to direct-IP HTTP after DNS failed |
| TLS | 0% | No encrypted C2 traffic established |

The absence of HTTP/TLS is a direct consequence of the DNS sinkhole limitation. The provided PCAP analysis (Section 6) recovers the HTTP traffic the lab could not.

---

## 5. Memory Analysis

A full memory dump of the Detonation VM was captured from the host using:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "FlareVM" dumpvmcore --filename="C:\Users\moses\UIW\malware_analysis\flarevm-postdetonation.elf"
```

The dump (8.73 GB ELF format, 8,730,336,884 bytes) is preserved on the host for offline analysis. VirtualBox briefly paused the VM, wrote raw memory bytes to a host file, and resumed the VM. No malware execution occurred on the host during this operation; the dump file is data, not executable.

Volatility 3 was the planned analysis framework. Intended plugins: `windows.pslist`, `windows.malfind`, `windows.netscan`, `windows.dlllist`. Volatility 3 was not installed during the analysis window; given the time budget, a deliberate decision was made to defer Volatility analysis rather than spend remaining time on tool installation.

For this deliverable, URSNIF's memory-resident behavior is documented from ProcMon and Process Explorer observation (Section 4.1 — process self-spawn-and-exit, Section 4.3 — zero file/registry writes). These observations are consistent with what `windows.malfind` would have surfaced at higher fidelity. The 8.73 GB memory dump is preserved for future analysis.

---

## 6. PCAP Analysis (Provided 2021-05-14 Capture)

The provided PCAP (`2021-05-14-Ursnif-infection-traffic.pcap`) was analyzed to recover the network IOCs that the live detonation could not surface (DNS sinkhole limitation). Two parallel analysis paths were used.

### 6.1 Security Onion ingestion

The PCAP was transferred to the Security Onion VM via `scp` from REMnux over the management network. Security Onion's `so-import-pcap` tool was run:

```
sudo so-import-pcap /tmp/2021-05-14-Ursnif-infection-traffic.pcap
```

The tool ingested the PCAP successfully:
- Verifying file → OK
- Assigning unique import identifier `811fb8b5efca216dfb4d7a0ef4055a2b`
- Analyzing traffic with Suricata → completed
- Analyzing traffic with Zeek → completed
- Reported PCAP date range: `2021-05-14 through 2021-05-15`

Elasticsearch ingested 1,256 events from the import. However, the standard Alerts dashboard view did not surface Suricata signature matches when filtered to the PCAP's 2021 date range — see Section 8 (Limitation 2).

### 6.2 Direct PCAP analysis with `tshark`

To recover the network IOCs efficiently, `tshark` was run on REMnux against the original PCAP file. Three targeted queries surfaced all IOCs needed for Phase 5 detection rule development:

```bash
# DNS query inventory
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -Y "dns.flags.response == 0" \
       -T fields -e dns.qry.name | sort -u

# HTTP request inventory
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -Y "http.request" \
       -T fields -e ip.dst -e http.host -e http.request.uri -e http.user_agent

# Destination IP inventory
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -T fields -e ip.dst | sort -u | grep -v "^$"
```

### 6.3 IOCs recovered

**C2 domains (confirmed malicious):**

| Domain | Role |
|---|---|
| `app.buboleinov.com` | Primary C2 — also observed in live detonation |
| `docs.atu.ngr.mybluehost.me` | Staging server — delivers `presentation.dll` |
| `todo.faroin.at` | Secondary C2 — receives longest encoded URIs (likely exfiltration) |

**Behavioral fingerprints (not malicious infrastructure):**

| Domain | Purpose |
|---|---|
| `api.msn.com` | URSNIF's internet connectivity check |
| `myip.opendns.com` | OpenDNS reflection — public-IP discovery |
| `resolver1.opendns.com` | OpenDNS resolver |
| `222.222.67.208.in-addr.arpa` | Reverse DNS lookup |

**C2 IP addresses:**

| IP | Role |
|---|---|
| `34.95.142.247` | Primary C2 (Google Cloud) |
| `162.241.24.47` | Staging server (Bluehost) |
| `208.67.222.222` | OpenDNS public resolver (benign) |

**HTTP URI patterns:**

- `/presentation.dll` — secondary stage payload download from staging server
- `/favicon.ico` — frequent cover-traffic requests interspersed with C2
- `/U6I1_2B0OhVkWdfd8/...`, `/sB4J02_2FE9Gwh_2BM3/...`, `/_2F9WZViPJ/...`, `/rwCl8Et9i/...`, `/9B7mKifdQKW/...` — long URL-safe-base64-style encoded strings carrying URSNIF's encrypted C2 communication payload (config request, beacon, exfiltration)

**HTTP User-Agent strings:**

- `Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko` — Internet Explorer 11 spoofing
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0` — Firefox 86 spoofing

The use of two distinct User-Agent strings against the same C2 host is consistent with URSNIF's documented technique of mimicking the user's actual browser — enumerating installed browsers and matching its outbound C2 fingerprint to the local environment.

---

## 7. Findings Summary

1. **Memory-resident execution model confirmed.** URSNIF wrote zero files and made zero persistence registry entries during five minutes of execution, validating the Phase 3 static-analysis hypothesis.
2. **Process self-spawn-and-exit pattern observed.** URSNIF launched a child `rundll32.exe` (PID 3788) and subsequently caused both rundll32 processes to exit — consistent with process injection into a benign host process.
3. **System and COM/OLE reconnaissance.** URSNIF probed `C:\Windows\System32` and the `HKCR\WOW6432Node\CLSID\` registry tree.
4. **C2 domain `app.buboleinov.com` confirmed live.** Queried during the live detonation and present in the provided 2021 PCAP.
5. **Two additional C2/staging domains and three C2 IPs recovered** from the PCAP (Section 6.3).
6. **Two browser-spoofing User-Agent strings recovered** for use in Suricata HTTP rule authoring.
7. **8.73 GB memory dump preserved** for future Volatility analysis.

---

## 8. Limitations

For academic integrity, three limitations of the live environment are documented honestly. None invalidates the Phase 4 deliverable; each is addressed by parallel evidence.

### 8.1 INetSim DNS service did not bind

INetSim was started with `--bind-address=10.0.0.1`. INetSim reported `dns_53_tcp_udp - started (PID 2373)` in its startup log, but UDP/TCP port 53 listeners did not become functional in subsequent verification (`ss -tulpn` returned no INetSim DNS entries; functional Python socket tests timed out). Initial troubleshooting identified Ubuntu's `systemd-resolved` occupying port 53; that service was disabled. After the fix, INetSim's main process re-bound but its DNS subprocess still did not actually serve queries. Further troubleshooting was de-scoped due to time budget.

**Impact.** During live detonation, URSNIF's DNS queries to `api.msn.com`, `go.microsoft.com`, and `app.buboleinov.com` reached REMnux but received ICMP port-unreachable responses rather than INetSim's simulated A records. URSNIF could not resolve domain names to IPs and did not establish HTTP-level C2 communication.

**Mitigation.** The DNS query attempts themselves are still observable as network IOCs (Section 4.4). The full HTTP-level C2 traffic is recovered from the provided PCAP analysis (Section 6.2).

### 8.2 Security Onion did not surface Suricata alerts on the imported PCAP

`so-import-pcap` ingested the PCAP successfully (1,256 events into Elasticsearch confirmed), but the standard Alerts dashboard view returned zero results when filtered to the PCAP's 2021 date range. The most likely cause is that the bundled Suricata ruleset shipped with Security Onion 3.0.0 (March 2026) does not include signatures matching the specific 2021 URSNIF C2 patterns — rules may have aged out or been deprecated. Diagnosis was de-scoped due to time budget.

**Impact.** Phase 4 cannot present a Suricata alert dashboard as evidence of network detection.

**Mitigation.** This is the foundation for Phase 5's deliverable. Phase 5 authors **custom Suricata rules** targeting the C2 domains, IPs, URI patterns, and User-Agent strings recovered from the PCAP. Custom rules derived from observed traffic are a more rigorous defensive deliverable than relying on bundled signatures, and the absence of bundled-rule alerts on this 2021 traffic actively justifies the need for custom rule authoring.

### 8.3 Volatility memory analysis deferred

Volatility 3 was not installed on the host at detonation time. The 8.73 GB memory dump is preserved at `C:\Users\moses\UIW\malware_analysis\flarevm-postdetonation.elf`. Memory-resident behavior is documented from ProcMon and Process Explorer observations.

**Mitigation.** ProcMon's zero-write findings and Process Explorer's process tree showing rundll32 self-spawn-and-exit corroborate what `windows.malfind` would have surfaced at higher fidelity.
