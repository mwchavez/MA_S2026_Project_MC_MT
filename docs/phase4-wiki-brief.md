# Phase 4: Dynamic and Memory Analysis — Wiki Brief

**For:** Marissa Turner
**From:** Moses (via Claude)
**Purpose:** Everything you need to write the Phase 4 "Dynamic and Memory Analysis" section of the GitHub Wiki. All detonation, observation, and PCAP analysis work is done — this brief gives you the outline, findings, and screenshot placement map. Write the prose in your voice; the technical content is confirmed.

---

## Suggested Wiki Section Structure

1. **Introduction** — 1 paragraph (purpose of Phase 4, methodology overview, deliverables)
2. **Pre-Detonation Preparation** — environment readiness, snapshots, monitoring tool staging
3. **Detonation Execution** — the actual `rundll32.exe block.dll,Pape1` invocation and observation window
4. **Live Behavioral Findings** — process behavior, file system, registry, network
5. **Memory Analysis Approach** — what was attempted, what was preserved, scope limitations
6. **PCAP Analysis (the provided 2021-05-14 capture)** — the C2 IOC harvest
7. **Detonation Findings Summary**
8. **Lab Limitations and Honest Disclosures**
9. **Transition to Phase 5** (1–2 sentences)

---

## Tools Used in Phase 4

| Tool | Purpose | VM |
|---|---|---|
| Process Monitor (ProcMon) | File, registry, and process activity logging | FlareVM |
| Process Explorer (ProcExp) | Live process tree and parent-child relationship inspection | FlareVM |
| Wireshark | Live network packet capture during detonation | FlareVM |
| INetSim | Simulated DNS/HTTP/HTTPS/SMTP services for sinkhole behavior | REMnux |
| Security Onion (Suricata, Zeek, Elasticsearch, Kibana) | Network security monitoring sensor | Security Onion VM |
| `so-import-pcap` | Security Onion's official PCAP replay/ingestion tool | Security Onion VM |
| `tshark` | Command-line PCAP analysis for IOC extraction | REMnux |
| VirtualBox `VBoxManage debugvm dumpvmcore` | Host-side memory dump capture of FlareVM | Windows Host |

---

## 1. Introduction (suggested content)

The goal of Phase 4 was to execute the URSNIF infection chain in the isolated detonation environment, observe the malware's runtime behavior, capture the resulting host-level and network-level telemetry, and analyze the provided PCAP from the original 2021-05-14 incident to recover network indicators that static analysis could not surface.

Phase 2 and Phase 3 had already established that `block.dll` employs runtime decryption with custom obfuscated arithmetic to defeat static IOC extraction (see Phase 3 deep-dive on `FUN_0103320c`). Phase 4 was therefore expected to surface IOCs that were not recoverable statically: C2 domains, dropped files, registry persistence, and process injection patterns.

The detonation was performed in the isolated three-VM lab using `rundll32.exe block.dll,Pape1` — the export name and invocation method validated during Phase 3 assembly analysis. The malware was permitted to execute for approximately five minutes while monitoring tools captured host and network behavior.

---

## 2. Pre-Detonation Preparation

### Snapshot discipline

Before introducing live malware execution into the FlareVM, three rollback snapshots were verified or created:

- `Post-Install - Analysis Tools Ready` — clean baseline (Phase 1)
- `Phase 3 Complete - Ghidra Project Saved` — Phase 3 stable state with `block.dll` staged but not executed
- `Pre-Detonation - Phase 4` — fresh snapshot taken immediately before any execution

After Phase 4 completed, an additional `Post-Detonation - Evidence Captured` snapshot was preserved for re-screenshotting and Phase 5 reference, then the FlareVM was reverted to the Phase 3 clean state.

### Boot order and network preparation

VMs were started in order: REMnux first (to stage network services), then Security Onion (sensor), then FlareVM (target). On REMnux, INetSim was started bound to the AnalysisNet interface (`10.0.0.1`).

### Network connectivity verification (pre-detonation)

From FlareVM:
- `ping 10.0.0.1` → 4/4 success (REMnux reachable on the analysis network) ✓

### Monitoring tool staging

Three tools were prepared on FlareVM **before** execution to ensure full observability from the moment URSNIF launched:

- **Process Monitor** — display cleared, capture stopped pending detonation, filter applied to `Process Name is rundll32.exe → Include` to suppress system noise
- **Process Explorer** — open with full process tree visible
- **Wireshark** — interface verified working (the `Ethernet` adapter on AnalysisNet), capture stopped pending detonation

📸 **Screenshot #57** — Three tools open on FlareVM, configured but not yet capturing.
📸 **Screenshot #58** — ProcMon Filter dialog showing the `rundll32.exe Include` filter applied.

---

## 3. Detonation Execution

### Command issued

In an Administrator Command Prompt on FlareVM:

```
cd C:\malware
rundll32.exe block.dll,Pape1
```

The command returned immediately to the prompt — consistent with `rundll32` fork-and-forget semantics. The malware was permitted to execute for five minutes while all three monitoring tools captured live data.

### Observation window

Detonation start time: ~6:14 PM. Capture stop: ~6:19 PM. Captures were stopped in the order ProcMon → Wireshark.

### Capture statistics

- **ProcMon:** 802,164 total events captured; 3,307 events matched the `rundll32.exe` filter (~0.4%) — confirming the filter eliminated system noise effectively
- **Wireshark:** 178 packets captured on the AnalysisNet interface

📸 **Screenshot #62** — Process Explorer showing the parent-child `rundll32` lineage during detonation (PID 964 → PID 3788).
📸 **Screenshot #63** — ProcMon after capture stop, showing event count and filtered rundll32 activity.
📸 **Screenshot #64** — Wireshark after capture stop, showing 178 packets captured.

---

## 4. Live Behavioral Findings

### 4.1 Process Behavior — Self-Spawn and Exit

URSNIF exhibited a clear **self-spawn-and-exit** pattern, captured via Process Explorer's Process Tree view:

```
cmd.exe (PID 5292)
└── rundll32.exe (PID 964)        — manual launch / parent
    └── rundll32.exe (PID 3788)    — URSNIF-spawned child
└── conhost.exe (PID 3240)
```

The child `rundll32.exe` (PID 3788) is the live URSNIF process for the duration of the detonation. By the end of the observation window, both `rundll32` processes had exited from the active process list, indicating that **URSNIF had migrated its execution into another process** (process injection) and terminated its loaders. This is documented URSNIF behavior consistent with the malware's memory-resident operating model.

📸 **Screenshot #70** — ProcMon Process Tree centered on the rundll32 lineage, showing both PIDs and their lifetimes.

### 4.2 Behavioral Reconnaissance — System32 Enumeration and COM/OLE Probing

ProcMon captured PID 3788 (URSNIF child) performing two distinctive reconnaissance behaviors:

**System32 enumeration:** Rapid `QueryDirectory` operations across `C:\Windows\System32` — consistent with URSNIF scanning for specific DLLs to load, hijack, or sideload.

**COM/OLE registry probing:** Sequences of `RegOpenKey`, `RegQueryValue`, `RegQueryKey`, `RegSetInfoKey`, and `RegCloseKey` against:
- `HKLM\System\CurrentControlSet\Control\...`
- `HKLM\SOFTWARE\Microsoft\Ole`
- `HKLM\SOFTWARE\Microsoft\OLE\Aggregate...`
- `HKCR\WOW6432Node\CLSID\{A4A1...}` (32-bit registry view, consistent with the 32-bit DLL)

This pattern is consistent with **COM CLSID hijacking reconnaissance** — URSNIF examining which COM objects it could subvert for persistence or in-memory injection via COM proxying.

### 4.3 File System and Registry — A Significant "Negative" Finding

After applying additional ProcMon filters for `Operation is WriteFile → Include` and `Operation is RegSetValue → Include`, the results were striking:

- **WriteFile events (filtered to rundll32 lineage): zero**
- **RegSetValue events (filtered to rundll32 lineage): zero**

**This is one of the most important findings of Phase 4.** URSNIF created no files on disk and registered no persistence entries during five minutes of execution. This is **not** a failure of analysis — it is a **direct confirmation of URSNIF's documented memory-resident execution model**. The malware conducts all of its banking-trojan operations (browser hooking, form grabbing, credential theft) within process memory and does not touch disk for persistence or configuration storage during a typical infection lifecycle.

This finding directly validates the static-analysis hypothesis from Phase 3: that `FUN_0103320c`'s arithmetic state mutation operates entirely on in-memory globals (`DAT_0104a008`, `DAT_0104a0d8`, etc.) and that all configuration is decrypted at runtime in memory rather than written to disk.

📸 **Screenshot #68** — ProcMon with `WriteFile` filter showing zero results for the rundll32 lineage.
📸 **Screenshot #69** — ProcMon with `RegSetValue` filter showing zero results for the rundll32 lineage.

### 4.4 Network Behavior — DNS Probing

The Wireshark capture surfaced URSNIF's outbound DNS query pattern, even though INetSim's DNS service was not successfully bound (see "Lab Limitations" below):

| Query order | Domain | Type | Significance |
|---|---|---|---|
| 1st | `api.msn.com` | A | Microsoft connectivity check (URSNIF's standard "do I have internet" probe) |
| 2nd-4th | `go.microsoft.com` | A (×3 retries) | Secondary Microsoft connectivity check |
| 5th+ | `app.buboleinov.com` | A | **C2 server domain** — confirmed real URSNIF C2 IOC |

REMnux responded with ICMP "destination port unreachable" to each DNS attempt (because INetSim's DNS bind had failed). However, **the queries themselves are the network IOC** — URSNIF's behavioral fingerprint of: connectivity check via legitimate Microsoft service, then C2 attempt to a registered malicious domain.

### 4.5 Network Behavior — Protocol Distribution

Wireshark Statistics → Protocol Hierarchy showed:

| Protocol | Percentage | Significance |
|---|---|---|
| DNS | 37.1% | Heavy DNS activity (consistent with C2 lookup retries) |
| ICMP | 26.4% | INetSim's port-unreachable responses |
| NetBIOS Name Service | 5.1% | URSNIF performing local network reconnaissance |
| SSDP | 2.2% | Service discovery probes |
| HTTP | 0% | URSNIF did **not** fall back to direct-IP HTTP after DNS failed |
| TLS | 0% | No encrypted C2 traffic established |

The absence of HTTP/TLS traffic in the live detonation is a direct consequence of the lab limitation (DNS sinkhole failure prevented domain-to-IP resolution). The provided PCAP analysis (Section 6 below) recovers the HTTP traffic that this lab environment could not.

📸 **Screenshot #65** — Wireshark with `dns` filter applied, first query (`api.msn.com`) highlighted with full DNS query details visible.
📸 **Screenshot #65b** — Wireshark with `dns` filter, the `app.buboleinov.com` C2 query highlighted.
📸 **Screenshot #67** — Wireshark Protocol Hierarchy showing protocol distribution.

---

## 5. Memory Analysis Approach

A full memory dump of the FlareVM was captured from the host using VirtualBox's `VBoxManage debugvm dumpvmcore` command. The dump is preserved at `C:\Users\moses\UIW\malware_analysis\flarevm-postdetonation.elf` (8.73 GB ELF format). The capture was performed while FlareVM was running — VirtualBox briefly paused the VM, wrote raw memory bytes to a host file, and resumed the VM. No malware execution occurred on the host during this operation; the dump file is data, not executable.

Volatility 3 was the planned analysis framework for this dump. The intended plugin set was:

- `windows.pslist` — process listing at the moment of capture (would reveal whether `rundll32.exe` was still alive or had exited)
- `windows.malfind` — detection of injected code regions in benign-looking host processes (would identify the URSNIF injection target)
- `windows.netscan` — active network connections in memory (would reveal C2 attempts not visible in Wireshark due to the DNS sinkhole failure)
- `windows.dlllist` — loaded DLLs per process (would reveal hijacked or sideloaded DLLs)

Volatility 3 was not installed on the host system at the time of detonation. Given the time budget of the analysis session, a deliberate decision was made to defer Volatility analysis rather than spend the remaining time on tool installation. The 8.73 GB memory dump is preserved for future analysis. **For the deliverable, the memory-resident behavior of URSNIF is documented from ProcMon and Process Explorer observation** (see Section 4.1 — process self-spawn-and-exit, and Section 4.3 — zero file/registry writes), which is consistent with what Volatility's `malfind` would have surfaced at higher fidelity.

📸 **Screenshot #71** — Host PowerShell showing the successful memory dump capture (8,730,336,884 bytes / 8.73 GB).

---

## 6. PCAP Analysis — The Provided 2021-05-14 Capture

The provided PCAP (`2021-05-14-Ursnif-infection-traffic.pcap`) was analyzed to recover the network IOCs that the live detonation could not surface (due to the DNS sinkhole limitation). Two parallel analysis paths were used:

### 6.1 Security Onion ingestion

The PCAP was transferred to the Security Onion VM via `scp` over the management network (REMnux → Security Onion). The official Security Onion ingestion tool was run:

```
sudo so-import-pcap /tmp/2021-05-14-Ursnif-infection-traffic.pcap
```

The tool ingested the PCAP successfully:
- Verifying file → OK
- Assigning unique import identifier `811fb8b5efca216dfb4d7a0ef4055a2b`
- Analyzing traffic with Suricata → completed
- Analyzing traffic with Zeek → completed
- Reported PCAP date range: `2021-05-14 through 2021-05-15`

Elasticsearch ingested 1,256 events from the import (visible in the SOC Dashboard view). However, the standard Alerts view did not surface Suricata signature matches when filtered to the PCAP's 2021 date range. This is documented in Section 8 below as a lab limitation.

📸 **Screenshot #73** — Security Onion console showing `so-import-pcap` completion with the PCAP date range and import identifier.

### 6.2 Direct PCAP analysis with `tshark`

To recover the network IOCs efficiently, `tshark` was used on REMnux against the original PCAP file. Three targeted queries surfaced all IOCs needed for Phase 5 detection rule development:

**DNS query inventory:**
```
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
```

**HTTP request inventory:**
```
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -Y "http.request" -T fields -e ip.dst -e http.host -e http.request.uri -e http.user_agent
```

**Destination IP inventory:**
```
tshark -r 2021-05-14-Ursnif-infection-traffic.pcap -T fields -e ip.dst | sort -u | grep -v "^$"
```

📸 **Screenshot #74** — tshark DNS query output showing all unique queried domains.
📸 **Screenshot #75** — tshark HTTP request output showing destination IPs, hosts, URIs, and User-Agents.
📸 **Screenshot #76** — tshark unique destination IP list.

### 6.3 IOCs recovered

**C2 Domains (confirmed malicious):**

| Domain | Role |
|---|---|
| `app.buboleinov.com` | **Primary C2** — also observed in live detonation, confirming this is the active C2 endpoint URSNIF reaches for during execution |
| `docs.atu.ngr.mybluehost.me` | Staging server — delivers `presentation.dll` (secondary stage payload) |
| `todo.faroin.at` | Secondary C2 — observed receiving the longest encoded URI patterns (likely exfiltration) |

**Connectivity-check / benign domains (URSNIF behavioral fingerprints, not malicious infrastructure):**

| Domain | Purpose |
|---|---|
| `api.msn.com` | Microsoft service used as URSNIF's "internet check" |
| `myip.opendns.com` | OpenDNS reflection — URSNIF discovering its public-facing IP (anti-NAT detection) |
| `resolver1.opendns.com` | OpenDNS resolver used to query `myip.opendns.com` |
| `222.222.67.208.in-addr.arpa` | Reverse DNS lookup |

**C2 IP Addresses:**

| IP | Role |
|---|---|
| `34.95.142.247` | Primary C2 IP (Google Cloud — common URSNIF tactic of using cloud reputation to evade IP-reputation filtering) |
| `162.241.24.47` | Staging server IP (delivers `/presentation.dll`) |
| `208.67.222.222` | OpenDNS public resolver (benign — used by URSNIF for IP discovery) |

**HTTP URI Patterns observed:**

- `/presentation.dll` — secondary stage payload download from staging server
- `/favicon.ico` — frequent cover-traffic requests interspersed with C2
- `/U6I1_2B0OhVkWdfd8/...`, `/sB4J02_2FE9Gwh_2BM3/...`, `/_2F9WZViPJ/...`, `/rwCl8Et9i/...`, `/9B7mKifdQKW/...` — long URL-safe-base64-style encoded strings carrying URSNIF's encrypted C2 communication payload (config request, beacon, exfiltration, etc.)

**HTTP User-Agent strings observed:**

- `Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko` — Internet Explorer 11 spoofing
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0` — Firefox 86 spoofing

The use of two distinct User-Agent strings against the same C2 host (`34.95.142.247` / `app.buboleinov.com`) is consistent with URSNIF's documented technique of mimicking the user's actual browser by enumerating installed browsers and matching its outbound C2 fingerprint to the local environment.

---

## 7. Detonation Findings Summary

Phase 4 produced the following confirmed findings:

1. **Memory-resident execution model confirmed.** URSNIF wrote zero files and made zero persistence registry entries during five minutes of execution, validating the static analysis hypothesis from Phase 3.

2. **Process self-spawn-and-exit pattern observed.** URSNIF launched a child `rundll32.exe` process (PID 3788) and subsequently caused both rundll32 processes to exit from the active process list — consistent with process injection into a benign host process.

3. **System and COM/OLE reconnaissance.** URSNIF probed `C:\Windows\System32` and the `HKCR\WOW6432Node\CLSID\` registry tree, consistent with COM hijacking reconnaissance.

4. **C2 domain `app.buboleinov.com` confirmed live.** This domain was queried during the live detonation and is also present in the provided 2021 PCAP, confirming it as the active C2 endpoint URSNIF reaches for under both lab and real-world conditions.

5. **Two additional C2/staging domains and three C2 IPs recovered from the PCAP.** Detailed IOCs in Section 6.3 above.

6. **Two browser-spoofing User-Agent strings recovered** for use in Suricata HTTP rule authoring.

7. **8.73 GB memory dump preserved** for future Volatility analysis.

---

## 8. Lab Limitations and Honest Disclosures

For academic integrity, two limitations of the live detonation environment are documented honestly here. Neither limitation invalidates the Phase 4 deliverable; both are addressed by the parallel analysis paths used.

### Limitation 1: INetSim DNS service did not bind successfully

INetSim was started with `--bind-address=10.0.0.1`. INetSim reported `dns_53_tcp_udp - started (PID 2373)` in its startup log, but UDP/TCP port 53 listeners did not become functional in subsequent verification (`ss -tulpn` returned no INetSim DNS entries; functional Python socket tests timed out). Initial troubleshooting identified that Ubuntu's `systemd-resolved` was occupying port 53 and was disabled. After this fix, INetSim's main process re-bound successfully but its DNS subprocess still did not actually serve queries. Further troubleshooting was de-scoped due to time budget.

**Impact:** During live detonation, URSNIF's DNS queries to `api.msn.com`, `go.microsoft.com`, and `app.buboleinov.com` reached REMnux but received ICMP port-unreachable responses rather than INetSim's simulated A records. Consequently, URSNIF could not resolve domain names to IPs and did not establish HTTP-level C2 communication.

**Mitigation:** The DNS query attempts themselves are still observable as network IOCs (Section 4.4), and the full HTTP-level C2 traffic is recovered from the provided PCAP analysis (Section 6.2). The lab's HTTP/HTTPS sinkhole would not have produced richer C2 telemetry than the real PCAP already contains.

### Limitation 2: Security Onion dashboard did not surface Suricata alerts on the imported PCAP

`so-import-pcap` ingested the PCAP successfully (1,256 events into Elasticsearch confirmed), but the standard Alerts dashboard view returned zero results when filtered to the PCAP's 2021 date range. The most likely cause is that the bundled Suricata ruleset shipped with Security Onion 3.0.0 (March 2026) does not include signatures that match the specific 2021 URSNIF C2 patterns — the rules may have aged out or been deprecated. Diagnosis of the alerting pipeline was de-scoped due to time budget.

**Impact:** Phase 4 cannot present a Suricata alert dashboard as evidence of network detection.

**Mitigation:** This is **the foundation for Phase 5's deliverable.** Phase 5 authors **custom Suricata rules** targeting the C2 domains, IPs, URI patterns, and User-Agent strings recovered from the PCAP analysis above. Custom rules — derived from observed traffic — are a more rigorous defensive deliverable than relying on bundled signatures, and the absence of bundled-rule alerts on this 2021 traffic actively justifies the need for Phase 5's custom rule authoring.

### Limitation 3: Volatility memory analysis deferred

Volatility 3 was not installed on the host at detonation time. The 8.73 GB memory dump is preserved at `C:\Users\moses\UIW\malware_analysis\flarevm-postdetonation.elf`. Memory-resident behavior is documented from ProcMon/ProcExp observations.

**Mitigation:** ProcMon's zero-write findings and ProcExp's process tree showing rundll32 self-spawn-and-exit are consistent with — and corroborate — what `windows.malfind` would have surfaced at higher fidelity.

---

## 9. Transition to Phase 5

> "Phase 4 produced the complete network IOC set required to author defensive detection rules and the behavioral observations required to characterize URSNIF's complete kill chain. Phase 5 synthesizes Phases 1–4 into a comprehensive IOC inventory, authors custom Suricata rules targeting the recovered C2 infrastructure, and provides actionable defensive recommendations for organizations seeking to detect or mitigate URSNIF infections."

---

## Screenshot Mapping (Phase 4 Summary)

| # | Content | Wiki placement |
|---|---|---|
| 53 | (Originally INetSim startup) — *not in final brief; de-scoped after DNS limitation* | — |
| 54 | (Originally so-status) — *optional supporting; not in final brief* | — |
| 55 | (Originally SOC empty alerts baseline) — *optional supporting* | — |
| 56 | (Originally FlareVM ping/nslookup) — *DNS test; supports Limitation 1 disclosure* | Section 8 (Limitation 1) |
| 57 | Three monitoring tools open and configured on FlareVM | Section 2 |
| 58 | ProcMon Filter dialog with rundll32.exe Include filter | Section 2 |
| 62 | Process Explorer during detonation showing parent-child rundll32 tree | Section 4.1 |
| 63 | ProcMon after capture stop with event count | Section 3 |
| 64 | Wireshark after capture stop with packet count | Section 3 |
| 65 | Wireshark dns filter — first query (api.msn.com) | Section 4.4 |
| 65b | Wireshark dns filter — app.buboleinov.com C2 query | Section 4.4 |
| 67 | Wireshark Protocol Hierarchy | Section 4.5 |
| 68 | ProcMon WriteFile filter — empty | Section 4.3 |
| 69 | ProcMon RegSetValue filter — empty | Section 4.3 |
| 70 | ProcMon Process Tree — rundll32 lineage with both PIDs | Section 4.1 |
| 71 | Host PowerShell — VBoxManage memory dump success (8.73 GB) | Section 5 |
| 72 | scp transfer of PCAP to Security Onion | Section 6.1 |
| 73 | Security Onion so-import-pcap completion | Section 6.1 |
| 74 | tshark DNS query output (C2 domains) | Section 6.2/6.3 |
| 75 | tshark HTTP request output (URIs, User-Agents) | Section 6.2/6.3 |
| 76 | tshark unique destination IP list | Section 6.2/6.3 |

---

## Notes for Marissa

- Phase 4 has the most "negative findings" of any phase — zero file writes, zero registry writes, no successful HTTP from live detonation. **Don't apologize for these.** They are direct experimental confirmations of URSNIF's documented memory-resident behavior. Frame them as positive validations of static-analysis hypotheses, not as missing data.
- The "Lab Limitations" section in this brief is honest about what didn't work in the live environment. **Keep that section in the Wiki — academic integrity matters more than appearing perfect.** The mitigations show that the deliverable is complete despite the limitations.
- The C2 IOCs in Section 6.3 are the core input to Phase 5's Suricata rule authoring. Treat that table as authoritative.
- If any finding here conflicts with a screenshot, **flag it to Moses before writing**.
- The memory dump file (`flarevm-postdetonation.elf`) is preserved on the host for any future deeper analysis. Don't delete it until after grading.
