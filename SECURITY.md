# Security Policy

This repository documents an academic malware analysis project conducted as coursework for **CSEC 4300 — Malware Analysis** at the University of the Incarnate Word. The subject of analysis is the **URSNIF (Gozi / ISFB)** banking trojan, using a publicly available sample set from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) dated 2021-05-14.

Because this project handles live malware artifacts, this policy defines the strict boundaries that govern what is stored in the repository, how the analysis environment is operated, how sensitive material is handled, and how security incidents (real or suspected) are escalated. All contributors and any future readers of this repository are expected to understand and adhere to this policy.

---

## 1. Scope and Authorized Use

This repository is licensed under the [MIT License](LICENSE) and is intended **strictly for academic and educational use** within the context of CSEC 4300 coursework and the related research it builds upon (CIS 3370 Intrusion Detection Systems and CIS 3345 Digital Forensics).

The contents of this repository — including documented IOCs, detection signatures, methodology, and analytical writeups — are **not authorized** for use in any of the following:

- Live operational defense outside of the documented academic context without independent validation
- Any offensive security activity, malware development, or unauthorized system access
- Detonation of URSNIF samples or any other malware outside of a documented, fully isolated analysis environment that meets or exceeds the controls described in Section 4 of this policy

Use of this material outside the scope above is the responsibility of the user and is not endorsed or supported by the project authors.

---

## 2. Repository Content Policy

### 2.1 What this repository **never** contains

The following content categories are explicitly prohibited from this repository under any circumstance, including in branches, draft commits, deleted history, or any other location reachable via Git:

- **Live malware binaries** in any format — including but not limited to `.exe`, `.dll`, `.xlsb`, `.eml` of malicious origin, JavaScript droppers, packed executables, or any portable executable derived from URSNIF or any related family
- **Compressed, encoded, or transformed malware** — including `.zip`, `.7z`, `.tar.gz` archives containing samples, base64-encoded binaries, hex dumps representing complete executable code, or any other reversible representation of a malicious binary
- **Memory dumps** that contain executable malware regions (`.elf`, `.raw`, `.dmp`, `.vmem` files captured during or after detonation)
- **VirtualBox virtual disk and machine state files** (`.vdi`, `.vmdk`, `.vbox`, `.sav`, snapshot files) for any VM that has been used to handle malware
- **Lab credentials** of any kind — Windows account passwords, Security Onion SOC credentials, REMnux user passwords, SSH keys, API tokens, or any secret derived from the lab environment
- **Personal or institutional network identifiers** — home router IP addresses, ISP-assigned IPs, MAC addresses of personal devices, the host machine's LAN configuration, or any data that could fingerprint the analyst's home or campus network
- **Personally identifiable information** of any party named or referenced in the malware artifacts (e.g., the original recipients of the phishing email)

### 2.2 What this repository **does** contain

The following content categories are permitted and constitute the deliverables of the project:

- Wiki and Markdown documentation of the analysis methodology and findings
- File hashes (MD5, SHA-256) of the URSNIF sample set artifacts
- Indicator-of-compromise (IOC) inventories (see Section 5 for handling rules)
- Custom YARA rules targeting URSNIF file-level indicators (`rules/yara/`)
- Custom Suricata rules targeting URSNIF network-level indicators (`rules/suricata/`)
- Disassembly excerpts presented as text — short, annotated, non-reconstructable code regions illustrating analytical findings
- Screenshots of analysis tools in use, with sensitive content redacted (see Section 6)
- PCAP-derived analytical output (e.g., `tshark` output tables) that does not include the raw PCAP file itself
- Methodology, lab-setup, and tool-reference documentation

### 2.3 Verification before commit

Before every commit, contributors must verify:

1. No file in the staged change set is a malware binary or a transformation thereof
2. No file contains credentials, secrets, or personal network identifiers
3. Screenshots have been reviewed for incidental disclosure (taskbar usernames, hostnames, file paths revealing the contributor's full identity, etc.)
4. The `.gitignore` is current and excludes `lab-credentials.txt`, `*.vdi`, `*.elf`, `*.raw`, `*.zip` containing samples, and any other prohibited file types

A `git status` and `git diff --staged` review is required before every commit involving new content. When in doubt, do not commit.

---

## 3. Sample Handling and Chain of Custody

### 3.1 Sample sourcing

The URSNIF sample set is obtained from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net), a public research repository that distributes malware samples in password-protected ZIP archives for research and educational purposes. The specific exercise used by this project is dated **2021-05-14** and is sourced under the standard password scheme published on the malware-traffic-analysis.net "about" page.

### 3.2 Acquisition and transfer

The sample ZIP is downloaded directly to the host machine and immediately transferred into the isolated analysis environment via a read-only ISO mount. Samples are **never** extracted or unpacked on the host system outside of the isolated VMs. The ISO transfer method was chosen specifically to eliminate bidirectional file paths between host and guest VMs (no shared folders, no SCP, no clipboard).

### 3.3 Storage location

Samples reside exclusively within the analysis VMs:

- `block.dll`, `.xlsb`, `.eml`, `.pcap` — REMnux at `/home/remnux/ursnif-samples/`
- `block.dll` (when staged for dynamic analysis) — FlareVM at `C:\malware\`, on a snapshot that is reverted after each detonation

Samples are **never** copied to the host filesystem and **never** committed to this repository.

### 3.4 Chain of custody documentation

For each sample artifact, the following is recorded in the Wiki:

- Source URL and date of download
- ZIP archive password
- MD5 and SHA-256 hashes (verified independently inside REMnux)
- Date and method of transfer into the analysis environment
- Location at which the sample resides during analysis

---

## 4. Lab Environment Security Controls

The following controls are enforced continuously throughout the analysis lifecycle. They are documented in detail in the Phase 1 Wiki section and are summarized here as the security baseline this project depends on.

### 4.1 Network isolation

| Network | Type | Subnet | Purpose |
|---|---|---|---|
| Management | VirtualBox Host-Only | 192.168.56.0/24 | Administrative access to Security Onion and REMnux. **No malware traffic.** |
| AnalysisNet | VirtualBox Internal | 10.0.0.0/24 | All detonation traffic. **Fully isolated from host LAN and internet.** |

The detonation VM has **a single network adapter**, attached to the Internal Network only. There is no route from the detonation VM to the public internet, the host machine, or the host's local network.

### 4.2 Isolation controls (all VMs)

- No bridged or NAT network adapters
- No VirtualBox shared folders
- No bidirectional clipboard
- No drag-and-drop
- No USB passthrough on the detonation VM
- Promiscuous mode is enabled only on the Security Onion monitor interface

### 4.3 Network isolation validation

Before any malware is introduced into the detonation environment, the following negative tests must all return failure (no connectivity), and the result must be documented:

- `ping 8.8.8.8` from the detonation VM — must fail (no internet)
- `ping <home router>` from the detonation VM — must fail (no host LAN)
- `ping <host machine>` from the detonation VM — must fail (no host access)
- `nslookup <public domain>` from the detonation VM via any external DNS server — must fail

The following positive test must succeed:

- `ping <REMnux analysis IP>` from the detonation VM — must succeed (AnalysisNet connectivity confirmed)

### 4.4 Snapshot discipline

- The detonation VM is reverted to a clean baseline snapshot after every analysis run involving live execution
- Multiple recovery snapshots are maintained (clean baseline, post-tool-install, pre-detonation)
- A post-detonation snapshot may be retained temporarily for re-screenshotting, but is destroyed after the relevant Wiki section is finalized

### 4.5 Tool verification

Every tool deployed in the analysis environment was verified before installation. Verification methods used in this project include:

- SHA-256 hash comparison against vendor-published values
- Microsoft Authenticode signature validation
- PGP / GPG signature validation (where available, e.g., Wireshark)
- VirusTotal cross-reference for unsigned or low-reputation tools, with documented justification for any detection ratio above 0/N

The full tool verification audit trail is maintained in `hashes.txt` on the host (not committed). A summary table is included in the Phase 1 Wiki documentation.

---

## 5. Indicator-of-Compromise (IOC) Handling

### 5.1 IOCs in this repository

This repository contains real C2 domains, IP addresses, URI patterns, and User-Agent strings observed in the URSNIF 2021-05-14 sample. The primary IOC sources are:

- `reports/ursnif-2021-05-14/iocs.json` — structured authoritative IOC inventory
- `rules/yara/*.yar` — YARA rules referencing file-level indicators
- `rules/suricata/custom.rules` — Suricata rules referencing network-level indicators
- The Phase 5 Wiki section — human-readable IOC tables

### 5.2 Defanging requirements

While this repository remains private and access is restricted to the analysis team and the course instructor, IOCs may be stored in their original (live) form to preserve the operational utility of the YARA and Suricata rules.

**If at any point this repository is made public**, all IOCs in human-readable documentation (the Wiki, Markdown reports, and `iocs.json`) must be defanged before the public release. Defanging conventions:

- Domains: `app[.]buboleinov[.]com` (brackets around dots)
- IPs: `34[.]95[.]142[.]247`
- URLs: `hxxp://` instead of `http://`
- File hashes do not require defanging

YARA and Suricata rules are functional artifacts and may retain the live indicators; rule files are intended for defensive deployment, not casual reading.

### 5.3 Reuse caution

The IOCs in this repository describe a 2021-era URSNIF infection. C2 infrastructure may since have been seized, sinkholed, or repurposed. Defenders integrating these IOCs into production should validate currency before relying on them.

---

## 6. Screenshot and Evidence Handling

Screenshots committed to `evidence/screenshots/` are reviewed before commit for the following:

- No taskbar entries, window titles, or browser tabs reveal personal identity beyond what is already disclosed in the project's authorship
- No file paths reveal the full home directory of the contributor's host machine if not already documented
- No credentials, password fields, or session tokens are visible
- No personal network identifiers are visible in `ipconfig`, `ip a`, or similar tool output

Where redaction is required, screenshots are edited prior to commit (not after) to ensure no sensitive content is preserved in repository history.

---

## 7. Reporting Security Concerns

If a security concern relating to this repository is identified — including but not limited to the accidental commit of prohibited content, suspected isolation breach, or discovery of a flaw in the documented analysis methodology — report it via one of the following channels:

- Open a private GitHub issue tagged `safety` if the concern is non-sensitive and benefits from team-visible discussion
- Contact the project authors directly:
  - Moses Chavez — @mwchavez
  - Marissa Turner — @marilturner
- For concerns that escalate beyond the team, contact the course instructor

Do not disclose the concern publicly or in any other channel before the team has had a reasonable opportunity to respond.

---

## 8. Incident Response

### 8.1 Accidental commit of prohibited content

If a malware binary, credential, or other prohibited content is accidentally committed:

1. **Stop further commits to the repository immediately.**
2. Do not push if the commit has not yet been pushed. Use `git reset` to remove the commit locally.
3. If the commit has been pushed, rewrite history with `git filter-repo` or `git filter-branch` to permanently remove the file, then force-push.
4. Rotate any credentials that may have been exposed.
5. If a malware binary was committed, treat the repository as compromised: clone a clean copy from the most recent known-good commit, verify it, and (if necessary) re-create the repository from that clean copy. The original repository should be deleted by an administrator.
6. Document the incident, root cause, and remediation steps in a private incident note, and inform the course instructor.

### 8.2 Suspected isolation breach

If at any point during analysis there is reason to believe the detonation VM has reached the public internet or the host LAN:

1. **Power off the detonation VM immediately** (hard power-off via VirtualBox, not a graceful shutdown).
2. Power off REMnux and Security Onion as a precaution.
3. Disconnect the host machine from the internet.
4. Audit the host for indicators of infection using a separate, trusted system if possible.
5. Revert all VMs to clean baseline snapshots.
6. Re-execute the network isolation validation tests in Section 4.3 from a clean state.
7. Do not resume analysis until the cause of the suspected breach has been identified and remediated.
8. Document the incident in the Wiki under a "Security Incidents" section, regardless of whether the breach is ultimately confirmed.

### 8.3 Suspected host infection

If the host machine itself shows signs of malware infection:

1. Disconnect from the internet.
2. Do not power on any VMs.
3. Do not interact with the repository from the host until the host has been verified clean by an independent system or rebuilt from known-good media.
4. Notify the course instructor.

---

## 9. Repository Access Control

- This repository is **private** for the duration of the course and the academic record retention period that follows.
- Access is restricted to the project team members (Moses Chavez, Marissa Turner) and the course instructor.
- No third parties, including other students, should be granted read or write access without written approval from the course instructor.
- Branch protection on `main` should be enabled to require pull request review before merge once the team grows beyond the two authors, or if any external collaborator is added.
- Force-pushes to `main` are permitted only in the context of incident response (Section 8.1).

---

## 10. End-of-Course Archival

At the conclusion of the course, the following archival steps will be performed:

1. The repository will be archived (read-only) on GitHub once the course grade is final.
2. The host-side analysis environment will be wound down:
   - All malware samples deleted from REMnux and FlareVM
   - The 8.73 GB FlareVM memory dump (`flarevm-postdetonation.elf`) deleted from the host
   - Samples ISO and tools ISO deleted from the host
   - VMs either destroyed or exported to encrypted offline storage for academic record-keeping
3. The `hashes.txt`, `lab-credentials.txt`, and any other host-side artifacts excluded from the repository will be retained on the host until the academic record retention period concludes, then securely deleted.
4. If the repository is to be made public after archival, the defanging process described in Section 5.2 must be completed before public release.

---

## 11. Authority and Revisions

This security policy is authored by the project team and is binding for the duration of the project. Revisions are tracked through the repository's commit history. Substantive revisions affecting safety controls, sample handling, or incident response procedures require agreement from both project authors and notification to the course instructor.

| Version | Date | Author | Summary |
|---|---|---|---|
| 1.0 | 2026-04-28 | Moses Chavez | Initial security policy |

---

*This policy reflects the security posture established in the project's Wiki Phase 1 documentation and is consistent with the safety controls documented throughout the analysis lifecycle. Discrepancies between this policy and other project documentation should be reported as a security concern (Section 7) and reconciled in favor of the more restrictive control.*
