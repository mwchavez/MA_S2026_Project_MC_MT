# Malware Analysis Lab: Network-Based Detection and Behavioral Analysis

## Overview

This project presents a virtualized malware analysis laboratory built on Security Onion, integrating network intrusion detection with dynamic and static malware analysis techniques. The lab environment enables controlled detonation of malware samples, captures resulting network telemetry via Suricata and Zeek, and correlates observed behaviors with binary-level indicators to produce actionable detection signatures and structured intelligence reports.

## Background

This work extends a prior project conducted for coursework in Intrusion Detection Systems and Digital Forensics, which focused on deploying a Security Onion sensor, capturing baseline network traffic, and authoring custom Suricata rules. The current iteration expands the scope into malware analysis by introducing a sandboxed detonation environment, simulated internet services, YARA-based file detection, and a structured analytical methodology grounded in the kill chain and diamond models.

## Lab Architecture

The lab consists of four virtual machines operating across two isolated network segments:

| VM | Role | Network |
|---|---|---|
| **Security Onion** | Network sensor (Suricata IDS, Zeek NSM, Elasticsearch/Kibana) | Management + Analysis (monitor) |
| **Analyst Workstation** | Web UI access, rule authoring, report generation | Management |
| **Malware Detonation VM** | Sample execution environment (REMnux / FlareVM) | Isolated Analysis |
| **INetSim / FakeNet** | Simulated internet services (DNS, HTTP, SMTP) | Isolated Analysis |

The **management network** (host-only) provides administrative access to Security Onion's web interface without exposing it to malware traffic. The **isolated analysis network** carries all detonation traffic, with Security Onion monitoring via a span interface. No traffic from the analysis network reaches the public internet.

## Analysis Methodology

Each malware sample undergoes a structured analysis pipeline:

1. **Triage** — Initial classification, source documentation, and snapshot of the detonation VM.
2. **Static Analysis** — Extraction of strings, PE headers, import tables, and section entropy. YARA rule matching against known signatures.
3. **Dynamic Analysis** — Controlled execution within the detonation VM. Network behavior captured by Security Onion; host-level artifacts observed in real time.
4. **Detection Engineering** — Development of custom Suricata rules targeting observed network indicators and YARA rules targeting file-level indicators.
5. **Reporting** — Production of a structured report per sample, including kill chain mapping, diamond model attribution, indicators of compromise (IOCs), and detection rule documentation.

## Repository Structure

```
├── docs/                        # Wiki and reference documentation
│   ├── lab-setup-guide.md       # Full environment build instructions
│   ├── tool-reference.md        # Tool configurations and usage notes
│   └── analysis-methodology.md  # Analytical framework documentation
│
├── rules/                       # Detection signatures
│   ├── suricata/                # Custom Suricata rules
│   │   └── custom.rules
│   └── yara/                    # YARA rules organized by family and indicator type
│       ├── malware_families/
│       └── indicators/
│
├── reports/                     # Per-sample analysis reports
│   └── sample-001/
│       ├── static-analysis.md
│       ├── dynamic-analysis.md
│       ├── kill-chain.md
│       └── iocs.json
│
├── runbooks/                    # Reusable threat hunting procedures
│   ├── traffic-analysis.md
│   ├── c2-detection.md
│   └── lateral-movement.md
│
├── README.md
└── LICENSE
```

## Malware Samples

Samples are sourced from public repositories intended for research and educational use. Candidate families and sample types under consideration include, but are not limited to:

- **Commodity RATs** — Remote access trojans with well-documented C2 protocols.
- **Banking trojans** — Samples exhibiting DNS manipulation and credential exfiltration behavior.
- **Ransomware (defanged/older variants)** — For file-system behavioral analysis and network beacon detection.

All samples are handled exclusively within the isolated analysis environment. No live malware is stored in this repository. Sample hashes and sourcing metadata are documented in each corresponding report directory.

> **Note:** Final sample selection is in progress and will be reflected in the `reports/` directory as analysis is completed.

## Tools and Technologies

- **Security Onion** — Network security monitoring platform (Suricata, Zeek, Elasticsearch, Kibana)
- **Suricata** — Signature-based intrusion detection and network traffic analysis
- **Zeek** — Network metadata generation and protocol logging
- **YARA** — Pattern matching for file-level malware identification
- **REMnux / FlareVM** — Linux and Windows-based malware analysis distributions
- **INetSim / FakeNet-NG** — Simulated internet services for dynamic analysis

## Authors

- **[Your Name]** — [GitHub handle or institutional affiliation]
- **[Partner Name]** — [GitHub handle or institutional affiliation]

## Acknowledgments

This project was developed as coursework for [Course Name: Malware Analysis], building upon prior work completed for Intrusion Detection Systems and Digital Forensics at [Institution].

## License

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for details.
