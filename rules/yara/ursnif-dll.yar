/*
    URSNIF (Gozi/ISFB) DLL Payload Detection
    Sample:  block.dll
    Source:  malware-traffic-analysis.net — 2021-05-14 exercise

    Authors: Moses Chavez (@mwchavez), Marissa Turner (@marilturner)
    Course:  CSEC 4300 Malware Analysis
    School:  University of the Incarnate Word
    Date:    April 2026

    Reference:
        https://www.malware-traffic-analysis.net/2021/05/14/index.html

    Basis for detection:
        Static analysis of block.dll on REMnux using rabin2, strings, and
        capa produced several distinctive static indicators, including an
        embedded PDB path with a random-word directory structure, two
        non-standard export names, an internal project filename, and a
        unique PE debug GUID. These indicators, individually or in
        combination, identify this specific URSNIF build with high
        confidence.
*/

import "pe"

rule URSNIF_block_dll_2021_05_14
{
    meta:
        description = "URSNIF (Gozi/ISFB) DLL payload from 2021-05-14 campaign"
        author      = "Moses Chavez, Marissa Turner"
        date        = "2026-04-24"
        reference   = "https://www.malware-traffic-analysis.net/2021/05/14/index.html"
        malware     = "URSNIF / Gozi / ISFB"
        family      = "banking trojan"
        severity    = "critical"
        md5         = "5a7c87dab250cee78ce63ac34117012b"
        sha256      = "8a26c32848c9ea085505359f67927d1a744ec07303ed0013e592eca6b4df4790"

    strings:
        // Embedded PDB path — random-word directory structure characteristic
        // of URSNIF's automated build pipeline. Backslashes escaped per YARA.
        $pdb = "Whether\\class\\156\\Through\\How.pdb" ascii nocase

        // Internal project filename — visible in exports metadata and resources
        $internal_name = "How.dll" ascii

        // Campaign-specific non-standard DLL exports. The combination of
        // these two names is highly distinctive; standard URSNIF samples
        // typically export DllRegisterServer or similar.
        $export_pape1     = "Pape1" ascii
        $export_riverslow = "Riverslow" ascii

        // PE debug directory GUID — a unique fingerprint for this build
        $debug_guid = { C7 3B 28 13 00 56 41 1D 84 ED 71 89 96 F2 19 E0 }

    condition:
        // Must be a PE file
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            // Definitive: exact PDB path match
            $pdb or

            // Strong: both distinctive exports present together
            ($export_pape1 and $export_riverslow) or

            // Strong: PE debug GUID match
            $debug_guid or

            // Moderate: internal filename plus at least one distinctive export
            ($internal_name and ($export_pape1 or $export_riverslow))
        )
}


rule URSNIF_heuristic_section_unpacking
{
    meta:
        description = "Heuristic: PE with section vsize expansion characteristic of packed or encrypted payloads (observed in URSNIF block.dll — .data vsize 0x108000 vs raw 0x1000)"
        author      = "Moses Chavez, Marissa Turner"
        date        = "2026-04-24"
        severity    = "medium"
        note        = "Heuristic — may produce false positives on legitimate packed/compressed software. Use as a triage indicator, not a definitive match."

    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        pe.number_of_sections >= 3 and
        for any i in (0 .. pe.number_of_sections - 1) : (
            // Virtual size 16x or more larger than raw size suggests
            // a runtime unpacking/decryption buffer.
            pe.sections[i].virtual_size > (pe.sections[i].raw_data_size * 16) and
            pe.sections[i].raw_data_size > 0
        )
}
