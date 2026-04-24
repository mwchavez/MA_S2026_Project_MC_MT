/*
    URSNIF XLSB Dropper Detection
    Sample:  I8m7XluZbbj10J53.xlsb
    Source:  malware-traffic-analysis.net — 2021-05-14 exercise

    Authors: Moses Chavez (@mwchavez), Marissa Turner (@marilturner)
    Course:  CSEC 4300 Malware Analysis
    School:  University of the Incarnate Word
    Date:    April 2026

    Reference:
        https://www.malware-traffic-analysis.net/2021/05/14/index.html

    Revision history:
        2026-04-24  Initial draft.
        2026-04-24  Verification pass on REMnux showed the raw-file rule
                    did not match because the "sheet.binary.macroEnabled"
                    string lives inside [Content_Types].xml, which is
                    compressed inside the ZIP container and therefore
                    invisible to YARA on the raw .xlsb. Rule rewritten to
                    rely only on strings visible in the ZIP central
                    directory (uncompressed filename entries).

    Basis for detection:
        The dropper is a .xlsb (Excel Binary Workbook) containing XLM
        (Excel 4.0) macros rather than VBA — specifically defeating
        olevba-class scanners. The first rule matches the raw .xlsb via
        ZIP filename strings in the central directory. The second rule
        matches artifacts in the UNZIPPED contents (obfuscated XLM
        function identifiers and the DocuSign-themed lure).
*/

rule URSNIF_xlsb_dropper_2021_05_14
{
    meta:
        description = "URSNIF XLSB dropper with XLM macros (raw .xlsb ZIP container) — 2021-05-14 campaign"
        author      = "Moses Chavez, Marissa Turner"
        date        = "2026-04-24"
        reference   = "https://www.malware-traffic-analysis.net/2021/05/14/index.html"
        malware     = "URSNIF dropper"
        severity    = "high"
        md5         = "eb6e605d7d61d17694a6bb3c72ef04c0"
        sha256      = "60f0eb98765e693f80626a8ce9a80937036b480dffc2a65eca55fbc7ccc94d18"
        note        = "Detects .xlsb files containing XLM macros by matching ZIP central directory filename entries — visible as plaintext even in the raw compressed container."

    strings:
        // ZIP local file header signature
        $zip_sig = { 50 4B 03 04 }

        // XLM macrosheet directory inside the .xlsb container.
        // This directory is the .xlsb equivalent of xl/macrosheets/ in
        // .xlsm files; its presence is the definitive structural signature
        // of an XLM-macro-bearing XLSB. Filenames appear as plaintext in
        // the ZIP central directory.
        $xld_path = "xl/xld/" ascii

        // Individual file paths within xl/xld/ observed in this sample
        $xld_sheet = "xldsheet" ascii
        $xld_bindex = "binaryIndex" ascii

    condition:
        $zip_sig at 0 and
        filesize < 200KB and
        any of ($xld*)
}


rule URSNIF_xlsb_unzipped_xlm_content
{
    meta:
        description = "URSNIF XLM macro artifacts and DocuSign lure (scan UNZIPPED .xlsb contents)"
        author      = "Moses Chavez, Marissa Turner"
        date        = "2026-04-24"
        severity    = "high"
        note        = "Apply to files extracted from the .xlsb ZIP container. These strings are inside compressed streams and are not visible to YARA on the raw .xlsb. Verified to match xlsb_unpacked/docProps/app.xml and xlsb_unpacked/xl/drawings/drawing1.xml on the reference sample."

    strings:
        // Obfuscated XLM function identifiers — random-character names
        // used to break automated deobfuscators (XLMMacroDeobfuscator
        // failed to parse these formulas during static analysis)
        $obf_fn1 = "DFJDFJDF" ascii
        $obf_fn2 = "FDJDFJKERJKJKER" ascii

        // DocuSign-themed social engineering lure strings (observed in
        // drawings/drawing1.xml and docProps/app.xml when unzipped)
        $lure_docusign  = "DocuSign" ascii wide
        $lure_protect   = "PROTECT SERVICE" ascii wide nocase
        $lure_encrypted = "DOCUMENT IS ENCRYPTED" ascii wide nocase
        $lure_editing   = "Enable Editing" ascii wide
        $lure_content   = "Enable Content" ascii wide

    condition:
        any of ($obf_fn*) or 3 of ($lure_*)
}
