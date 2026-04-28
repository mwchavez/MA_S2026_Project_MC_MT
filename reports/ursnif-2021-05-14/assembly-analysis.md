# Assembly-Level Code Analysis Report — URSNIF block.dll (2021-05-14)

**Authors:** Moses Chavez, Marissa Turner
**Sample:** `block.dll` (SHA-256 `8a26c32848c9ea085505359f67927d1a744ec07303ed0013e592eca6b4df4790`)
**Analysis date:** April 2026
**Environment:** Windows Detonation VM, isolated AnalysisNet (no network execution).
**Tools:** Ghidra 12.0.4, Detect It Easy 3.10.

---

## 1. Scope

This report documents Phase 3 of the analysis pipeline: assembly-level code analysis of `block.dll`. Per the kickoff guide, the focus is **recognition and explanation** of suspicious code constructs rather than exhaustive reverse engineering.

The objectives were to:

- Disassemble `block.dll` in Ghidra and orient within the binary
- Identify at least one meaningful (non-library) URSNIF function
- Provide a plain-English explanation of what that function does and why it is suspicious
- Determine whether the binary is packed or obfuscated, and document the evidence

`block.dll` was loaded onto the Detonation VM via `ursnif-samples.iso` (read-only optical mount). The DLL was not executed during this phase.

---

## 2. Compiler and Toolchain Fingerprinting

Detect It Easy reported:

| Field | Value |
|---|---|
| File type | PE32 (32-bit DLL) |
| Linker | Microsoft Linker 9.00.21022 |
| Compiler | Microsoft Visual C/C++ 15.00.21022 |
| Tool | Visual Studio 2008 |
| Language | C++ |
| Debug data | PDB 7.0 link present |
| Packer signature | **None detected** |

Ghidra's Function ID feature independently corroborated the Visual Studio 2008 origin by matching multiple library functions (e.g., `_initptd`) to MSVC 2008 Release library signatures with high confidence.

---

## 3. Ghidra Setup

A non-shared Ghidra project named `URSNIF-block-dll` was created. `block.dll` was imported with auto-detected language `x86:LE:32:default:windows` and compiler ID `windows`. Auto-analysis was performed with the standard analyzer set plus three additions:

- **Disassemble Entry Points** — necessary for export-driven entry analysis (`Pape1`, `Riverslow`)
- **Embedded Media** — resource extraction
- **Subroutine References** — improved cross-reference quality

The PDB Universal analyzer reported a failure to locate a PDB file. This was expected: the FlareVM has no internet (Microsoft public symbol server is unreachable), and the analysis did not require PDB symbols.

During import, Windows Defender Firewall prompted to allow OpenJDK Platform Binary network access. Access was **denied** to maintain the FlareVM's no-network posture. Auto-analysis is fully offline.

---

## 4. Initial Orientation

### 4.1 Exports

The two non-standard exports identified in Phase 2 were confirmed in Ghidra's Symbol Tree:

- `Pape1` — Phase 4 detonation target (`rundll32.exe block.dll,Pape1`)
- `Riverslow` — secondary export, fallback target

Neither corresponds to a standard DLL export name (`DllMain`, `DllRegisterServer`, etc.).

### 4.2 Imports

Five name-based imports from KERNEL32.DLL: `VirtualAlloc`, `VirtualProtectEx`, `GetProcAddress`, `LoadLibraryA`, `IsDebuggerPresent`. The remainder of URSNIF's API surface is resolved at runtime.

### 4.3 Cross-reference inventory

| Import | Total references | Direct CALL sites |
|---|---|---|
| `GetProcAddress` | 16 (1 import pointer + 15 calls) | 15 |
| `LoadLibraryA` | 3 (1 + 2) | 2 |
| `VirtualAlloc` | 3 (1 + 2) | 2 |

**Every** `GetProcAddress` call site is annotated `COMPUTED_CALL` in Ghidra (e.g., `CALL EBX=>KERNEL32.DLL::GetProcAddress`). The API address is loaded into a register at runtime, not called via a direct import-table reference. This is a textbook URSNIF anti-analysis pattern.

### 4.4 Defined Strings — geo-targeting evidence

Ghidra's Defined Strings window surfaced country-name strings (`united-states`, `united-kingdom`, `trinidad & tobago`), day-of-week strings, and the fake copyright string `© Equalher Corporation`. The country list corroborates capa's "System Location Discovery" capability finding from Phase 2 — URSNIF tailors behavior by region.

---

## 5. Library Code vs URSNIF Code — Methodological Pivot

A significant Phase 3 finding is the realization that several of the most "interesting-looking" cross-reference targets are statically-linked Microsoft Visual C Runtime (CRT) library code, not URSNIF logic. Ghidra's Function ID matched several functions to MSVC library signatures with high confidence ("Library Function — Single Match"):

- **`__sbh_alloc_new_region`** — MSVC small-block heap allocator. Both `VirtualAlloc` xrefs land here (heap region growth).
- **`_initptd`** — MSVC per-thread data initializer. Resolves `EncodePointer` and `DecodePointer` for runtime function-pointer obfuscation throughout the CRT.
- **`__crtMessageBoxA`** — MSVC CRT wrapper for assertion failure dialogs. Resolves USER32 APIs through `__encode_pointer`.
- **`rand_s`** — MSVC secure random number generator. Loads `ADVAPI32.DLL` and resolves `SystemFunction036` (`RtlGenRandom`).

These functions account for several of the `GetProcAddress` and `LoadLibraryA` xrefs but are benign Microsoft library code statically linked into the binary by Visual Studio 2008.

The methodological response: filter the function tree to `FUN_*` (Ghidra-discovered, Function-ID-unmatched) entries, then follow XREFs from URSNIF's own exports (`Pape1`, `Riverslow`) into the binary. This pivot is broadly applicable to any statically-linked malware where library code visually competes with malicious code in the disassembly.

---

## 6. Deep-Dive: `FUN_0103320c`

### 6.1 Selection rationale

After filtering the Symbol Tree to `FUN_*`, `FUN_0103320c` was identified as a function with a direct cross-reference from the export `Pape1`:

```
FUN_0103320c                        XREF[1]:  Pape1:0103348d(c)
```

`FUN_0103320c` is called from offset `0x103348d` inside the `Pape1` export. Because `Pape1` is the function we plan to invoke via `rundll32.exe block.dll,Pape1` for Phase 4 detonation, **`FUN_0103320c` is part of URSNIF's earliest execution path** — running before any externally-observable malicious behavior.

### 6.2 Decompiled C reconstruction

```c
void FUN_0103320c(int param_1)
{
    int iVar1;
    int iVar2;

    iVar1 = param_1 * 2 + 1;
    iVar2 = iVar1 * param_1 - param_1;
    DAT_0104a0d8 = (char)iVar2 + (char)DAT_0104a0d8 + (char)iVar1 + 4;
    DAT_0104a00c = 0;
    DAT_0104a010 = iVar2 + param_1 * 3 + 0x16;
    DAT_0104a0dc = ((DAT_0104a008 - (iVar2 + ((uint)DAT_0104a0d8 + param_1) * -0x48 + -0x120))
                    + 0x9b21 + DAT_0104a010 * 2) * (uint)DAT_0104a0d8 - param_1;
    DAT_0104a008 = (DAT_0104a010 - DAT_0104a0dc) + -0x15450;
    return;
}
```

### 6.3 Plain-English description

`FUN_0103320c` is a small, focused function that takes a single integer argument and updates five global variables in `block.dll`'s `.data` section: `DAT_0104a008`, `DAT_0104a00c`, `DAT_0104a010`, `DAT_0104a0d8`, `DAT_0104a0dc`. It does so through chained multiplications, additions, and bitwise operations involving "magic" hardcoded constants — `0x16`, `0x48`, `0x120`, `0x9b21`, `0x15450`. The function makes no Windows API calls, references no strings, and produces no observable system-level effect. From a behavioral-IOC standpoint, the function looks "boring."

### 6.4 Why the function is suspicious

Despite its outwardly innocuous appearance, `FUN_0103320c` exhibits several patterns characteristic of malware anti-analysis logic and key derivation:

1. **Heavy obfuscated arithmetic.** Chained multiplications and subtractions with magic constants. Not the output of normal application source code; consistent with output from a code generator or post-compilation obfuscator designed to defeat static analysis.

2. **Self-referential state updates.** `DAT_0104a0d8` is read and written within the same expression. This builds path-dependent state: subsequent calls produce results that depend on the cumulative history of how many times the function has been invoked. A static analyst cannot predict the values without dynamic execution.

3. **No surface behavior.** Lack of API calls, strings, or syscalls is a deliberate evasion strategy. Reverse engineers hunting for traditional malicious indicators (network APIs, registry APIs, process injection APIs) will not flag this function.

4. **Direct call from the export.** Invoked very early during DLL execution via `Pape1`. By the time downstream functions read the `DAT_*` globals, the values have already been mutated. Consistent with **runtime configuration arming** or **decryption-key seeding**.

5. **Global state at fixed addresses.** The five `DAT_*` globals are clustered at `0x0104a008–0x0104a0dc`. Consistent with a **configuration block** or **key table** that other URSNIF functions read to construct API hashes, decrypt strings, or compute control-flow targets.

### 6.5 Interpretation

`FUN_0103320c` is best understood as a **runtime configuration / key-derivation helper**. It mutates global state used by downstream URSNIF functions to derive seed values for string decryption and hash-based API resolution. This interpretation is consistent with two prior findings:

- **Phase 2 found zero plaintext IOCs in the binary.** Explained if URSNIF stores those strings encrypted and derives the decryption key at runtime from state mutated by functions like `FUN_0103320c`.
- **Phase 2 identified a `.data` section virtual-size anomaly** (raw 0x1000, virtual 0x108000 — a 264× expansion). Explained if the binary allocates a large in-memory buffer at runtime to hold decrypted configuration and unpacked code.

These two static-analysis findings, paired with the assembly-level evidence above, form a coherent picture: URSNIF arms its runtime cryptographic state inside `FUN_0103320c`, then uses that state to decrypt configuration and resolve APIs throughout execution.

---

## 7. Packing and Obfuscation

Three independent pieces of evidence support the conclusion that `block.dll` is **not commercially packed** but **is heavily obfuscated through inline runtime decryption**:

| Evidence | Source | Interpretation |
|---|---|---|
| `.data` raw 0x1000 → virtual 0x108000 (264× expansion) | Phase 2 (`rabin2 -S`) | Runtime memory allocation for unpacked/decrypted content |
| No commercial packer signature; total entropy 6.13 | Phase 3 (DIE) | No single high-entropy compressed blob |
| Zero plaintext IOC strings | Phase 2 (`rabin2 -zz` + grep) | URLs, registry paths, configuration not stored as plaintext |
| Heavy obfuscated arithmetic in `FUN_0103320c` | Phase 3 (Ghidra) | Custom in-binary key-derivation logic |
| capa: "link many functions at runtime", "execute shellcode via indirect call" | Phase 2 | Runtime API resolution + indirect-call execution model |

DIE's per-section entropy distribution showed `.text` at 6.19 (slightly elevated for compiled code), with smooth ~5.5–6.0 distribution across the file. This is consistent with a normal-entropy PE that performs runtime decryption — encrypted strings are scattered across `.text` mixed with code and decrypted in-memory via the obfuscated arithmetic functions.

This is more sophisticated than commercial packing. It forces dynamic analysis (Phase 4) to recover the configuration data.

---

## 8. Findings Summary

1. `block.dll` is a 32-bit Windows PE DLL compiled with Visual Studio 2008 (MSVC 15.00.21022).
2. The binary statically links MSVC C Runtime, which accounts for several "interesting-looking" import xrefs that are in fact benign library code.
3. URSNIF's true entry points are the non-standard exports `Pape1` and `Riverslow`. `Pape1` is the Phase 4 detonation target.
4. URSNIF resolves the bulk of its API surface at runtime via `GetProcAddress` — every one of the 15 GetProcAddress call sites is `COMPUTED_CALL`.
5. `FUN_0103320c`, called from `Pape1`, is a custom obfuscated arithmetic function that mutates global state used by downstream URSNIF code for runtime key derivation.
6. `block.dll` is not commercially packed (DIE), but is heavily obfuscated through inline runtime decryption — a more sophisticated approach than packing.
7. No plaintext IOCs are recoverable from static analysis. Phase 4 will recover the C2 domains, IPs, URI patterns, and User-Agent strings via dynamic execution and PCAP analysis.
