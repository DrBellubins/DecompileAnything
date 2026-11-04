# Cross-platform MSVC support (PE targets, COFF candidates, `cl`)

A separate track from [Design-Plan.md](Design-Plan.md) Phases 4 and 5: it makes the tool work on
binaries built by Microsoft's compiler, on a Linux machine, with no Windows installed. Every
number below was measured on this machine on **2026-11-04** against
`Tests/Proprietary/notepad.exe`. **No code in `decomp/` was changed to obtain them** - the probe
ran with a `project.toml` and an analysis cache outside the repo (`/tmp/danotepad`), and `decomp/`
is still untouched by this work.

---

## 1. Three separable things, and only one of them is "MSVC"

| | What it means | Who needs it | What it costs |
|---|---|---|---|
| **A. read a PE target** | `detect`, `analyze`, `show`, `find` on a `.exe`/`.dll` | the target side of every command | fixing what is already written - no new dependency (LIEF reads PE today) |
| **B. build a COFF candidate** | `try` compiles candidate source to a `.obj` and reads it back | the candidate side of `try` | LIEF 1.0 reads COFF today; the work is COFF's *semantics* (no symbol sizes, no relocation addends) |
| **C. match MSVC codegen** | a candidate compiled by `cl` with the target's flags assembles to the target's bytes | the gate, i.e. the whole point | `cl.exe`, which is Windows-only - see §5 |

Two names to keep apart while reading this:

* **PE support is not MSVC support.** `x86_64-w64-mingw32-g++` (installed here) emits PE/COFF
  with GCC codegen, and the MSVC *flags* in `toolchain.build_flags` would not apply to it. It
  is useful for exercising A and B and must never be labelled an MSVC variant.
* **`/usr/bin/link` on this machine is binutils `link`**, not Microsoft's `link.exe`. Any probe
  that finds a compiler by name must not accept it (`cli.py:486` already maps the `msvc` family
  to `cl`, which is the right thing to extend).

## 2. The probe target

`Tests/Proprietary/notepad.exe`, PE32+ AMD64, GUI subsystem, 240 KB, image base
`0x140000000`, ASLR on, 6 sections, **no COFF symbol table** (`nm` says "no symbols"), 28
imported DLLs, 256 base-relocation entries.

| Fact | Where it comes from | Value |
|---|---|---|
| Toolset | Rich header, 9 entries | every MSVC tool at build id `0x646f` = **25711** |
| Toolset (independent) | `optional_header.major/minor_linker_version` | **14.12** - VS2017 15.6-era (v141); consistent with 25711 |
| Whole-program codegen | debug directory: `POGO` with signature `LCTG`, plus `REPRO` | built with **`/GL` + `/LTCG`** and `/REPRO` (PGO itself is *not* proven by this) |
| CRT | imports from `msvcrt.dll`: `__getmainargs`, `_cexit`, `_XcptFilter`, `_ismbblead` | the *downlevel* CRT (`msvcrt.lib`) - not UCRT, not `vcruntime140.dll` |
| Debug record | `CODEVIEW` | `notepad.pdb`, GUID `5c1bb141-8276-e6c4-c297-fcbaec420f58`, age 1 |
| Function table | `.pdata` (x64 unwind info) | **186 records**, 99 778 of the 101 742 `.text` bytes; median function 192 bytes |
| Build tree | the PDB's module list | `d:\os\obj\amd64fre\shell\osshell\accesory\notepad\objfre\amd64\*.obj` - a Windows `amd64fre` OS build, 116 compilands |

`TimeDateStamp` is a reproducible-build constant (it decodes to 2053), so the toolset, not the
timestamp, is what dates this file.

Re-measure it with:

```sh
.venv/bin/python -c "import lief; b=lief.PE.parse('Tests/Proprietary/notepad.exe'); \
print(b.header.machine, [ (hex(e.id), hex(e.build_id), e.count) for e in b.rich_header.entries ])"
# .pdata (RVA + image base):
.venv/bin/python -c "import lief,struct; b=lief.PE.parse('Tests/Proprietary/notepad.exe'); \
d=bytes(b.get_section('.pdata').content); print([struct.unpack_from('<III',d,k*12) for k in range(len(d)//12)][:8])"
# the PDB (no Windows tools needed):
curl -sSL -o /tmp/notepad.pdb \
  https://msdl.microsoft.com/download/symbols/notepad.pdb/5C1BB1418276E6C4C297FCBAEC420F581/notepad.pdb
llvm-pdbutil dump --summary --modules --publics --section-contribs /tmp/notepad.pdb
```

## 3. What already works on a PE, and what does not (measured)

Working today:

* `toolchain.build_note()` (`toolchain.py:84,200`) reads it: `format=PE`, `arch=AMD64`,
  `file_type=EXE`, `pie=True`, `compiler=msvc`, `linker_version=14.12`, the Rich entries, and
  `abi = MSVC CRT (the Rich header is written by the Microsoft linker)`.
* `decomp analyze` runs end-to-end: 109 s (import 2.3 s, auto-analysis 104 s, export 1.7 s),
  **236 functions** (221 bodies + 15 IAT thunks), 25 033 instructions, 7 676 references, 483
  strings, language `x86:LE:64:default`, image base `0x140000000`. Ghidra's import names
  survive into the cache (`OpenProcessToken`, `TextOutW`, ...), and **all 186 `.pdata`
  function starts are function entries in the cache**.

Broken, in the order it bites:

1. `extract.section_capabilities` (`extract.py:28,35`) reads `section.flags`. LIEF's PE section
   attribute is **`characteristics`** (`pointerto_raw_data`, `sizeof_raw_data`,
   `numberof_relocations` are spelled the same way). `AttributeError` out of
   `TargetImage.__init__` (`extract.py:107`) and out of `toolchain.target_shape`
   (`toolchain.py:634`) - so `try`, `show`, `find` and `detect --range` all die on a PE. The
   PE executable mask there (`0x20000020`) also ANDs `MEM_EXECUTE` with `CNT_CODE`; they are
   alternatives, not a pair.
2. `_read_pe` never fills `note["sections"]`, so `cli._address_offset()` (`cli.py:959`) returns
   `None` and `decomp find` dies at `cli.py:649` (`int(None)`). For a PE this offset is 0 in
   practice - Ghidra loads the image at its own `imagebase` - but "compute it as 0 because the
   format says so" has to be an answer the code can give.
3. `_read_pe` never fills `note["needed"]` from the PE imports, so `note["static"]` is
   reported **`True` for a binary that imports 28 DLLs**. That feeds the report and
   `starter_config`.
4. `_read_pe` reads `binary.debug_info` and `entry.number`; LIEF 1.0 spells them `binary.debug`
   and `entry.count`. So the CodeView record - the PDB GUID, the single most useful fact about
   an MSVC binary - is silently dropped, and every Rich `count` is recorded as 0.
5. Function sizes: 154 of the 186 `.pdata` extents match the cache exactly, 32 come out
   **smaller**, because `ghidra.py:227` sums the ranges of Ghidra's body and Ghidra excludes
   the gaps inside a body (alignment padding, jump tables) - the same multi-range problem
   README already names for `-O2` hot/cold bodies. The cache additionally holds 35 function
   entries that are not in `.pdata` (Ghidra inventing functions in the alignment gaps).
   Nothing in the tool reads `.pdata` today.

Names: `normalize.demangle` (`normalize.py:90`) feeds only `_Z…` names to `c++filt`, and MSVC
decorations (`?EditProc@@YA…`, `??_C@_0BJ@…`) are passed through untouched. Matching by
decorated name is fine and stable; display and `simple_name` are not.

## 4. Ground truth an MSVC target carries (and ELF does not)

Two things are worth more than anything in §3:

* **`.pdata` is the compiler's own function table.** For x64 PE it lists
  `(begin, end, unwind)` for every function, with no symbols and after stripping. On the probe
  target it gives 186 units with exact ranges - strictly better than Ghidra's recovery, and it
  is the PE answer to "read the ELF symbol sizes". `.pdata` RVAs are relative to the image
  base, so they must be biased by `imagebase` to meet Ghidra's addresses.
* **Microsoft publishes the PDB for shipped Windows binaries.** With the GUID and age from the
  CodeView record, `https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><age>/<pdb>`
  returned the real file here (249 856 bytes). `llvm-pdbutil` (LLVM 23, installed) reads it on
  Linux and gives: 978 public symbols with decorated names and `section:offset`, **239 `.text`
  section contributions** - one COMDAT per function, i.e. name → address → size - and the
  link-time module list, which names the original translation units
  (`notepad`, `npfile`, `npinit`, `npmisc`, `npprint`, `npreplace`, `npdate`, `nputil`,
  `nputf`, `nptracelogger`, `filedialogevents`, `precomp`). For a stripped proprietary binary
  that is an *answer key*: unit boundaries, sizes, names, and which unit each unit came from.
  Caveat: Ghidra 12.1.2's PDB feature here is the old DIA `pdb.exe`
  (`Ghidra/Features/PDB/src/pdb/*.cpp`, no Linux binary shipped), so a PDB cannot be imported
  *inside* Ghidra on Linux - read it outside and merge it into the cache.

One fact from `.pdata` and the PDB together should shape expectations: the function at
`0x1400079cc` spans **43 095 bytes** and `.pdata` and Ghidra agree exactly. On an `/LTCG`
image, the unit the linker emitted is not the function the source had.

## 5. Getting something that speaks MSVC onto a Linux machine

`cl.exe` is Windows-only and there is no Linux port of the MSVC front-end. Three tiers:

**A. Real `cl.exe` under Wine - the only thing that can satisfy the byte gate.**
[`mstorsjo/msvc-wine`](https://github.com/mstorsjo/msvc-wine/) is the standard route:

```sh
./vsdownload.py --dest ~/my_msvc/opt/msvc --accept-license     # MSVC + Windows SDK, from VS installer manifests
./install.sh ~/my_msvc/opt/msvc                                # wrappers: bin/{x86,x64,arm,arm64}/{cl,link,lib,dumpbin,rc,mt,nmake,ml64}
export PATH=~/my_msvc/opt/msvc/bin/x64:$PATH                   # and source wrappers/msvcenv.sh if not using the wrappers
```

Relevant details for this tool, all from reading that repo:

* `--major 15|16` and `--msvc-version <ver>` install a toolset of the **era** you are matching;
  the default is the newest. The probe target wants v141 (linker 14.12 / build 25711).
* `wrappers/wine-msvc.sh` prefers `wine64`, which matters here: this machine's `/usr/bin/wine`
  is a 32-bit ELF whose interpreter `/lib/ld-linux.so.2` is not installed
  (`wine` → "required file not found"), while `wine64` works (9.21 Staging).
* The wrappers rewrite `/absolute/paths` into `z:/absolute/paths` (a real cl-under-Wine bug)
  and unixify the diagnostics (strip `\r`, rewrite `z:\...`). `compile.py`'s promise of
  returning diagnostics verbatim therefore depends on going through those wrappers, or on
  doing the same normalisation.
* Missing prerequisites here: `msitools`/`msiextract`, `libgcab ≥ 1.2`, `winbind` (the C1902
  "Program database manager mismatch" fix), plus ~1-2 GB of download. Wine itself is present.

**B. `clang-cl` / `clang --target=x86_64-pc-windows-msvc` - native, no Wine.** Installed
(clang 23) and it produces correct COFF today (`clang-cl /O2 /c t2.cpp /Fot2.obj` →
`x86-64 COFF object file`). It cannot compile the benchmark as it stands:
`#include <vector>` → *file not found*, because there is no MSVC STL / Windows SDK on this
machine. msvc-wine's *download step alone* (no Wine needed) supplies them via
`msvcenv-native.sh`; `lld-link` is also needed and is **not** installed (no `lld` at all).
Codegen is clang's, so this tier is for exercising A and B, never for the byte gate.

**C. MinGW-w64 gcc** (installed, `objdump -dr` reads its `.obj` files fine): PE/COFF plumbing
only, see §1.

## 6. What the gate can honestly promise on an MSVC target

Byte-identity is the tool's whole point, and it holds only when the candidate is compiled the
way the original was. For shipped MSVC binaries three things break that:

* **`/GL` + `/LTCG`.** The code in the image was regenerated by the linker - cross-TU inlining,
  `/OPT:ICF` folding of identical COMDATs, link-time layout. No per-translation-unit compile
  reproduces it. The 43 KB function in §4 is what that looks like from the outside.
* **Toolset era.** This target is v141 (2017). A 2022-era `cl` is seven years of codegen
  changes away; msvc-wine can install the old one, and `detect` naming the build number is what
  makes that choice instead of a guess.
* **CRT flavour.** `msvcrt.lib` (this file) vs UCRT vs static `/MT` changes what a function
  *reaches*, which the `relocation` category will keep reporting honestly.

So the rule to implement, and to state in the report rather than hide:
**the byte gate applies to a target a variant can reproduce.** A variant table that says
`ltcg = true` (or a target whose `.pdata`/PDB shows a merged body) gets a
*shape-and-references* score with byte-identity reported as unreachable, exactly like the
-O1/-O2/"not -O0" honesty in `detect`. That is a `diff.py`/`cli.py` decision, not a
`try`-refuses-to-run decision.

## 7. Phases

Numbered `MS-*` so they do not renumber Design-Plan's Phases 1-5. Each phase is independently
useful and each has a check script in `Tests/tools/`, in the style of
`check_analysis_cache.py`.

**MS-0: make the PE path run.** (~50 lines, no new dependency, fixes four real crashes.)
`section_capabilities`: PE `characteristics`, correct masks, and a COFF branch (COFF has no
`binary.format`; its header has `machine`/`kind`, no `identity_class`).
`_read_pe`: fill `note["sections"]` (RVA + `imagebase`) and `note["needed"]` from
`binary.imports`; read `binary.debug` (CodeView GUID/age/PDB name, `POGO`/LCTG, `REPRO`) and
`entry.count`. Then `decomp detect`, `show` and `find` work on a PE, and `detect` can say
`/GL` and name the toolset.
*Check:* `Tests/tools/check_pe_target.py` - on `Tests/Proprietary/notepad.exe`: `compiler =
msvc`, `linker_version = 14.12`, `static = False`, 28 imports, the PDB GUID, `LCTG` reported,
and `find`/`show` return results without raising.

**MS-1: `.pdata` as the source of function boundaries.** Read `.pdata` in `extract.TargetImage`
(biased by `imagebase`), keep it in the cache alongside the Ghidra ranges, and prefer it for
`entry`/`size`; report the disagreement instead of silently taking one side.
*Check:* the same script asserts 186 units with exact sizes and no invented function in an
alignment gap; today's numbers (154 exact, 32 short, 35 invented) are the baseline it must
improve on. This is also worth doing for ELF-free reasons: it is the fix for the multi-range
bodies Phase 5 needs anyway.

**MS-2: put a compiler on the machine.** msvc-wine full install (A) into a dedicated prefix,
`--major 15` for a target-era match; optionally download-only + `lld` (B) for a fast, Wine-free
path. Record the result in `decomp check` (it already maps the `msvc` family to `cl` at
`cli.py:486`): probe `cl`, `link`, `dumpbin`, print their versions, and refuse to accept
`/usr/bin/link`. Add `msvc-o0`/`msvc-o2` variants to `Tests/project.toml` and a PE build of the
benchmark (`Tests/eval.py` needs `/Fe` linking and an answer key from `.pdata`/PDB instead of
`nm --print-size`).
*Check:* `Tests/tools/check_msvc_toolchain.py` (versions, and one probe compile + one probe
link at each level), and the benchmark's own `selfcheck` passing on the PE build.

**MS-3: the COFF candidate side - this is where `try` starts working on PE.**
`extract.CandidateObject` (`extract.py:334`) needs a COFF branch: sections and relocations come
from `section.relocations`, **COFF symbols carry no size and no function flag** - the extent of
a function is its COMDAT section (`.text$<name>`, MSVC's default `/Gy`, which gives *exact*
sizes, better than ELF's symbol sizes) or the object's own `.pdata` entry. COFF relocations
have **no addend**: `AMD64_REL32`/`ADDR32NB` take the value already in the bytes as an implied
addend, which replaces the ELF ".o relocates a section, the addend is the offset" rule in
`extract.py`. `normalize.py`'s tokeniser needs no change (x86-64 is already supported, and the
relocated field sits at the same offset capstone reports). `compile.py:60` currently refuses a
non-standard candidate suffix for MSVC drivers - use `/Tp` instead of refusing.
*Check:* a PE port of `check_phase2_try.py`: the untouched source through `decomp try` for every
benchmark unit at `msvc /Od` (expected: byte-identical for the free functions) and the
deliberately wrong candidates still classified correctly.

**MS-4: say what an MSVC build is.** A Rich `build` → toolset table (cross-checked against the
optional-header linker version, which independently said 14.12 here) and the tool-id meanings;
MSVC members of `shape_profile`/`PROBE_SOURCE` (x64 `cl` uses `rsp`-relative locals and shadow
space, never a frame pointer, no `endbr`, and a `/GS` guard call rather than a canary) so
`detect` can answer `/Od` vs `/O1|/O2` and report `/GL`; C++/`-std` evidence from decorated
names and the CRT import family instead of `.dynstr`/`_STD_MARKERS` (`toolchain.py:268,275`,
both Itanium-only); `/std:c++…`, `/MT` vs `/MD`, `/GS-` and friends in `build_flags`
(`toolchain.py:46`, which collapses everything to `/Od`|`/O2`).

**MS-5 (after Design-Plan Phase 4): MSVC C++ structure.** vtables in PE are `.rdata` absolute
RVAs - readable straight from the file, no relocation addends, unlike a PIE's `.data.rel.ro` -
but the type system is MSVC RTTI (`RTTICompleteObjectLocator`, `.?AV…` descriptors) with thunks
for multiple inheritance, so `--table`/`--members` need a second model rather than a
generalisation of the Itanium one. Do it after Phase 4 exists, so it is a parallel implementation
and not a redesign.

Dependency order: **MS-0 → MS-1** is self-contained and improves the tool on this very file with
no compiler at all. **MS-2 → MS-3** is the path to `try` on PE. **MS-4** and **MS-5** are
independent of each other. Nothing here changes the ELF path.

## 8. Traps, written down before the work

* LIEF 1.0 PE/COFF spellings: `section.characteristics`, `pointerto_raw_data`,
  `sizeof_raw_data`, `numberof_relocations`, `binary.debug`, `entry.count`,
  `header.machine`. COFF has no `binary.format`; `lief.parse` auto-detects `.obj` files and
  returns a `COFF.Binary`.
* `.pdata`, PDB addresses and PE relocations speak **RVAs**; Ghidra speaks
  `imagebase + RVA`. Forget the bias once and everything is "no such function".
* COFF: no symbol sizes, no `is_function`, relocations per section with no addend, and one
  COMDAT section per function - which is the good news, and what MS-3 should use.
* MSVC names are decorated and `c++filt` cannot read them. Keep the decorated name as the
  comparison key; undecorate only for display (`undname.exe` ships with the toolset, or
  `llvm-pdbutil` from the PDB).
* `/GL` changes what a "function" is. Report it, and never promise the byte gate on it.
* A 32-bit `wine` launcher is not enough - prefer `wine64`, and let the wrappers do the
  `z:/` path rewriting rather than shelling to a bare `cl.exe` with `/Fo/home/...`.
* The public PDB for a shipped Windows binary is usually **stripped of full type info**
  (`Is stripped: true` here) but still carries publics and section contributions - which is
  exactly the answer key, and not what a full debug PDB looks like.

## 9. Explicitly not in scope

Importing PDBs inside Ghidra (no Linux parser in the pinned install - do it outside); matching
`notepad.exe` byte-for-byte (§6); treating a MinGW-built PE as an MSVC target (§1); ARM64
Windows, and any Windows-on-ARM or MSVC-x86 host tooling beyond what
`Tests/project.toml`'s `arch` field already models.
