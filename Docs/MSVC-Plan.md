# Cross-platform MSVC support (PE targets, COFF candidates, `cl`)

A separate track from [Design-Plan.md](Design-Plan.md) Phases 4 and 5: it makes the tool work on
binaries built by Microsoft's compiler, on a Linux machine, with no Windows installed. Every
number below was measured on this machine on **2026-11-04** against
`Tests/Proprietary/notepad.exe`. **No code in `decomp/` was changed to obtain them** - the probe
ran with a `project.toml` and an analysis cache outside the repo (`/tmp/danotepad`), and `decomp/`
is still untouched by this work. (MS-0 has changed `decomp/` since; every number below is still
what `Tests/tools/check_pe_target.py` measures, which is now the machine-readable form of this
section.)

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
* **`/usr/bin/link` on this machine is GNU coreutils' `link`** (9.12, the `link()` syscall
  wrapper) - measured 2026-11-04; there is no binutils `link` here at all (`ld` is). Any probe
  that finds a compiler by name must not accept it (`cli.py:486` already maps the `msvc` family
  to `cl`, which is the right thing to extend; `decomp check` now identifies every MSVC tool by
  its banner instead).

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

The probe target is gitignored (`Tests/Proprietary/`), so re-measure it after fetching it; the
check script exits 2 - not 1 - when the file or its analysis is absent.

Re-measure it with:

```sh
.venv/bin/python -c "import lief; b=lief.PE.parse('Tests/Proprietary/notepad.exe'); \
print(b.header.machine, [ (hex(e.id), hex(e.build_id), e.count) for e in b.rich_header.entries ])"
# .pdata (RVA + image base):
.venv/bin/python -c "import lief,struct; b=lief.PE.parse('Tests/Proprietary/notepad.exe'); \
d=bytes(b.get_section('.pdata').content); print([struct.unpack_from('<III',d,k*12) for k in range(len(d)//12)][:8])"
# the PDB (no Windows tools needed) - fetch, verify, and keep it in a symbol-store layout:
.venv/bin/decomp symbols Tests/Proprietary/notepad.exe
llvm-pdbutil dump --summary --modules --publics --section-contribs \
  cache/symbols/notepad.pdb/5C1BB1418276E6C4C297FCBAEC420F581/notepad.pdb
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

Broken, in the order it bites. (This is the state before MS-0; §7 records what closed each of
them.)

1. `extract.section_capabilities` (`extract.py:28,35`) reads `section.flags`. LIEF's PE section
   attribute is **`characteristics`** (`pointerto_raw_data`, `sizeof_raw_data`,
   `numberof_relocations` are spelled the same way). `AttributeError` out of
   `TargetImage.__init__` (`extract.py:107`) and out of `toolchain.target_shape`
   (`toolchain.py:634`) - so `try`, `show`, `find` and `detect --range` all die on a PE. The
   PE executable mask there (`0x20000020`) also ANDs `MEM_EXECUTE` with `CNT_CODE`; they are
   alternatives, not a pair.
2. `_read_pe` never fills `note["sections"]`, so `cli._address_offset()` (`cli.py:959`) returns
   `None` and `decomp find` dies at `cli.py:649` - on `int("None")`, because `cache.write`
   stores `str(value)` and the missing offset reaches the reader as text. For a PE this offset is 0 in
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
  returned the real file here (249 856 bytes). Since 2026-11-06 that is a command, not a recipe:
  `decomp symbols <target>` (`decomp/symbols.py`) asks the server with the record `detect` reads,
  verifies the answer out of the PDB's own MSF stream 1 (its GUID, and the link timestamp that
  equals this image's `TimeDateStamp`), and stores it as `<store>/<pdb>/<GUID+age>/<pdb>` - the
  layout a `_NT_SYMBOL_PATH` symsrv client looks in. Two key facts it had to get right: the age in
  the key is **hex** (age 1 → `…581`, age 10 → `…A`; `detect` printed it in decimal before, which
  404s on images the linker rewrote ten or more times), and the key is the **bare file name**
  (`deadrising2.exe` asks for `c:\bcg\…\deadrising2.pdb`, served as `deadrising2.pdb` - and not
  served at all, since Microsoft only has Windows' own symbols: exit 1 with the URL, which is a
  different answer from the exit 3 "no CodeView record"). Its own header age is 3 against the
  record's 1: a shipped PDB is rewritten after the link, and the record's age is the key, so the
  command says that instead of calling it a mismatch. Reading the stream directory needed a real
  MSF reader: this file's directory is one block below the address its superblock gives, so a
  candidate is accepted only when it accounts for exactly `NumDirectoryBytes`.
  `llvm-pdbutil` (LLVM 23, installed) reads it on
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
* This section stays the *why*; the *how*, for every era from VS2005 to VS2026 and for both 32-bit
  and 64-bit hosts and targets, is [Setup.md](Setup.md) §6. Two things it settled that this section
  assumed: the `--msvc-version` → toolset/SDK mapping (the probe target's 14.12 is
  `--major 15 --msvc-version 15.5`), and the fact that `msitools` cannot be installed on this
  machine at all (no root), plus that its Wine cannot start a *32-bit* PE - which decides whether
  the VS2013-and-older toolchains are reachable here at all (Setup.md §6.7).

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

**MS-0: make the PE path run.** *Done 2026-11-04.* `Tests/tools/check_pe_target.py` is the
gate and it passes on `Tests/Proprietary/notepad.exe`: `compiler = msvc`, `linker_version =
14.12`, toolset `v141 (Visual Studio 2017)` cross-read against Rich build id `25711`,
`static = False` with the 28 imports listed, the PDB's GUID/age plus the
`msdl.microsoft.com` URL it can be fetched from, `pogo = LCTG` / `ltcg = True`, Rich counts
non-zero, `.text` in the section map at `0x140001000`, the entry point inside it, and
`find`/`show` run as the CLI runs them (exit 0, 36 of 45 references bound to operands).
`detect --write` on a PE writes a config that names `cl`, `o0`, and the /GL warning, and
`--range 0x140012000-0x140018000` samples 65 bodies inside `.text` while a range outside the
image is reported as empty. All four items of §3 are closed; the ELF path is unchanged
(Phase 1/2/3 checks report the same numbers as before). The analysis cache for this target now
lives in the repo's own cache (`cache/ghproj/899346f9f283a4fd`), so `decomp find`/`show` on
it need no `--config`; it was made before MS-0, which is why `cache.address_offset` below is
not a hypothetical (the MS-1 re-analysis rewrote it, so the tolerant reader is now asserted
directly rather than relied on from an old file).

Four things §3 did not list, found while fixing it:

* **The image-base bias is needed on the byte path too, not only in the note.** LIEF's PE
  section `virtual_address` is an RVA, so `extract.TargetImage` could find no section for any
  analysed address. `extract.file_address_base()` is now the single place that answers "what
  do I add to this file's section addresses to get the addresses everything here is keyed
  by": the image base for a PE, 0 for ELF/Mach-O. `cli._address_offset()` then computes
  `(0, ".text")` for a PE - the answer "the format says so", with the basis recorded.
* **A cached `meta` value is stored as `str(value)`**, so an analysis made before this fix
  holds the text `"None"` and `int(meta["address_offset"])` raised in `find`/`show`/`try`
  whatever the code now records. `cache.address_offset(meta)` reads it as 0.
* **`.rdata` is a PE's `.rodata`.** `extract._COMPARABLE` and `_POINTER_SECTIONS` are prefix
  lists, and without it the bytes of every string and table the analysis named read back as
  `None`. Verified against `0x1400205f0`, which holds `TextOutW`.
* **A CRT import is not a language.** `msvcrt.dll` is what a plain C program imports, so
  `language_evidence` now reports `abi = MSVC CRT (msvcrt.dll: the downlevel C runtime...)`
  and leaves `language` unset instead of claiming C++ (that needs decorated names: MS-4). It
  also has to match import names case-insensitively - a PE writes them upper-cased.

The COFF half of MS-0 is exactly what §7 asked for and no more: `extract._machine_name` and
`extract._bits_of` read a COFF header (`machine`, and no `identity_class` at all - `kind` says
EXEC/OBJ), so `CandidateObject` opens a `.obj` instead of failing on the header, and
`section_capabilities` answers from `characteristics` with no `binary.format` to consult. The
check builds a `clang-cl` object when one is installed and asserts machine/bits/no-error; the
symbol and relocation semantics (no sizes, no addends, one COMDAT per function) are MS-3.

**MS-1: `.pdata` as the source of function boundaries.** *Done 2026-11-04.*
`extract.TargetImage._read_function_table` reads `.pdata` (its RVAs through
`extract.file_address_base()`, exactly as planned), `analyze` writes it into a new cache table
`units(source, entry, end, size, unwind, section)` in the analysis' addresses, and everything
that reads a body can consult it. `Tests/tools/check_pe_target.py` is the gate; the numbers it
asserts are the ones §3 item 5 measured by hand, which the tool now produces itself:

```
  unit table   .pdata: 186 units, 99778 bytes - the file's own boundaries (.text 99778)
               154 agree with the analysis, 32 the analysis reports shorter, 0 longer,
               0 of its units are not a function entry in the analysis
               35 analysis function entries are not in .pdata - the analysis made those up
```

* **Preferred, not merely kept.** `extract.original_function` compares the unit's extent whenever
  the caller did not pass `--size`, and gets the unit's bytes by reading the *file* contiguously
  over it. That is also the multi-range fix Phase 5 asked for: 12 of this file's bodies have a
  gap inside them, and `0x140005af4` (2 ranges, a 67-byte gap, 2222 bytes analysed) is now
  compared over the compiler's contiguous 2289. Every disagreement is reported as a warning, and
  an explicit `--size` still wins, because a caller who names a range asked for one.
* **Reported on both sides.** `show` prints `; .pdata 0x…-0x… (3567 bytes): the file's own
  function table, the analysis' body is 3566 - `decomp try` compares the unit and says so`, or,
  for an entry the table does not name, `names no unit at 0x140001120: this function is the
  analysis' own - its units end at 0x140001118 and start again at 0x140001160, a 72-byte gap`.
  `find` marks what it lists (`<- not in .pdata`, `<- .pdata says N`), `status` names the table,
  and `show --json` carries the record.
* **The ELF path did not move.** The schema gained a table, but reading it is tolerant
  (`cache.has_table`, and every unit helper returns nothing when there is none), so the analyses
  already on disk keep working and keep their answers; `check_pe_target.py`'s last group
  re-measures that on `gcc-o0/da_tests.stripped`. A PE analysis has to be re-run
  (`analyze --force`) to gain its table - which is how the numbers above were obtained here.

Four things §7 did not predict:

* A PE section's `size` is its **virtual** size and LIEF's `content` is only the initialised
  bytes: walking `size` invents zero-length units out of the padding. The 186 real records live
  in 2232 bytes of a 2560-byte `.pdata`.
* `functions.bytes` in the cache is the **concatenation** of the analysis' ranges, so a gap
  inside a body is *missing* from the blob rather than zero-filled. Extending the blob to a
  unit's extent appends the wrong bytes; the unit has to be re-read from the file.
* The 35 analysis-only entries are not scattered: they sit in the **alignment gaps between
  units**, so printing the gap they are in is the honest annotation, and it is why `find`
  should not list them like real units.
* `unit_at`, keyed on the entry, is not the whole question: an analysis function can start
  *inside* a unit. `cache.unit_covering` answers that separately and `show` says "the analysis
  split one unit the compiler bounded as one" - a case this file happens not to contain.
* Comparing a unit means **decoding** its padding, and that path had never run:
  `normalize._fill_gaps` appended capstone's own instruction objects, whose length is `.size`
  and not `.length`, so the first byte it tried to fill raised `AttributeError`. It now decodes
  gaps into this module's `Instruction` (an undecodable byte advances one byte), and the check
  asserts instructions come out *inside* a gap - 13 of them in the 67-byte gap at
  `0x140005af4`, 520 for the unit overall.
* A side effect worth knowing: `decomp try`'s **original side** now works on a PE end to end -
  `try 0x140001d58` against any candidate decodes 766 instructions over the unit's 3567 bytes,
  binds 151 symbols, and reports the unit disagreement as a note. What is missing is only the
  candidate side (MS-3), which is exactly the split MS-0/MS-1 were built on.

Still open after MS-1, deliberately: `detect --range` still samples `.text` cut at every `ret`
(`toolchain.target_shape`), so it does not use the unit table yet; MS-4's shape profiles should
sample real units. *(Closed by MS-4: `target_shape` samples `.pdata` records through
`extract.pdata_records`.)*

**MS-2: put a compiler on the machine.** *Done 2026-11-04 - v141 14.12 plus a usable Windows
SDK; `Tests/tools/check_msvc_toolchain.py` exits 0.* The Windows SDK was the blocker earlier and
what unblocked it is §6.11 of Setup.md (msitools + two package names this driver had filtered
out).

What is on the machine (all re-runnable with `toolchains/install_msvc.py`, §6.10 of Setup.md):

```
cl      -> Microsoft (R) C/C++ Optimizing Compiler Version 19.12.25835.7 for x64
link    -> Microsoft (R) Incremental Linker Version 14.12.25835.7
lib     -> Microsoft (R) Library Manager Version 14.12.25835.7
dumpbin -> Microsoft (R) COFF/PE Dumper Version 14.12.25835.7
```

i.e. toolset **14.12**, the era `decomp detect` read off `notepad.exe` (§2) - reached with
`--major 15 --msvc-version 15.5 --host-arch x64 --architecture x64`, which is what §5 predicted
(`--msvc-version 15.5` → 14.12). `cl`'s own version is 19.12 and the toolset is 14.**12**: same
minor, different major, from VS2015 on. `cl /?` prints no banner - `/Bv` does; the other four
answer to `--version` as well as `/?`.

* **The default install is not the toolchain.** That channel resolves `VC.Tools.14.12` to 363
  packages / 2.1 GB because the VS2017 graph hangs the IDE shell under the toolset. Keeping the
  pinned toolset, its own CRT headers and x64 import libraries, and the Windows SDK gives 10
  packages / 485 MB (`install_msvc.py`'s `KEEP`). The versionless `Microsoft.VisualCpp.CRT.*`
  packages must stay out: they put a second, newer `VC/tools/msvc/14.16` in the tree, and
  `install.sh` picks the highest version that has bin+include+lib.
* **`--msvc-version 15.5` cannot be installed as written**: it pins Windows SDK 10.0.16299, which
  the 15.9 channel no longer serves ("WinSDK version 10.0.16299 not found / Available versions:
  10.0.19041"). Pass `--sdk-version 10.0.19041`.
* **The Windows SDK payloads cannot be extracted on this machine.** They are the one thing
  missing. `vsdownload.py` extracts them with `msiextract` (msitools) - not installable here, no
  root - and Wine 9.21's own `msiexec /a` stops at `InstallAdminPackage` with **1627** for every
  one of these WiX-built MSIs (`/i` returns 0 and installs nothing). The cabs cannot substitute:
  their entries are obfuscated (`cat<hash>`), so the file tree only exists in the MSI's
  `File`/`Directory` tables. `toolchains/msiextract.py` implements the `msiextract -C DEST
  package.msi` interface over `wine64 msiexec /a` - it is put on PATH by the driver and it does
  extract VC-era MSIs, just not these - so the remaining step is msitools, or an MSI reader.
  With `--no-sdk`, the driver leaves an empty `Windows Kits/10/{Include,Lib}` placeholder so
  `install.sh` still builds the wrappers, and `decomp check` reports that placeholder as not
  usable rather than as an SDK.
* **What the toolset proves now** (`Tests/tools/check_msvc_toolchain.py`, exit 2 while the SDK is
  a placeholder, 0 when it is real): identity of cl/link/lib/dumpbin by banner, all four in the
  same toolset family, `/usr/bin/link` refused (§1 - measured: it is GNU **coreutils** `link`
  9.12, not binutils `link`, which does not exist here), `clang-cl` named as clang, then a probe
  compile at `/Od` and `/O2` built through `decomp.compile.build()` with the variant's own flags.
  Both produce x86-64 COFF that `extract.CandidateObject` opens with no error, each function in
  its own `.text$mn` - MS-3's premise, measured - and the two objects differ.
* **`/Tp`/`/Tc` are needed for sources, not just for odd suffixes.** `driver_form()` now names the
  language: `cl` reads a bare `/home/…/x.cpp` as an option, and the msvc-wine wrapper rewrites
  `/t/x…` by stripping two characters, so an absolute path as a bare argument cannot work.
* **MSVC/PE flags and variants**: `Tests/project.toml` gains `msvc-o0`/`msvc-o2` (`cl`, `/Od`
  and `/O2`, `/MT` so the reference binary runs under Wine with no VC redist installed) and
  `mingw-o0`, which is PE plumbing only and labelled as such (§1). `Tests/eval.py` gained the PE
  half of the answer key - `.pdata` read with stdlib only, names from COFF symbols or from the
  map file it asks `link` for (`/MAP:<binary>.map`, not from the config, since only the build
  knows where the binary is), a Wine runner for the reference binary, and no `strip` for a PE,
  which has no symbol table to strip. Measured on the MinGW PE build: `answer key: 89 units (89
  markers in source)` and `selfcheck` → `89 cases, 0 failures`. One real finding there: **a
  GCC-built PE splits `.pdata` across block groups of one function**, so almost no record starts
  at a named symbol; eval.py says so and falls back to symbol spacing for the extents. The MSVC
  case (§4, one record per function) is what the exact form is for - `notepad.exe` still yields
  exactly 186 units through this code.

Measured now, with the real thing (all of it in `check_msvc_toolchain.py`, groups 3 and 4):

* `cl /MT /O2 hello.cpp` → a PE → `wine64` prints `sum=135`. The whole path - driver, linker,
  CRT, Wine - works with stock flags, no `/NODEFAULTLIB` or other workarounds.
* The gate's probe **links and runs** at /Od and /O2 (an entry point is compiled separately:
  the shape probe has no `main`, which is what makes it useful for shapes and useless for
  linking). `eval.py build/selfcheck --variant msvc-o0` and `msvc-o2`: **answer key 89 units
  (89 markers), 0 unresolved, `selfcheck` 89 cases 0 failures** for both.
* `.pdata` is **not** complete for an /Od build, and that is a correction to §4: 12 of this
  benchmark's 89 units have no unwind record at all. The missing ones are exactly the functions
  the compiler gave **no prologue and no epilogue** - they only write the caller's shadow space,
  never touch `rsp`, call nothing, and have a single `ret`, so there is nothing for unwind info
  to describe and `link` emits neither `$unwind$…` nor `$pdata$…` for them. A four-function
  control separates the two cases cleanly (`int other(int a,int b){return a-b;}`: no record;
  `int leaf_no_frame(int a,int b){return a<b?a:b;}`, which spills to a frame: one). An /O2 or
  /GL build gives every function a frame or inlines it, which is why notepad.exe has 186 of
  186. eval.py now uses `.pdata` first and adds the named functions it does not describe, with
  the count printed.
* The MSVC map parser needed a real map to get right: a "Publics by Value" row has **no
  section-name column** (`0001:` indexes the map's own merge groups - `.text$mn`, `.text$mn$00`
  and `.text$x` are all group 0001 here), and the `Rva+Base` column is already final, image
  base included. Rows of group `0000` are the `<absolute>`/`<linker-defined>` symbols.
* `cl` argument order is now asserted rather than assumed: everything after `/link` goes to the
  linker, so `/Fe:` and the objects come **before** it (`D8003: missing source filename` is what
  happens otherwise, and the gate had that bug until it could run).
* The benchmark's own headers are a portability case: `TestFunctions/math.h` on the include path
  shadows the C runtime's `<math.h>` for `cl`, which searches the `-I` directories for angle
  brackets; GCC's `<cmath>` escapes them with `#include_next`. eval.py puts only the top source
  directory on the path now, and says why.
* `decomp detect <PE> --probe` works: it compiles the shape probe with `cl /Od|/O1|/O2 /Gy`
  through the wrappers and reads the COFF objects. A COFF object has no symbol sizes, so its
  bodies are its `.text$…` sections (that is what /Gy is for here). On notepad.exe it answers
  `optimize = 0` from 9 bodies cut at `ret` - the sample, not the answer: MS-4 should score
  against real `.pdata` units, and -O1/-O2 of v141 are weakly separable at best.

Deliberately not here: reading COFF *candidate* symbols, which is MS-3 (the probe objects above
are the evidence for it).

**MS-3: the COFF candidate side - this is where `try` starts working on PE.** *Done
2026-11-05.* `extract.CandidateObject` has a COFF branch: sections keyed by file position, a
symbol table read for names and types only, extents derived (COMDAT section, or next function
symbol in the section minus `cl`'s inter-function padding), and relocations read per section with
the value in the bytes as the implied addend. `Tests/tools/check_coff_candidate.py` is the gate:
**89/89 units scored, mean 100.00 %, 88 of 89 past the gate, 54 byte-identical**, and the one
that is not is STRUCT-24, whose reason is MS-5 (below). Group 1 of that script is MS-3's actual
claim, measured before any candidate is judged: for **all 89 units** of the benchmark, the extent
the tool reads out of the `.obj` equals the extent the *original* side compares (`.pdata` where
the image has a record for the function, the analysis' body where it does not). Group 3 re-runs
the wrong candidates of `Tests/examples/candidate_math_bad.cpp` built by `cl` - all three are
still reported as the kind of wrong they are, with the same judgement as the ELF gate; only the
category sets differ, because `cl` at `/Od` aligns the two streams differently than GCC.

What the format actually is, measured on the benchmark's own `Tests/build/msvc-o0/*.obj`:

* **A COFF object may give several sections the same name.** `link` takes one COMDAT per
  `.text$mn` and there are five in `math.obj` (14 695, 60, 29, 37, 14 bytes), plus repeated
  `.pdata`/`.xdata`. A name cannot be the key for anything: `CandidateObject` now keeps sections
  in file order (`_section_order`, `_section_of_index`) and only disambiguates a *duplicated*
  name (`.text$mn#1`), so an ELF key stays exactly the section name it always was.
* **`lief`'s `relocation.symbol_idx` is the raw COFF record index, auxiliaries included; its
  `binary.symbols` has folded the auxiliary entries away.** Indexing the list with it gives every
  call in the object the wrong callee: the `AMD64_REL32` of the self-recursive call in
  `FibonacciRecursive` names index 251, which is that function in the file and
  `?SolveQuadraticRoot@…` ten symbols into LIEF's list (`dumpbin /disasm` says `?FibonacciRecursive`,
  and it is right). The index has to be rebuilt by walking the table and adding each entry's own
  `auxiliary_symbols` count - `_coff_symbol_table`. This one bug was worth 12 units.
* **A COFF symbol names no size and no function.** LIEF reads the type bits as `is_function`
  (`DT_FUNCTION`), and the extent comes from the section: for a `/Gy` COMDAT the section *is* the
  function (exact, better than ELF's `st_size`), and otherwise the next function symbol in the
  section, **minus the trailing `int 3`/`nop` run** - `cl` aligns functions to 16 bytes, so
  `AbsDiff` is 49 bytes and its next symbol is 64 along. Cutting that run by counting filler bytes
  is wrong: 12 units have a last real instruction whose encoding ends in `0xcc`/`0x90` (measured),
  so `_code_extent` decodes and cuts at the last instruction that is not padding. That is exact for
  all 89. The object's own `.pdata` is *not* a usable extent source here: its record fields hold
  the section-relative offsets (a COMDAT's reads `0x0, 0x3c, 0`) and its relocations name the
  section and `$LN` labels, so nothing there identified a unit exactly; the image's `.pdata`
  (MS-1) remains the one that does.
* **A COFF relocation has no addend field**, only "fix the field at this offset against this
  symbol", so the number already in the bytes is the implied addend (that is why a `.pdata` record
  reads as it does). Widths come from the relocation type (`_COFF_FIELD_WIDTH`) when LIEF does not
  fill `size`.
* **A COFF relocation that names a symbol never means "the object at this offset in the
  section".** The ELF rule (a relocation against a section symbol carries the offset inside it as
  the addend) misapplied to `strncpy`, a CRT import, and paired the call with whatever symbol sat
  at offset 0 of `.text$mn`. In COFF only a *nameless* relocation is a section-relative
  reference; a named one resolves through the symbol - which is also why the section of the named
  symbol is taken from the table index rather than from the name.
* **An object types its undefined externals, and that says whether a reference reaches a
  function or data.** `/GS` code reaches `__security_cookie` through a rip-relative slot; as an
  "external" it became a symbol token that could not pair with the data object the image has
  there, and it cost the string/struct units. `Ref.kind` now follows the COFF type.
* `cl` **does not search the including file's directory for `<angle>` includes** - measured:
  `#include <a.h>` in a file next to `a.h` is "Cannot open include file". So
  `driver_form` must not add each source's own directory as `/I` for an MSVC driver: that puts
  this project's `math.h` where the C runtime's `<math.h>` is looked for and the CRT headers fail
  to build (the same trap MS-2 found for `eval.py`; `Tests/project.toml`'s `include_dirs` now
  lists only the top source directory and says why). Quoted includes still resolve - `cl` searches
  the includer's directory for those.
* Ghidra's invented names are only synthetic if you recognise them: `s_<literal>_<address>` with a
  9-digit PE address slipped past the `{4,8}`-hex-digit pattern, so a PE's string literals counted
  as *named* objects and every reference to one was reported as a relocation difference. The
  pattern now covers an address of any realistic width.
* `--fn` accepts the identifier part of a decorated name (`?AbsDiff@CMathTests@@SAHHH@Z` is found
  by `AbsDiff`), which is what a model reading a source file knows. The decorated form stays the
  comparison key: `c++filt` cannot read MSVC names (§8).
* **Byte-identity is still 54 of 89, and that is the honest number.** A `.o` keeps a
  `00 00 00 00` displacement where the link writes the final one, so a unit that reaches anything
  outside itself cannot be byte-equal to the linked image - at any `-O`, for either format. The
  instruction stream and the symbol tokens are what is compared; `bytes_equal` is reported, not
  required.

STRUCT-24 is the one unit the untouched source does not pass, and it is MS-5's job: the `.obj`
names all three type descriptors by symbol (`??_R0?AVCVehicleEntity@`, `??_R0?AVCEntityBase@`,
`??_R0?AVCCharacterEntity@`), while the target side can only repeat the *data type* Ghidra
applied to all three (`RTTI_Type_Descriptor`) - nothing on the target side says which descriptor
is which, so no token pairs. MS-5's model of `RTTICompleteObjectLocator`/`.?AV…` is what would
name them - and it does: that unit now scores 100.00 % and `msvc-o0` gates 89 of 89 (see MS-5). **Measured and not gated: `msvc-o2`** (`--variant msvc-o2`, 89/89 scored, **91.40 % mean, 74 of
89 past the gate**, extents agreeing for 81 of 89). Two things happen at `/O2` and neither is a
COFF-reading problem. `/O2` implies `/Gy`, so *every* function is its own COMDAT - all 223
candidate functions in this benchmark's three objects are COMDATs, which is the exact-extent path,
and it is the /Od build that is the awkward one. And `/O2` also splits a function into hot and
cold blocks, each its own COMDAT, and `link` emits a `.pdata` record **per block**: for 8 units the
record the analysis' address lands on is a block of the function, not the function (Crc32OfBuffer's
unit is 5 bytes, Base64Encode's 4, TextToIntList's 20, EntityHealthTotal's 28) while the
candidate's entry COMDAT is the whole hot block (291, 463, 187, 105 bytes). That is Phase 5's
finding mirrored: at `-O2` in ELF the file's table is right about a *partition* and the analysis'
ranges hold the other part, so `original_function` joins them; here the file's table describes
blocks and the candidate holds the function. What would close it belongs with MS-4: block groups
of one function (`.text$mn`, `.text$mn$00`, `.text$x` - the same grouping MS-2's map parsing
already had to see through) joined into one unit, exactly as a `.cold` partition is joined today
*(asked of MS-4, and still open there: it needs a reader for the chained `UNWIND_INFO` that
names the next block - see MS-4's closing note)*.
Until then the variant is measured, reported, and not held to a number.

A second `/O2` finding, and a warning for anyone who scores at `/O2`: **the negative controls stop
meaning what they do at `/Od`**. `LengthOfProbe` - a counted loop where the original has a sentinel
test - scores **100 %** at `/O2`, and the other two probes report categories unrelated to what is
wrong with them. The optimiser erases the difference between two source shapes, so a *wrong*
candidate can be indistinguishable from the right one. That is not a defect in the report; it is
what a byte gate at `/O2` can promise, and it is why the wrong candidates are held to their
categories for `/Od` only.


**MS-4: say what an MSVC build is.** *Done 2026-11-05.* `Tests/tools/check_msvc_detect.py` is
the gate (six groups; exit 2 when there is no `cl` to probe with, 0 here). What it asked for and
what it got:

* **Rich `build` → toolset, with the tool-id meanings.** The product ids are Microsoft-internal;
  the table `decomp.toolchain` now carries is the one RichHeaderResearch publishes
  (`spoof_check.py`), and the parts the tool relies on are *measured on this machine*: **id 258
  ("Linker1400") is link.exe's own record and its build number is the fourth component of that
  linker's version** - `link.exe 14.12.25835.7` writes build 25835, and the gate asserts that
  pair, so the table is anchored on a measurement and not on a lookup. `rich_identity` reads the
  toolset from that record and `toolset_identity` **compares it** with the optional header's
  linker version: on `notepad.exe` build 25711 reads as 14.12 and the header says 14.12, so the
  report says the two readings agree; a disagreement is reported as "one of these headers was
  rewritten after the link", which is the only useful thing to say about it.
  *The reason the identity comes from id 258 and not from the largest build number*: id 147
  ("Implib900", the import-library stubs) carries **build 30729 in the Windows OS binary of 2018
  and in a file this machine linked today with 14.12.25835** - that number identifies nothing.
  Id 1 ("Import0", always build 0) is recorded as a count. Both are excluded from the identity.
* **The compiland counts, which are a second reading of `/GL` and of the language mix.** The
  front-end records are per compiland: `notepad.exe` reports 23 C, 5 C++, 3 asm and **25
  Utc1900_LTCG_C**, so `/GL` is confirmed from the object side, independent of the POGO
  directory, and it survives stripping. Caveat, measured: a hello-world built here at `/MT`
  reports *179* C++ records, because the CRT objects the link pulled in are counted too - so the
  count says C++ is in the image, not how much of the program is.
* **Language from decorated names, runtime from the import family.** `?terminate@@YAXXZ` in an
  import table is a C++ name, so `language = c++` is claimed now, with `language_proof` naming
  the evidence (MS-0 left it unset because an `msvcrt.dll` import proves nothing; a *decoration*
  does). A PE's import *and export* names are read into the same carrier as an ELF's `.dynstr`,
  because that is the only place a stripped PE keeps names. `msvc_runtime` classifies the CRT: the
  UCRT (`api-ms-win-crt-*`, `ucrtbase`), the v14x `vcruntime`/`msvcp` pair, the per-version
  `msvcrNN` (which toolset), and the downlevel `msvcrt.dll`; **no CRT DLL imported = the CRT is
  in the file = `/MT`** - measured against a `/MD` and a `/MT` build of the same source, which
  differ exactly that way. With a static CRT there is no decorated import to read, and the
  front-end records become the (coarser, labelled as such) C++ evidence.
* **`/std:` honesty.** MSVC decoration encodes no standard level, so `msvc_std_evidence` names
  what the toolset does bound: the level it defaults to (c++14 for any v14x) and the levels it
  has a switch for (c++17 from 14.16, c++20 from 14.2x) - labelled "proved by the toolset, not
  by a name" in the report and in the config it writes.
* **`build_flags` can say the flags instead of collapsing them**: `/Od`|`/O1`|`/O2` (three, not
  two), `crt` → `/MT`|`/MD`, `guard: false` → `/GS-`, `ltcg` → `/GL` **with `/LTCG` added to
  the link**, `comdat` → `/Gy` (opt-in, never implied, because it changes where a candidate's
  extents come from - MS-3), `inline`, `fp`, `/std:`. `Tests/project.toml`'s existing MSVC
  variants produce byte-identical flag lists, so MS-3's numbers still stand. `detect --write`
  on a PE now also writes the toolset with both readings, the era to install (`--major 15
  --msvc-version 15.5`), `ltcg = true`, and `crt = "md"|"mt"` from what the file imports.
* **MSVC shape profiles.** `FEATURES_MSVC` replaces the Itanium set for an MSVC target/probe -
  frame pointers, `endbr` and the `%fs:` canary are all identically zero on both sides of a PE,
  so they carry no signal. What does, measured with this v141 `cl` over `PROBE_SOURCE` (shares
  of bodies, or of instructions):

  | level | locals off `%rsp` | args to home slots | `/GS` guard | calls/ins | xmm |
  |---|---|---|---|---|---|
  | `/Od` | 0.537 | **1.00** | 0.111 | 0.011 | 0.047 |
  | `/O1` | 0.083 | 0.11 | 0.111 | 0.010 | 0.042 |
  | `/O2` | 0.075 | 0.00 | 0.111 | 0.003 | **0.308** |
  | `notepad.exe` | 0.118 | 0.037 | 0.156 | 0.087 | 0.002 |

  `/Od` against the optimising levels is a fourfold gap and is what `detect` claims; `/O1`
  against `/O2` is reported as a **class** (`level_class = /O1|/O2`), because the feature that
  separates them here is `xmm` - whether `/O2` vectorises depends on whether the program has a
  loop it can vectorise, which is a property of the code and not of the flags. On `notepad.exe`
  (an `/O2` `/GL` build) the ranking is `/O1` 0.268, `/O2` 0.514, `/Od` 1.548 and the answer is
  printed as "optimised cl code, `/O1` or `/O2`" - which is the honest ceiling for a GUI binary
  with no float loops in it, and the tool says so rather than picking one. `/GS` on is reported
  from the shape (16 % of this file's bodies check the guard).
  Two bugs this found: `probe_signatures` keyed a COFF object's sections **by name**, and with
  `/Gy` every function is its own `.text$mn`, so the probe had been measuring *one* body per
  level (9 now); and the sample itself, see the next item.
* **Sampling real units, which MS-1 had left open.** `target_shape` samples the file's own
  function table when it has one: for an x64 PE that is `.pdata` (`extract.pdata_records`, the
  same reader `try` uses), so `detect --range` and the shape score measure *units*, not a
  disassembly cut at every `ret`. On `notepad.exe`: 135 of the 186 units are in the sample band
  (mean 36.7 instructions), and inside `0x140012000-0x140018000`, 52 of the 75 records there -
  never more bodies than the file names. **The ELF path did not move**: it still samples the
  ret-cut stream and still scores the Itanium features, and group 6 of the gate asserts both
  (as does `check_phase3_discovery.py`, unchanged).

Not done, and it is not a `detect` problem: the `/O2` hot/cold **block-group join** MS-3 left
here (joining `.text$mn`, `.text$mn$00`, `.text$x` into one unit, the mirror of Phase 5's
`.cold` join). Both readings now exist - the image's `.pdata` names the blocks and the candidate's
COMDATs name the function - but joining them needs the unwind chain (a chained `UNWIND_INFO`
carries the target block's RVA), which is a reader of its own. `msvc-o2` therefore stays
measured-and-not-gated at 91.40 % / 74 of 89 with its reason named (MS-5 has since closed one of
those 14 - the `dynamic_cast` unit now passes at `/O2` as well - so it is 75).


**MS-5 (after Design-Plan Phase 4): MSVC C++ structure.** *Done 2026-11-05.* The plan was to do
this as a parallel model, not a redesign of Phase 4, and that is what it is: `structures.Recovery`
now picks an ABI (`_choose_abi`) and has a second reader for the RTTI graph
(`_msvc_read`/`_msvc_typeinfo_at`/`_msvc_chd`/`_msvc_vftable`) next to the Itanium probe.
`Tests/tools/check_msvc_structures.py` is the gate; six groups, all passing. The vftables in a PE
are `.rdata` absolute qwords - readable straight from the file, no relocation addends, unlike a
PIE's `.data.rel.ro` - and that part turned out to be the easy half.

* **Choosing the model is a fact about the file, not about the container.** The build note comes
  first: `compiler_hint` (the Rich header / `.comment` the analysis read) is evidence about the
  target. The variant the analysis was configured with comes second, because for a proprietary
  binary that is a stand-in guess - `Tests/Proprietary/deadrising2.exe` is recorded under a
  `g++ -m32` variant and reading it as Itanium found 6 classes where MSVC's own records name
  769. With neither, a PE is tried as MSVC and, if the file carries no `.?AV` string, the note
  says so and the Itanium model is tried in its place. Group 6 asserts the §1 trap the other way:
  `Tests/build/mingw-o0` (a PE built by `x86_64-w64-mingw32-g++`, no build note of its own) is
  read as Itanium and its three classes come out with their bases.
* **The entry point is the type-name string.** `.?AVCVehicleEntity@@` is the decoration for a
  class named `CVehicleEntity` (`.?AV` class/struct, `.?AU` union, `.?AE` enum class, `.?AX` enum,
  `?$…` a template). Everything else hangs off it: the **TypeDescriptor** is the 16-byte header
  (x64) whose first qword is the CRT's own `type_info` vftable, followed by the string. The
  **RTTICompleteObjectLocator** carries signature, *offset of this vftable from the top of the
  object*, `cdOffset`, the TypeDescriptor, and the **RTTIClassHierarchyDescriptor**; the CHD's
  array of **BaseClassDescriptor**s is what names the bases, and each BCD's two numbers are the
  subobject displacement and its vftable offset - the amount a thunk adjusts `this` by. A locator
  is only a locator if its CHD contains a BCD for that same descriptor; that test is what tells a
  locator apart from the base-class descriptors that also point at it.
* **Field widths come from the target, not from the ABI document.** x64: the COL's five fields are
  4-byte **RVAs** and the vftable slots and the descriptor header are absolute **qwords**. A
  shipped 32-bit MSVC binary (`deadrising2.exe`) uses absolute 4-byte addresses for all of it.
  The reader probes once per target, records which mode it found, and says which in the note -
  "4-byte RVAs" for the benchmark, "absolute 4-byte addresses" for the game. Group 4 requires that
  the second case stays in the report.
* **Where a vftable begins is structural.** The slot that holds a pointer to a locator *is* the
  boundary: the methods start at the next slot. There is no offset-to-top in MSVC's vtable, so the
  benchmark's classes have **3 slots (deleting destructor, `GetHealth`, `Classify`)** where the
  same source under g++ gives 4 (the D1/D2 pair). Group 2 asserts the slot count, that every slot
  points at the answer key's real method, the bases, and the member offsets - `+0x8`/`+0xc` for
  `CEntityBase`, `+0x10`/`+0x14` for `CVehicleEntity`, `+0x10` for `CCharacterEntity`, which is
  what the Microsoft x64 layout of `structs.h` says.
* **`this` is `%rcx`, and the frame is not stable.** Field recovery seeds `this` from `%rcx` on
  MSVC x64 (SysV uses `%rdi`; 32-bit MSVC thiscall is `%ecx`, and 32-bit *GCC* passes it on the
  stack at `8(%ebp)`). At `/Od` `cl` spills it to `8(%rsp)`, then `sub $0x28,%rsp`, then reloads
  `0x30(%rsp)` - so a frame slot is an offset from one *stack pointer value* and has to move when
  `%rsp` moves. Doing that unconditionally broke the `-m32` Itanium case, which addresses its
  frame through `%ebp`: slots are now tracked per frame register.
* **Destructors come in two forms and the vftable says which.** The slot holds the *deleting*
  destructor; at `/Od` it writes no vptr itself - it calls the one that does, then frees. A derived
  class with nothing of its own to clean up has a destructor that writes no vptr at all: `cl` emits
  `??1CVehicleEntity@@UEAA@XZ` as a stub whose only call is the base's. So the rule follows the
  call chain (bounded, 3 hops) from the slot to a function that stores this class's vptr or a
  base's. Two limits came out of that and are stated rather than papered over: `/Od` `/MT` builds
  fold identical destructors (`??_ECVehicleEntity` and `??_ECCharacterEntity` are one function
  referenced by both vftables - the tool says the destructor slot is shared instead of naming a
  destructor), and at `/O2` both derived constructors are the same folded address.
* **A pure slot is only claimed when it is named.** `/MD` builds import `_purecall`, and matching
  that name is decisive. `/MT` links it in and leaves it unnamed, and the shape that was going to
  stand in for it - the same target in two vftables, reached by no call - is *also* exactly what a
  folded destructor looks like: it called `CVehicleEntity`'s deleting destructor a pure virtual.
  That heuristic is gone; unnamed cases get the limit stated instead.
* **One object, one name, both sides.** `normalize.msvc_object_name`/`msvc_type_symbol` map
  `??_R0?AVX@@@8` ↔ `typeinfo for X`, `??_R1A@?0A@EA@X@@8` ↔ `complete object locator for X`,
  `??_7X@@6B@` ↔ `vtable for X` (`??_R1`'s four fixed numbers - `A@?0A@EA` - are between the
  record kind and the name, so those symbols are matched whole). That is what lets the
  candidate-side relocation against `??_R0?AVCVehicleEntity@@@8` pair with the target-side
  descriptor: **STRUCT-24 scores 100.00 %** and `check_coff_candidate.py` now gates **89 of 89**
  units at `msvc-o0` with `KNOWN_GAPS` empty - MS-3's one gap is closed.
* **At the size of a shipped binary.** `deadrising2.exe` (32-bit, Havok): 770 type descriptors,
  685 locators, 685 vftables, **769 classes** in ~9 s, correct bases (`hkReferencedObject` →
  `hkBaseObject`), 107 nested names decoded from MSVC's innermost-first `.?AUSimpleMapping@hkaSkeletonMapper@@`
  to `hkaSkeletonMapper::SimpleMapping`, and 64 template names kept verbatim because they are not
  one identifier. `notepad.exe`, which has no `.?AV` string anywhere, stays at 0 classes and says
  why (group 5).
* **Two header bugs this found**, both only visible at that scale: a 16-byte `movaps` through
  `this` was declared `float`, so the class body contradicted its own `static_assert`; and a
  non-identifiable name was emitted in a *base list* (`public ?$BasicArrayImplementation@E$00`).
  A member is now typed as wide as the access that proved it, an unprovable lower bound is said in
  a comment instead of asserted, and undeclarable bases stay in the comment. `types.h` for the
  benchmark PE (140 lines) and for `deadrising2.exe` (27,796 lines) both pass `g++ -fsyntax-only`.

Not done, and not hidden: field recovery at `/O2` is partial (`m_speed` at `+0x14` is not seen -
the accesses are inlined into a caller and `this` stays in registers), so `msvc-o2` stays
measured-and-not-gated, as in MS-3; multiple inheritance is read from the BCDs (displacement and
vftable offset) but the benchmark has no MI class to exercise it, only the shipped binary; and
while reading the MinGW PE it became clear the *Itanium* model seeds `this` from `%rdi`, which is
wrong for x86-64 MinGW (`%rcx`) - its field offsets come out empty there, and that is a Phase 4
gap, not an MS-5 one.

Dependency order: **MS-0 → MS-1** is self-contained and improves the tool on this very file with
no compiler at all. **MS-2 → MS-3** is the path to `try` on PE. **MS-4** and **MS-5** are
independent of each other. Nothing here changes the ELF path.

## 8. Traps, written down before the work

* LIEF 1.0 PE/COFF spellings: `section.characteristics`, `pointerto_raw_data`,
  `sizeof_raw_data`, `numberof_relocations`, `binary.debug`, `entry.count`,
  `header.machine`, `binary.imagebase` (not `image_base`). COFF has no `binary.format` and no
  `identity_class` in its header - it says `machine` and `kind`; `lief.parse` auto-detects
  `.obj` files and returns a `COFF.Binary`.
* In this LIEF build (PyPI 1.0.0-d05b3499b) `binary.debug_info` is **`None`** - it is the
  abstract DebugInfo, and the extended parser is not compiled in (it prints "Debug info not
  available for this build"). The PE debug directory is `binary.debug`, which does work and
  yields `CodeViewPDB` / `Pogo` / `Repro` objects. Ask for both names, in that order
  (`toolchain._debug_records`).
* `.pdata`, PDB addresses and PE relocations speak **RVAs**; Ghidra, objdump and this tool's
  cache speak `imagebase + RVA`. Forget the bias once and everything is "no such function" -
  and note that it is needed in three places: the build note, the section map used to read
  bytes, and the `-O` shape sample's `--range` filter. (A unit table's rows are written in the
  **analysis'** addresses, i.e. after the bias, so the cache and the analysis meet without one
  more conversion: `TargetImage.units` is in the file's addresses and `analysis_units()` is the
  biased copy.)
* A PE section's `size` is its virtual size, its `content` only the bytes the file initialises -
  iterating a table by `size` walks padding that is not in the file (MS-1). And a cached
  function's `bytes` is the concatenation of its ranges, so a gap inside a body is absent from
  it, not zero-filled.
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
