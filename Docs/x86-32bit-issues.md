# x86 (32-bit) toolset: issues found while decompiling a real 32-bit MSVC binary

Started 2026-11-08. This is the log for the run the user asked for: decompile
`Tests/Proprietary/4.1.1_wrar411.exe` with the 32-bit toolset, 90 % byte-match bar, and
only fix tool problems if they are written down here.

Read it as: **symptom → evidence → cause → what I did → status**. Numbers are from the
files on disk, not from notes; where an earlier note was wrong I say so and correct it
(entry 12), because those notes get quoted back later.

Toolchains present while these were measured: `toolchains/msvc` = **v141 only**
(`bin/x86/cl` → `C/C++ Optimizing Compiler 19.12.25835.7`, Visual Studio 2017), 32-bit PEs
run through wibo (`toolchains/wibo/wibo`) or the repository `.wine` prefix. No v90.

---

## 1. The 32-bit "program" was an installer, and nothing in the tool noticed

`4.1.1_wrar411.exe` is 1,506,653 bytes. `decomp analyze` analysed the first 103,424 bytes
(the PE: `.text` 0x401000-0x412000, entry 0x40a93a) and reported a 346-function program.
The other 1,403,229 bytes are a **RAR 4 archive appended as an overlay**:

```
$ 7z l Tests/Proprietary/4.1.1_wrar411.exe
Type = Rar   Offset = 103424   Characteristics = Lock Solid   Solid = +   Blocks = 1
33 files, 4069697 bytes unpacked (1397679 packed)
```

So the file is the official WinRAR 4.11 32-bit installer: an SFX module (`sfxrar32`, PDB
`d:\Projects\WinRAR\SFX\setup\build\sfxrar32.pdb`) followed by the program directory. The
program to decompile is **`WinRAR.exe` inside it** (1,150,464 bytes), which is now unpacked
at `Tests/Proprietary/wrar411/`. The user's request (m00225) was the same conclusion.

What I did: unpacked the payload, retargeted the run at `WinRAR.exe`, kept the SFX module's
config and analysis for later (it is a small, self-contained RAR reader - a warm-up target).

Status: **tool-side gap, not fixed.** `decomp detect`/`analyze` should report a trailing
overlay it did not analyse ("this PE has 1.4 MB of appended data; it is a RAR SFX package -
the program may be inside it"). For 32-bit Windows shareware that case is common, so it is
worth having in the x86 plan (Docs/MSVC-x86-Plan.md) rather than in the target folder.

## 2. `link.exe 9.0` has no toolset-table entry, so the era cannot be named (fixed in §14)

`decomp detect Tests/Proprietary/wrar411/WinRAR.exe` printed:

```
  linker       MSVC link.exe 9.0
  toolset      MSVC link.exe 9.0 (no toolset table entry) - link.exe 9.0
  build notes  codeview:d:\Projects\WinRAR\build\winrar32\Release\WinRAR.pdb
               guid=8ce42f70-d7b9-4896-ab25-3881a14b7227 age=1;
               rich:id=145:build=30729:1; rich:id=132:build=30729:185;
               rich:id=131:build=30729:167; rich:id:150:build=20413:10; ...
```

The toolset table starts at v100, so everything v80/v90/v100-era falls into "cannot name".
The **Rich header names the compiler directly** - build `30729` on 185 + 167 + others =
`cl 15.00.30729` = **Visual C++ 2008 SP1 (toolset v90)**; the stray `build=20413` records
are VC2005-SP1-era objects pulled in by the same link. That is how the era was determined
here, and it is a reading of the tool's own output, not a feature.

Status: **not fixed.** Follow-up: add v80/v90/v100/v110 rows (linker version → toolset →
`_MSC_VER`) to the table, and/or have `detect` surface `rich:` build ids as a first-class
"compiler build" row instead of burying them in `build notes`.

## 3. Every `-O` ranking in this run is wrong-era (the era gap) (resolved by §13)

With only v141 installed, `detect` measured this file against `bin/x86/cl` 19.12:

```
  toolchains/msvc/bin/x86/cl   -O2  distance 0.526  next 0.736
  toolchains/msvc/bin/x86/cl   -O1  distance 0.736  next 0.736
  toolchains/msvc/bin/x86/cl   -O0  distance 3.506  next 3.506
```

Those numbers describe *this* toolchain, not the one that made the file; `detect` says so in
the same block. The honest consequence for the run: the `exact` byte-match tier is out of
reach for `WinRAR.exe` until a v90 compiler exists here, and the 90 % bar must be measured
against the right compiler before it means anything.

What I did: the target config records the bar and the cap separately rather than hiding it -
`threshold = 90.0`, `[gate] require = "semantic"`, and three variants
(`msvc-o0-x86`, `msvc-o1-x86`, `msvc-o2-x86`) so the optimisation choice stays auditable.
See `Tests/Proprietary/wrar411-recovered/project.toml` (its header explains each flag).

Status: **blocked on the toolchain**, not a code defect. Instructions to unblock: §"What to
download" at the end of this file.

## 4. The shape probe is weaker for a file whose functions are not in the headers

`detect` samples "the executable sections, cut at every `ret`" when it has no function table:
for this file it sampled 363 bodies, mean 30.6 instructions, and reported

```
  frame 0.006  framemem 0.013  poprbp 0.174  spill 0.000  subrsp 0.039  gs_frame 0.033
  sample better: the cached analysis is available: pass --sample <name> to sample its
                function boundaries instead of this ret-cut stream
  /GS: the stack guard appears in 3% of the sampled bodies ... that share is a floor, not the share
```

A `ret`-cut stream cuts prologues off some bodies, so `/GS` (3 %) under-reports and the
frame features are biased. It also cannot see the C++ exception prologues that are the
strongest era markers.

What I did: run `decomp analyze` first (it is needed anyway) and pass `--sample` when the
probe matters. Status: **not fixed.** Follow-up: `detect` should prefer the cached
analysis's boundaries automatically whenever one exists, and say that it did.

## 5. Correct x86 behaviour worth recording (no action)

Three things the 32-bit path got right on a real target - these are the X86-1/X86-2
acceptance signals:

- driver resolution picked the x86 driver by *target* (`probe cl -> toolchains/msvc/bin/x86/cl`)
  and explained why (the wrapper dir is not on PATH), and it *ran* that 32-bit `cl` to read
  its banner (19.12.25835.7) on Linux;
- `/guard:cf is x64-only: nothing is claimed about it for a 32-bit image` - no invented flag;
- `63% of the sampled bodies end in 'ret $N'` → it identifies stdcall/thiscall (WinAPI and
  C++ members) without mistaking it for an optimisation-level signal, and
  `almost no sampled body sets up a %ebp frame: this is not /Od code on a 32-bit target`.

## 6. `detect` calls a non-relocatable image "PIE"

`pefacts.py` (in the target's `tools/`) reads the optional header straight:

```
WinRAR.exe: linker 9.0  imagebase 0x400000  entry RVA 0xb3f66  subsystem 2
            dllcharacteristics 0x8140   (= TERMINAL_SERVER_AWARE | NO_ISOLATION | FORCE_INTEGRITY)
```

`0x0020 DYNAMIC_BASE` is **clear**, so the image is not ASLR-capable - yet `detect` printed
`object  EXE (PIE)`. It infers PIE from the presence of a `.reloc` section; `link.exe`
emits `.reloc` unless `/FIXED`, so for 32-bit MSVC output that test is wrong (and it feeds
anything that later decides whether relocations must match).

Status: **documented, not fixed.** Small, testable fix: use the `DYNAMIC_BASE` bit (and
treat a bare `.reloc` as "relocations present, not position-independent").

## 7. No PDB anywhere, so names must be reconstructed - and the binary gives a lot

`detect` printed the CodeView record and built the symbol-server key
(`WinRAR.pdb`, guid `8ce42f70-d7b9-4896-ab25-3881a14b7227`, age 1). Both URLs answer 404:

```
https://msdl.microsoft.com/download/symbols/WinRAR.pdb/8CE42F70D7B94896AB253881A14B72271/WinRAR.pdb  → http 404
```

WinRAR is not on Microsoft's symbol server, and the shipped file carries only the debug
*directory* (1 entry, type 2 = CODEVIEW) - no stream, so no public symbols.

What is still in the binary, and what the recovered names will follow (see the target's
`TARGET.md` for the full list): registry/setting value names WinRAR itself uses
(`ArcHistory`, `DialogEditHistory`, `Extraction`, `CustomExt`, `ExternalViewer`,
`ShellExt`, `OpenSFX`, `SFXLocal`, …), dialog resource names it loads by string
(`RENAMEDLG`, `CREATEVOLDLG`, `FAVORITESDLG`, …), and the RAR-format field names from
`TechNote.txt`, which ships *inside the same package*.

Status: no fix needed; the naming rule for the run is "names the binary can be shown to
use", recorded per function.

## 8. A 32-bit PE has no unit table, so matching is per-function only

For this target the analysis cache has `units` = **0 rows** (`meta.unit_source = None`):
i386 PEs carry no `.pdata`/unwind table, so MS-4's unit rows and shape profiles have nothing
to read. Everything in this run is scored per function.

Status: matches the known MS-4 follow-up (scratchpad, 2026-11-04). The i386 unit source has
to be "function bodies + `.reloc`-adjacent data", not `.pdata`.

## 9. The static CRT is inside the image, so "the program" needs a denominator

No CRT DLL is imported (`/MT`), and the analysis recovered CRT names it knows - 242 of them,
52,463 bytes, e.g. `___tmainCRTStartup` 0x4b3de8, `__SEH_prolog4` 0x4b68b4 (63 callers),
`__SEH_epilog4` 0x4b68f9, `__alloca_probe` 0x4af840 (233 callers), `_free` 0x4af1b0 (174),
`_memset` 0x4af870 (161), `_memcpy` 0x4af8f0 (83), `___InternalCxxFrameHandler`. WinRAR.exe
has 2,724 function bodies / 714,388 bytes in total.

Consequence for a 90 % bar over "the program": a fifth of the reachable bytes are runtime
code that no decompiled source should re-write - the same CRT a v90 candidate would link
against. So the report will state its denominator (program-owned functions) and list CRT
functions as linked-runtime, matched by construction, not by source.

Status: **decision, documented here.** The count itself comes free: Ghidra's recovered names
separate the CRT from the program (2482 of the bodies are unnamed `FUN_*`).

## 10. Running the CLI in this sandbox

`python3 -m decomp.cli …` fails with `ModuleNotFoundError: No module named 'typer'`. The
working invocation is `.venv/bin/decomp …` or `.venv/bin/python -m decomp.cli …`
(Docs/Setup.md §2, persistent venv at `.venv/`). Noted because the 32-bit run hit it once.

## 11. Analysis cost for a 1.1 MB 32-bit target

`decomp analyze Tests/Proprietary/wrar411/WinRAR.exe` produced
`cache/ghproj/4fcff4248eda0e31/analysis.db` (26.5 MB, ~15 min wall clock): 2734 functions
(2724 bodies, 10 thunks), 216,191 instructions, 61,502 references, 2908 strings, 32,656
symbols, `language_id = x86:LE:32:default`. Reading that cache read-only is what all the
scoping below is built on (`tools/triage.py`, `tools/map.py`).

## 12. Corrections to earlier notes from this session (so they are not quoted back)

- The payload listing earlier in this session ("11 files: Setup.exe, zsys.7z, SFX.dll,
  RARreg.key, zip2rar.exe, UnRAR.dll …", shared CRC `3939e45a`) **does not describe this
  file**. The authoritative listing is `7z l` above (33 files). Do not reuse those names.
- `tools/rarwalk.py` mis-parses this archive: it walks MAIN(flags 0x000c = Lock+Solid,
  head size 13) then a `0x7a` record with flags `0x8000` at 0x19414, and stops; 7z reads the
  same bytes as a valid solid archive with 33 files. Treat `rarwalk.py` as a probe of the
  simple cases only, and `7z l` as the source of truth for real-world RAR files.
- The scope table was first anchored at 0x480230. The PE's entry is **0x4b3f66** (`entry`,
  10 bytes) and 0x480230 is an unrelated message/report hub. Re-ran with the right entry;
  `tools/scope_winrar.jsonl` and `tools/map_winrar.jsonl` are the corrected files.
- `Tests/Proprietary/wrar411-recovered/project.toml` pointed at this file before it existed,
  and a `project-winrar.toml` was named in commands but never written. Both are fixed: this
  file exists, and the WinRAR.exe config is `Tests/Proprietary/wrar411-recovered/winrar.toml`.

---

## 13. The v90 toolchain, as installed here (closes §2, §3 and "what to download")

The operator downloaded `toolchains/VS2008ExpressWithSP1ENUX1504728.iso` (784,902,144 bytes,
Visual Studio 2008 Express with SP1, full media). It does contain the compiler, and it is the
right one: extracted with 7z + `toolchains/msiextract.py` into `toolchains/vc90`, its driver
prints

```
Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 15.00.30729.01 for 80x86
```

whose build (30729) is exactly the build every Rich record of `WinRAR.exe` carries. A candidate is
now compiled with the same compiler release that made the target, which is the only way a 90 %
bar is reachable at all.

**The headers and libs do not come from that ISO.** The VS2008 Express payload ships the Win32 SDK
only as merge modules (`VCExpress/WCU/WinSDK/WinSDK_*.exe`), and the extracted tree has no
`windows.h`. The operator's second download, `toolchains/GRMSDK_EN_DVD.iso` (594,841,600 bytes,
Windows SDK 7.1), is the wrong era *as a compiler* (its tools are cl 16.00-era) and the right
thing as a header/lib set: `toolchains/media/sdk71/Program Files/Microsoft SDKs/Windows/v7.1/`
`{Include,Lib}`, where `Lib/` is the x86 set (x64 and IA64 are subdirectories) and every DLL the
target imports has an import library in it. `toolchains/vc90/bin/x86/msvcenv.sh` puts both on
`INCLUDE`/`LIB` in the `z:\…` form the guest expects.

Three facts about running this toolchain here, all learned the hard way:

- `mspdb80.dll` and `mspdbcore.dll` have to sit next to `cl.exe`. VS2008 keeps them in
  `Common7/IDE`; wibo resolves a program's DLL imports from its own directory, so without the copy
  `cl` dies before it reads a source file.
- A **relative `/I` is not resolved** through wibo (`/I..\..\include` → `C1083 Cannot open include
  file`), while an absolute path is (wibo maps a POSIX path to `z:`). The CLI passes absolute
  paths, so this only bites hand-run commands - but it makes hand-run probes misleading.
- `VC/bin` has no `amd64/` subdirectory: VS2008 **Express** is an x86-host, x86-target compiler. A
  64-bit v90 candidate would need the Professional/SDK cross-compiler. Not a gap for this target
  (the target is i386), but it is why `check.py`'s x64 row cannot be satisfied by this prefix.

What the era gap was worth, measured on the same sample with the same probe (1,248 real function
bodies from the cached analysis): the shape distance to the target at `/O2` was **0.526 with v141**
and **0.319 with v90**; `/O1` 0.736 → 0.625; `/O0` 3.506 → 3.303. So §3's ranking was
qualitatively right (optimised, `/O2` nearest) and quantitatively off by ~40 %. `decomp detect`
now names the target: `toolset v90 (Visual Studio 2008) - link.exe 9.0`, and its fidelity line
reads `[ok] the toolset matches`.

## 14. The toolset table stopped at v100, so a v90 file could not be named — fixed

`decomp/toolchain.py::_MSVC_TOOLSETS` began at `((10,0), "v100")`. `WinRAR.exe` (and
`4.1.1_wrar411.exe`, and `Tests/Proprietary/deadrising2.exe` at link.exe 8.00) therefore read as
`MSVC link.exe 9.0 (no toolset table entry)`, which `fidelity.py` turns into "its era cannot be
named" - a shrug at a question the optional header had already answered. Added `((9,0), "v90")`
and `((8,0), "v80")`.

What is deliberately *not* in the companion build table: pre-15.00 build numbers. They are not
monotonic across families - the VC 10.0 RTM build is 30319, **below** VC 9.0 SP1's 30729 - so a
build number can corroborate a family the linker version already named, it cannot decide an era by
itself. Only `(30729, "15.00")` is listed, because it was measured twice on this machine (the
toolchain prints it; a file it links carries it).

Regression: `Tests/tools/check_msvc_detect.py` asserted the *limitation* (a link.exe 8.00 file must
say "outside the toolset table"). It now asserts the two halves separately: the file's own era is
named (`v80 (Visual Studio 2005)`) and the gap to the compiler installed here is still stated.
Green with `PATH=toolchains/msvc/bin/x64` on PATH.

## 15. A `cl` named by path was not recognised as `cl` — fixed

`check.Tool` keyed two decisions off `self.name`, the string the caller passed. With
`compiler = "cl"` that string is `cl`; with a driver named by path - which is what a config with
`[msvc] prefix` produces, and what every 32-bit MSVC variant here uses - it is
`…/toolchains/vc90/bin/x86/cl`. Two consequences, both observed in this session:

- `_banner_arguments(self.name)` chose the non-MSVC probe order, so `cl` was asked `--version`
  (which prints nothing) and then `/?` (which has no version in it). That is the whole reason an
  earlier run reported the freshly installed vc90 toolchain as "no version banner found" - it was
  not a Wine problem.
- `toolset()` tested `self.name == "cl"`, fell through for a path, and fed the **compiler** version
  15.00 to a table keyed by **linker** version: `toolset MSVC link.exe 15.0 (no toolset table
  entry)`, printed next to a target correctly named v90. The old `if major < 16: return None`
  guard hid this for the bare-name case and answered nothing either.

Fixed with a `Tool.tool_key` property (basename, `.exe` stripped) used by both decisions. A v90
driver named by path now reports `= toolset v90 (Visual Studio 2008)` and
`decomp detect -C Tests/Proprietary/wrar411-recovered/winrar.toml` says
`[ok] the toolset matches: the file is v90 (Visual Studio 2008) and …/vc90/bin/x86/cl is that
toolset`.

## 16. `decomp check` described a different toolchain than the variants it had just resolved

With `[msvc] prefix` pointing at `toolchains/vc90`, the `compiler <variant>` rows named
`toolchains/vc90/bin/x86/cl` while the `msvc toolchain` / `msvc target x86` rows described
`toolchains/msvc` (v141), because `msvc_prefix()` looked at PATH and then at
`_installed_prefixes()`, which returns `toolchains/msvc` first. A config that pins a prefix has
already answered that question, so the pin is now tried first (`msvc_prefix(…, preferred=…)`,
accepted when the directory looks like a prefix) and reported with where it came from.

Still open, and unrelated to the order: `check.py`'s layout probes (`toolset_dirs`, `_kits_dir`,
`MSVC_CRT_LIBS`, `MSVC_SDK_LIBS`) only know the SDK-shaped v100+ layout, so a VS2008 prefix
reports no CRT and no SDK. The v90 layout is `VC/lib` flat with `libcmt.lib`/`libcpmt.lib` and has
no UCRT at all, so a legacy prefix needs its own probe list, not a looser match of the same one.
Until that is written, the "this variant links the CRT statically" sentence from `abi` is the only
correct CRT statement for v90, and `decomp check`'s per-arch rows should be ignored for it.

## 17. `std = "c++17"` asks v90 for `/std:c++17`, which it does not have

Every candidate build of this target emits `cl : Command line warning D9002 : ignoring unknown
option '/std:c++17'` and compiles anyway. `/std:` does not exist before VS2015, so no value of
`std` is spellable by v90: the tool should skip the flag when the resolved driver predates it
rather than pass an option the driver cannot honour. Not fixed here (it is a warning, and the
candidate sources are C++98-compatible). If it is fixed, the test is that a v90 probe build emits
no D9002.

## 18. The hand-written vc90 wrappers pointed at the wrong files (fixed)

`toolchains/vc90/bin/x86/{link,lib,cvtres,dumpbin,ml,nmake}` were written as
`exec "$WIBO" "/name.exe"` - an absolute guest path at the filesystem root - instead of
`"$BINDIR/name.exe"`. `cl` was right, so the mistake stayed hidden until a link was attempted. If
these wrappers are regenerated, generate them from a loop over the toolset's `bin` directory rather
than by hand.

## 19. Where this leaves the 90 % bar

The toolchain question is closed; the remaining gaps are the ones §4, §8 and §9 describe: a 32-bit
PE names no units (so matching is per-function, and the analysis' own body range can differ from
the compiler's symbol size - `--size` is the bridge), the static CRT is inside the image (so any
percentage needs its denominator stated), and this file's functions come from a decompiler, not
from headers, so the reading has to earn its names. Entry 3's conclusion (`/O2`) is now a v90
measurement rather than a v141 one, and `winrar.toml` keeps both the current variants and the
pre-v90 numbers as history.

## 20. A 32-bit PE calls through its IAT, and neither side could name that slot — fixed

The first two units of `WinRAR.exe` (`ConvertToAnsi` at 0x477bc0, `ConvertToWide` at 0x477c00)
compile to **exactly** the target's bytes with v90 `/O2` - 53/53 and 49/49 - and still capped out at
`structural`, one line from the top tier:

```
1 reference stands not verified: DAT0 -> WideCharToMultiByte ...
symbols this function reaches (1): original: PTR_WideCharToMultiByte_004c515c
                                  candidate: __imp__WideCharToMultiByte   UNVERIFIED
```

An i386 PE reaches an API through a pointer slot: `call *0x4c515c`. Three names exist for that one
object and none of them was usable:

- the disassembler's, from the value it resolved there: `PTR_WideCharToMultiByte_004c515c`, which
  `_SYNTHETIC` rightly classifies as invented (the rule exists so a Ghidra-named `.rdata` label
  cannot be matched by name);
- the candidate object's, `__imp__WideCharToMultiByte`, which is the real COFF symbol name for the
  import thunk;
- and the file's own, in its **import directory**, which says plainly that slot 0xc515c holds
  `WideCharToMultiByte`. Nobody was reading it.

So for *this* target format every unit that calls an API - which is nearly all of them, the file
imports 426 names from 10 DLLs - was capped one tier below what it had actually proven, and a
90 % goal was unreachable in practice no matter how good the reading was. Two small changes fix it:

- `decomp/extract.py`: `TargetImage._read_imports()` reads the PE import directory into
  `import_slots` (iat RVA + `file_address_base` + `self.offset`, the same address domain as
  `self.sections` and `self.units`), and the reference binder's `describe_object` names a reference
  that lands on such a slot with it (`identity = "iat@0x…"`). Ordinals are skipped - a number
  matches nothing on the other side. `WinRAR.exe` yields 424 named slots out of 426 entries, which
  is the 2 ordinal imports the import table itself showed.
- `decomp/normalize.py::clean_symbol`: strip a leading `__imp_`, leaving the decorated name of the
  imported symbol, so the candidate's spelling and the file's spelling compare.

Both are narrow: nothing else produces `PTR_<name>_<hex>` labels that the import directory also
names, and `__imp_` is only ever an IAT thunk. After it, `try` on 0x477bc0 reads
`tier exact PASS … the candidate assembles to the original bytes: every byte but the 4 the link
fills in matches` and the symbol row becomes `original: WideCharToMultiByte  candidate:
_WideCharToMultiByte  ok (name)`.

Regression: `check_phase4_evidence` (47 checks), `check_gate_tiers`, `check_diff_accounting`,
`check_msvc_x86_reference`, `check_pe_target`, `check_phase2_try`, `check_msvc_x86_candidate` all
exit 0. The x64 PE suite's numbers are unchanged by it (`check_coff_candidate`: 70 exact / 19
structural before and after), which says the 19 caps there are a different family - see §22.

## 21. A suite that asserts an empty ledger sees the rows an earlier suite banked — fixed in the suite

`Tests/tools/check_phase5_ledger.py` copies the project's analysis into `cache/phase5-ledger/` and
asserts the copy "starts with an empty ledger". The copy is a `copytree`, and the shared
`cache/ghproj/<key>/analysis.db` had 6 rows in its `matches` table by the time it was made - any
suite that runs `try` against the real analysis banks rows there, and they persist. Four checks
failed, and they failed identically at HEAD without my changes (verified with a `git stash` of
`decomp/normalize.py` and `decomp/extract.py`), so it was state, not a regression. The copy now
clears `matches` after `copytree`, with a comment saying why: the suite measures what *it* banks,
and pretending the inherited rows are not there would only make the assertion false in a different
way. Green again: 55 checks, exit 0.

The general hazard for anyone running these suites: the analysis cache is shared, the ledger is part
of it, and `decomp try` writes to it by default (`--no-learn` is the switch when you only want to
score a guess).

## 22. `check_coff_candidate` has been failing on a stale `KNOWN_GAPS` since MS-5 — found, not fixed

`KNOWN_GAPS["msvc-o0"]` is `{}` with the comment "the entry is gone: 89 of 89 units pass", but the
suite scores 89 units at mean 100.00 % with tiers `{exact: 70, structural: 19}` - 19 units below the
gate, and 19 is exactly what `Tests/README.md` now documents (the 2026-11-07 correction). The
expectation and the documentation disagree; only the expectation was never updated. The 19 ids, from
a run at HEAD and with the current code (identical both ways): MATH-13, MATH-24, MATH-26, MATH-27,
MATH-28, MATH-29, STR-04, STR-07, STR-08, STR-10, STR-13, STR-15, STR-17, STRUCT-04, STRUCT-20,
STRUCT-21, STRUCT-22, STRUCT-24, STRUCT-25.

Left as it was found, because it is an x64 MSVC question and fixing it properly means writing the
reason per unit, not a count. Two things were done around it: the suite now prints **every** unit
below the gate instead of 12 plus "... N more" (a truncated list hides the very ids the next reader
has to write into `KNOWN_GAPS`), and this entry names them so the next session can start from the
list instead of re-running the suite to find it. What is *not* yet known is whether those 19 caps
are the same "unnamed callee / object with no bytes anywhere" family the x86 suites document
(Docs/MSVC-x86-Plan.md X86-6) or something else - the first two of them to look at are MATH-26
(`Vec3Cross`, pure arithmetic, so an unverified reference there cannot be an API call) and
STRUCT-24, which MS-5 already claims to have resolved.

## 23. Three codegen tells that decided declarations while decompiling WinRAR.exe

Not tool defects - things the i386 code says that the source has to agree with. Each one was
measured with `decomp try`, and each one changed the tier.

- **`ret $0xc` is the calling convention, in bytes.** The first candidate for the wide-copy helper
  at 0x46f500 was written as plain cdecl: it came out 50 bytes with `retl`, where the target has
  54 and `retl $0xc`. Declaring it `__stdcall` made the argument slots line up (`movl 0x10(%esp)`
  = the third argument) and the size match. One trap on the way: writing `wchar_t __stdcall f(...)`
  instead of `wchar_t *__stdcall f(...)` silently makes the return type `wchar_t` (error C2440 on
  every `return`) - the convention belongs to the declarator, not to the type name.
- **`testl %edi,%edi` + `jbe` is an unsigned range test.** A zero test would be `je`; a signed
  `<= 0` would be `jle`. That says the parameter is unsigned *and* that the source asked "is there
  room" and fell through to the copy, with the empty-buffer return as a separate block at the end
  of the body (`jbe 0x46f52e`). Writing it the other way round (`if (cch == 0) return pDst;`)
  produced the same 54 bytes and a **different tier**: 81.82 %, `none`, with the branch inverted
  (`jne`) and the return block hoisted. Reordered, it is 54/54 `exact`. Byte counts can agree while
  the instruction stream does not - which is why the tool gates on tiers and not on percent.
- **`movl %ecx,%eax` before the member write means the member returns `*this`.** A `void` thiscall
  setter would write through ECX and be 8 bytes; this one is 9 and returns the object by reference
  (0x472610, 47 callers). Register folding does not rescue a wrong return type, because the extra
  `mov` is an instruction the original has and the candidate does not.

Two facts about v90 `/O2` that the match depends on: it leaves `wcsncpy` as a call to the CRT's
`_wcsncpy` (no intrinsic expansion), and it restores `this` in a thiscall body with `popl %ecx`
rather than a second `mov` - so a source that writes `if (m_pData) free(m_pData);` reproduces the
14-byte original exactly. `decomp try` without `--fn` picks between the symbols in one object by
size, which is why `tools/score.py` must not assume the "matches N symbols" listing appears.

## 24. The analysis names 857 of this image's 2724 bodies as CRT, but not all of the CRT

`tools/order.py` flags a body as library code when the analysis gave it a CRT name. That filter
under-counts: 0x4a5f50 (129 callers, `FUN_`) pushes five arguments - one of them a literal `0` -
at `FID_conflict:__vswprintf_p_l` (0x4aefe1), which makes it the CRT's own `_snwprintf`; 0x4afc55
(107 callers) and 0x4afe20 sit in the same address cluster. So neither "is it named" nor "is it
small and widely called" decides whether a body belongs to the program: check what it calls and
where it sits, before putting it in the march or in the denominator. (The count itself is
TARGET.md §8.)

## 25. The target's bodies contain break-point placeholders a candidate build cannot emit

While matching `GetFilePart` (0x455e10) the candidate reached *the same size and the same
instruction count* - 84 bytes, 30 instructions - and still failed with 15 instructions paired as
missing and 15 as extra. The reason is in the original's bytes, at `0x455e1a`:

```
  455e17: 8d 70 02                leal   0x2(%eax), %esi
  455e1a: 8d 9b 00 00 00 00       leal   (%ebx), %ebx      <- six bytes, writes nothing
  455e20: 66 8b 08                movw   (%eax), %cx
```

`lea r,[r]` with the same register on both sides is a no-op. Counted across the image: **653 of them,
inside 389 of the 2,724 reachable bodies**, in three widths (2, 3 and 6 bytes - 173 of the 653 are
the six-byte `8d 9b 00 00 00 00` form). They are not loop alignment: sampled over 400 of them, what
follows is `MOV` (219), `MOVZX` (91), `CMP` (35), `PUSH` (17) - they sit at *statement* boundaries.
That is MSVC's pending-break-point placeholder, which the VC 9.0 back end emits when it is generating
debug info, using a register that is dead at that point (`ebx` above).

What it costs: a unit that contains one of these cannot be byte-exact against a candidate built
without debug info, because no C spelling produces the placeholder. 389 units are affected - about 14 %
of the image, and it is spread through the program rather than concentrated in the CRT.

Why the candidate is not built with `/Zi`: the v90 driver dies on it under wibo, always, whatever the
other flags:

```
cl /c /O2 /MT /Zi /Fopbi.obj pbi.c
  pbi.c
  wibo: call reached missing import NdrClientCall2 from rpcrt4
```

That is a gap in wibo's `rpcrt4`, not in the compiler: Wine gained `NdrClientCall2` (implemented in
assembly) only in 2024, `ValveSoftware/wine` commit `e994c8e`, and the open `decompals/wibo` PR #127
("run the VS2013 32-bit-host toolchain under wibo") is the same class of gap. Running v90's 32-bit
`cl.exe` under Wine instead is not available here - this host's Wine cannot start an i386 PE image
(§4), which is why the v90 toolchain goes through wibo at all.

So, in order of preference:

1. get a wibo build that exports `NdrClientCall2` (then add `/Zi` to the variant and re-measure:
   expect the 389 affected units to move), and
2. until then, treat those units as capped at `structural` - the gate this project asks for - and say
   so in the report rather than reporting a percentage that cannot move.

Do not push dead code into the source to fill the hole. The tool compares semantics, and an unused
variable or a fake store to make the byte count agree would buy a matching size with a worse answer.

**Correction (measured later the same day, and it changes the 90 % bar).** The claim that no
candidate build emits these is wrong. The VC 9.0 `/O2` back end emits them by itself, with no debug
flag: `cache/ghproj/candidates/candidate_gfp_variants.o` (built from `/O2 /W3 /EHa /nologo /MT`, the
flags the variant prints) contains four `leal (%ebx), %ebx`, one of them at offset `0xa` of a
function whose target-side twin has one at the same offset, and `candidate_strutil.o` contains one.
So a unit that contains a placeholder is **not** capped, and the "389 units, about 14 % of the image"
figure above is not a ceiling on the project - it is a count of places where the compiler put padding
in the target, which the same compiler will tend to reproduce. `/Zi` and the wibo `NdrClientCall2`
gap are not on the critical path for that reason any more (§19's arithmetic should not carry the 14 %).
What the placeholders do mean is what §29 measures: they are part of the bytes, and they appear or
disappear with the shape of the code around them, so a source change that is *more* faithful can
still lose bytes.

## 26. The target is built `/EHa`, and the tool hardcoded `/EHsc` — found while reading a 104-byte free-two-members function (fixed)

`0x401a70` (104 bytes, 94 callers) is one of the program's smaller own-code bodies: a `__thiscall`
member that frees a member at `+0x10`, then a member at `+0`, both through the CRT `free` the image
carries at `0x4af1b0` (which the analysis already names `_free`). Its body begins:

```
  0x401a70  pushl $-1
  0x401a72  pushl $0x4c0c83        ; a scope table in .rdata, one per such function
  0x401a77  movl %fs:0, %eax
  0x401a7d  pushl %eax
  0x401a7e  pushl %ecx
  0x401a7f  pushl %esi
  0x401a80  movl 0x4d8620, %eax    ; __security_cookie, the /GS guard value
  0x401a85  xorl %esp, %eax
  0x401a87  pushl %eax
  0x401a88  leal 0xc(%esp), %eax
  0x401a8c  movl %eax, %fs:0       ; the frame is now registered
  0x401a92  movl %ecx, %esi        ; the thiscall `this`
  0x401a94  movl %esi, 8(%esp)     ; slots the unwinder will need
  0x401a98  movl $0, 0x14(%esp)
  0x401aa0  movl 0x10(%esi), %eax  ; the body itself starts only here
```

That is a **frame the source does not contain**. Counting the image: **205 of its 2,719 bodies open
with `pushl $-1` followed by `pushl $<scope table in .rdata>`** (each table is its own object at
`0x4c0ca8`, `0x4c1658`, `0x4c2fe8`, …), and the image contains `__except_handler4`,
`__SEH_prolog4`, `__SEH_epilog4`, `_EH4_TransferToHandler`, `__EH_prolog3_catch`,
`___CxxFrameHandler3`, `_GetRangeOfTrysToCheck`, `?CatchGuardHandler@@YA…`,
`?TranslatorGuardHandler@@YA…` and `@__security_check_cookie@4` — while a query for any name
containing `GSHandlerCheck` returns **nothing**. So this is VC 9.0's EH4 machinery, with the guard
cookie checked by the plain `__security_check_cookie` that v90 uses.

Why that is a decompilation problem rather than a curiosity: nothing in a faithful source asks for
that prologue. A function that frees two members behind an object with a destructor gets the frame
only under one exception model, and `decomp/toolchain.py` was putting `/EHsc` on every MSVC command
line (line 333 of `build_flags`, hardcoded). Measured with the installed v90 driver on
`Tests/Proprietary/wrar411-recovered/probe/eh_probe.cpp` — a `__thiscall` member that frees two
members behind a scoped guard, which is the shape of `0x401a70`:

| flags | first instructions of the body | object |
|---|---|---|
| `/O2 /MT /EHsc` | `pushl %ecx; pushl %esi; movl %ecx,%esi; movl (%esi),%eax; …` — **no frame at all** | 733 B |
| `/O2 /MT /EHa` | `pushl $-0x1; pushl $0x0; movl %fs:0x0,%eax; pushl %eax; pushl %ecx; pushl %esi; movl 0x0,%eax; xorl %esp,%eax; pushl %eax; leal 0xc(%esp),%eax; movl %eax,%fs:0; movl %ecx,%esi; movl $0x0,0x14(%esp); …` | 1543 B |

The second row is the target's frame: the same eleven instructions, in the same order, up to the
operands that name data — `pushl $0x0` is its scope table and `movl 0x0,%eax` is `__security_cookie`,
both of which appear as zero in the object because they are relocations. No spelling of that source
under `/EHsc` gets a frame at all, so every unit of this program with a destructor or a `try` was
going to differ in its first instructions no matter how good the reconstruction was.

What was changed: the flag set is now configurable per variant — `eh = "a"` in `[variants.*]`, turned
into `/EHa` by a new `_msvc_eh()` in `decomp/toolchain.py`. Absent or unrecognised values keep
`/EHsc`, which is what `cl` itself means with no `/EH` on the command line, so existing configs and
`Tests/project.toml` are unaffected (verified: `build_flags` with no `eh` key returns the same list
as before). `Tests/Proprietary/wrar411-recovered/winrar.toml` sets `eh = "a"` on all four x86
variants, with the evidence quoted in the file.

Regression measured after the change: the units already at `exact` under `/EHsc` stay exact —
`decomp try 0x46f500 src/strutil.cpp` (the `strCopyN` ← `_wcsncpy` unit) reports `tier exact /
match 100.00 % / 54 vs 54 bytes / 22 vs 22 instructions / categories all 0` with `/EHa` in the
banner, and `Tests/tools/check_driver_resolution_cli.py` is still OK. `/EHa` is not a free win
either: it changes what the compiler may assume about exceptions coming from outside the module, so
its effect on other units has to be measured per unit, not assumed.

Two things this does **not** settle, both of which will come up again: `/GS` needs no flag of its own
— the cookie is loaded from `__security_cookie` at `0x4d8620` and checked by
`@__security_check_cookie@4`, and candidate objects built *before* this change already carried that
machinery, because `/GS` is the v90 default at `/O2` — and the frame-pointer choice is a separate
flag (`/Oy`) that this target's bodies show both ways: 205 framed bodies and many with no
bookkeeping at all, which is `/O2` deciding per function, not a flag set by the project.

## 27. `/std:c++17` on a VC 9.0 driver: a warning per file, and a flag the report claimed was used (fixed)

`decomp/toolchain.py` built every MSVC command line as `/std:c++<level> /Ox /W3 /EHsc /nologo`, and
`c++17` was the default when a variant said nothing. On a v141 or newer driver that is a real flag.
On the VC 9.0 driver this target needs, it is not: `cl` answers

```
cl : Command line warning D9002 : ignoring unknown option '/std:c++17'
```

once per source file, and compiles as if nothing was said. Two consequences, both of the kind that
matter here: the build log of every x86-32 unit carries noise that is not about the candidate, and
`decomp try` prints the flags it used — a report naming a flag **the driver threw away** is not a
report of the build that happened. (The detection side already knows this: `language_evidence()` says
which levels a given toolset offers, and `Tests/tools/check_msvc_detect.py` group 3 asserts that
`/std:c++17` is reported as available only from 14.16. The flag builder simply never consulted it,
because `build_flags(variant)` is not given the toolset.)

Fixed in `decomp/toolchain.py`: `_std_omitted(std)` recognises `std = "none"` (also `off`, `default`,
`compiler-default`, `driver-default`, the empty string) and both flag builders then emit **no** dialect
switch — for `cl` and for GCC, so `std` means the same thing on both. Any other value behaves exactly
as before (`_std_year` still defaults to 17), which is why `Tests/project.toml`, whose variants set
`std = "c++17"` explicitly, is unchanged. Verified with the real driver:

```
$ echo 'int main(){}' > /tmp/stdnone.cpp
$ toolchains/vc90/bin/x86/cl /c /std:c++17 ...   ->  D9002 warning, then compiled
$ toolchains/vc90/bin/x86/cl /c ...              ->  no warning
$ python3 -c "... build_flags({'compiler':'cl','optimize':2,'std':'none'})"
['/O2', '/W3', '/EHsc', '/nologo']
```

`Tests/Proprietary/wrar411-recovered/winrar.toml` now sets `std = "none"` with a pointer here. Not
done, and worth doing when the detection work touches this: `decomp detect --write` should put
`std = "none"` in the `[target]` block for a toolset whose table says it offers no dialect switch,
instead of leaving the default in place.

## 28. A candidate's call to a helper of its own has no callee name in the object — measured, and one earlier claim corrected

Two runs of the v90 driver on a two-function source (`static int helper(int)` called twice by
`outer`, `/O2 /Ob0 /MT /EHa`, disassembled with `llvm-objdump -d`):

* default (`/Gy`, function-level linking, which is what `/O2` does in this era): the object contains
  **one `.text` per function** — objdump prints `Disassembly of section .text` twice — 832 bytes.
* `-Gy-`: one `.text` holding both, 694 bytes.
* In **both** spellings the call operands carry **no callee name**:
  `calll 0xc <?outer@@YAHH@Z+0xc>`. The operand is a section-relative address whose meaning lives in a
  relocation, and the disassembler attributes it to the enclosing function. `/Ob0` is needed to see
  any of this at all: at plain `/O2` the helper is inlined and there is no call.

What that means for matching. The target is a linked image, so every call in it has a resolved address
(`calll 0x466160`). A candidate that calls a helper of its own has an operand whose value is decided
only at link time. Whether that is a *difference* is a question for the matcher's relocation handling,
and the direct measurement I have is this target's own resource loader: with `HasTable()` **declared
but not defined**, the candidate's call had no target in the object and the unit scored 95.65 %;
defining it in the same translation unit, so the call resolves inside the object, moved the same
source to `structural` with masked bytes identical to the target's. So an intra-unit call costs bytes
when the callee is missing and nothing byte-wise when it is present.

Correction, so an earlier claim does not propagate: a note written earlier in this session said `/Gy-`
makes the callee's mangled name appear in the call operand, and that the matcher renders such an
operand as `L0`. Re-measured today against the two objects described above, **neither reproduces** —
`/Gy-` does not name the callee, and `L0` does not appear in this tool's output for them. If a unit
stops at `structural` because its callees cannot be identified, that is the matcher's symbol
resolution — the X86-6 "unnamed callees" family — and not a `/Gy` flag choice.

## 29. `GetFilePart` (0x455e10): five spellings measured, and what actually separates them

The unit is 84 bytes and I had it at the same size and instruction count five times over, so the
remaining difference is worth naming precisely rather than guessing at more C. Every row below is
`decomp try` against `0x455e10`, variant `msvc-o2-x86`, one source file
(`Tests/Proprietary/wrar411-recovered/probe/gfp_variants.cpp`), differing only in how the same
function is written.

| spelling | candidate bytes | folded categories |
|---|---|---|
| `while (*p) ++p;` | 86 (+2) | opcode 14, operand 3, missing 2, extra 6 |
| `while (*p++);` | 84 (+0) | opcode 8, operand 6, register 1, missing 2, extra 2 |
| same, `+ (-1)` for the count | 82 (−2) | opcode 6, operand 7, register 1, missing 2, extra 2 |
| same, comparison widened to `int` | 82 (−2) | (same shape) |
| same, drive test inverted | 82 (−2) | (same shape) |

What the last 84-vs-84 difference is, from `llvm-objdump -d` of the candidate against the analysis'
instruction list for the target:

* **Two return points.** The target ends `movl %edx,%eax / retl $4` and, in a separate block at the
  end of the body, `leal 2(%edx,%eax,2),%eax / retl $4`, and it hoists `leal 4(%edx),%eax` *before*
  the `cmpw $0x3a` test. Every spelling I wrote merged those into one exit (`addl $0x4,%eax`
  in place), which is the −2 bytes.
* **Encodings the compiler picks, not the source.** The target has `sarl $1,%eax`; the same shift in
  my object is `sarl %ecx` (the one-byte implicit-1 encoding). The target has `addl $-1,%eax` and the
  back end gives `subl $1,%ecx`. Both are reported as `opcode` differences - `sarl` vs `sarl $1` are
  different mnemonic strings to the matcher, though they are the same operation and the same operand.
* **The comparison width** (`movzwl`+`cmpl` in the target, `movw`+`cmpw` when `wchar_t` is compared
  against `wchar_t`) is a genuine source signal - the target really does widen - but widening it
  changes the size of the loop body, and with it whether the compiler emits its statement-boundary
  padding (see the correction at the end of §25). That is why the more faithful spelling scored two
  bytes worse.

For the tool, two of these are worth fixing rather than working around, and neither is done:

1. `sarl $1, %ecx` and `sarl %ecx` (and `addl $-1` / `subl $1`) should normalize to one form on both
   sides; today they land in the `opcode` category, which is the category the gate treats as "the
   operation itself differs".
2. A body's statement-boundary padding should probably be its own category, or masked the way the
   link-written fields are, because it is the compiler's layout choice. Today it shows up as missing
   and extra instructions, which is how a *correct* decompilation of a 389-unit population reads as a
   15-vs-15 instruction mismatch.

Until then: keep the shape the operands prove (widened comparison, two return points, the hoisted
`lea`), accept the `structural`-or-worse tier on units like this, and do not treat the placeholder
count as a ceiling.

## 30. A 32-bit call to `free()` can point at an 11-byte forwarder, and the analysis gives that no name — fixed at read time (2026-11-08) #x86-32 #thunk #naming

Symptom, from reading a unit that had nothing else wrong with it. `0x4384d0` (11 bytes) is
`movl 8(%ecx),%eax / pushl %eax / calll 0x4afc55 / popl %ecx / retl`, and `0x4afc55` is:

```
8b ff            movl %edi,%edi
55               pushl %ebp
8b ec            movl %esp,%ebp
5d               popl  %ebp
e9 56 f5 ff ff   jmpl  0x4af1b0        ; which the analysis names `_free`
```

So the source says `free(p)`. The analysis leaves `0x4afc55` as a body of its own, unnamed
(`FUN_004afc55`, `kind=function`), and `functions.thunk_target` is empty for it — so the call reads
as a call to an anonymous helper, a candidate's `call _free` cannot pair with it, and the unit cannot
reach `exact` no matter what the source says. **107 bodies call that one forwarder**; 129 units call
one of the nine bodies of this shape in the image.

Three forms exist, and only one kind is a problem:

* `e9 rel32` alone (5 bodies): the analysis *does* classify these (`kind=thunk`, named
  `thunk_FUN_…`), and they are 2–4-caller oddities. No change needed.
* `ff 25 <abs>` through a pointer slot (5 bodies): also already named — `CharToOemA`, `OemToCharA`,
  `CharLowerW`, `RtlUnwind`, `GetCurrentProcessId`. §20's import-table reading covers these.
* `8b ff 55 8b ec 5d e9 rel32` (4 bodies): **not** classified, **not** named. These are the ones that
  cost matches: `_free` (107 callers), `_atol` (6), `_clearerr_s` (1), and one to an unnamed body.

Fix (`decomp/extract.py`, `_forwarded_call`, called from `original_bindings.build`): when a referenced
body is *nothing but* an unconditional jump — optionally behind the six-byte `mov edi,edi /
push ebp / mov esp,ebp / pop ebp` no-op — follow it and take the destination's name, kind and size.
At read time, so no re-analysis and the existing cache is enough; the file's own bytes answer it.

Deliberately **not** followed: a body that adjusts `this` before jumping
(`movl -0x10(%ebp),%ecx / addl $8,%ecx / jmp <destructor>`, ~540 bodies whose last instruction is a
jump). Those are constructor and destructor thunks — a real unit with its own address, which is what
a source-level call really targets, and the immediate in it is a *member offset*, i.e. layout
evidence. Jumping through one would invent a callee the source does not name and throw that evidence
away. Making those pair is the phase-6 question of "can the tool reproduce a compiler-generated
thunk", not a naming gap.

Verified on the unit above, with the fix: the report line reads
`SYM12 original: _free  candidate: _free  ok (name)` and the unit is **`exact` PASS**
(`AutoBuffer::~AutoBuffer`, 11 vs 11 bytes). Before the fix the same source reached `structural` at
80 % with that one reference unpaired. (The 80 % run also caught a mistake of mine rather than the
tool's: I had the class's heap member at `+4`; the bytes say `8(%ecx)`, so the layout needs a member
or gap at `+0x04` — §24's rule that an operand's offset is the layout evidence, in miniature.)


## 31. 293 of this image's bodies open with an EH4 frame, and its second operand is a compiler-generated thunk (2026-11-08) #x86-32 #eh #slot

While reading 0x401a70 (104 bytes, 94 callers - a member that hands two heap fields back to the
allocator) I found that its first two instructions are not a prologue I can write:

```
0x401a70  pushl $-1
0x401a72  pushl $0x4c0c83
0x401a77  movl %fs:0, %eax
0x401a7d  pushl %eax
0x401a7e  pushl %ecx
0x401a7f  pushl %esi
0x401a80  movl 0x4d8620, %eax        ; ___security_cookie
0x401a85  xorl %esp, %eax
0x401a87  pushl %eax
0x401a88  leal 0xc(%esp), %eax
0x401a8c  movl %eax, %fs:0
```

**How common:** 293 of the image's 2,734 bodies (10.7 %) begin `pushl $-1`, and they are not
stragglers - 131 of the 151 bodies between 40 and 160 bytes do, and 162 of the 202 between 160 and
400 bytes. This is the target's normal function shape, not an interesting one.

**What the operands are.** The first push is the EH4 state slot (initialised to -1 = "in no try
block"). The second is **not a data table**: 0x4c0c83 is in `.text`, and it decodes as the
per-function "check the cookie, then chain to the real handler" thunk that MSVC emits next to every
function that has both `/GS` and an EH frame:

```
0x4c0c83  movl 0x8(%esp), %edx
0x4c0c88  leal -8(%edx), %eax
0x4c0c8b  movl -0xc(%edx), %ecx
0x4c0c8e  xorl %ecx, %eax
0x4c0c90  calll <__security_check_cookie>
0x4c0c95  movl $0x4cfae8, %eax       ; and 0x4cfae8 begins 22 05 93 19 = 0x19930522, the
0x4c0c9a  jmp   <handler>            ; MAGIC_ESP32 of an EH4 scope table
```

In a candidate build the same construct appears under its own name - `__ehhandler$?release4@TryFirst@@QAEXXZ`
begins `movl 0x8(%esp),%edx / leal 0xc(%edx),%eax / movl -0x18(%edx),%ecx / xorl %eax,%ecx / call …`.
So the operand the diff sees is **a reference to a compiler-generated function that nothing in the
image names**. That is the §22 family (an unresolvable reference slot), and it means none of these
293 units can reach `exact` until the matcher pairs `__ehhandler$` thunks. It is *not* a
decompilation error, and it is not the same thing as the §25 padding.

**The frame is information, and my first guesses were wrong.** Compiling probe/eh_variants.cpp with
the project's own flags (`cl /c /O2 /MT /EHa`) :

* a plain member that frees two fields, and the same with an empty inline guard object in scope, and a
  destructor of a class with a user-declared destructor - all three compile to the same 36-byte body
  with **no frame at all** (`pushl %esi / movl %ecx,%esi / …`);
* an actual `try { if (pB) free(pB); } catch (...) {}` around the first release, with the second
  release after it, does produce the frame - `pushl $-1 / pushl $0x0 (relocated to the thunk) /
  movl %fs:0x0,%eax / pushl %eax / subl $8,%esp / pushl %ebx … / movl 0x0,%eax / xorl %ebp,%eax /
  pushl %eax / leal -0xc(%ebp),%eax / movl %eax,%fs:0x0 / movl $0,-0x4(%ebp)` - plus a
  `__catch$?release4@…$0` block and a `jmp` over it.

The family is right; the layout is not. The target's frame is esp-relative (no `pushl %ebp`), pushes
only `%ecx` and `%esi`, spills `this` at `8(%esp)` and keeps the state at `0x14(%esp)`, and has no
catch block and no `jmp` in the body. What the bytes do say about the source is: the state slot is
written 0 before the first release and -1 after it - "inside try block 0", then "left it" - and the
second release is outside any block. So there is an exception region around the first call only, and
whatever is being guarded there is not something I can name from the body.

For the tool, one thing is worth fixing rather than working around, and it is not done: the frame's
layout depends on the whole function - which registers it needs, whether a catch block exists -
including parts of the function that are not inside the byte range the diff compares. A unit whose
first 11 instructions are a frame should probably be reported as "frame not modelled" instead of
counting ten missing and ten extra instructions, which is what makes an EH4 unit read as a wrong
decompilation when only the frame's bookkeeping differs.

## 32. CRT code inlined from a header looks exactly like a program function, and it is the busiest unit in the image (2026-11-08) #x86-32 #crt

0x4a5f50 is 27 bytes with **129 callers**, which makes it rank 5th in `tools/march_winrar.jsonl` - the
importance order built from the call graph. It is not the program's code. Reading the bytes:

```
0x4a5f50  movl 8(%esp), %ecx          ; arg2 -> ecx   (a wchar_t * destination)
0x4a5f54  leal 0xc(%esp), %eax        ; address of arg3 = the start of the varargs area
0x4a5f58  pushl %eax
0x4a5f59  movl 8(%esp), %eax          ; note: one push deep, so this is arg3, not arg2
0x4a5f5d  pushl %eax                  ; the format string
0x4a5f5f  pushl $0                    ; locale = NULL
0x4a5f61  pushl %edx                  ; the maximum count, taken from the CALLER's %edx
0x4a5f62  pushl %ecx
0x4a5f62  calll 0x4aefe1              ; FID_conflict:__vswprintf_p_l  (_vswprintf_p_l)
0x4a5f67  addl $0x14, %esp
0x4a5f6a  retl
```

That is `_vswprintf_p_l(dst, count, format, NULL, va_list)` with `va_start` done by hand - which is
what the VC 9.0 headers' inline/C++-overload expansion of a wide `printf`-family call compiles to
(`toolchains/vc90/VC/include/stdio.h:513` declares `_vswprintf_p_l`; lines 539-540 are the
`__DEFINE_CPP_OVERLOAD_STANDARD_FUNC_0_1_ARGLIST_EX` overloads that build the `va_list` and pass
`_countof` as the count). The count arriving in `%edx` is the tell: no C++ signature I can write asks
for it, because it comes from a template the header instantiated at the call site.

Two things for the tool:

* `functions.bytes`-based counting and the call graph both treat this as an ordinary body, and the
  analysis names 0 of its references as imported (the callee is a static CRT body, not an import), so
  the §23 CRT bucket - which keys off the analysis naming a body as CRT - misses it. A header-inlined
  CRT stub is invisible to that rule. It matters because it is *ranked above* real program functions:
  the importance order needs a "looks like a CRT header inline" marker (recognisable from a hand-built
  `va_list` + a call into a `_v*printf*`/`_v*scanf*` CRT body) or the march spends its first
  functions on other people's code.
* It is also a reminder that "129 callers" is a statement about the *program's* use of formatted
  printing, which is useful context for the report even when the unit is not the program's source:
  this is where WinRAR's format strings go.

## 33. Two ways to read the wrong table without an error: the cache's id/address keys, and a map built for another image (2026-11-08) #tool #analysis-cache

Both of these produced confident, wrong statements in this project's notes, and neither one fails
loudly:

* **`refs.fn` is a `functions.id`; `refs.to_address` and `functions.entry` are addresses.** Joining
  them without translating gives an empty result, which reads as "no unit calls this". One survey of
  which functions call the `_free` forwarder printed `0`, and then `0` again, until the id→entry map
  was applied; the answer was 129 units (§30). `cache.refs()`, `xref.py` and `map.py` all translate;
  hand-written queries have to.
* **`tools/map.py` output is keyed to one image.** `map.jsonl` in `Tests/Proprietary/wrar411-recovered/`
  was built from the SFX stub (`4.1.1_wrar411.exe`, 460 functions, entry `0x40a33a`). Sorting it by
  fan-in and reading the first rows gave a "next functions by importance" list whose addresses do not
  exist in `Tests/Proprietary/wrar411/WinRAR.exe` (2,724 functions, entry `0x4b3f66`) — the numbers
  were plausible, the units were not the target's. `map_winrar.jsonl` is the real one, and `disasm.py`
  or `map.py` both say `0x… is not a function entry` when a stale map is being quoted. Rule: rebuild
  the map whenever the analysed file changes, and print the analysis key next to any order derived
  from one.

The reachability half of that map is worth recording too, because it bounds "what matters": of the
2,724 bodies, **1,662 (507,396 bytes) are reachable along call edges from the entry point and 1,062
are not** — the program is callback- and vtable-driven, so a call-graph order under-rates the parts
reached only through a function pointer (`map.py`'s docstring measures the six such edges in the
smaller image, one of which is the dialog procedure passed to `DialogBoxParamW`).
