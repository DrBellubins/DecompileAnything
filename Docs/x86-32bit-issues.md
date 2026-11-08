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

## 34. `decomp try` asked this project for a variant it never had, because of how the analysis was cached (2026-11-08) #tool #variant

Re-running the WinRAR.exe target in a new project directory (`Tests/Proprietary/winrar-reverse`),
the first `decomp try` failed before compiling anything:

```
Tests/Proprietary/winrar-reverse/project.toml: no [variants.gcc-o0] (configured: msvc-o0-x86, msvc-o1-x86, msvc-o2-x86)
```

`try` defaults its variant to "the one the analysis was run with" (`meta.variant`), and that
analysis was cached when the binary was analysed with `Tests/project.toml` in force, whose variant
name is `gcc-o0`. The record is per-file, not per-config, so the target's own config - which
correctly defines three v90 x86 variants - is asked for a variant invented by a different project's
config, on a 32-bit MSVC target that could never be built by `gcc -O0`.

Not fixed, and the fix is not obvious: guessing the variant from the config would silently change
which build a unit is scored at, which is exactly what the field exists to prevent. The message is
already good (it names the configured variants), and `decomp status` prints the recorded variant
next to each target, so the diagnosis is one command away. What *is* worth doing sometime: have
`decomp analyze` warn when the config in force at analysis time does not define the variant it is
about to record against the file, because that is where the mismatch is created and it is invisible
afterwards.

What the run does instead: `tests/Proprietary/winrar-reverse/tools/da` pins
`-v msvc-o2-x86` for `try` and `link`, with a comment saying why, so no command in the project's
notes can accidentally score a unit at the wrong `-O`.

Related papercut from the same first run, mine not the tool's: `include_dirs = [...]` written
*after* a `[table]` header in a TOML file is that table's key, not a top-level one, so the config
was read as "no include directories" and a candidate died on `C1083 Cannot open include file`.
`decomp check` does report the include directories it found, so the answer was visible - but a
candidate build that fails on a quoted include could say "0 include directories are configured for
this target" rather than only showing the compiler's error.

## 35. "byte-match %" was not a byte figure — added one (fixed, 2026-11-08) #tool #metric

A unit of this target, 0x455790 (71 bytes), was reproduced instruction-for-instruction except for
five instructions: eight opcode differences, six operand, one register, six missing. Its candidate
was 57 bytes. The report said:

```
match 12.50% - progress only, the tier is what gates (the old threshold was 90%)
```

and that number is not a byte count and never was. `match_percent` is
`matched_instructions / max(instruction counts)` where *matched* means the instruction **text** is
identical down to the register names. So:

* it is a byte statement in disguise in one direction - an identical text assembles to identical
  bytes, which is why the `exact` tier implies 100 % - but it weighs every instruction the same,
  so a 1-byte `pushl` and a 6-byte `cmpw` count alike;
* it says nothing at all about how much of the original's bytes a near miss reproduces, and a
  candidate whose only fault is that VC 9 chose `%ecx` where the target used `%edi` reads as a
  handful of percent, which is honest about the bytes (those encodings *are* different bytes) but
  not a description of how close the reading was.

The project the user set for this target is a **90 % byte-match bar per function**, so the run
needs a byte figure. `compare_bytes` already answers the yes/no question ("are these bodies the
same bytes with the link-written fields masked"), which is what gates `exact`, and a positional
byte count is not usable: with a `pushl %edi` at offset 0 in the original and nothing there in the
candidate, *every* later byte of an otherwise identical body shifts, and the positional comparison
reported 3/71 = 4.23 % for the unit above.

What `decomp/diff.py` does now: the aligner already computes the stretches where the two streams
match exactly (`difflib` matching blocks); `compare()` weights those stretches by the length of
each instruction (lengths come from the addresses the tokens carry, per side, since a candidate
object numbers its instructions from its own start) and reports

```
bytes reproduced 8/71 = 11.27% (instructions matched exactly, weighed by their length)
```

next to the instruction-count figure. Bytes the candidate does not have are counted against it
through the denominator (the longer body). It is deliberately still "matched exactly": the tier
stays the judge of correctness, and this number is the one a byte-match bar can be read against.
Nothing that gates a tier changed - `bytes_equal_masked` and the tier rules are untouched.

Regression, one suite at a time (they share the analysis cache, per the note in Tests/README.md):
`check_phase2_try` OK, `check_diff_accounting` (285 verdicts) all groups passed, `check_gate_tiers`
all groups passed, `check_masked_bytes` all groups passed, `check_phase4_evidence` 47 checks,
`check_pe_target` OK, `check_phase5_ledger` 55 checks, `check_msvc_x86_candidate` OK.
`check_coff_candidate` still exits 1 with `{'exact': 70, 'structural': 19}`, mean 100.00 % -
identical to the pre-existing §22 baseline (its `KNOWN_GAPS` expectation is stale), so it is
unchanged by this: re-ran it at this commit precisely so that claim is a measurement.

For the project's own use: `Tests/Proprietary/winrar-reverse/tools/score.py` records that figure
per unit in `scores.jsonl` and its "at the bar" count means **≥ 90 % of the unit's bytes *and*
the configured tier**, both, with the reason printed for anything below.

## 36. Three more codegen tells from the same image, all of them deciding a declaration (2026-11-08) #x86-32 #codegen

Measured with the v90 driver on this target, in the new project; each changed a tier.

* **`testl %e,%e / jbe` is `if (x > 0)` on an unsigned, and `je` is `if (x != 0)`.** The two
  `strCopyN` bodies (0x46f500, 0x46f4c0) are byte-identical to the candidate except for that one
  instruction when the count test is written `!= 0`: 54/54 bytes, 22/22 instructions, and
  `match 95.45 %` at tier `none` on a single opcode difference. Writing `if (cch > 0)` inverts to
  `jbe` and both units become `exact`. The count parameter is `unsigned` in the mangled names the
  ledger carries for them (`...I@Z`), which agrees.
* **A `bool` result that is held across a call is a local, not two `return`s.** 0x477bc0
  (`ConvertToAnsi`, 53 bytes) keeps the constant 1 in `%bl` across the API call and has two exit
  blocks. `if (!call) return false; return true;` compiles to a branchless `setne %al` (42 bytes,
  tier none). `bool ok = true; if (!call) ok = false; return ok;` is 53/53 `exact`. An
  `int ok = 1` local is 57 bytes with three opcode differences. The probe is
  `Tests/Proprietary/winrar-reverse/probe/conv_variants.cpp`; it is worth keeping because the
  three spellings differ only in how the result value is named.
* **A value read from `.rdata` rather than folded into an immediate is a global in another
  translation unit.** 0x455790 ends `movl 0x4c5874,%eax / movl %eax,(%edi)`; the file bytes at
  0x4c5874 are `5c 00 00 00`, i.e. the wide string `"\\"`. Declaring that object in the same file
  as `static const wchar_t g_szSep[2] = L"\\";` makes VC 9 fold it and emit `movl $0x5c,(%eax)` -
  one instruction, four bytes shorter, and a *wrong* statement about the program. Declared
  `extern const wchar_t g_szSep[2];` the candidate emits the same load-and-store pair, and the
  reading is the correct one: the program keeps its path separator in one shared object (which is
  also consistent with the same image accepting `/` - see `IsPathSepW` at 0x455760, which tests
  both).

One correction to §33's numbers, so both are not quoted back as if they measured the same thing:
its "1,662 of 2,724 bodies are reachable from the entry point" counts every body, including the
CRT's. `Tests/Proprietary/winrar-reverse/tools/march.py` counts reachability among the same call
edges but reports the **program-owned** subset (731 of 1,817, 214,532 of 638,280 bytes), because
that is the subset a source file could change. Both are correct for their question; a project's
report should say which one it printed.

## 37. A candidate's vptr store is a link-filled address, and the differ saw it as an operand difference — found, diagnosed, fixed (2026-11-08) #tool #relocation #vptr #fixed

Unit 0x4313d0 of `WinRAR.exe` (35 bytes) reproduced nine instructions to nine, and still stopped at 82.86 % and tier `structural`. One line of the report explains it:

```
-0x4313d4  movl $DAT0, (%ecx)
+     0x4  movl $0, DAT0(%ecx)
 ! operand: operands differ
```

The target stores the address of a one-slot vtable (`movl $0x4c7020,(%ecx)`). A candidate cannot spell that address: `cl` emits `movl $0x0,(%ecx)` with an `IMAGE_REL_I386_DIR32` against `??_7Sink…@@6B@`, because the value is the link's to choose. So the two bodies differ in one field **the link writes** — exactly the class of difference the byte comparison already masks — and it was counted as an `operand` difference.

The first diagnosis of this (written before the reading was finished, and wrong in its mechanism) said the candidate had no reference for such an operand at all. It has one. The fault is **which operand owns the field**:

* `normalize._slots` says plainly that `enc_offset` is "a convention, not a decoding": for a `[reg]` operand it may invent a displacement slot from the instruction's length (`movl $0x0,(%ecx)` is six bytes, and a `[reg + disp32]` encoding is never shorter than six), and for `cmpl $0, x(%ecx)` it reads two *real* fields from overlapping ranges. So an immediate slot and a displacement slot claimed the same four bytes.
* `extract.CandidateObject.bindings` then preferred the memory operand — "pair the address operands first" — and bound the relocation to the `(%ecx)` displacement. `reference()` resolved it happily to the vtable object, so the reference existed; it was attached to an operand that is not the field, and the immediate kept its literal `0`. That is why the two sides printed different lines and the category was `operand`.

The rule that settles it, and it is a property of the instruction set rather than of any target: **an absolute-address relocation (`IMAGE_REL_I386_DIR32`, `R_386_32`, `IMAGE_REL_AMD64_ADDR32`) rewrites a field that holds an address, and a register-relative displacement never holds one.** So when an instruction carries an immediate and another slot claiming the same bytes, the immediate is the field. The binder already knew the weak form of this ("a non-PIE 32-bit object writes `pushl $_ZTI14CVehicleEntity`: an `R_386_32` on an immediate of 0") as a *leftover* fallback, which fires only when nothing else competes — and here something always competes, because it is the same instruction.

Fix (`decomp/extract.py`, in `bindings`): pair a non-PC-relative 4-byte relocation with the immediate whose claimed field the relocation's offset falls inside, but only when another slot claims those same bytes; otherwise the existing ordering is untouched, so x86-64 rip-relative bindings are unaffected.

Test (`Tests/probe/x86_addr_store.cpp`, group 6 of `Tests/tools/check_msvc_x86_candidate.py`): the smallest source that stores the address of a global through a register-relative operand three ways (`(%ecx)`, `8(%esi)`, a stack slot), asked of **both** 32-bit toolchains the repository has. Each must bind exactly one reference, to the `imm` operand, naming `g_slot`, of class `data`; `store_constant` — same instruction shape, no relocation — must bind nothing, because the fix is about who owns a relocated field and not about inventing references. Measured with the fix stashed out: `bound to disp`, three FAILs per toolchain; with it: all six pass, `bound to imm`, names `?g_slot@@3HA` / `g_slot`.

Regressions (sequential): `check_msvc_x86_candidate` 0 with the new group, `check_coff_candidate` {exact 70, structural 19} and mean 100.00 % = its §22 baseline unchanged, `check_masked_bytes` gcc-o0-x86 {67, 21, 1} unchanged, `check_diff_accounting`, `check_gate_tiers`, `check_phase2_try`, `check_msvc_x86_reference`, `check_phase4_evidence`, `check_phase6_link` all 0.

End to end, on the unit that started this: 0x4313d0 went from "bytes reproduced 29/35 = 82.86 %, operand 1" to **35/35 = 100 %, categories all zero**, still capped at `structural` only because three *other* references (two placeholder callees and the vtable object) are unnamed. Scale of what this unlocks on an i386 MSVC target: **2,067 instructions in 726 of the image's 1,784 program-owned bodies** store an address immediate — every constructor and destructor, and every function that installs a callback or takes a global's address.

## 38. `cl` under wibo dies in the loader instead of compiling: `wibo: call reached missing import lstrcatW from kernel32` (2026-11-08) #tool #wibo #fixed

While compiling project files that include `<windows.h>`, the v90 driver died like this:

```
pathutil.cpp
wibo: call reached missing import lstrcatW from kernel32
Aborted (core dumped)
```

No object, exit 134, and not one word about the source. `toolchains/vc90/bin/x86/cl` is a wrapper that ends in `exec "$WIBO" "$BINDIR/cl.exe" "$@"` — this box has no i386 Wine guest (§4), so wibo loads `cl.exe` itself, and the message is wibo's: a call landed on an import thunk it never bound. It is *not* the §22 "wibo cannot pass `<vector>`" case, which is C++ EH inside STL headers and deterministic.

**What sets it off, measured.** The first read of this session called it intermittent ("seen three times in roughly forty invocations… a controlled repeat came back 8/8"), and that was wrong: the eight that came back were eight that wrote into a directory that already existed. The variable was the **output path**. `cl` does not create an output directory, and under this loader the failure to open it never becomes a compiler diagnostic — `cl` calls into path-building code, hits `lstrcatW`, and dies:

| invocation | result |
|---|---|
| `/Fotmp/nx.obj`, `tmp/` absent in the working directory | `lstrcatW`, exit 134, no object |
| same command, `tmp/` created first | exit 0, object written |
| `/Fotmp2/deep/z.obj` (two levels missing) | `lstrcatW`, exit 134 |
| `/Fo/tmp/missing-dir/z.obj` (absolute, directory absent) | `lstrcatW`, exit 134 |
| `/Fo/tmp/y.obj` (absolute, directory present) | exit 0 |

So: **any `/Fo` whose containing directory does not exist**, relative or absolute, and the source's relativity is irrelevant. That is a property of the loader running the compiler, not of the target, the flags, or the source — which is why the fix belongs in the tool and not in a project.

**Fixed** (`decomp/compile.py`): `compile.loader_aborted(returncode, stderr, stdout)` separates "the *loader* gave up on the compiler" (a status ≥ 128, a negative status, or no status at all, and either a known loader line or nothing printed) from "the compiler judged the source", and `build()` re-runs the identical command once in that case. The result and `describe()` both say it happened (`retried`, printed as `note: the driver was aborted before it reported anything (its loader, not the source); ran it once more`), because a build that succeeded on the second attempt should not be quoted as if it succeeded once. A compile error is **not** retried: it exits 1 or 2 with the compiler's words, and retrying those would hide the error, double the time of every failed candidate, and re-run a compiler writing into the same object file.

The loop itself should not hit this any more: `build()` has always created `object_path.parent` before invoking a driver, which is the whole reason forty-odd `decomp try` runs today did not trip it while my hand-typed shell commands did. The retry is for the rest — a loader hole, a killed driver, a directory that could not be created — and the honest part of the fix is that the loader's own line is what the failure now reports, instead of the loop saying "the candidate does not compile".

`Tests/tools/check_loader_abort.py` drives `build()` with a stub driver of its own, so it does not wait for the bug to recur, and counts invocations: abort-then-succeed → run twice, `ok`, note present; always-aborts → run twice, and the failure the reader sees is the loader's line; a compile error → run **once**, the compiler's words unchanged, no invented note; killed silently → retried. 21 checks, exit 0. The false-positive half is the part worth testing: a driver that exits 0 is never an abort whatever it printed, and a driver's own `fatal error` is never one.


## 39. A call to a function of the same object turned into a jump to a label inside the caller (fixed, 2026-11-08) #tool #coff #relocation #fixed

`GetUserSettingD` (0x45fe70, 28 bytes) had been 28/28 for two days. It fell to 23/28 the moment its callee was reproduced *in the same source file*:

```
-0x45fe84  calll SYM15
+     0x14  calll L0
 ! operand: operands differ
```

`L0`. The candidate's call had stopped naming anything. Two separate faults were behind that one line, and the second only shows up when a tool asks about two functions in one object.

**1. Where an address is an edge, and where it is the link's turn.** An MSVC front end gives every function its own section, and every one of those sections carries the same name — plain `.text` from the MSVC 9 driver, `.text$mn` from a newer one. This is not a flag to hunt for: `cl /O2` (the variant the WinRAR reading is scored at) splits them with nothing on the command line, three `.text` sections for a three-function probe; the newer driver at `/Od` keeps one section and needs `/Gy` to split. So a call from one function of a translation unit to another is a call *across sections whose names are identical*, and its relocation record names the callee's own symbol (measured in both objects: `?ReadSettingD@@YGKPAUHKEY__@@PB_W1K@Z` → section `.text#1`, `_inner_of_this_unit` → `.text$mn#2`) with the field in the code left at **0**.

Capstone therefore resolves the call to address 0, and `normalize_function`'s rule for an operand inside the unit applies: a branch or call that lands inside the body being compared becomes `L<offset>`, a rule that exists for real edges (a jump to a cold block of the same function, a self-recursive call). Both sections start at offset 0, so the callee's address is "inside" the caller, and the reference the binder had just resolved was thrown away at tokenising time. Nothing about the *relocation* was wrong — the tokeniser's "inside this unit" test was being asked about an address from another section.

Fix (`decomp/normalize.py`, `normalize_function`): the tokeniser is told which section those addresses live in, and an address carried by a reference from a **different** section is not an edge in this unit. A call inside one shared section is untouched: it needs no relocation at all and is resolved by the existing in-section symbol lookup, which is also how a self-recursive call keeps reading as `L0` on both sides. `decomp/cli.py` passes `original.section` / `candidate.section`.

**2. A function's relocations were read from whatever function was asked about last.** `extract.CandidateObject.function()` stored the extents it had just assembled in instance state (`self._extent_sections`), and `bindings()` and `masked_fields()` filtered the relocation table through that state. Ask for one function and it is correct. Ask for a second — a caller and its callee, which is what a translation unit *is* — and the second one's sections decide which relocations belong to the first: measured on the split-object probe, `calls_its_own_unit` then reports **nothing bound** for its call, and a unit that is a faithful reproduction prints `calll` with no target. Nothing errors; the reference is just gone.

Fix: extents travel on the `Function` (`extent_sections`, and a `blocks()` that yields `(section, address, length)` per block), instead of being remembered by the object. That is also the shape a two-block body needs independently of this bug — a `-O2` cold partition is a *different section* with its own address domain — and the instance state is now gone, so there is no order in which asking twice can differ from asking once.

Both were considered and rejected as fixes elsewhere: the relocation reader already resolves these calls correctly (it names the callee's symbol by table index, which is why the section's name never has to be trusted — while it is at it, `_read_relocations_coff` no longer labels an unknown symbol index as living in the section the record sits in, which is the *source*, not the target). Reading a record that names a *section* symbol as an offset into that section was measured too: it happens for `.debug$F`, and not for any code these compilers produce.

Test (`Tests/probe/x86_call_pair.cpp`, group 7 of `Tests/tools/check_msvc_x86_candidate.py`): a caller and a callee in one TU plus a self-recursive function, built by the same driver twice — as it comes, and with `/Gy`. Three claims, one per rule:

* the split object really does put caller and callee in two sections sharing one name (otherwise the group measures nothing), the call reaches a **function** named `?inner_of_this_unit@@YAHH@Z`, and the token is `calll SYM0`;
* a self-recursive call is still `calll L0` — the edge rule the fix must not break;
* the one-section object has no relocation on that call at all, and still reaches the callee.

Measured with the tokeniser guard disabled: `the call is tokenised as a reference to a symbol (calll L0)` FAILs. Measured with the extent state still on the object: `the call … reaches a function (nothing is bound)` FAILs. With both: the group is 9 checks and exits 0.

Regressions (sequential, on the final code): `check_msvc_x86_candidate` 0 with group 7 added, `check_coff_candidate` tiers {exact 70, structural 19} with all 89 extents at 100.00 % and byte-identical output to the §22 baseline (21 report lines both times), `check_phase5_o2` (cold partitions — the `extent_sections` path) OK, `check_phase5_ledger` 55, `check_phase4_evidence` 47, `check_phase6_link` 43, `check_phase7_fidelity` 56, `check_diff_accounting` / `check_masked_bytes` / `check_gate_tiers` all groups, `check_phase2_try`, `check_pe_target`, `check_loader_abort` (made independent of a leftover counter file: it now clears its own, and passes twice in a row).

End to end on the units that started it: 0x45fe70 back to **28/28 = 100 %**, and the string getter 0x45fe40 built the same way is **38/38 = 100 %**; both stay `structural` because the callee they reach is itself unreproduced, which is the honest reason rather than a byte loss. Scale: any candidate that defines a caller and a callee in one translation unit — every subsystem of every target — had its internal calls reported as operand differences.
