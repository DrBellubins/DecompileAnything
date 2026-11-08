# Tests: the decompilation benchmark

`TestBinary/` is a small C++ program written so that every function in it is a
decompilation *unit*. `eval.py` builds it, describes it, and scores a candidate
re-implementation of one unit against it. This harness does not use the decomp tool -
binutils + the standard library only - so it can judge the tool (see
`Docs/Design-Plan.md`, Phase 2).

## Quick start

```sh
cd Tests
python3 eval.py build --variants gcc-o0,gcc-o2,gcc-o0-x86   # compile, strip, describe
python3 eval.py selfcheck                                   # the reference proves itself
python3 eval.py crosscheck --variants gcc-o0,gcc-o2         # behaviour must not depend on -O
python3 eval.py self                                        # calibration ceiling
python3 eval.py report                                      # coverage of the benchmark
python3 eval.py units                                       # id, level, size, name
python3 eval.py try --unit MATH-01 --src my/math.cpp --fn AbsDiff
```

Everything generated lives in `Tests/build/<variant>/` (gitignored): `da_tests`
(with symbols), `da_tests.stripped`, `answer_key.json`, `task_list.json`,
`goldens.jsonl`, `build.json` — which records, besides the compiler and its flags,
`answer_key_extents`: what bounded every unit of that variant's key (a function table, a symbol
length, or the next name), the same thing `build` prints under the unit count.

## Feeding the decomp tool

`Tests/project.toml` also carries a `[ghidra]` table (`cache_dir = "../cache/ghproj"`), which
is what the `decomp` CLI reads; `eval.py` ignores it. To check the tool's own analysis cache
against this benchmark's ground truth:

```sh
.venv/bin/python Tests/tools/check_analysis_cache.py
```

It resolves each unit's answer-key address into the cached analysis and reports whether the
function, its size, its instructions and its pseudo-code are there.

To check the tool's own decompilation loop against this benchmark's ceiling:

```sh
.venv/bin/python Tests/tools/check_phase2_try.py
```

It feeds the untouched original source through `decomp try`'s code path for every unit and
compares with what `eval.py self` reports (100.00% mean, 89/89 pass at gcc-o0 vs the
harness's own 99.53%, 83/89), then re-scores the deliberately wrong candidates in
`Tests/examples/candidate_math_bad.cpp` and requires the report to name the kind of problem
they are. Every variant is gated against its own `KNOWN_GAPS` list, and the gate itself is the
`[gate] require` tier from `project.toml` (`semantic`): 0 known gaps at -O0 (89/89), 3 unnamed-unit
references at -O2 (86/89), 12 32-bit data references at `-m32` (77/89). For the -O2 row it also
re-scores each unit whose *analysis* size differs from the answer key's over the answer key's
range, which is the cross-check that the extent the tool derives is the compiler's.

To check that the scorer's own counts add up (Docs/byte-cleanup-plan.md, Phase 1):

```sh
.venv/bin/python Tests/tools/check_diff_accounting.py
.venv/bin/python Tests/tools/check_gate_tiers.py
.venv/bin/python Tests/tools/check_masked_bytes.py
.venv/bin/python Tests/tools/check_phase4_evidence.py
.venv/bin/python Tests/tools/check_phase5_ledger.py
```

A `replace` region whose two sides are different lengths used to be zipped, so the leftover
lines were counted nowhere: "instructions 5 vs 3 (+-2)" beside "missing 0, extra 0". The gate
asserts the accounting identity instead of hoping for it - `matched + replaced + missing ==` the
original's instruction count, the same on the candidate side, one `diff` entry per counted line,
and `size delta == extra - missing` - over synthetic streams built to shrink, to grow, to do both
in one diff, and to hide a relocation in a matched line; then over every verdict the benchmark
can produce (each unit of all three ELF variants, the wrong candidates, and truncated extents:
285 verdicts, 32 with a difference, 17 whose length differs). A verdict that reports different
instruction counts with nothing in `missing`/`extra` fails the group by name.

**What the gate is** (Phase 2, `Docs/byte-cleanup-plan.md`). `Tests/project.toml` and
`decomp/project.toml` carry `[gate] require = "semantic"`, and `check_phase2_try.py` /
`check_phase5_o2.py` gate on the tier the target config states, so the pass counts in this file are
tier counts. Measured with it, on the untouched source: **-O0 89/89, -O2 86/89, -m32 77/89**, means
unchanged (100.00 / 99.91 / 99.38) - six units out, all six an operand difference on a reference
the two sides cannot pair (`leaq SYM1(%rip)` against `leaq SYM0(%rip)` at -O2, an object named
`DAT1` against `DAT0` at -m32), all six named in `KNOWN_GAPS` with the reason. Phases 4 and 5
moved those counts again (79 / 78 / 59 today, see "known gaps" below for what each cap is and what
would lift it); the means did not move. The tiers, lowest
first: `structural` (same length, operations and targets), `semantic` (+ every operand right, +
streams identical once registers are folded), `exact` (+ the bytes are equal once the fields the
link writes are zeroed on both sides); `percent` and `none` are the escape hatches, and `--gate`
overrides per call.

`check_gate_tiers.py` is the acceptance for the tiers themselves: a swapped `subss`, a dropped
`mulss`, a wrong immediate and a different callee never reach `semantic`; a pure register-allocation
difference does (reported "allocation only", folded streams identical); `movl %eax,%ecx` vs
`movq %rax,%rcx` stays an opcode difference; and it prints the tier histogram of every variant
(-O0: exact 89, -O2: exact 86 + structural 3, -m32: exact 77 + structural 11 + none 1).

**What `exact` means** (Phase 3, `Docs/byte-cleanup-plan.md`). Two bodies that reach the same
things in the same order still differ in the bytes the link writes - a call's displacement, a
pc-relative offset, the address of a global - so comparing those bytes compared nothing. The
masked byte comparison zeroes exactly those fields on each side: the candidate's come from its own
relocation table, the original's from the address-carrying operands of its decoded instructions
(including the calls an object file resolves in-section). Everything else is compared, including
the length of each encoding.

`check_masked_bytes.py` is the acceptance for that. It checks where the field actually sits on real
encodings (a `0f 8x` rel32 starts two bytes in, not one; in `cmpb $0, x(%rip)` the displacement is
at offset 2, not length-minus-four; an immediate is not a field unless something resolves it, and in
a non-PIE 32-bit object `pushl $_ZTI...` is), that a call-and-globals body whose only difference is
the link's addresses masks to equal, that a `jmp short` against a `jmp rel32` to the same function
is caught at the byte level and named with its offset and instruction, that a field only one side
has is not hidden, and that a cold partition is masked at its offset in the concatenated body.
Measured on the untouched source, identical bytes without masking versus with it: **-O0 54 → 89 of
89, -O2 55 → 86, -m32 58 → 77** - every unit that reaches the gate also proves its bytes, and the
units below it are exactly the `KNOWN_GAPS` above.

Phase 4 asks the other question about a reference: *what is it, and how wide*. A `float` pool entry
and the `double` next to it used to be interchangeable, because the tool only asked whether both
sides could see a reference at all. The access width now comes from the instruction (`movss` reads 4
bytes, `movzbl` 1), the bytes a reference names are compared at that width, a string is compared at
the length the original cached plus its terminator against a candidate read that stops at its own
NUL, and a match none of that can prove is counted as **`unverified`**, which caps the tier at
`structural` unless the project says `[gate] waive = "unverified"`. Two things had to be true first:
a RIP-relative relocation names the object at `addend + field width`, not at the addend (the
candidate had been reading four bytes past every RIP-relative access), and a candidate section is
refused only where a relocated *window* sits, not wholesale - every constant pool carries
relocations. Measured afterwards on the untouched source, units reaching the gate: **-O0 89 → 87,
-O2 86 → 84, -m32 77 → 63**. The first two rows' losses are MATH-13 and STRUCT-21, whose
references are `.bss` data neither side can name; the m32 losses are the same rule applied to PLT
thunks whose import the stripped binary does not name. What it bought: 351 float references now
carry `bytes` evidence, 353 strings are compared as strings, and `check_phase4_evidence.py` proves
the point - MATH-20's `360.0f`→`359.0f` and STR-15's `x%.1f`→`x%.2f` both fail the gate, naming
the bytes and the instruction they are read at.

To check the match ledger (`Docs/byte-cleanup-plan.md` Phase 5):

```sh
.venv/bin/python Tests/tools/check_phase5_ledger.py
```

Two function bodies of the same measured size are not a name for *which* helper a call reaches, so
a callee matched on size alone now counts with the references that are not verified and the unit
stops at `structural` until something proves the pair. What proves it is the ledger: `decomp try`
writes `(variant, entry, kind)` → the candidate's own spelling of it for a unit that reaches the
gate, plus every reference it proved by name, string or bytes — never on size — and every later
unit that reaches that address is scored against it. The synthetic groups cover both directions: an
unnamed same-size callee caps the tier at `structural` and names the reference; bank the pair and
the same source reaches `exact` with every callee reading `ledger`; rename it in the ledger and the
unit fails, naming the address and both names. Two named callees of different sizes were never
allowed, and a candidate that names nothing is not refuted, only unverified. The token groups are
the other half of the plan: a callee the loop already has a name for gets the same token in every
unit, so pairing no longer depends on the order the two sides happened to reach it. Then the real
target: `MATH-24` at -O0 is capped by one helper (`SquareRootNewton` at 0x102e1e), the frontier
query names exactly that callee, banking it takes the unit to `exact`, renaming it in the ledger
takes it to `none`, and `decomp ledger` / `--json` are checked as the loop sees them (`--limit`,
`--no-frontier`, and `try --no-learn` included). It runs against a *copy* of the analysis
(`cache/phase5-ledger`, generated `Tests/phase5-scratch.toml`) because a ledger changes scores by
design and the other suites measure the target without one.

To check the `-O2` work itself (`check_phase5_o2.py`, named for the earlier phase list):

```sh
.venv/bin/python Tests/tools/check_phase5_o2.py
```

Three claims, none of them this tool's own opinion. **The extent:** for every unit of all three
ELF builds, the `(address, size)` that `extract` settles on equals the answer key's - which comes
from the *unstripped* build's symbol table, while the tool is only allowed the stripped file
(89/89 on each). **The loop:** the untouched source at `-O2` through `decomp try`'s own path must
hold (measured 99.91% mean, 78/89 past the tier gate - 86 before the match ledger's same-size rule,
see above - against the harness's 98.27%/72). **The two
mechanisms that make a split body comparable:** a unit whose bytes sit at 0x1000 and 0x9000
tokenises as one stream with unit-relative labels (`jmp L6`/`jmp L0` - positions, not addresses),
and the register-folded comparison (`normalize.abstract_registers`, run on every score) makes
`movl %eax, %ecx` and `movl %r9d, %r8d` the same token while a *different* choice stays different.

To check the tool's own discovery and toolchain detection (Phase 3):

```sh
.venv/bin/decomp analyze build/gcc-o0/da_tests --variant gcc-o0   # the unstripped build
.venv/bin/python Tests/tools/check_phase3_discovery.py
```

Detection is judged against `build.json` (the compiler, class, PIE/static, and the exact flags
the generated `project.toml` must reproduce) and against the `-O` the variant really used -
exactly for `-O0`, "not -O0" for `-O2`, since the shape of a prologue cannot tell -O1 from -O3.
The `-O` sample is narrowed to the answer key's own address span, because the -m32 build is
statically linked and most of its image is glibc. Discovery is judged against the answer key's
unit addresses and the source's own names: a string search must reach the same code in the
stripped and unstripped builds, `--family` must bring back every unit of a family, and a
vtable's slots must resolve to that class's methods. (That is why the *unstripped* build is
analysed too: name and vtable queries need names to find.)

To check the tool's own C++ structure recovery (Phase 4):

```sh
.venv/bin/python Tests/tools/check_phase4_structures.py
```

Nothing here may use a symbol name, so it runs against `build/gcc-o0/da_tests.stripped`. The
classes, their bases, their vtable slots, their constructors/destructors and their member
offsets are judged against `answer_key.json` (which names the compiler's own ctors, dtors and
virtual methods with their addresses) and against the layout in
`TestBinary/TestFunctions/structs.h`, including the 32-bit one (`gcc-o0-x86`: members at
`+0x4`/`+0x8`, not `+0x8`/`+0xc`). It also compiles the header `decomp types --write`
produces (`g++ -std=c++17 -fsyntax-only`) - a wrong layout has to fail the candidate's build,
not the tool's opinion - re-scores STRUCT-24 to prove both sides name the same `type_info`,
and requires the opposite result on `Tests/Proprietary/notepad.exe`: an MSVC binary's RTTI is
not this format, so claiming a class there would be a false positive.

## A real proprietary target (`Tests/Proprietary/`, gitignored)

`notepad.exe` is a shipped MSVC binary, PE32+ (Docs/MSVC-Plan.md §2 says what it is and how to
re-measure it). It is not built by `eval.py` and has no `answer_key.json`: its answer key is
the `.pdata` function table and the public PDB Microsoft serves for it (MSVC-Plan §4) - and
since MS-1 the tool reads that table itself. To check the tool's own PE support (MS-0 + MS-1):

```sh
.venv/bin/decomp analyze Tests/Proprietary/notepad.exe     # ~110 s, needs Ghidra once
.venv/bin/python Tests/tools/check_pe_target.py
```

Nothing there needs a compiler - it is the target side only. It asserts the facts the file
carries (container, 28 imports, the v141 toolset cross-read from the Rich build id, the PDB
GUID and its URL, POGO/LCTG), reads a `.rdata` string's bytes at the address the analysis
named, asks what the PE's own address offset is (0, with the basis named), re-reads a COFF
`.obj` if a COFF-emitting compiler is installed, and runs `decomp find`/`show` as the CLI runs
them.

Its MS-1 group is the function-table half: all 186 `.pdata` units are in the cache with the
extents the file gives, the disagreement with the analysis is reported with the numbers
MSVC-Plan §3 measured by hand (154 agree, 32 the analysis reports shorter, 0 longer, 0 units
without an entry, 35 entries the file names no unit for), a unit the analysis cut short is
compared at the compiler's extent, a body split across ranges with a gap in it is read
contiguously across that gap, and `find`/`show` say which entries the table does not name. It
then re-checks the ELF path, which has no unit table and must be unchanged. Exit 1 means a
fact came out wrong; exit 2 means the target or its analysis is missing.

## Building the benchmark itself as a PE (MS-2)

`Tests/project.toml` has three PE-capable variants. `cl` needs the MSVC toolchain of
Docs/Setup.md §6 on PATH (and `WINEPREFIX` set, since the wrappers shell out to Wine):

```sh
PATH=$PWD/toolchains/msvc/bin/x64:$PATH WINEPREFIX=$PWD/.wine \
  .venv/bin/python Tests/eval.py build --variant msvc-o0
.venv/bin/python Tests/tools/check_msvc_toolchain.py      # exit 0 = the toolchain and its SDK
.venv/bin/python Tests/tools/check_msvc_x86_install.py    # the same probe at the x86 target (X86-1)
```

`msvc-o0`/`msvc-o2` are real MSVC variants (`cl /Od`, `/O2`, `/MT`). `mingw-o0` is **not** an
MSVC variant and never a stand-in for one (Docs/MSVC-Plan.md §1) — it is here because it is the
only PE this machine can build without an MSVC toolchain, so it is what exercises eval.py's PE half:
the answer key comes from the file's `.pdata` function table (read with stdlib only) plus names
from COFF symbols or from a linker map, `strip` is skipped (a PE from `link` has no symbol table
to strip), and the reference binary is run through `wine64`.

Measured on **both `msvc-o0` and `msvc-o2`**: `answer key: 89 units (89 markers in source)`, no
unresolved marker, and `selfcheck` → `89 cases, 0 failures`. Measured on `mingw-o0`: the same
`89 units` and `89 cases, 0 failures`. Note the difference in what the two kinds of PE say: an
**MSVC**-built x64 PE has one `.pdata` record per function (`notepad.exe`: exactly 186) — **except**
for functions the compiler gave no prologue and no epilogue, which get no unwind record at all
(12 of 89 at `/Od`); a **GCC**-built one splits a function across several records. eval.py prints
the count from each source and falls back to symbol spacing for the extents it cannot get from
`.pdata`. Two build rules that only the MSVC driver enforced, both measured:

* **Only the top source directory goes on the include path.** With `TestFunctions/` on it, `cl`
  finds that directory's `math.h` for the C runtime's own `<math.h>` (cl searches `-I`/`/I`
  directories for angle includes; GCC's `<cmath>` escapes them with `#include_next`) and the CRT
  headers then fail on their own using-declarations
  (`cstdlib(20): error C2039: 'fabs' is not a member of '`global namespace''`).
* **`/link` comes last.** `/Fe:` and the objects precede it; an object after `/link` is
  `cl : Command line error D8003 : missing source filename`.

## Which target bitness the installed MSVC toolchain can build (MSVC-x86 X86-0)

```sh
.venv/bin/python Tests/tools/check_msvc_x86_toolchain.py   # exit 0 = the report matches the tree
```

No compiler runs here, and nothing is built: this is the report check that [MSVC-x86-Plan.md](../Docs/MSVC-x86-Plan.md)
X86-0 asked for, and it is meant to pass **both before and after X86-1**. For each target arch in
`x64 x86` it measures the tree itself - `VC/Tools/MSVC/<v>/bin/Host*/<arch>/cl.exe`, the toolset's
`lib/<arch>` CRT import libraries, the SDK's `Lib/<ver>/{ucrt,um}/<arch>`, the `<prefix>/bin/<arch>/cl`
wrapper - and asserts that what `decomp check` prints agrees with it, that `can_build` is only true
when the first three all hold, and that `on_path` is judged by the wrapper directory. It also asserts
the two things the operator asked for directly: an x64-only toolchain is called x64-only and comes
with the install command that would add the 32-bit target, and a `[variants.*] arch = "x86"` MSVC
variant is named **before any work starts** (`arch <name>`, a warning, naming which half is missing
and which is present) while `arch = "AVX2"` - an ISA level, not a bitness - is not contradicted. A
GCC `arch = "x86"` variant is named only when `g++ -m32` really fails. Exit 2 means there is no
MSVC toolchain here to judge.

Measured 2026-11-07, on the v141 tree this machine has (`toolchains/msvc`, `Hostx64/x64`, `lib/x64`,
SDK x86 import libraries present, `lib/x86` absent): 38 checks, exit 0, run twice - once with a
default shell (`cl` off PATH) and once with the documented `PATH=$PWD/toolchains/msvc/bin/x64`.
Both report `msvc target x64 ok`, `msvc target x86 warn - x64 only: no 32-bit target from this
toolchain`. **That x86 line is what X86-1 changed**: re-run after the install below, the same 38
checks pass and the report says `msvc target x86 ok`. `check_msvc_toolchain.py` and
`check_msvc_detect.py` still exit 0; `check_coff_candidate.py`
exits 1 the same way it did before this change (19 units land at `structural` at 100% bytes - see
the MS-3 section), which was verified by running it with `decomp/check.py` stashed.

## A 32-bit MSVC target compiler on the machine (MSVC-x86 X86-1)

```sh
.venv/bin/python Tests/tools/check_msvc_x86_install.py   # exit 2 = no x86 target installed to judge
```

The machine-side half: it runs the [../Docs/Setup.md](../Docs/Setup.md) §6.8 probe at x86 through the
installed wrapper, which the report check deliberately never does. Four groups: both target halves
in the tree (`Host*/<arch>/cl.exe`, `lib/<arch>`, `bin/<arch>/cl`); the banner of *both* wrappers,
which must agree with each other and with the toolset directory (`cl` says 19.12 where the
directory says 14.12 - the §6.3 offset, and the compiler's own banner names its target `for x86`);
then `#include <vector>` compiles and a `/MT` console program **links**, with no bitness flag
anywhere in the command line - the flags are `build_flags()` for a variant that names no `arch`, so
the only thing that decides the target is which `cl.exe` ran; and `extract.CandidateObject` reads
the `.obj` back as `machine I386 / bits 32`, while the same source through `bin/x64/cl` reads
`AMD64 / 64`. The i386 `.exe` is asserted to be a 32-bit PE and **not run**: a 32-bit *guest* is a
different question than a 32-bit *target* (Setup.md §6.7), and nothing here is gated on running one.
Nothing is claimed about i386 codegen (X86-3/X86-4) or about what `arch = "x86"` selects (X86-2) -
the probe calls the wrappers directly, which is why it does not go through `decomp compile`.

Measured 2026-11-07, after `toolchains/install_msvc.py --architecture x86 x64` (15 packages /
580.8 MB against the x64-only selection's 11 / 513.1 MB - the added four are `Tools.HostX64.TargetX86`
and the x86 CRT desktop + OneCore packages; the prefix went from 1.1 GB to 1.4 GB on disk, and 23
libraries were linked for x86 out of `lib/onecore/x86`, against 22 for x64): 25 checks, exit 0,
run twice, with and without the documented `PATH`. Both compilers answered `Version 19.12` / one
toolset / `for x64` and `for x86`; the x86 probe linked and its object read back I386/32.
`check_msvc_x86_toolchain.py` still exits 0 on the new tree - it was written to measure the tree
rather than remember this machine - and the `decomp check` lines moved from
`msvc target x86 warn` to `msvc target x86 ok ... Hostx64/x86/cl.exe`.

## Which driver a variant gets (MSVC-x86 X86-2, 2026-11-07)

A variant's `arch` selects the compiler. For `cl` that is a different executable per target bitness
(`<prefix>/bin/x86/cl` vs `bin/x64/cl`) — never a flag — so `Tests/eval.py` and the `decomp` tool now
ask one resolver (`decomp.toolchain.compiler_for`) instead of taking whatever `cl` a shell has.

```sh
.venv/bin/python Tests/tools/check_msvc_x86_toolchain.py     # nine groups, exit 0, ~2 min
```

The X86-2 groups are the ones that spend a compiler (groups 1–5 are the X86-0 report check):

* **6** `build_flags({'compiler':'cl','arch':'x86'})` carries no `-m32` and no `/arch:IA32`, and is
  identical to the x64 variant's flags; `/arch:AVX2` and GCC's `-m32` are unchanged; a path-named
  `cl` is given `/c /Tp /Fo`, not `-c -o`.
* **7** `arch = "x86"` resolves to `toolchains/msvc/bin/x86/cl` and **the object it builds measures
  32-bit**; `arch = "x86-64"` resolves to `bin/x64/cl` and 64; the driver's directory and the object
  agree. A variant that names its driver by path is honoured (with a warning, not a substitution), and
  the rule order is checked with a real `PATH`: PATH first for the bitness it serves, then the
  installed toolchain by path, with the ruled-out driver kept in the record.
* **8** a config that pins an `[msvc] prefix` with no x86 driver gets `refused=True`, an **empty
  command**, and no object file — the missing target is named before any compiler runs.
* **9** the old safety net still fires: a 64-bit object against the cached 32-bit analysis is refused
  as a usage error, now naming the driver and the bitness it emits as the cause.

`decomp try` prints the driver it resolved before it compiles (`driver … - targets x86, <why>`), stops
with that gap and exit 2 when there is no driver for a variant's `arch`, and `try --json` records
`driver` / `driver_arch` / `driver_from` next to `flags` in every result; `decomp link` refuses the
same variant before linking anything. That is `Tests/tools/check_driver_resolution_cli.py` (it drives
the real argv and exit codes, and needs the cached `msvc-o0` / `gcc-o0-x86` targets):

```sh
.venv/bin/python Tests/tools/check_driver_resolution_cli.py    # ~3 min, exit 0
```

or by hand, the MS-3 path with the driver line on top:

```sh
.venv/bin/python -m decomp.cli try 0x140002910 Tests/TestBinary/TestFunctions/math.cpp \
  --fn '?AbsDiff@CMathTests@@SAHHH@Z' --bin Tests/build/msvc-o0/da_tests.stripped \
  --config Tests/project.toml --variant msvc-o0 | head -4
```

`Tests/project.toml` pins `[msvc] prefix = "../toolchains/msvc"`, so these checks and `eval.py` do not
depend on the caller's `PATH`; delete the table to go back to discovery. Sharing the flag rule did not
move the benchmark: `eval.py build --variant msvc-o0` still produces the same `.text` (133904 bytes,
md5 `1e773b94118b0360ae5deaf23c68f948`) and the same 89-unit answer key. Its old extra `/FS` is gone —
it serialises PDB writes and the benchmark builds objects one at a time.

## A check that never returns (MSVC stalls, 2026-11-07)

```sh
PATH=$PWD/toolchains/msvc/bin/x64:$PATH .venv/bin/python Tests/tools/check_msvc_toolchain.py
PATH=$PWD/toolchains/msvc/bin/x64:$PATH .venv/bin/python Tests/tools/check_msvc_detect.py
```

Both used to be described as "slow, many minutes"; in a shell without `WINEPREFIX` they never
returned a status at all, which is what left X86-1's §7 re-run incomplete. Two causes, both
measured, both fixed in [`../decomp/spawn.py`](../decomp/spawn.py) (write-up:
[../Docs/Setup.md](../Docs/Setup.md) §6.12):

* **Wine with no `WINEPREFIX` is stuck, not slow.** `cl /?` in the fallback `~/.wine` produced
  nothing at 100 s; the same call in this repository's own `.wine` answers in **0.9 s**. Any command
  that goes through Wine - a wrapper script, or `wine`/`wine64` named directly, which is how a built
  PE gets *run* - now gets the project prefix when the caller set none, and the tool says it did.
  `decomp check` gained a `wine prefix` row that names the prefix in effect, or warns that there is
  none. An exported `WINEPREFIX` always wins.
* **`subprocess.run(timeout=n)` is not a deadline.** CPython kills the direct child - a `bash`
  wrapper - and then waits for pipe EOF that the wrapper's `sed` jobs, its `wine64` and the
  `wineserver` behind them keep open. Every timeout in the tool was nominal, and the MSVC banner
  probe asks up to fourteen tools in up to three spellings each, so "120 s per tool" was really
  hours. `spawn.run()` puts the child in its own process group, reads both pipes in threads and
  `killpg`s the group at the deadline: a call that will never answer returns *at* the deadline,
  labelled `timed_out`, with whatever arrived. `check.Tool`'s banner probe is bounded at 20 s and
  cached per tool path, so asking about the same toolchain twice no longer waits twice.

Measured after the fix, in the exact shell that used to hang (`PATH` with `toolchains/msvc/bin/x64`,
**no** `WINEPREFIX`): `check_msvc_toolchain.py` **exit 0 in ~50 s** - identity, probe compile at
/Od and /O2 (different bytes, one `.text$…` COMDAT per function), probe link and run under Wine,
and group 4 as `eval.py build` **2.5 s** + `selfcheck` **89 cases, 0 failures**. `check_msvc_detect.py`
**exit 0 in ~50 s** - all six groups, including the three-level `/Od` vs `/O1|/O2` shape probe and
the `.pdata` unit sample. `decomp check -C Tests/project.toml` answers in 2.3 s.
`check_coff_candidate.py` waits out no compiler timeout any more; its known pre-existing 19-unit
gate failure is unchanged. The documented invocation (with `WINEPREFIX=$PWD/.wine` exported, where an
explicit prefix wins over the tool's default) was re-run the same day: both scripts exit 0, together
in under 90 s.

One thing this exposed about running the suites: several of them share `cache/ghproj/candidates-*`
and `Tests/build/<variant>/`, so **do not run them in parallel**. Four started together made
`check_gate_tiers.py` report "the candidate object is 32-bit … but the analysis of this target is
x86:LE:64" - a sibling's object, not a regression; run alone it is `all groups passed`, exit 0.

## Scoring a COFF candidate against a PE target (MS-3)

With the benchmark built (`msvc-o0`) and analysed once, the whole loop runs on a PE:

```sh
.venv/bin/decomp analyze Tests/build/msvc-o0/da_tests.stripped --variant msvc-o0
.venv/bin/python Tests/tools/check_coff_candidate.py            # puts the repo's own
                                                                # toolchains/msvc/bin/x64 on PATH
```

Three groups, in the order the risk falls. **(1) Extents** - a COFF symbol has no size and no
function flag, so this is the part that can silently compare the wrong bytes: for every unit, what
`extract.CandidateObject` derives must equal what the original side reads (the image's `.pdata`
where it names the function, the analysis' body where it does not). All 89 agree; the script prints
how many came from a COMDAT section and how many from the next symbol in the section. **(2) The
loop** - the untouched source through `decomp try` for every unit, the same call
(`cli.score_candidate`), the same threshold and the same KNOWN_GAPS discipline as
`check_phase2_try.py`: **89 of 89 scored, 100.00 % mean, 54 byte-identical, 89 identical once the
fields the link writes are masked.** The *gate* result is not what it was when this paragraph was
written: since the tier rules landed, 70 reach `exact` and **19 land at `structural` at 100.00 %
with `bytes +0 {}`**, because a callee neither side can name caps the tier there. That is the
naming gap (X86-0 recorded the same 19 units as a pre-existing MS-3/MS-6 question, and
`check_coff_candidate.py` exits 1 on them), not the COFF reader: extents, bytes and categories are
all clean. `STRUCT-24` is one of the 19 — its unverified reference is `__RTDynamicCast`, original
side `FUN_14000e794`, "nothing on either side names it" — and because
`check_msvc_structures.py`'s loop group asserts that same unit passes, **that group now fails for
the same reason** (re-measured 2026-11-07, and identically at HEAD without X86-4's changes, so it is
not a consequence of that phase). Both wait on the same thing: a name for a CRT helper a symbol-less
`/MT` image does carry but does not say (the fetched PDB's `S_PUB32` rows, or the ledger). **(3) The wrong candidates** of
`Tests/examples/candidate_math_bad.cpp`, built by `cl`, still reported as the kind of wrong they
are. `msvc-o2` runs the same script over the `/O2` build and is **measured but not gated** (no
`KNOWN_GAPS` entry = report, don't fail): 91.40 % mean, 75 of 89 past the gate, because `cl /O2`
splits a function into hot and cold COMDAT blocks and the image's `.pdata` then names a block.
Group 3 is held to its categories for `/Od` only: at `/O2` the optimiser can make a deliberately
wrong candidate score 100 %, which is a fact about the gate, not a bug in the report.
Exit 2 when there is no `cl`, no build, or no analysis of it.

`decomp check` prints the same facts about the installed toolchain (versions, the toolset family,
the Windows SDK state).

## Reading i386 COFF: a 32-bit MSVC candidate (MSVC-x86 X86-3, 2026-11-07)

`check_coff_candidate.py` is the x64 candidate side and stays that; a second arch inside it would
change what its numbers mean. The i386 side is its own script, and it asks one question x64 never
has to ask: **on i386 every reference to something outside the body is an absolute 32-bit field**
(`I386_DIR32`), not a pc-relative one — and a field whose width the tool does not know is a field it
cannot mask, cannot read an offset out of, and cannot compare.

```
.venv/bin/python Tests/eval.py build --variant msvc-o0-x86          # ~3 s, no `cl` on PATH needed
.venv/bin/python -m decomp analyze Tests/build/msvc-o0-x86/da_tests.stripped \
        --variant msvc-o0-x86 --config Tests/project.toml            # Ghidra once, cached
.venv/bin/python Tests/tools/check_msvc_x86_candidate.py             # ~35 s
```

The candidate objects are built through `compile.build(variant=…)`, i.e. the same driver resolver
`decomp try` uses (`arch = "x86"` → `toolchains/msvc/bin/x86/cl`), and every object the script reads
must *measure* 32-bit: an x64 object handed to an i386 target would be scoring nothing.

1. **The field rules**, no target needed. The width of every `IMAGE_REL_I386_*` field as LIEF spells
   it (`TYPE.I386_DIR32` — and LIEF reports a record `size` of 0, so the type table is the only
   source of a width); no i386 record biased as though it were pc-relative; the same rule pointed the
   other way, an x86-64 `R_X86_64_PC32`/`PLT32` on a call keeps its `+4`; and the two i386 spellings
   of "reach outside the body" — a `[disp32]` memory operand and a relocated `$disp32` immediate —
   found at the same offset at the same width, with an *unresolved* immediate left a constant.
   Measured against one real object: `math.obj`, 84 functions (5 their own COMDAT, 79 bounded by the
   next symbol), 784 relocations, all 784 with a known field width (0 were, before the fix).
2. **Extents**: 89/89 units — the extent read out of the `.obj` equals the extent the original side
   is compared over. An i386 PE has no `.pdata` (only `.xdata$x`/`.sxdata`), so the original side is
   read over the analysis' body: the `gcc-o0-x86` situation, which is why these numbers belong next
   to the `-m32` ones and not next to `msvc-o0`'s.
3. **The loop**: 89/89 scored, **mean 99.75 %**, byte-identical 52, identical once the link-filled
   fields are zeroed 86, tiers `{exact 66, structural 17, none 6}`, **66 past the gate**. The floor
   is in the script as `{extents: 89, pass: 66, mean: 99.75}`, taken from this run — X86-3 refuses
   to invent a floor before measuring one. `--all` lists every unit below the gate.
4. **The controls** (40.00 %, 38.10 %, 88.89 %) still reported as the kind of wrong they are.

The 23 that stop short are two families, and neither is a reading gap — `decomp try` says so on its
own, which is how they were classified:

* 15 reach 100.00 % with identical masked bytes but a callee neither side can name — `SYM0 original:
  FUN_004076e0 candidate: ?ToLowerChar@@YADD UNVERIFIED` — so the tier caps at `structural`. The
  naming gap (a PDB's `S_PUB32` rows, or the ledger), not this one.
* 8 are operand differences, 7 of them one shape: `- subss 0x41f488(%ecx), %xmm0` against
  `+ subss (%ecx), %xmm0`, because in the object the base of that address is a relocation placeholder
  and in the image it is the final address. X86-6 ("the i386 normalisation both 32-bit paths share")
  is the same set of units that caps `gcc-o0-x86`.

Two facts the answer key needed, both measured rather than read off documentation: `link /MAP` writes
`Rva+Base` at the image's own pointer size — 8 digits for a 32-bit link, 16 for x64 — and an i386 PE
carries no function table at all, so its key is the map with extents from symbol spacing, printed as
the worse key: `note: da_tests carries no .pdata … its answer key is link /MAP: 906 names` → 89 units
matched to the source markers. Goldens warn (`/lib/ld-linux.so.2: could not open`: this Wine cannot
run a 32-bit image), and `crosscheck` treats that as "no goldens". (Superseded the same day by
X86-4 below: with wibo installed the 32-bit program runs, its goldens are captured, and its
self-test passes.)

## Which operand owns a relocated field (§37, 2026-11-08) #x86-32 #relocation

A 32-bit object stores an address as `movl $0x0, 8(%esi)` plus an `IMAGE_REL_I386_DIR32` sitting on
the immediate. Those four bytes are also what a slot list built from instruction *length* would call
the memory operand's displacement — and only one of the two is a field of the instruction. The
binder preferred the memory operand ("pair the address operands first"), so the reference resolved to
the right object and was attached to the wrong operand, the immediate kept its literal `0`, and the
differ reported an `operand` difference on a field the link fills in. Every unit that stores a vptr,
a global's address or a function pointer was capped by it — on the WinRAR 4.11 image, 2,067
instructions in 726 bodies.

Group 6 of `check_msvc_x86_candidate.py` is the acceptance, asked of **both** 32-bit toolchains:
`Tests/probe/x86_addr_store.cpp` stores `&g_slot` through `(%ecx)`, through `8(%esi)` and into a
stack slot, and each must bind exactly one reference, to the `imm` operand, naming `g_slot`, of class
`data`. `store_constant` — same shape, no relocation — must bind nothing, because the rule is about
who owns a relocated field, not about inventing references. With the fix stashed out the group fails
six times (`bound to disp`); with it, six pass (`bound to imm`). Nothing else moved: `check_coff_candidate`
stays at `{exact 70, structural 19}` (its §22 baseline), `check_masked_bytes`/`check_gate_tiers` at
gcc-o0-x86 `{67, 21, 1}`, and `check_diff_accounting`, `check_phase2_try`, `check_msvc_x86_reference`,
`check_phase4_evidence`, `check_phase6_link` all exit 0. End to end, the unit that started it went
from 29/35 bytes with an operand difference to **35/35 with every category at zero**.

## A driver aborted by its loader is retried once, a compile error is not (§38, 2026-11-08)

`toolchains/*/bin/x86/cl` runs a Windows PE through a loader; that loader sometimes dies instead of
starting the compiler — `wibo: call reached missing import lstrcatW from kernel32`, exit 134, no
object, and not one word about the source. Measured cause: **a `/Fo` whose containing directory does
not exist** (relative or absolute — VC does not create output directories, and under this loader the
failed open never becomes a diagnostic). `compile.build` already creates the directory, which is why
the loop never tripped it and my hand-typed shell commands did.

`compile.loader_aborted()` separates a killed driver from a compiler that judged the source, `build()`
re-runs the command once in the first case and says so (`retried`, printed as a `note:` line by
`describe`), and never retries the second. `Tests/tools/check_loader_abort.py` (21 checks, ~2 s)
drives `build()` with a stub driver it writes itself and counts invocations — abort-then-succeed runs
twice and reports the retry, always-aborts runs twice and reports the loader's line as the failure, a
compile error runs **once** with the compiler's words unchanged, a silent SIGKILL is retried. It does
not depend on the bug recurring on demand.

Two probes from the same day, both read out of objects rather than argued about:
`Tests/probe/x86_addr_store.cpp` (above) and `Tests/probe/wstr_scan_shapes.cpp`, which settles which
C spelling makes VC 9 emit the terminator scan `movw (%eax),%cx / addl $2,%eax / testw %cx,%cx /
jne <loop>` — `while (*p++) ;` does, `while (*p) ++p;` and `for (; *p; ++p)` do not (they emit a
`cmpw $0,(%eax)` test at the top), which is what several bodies of a 32-bit MSVC target show.

## A call to a function of the same object reaches that function (§39, 2026-11-08) #tool #coff #relocation

A decompilation project defines callers and callees in one translation unit, and the image then calls
them directly. In the object the call looks like nothing: an MSVC front end gives every function its
own section — VC 9's `/O2` does it with no flag asked for, a newer driver with `/Gy` — all of those
sections carrying one name, the relocation record naming the callee's symbol, and the four bytes in
the code left at **0**. Capstone reads that as a call to address 0, which is inside the caller's own
body (both sections start at 0), and the rule that turns a branch inside the unit into `L<offset>`
collected it: the differ printed `calll L0` against `calll SYM15` and called it an operand
difference, so a unit that reproduced the call exactly lost its bytes for making it.

Group 7 of `check_msvc_x86_candidate.py` is the acceptance: `Tests/probe/x86_call_pair.cpp` (a caller,
a callee, and a self-recursive function) built by the same driver twice, as it comes and with `/Gy`.
It requires the split object to really be split — two sections sharing a name, or the group would
measure nothing — then holds three rules at once: the cross-section call reaches a **function** named
`?inner_of_this_unit@@YAHH@Z` and tokenises as `calll SYM0`; a self-recursive call is still
`calll L0`, because that one really is an edge inside the unit; and the one-section object, where the
call carries no relocation at all, still reaches its callee by the in-section lookup. 9 checks, exit
0. With the tokeniser's section rule disabled the third line becomes `calll L0` and the group fails;
with the extents still remembered on the `CandidateObject` rather than carried on the `Function`, the
caller's call reports *nothing bound* and it fails the same way — asking a second function about its
extents silently changed which relocations the first one owned, which is the shape of every real
candidate file.

## The 32-bit MSVC reference build and its answer key (MSVC-x86 X86-4, 2026-11-07)

X86-3 made an i386 candidate readable; this is the asset it is read against, and the asset had three
problems of its own. `check_msvc_x86_reference.py` asserts all three, plus the one thing the plan
explicitly refuses to claim.

```sh
.venv/bin/python toolchains/install_wibo.py                          # §6.7 Option B, no root
.venv/bin/python Tests/eval.py build --variant msvc-o0-x86          # ~4 s
.venv/bin/python Tests/eval.py selfcheck --variant msvc-o0-x86      # exit 2 if no 32-bit guest
.venv/bin/python Tests/tools/check_msvc_x86_reference.py            # ~1 s
```

1. **No bitness flag.** `build_flags`/`link_flags` for `msvc-o0-x86` are
   `/std:c++17 /Od /W3 /EHsc /nologo /MT` + `/SUBSYSTEM:CONSOLE`: no `-m32`, no `/arch:IA32`, and
   **no `/MACHINE:X86`** — measured, not assumed: a link is only told what its inputs do not already
   say, and every object here is an i386 object. The assertion is on the file: the linked program is
   `machine 0x14c`, optional header PE32, 32-bit.
2. **One directory, one program.** `link` appends `.exe` to an extension-less `/Fe:` target, so a
   fresh build wrote `da_tests.exe` while an old `da_tests` sat in the same directory — and the
   rename guard (`if not binary.exists()`) never fired. Every MSVC build directory on this machine
   held a fresh `da_tests.map` and objects beside the **previous** build's binary: the answer key was
   built from the new map against the old image's section table, and `da_tests.stripped` — which is
   what gets analysed, because a PE is not stripped — was a copy of the old bytes. The `.text`
   after-strip check cannot see this: it compares a file against its own copy. Now the previous
   `da_tests`, `da_tests.exe` and `da_tests.map` are removed before linking, and the build refuses
   if the map's `Timestamp is …` header and the image's own `TimeDateStamp` disagree. What the
   script asserts: one reference binary per directory, `.stripped` byte-identical to it, map stamp ==
   image stamp, and every answer-key unit address inside an executable section of *that* image
   (89/89; before the fix, a directory with an old image and a new map would have failed here).
3. **The answer key names its own basis.** `eval.py build` prints the extent source under the unit
   count, and `build.json` records it as `answer_key_extents`:
   *`answer key: 89 units …` then `extents: 89 of 89 units came from a link /MAP name bounded by
   the next name (this PE carries no function table)`*. The x64 keys are unchanged (`89 units`, same
   md5s) and their provenance says what they always used — `msvc-o0`: 77 units from `.pdata` + 12
   from the next named boundary; `msvc-o2`: 33 + 56; `mingw-o0`: 89 from `.pdata`. Recording it is
   what keeps "the same 89 units" from meaning two different things across variants.
4. **Running it.** A 32-bit *target* needed nothing from this machine; a 32-bit *guest* needs
   [../Docs/Setup.md](../Docs/Setup.md) §6.7, and this Wine still has no i386 guest (re-measured:
   `/usr/lib/wine` holds `x86_64-unix`/`x86_64-windows` only, and the host's `/lib/ld-linux.so.2`
   resolves now — the failure moved, it did not go away). Option B closes it with no root:
   `toolchains/install_wibo.py` fetches wibo 1.2.0 (sha256 pinned), runs the §6.7 probe — an
   i386 `hello32` that must exit 3 — and installs it at `toolchains/wibo/wibo`, where
   `toolchain.wibo_path()` finds it (`$DECOMP_WIBO`, PATH, that path). `runner()` prefers it for an
   image whose optional header is PE32 and keeps `wine64` for PE32+; with nothing installed,
   `selfcheck` exits **2** naming the option instead of reporting a failure. Measured here:
   `goldens: 89 cases`, `selfcheck` → `89 cases, 0 failures`, and
   `crosscheck: 0 differing cases across 7 variants` — the 32-bit MSVC program behaves like the four
   x64 builds and the `-m32` one on every case (the two pre-existing cross-arch float differences
   are gcc-o0-x86's, and are still labelled expected).
5. **`decomp check` now separates the two facts.** Next to `msvc target x86 ok` it prints
   `run 32-bit PE`, which is about Wine or wibo, never about the toolchain: with wibo it names it,
   with an i386 Wine guest it names that, and with neither it warns with the two commands that fix
   it and the sentence "Building 32-bit code never needed either of them".

Two operational notes. Rebuilding a variant changes the bytes of `da_tests.stripped`, so its analysis
cache entry is new: after any rebuild, re-run `decomp analyze … --variant <v>` before the
candidate-side checks, which otherwise exit 2 and say so. And the rebuild makes every PE directory
self-consistent for the first time, which re-anchors scores on the current link: the seven
`answer_key.json` files are byte-identical (`msvc-o0 d7add1c0…`, `msvc-o0-x86 f6876757…`), but
`check_msvc_structures.py`'s loop group now fails on `STRUCT-24` for the naming gap described in the
MS-3 section above — measured again with these changes stashed at HEAD, so it is not a consequence
of this phase.

Not claimed: any byte score (that is X86-3's, and its floors are unchanged — see the section above),
running a shipped 32-bit target's behaviour, or that wibo is required anywhere: it is a runner, and
the tool works without it.

## The C++ structure of a PE (MS-5)

```sh
.venv/bin/python Tests/tools/check_msvc_structures.py         # groups 1, 2, 5 need an analysed
                                                              # msvc-o0; 3 needs `cl`
```

Six groups, and every expectation comes from the answer key, from `structs.h`, or from what the
file itself carries. **(1) The records**: the model chosen for a `cl` binary is the MSVC one, every
class names a type descriptor, every vftable is claimed by an RTTICompleteObjectLocator, and the
class-hierarchy walk came from the base-class descriptors, not from a symbol. **(2) The
structure**: the three benchmark classes with their bases, **3 vftable slots each** (MSVC has no
offset-to-top and one destructor slot; the Itanium form of the same source has 4), every slot
pointing at the answer key's real method, no constructor or destructor claimed that the compiler
did not build for that class, the real ones identified where the file proves them, the member
offsets of `structs.h` in the Microsoft x64 layout (`+0x8`/`+0xc`, `+0x10`/`+0x14`), nothing
outside the object, and a pure slot either claimed or named as a limit. **(3) One object, one
name**: `object_at` on the target's descriptor and `normalize.clean_symbol` on the object's
`??_R0?AVCVehicleEntity@@@8` must produce the same words, and STRUCT-24 must pass `try`. **(4) A
shipped 32-bit binary**: `Tests/Proprietary/deadrising2.exe` - 770 type descriptors, 769 classes,
hierarchy, nested names, absolute-address records reported as such, and its 27,796-line `types.h`
compiling. **(5) Notepad**: no `.?AV` string, so no classes, and the reason in the notes. **(6) A
MinGW PE is not an MSVC target**: `Tests/build/mingw-o0` must be read by the Itanium model.
Exit 2 for a group whose target or compiler is absent.

The `cl`-needed group is the one MS-3 left open, so if you are changing RTTI naming, run both
this and `check_coff_candidate.py`: the second is the one that turns a naming failure into a
failing unit.

## What an MSVC build is (MS-4)

```sh
PATH=$PWD/toolchains/msvc/bin/x64:$PATH WINEPREFIX=$PWD/.wine \
  .venv/bin/python Tests/tools/check_msvc_detect.py
```

Seven groups, and only two of them need a compiler — see
[What a 32-bit MSVC build is](#what-a-32-bit-msvc-build-is-msvc-x86-x86-5-2026-11-07) for the
seventh, which is the 32-bit one. **(1) The toolset, read twice**: the Rich
header's linker record (id 258) gives build 25711 on `notepad.exe`, which reads as the 14.12 its
optional header states, so `agree` must be true; the records that name no toolset (id 1 at build
0, id 147 at build 30729) must stay out of the identity — the same 30729 appears in a 2018 OS
binary and in a file this machine links today, which is what the assertion is built on. The
anchor group then builds a PE with the installed toolchain and requires its Rich build to equal
the build `link.exe` prints in its own banner: the toolset table is anchored on a measured pair.
**(2) Language and runtime**: C++ claimed from a decorated import and labelled with its proof, the
CRT family named from the imports (UCRT / vcruntime / msvcrt / none = `/MT`), all of it checked
against a `/MD` and a `/MT` build of the same source. **(3) `/std:`**: named as what the toolset
bounds, with the levels a 14.12 compiler does not have. **(4) Flags**: `/Od|/O1|/O2` as three
flags, `/MT`/`/MD`, `/GS-`, `/GL` with `/LTCG` on the link, and the `project.toml` `detect`
writes for a PE parsed back and compiled. **(5) The shape profile**: `cl` probed at `/Od|/O1|/O2`,
requiring `/Od` to be far from the optimising levels on the MSVC features and `detect` on the
shipped `/O2 /GL` target to answer an optimising level while reporting `/O1|/O2` as a class, and
reporting `/GS` from the code. **(6)** the ELF path — still the ret-cut sample, still the Itanium
features. **(7)** the 32-bit path — see the X86-5 section. Exit 2 when there is no `cl` (groups 1-4
still run and are reported).

## What a 32-bit MSVC build is (MSVC-x86 X86-5, 2026-11-07)

```sh
# the whole file, with the x64 groups included
PATH=$PWD/toolchains/msvc/bin/x64:$PATH WINEPREFIX=$PWD/.wine \
  .venv/bin/python Tests/tools/check_msvc_detect.py
```

Group 7 is the 32-bit one, and it needs no `cl` on PATH — the driver comes from `[msvc] prefix` in
`Tests/project.toml`, which is how `try` and `check` get it too. It asserts, against this machine's
`bin/x86/cl`: the **x64 feature set reads 0.000** at `/Od`, `/O1` and `/O2` (`rspmem`, `argstore`,
the cookie-xor-`%rsp` of `/GS` — they are Microsoft *x64 ABI* features and cannot carry an answer
here); the **i386 set separates the classes** — `/Od` stands up a `%ebp` frame in 78% more bodies
than `/O1|/O2` do, while `/O1` and `/O2` sit 0.890 apart against `/Od`'s 2.812, so they are
reported as a class; the i386 `/GS` reading (the cookie xor-ed with the **frame** register) is
non-zero at `/Od` and `/O1`. Then `detect` itself: on `Tests/Proprietary/deadrising2.exe` the
readings are non-zero (1 515 bodies), the probe driver is `bin/x86/cl` and is named with why, and
the answer carries the era gap in the same line (`the file names link.exe 8.0, which is outside the
toolset table`) — no v141 `-O` is presented as that file's. The known-answer case is
`Tests/build/msvc-o0-x86/da_tests.stripped`, built here at `/Od`: sampled from the **cached
analysis** it must answer `-O0` with confidence `strong` (measured distance 1.248 against 1.776).
That last group is skipped with a printed reason if the target is not analysed — a 32-bit PE has no
function table, so the analysis is the only sample whose bodies start at real boundaries; the
ret-cut sample ranks `/O1` first and says so in the same sentence. Finally the dialect guards: no
`-fstack-protector` finding for a `built by msvc` file (it gets `/GS`), no x86-64 ISA claim for a
32-bit image, and `fidelity.version_agreement` naming an **x64 driver against a 32-bit file** as a
bitness gap — the one answer `check`, `try` and `detect` all read. And the ranked `-O` rows are
required to name the driver that measured: the label the tool prints must open the same file as the
resolved driver (printing the last 40 characters of the path read
`mpileAnything/toolchains/msvc/bin/x86/cl`, which names nothing).

By hand:

```sh
.venv/bin/python -m decomp detect Tests/Proprietary/deadrising2.exe -C Tests/project.toml
.venv/bin/python -m decomp detect Tests/build/msvc-o0-x86/da_tests.stripped \
  -C Tests/project.toml --sample FUN_        # the analysis sample, real boundaries
```

## The binary

`main.cpp` only parses the mode and hands a `CSelfTest` to the three test classes:
`CMathTests` (loops, comparisons, vector math), `CStringTests` (strncpy/strcat/strcmp,
parsing, buffers), `CStructTests` (structs, unions, bitfields, containers, vtables,
RTTI). `SelfTest.cpp` is the harness they call into.

Three things make it usable as a benchmark:

* **Every unit is called** and is `DA_NOINLINE`, so exactly one body per unit exists at
  one address at every optimisation level. Plain helpers are *not* marked, so they get
  inlined into units at -O2 like in any real binary.
* **89 hand-checked expectations** (`st.Want*`) are inside the binary: CRC-32 of
  "123456789" = 0xCBF43926, gcd(1071,462) = 21, Collatz(27) = 111, primes(100) = 25,
  FNV-1a("hello") = 0x4F9F2CAB, and so on. The ground truth of the benchmark is itself
  tested - `eval.py selfcheck` must print `0 failures` for every variant.
* **A golden trace** (`--golden`) records inputs and results per case, so behaviour can be
  compared between builds, and later used for a Unicorn-style behavioural check.

## Unit annotation

Every unit definition carries one line that `eval.py` reads:

```cpp
// DA-UNIT <ID> level:<easy|medium|hard> tags:<comma,separated,tags>
```

IDs are `MATH-nn`, `STR-nn`, `STRUCT-nn`, in file order, and each also needs a
`DA_CASE(st, "ID")` block in that class's `RunSelfChecks` (add both when adding a unit;
`build` reports any marker without a matching symbol). Tags are free-form; `report`
aggregates whatever is there, which is how coverage is reviewed. Current families:
control flow (`for`, `while`, `nested-loop`, `recursion`, `binary-search`), arithmetic
(`mul`, `div`, `int64`, `bitops`, `shift`, `fixed-point`, `poly`, `float`, `sse`),
data (`rdata-table`, `table`, `const`, `static-state`), types (`struct-arg`,
`struct-return`, `union`, `bitfield`, `field-offsets`, `padding`, `nested-struct`,
`array-of-struct`, `sizeof`), dispatch (`vtable`, `virtual`, `rtti`, `dynamic-cast`,
`fnptr`, `switch-jump-table`), strings (`strncpy`, `strncat`, `strcmp`, `format`,
`parse`, `truncate`), and memory (`ptr-chase`, `double-pointer`, `free-list`, `mask`).

## Evaluation protocol

What the model under test gets:

1. `Tests/build/<variant>/da_tests.stripped` - the only artifact it may read bytes from.
2. `task_list.json` - address + size of each unit, no names, no tags.
3. `decomp show/try/find/types` (once it exists) over that stripped binary.

What it produces: a `.cpp` (its own headers/types) that defines a function for a unit.

Scoring (`eval.py try --unit ID --src file.cpp --fn name`):

* the original bytes come from the **stripped** binary and its addresses are resolved to
  names through `answer_key.json` (from the unstripped build - `strip` is verified not to
  move `.text`, so addresses stay valid);
* the candidate is compiled from source with the *same* flags as the variant, and its
  function is found by name in the `.o`;
* both sides are normalised: branch targets become function-relative labels, call targets
  become demangled names (via relocations on the candidate side), data references become
  ordered `DATA<n>` tokens;
* the score is a token-sequence match ratio plus **categories**: `opcode` (wrong
  operation), `operand` (right operation, wrong offset/type/constant), `missing`/`extra`
  (wrong control flow or size). Read the categories, not the percentage.

A unit counts as **done** at `match >= threshold` (97% in `project.toml`) **and** zero
`opcode` mismatches - matching the design decision that relocation and opcode agreement
are required, not just a ratio.

## Calibration (measured, same machine)

`eval.py self` recompiles the untouched original source and scores it as a candidate.
That is the ceiling: a perfect answer cannot beat these numbers, and any remaining gap is
the harness's fault, not the model's.

| variant | units | mean | identical after normalise | above threshold |
|---|---|---|---|---|
| gcc-o0 (x86-64) | 89 | 99.5% | 78 | 83 |
| gcc-o2 (x86-64) | 89 | 98.3% | 70 | 72 |
| gcc-o0-x86 (-m32, static, -fno-pic) | 89 | 87.2% | 10 | 11 |

Unit sizes: 13.6 KB of unit code at -O0, median 123 bytes, 15 units 32-63 B, 14 over
256 B; at -O2 the median is 77 bytes and 8 units are under 32 B. That bracket is close to
what `calib` measured on deadrising2.exe (median function gap 160 B, 18% under 64 B), so
per-function difficulty is representative.

### Phase 6: `check_phase6_link.py`

The capstone the plan was for: take the functions the loop reproduced, compile them with the
variant's own flags, link them into a program with the variant's own link flags, and ask whether
that is the original program. `decomp link` answers it section by section and function by function
at the addresses the linker chose.

Two claims carry the report. A link is the target's or the tool says so: the variant's `linkflags`
come from the config (`-no-pie -static` for the MS-2 stand-in; "nothing is recorded" for `gcc-o0`),
and the driver form follows `eval.py`, so an MSVC variant would be linked the way the harness links
it. And a difference that follows the layout is a consequence, not a second problem: once one body
is a different length, every address after it moves, so the report names where the layout moved,
labels the bodies whose only difference is an operand the link rewrote, and calls a data value that
differs by exactly a known shift a pointer to moved code. `pair_extents` keeps the discipline the
rest of the project has: a matching length is not evidence, so a length difference the layout does
not confirm is reported as two extents with no pair rather than as a changed function - and an
anchor from the match ledger is the one thing that outranks layout, because it says what a body
*is*, whatever its length.

Measured here: the benchmark program, built from its own sources under `gcc-o0`, relinks with
`16 sections compared: 16 identical`, `.text` identical at 49969 bytes, exit `0`. Add one `if` to
`CMathTests::SolveQuadraticRoot` and the same command exits `1`, names the changed function, names
where the layout moved, and shows 36 of the 143 compared pairs as operands the link rewrote rather
than source differences. Reading a program is LIEF on both sides, so this is ELF only: PE and
Mach-O say so instead of being compared wrongly (Phase 7 of the cleanup plan brings MSVC `link`).

### Phase 7: `check_phase7_fidelity.py`

Two things decide whether the byte gate is reachable that are not `-O`: whether the compiler
installed here is the compiler that made the file, and which flags the build used besides it.
This suite checks that the tool says both, and that it keeps the two kinds of answer apart - a
file's own record versus a pattern its code shows.

The version reading needs no new data: `.comment` (ELF) and the Rich header (PE) are already in the
build note, and the comparison is against the compiler the variant would actually run. A different
minor release is as much of a wall for `exact` as a different toolchain - byte-identity across two
releases is not something a loop iterates towards - so it becomes a `Verdict.build_mismatch`, which
`gaps("exact")` names before the byte differences it explains. A file that names no compiler
(stripped ELF, a binutils-linked PE) is left alone: not knowing is not a mismatch, and no tier is
capped for it. `decomp check` asks the question for every target in the cache before a session
starts; `decomp try` says it again on the score, where the loop reads it.

For the flags, the wording follows the evidence. `ET_DYN` with no program interpreter *is*
position-independent code, so `-fPIC` goes into a generated `cppflags`; `.note.gnu.property` names
CET and the x86-64-vN ISA level in the compiler's own spelling, so those come out as the exact flags
(`-fcf-protection=full`, `-march=x86-64-v3`); a PE's Guard CF bit is the linker's own statement
about `/guard:cf`. A canary in some bodies says some `-fstack-protector` level was on but not which,
`%ymm` says an AVX level without naming it, and a reciprocal pattern is a lead - those are findings
with the evidence quoted, never flags written into a config for you.

Built here with the flags known: three plugins at `-O1`, `-O2 -mavx2 -mfma` and
`-fcf-protection=full -fstack-protector-all`; all three read as shared objects, the AVX one's
property note names `x86-64-baseline` and `x86-64-v3`, the hardened one's names `IBT`/`SHSTK`, and
the plain one is told to build for the baseline rather than for this machine's `-march`. Measured on
real targets: `Tests/Proprietary/Dr Up-down gate.so` says gcc 16.1.1 against this machine's 16.2.1
(a hard cap, named before any `try`) and asks for `-fPIC`; `notepad.exe` declares Guard CF and
names MSVC, so a g++ variant against it is reported as a different code generator, not a bad model.
Scoring the benchmark's own source stays silent - its `.comment` names the compiler installed here -
which is the half that matters: the tool does not raise a toolchain gap where the bytes already match.


## Known gaps

* **Same-size callees are capped until they are decompiled** (since `Docs/byte-cleanup-plan.md`
  Phase 5). A call to a helper the stripped binary does not name, matched only because both bodies
  are the same size, is no longer evidence: those units stop at `structural` — 8 at -O0, 6 at -O2,
  6 at -m32 (MATH-24/27/29, STR-04/07/08, STRUCT-22/25 at -O0). Their instructions, operands and
  bytes all agree; what is missing is a name. The counts went *down* on purpose, and the fix is on
  the loop's side: `decomp ledger` lists those callees by how many functions call them, and banking
  one (which is what `decomp try` does when the helper itself reaches the gate) takes every unit
  that calls it back to `exact` — `Tests/tools/check_phase5_ledger.py` measures that on real bytes.
  `check_masked_bytes.py` and `check_phase2_try.py` print which units those are (`capped only by
  callees matched on equal size`, `LEDGER …`).
* **Unnamed `.bss` data and unnamed PLT thunks** are the Phase 4 half of the same rule: MATH-13 and
  STRUCT-21 at -O0/-O2 (data neither side can describe), and at -m32 the thunks whose import the
  stripped binary does not name. Reproducing the object (structures-plan) lifts them; so does the
  project saying `[gate] waive = "unverified"`.
* **32-bit absolute references are normalised** (was: "-m32 normalisation is weak, 87% ceiling",
  closed by [../Docs/MSVC-x86-Plan.md](../Docs/MSVC-x86-Plan.md) X86-6, 2026-11-08). An absolute
  operand (`movl 0x804a2c4`, `movzbl 0x80dd6a4(%eax)`, `flds 0x804a2c0(,%eax,4)`) and the
  `R_386_32`/`DIR32` that fills the same field in a `.o` are now one reference, reached from either
  side; the placeholder spellings (`(%ecx)`, `(, %eax, 4)`) are read as that field before the link,
  and a `.rel` record that names a *section* takes its offset from the field it sits on instead of
  from 0 — that was anchoring every pool window on the section's first symbol. The floor moved:
  `gcc-o0-x86` is **67 of 89 `exact`** (was 59) with `check_masked_bytes.py`'s `MIN_EXACT` raised to
  67, and its `KNOWN_GAPS` list is down from twelve units to one (`MATH-32`: both sides state the
  table and pair the same operand, but one names an *element* and the other the base plus an index,
  so the four bytes compared at that width are two elements). x86-64 is untouched: `gcc-o0` 79 and
  `gcc-o2` 78 exact, same `KNOWN_GAPS`. What still caps 21 `-m32` units is the same thing that caps
  the x86-64 ones — callees and objects neither side can name (the two bullets above), not 32-bit
  addressing. x86 is still *not* a stand-in for MSVC: "-m32 as the closer match to the 32-bit MSVC
  targets" in `project.toml` is about addressing forms only.
* **32-bit MSVC is a first-class variant now** ([../Docs/MSVC-x86-Plan.md](../Docs/MSVC-x86-Plan.md)
  X86-1…X86-4, all 2026-11-07): the toolset has `bin/Hostx64/x86` + `lib/x86` and
  `bin/x86/{cl,link,lib,ml,…}` wraps them; `arch = "x86"` resolves to that driver (X86-2);
  `_COFF_FIELD_WIDTH` reads the `I386_*` spellings (X86-3); and `[variants.msvc-o0-x86]` is built,
  analysed, scored (`check_msvc_x86_candidate.py`, floor `{extents 89, pass 70, mean 100.00}`) and
  *run* (X86-4: wibo, `89 cases, 0 failures`, goldens captured, `crosscheck` clean). A 32-bit
  *target* needed none of the Wine work; a 32-bit *guest* needed Setup.md §6.7's Option B.
  `decomp check` keeps the two facts apart (`msvc target x86` vs `run 32-bit PE`).
  X86-6 closed the last phase of that plan on 2026-11-08, which is what took `msvc-o0-x86` from
  `{exact 66, structural 17, none 6}` / mean 99.75% to **`{exact 70, structural 19}` at a 100.00%
  mean with all 89 units' masked bytes identical**; the 19 are capped only by references neither side
  can describe. X86-5 closed the same day — an i386 shape profile measured on this `cl` means
  `detect` answers `-O` for a 32-bit MSVC file, probes with the driver of that bitness, and states
  the toolset-era gap inside the answer (see *What a 32-bit MSVC build is* above).
  Two rules for reading any 32-bit MSVC number: a 32-bit PE has no `.pdata`, so its answer key is
  symbol spacing or `link /MAP` (and `eval.py build` prints which), and its numbers belong next to
  the `-m32` row, never next to `msvc-o0`'s.
* **Goldens are per-variant, not portable.** `crosscheck` treats a same-arch difference as
  a bug (there are none) and x87-vs-SSE float differences as expected: `-m32` computes
  `SineApprox` and `InitVehicleDescriptor`'s grip in float registers with different
  rounding, and `ChecksumDescriptorBytes` therefore hashes different struct bytes.
* The -O2 gap that was real codegen is now mostly extent: the tool was comparing Ghidra's range
  instead of the compiler's unit. Since Phase 5 it reads the file's own function table
  (`.eh_frame` FDEs, `st_size` where symbols survive), and the -O2 row moved from 65.88%/34 to
  99.91%/88. What is left of "semantically right but not byte-identical" in this benchmark is
  builtins (`sqrtf` inlined as `sqrtsd` in a `.o` but called through the PLT in the linked
  binary) and jump-table layout - the honest case for the optional behavioural check
  (goldens + Unicorn), which is not implemented.

* **Named data is thin on a stripped target.** `decomp link` compares data sections whole and
  compares the dynamic relocation tables, but it can only *name* a data object when the file's
  symbol table names it - a stripped benchmark target has none, so vtables and static data are
  reported at section level. The Phase 4 structure recovery knows those shapes; wiring it in is the
  obvious next step.
* **The unit table and the symbol table are not the same table.** For this benchmark the analysis
  splits and merges some functions differently from ELF symbols, so `decomp link` reports some
  extents as having no pair instead of naming them. It does not claim a pairing it cannot support;
  what improves it is more anchors (a populated ledger) and a better unit table (Phase 4 records),
  not a guess from size.

* **A target built by a compiler this machine does not have cannot reach `exact`** (since
  `Docs/byte-cleanup-plan.md` Phase 7). `Tests/build/msvc-o0*` and the MSVC files under
  `Tests/Proprietary/` have no `cl` here, and `Tests/Proprietary/Dr Up-down gate.so` names gcc
  16.1.1 while 16.2.1 is installed. `decomp check` says so per target and a scored candidate puts
  it in the gaps for `exact` before the byte differences it explains; the scores of the gcc-built
  benchmark are unaffected, and no tier is capped for a file that names no compiler at all.

## Adding or changing a unit

1. Declare it in the module header with `DA_NOINLINE`, define it under a new `DA-UNIT`
   marker, and add the matching `DA_CASE` block with at least one `Want*` you can justify
   by hand.
2. `python3 eval.py build && python3 eval.py selfcheck` - zero failures, no unresolved
   markers.
3. `python3 eval.py self --variant gcc-o0` - if a unit drops far below the others, the
   unit depends on something unrepresentable (UB, uninitialised padding, a global) rather
   than the model being wrong.

The `normalize`/`score_tokens` half of `eval.py` is deliberately shaped to be lifted into
`decomp/normalize.py` and `decomp/diff.py` when those exist; `answer_key.json` is the
"analysis cache" those commands read.
