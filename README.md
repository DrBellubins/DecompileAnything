![Decompile Anything](Images/DecompileAnythingBanner.png)

`decomp` is a CLI that lets an LLM decompile a function out of a compiled binary and keep
iterating until the candidate recompiles to the same bytes. The tool **never edits source**:
it reports facts about the original binary and scores a candidate the model wrote.

* [Docs/Design-Plan.md](Docs/Design-Plan.md) - the plan, phases, and the design decisions.
* [Docs/Setup.md](Docs/Setup.md) - the environment (Ghidra, JDK, venv) and why it is set up that way.
* [Tests/README.md](Tests/README.md) - the benchmark that judges the loop, independent of this tool.
* [Docs/MSVC-Plan.md](Docs/MSVC-Plan.md) - what it would take to support MSVC/PE targets from Linux, measured on a real one.

## Status

| Phase | Deliverable | State |
|---|---|---|
| 1 | package, config, startup checks, `analyze`, analysis cache | **implemented** |
| 2 | `try`: compile -> extract -> normalise -> diff | **implemented** |
| 3 | `detect`: compiler/object/flags from the file; `find`: xrefs, vtables, related functions | **implemented** |
| 4 | `types`: vtables, RTTI, the shared header | not implemented |
| 5 | -O2 hardening, register-abstracted diff, Unicorn behaviour check | not implemented |
| MS-0 | read a PE target: sections, imports, debug records, `find`/`show`/`detect` | **implemented** (`python Tests/tools/check_pe_target.py`) |
| MS-1 | `.pdata`: the file's own function table, kept, preferred, disagreement reported | **implemented** (same script) |
| MS-2 | `cl` on the machine, `decomp check` identification, PE variants in the benchmark | **partly** - toolset v141 14.12 installed and compiling, the Windows SDK cannot be extracted here (`python Tests/tools/check_msvc_toolchain.py`, exit 2) |
| MS-3..MS-5 | COFF candidates for `try`, MSVC flags, MSVC C++ | not implemented |

## Use it

```sh
.venv/bin/decomp check -C Tests/project.toml                  # Ghidra/JDK/Python/cache/compilers
.venv/bin/decomp detect Tests/build/gcc-o0/da_tests.stripped  # who built it, and at what -O
.venv/bin/decomp analyze Tests/build/gcc-o0/da_tests.stripped --variant gcc-o0
.venv/bin/decomp status                                       # what is cached
.venv/bin/decomp find strncmp                                 # name, 0xaddr, string, global, vtable
.venv/bin/decomp find coin --family 2                          # the functions that belong together
.venv/bin/decomp show 0x2834 --bin Tests/build/gcc-o0/da_tests.stripped
.venv/bin/decomp try 0x2834 my/math.cpp --fn AbsDiff           # build, diff, score
```

Only `analyze` starts Ghidra (about 10 s for a 193-function binary, once per binary).
`detect`, `show`, `find`, `status` and `try` never start a JVM: they read the file's own
headers or the SQLite cache, and a `try` takes about as long as compiling the candidate
(~0.2 s here), which is what makes a stateless CLI usable inside an agent loop.
`show`/`find`/`try` accept the file addresses that `nm` and `objdump` print as well as
Ghidra's (see "Address domains"); `detect`'s `--range` is always in file addresses.

Exit codes: 0 ok - for `try`, the candidate passes the gate; 1 a check or the work failed -
for `try`, below the gate; 2 usage or config error; 3 nothing found, or a command of a later
phase.

## Layout

```
decomp/
  cli.py        typer commands: check, analyze, status, detect, show, find, try, (types)
  config.py     project.toml discovery, Ghidra install resolution, cache path rules
  check.py      startup checks, each naming what it looked for and the fix
  ghidra.py     the only JVM code: import, auto-analyse, export
  cache.py      the analysis cache (SQLite) and its read API
  toolchain.py  build flags per variant, the target's build note, the -O inference
  discover.py   what a query names, what reaches it, what belongs with it
  compile.py    build the candidate source -> .o with the target's own variant flags
  extract.py    one function out of either side: the cache (original) or the .o (candidate)
  normalize.py  the shared decoder and the tokeniser: both sides -> one token stream
  diff.py       align, score, categorise, and say what counts as done
  project.toml  the default target config, used only when nothing closer is found
```

The cache lives in `cache/ghproj/<key>/` (`cache_dir` in `project.toml`; never under a path
element starting with `.`):

```
<key>/analysis.db    functions, instructions, resolved references, call graph, pseudo-code,
                     symbols, strings, sections, the function table the file carries itself
                     (a PE's `.pdata`, units in the analysis' addresses), and the meta table
                     (analysis facts)
<key>/target.gpr     the Ghidra project itself, so re-analysis is never needed
```

`<key>` is a content hash of the target, so the cache follows the bytes, not the filename.
Every write is one transaction whose last statement records `complete`; a half-written cache
is never mistaken for a usable one, and a cache written by another `CACHE_VERSION` is rebuilt.
Tables added later (the function table is one) are read tolerously instead of forcing a
rebuild: an analysis written before they existed keeps working and simply has none, and a tool
that needs one says which command re-analyses it.
Candidate objects go to `cache/ghproj/candidates/`.

## Address domains

Ghidra loads a PIE at `0x100000`, while `nm`, `objdump` and LIEF all speak the file's own
addresses. `analyze` computes the offset from the section map and stores it in
`meta.address_offset`; `show` prints both forms and accepts either one:

```
; entry 0x102834 (file 0x2834)  size 33  section .text  kind function
```

Phase 2 depends on this being exact: it reads the *values* the original reads (a string, a
table) out of the file by address, and the candidate's out of the `.o`.

## Knowing how the binary was built (`decomp detect`)

A candidate has to be built the way the original was, so the first question is how it *was*
built. `detect` reads that out of the file - no Ghidra, no analysis:

```
$ .venv/bin/decomp detect Tests/build/gcc-o0-x86/da_tests.stripped --range 0x804c866+0x6da0
  file         ELF I386 32-bit
  object       EXEC                       # not a PIE: the variant needs -no-pie
  linked       static                     # -> linkflags = ["-static"]
  built by     gcc 16.2.1                # from .comment
  abi          C++ ABI runtime (the symbol __cxa_)
  code shape   frame 1.000  spill 0.147  framemem 0.389  xmm 0.000   (95 bodies)
  g++ -O0  distance 0.262   next 3.084
  optimize = 0  (strong: the shape of this code is not produced by the other levels)
```

`--write project.toml` turns that into a config the tool can use: the compiler, `arch`, and
`cppflags`/`linkflags` follow from the object type (a PIE is the default, `EXEC` implies
`-no-pie`, a static link implies `-static`), and `-std` is floored by what the imports
prove (`basic_string_view` needs C++17). Measured on the benchmark, whose flags are known:

| variant | compiler / bits / PIE / static | variant name it writes | `-O` over the program's own code |
|---|---|---|---|
| gcc-o0 | correct | `gcc-o0` | **-O0**, distance 0.94 vs 3.32 next |
| gcc-o2 | correct | `gcc-o2` | **-O2** (0.31); "optimised code" is the strong part, the level is not |
| gcc-o0-x86 | correct (32-bit, static, non-PIE) | `gcc-o0-x86` with `-m32 -no-pie -static` | **-O0**, 0.26 vs 3.08 next |

The `-O` answer is a *measurement*, not a claim: the reference snippets in
`toolchain.PROBE_SOURCE` are compiled with the compilers installed here at `-O0..-O3`, and
what is compared is the *shape* of the code each flag set produces (frame pointer, argument
spilling, locals reloaded through the frame, epilogue form, `endbr`, stack canary, vectorised
loops). That is toolchain-specific on purpose - a candidate is going to be built with this
toolchain. Two honest limits, both printed by the tool:

* `-O1`/`-O2`/`-O3` shade into the same shape; what is firmly established is *"this is not
  -O0"* (no frame pointer, no argument spilling). The report says which, with the margin.
* A **statically linked** image is mostly somebody else's library code, and it outvotes the
  program. `detect` says so and asks for `--range <file addresses>` (or `--sample <name>`,
  which samples the cached analysis instead). Narrowed, the -m32 build reads as -O0 with a
  margin of 2.8; un-narrowed it answers -O1 and says the sample spans builds.

For PE, the Rich header, the linker version and the debug directory are read: a real MSVC
binary (`Tests/Proprietary/notepad.exe`) reports `compiler = msvc`, link.exe 14.12 = the v141
(VS2017) toolset, every tool at Rich build id 25711, `/GL`+`/LTCG` from its POGO record, and
the PDB's GUID with the address Microsoft serves that PDB from. `find`, `show`, `detect` and
`detect --range` work on it (`python Tests/tools/check_pe_target.py`), and the report says
plainly that a `/GL` image cannot be reproduced byte-for-byte by a single-file compile.

An x64 PE also carries the compiler's own function table, and since MS-1 the tool uses it.
`decomp analyze` reads `.pdata` into the cache next to the analysis' ranges and prints the
reconciliation instead of silently picking a side - on `notepad.exe`, 186 units / 99 778 bytes,
154 agreeing with the analysis, 32 the analysis reports shorter, 0 longer, and 35 analysis
entries the file names no unit for. A unit's extent is what `try` compares (`--size` still
overrides it), `show` prints the unit or the gap an invented function sits in, and `find` marks
what the table does not know. What is still missing on a PE is a candidate side at all -
[Docs/MSVC-Plan.md](Docs/MSVC-Plan.md) §5-§7.

`.dynstr` and `DT_NEEDED` say which C++ ABI and standard library a *stripped* ELF uses; on a
PE the imports say which CRT it links (`msvcrt.dll` = the downlevel C runtime), which is a
runtime, not a language - an MSVC binary's language comes from its decorated names, and that is
MSVC-Plan MS-4.

## The group a request asks about (`decomp find`)

"Decompile the coin system" is not a name search. `find` now answers it in three steps, all
address-driven, so it works on a stripped binary:

* **what the query names** - functions, strings, *and* symbols: globals, vtables, RTTI,
  imports (`symbols and data`), since the thing in "which functions touch this global" is
  not a function;
* **what reaches it** (`--xref`, on by default) - every function that references it, with
  the instruction at each site; **what it points at** (`--table`) - the pointer slots of a
  data object, which is a vtable's method list, read from the link's relocations (in a PIE
  the file bytes there are zeros) and bounded by the next symbol the file names; and
  **what points at it** (`--members`) - which vtables a function appears in, and the other
  methods of that class;
* **what belongs with it** (`--family <hops>`) - the functions grown outward along the call
  graph from whatever matched, ranked by call edges and by reaching the same objects, with
  the reason next to each name, plus the objects the group shares.

Measured on the benchmark (`python Tests/tools/check_phase3_discovery.py`): searching the
string `hello` reaches the same one function at the same file address in the stripped and
the unstripped build (names are what stripping takes away, reachability is not); a
`--family 2` query for "Vehicle" from the unstripped build returns 5 seeds and brings back
**5 of 5** of that family's units; and `_ZTV14CVehicleEntity` resolves to its four methods
(`~CVehicleEntity` x2, `GetHealth`, `Classify`), with 3 of them found again through
`--members`. An abstract base's vtable shows only its concrete slots - a pure-virtual slot
is `__cxa_pure_virtual`, which is what the file says.

## The loop (`decomp try`)


`try` compiles the candidate with the **variant the analysis was recorded with** - same
compiler, same `-O`, same `-std`, same `-m32` - pulls the target function out of the `.o`,
and diffs it against the cached original:

```
$ .venv/bin/decomp try 0x2834 Tests/TestBinary/TestFunctions/math.cpp --fn AbsDiff \
      -C Tests/project.toml --bin Tests/build/gcc-o0/da_tests.stripped
target .../Tests/build/gcc-o0/da_tests.stripped  (key 601677537ac2f6d3, variant gcc-o0: -std=c++17 -O0 -Wall -Wextra)
build: ok (0.19s) -> cache/ghproj/candidates/candidate_math.o

match 100.00% (threshold 97%) PASS
  FUN_00102834 @ 0x102834  vs  CMathTests::AbsDiff (.text)
  bytes 33 vs 33 (+0)  IDENTICAL
  instructions 13 vs 13 (+0)  categories: opcode 0, operand 0, register 0, relocation 0, missing 0, extra 0
  the candidate assembles to exactly the original bytes
  no differing instructions
```

What makes the two sides comparable (`extract.py`, `normalize.py`, `diff.py`):

* Both bodies are decoded by the same capstone handle in AT&T syntax, so the lines read like
  the ones `decomp show` prints. The original side keeps the instruction boundaries the
  analysis recorded; the candidate side is a linear sweep of its range in the `.o`.
* Branches inside the function become function-relative labels (`jmp L57`), so a moved
  function or a different load address is not a difference.
* Every operand that carries an address is replaced by a symbol token: on the original side
  from the analysis' resolved references, matched by the address the operand encodes; on the
  candidate side from the `.o`'s relocations, matched by the field they sit on - plus the
  object's own symbol table for references that need no relocation because they stay inside
  the section (a call to a helper in the same file, taking a function's address).
* Tokens are positional per side - the n-th callee, the n-th object read - because a stripped
  binary and a `.o` rarely agree on names. What a token *means* is kept and compared
  (`diff.refs_compatible`): by name when both sides know a real one, by the bytes there when
  both sides know *what object* they are reading (a size on both, or a name on both), by size
  when both know one. An anonymous `.rodata` pool is laid out per build - the same constants
  at different offsets - so two windows into it are not the same object twice and a
  difference there is the linker's, not the candidate's. That is what makes `relocation` mean
  "reaches a different function or object" instead of "the addresses differ", and it is why
  the report lists every symbol the function reaches with both sides' names:

```
  symbols this function reaches (1, differing first):
    SYM0   original: FUN_001068c0             candidate: ToLowerChar             ok
```

A unit counts as done at `match >= threshold` **and** `opcode 0` **and** `relocation 0`
(Design-Plan, Key Design Decisions): the ratio alone can be met by code that does something
else. `--json`, `--max-diff`, `--max-symbols`, `--size`, `--include`, `--fn` and
`--register-abstract` are documented in `decomp try --help`.

## Verified on the loop (measured here, 2026-11-03)

`python Tests/tools/check_phase2_try.py` feeds the **untouched original source** through
`decomp try`'s own code path for every unit of the benchmark and compares with the ceiling
the independent harness reports (`Tests/eval.py self`, which scores the same source with
binutils only):

| variant | units scored | mean match | byte-identical | pass the gate | eval.py self (the ceiling) |
|---|---|---|---|---|---|
| gcc-o0 (x86-64) | 89 / 89 | **99.94 %** | 54 | **88 / 89** | 99.53 %, 83 / 89 |
| gcc-o0-x86 (-m32, static) | 89 / 89 | 99.21 % | 58 | 78 / 89 | 87.19 %, 11 / 89 |
| gcc-o2 (x86-64) | 89 / 89 | 65.88 % | 29 | 34 / 89 | 98.27 %, 72 / 89 |

Only the -O0 rows gate: at -O0 the untouched source has to be accepted, and it is for every
unit except STRUCT-24 (a vtable defined in another translation unit - the `.o` relocates
against `_ZTV...+16` while the PIE link reads a `.data.rel.ro` pointer slot, so the two sides
genuinely name different objects; vtables and RTTI are Phase 4). The -O2 row is reported, not
gated: 51 of those 89 units have bodies split into a hot part and a cold one and Ghidra's
function boundaries differ from the compiler's symbol ranges - which is precisely the Phase 5
`-O2` work. `--size <the compiler's symbol size>` is the escape hatch today, and
`--register-abstract` (already reported separately as the `register` category) is the Phase 5
knob.

The same script re-scores the deliberately wrong candidates in
`Tests/examples/candidate_math_bad.cpp` and requires the report to name the kind of problem
they are (wrong comparisons, a different algorithm, a different loop shape). Phase 1's
cross-check against the answer key still runs: `python Tests/tools/check_analysis_cache.py`
(89/89 addresses and sizes at -O0, 89/89 addresses and 38/89 sizes at -O2), and Phase 3's
is `python Tests/tools/check_phase3_discovery.py` (the table above, plus the `find` gates;
all three scripts print OK on this machine).

## Known gaps

* `-O1` vs `-O2` vs `-O3` is not distinguishable from prologue/epilogue shape; `detect` says
  "not -O0" firmly and the level weakly. Vectorisation, inlining depth and unrolling are the
  Phase 5 evidence for that.
* The `-O` inference samples the file's `.text` cut at every `ret` when there is no analysis
  to take real boundaries from; with a cached analysis and `--sample <name>` it uses the real
  ones. For a statically linked target the answer needs `--range` (see above).
* A PE/MSVC target: `analyze` works on one (236 functions out of `Tests/Proprietary/notepad.exe`,
  ~140 s), and since MS-0 so do the build note, `find`, `show` and `detect` (its report names
  the v141 toolset, `/GL`+`/LTCG`, and the public PDB that carries the answer key); since MS-1
  so does its own function table, `.pdata`, whose 186 unit boundaries the tool keeps, prefers for
  a unit's extent, and reports its disagreement with the analysis with. Since MS-2 there *is* an
  MSVC compiler here - `cl`/`link`/`lib`/`dumpbin` 14.12.25835.7 (v141, the era `detect` names
  for that file), built through `decomp compile` at `/Od` and `/O2`, and its COFF objects open in
  `extract.CandidateObject` with each function in its own `.text$mn`. Still missing: `try` on a
  COFF candidate (MS-3 - the section-as-extent and no-addend relocation rules), and any *link*
  with `cl`, because the Windows SDK of that prefix is an empty placeholder (below).
  [Docs/MSVC-Plan.md](Docs/MSVC-Plan.md) measures all of it and phases the work.
* Ghidra's function boundaries at `-O2` differ from the compiler's, and a `-O2` body can be
  split across `.text` and `.text.unlikely`; only the first range is compared today.
  Extracting across ranges is Phase 5. (An x64 PE no longer has that problem: the unit table
  gives one contiguous range and the bytes are read across it - see MS-1.)
* `detect --range` still samples a PE's `.text` cut at every `ret` rather than over the unit
  table it now has. MS-4's shape profiles should sample the units.
* A vtable or other object defined in another translation unit is named by the `.o` and
  reached through a pointer slot in the linked image (STRUCT-24 above). Phase 4.
* A candidate that calls a helper it does not define reaches it by name, while the analysis of
  a stripped target knows it by address only: that call reads as an operand difference, and
  the symbol table prints both names so the loop can still see what happened.
* The MSVC toolchain here is complete except for its **Windows SDK**: the SDK ships as payload
  MSIs, and this machine has no way to extract them - `msitools`/`msiextract` needs root, and
  Wine 9.21's `msiexec /a` stops at `InstallAdminPackage` with 1627 on those MSIs (the cabs alone
  are no use: their entries are named `cat<hash>`, the tree lives in the MSI tables). So `cl`
  compiles freestanding code and nothing more; `toolchains/install_msvc.py` + Docs/Setup.md §6.10
  reproduce the install, and `decomp check` says which part is missing. `clang-cl` is installed
  but is clang's codegen, never an MSVC variant; `lld-link` is absent.
  MinGW-w64 gcc produces PE/COFF but with GCC codegen, so it can test the container, never the
  match. The setup steps for every toolset era, VS2005 - VS2026, 32-bit and 64-bit, are
  [Docs/Setup.md](Docs/Setup.md) §6 - including the two facts that decide reachability here: the
  manifest route's extractor cannot be installed without root, and this Wine cannot start a
  32-bit PE, so VS2013-and-older host tools need multilib Wine or wibo. The diff supports x86
  only (`x86:LE:32/64`); `try` says so rather than guessing.
* `[ghidra] language` in `project.toml` is validated but not wired into the importer;
  Ghidra's auto-selection is used and the chosen language is recorded.
