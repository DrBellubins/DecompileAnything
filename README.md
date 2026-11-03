# DecompileAnything

`decomp` is a CLI that lets an LLM decompile a function out of a compiled binary and keep
iterating until the candidate recompiles to the same bytes. The tool **never edits source**:
it reports facts about the original binary and scores a candidate the model wrote.

* [Docs/Design-Plan.md](Docs/Design-Plan.md) - the plan, phases, and the design decisions.
* [Docs/Setup.md](Docs/Setup.md) - the environment (Ghidra, JDK, venv) and why it is set up that way.
* [Tests/README.md](Tests/README.md) - the benchmark that judges the loop, independent of this tool.

## Status

| Phase | Deliverable | State |
|---|---|---|
| 1 | package, config, startup checks, `analyze`, analysis cache | **implemented** |
| 2 | `try`: compile -> extract -> normalise -> diff | **implemented** |
| 3 | `find`: xref/vtable queries, compiler and flag inference | partial - name, string and address search work |
| 4 | `types`: vtables, RTTI, the shared header | not implemented |
| 5 | -O2 hardening, register-abstracted diff, Unicorn behaviour check | not implemented |

## Use it

```sh
.venv/bin/decomp check -C Tests/project.toml                  # Ghidra/JDK/Python/cache/compilers
.venv/bin/decomp analyze Tests/build/gcc-o0/da_tests.stripped --variant gcc-o0
.venv/bin/decomp status                                       # what is cached
.venv/bin/decomp find strncmp                                 # by name, 0xaddr, or string content
.venv/bin/decomp show 0x2834 --bin Tests/build/gcc-o0/da_tests.stripped
.venv/bin/decomp try 0x2834 my/math.cpp --fn AbsDiff           # build, diff, score
```

Only `analyze` starts Ghidra (about 10 s for a 193-function binary, once per binary).
`show`, `find`, `status` and `try` read the SQLite cache and never start a JVM; a `try` takes
about as long as compiling the candidate (~0.2 s here), which is what makes a stateless CLI
usable inside an agent loop. `show`/`find`/`try` accept the file addresses that `nm` and
`objdump` print as well as Ghidra's (see "Address domains").

Exit codes: 0 ok - for `try`, the candidate passes the gate; 1 a check or the work failed -
for `try`, below the gate; 2 usage or config error; 3 nothing found, or a command of a later
phase.

## Layout

```
decomp/
  cli.py        typer commands: check, analyze, status, show, find, try, (types)
  config.py     project.toml discovery, Ghidra install resolution, cache path rules
  check.py      startup checks, each naming what it looked for and the fix
  ghidra.py     the only JVM code: import, auto-analyse, export
  cache.py      the analysis cache (SQLite) and its read API
  toolchain.py  build flags per variant, the target's build note (.comment / Rich header)
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
                     symbols, strings, sections, and the meta table (analysis facts)
<key>/target.gpr     the Ghidra project itself, so re-analysis is never needed
```

`<key>` is a content hash of the target, so the cache follows the bytes, not the filename.
Every write is one transaction whose last statement records `complete`; a half-written cache
is never mistaken for a usable one, and a cache written by another `CACHE_VERSION` is rebuilt.
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
  both could read them, by size when both know one. That is what makes `relocation` mean
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
(89/89 addresses and sizes at -O0, 89/89 addresses and 38/89 sizes at -O2).

## Known gaps

* Ghidra's function boundaries at `-O2` differ from the compiler's, and a `-O2` body can be
  split across `.text` and `.text.unlikely`; only the first range is compared today.
  Extracting across ranges is Phase 5.
* A vtable or other object defined in another translation unit is named by the `.o` and
  reached through a pointer slot in the linked image (STRUCT-24 above). Phase 4.
* A candidate that calls a helper it does not define reaches it by name, while the analysis of
  a stripped target knows it by address only: that call reads as an operand difference, and
  the symbol table prints both names so the loop can still see what happened.
* `find` does not yet answer xref/vtable questions ("what touches this global") beyond the
  raw reference list, and flag inference (Phase 3) is not started.
* PE/MSVC targets are untested here: the ELF path works, the Rich-header note is written but
  unexercised, and `cl` is not installed on this machine. The diff supports x86 only
  (`x86:LE:32/64`); `try` says so rather than guessing.
* `[ghidra] language` in `project.toml` is validated but not wired into the importer;
  Ghidra's auto-selection is used and the chosen language is recorded.
