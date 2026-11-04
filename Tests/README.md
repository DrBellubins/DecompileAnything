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
`goldens.jsonl`, `build.json`.

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
compares with what `eval.py self` reports (99.94% mean, 88/89 pass at gcc-o0 vs the
harness's own 99.53%, 83/89), then re-scores the deliberately wrong candidates in
`Tests/examples/candidate_math_bad.cpp` and requires the report to name the kind of problem
they are. Current result: 89/89
addresses and sizes exact for both `-O0` variants; at `-O2` all 89 addresses still match but
51 sizes differ (Ghidra's own function boundaries), and STR-04/STR-11 are classified as
thunks because their -O2 body is a tail call.

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

## Known gaps

* **-m32 normalisation is weak** (87% ceiling): 32-bit addressing forms (`movl 0x804a2c4`,
  `$displ,%eax` + `R_386_*`) are not all mapped to names. x86 is *not* a stand-in for MSVC
  either - "-m32 as the closer match to the 32-bit MSVC targets" in `project.toml` is about
  addressing forms only. A real `msvc-*` variant of this benchmark (PE/COFF, `cl` or
  `clang-cl`, an answer key from `.pdata`/the PDB instead of `nm --print-size`) is phase MS-2
  of [../Docs/MSVC-Plan.md](../Docs/MSVC-Plan.md).
* **Goldens are per-variant, not portable.** `crosscheck` treats a same-arch difference as
  a bug (there are none) and x87-vs-SSE float differences as expected: `-m32` computes
  `SineApprox` and `InitVehicleDescriptor`'s grip in float registers with different
  rounding, and `ChecksumDescriptorBytes` therefore hashes different struct bytes.
* The -O2 gap is real codegen, not normalisation: builtins (`sqrtf` inlined as `sqrtsd`
  in a `.o` but called through the PLT in the linked binary) and jump-table layout.
  Behavioural checking (Phase 5, goldens + Unicorn) is the way to close those.

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
