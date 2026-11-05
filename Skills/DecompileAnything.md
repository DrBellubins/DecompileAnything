---
name: decompileanything
description: Iteratively decompile functions out of a compiled binary into source that recompiles to the same bytes. Use when recovering a function from a stripped binary, when a decompiled candidate must be made binary-accurate, or when working in this repo (Tests/eval.py benchmark).
---

# Loop

Build once, then iterate per function. The tool never edits source - it reports facts and
scores; you write the source.

```sh
cd Tests
python3 eval.py build --variants gcc-o0,gcc-o2,gcc-o0-x86   # once per session
python3 eval.py units                                       # what is in the binary

../.venv/bin/decomp detect build/gcc-o0/da_tests.stripped   # compiler/-O, and project.toml (--write)
../.venv/bin/decomp analyze build/gcc-o0/da_tests.stripped --variant gcc-o0   # once per binary
../.venv/bin/decomp find strncmp                            # name, 0xaddr, string, global, vtable
../.venv/bin/decomp find coin --family 2                    # the group of functions a request means
../.venv/bin/decomp show 0x2834 --bin build/gcc-o0/da_tests.stripped          # reads the cache
../.venv/bin/decomp try 0x2834 cand/math.cpp --fn AbsDiff                     # build, diff, score
../.venv/bin/decomp types                                                   # the classes this binary has
../.venv/bin/decomp types --write TestBinary/TestFunctions                   # and the header to use
```

Per unit: `decomp show` (pseudo-code + the original instruction stream + resolved
references + callers/callees) → write the function with its real signature and real field
offsets → `decomp try` → read the diff → change the thing the diff names. Stop when
`match >= threshold` **and** `opcode: 0` **and** `relocation: 0`. Never stop on the
percentage alone.

`try` builds the candidate with the target's own variant flags (same compiler, `-O`, `-std`,
`-m32`), so never compare -O0 asm to -O2 asm; it prints the object path, so `objdump -dr`
on the candidate is one command away. `--fn` names the symbol in the candidate to compare
(without it, the object must define exactly one function). `--include` adds `-I` for a header
the candidate needs; `[include_dirs]` in the target's `project.toml` does it permanently.

The extent it compares is the one the **file** gives: `.eh_frame`'s FDE records for ELF (`.pdata`
for PE), so at `-O2` a body the disassembler drew in several ranges is still one unit, and a
`jumps past the end of the range you gave it` warning means the extent is wrong, not the code.
`--size` overrides it; `decomp analyze` prints where the file's table and the analysis disagree.

# Driving `decomp`

* Start a new target with `decomp detect <bin> --write project.toml`: it reads the compiler and
  version from `.comment` (Rich header on PE), PIE vs `-no-pie`, static vs dynamic, the C++ ABI
  and the lowest `-std` the imports prove, and infers `-O` by comparing the *shape* of the
  target's code against what this machine's compilers produce at each `-O`. Trust the facts;
  read the `-O` line's `confidence`/margin. For a **statically linked** target, narrow the
  sample: `--range 0xLO-0xHI` over the program's own code (an answer over the whole image is
  mostly glibc's flags, and the tool says so).
* `decomp find` answers three kinds of question: what a name/address/string/**global/vtable**
  is, what reaches it (`--xref`, with the instruction at each site) and what it points at
  (`--table` gives a vtable's method list; `--members` gives the class the function belongs
  to), and `--family <hops>` gives the connected group with the reason for each entry.
  In a stripped binary there are no names to search: start from a string or an address, then
  grow with `--family`.
* A **PE/MSVC target**: `decomp analyze`, `find`, `show` and `detect` work on one
  (`Tests/Proprietary/notepad.exe`: 236 functions; `detect` names the v141 toolset from the
  Rich build id, `/GL`+`/LTCG` from its debug directory, and the public PDB that holds that
  file's answer key). `try` does not yet: nothing implements COFF *candidate* semantics (MS-3).
  Both are a named gap phased in `Docs/MSVC-Plan.md`, not something to debug mid-task.
  Since MS-2 there is an MSVC toolchain here — `cl`/`link`/`lib`/`dumpbin` **14.12.25835.7**
  (v141, the era `detect` names for that target) at `toolchains/msvc/bin/x64`, needing
  `PATH=…:$PATH WINEPREFIX=$PWD/.wine`. It **compiles, links and runs** PE programs under Wine
  (`Tests/eval.py build --variant msvc-o0|msvc-o2` builds the benchmark's own test binary: 89/89
  answer-key units, `selfcheck` 89 cases 0 failures), and `detect --probe` measures its
  `/Od|/O1|/O2` shapes. Its `.obj` files show one `.text$<name>` COMDAT per function, which is
  where a COFF function's exact extent comes from. Two argument rules: `/link` last (everything
  after it goes to the linker), and only the top source directory on the include path (a
  project `math.h` in an `-I` directory shadows the CRT's `<math.h>` for `cl`). `decomp check`
  identifies all of it by banner and refuses impostors (`/usr/bin/link` is GNU coreutils;
  `clang-cl` is clang) — read its `msvc *` rows before believing any MSVC variant is usable.
  An x64 PE carries the compiler's own function table in `.pdata` (186 units on that file) and
  the tool reads it: `analyze` caches it and prints the reconciliation with the analysis (154
  agree, 32 the analysis reports shorter, 35 entries the file names no unit for), a unit's extent
  is what a diff compares (`--size` still overrides it), `show` prints the unit or names the gap
  an analysis-only function sits in, and `find` marks those entries `<- not in .pdata`. Trust
  the unit boundary over the analysis' size; trust the analysis for instruction boundaries.
  A cached analysis made before this has no unit table - `analyze --force` gives it one.
* Only `analyze` starts Ghidra (~10 s per binary, once). `detect`/`show`/`find`/`status` read
  `cache/ghproj/<sha256-16>/analysis.db` or the file itself in ~0.1 s. Re-running `analyze` on
  the same bytes says "already analysed"; `--force` rebuilds.
* `decomp show` accepts the addresses `nm`/objdump print **and** Ghidra's: a PIE is loaded at
  `0x100000`, and `meta.address_offset` records the gap, so `decomp show 0x2834` works.
* Several targets can be cached; then pass `--bin <file>` or `--key <key>` (both printed by
  `decomp status`).
* Exit codes: 0 ok, 1 failed check/work, 2 usage or config, 3 nothing found or a later phase.
* `decomp check` before debugging a failure - it names the Ghidra/JDK/Python/cache/compiler
  problem and the fix.

# Reading a score

| signal | what it means | do |
|---|---|---|
| `opcode: n` | wrong operation: cmov vs branch, imul vs shifts, signed vs unsigned load | fix the operation; `movzbl` vs `movsbl` and `idiv` vs `shrd` are the usual ones |
| `operand: n` | right operation, wrong offset/constant/type | field offsets, struct layout, the type of an array element, a truncated buffer bound |
| `relocation: n` | same shape of code, reaching for something else: a different callee, a different table, different bytes in it | the report's `symbols` line names both sides - fix the callee or reproduce the data (tables and string literals are part of the answer). Bytes are only compared when both sides know what object they are: an anonymous `.rodata` pool is laid out per build |
| `register: n` | register allocation only | not yours to fix; `--register-abstract` maps each side's registers to the order they first appear, so the same choice in different registers matches. Measured on this benchmark it changes no score - the untouched source has 0 register differences at every `-O` - so treat it as a reading aid, not a way to pass |
| `missing`/`extra` | control flow or size differs | loop form (counted vs conditional), hoisted invariant, inlined vs called helper, early return vs branch |
| `size_delta` large with high % | something is inlined or vectorised that should not be (or the reverse) | compare at the variant's own `-O`; never compare -O0 asm to -O2 asm |

Before blaming the model, run `python3 eval.py self` - it recompiles the untouched
original and scores it. That is the ceiling (99.5% at gcc-o0, 98.3% at gcc-o2 on this
machine): a unit scoring far below the ceiling *for everyone* is a harness or fixture
problem.

# Facts about this benchmark

* `Tests/TestBinary/TestFunctions/*.cpp` holds the units; each definition carries
  `// DA-UNIT <ID> level:... tags:...` and a matching `DA_CASE(st, "ID")` block in that
  class's `RunSelfChecks`. Units are `DA_NOINLINE` (one body, one address, any `-O`);
  helpers are not, so helpers vanish into units at -O2 on purpose.
* After any edit to `TestBinary`: `eval.py build` then `eval.py selfcheck` must print
  `0 failures`, and `eval.py crosscheck` must show no same-arch differences. The 89
  hand-checked expectations are the ground truth - if a `Want*` disagrees with the code,
  work out which one is wrong instead of editing the expectation to match the run.
* `decomp types` recovers the C++ structure the file carries: classes named from their RTTI,
  their bases, their vtables (slot by slot, nulls reported as null), their constructors and
  destructors, and the member **offsets** and widths its own code touches. `--write <dir>`
  turns that into a `types.h` a candidate can include (the header says which types are guesses;
  field names are placeholders like `f0x8`). `decomp show` adds one `structure:` line for a
  function it can place. Nothing is claimed for an MSVC/PE target: that RTTI format is MS-5.
* `decomp try` compares **symbolically**: branches inside the function are function-relative
  labels, and calls/data references become positional tokens (`SYM0`, `DAT0`) matched by order,
  then checked by what they reach (a real name both sides know, the bytes there, the size). So
  the score does not depend on the link address, and a table with the wrong bytes is still a
  failure. `decomp try --json` gives the whole report if you need to parse it.
* Float results are only comparable as **bit patterns** (`goldens.jsonl` stores both
  `f` and `bits`). x87 (-m32 default) and SSE (-m32 `-msse2`, x86-64) legitimately
  disagree: `SineApprox`, `SquareRootNewton` and `(float)mass * 0.001f` all differ in the
  last ulp. That is why goldens are per-variant.
* Unions lie: writing through one view changes the other (`RectFromCorners` fills the
  width/height view, so `m_right`/`m_bottom` become 8/8 - `RectArea` then returns 49, not
  64). Struct padding is observable too (`ChecksumDescriptorBytes` hashes it). A diff in a
  field offset is a struct-layout oracle - use it to fix the header, then re-score.
* `-m32` builds use `-no-pie -fno-pic`: a PIE link on i386 relaxes the pc-thunk/GOT
  sequence into `%gs` addressing, so object code and linked code stop matching.
* At `-O0` every function starts with a frame, so tiny units are 30+ bytes there; the
  sub-32-byte bucket only appears at -O2. Judge sizes per variant.

# Writing the candidate

* Keep the real signature: by-value vs by-reference struct args, hidden return pointer,
  and `this` are visible in the first six instructions.
* Reproduce the *data*: tables (`k_chokeThresholds`, the CRC table, the base64 alphabet),
  bounds, and buffer capacities. Values in `.rodata` are part of the answer - and the
  normaliser only compares data references by order, so the values are verified by the
  goldens/strings, not by the score.
* Match the shape, not the compiler: a counted loop and a conditional loop with the same
  body are different code. `while (angle > 180.0f) angle -= 360.0f;` is not
  `fmodf`. Prefer what the branches and comparisons prove, and let the categories tell you
  which one the binary has.
* If the binary reads a global you cannot name yet, name it by role only when the code
  proves the role; otherwise keep a neutral name and record the offset.
