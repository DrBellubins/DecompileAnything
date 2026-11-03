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
  `$displ,%eax` + `R_386_*`) are not all mapped to names. Fix before using x86 as the
  MSVC-like target.
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
