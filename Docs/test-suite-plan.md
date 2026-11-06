# decomp Test Suite Expansion Plan

A plan for growing the `da_tests` benchmark (math, strings, structs) into a comprehensive suite for byte-matching and difficult, human-readable re-creation.

## 1. Purpose and goals

The current suite checks whether the tool can match typical compiler output for small, well-behaved units. The expanded suite answers three further questions:

1. **Does the tier system tell the truth?** A unit reaching `exact` must be byte-equal modulo link-written fields. A near-miss must not pass.
2. **Where does the tool break?** Cover the constructs that make decompilation hard (compiler idioms, ABI quirks, optimizer transformations), each isolated in its own unit.
3. **Can an LLM reconstruct realistic, readable code?** Multi-function programs where the right answer is a human-style design, not one compiler-friendly function.

## 2. Vocabulary: two ladders

The plan uses two separate ladders. Keeping them apart avoids confusion.

**Match tiers** (what the tool reports, from `decomp/diff.py`):

| Tier | Meaning |
| --- | --- |
| `none` | Different shape or different operations |
| `structural` | Same length, operations and targets; operands not proven right |
| `semantic` | Same operations, operands and targets in whatever registers; bytes not proven equal |
| `exact` | Assembles to the original bytes, with link-written fields masked |

**Difficulty levels** (how hard a unit is to reconstruct, assigned by the test author):

| Level | Description | Typical target tier |
| --- | --- | --- |
| **D1 Easy** | Leaf functions, straight-line or single-loop code, no external references | `exact` at every `-O` |
| **D2 Medium** | Several loops, struct access, calls to libc or one helper, simple data references | `exact` at `-O0`, `semantic`+ at `-O2` |
| **D3 Hard** | Compiler idioms, ABI-sensitive signatures, jump tables, vtables, globals, chained helpers | `semantic` expected, `exact` achievable with effort |
| **D4 Extreme** | Optimizer-dominated output (vectorization, unrolling, cold splits, ICF, LTCG), exceptions, virtual inheritance | `structural` is an acceptable ceiling; documented per unit |

Every unit gets one difficulty level **and** an expected tier per build variant. A unit that legitimately cannot exceed `structural` at `-O3` is a documented ceiling, not a failure.

## 3. Current coverage and gaps

| Covered today | Not covered |
| --- | --- |
| 32-bit int loops, bit tricks, CRC, hash | 64-bit integers, division and modulo by constants, 128-bit multiply |
| `float` math and `CVec3` struct return | `double`, int/float conversions, SIMD intrinsics, libm calls |
| C-string functions, bounded buffers | Wide or UTF-8 strings, parsing functions, varargs formatting |
| Bitfields, unions, one jump table, single-inheritance vtables, `dynamic_cast` | Multiple and virtual inheritance, templates, lambdas, function pointers, exceptions |
| Intrusive list, pool, queue | Globals and statics (`.data`/`.bss`), TLS, tail calls, other `switch` shapes |
| Helpers kept alive by `DA_NOINLINE` | Inlined helpers, ICF-folded functions, cold partitions, call chains that exercise the ledger |

## 4. Suite architecture: three layers

**Layer A: Unit corpus (byte matching).** Extends the existing model. One `DA-UNIT` per function, `DA_NOINLINE`, called from `RunSelfChecks` with hand-checked expectations. This is the bulk of the work.

**Layer B: Reconstruction programs.** Six to ten small multi-file programs (200-600 lines each) with realistic structure. Units are meant to be recovered together using `find --family`, `types` and `ledger`. Scored on tier per unit plus a readability rubric.

**Layer C: Tool-regression fixtures.** Tiny synthetic pairs (original source and hand-written candidate) that pin the behavior of the diff engine. These test `decomp try`, not decompilation skill.

## 5. Build matrix

Each unit's manifest lists the expected tier **per variant**.

| Axis | Values |
| --- | --- |
| Compiler | g++, clang++, MSVC `cl` (toolset matching your msvc-wine install) |
| Optimization | `-O0`, `-O1`, `-O2`, `-O3` (`/Od`, `/O1`, `/O2` for MSVC) |
| Architecture | x86-64, x86 (`-m32`) |
| Link mode | PIE, no-PIE, static, stripped (stripped is the real test) |
| MSVC extras | `/GL` + `/LTCG` (expected cap below `exact`), `/MT` vs `/MD`, `/GS` on/off, `/Gy` |
| Special | `-ffunction-sections`, `-fno-inline-functions`, `-fno-rtti`, `-fomit-frame-pointer`, `-fcf-protection` |

Two matrix sizes:

- **Smoke** (every change): gcc `-O0` and `-O2`, x86-64, stripped.
- **Full** (nightly or on demand): everything above.

## 6. Cause tags

Keep `level:` and add a cause tag so failures can be grouped by *why* a unit is hard:

| Tag | Meaning |
| --- | --- |
| `idiom` | Magic-number division, `cmov`, `lea` arithmetic, `setcc` chains |
| `abi` | Calling convention, sret, struct-in-registers, varargs, x87/SSE return |
| `layout` | Padding, bitfields, unions, flexible arrays, alignment |
| `dispatch` | Jump table, vtable, function pointer, thunk |
| `opt` | Unrolling, vectorization, inlining, tail call, cold split, loop inversion |
| `data` | Globals, statics, `.rodata` pools, string literals, TLS |
| `link` | ICF, COMDAT, PLT/GOT, relocation-width edge cases |
| `unwind` | Exceptions, landing pads, cleanup (`.eh_frame`, `.pdata`, LSDA) |
| `chain` | Needs another unit identified first (ledger dependency) |

## 7. Layer A: new unit modules

Each module holds roughly 20-30 units with 2-3 cases per unit. Difficulty ranges are given per module.

### 7.1 `wideint` (D1-D3, tag `idiom`)

64-bit and wide integer math: `Mul64High`, `Div64ByConst` (divisors 3, 7, 10, 1000), `Mod10`, signed vs unsigned division by powers of two, `RotateLeft32/64`, `PopCount64`, `ByteSwap`, `Add128` (carry chains), `SaturatingMul`, `SignExtendFromBits`, `RoundUpPowerOfTwo`. Exercises the magic-number multiply and shift/subtract patterns that look nothing like the source at `-O2`.

### 7.2 `doublemath` (D1-D3, tags `abi`, `idiom`, `data`)

`double` and conversions: truncate/round/floor to int, unsigned-to-float boundary, `Lerp`, NaN comparisons, `Hypot`, Horner polynomial, branchless min/max, `Clamp01`, calls to `sqrt`/`fabs`/`floor` (intrinsic vs libm call), `memcpy` type punning. Pooled constants of different widths stress `.rodata.cst*` / `.rdata` handling.

### 7.3 `control` (D1-D4, tags `opt`, `dispatch`)

Dense switch (jump table), sparse switch (binary search), fallthrough, `default: unreachable`, nested loops with `break`/`continue`/`goto`, `do/while`, early-return ladders, multiple induction variables, unknown trip count (unrolled/vectorized at `-O3`), short-circuit chains, ternary chains (`cmov`), tail recursion (tail call vs loop), mutual recursion, `noreturn` helper.

### 7.4 `globals` (D2-D4, tags `data`, `link`)

Global counters (`.bss`), initialized tables (`.data`, `.rodata`), function-local statics with guard variables, `const` lookup tables indexed by computed values, `extern` vs `static` linkage, struct globals with embedded pointers (PIE relocation test), `thread_local`, string-literal tables, duplicate literals (pooling). Targets `unverified` references and the ledger's data handling, currently the weakest area.

### 7.5 `calls` (D2-D4, tag `abi`)

Structs by value (small, medium, large, mixed float/int), sret returns, many-argument functions (stack spill), varargs and custom `Printf`-style, callbacks (`qsort` comparator, function pointers in structs), member function pointers, x86 `thiscall`, MSVC `__fastcall`/`__vectorcall`, `[[noreturn]]`, `restrict`, constant-size `memcpy`/`memset` (inlined vs call), `alloca`.

### 7.6 `oop` (D3-D4, tags `dispatch`, `layout`)

Multiple inheritance (two vtables, `this`-adjusting thunks), virtual inheritance (vbtable, vbase offset), abstract interface with several implementers, `final` classes (devirtualization), covariant returns, virtual destructor chains, multi-level `dynamic_cast`, `typeid`, copy/move constructors, member-initializer order, empty base optimization, static dispatch. Targets `structures.Recovery` on both the Itanium and MSVC ABIs.

### 7.7 `templates` (D2-D4, tags `opt`, `link`)

Function templates at several types, class template with non-trivial members, `Array<T,N>`, CRTP, `constexpr` functions (they vanish; tests honest reporting), lambdas (captureless as function pointer, capturing as functor), no standard library so there is no library noise.

### 7.8 `exceptions` (D3-D4, tag `unwind`)

Try/catch with typed handlers, RAII cleanup (landing pads), rethrow, `noexcept`. Include a `-fno-exceptions` control build. Tests `.eh_frame`, LSDA, `.pdata` + `.xdata` and cold partitions.

### 7.9 `simd` (D4, tag `opt`)

SSE intrinsics (add, shuffle, dot product), auto-vectorized loop with remainder, AVX variant (separate build variant), scalar fallback with identical semantics, alignment-sensitive loads, horizontal sum. Likely `structural` ceiling; record as expected.

### 7.10 `mixed` (D3-D4, tag `chain`)

Units that combine several of the above: tokenizer, tiny VM interpreter loop, open-addressing hash map, fixed-point DSP biquad, string-interning table. This module bridges to Layer B.

## 8. Layer B: reconstruction programs

Realistic mini-programs built to be reconstructed as a group.

| Program | Difficulty | What it exercises |
| --- | --- | --- |
| Resource manager | D2-D3 | Linked lists, refcounts, virtual `Release`, intrusive containers |
| Hash map / string interner | D3 | Hashing, probing, globals, pool allocator |
| Save-file serializer | D3 | Packed structs, bitfields, byte swap, CRC, variable-size `memcpy` |
| Tokenizer + parser | D3 | Char tables, state machine, recursive descent, string pooling |
| Audio DSP chain | D3 | Biquad, ring buffer, float/double mix, struct-state `memcpy` |
| Mini renderer math | D3 | Matrix/vector, quaternion, frustum test, struct-of-arrays transforms |
| Entity system | D3-D4 | Extended `CEntityBase` hierarchy, factory, update loop, function-pointer event table |
| Tiny VM / interpreter | D4 | Opcode switch, stack machine, helper chain, ledger frontier ordering |

For each program, ship: the source, a call-graph diagram, the `DA-UNIT` manifest with the **expected dependency order**, and the expected ledger progression. The test is whether `ledger --frontier` suggests a sensible order and whether later units pass once earlier ones are in the ledger.

## 9. Readability criteria

The corpus sources must follow human-style rules: meaningful names, no macro obfuscation, short functions, comments that explain intent without leaking compiler tricks, conventional idioms, no hand-unrolling unless the unit is about that.

Candidates are scored 0-2 on each of five points:

1. Names and types are semantically sensible (not `param_1`).
2. Control flow is structured (no gratuitous `goto`).
3. Magic numbers are named or explained.
4. No temporaries or casts introduced only to coax register allocation.
5. Recovered struct types from `types.h` are used instead of raw offsets.

Report readability separately from tier. A `semantic` unit full of casts and `goto`s must look worse than an equally scored clean one.

## 10. Layer C: tool-regression fixtures

- **Category isolation:** one pair each for pure `opcode`, `operand`, register allocation, swapped operand order (must be `operand`, not `register`), `relocation` (same shape, different callee), `missing`, `extra`.
- **Accounting identity:** random insert/delete/replace fuzz asserting `accounting_problems()` is empty.
- **Tier boundaries:** candidates landing exactly at `structural`, `semantic`, `exact`; `unverified` references capping at `structural`; the same case with `waive = unverified`.
- **Ledger behavior:** an anonymous callee named correctly vs incorrectly after the ledger learned it; a different variant must not inherit the claim; `size`-only evidence must never be recorded.
- **Unit boundaries:** `.pdata` vs analysis disagreement, `--size` override, `.cold` sibling, thunk misclassification, padding gaps (`_PAD_GAP`).
- **Address domains:** PIE offset, PE image-base bias, 32-bit absolute relocations (`R_386_32`).
- **Mutation tests (highest value):** for each Layer A unit, auto-generate 3-5 near-miss mutants (off-by-one constant, swapped branch, `<` vs `<=`, wrong callee, signed vs unsigned, dropped store). Each mutant **must score below** the reference's tier. This directly verifies the gate cannot be fooled.

## 11. Harness and reporting

- **Manifest per unit:** ID, difficulty, cause tags, module, dependencies, expected tier per variant, expected-fail reason, golden trace file.
- **Golden traces:** keep `--golden`; add `double` and 64-bit rendering and a fixed seed per module so diffs are meaningful.
- **Answer key:** stored outside the analyzed binary's directory so an LLM run cannot read it.
- **Reports:** tier matrix (unit by variant), pass rate per tag and per difficulty, regression list vs last run, ledger growth curve for Layer B, time per `try`.
- **Ground-truth checks:** `Want*` expectations for every unit, plus cross-compiler agreement of golden traces.
- **Sanity gate:** every variant's golden trace must match the gcc `-O0` reference, proving the matrix is not silently changing semantics.

## 12. Phased rollout

Each phase is tied to a difficulty band, an expected-tier target, and an exit criterion. Do not start a phase until the previous exit criterion holds.

### Phase 0: Foundation (no new difficulty)

**Work:**

- Extend `CSelfTest` with `OutDouble` and `OutUInt64` (and matching `Want*`).
- Extend the manifest with difficulty, cause tags, expected tier per variant, dependencies.
- Build the matrix runner (smoke and full) and the tier-matrix report.
- Port existing units into the new manifest with measured baseline tiers.

**Exit:** the existing suite runs through the matrix runner and the baseline report is committed.

### Phase 1: D1-D2 breadth

**Modules:** `wideint`, `doublemath`, `control` (D1-D2 subset), first fixtures from Layer C (category isolation, accounting fuzz).

**Target tiers:** `exact` for D1 at all `-O`; `exact` at `-O0` and `semantic`+ at `-O2` for D2.

**Exit:** at least 90% of D1 units reach `exact` at smoke variants; every Layer C category fixture passes; the accounting fuzz is clean.

### Phase 2: D2-D3 data and ABI

**Modules:** `globals`, `calls`, the D3 parts of `control` and `wideint`; mutation generator; ledger-behavior fixtures.

**Target tiers:** `semantic` expected for D3, `exact` where achievable; `unverified` references documented per unit.

**Exit:** the mutation generator produces at least 300 mutants with equivalent-mutant filtering, and every non-equivalent mutant scores below its reference. Data-reference weaknesses are listed with a fix or waiver decision.

### Phase 3: D3-D4 structure and MSVC

**Modules:** `oop`, `templates`, `exceptions`; MSVC variants (`/GL` cap, ICF, `/MT` vs `/MD`); unit-boundary and address-domain fixtures.

**Target tiers:** `semantic` for D3; `structural` is an accepted ceiling for D4 where the manifest says so.

**Exit:** `structures.Recovery` correctly identifies classes, bases and slots on both ABIs for every `oop` unit; every ceiling is justified in the manifest.

### Phase 4: Layer B programs and readability

**Work:** the eight reconstruction programs (start with Resource manager and Hash map, finish with VM and Entity system), dependency-order manifests, readability rubric tooling.

**Target tiers:** per-unit tiers as above; the new measure is the group result (fraction of the program reconstructed to `semantic`+ following the suggested order).

**Exit:** `ledger --frontier` ordering is judged sensible on every program, and the rubric is applied to at least one candidate run per program.

### Phase 5: Extremes and hardening

**Modules:** `simd`, `mixed`, `-O3`, `-fno-rtti`, stripped static builds, `-m32` across the board.

**Target tiers:** D4 units graded against documented ceilings; regressions measured against ceilings, not against `exact`.

**Exit:** the full matrix runs nightly, expected tiers are stable across two consecutive toolchain-pinned runs, and the report shows pass rate by difficulty and cause tag.

### Rollout summary

| Phase | Difficulty band | Modules / layers | Target tier | Approx. new units |
| --- | --- | --- | --- | --- |
| 0 | n/a | Harness, manifest | Baseline only | 0 |
| 1 | D1-D2 | wideint, doublemath, control (part), Layer C basics | `exact` / `semantic`+ | 60-70 |
| 2 | D2-D3 | globals, calls, control (rest), mutants | `semantic` | 60-70 |
| 3 | D3-D4 | oop, templates, exceptions, MSVC variants | `semantic` / ceiling `structural` | 60-70 |
| 4 | D3-D4 | Layer B programs | group result | program units (about 80-120) |
| 5 | D4 | simd, mixed, extreme variants | documented ceilings | 30-40 |

Overall size: about 200-250 Layer A units, 8 programs, about 60 fixtures, and about 1,000 generated mutants.

## 13. Risks and open questions

- **Matrix explosion:** decide smoke vs nightly axes early and keep smoke fast.
- **Ceilings vs failures:** some units (SIMD at `-O3`, `/LTCG`) cannot exceed `structural`. Document them as ceilings.
- **Toolchain drift:** pin compiler versions in the manifest; a gcc upgrade changes idioms and invalidates expected tiers.
- **Equivalent mutants:** some mutants compile to identical bytes; the generator must detect and discard them.
- **LLM contamination:** keep reference sources and the answer key out of anything a candidate-generating model can read.
- **Cross-compiler golden drift:** floating-point results can differ legitimately between compilers; decide tolerances per unit.