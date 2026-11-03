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
python3 eval.py try --unit STRUCT-12 --src cand/structs.cpp --fn UnlinkNode
```

Per unit: `show` (asm + pseudo-code + referenced types/symbols) → write the function with
its real signature and real field offsets → `try` → read the diff → change the thing the
diff names. Stop when `match >= threshold` **and** `opcode: 0`. Never stop on the
percentage alone.

# Reading a score

| signal | what it means | do |
|---|---|---|
| `opcode: n` | wrong operation: cmov vs branch, imul vs shifts, signed vs unsigned load | fix the operation; `movzbl` vs `movsbl` and `idiv` vs `shrd` are the usual ones |
| `operand: n` | right operation, wrong offset/constant/type | field offsets, struct layout, the type of an array element, a truncated buffer bound |
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
