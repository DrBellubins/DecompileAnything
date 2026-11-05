# Working on `decomp` and its benchmark

Read this only when editing the tool, the test binary or the benchmark, not when decompiling a user's target. Run commands from `Tests/`; the CLI is `../.venv/bin/decomp`.

## Building and checking

```sh
python3 eval.py build --variants gcc-o0,gcc-o2,gcc-o0-x86   # once per session
python3 eval.py units                                       # what is in the binary
python3 eval.py self                                        # recompile the untouched original and score it
python3 eval.py selfcheck                                   # must print "0 failures"
python3 eval.py crosscheck                                  # must show no same-arch differences
```

- After any edit to `TestBinary`: `eval.py build`, then `selfcheck` (0 failures), then `crosscheck` (no same-arch differences).
- The 89 hand-checked expectations are the ground truth. If a `Want*` disagrees with the code, work out which one is wrong; do not edit the expectation to match the run.
- Before blaming a candidate or the tool, run `eval.py self`. It is the ceiling: 99.5% at gcc-o0 and 98.3% at gcc-o2 on the reference machine. A unit scoring far below the ceiling for every candidate is a harness or fixture problem.

## Benchmark layout

- `Tests/TestBinary/TestFunctions/*.cpp` holds the units. Each definition carries `// DA-UNIT <ID> level:... tags:...` and a matching `DA_CASE(st, "ID")` block in that class's `RunSelfChecks`.
- Units are `DA_NOINLINE` (one body, one address, any `-O`); helpers are not, so helpers vanish into units at `-O2` on purpose.
- Example run: `decomp detect build/gcc-o0/da_tests.stripped`, `decomp analyze build/gcc-o0/da_tests.stripped --variant gcc-o0`, `decomp show 0x2834 --bin build/gcc-o0/da_tests.stripped`, `decomp try 0x2834 cand/math.cpp --fn AbsDiff`, `decomp types --write TestBinary/TestFunctions`.

## Fixture facts worth knowing

- Float results are compared as bit patterns (`goldens.jsonl` stores both `f` and `bits`). x87 (`-m32` default) and SSE (`-m32 -msse2`, x86-64) legitimately disagree: `SineApprox`, `SquareRootNewton` and `(float)mass * 0.001f` differ in the last ulp, which is why goldens are per-variant.
- Unions lie: writing through one view changes the other. `RectFromCorners` fills the width/height view, so `m_right`/`m_bottom` become 8/8 and `RectArea` returns 49, not 64.
- Struct padding is observable: `ChecksumDescriptorBytes` hashes it. A diff in a field offset is a struct-layout oracle; use it to fix the header, then re-score.
- `-m32` builds use `-no-pie -fno-pic`.
- Tiny units are 30+ bytes at `-O0` (every function has a frame); the sub-32-byte bucket only appears at `-O2`.
