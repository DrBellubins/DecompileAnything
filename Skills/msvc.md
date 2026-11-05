# PE / MSVC targets in `decomp`

Read this only when the target is a PE built by MSVC. Counts and versions below are a snapshot from when this was written; re-check with `decomp check` and `decomp status`.

**Consequence for the main workflow:** scope the request (Steps 1 and 2) as usual, but `try` cannot score candidates, so recovered functions are **unscored**. Label them that way in the match report and never call them matched.

## What works

- `decomp analyze`, `find`, `show` and `detect` work on a PE. The reference example is `Tests/Proprietary/notepad.exe` (236 functions). `detect` names the v141 toolset from the Rich header build id, `/GL` + `/LTCG` from the debug directory, and the public PDB that holds that file's answer key.
- `try` does **not** work on a PE yet: nothing implements COFF *candidate* semantics (`MS-3` in `Docs/MSVC-Plan.md`). `decomp types` also claims nothing for a PE, because that RTTI format is `MS-5`. Both are named, phased gaps, not something to debug mid-task.

## The MSVC toolchain (since MS-2)

- `cl` / `link` / `lib` / `dumpbin` **14.12.25835.7** (v141, the era `detect` names for the reference target) at `toolchains/msvc/bin/x64`. It needs `PATH=<that dir>:$PATH WINEPREFIX=$PWD/.wine`.
- It compiles, links and runs PE programs under Wine. `Tests/eval.py build --variant msvc-o0|msvc-o2` builds the benchmark's own test binary: 89/89 answer-key units, `selfcheck` 89 cases, 0 failures.
- `detect --probe` measures its `/Od`, `/O1`, `/O2` code shapes.
- Its `.obj` files hold one `.text$<name>` COMDAT per function, which is where a COFF function's exact extent comes from.
- Two argument rules: put `/link` last (everything after it goes to the linker), and put only the top source directory on the include path (a project `math.h` in an `-I` directory shadows the CRT's `<math.h>` for `cl`).
- `decomp check` identifies each tool by banner and refuses impostors (`/usr/bin/link` is GNU coreutils; `clang-cl` is clang). Read its `msvc *` rows before believing any MSVC variant is usable.

## The function table (`.pdata`)

An x64 PE carries the compiler's own function table in `.pdata` (186 units on the reference file) and the tool reads it:

- `analyze` caches it and prints the reconciliation with the analysis (on the reference file: 154 agree, 32 the analysis reports shorter, 35 entries the file names no unit for).
- A unit's extent is what a diff compares; `--size` still overrides it.
- `show` prints the unit, or names the gap an analysis-only function sits in.
- `find` marks analysis-only entries `<- not in .pdata`.
- Trust the unit boundary over the analysis' size; trust the analysis for instruction boundaries.
- A cache made before this feature has no unit table: `analyze --force` gives it one.
