# PE / MSVC targets in `decomp`

Read this only when the target is a PE built by MSVC. Counts and versions below are a snapshot from when this was written; re-check with `decomp check` and `decomp status`.

**Consequence for the main workflow:** none different. Scope the request and score candidates
exactly as SKILL.md describes - `try` works on a PE target and a COFF candidate (since MS-3).
What is still missing on a PE is `decomp types`: that RTTI format is `MS-5`, so a class or a
type descriptor cannot be named on the target side, and a unit that reaches one (a
`dynamic_cast`) will report a relocation difference that is not the candidate's fault. Name that
reason rather than chasing it.

## What works

- `decomp analyze`, `find`, `show` and `detect` work on a PE. The reference example is `Tests/Proprietary/notepad.exe` (236 functions). `detect` names the v141 toolset from the Rich header build id, `/GL` + `/LTCG` from the debug directory, and the public PDB that holds that file's answer key.
- Since MS-4 the build report is much more specific, and its facts are worth reading before
  choosing a variant: the toolset is read from link.exe's own Rich record **and** the optional
  header (and it says whether they agree); the per-front-end compiland counts say how many C, C++
  and asm compilands the link had and how many went through `/GL`; the language is claimed from a
  decorated name and the CRT family from the imports (`/MD` vs `/MT`); `/std:` is stated as what
  that toolset bounds, never as a fact; and for a PE the `-O` shape sample walks `.pdata` units.
  If `detect` answers `/O1|/O2`, treat that as a class: try the other level before believing a
  bad score is the candidate's fault.
- `try` works on a PE target: the candidate is compiled to a `.obj` and read back with COFF
  semantics (extents derived from the object, relocations with no addend). `decomp types` claims
  nothing for a PE, because that RTTI format is `MS-5` - a named, phased gap, not something to
  debug mid-task.

## The MSVC toolchain (since MS-2)

- `cl` / `link` / `lib` / `dumpbin` **14.12.25835.7** (v141, the era `detect` names for the reference target) at `toolchains/msvc/bin/x64`. It needs `PATH=<that dir>:$PATH WINEPREFIX=$PWD/.wine`.
- It compiles, links and runs PE programs under Wine. `Tests/eval.py build --variant msvc-o0|msvc-o2` builds the benchmark's own test binary: 89/89 answer-key units, `selfcheck` 89 cases, 0 failures.
- `detect --probe` measures its `/Od`, `/O1`, `/O2` code shapes.
- Its `.obj` files hold one `.text$<name>` COMDAT per function **only with `/Gy`**; with the
  benchmark's flags every function shares one `.text$mn`, and a COFF symbol carries no size, so the
  extent is the next function symbol in the section minus the trailing `int 3`/`nop` padding. The
  tool derives that itself; if a report says the candidate's unit is longer than the original's by
  a dozen `int3`s, that is the tool, not the candidate.
- The candidate's name is decorated (`?AbsDiff@CMathTests@@SAHHH@Z`). `--fn` accepts the plain
  identifier (`AbsDiff`); the decorated form stays the comparison key, so do not be surprised by it
  in a report.
- A `.obj` keeps placeholder displacements where the link writes the final ones, so `bytes
  identical` is not reachable for a unit that reaches outside itself - at any `-O`, either format.
  The instruction stream and the symbol tokens are the score.
- Two argument rules: put `/link` last (everything after it goes to the linker), and put only the top source directory on the include path (a project `math.h` in an `-I` directory shadows the CRT's `<math.h>` for `cl`).
- `decomp check` identifies each tool by banner and refuses impostors (`/usr/bin/link` is GNU coreutils; `clang-cl` is clang). Read its `msvc *` rows before believing any MSVC variant is usable.

## What a report about an MSVC target can and cannot say (MS-4)

- `/Od` against the optimising levels is knowable from the code (`cl /Od` keeps every local at
  `N(%rsp)` and writes every argument to its home slot; `/O1|/O2` do not). `/O1` against `/O2`
  is **not**: the only feature that separates them is whether `/O2` found a loop to vectorise.
  A `try` run at the wrong one of those two is not a broken candidate.
- `/GL` is said twice - the debug directory (POGO/LCTG) and the linker's own compiland records -
  and both mean the byte gate is off for that target: no single-file compile reproduces a
  link-time-regenerated image.
- `/GS` is reported from the shape (the cookie xor-ed with `%rsp`, or its check), because no
  header records it.
- At `/O2` the image's `.pdata` can name a **block** of a function rather than the function
  (hot/cold splitting, one COMDAT each), so a unit may be reported as a handful of bytes while
  the candidate holds the whole function. That is a known open gap in the tool, not a candidate
  bug - it is the 8 units `msvc-o2` does not pass.

## The function table (`.pdata`)

An x64 PE carries the compiler's own function table in `.pdata` (186 units on the reference file) and the tool reads it:

- `analyze` caches it and prints the reconciliation with the analysis (on the reference file: 154 agree, 32 the analysis reports shorter, 35 entries the file names no unit for).
- A unit's extent is what a diff compares; `--size` still overrides it.
- `show` prints the unit, or names the gap an analysis-only function sits in.
- `find` marks analysis-only entries `<- not in .pdata`.
- Trust the unit boundary over the analysis' size; trust the analysis for instruction boundaries.
- A cache made before this feature has no unit table: `analyze --force` gives it one.
