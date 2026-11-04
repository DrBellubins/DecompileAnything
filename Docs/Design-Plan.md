# LLM Decompile Tool: Implementation Plan

## Goal
A Python CLI that lets an LLM decompile functions from a binary by iterating: write source, compile, diff against the original, refine until the match threshold is met.

## Required Tools

**External (non-Python)**
| Tool | Purpose |
|---|---|
| Ghidra (recent release, with PyGhidra) | Analysis, function discovery, pseudo-code, xrefs, types |
| JDK (version Ghidra requires, currently 21+) | Runs Ghidra |
| Compiler (`gcc`/`clang`, optionally MSVC `cl`) | Builds candidate source into `.o` files. `cl` is Windows-only; the two ways to have it on Linux, and what each costs, are in [Docs/MSVC-Plan.md](MSVC-Plan.md) §5 |

**Python libraries**
| Library | Purpose |
|---|---|
| `pyghidra` | Drive Ghidra from CPython (bundled with Ghidra) |
| `lief` (or `pyelftools` + `pefile`) | Read `.o` and binary files, relocations, `.comment`, Rich header |
| `capstone` | Disassemble original and candidate functions |
| `typer` (or `click`/`argparse`) | CLI |
| `difflib` (stdlib) | Instruction-stream diff |
| `sqlite3` / `json` (stdlib) | Analysis cache |
| `unicorn` (optional, later) | Behavioral equivalence checks |

## Architecture

```
decomp/
  cli.py        # commands
  ghidra.py     # PyGhidra wrapper: analyze, export
  cache.py      # SQLite/JSON snapshot of analysis
  toolchain.py  # compiler detection + build config
  compile.py    # build candidate -> .o
  extract.py    # pull candidate function bytes + relocs from .o
  normalize.py  # addresses -> symbol names, optional register abstraction
  diff.py       # compare + categorize differences
  project.toml  # compiler, flags, include paths, threshold
```

## CLI Surface

- `decomp analyze <bin>`: run Ghidra once, cache everything.
- `decomp find <query>`: search by name, string, xref, or vtable; list related functions.
- `decomp show <func>`: asm, Ghidra pseudo-code, referenced types and symbols.
- `decomp try <func> <file.cpp>`: compile, diff, print match % and compact categorized diff.
- `decomp types`: shared struct and class definitions recovered so far (a header the LLM can reuse).

## Phases

Status: **Phase 1, Phase 2 and Phase 3 are implemented.** What the commands do, the cache format, the
measured results on `Tests/`, and the open gaps are documented in [README.md](README.md). The
rest of this plan is unchanged and still authoritative for what comes next.

**Phase 1: Skeleton and analysis cache** - done, 2026-11-03
1. Set up the package, config file, and startup checks (Ghidra path, JDK, compiler).
2. `analyze`: open the binary via PyGhidra, run auto-analysis, export per function: name, address, size, bytes, instructions, resolved references, pseudo-code, and callers and callees.
3. Store in the cache so later commands never start Ghidra.

**Phase 2: Compile and diff (the core loop)** - done, 2026-11-03
1. `compile.py`: invoke the compiler with the configured flags, producing a `.o`. (Done: the
   flags come from the variant the analysis was recorded with; the compiler's diagnostics are
   returned verbatim and the object is kept for `objdump`.)
2. `extract.py`: pull the target function's bytes and relocation entries from the `.o` (LIEF),
   mapping relocations to symbol names. (Done, plus the two cases a `.o` has that a linked
   image does not: a relocation naming a *section* with the offset as its addend, and a call
   or address-of inside the same section, which needs no relocation at all.)
3. `normalize.py`: on the original side, replace call targets and global addresses with symbol
   names from the cache. Both sides now compare symbolically. (Done as one shared tokeniser:
   positional symbol tokens per side, names/bytes/sizes kept and compared, function-relative
   branch labels.)
4. `diff.py`: align instruction streams, compute a match ratio, and categorize differences
   (opcode, operand, register-only, relocation, size). (Done; `register` is reported and
   `--register-abstract` exists, but the -O2 register-allocation work stays in Phase 5.)
5. Output: match %, size delta, and the differing lines only, kept short for the LLM's
   context. (Done, plus a table of what every symbol token means on each side.)
6. Validate on one simple free function from your test program at `-O0`. (Done, and further:
   `Tests/tools/check_phase2_try.py` scores all 89 units of the benchmark through the tool's
   own path - 99.94% mean, 88/89 pass the gate at gcc -O0, above the independent harness's
   own 99.53%/83. Known gaps are named in README.md.)

**Phase 3: Discovery and compiler detection** - done, 2026-11-03
1. `toolchain.py`: detect the compiler via `.comment` (ELF) or the Rich header (PE), and write a starting `project.toml`. (Done as `decomp detect <bin> [--write path]`: `.comment`/Rich header/CodeView, the object type - PIE vs `-no-pie`, dynamic vs `-static` - the machine class, and the C++ ABI and lowest `-std` proved by `.dynstr`/`DT_NEEDED`. The written config separates facts from guesses in comments and its `[variants.*]` reproduces the flags the target was really built with, measured on all three benchmark variants.)
2. `find`: name and string search, plus xref queries ("functions touching this global/vtable") to support requests like "decompile the coin system". (Done: symbol/global/vtable search, xrefs with the instruction at each site, the pointer slots of a data object - a vtable's methods - and which vtables a function appears in, plus `--family <hops>`, which grows the match along the call graph and ranks the result by call edges and shared objects. New module `discover.py`; the pointers come from the link's relocations, because in a PIE the file bytes of `.data.rel.ro` are zeros.)
3. Flag inference helper: compile a few reference snippets at different optimization levels and compare prologue and epilogue patterns. (Done: `PROBE_SOURCE` is compiled at `-O0..-O3` with the installed toolchain and the target's own code is described the same way, then ranked. -O0 is separated strongly from everything else (0.94 vs 3.32, and 0.26 vs 3.08 for the -m32 build); -O1/-O2/-O3 are reported as "optimised code", not a level, because that is what the evidence carries. A statically linked image must be sampled with `--range`: its glibc outvotes the program, and the tool says so rather than answering confidently.)

What Phase 3 learned, for whoever extends it:

* LIEF returns section flags as an **int** for ELF/PE (`str(section.flags)` is `"6"`), which the
  Phase 2 code was string-matching: every ELF section was silently read as neither allocated
  nor writable, so `TargetImage.read()` never returned anything and `diff`'s byte comparison of
  referenced objects had never actually run. Fixed (`extract.section_capabilities`), and the
  byte rule is now sound: bytes count only where both sides know what object they are reading
  (a size on both, or a name on both), because two 16-byte windows out of two independently
  laid-out `.rodata` pools are not the same object. `check_phase2_try.py` is unchanged at
  88/89 with that rule.
* Dynamic relocations have `has_section == False`; `R_*_RELATIVE` ones carry a *nameless*
  pseudo-symbol whose value is the addend. Both are traps that silently drop every pointer in
  the image if written the obvious way.
* Ghidra's own labels (source DEFAULT/ANALYSIS) sit *inside* objects, so an object's extent is
  bounded by the next symbol the **file** names (source IMPORTED), not by the next label.
* `endbr64`/`__stack_chk_fail`/frame-pointer shares are worth reporting as facts about the
  build (`-fcf-protection`, `-fstack-protector-strong` vs `-all`, `-fno-omit-frame-pointer`);
  they came free with the shape profile.

**MS-0..MS-5: MSVC / PE targets, a separate track** - MS-0 and MS-1 implemented, the rest not
Measured against a real MSVC binary (`Tests/Proprietary/notepad.exe`) in
[Docs/MSVC-Plan.md](MSVC-Plan.md), which is authoritative for that track: what a PE target already
gives the tool (its build note, and `.pdata` - the compiler's own table of 186 function ranges,
which MS-1 now caches, prefers for a unit's extent, and reports its disagreement with the
analysis over), what broke before MS-0 (`find`, `show`, `try`, `detect --range`), how to get `cl`
onto a Linux machine, and why the byte gate cannot be promised for a `/GL`+`/LTCG` target. MS-0
and MS-1 change nothing in the ELF path; MS-3 (COFF candidates) is the phase that makes `try`
work on PE at all.

**Phase 4: C++ structure recovery**
1. Identify vtables, constructors, and destructors from Ghidra data and RTTI where present.
2. Maintain a shared header (`types.h`) that candidates include, updated as struct layouts are confirmed.
3. Expose it via `decomp types`.

**Phase 5: Hardening**
1. Move to `-O2` test builds and handle inlining and register-allocation noise (register-abstracted comparison mode).
2. Optional: Unicorn-based behavioral check for functions that are semantically correct but not byte-identical.
3. Optional: synthesize a target `.o` (via `.reloc`) so `objdiff-cli` can be used as an alternate backend.

## Test Plan

- Write a small C++ program with several classes, a struct, virtual methods, and free functions.
- Build it with known flags, keep the source, and strip symbols from the "original."
- Success criterion: the LLM recovers each function to the threshold using only `show` and `try`.
- Progression: `-O0` free functions, then class methods, then virtual dispatch, then `-O2`.

## Key Design Decisions

- **Stateless CLI over a cached analysis**, so commands are fast and any agent harness can drive it.
- **The tool never edits source.** The LLM writes files; the tool only reports facts and scores.
- **Compact, categorized diffs**, not just a percentage, so the LLM knows what to change.
- **Match threshold is configurable** (e.g. 97%), but require relocation and opcode matches, not just ratio, to count as done.