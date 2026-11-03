# LLM Decompile Tool: Implementation Plan

## Goal
A Python CLI that lets an LLM decompile functions from a binary by iterating: write source, compile, diff against the original, refine until the match threshold is met.

## Required Tools

**External (non-Python)**
| Tool | Purpose |
|---|---|
| Ghidra (recent release, with PyGhidra) | Analysis, function discovery, pseudo-code, xrefs, types |
| JDK (version Ghidra requires, currently 21+) | Runs Ghidra |
| Compiler (`gcc`/`clang`, optionally MSVC `cl`) | Builds candidate source into `.o` files |

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

Status: **Phase 1 is implemented** - the commands that exist, the cache format, the measured
results on `Tests/`, and the open gaps are documented in [README.md](README.md). The rest of
this plan is unchanged and still authoritative for what comes next.

**Phase 1: Skeleton and analysis cache** (done)
1. Set up the package, config file, and startup checks (Ghidra path, JDK, compiler).
2. `analyze`: open the binary via PyGhidra, run auto-analysis, export per function: name, address, size, bytes, instructions, resolved references, pseudo-code, and callers and callees.
3. Store in the cache so later commands never start Ghidra.

**Phase 2: Compile and diff (the core loop)**
1. `compile.py`: invoke the compiler with the configured flags, producing a `.o`.
2. `extract.py`: pull the target function's bytes and relocation entries from the `.o` (LIEF), mapping relocations to symbol names.
3. `normalize.py`: on the original side, replace call targets and global addresses with symbol names from the cache. Both sides now compare symbolically.
4. `diff.py`: align instruction streams, compute a match ratio, and categorize differences (opcode, operand, register-only, relocation, size).
5. Output: match %, size delta, and the differing lines only, kept short for the LLM's context.
6. Validate on one simple free function from your test program at `-O0`.

**Phase 3: Discovery and compiler detection**
1. `toolchain.py`: detect the compiler via `.comment` (ELF) or the Rich header (PE), and write a starting `project.toml`.
2. `find`: name and string search, plus xref queries ("functions touching this global/vtable") to support requests like "decompile the coin system."
3. Flag inference helper: compile a few reference snippets at different optimization levels and compare prologue and epilogue patterns.

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