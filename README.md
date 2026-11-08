![Decompile Anything](Images/DecompileAnythingBanner.png)

# DecompileAnything

DecompileAnything lets an LLM decompile a binary into **human-readable C/C++ that recompiles to the original bytes** (or, where exact matching isn't possible, to a similarity level you choose).

You ask for a feature ("decompile the input system"), not a list of functions. The tool finds the code that implements it, then the LLM recovers each function by looping: write source, compile it with the binary's own compiler and flags, diff against the original, refine. The `decomp` CLI does the analysis, compiling and scoring. It never edits source; the LLM does.

## Setup

**You need:**

- [Ghidra](https://ghidra-sre.org/) 12.x installed system-wide (e.g. `/opt/ghidra`), with `GHIDRA_INSTALL_DIR` set
- JDK 21+
- Python 3.11+
- `gcc`/`g++` (or `clang`) to build candidates; for 32-bit ELF targets, the 32-bit multilib (`decomp check` probes it)

**Install:**

```sh
python3 -m venv --system-site-packages .venv
source .venv/bin/activate

# pyghidra MUST come from the wheel bundled with your Ghidra, not PyPI
pip install "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl
pip install -e . --no-build-isolation
```

**Verify:**

```sh
decomp check
```

Every line should say `ok`. Anything that doesn't tells you how to fix it.

*Windows (PE/MSVC) targets* additionally need `cl` running under Wine. See [Docs/Setup.md](Docs/Setup.md) §6.

- For a **32-bit PE**, the target bitness is which `cl` runs, so you need the toolchain's `bin/x86` driver as well as `bin/x64`. `decomp check` prints an `msvc target x86` and `msvc target x64` row saying which this machine can build.
- Building 32-bit code needs nothing else. *Running* a 32-bit PE (for the benchmark's goldens and `selfcheck`) needs wibo or a Wine with an i386 guest; `decomp check` reports that separately as `run 32-bit PE`.
- `[msvc] prefix` in `project.toml` pins the toolchain a project is built with, so a variant resolves to that toolchain's driver instead of whatever `cl` is on `PATH`.

## Quick start

```sh
decomp detect Tests/build/gcc-o0/da_tests.stripped --write project.toml   # compiler + flags -> config
decomp analyze Tests/build/gcc-o0/da_tests.stripped -C project.toml       # run Ghidra once, cache the result
decomp find strncmp                                                       # search by name, string, address
decomp show 0x2834                                                        # everything known about a function
decomp try 0x2834 my/math.cpp --fn AbsDiff                                # compile, diff, score
decomp ledger                                                             # what has passed, and what to do next
decomp link                                                               # rebuild from what passed, compare whole (ELF)
```

Only `analyze` starts Ghidra. Everything else reads the cache, so `find` and `show` take about a second or less. `try`, `link` and `detect` also run a compiler, which takes longer, especially for MSVC under Wine.

## Commands

| Command | What it does |
|---|---|
| `decomp check` | Verify Ghidra, JDK, Python, compilers |
| `decomp detect <bin>` | Read the compiler, flags and likely `-O` level from the file, say whether the compiler on this machine is the one that made it, and list the flags the file itself names; can write a starting `project.toml` |
| `decomp analyze <bin>` | Run Ghidra once and cache everything |
| `decomp status` | List analysed binaries |
| `decomp find <query>` | Search names, strings, addresses, globals, vtables; `--family N` grows the match along the call graph |
| `decomp show <fn>` | Pseudo-code, assembly, references, callers/callees, class membership |
| `decomp try <fn> <file.cpp>` | Compile a candidate and diff it against the original; a unit that reaches the gate is recorded in the match ledger |
| `decomp ledger` | The pairs `try` has proven (which candidate symbol reproduces which address) and the frontier: unnamed callees the reproduced units reach most often |
| `decomp link` | Rebuild the program from the sources the ledger recorded, link it with the target's own flags, and compare it section by section. ELF only |
| `decomp types` | C++ classes, vtables and field offsets the binary proves; `--write <dir>` emits a `types.h` |
| `decomp symbols <pe>` | Fetch a Windows binary's PDB from Microsoft's symbol server |

Addresses can be Ghidra's or the file addresses that `nm`/`objdump` print. If more than one binary is cached, pass `--bin <file>`.

Exit codes: `0` ok (for `try`: reached the gate), `1` failed or below the gate, `2` usage/config error, `3` nothing found.

## How decompilation works

1. **Set up.** `detect` and `analyze` fix the compiler, flags and pass mark for the project.
2. **Scope.** Turn the request into a function list: find a foothold (an import, string or constant the feature must touch) with `find`, then grow it with `--family` and `show`. Library code and CRT are listed as excluded.
3. **Recover.** For each function, leaves first: `show` it, write the source with the real signature and field offsets, `try` it, read the diff, and fix what it names. Repeat until it passes. A passing unit goes into the match ledger, so later units are scored against names already proven; `decomp ledger` shows which callee to do next.
4. **Make it readable.** Group by class, add real types and names only where the binary proves them, comment provenance. Re-score everything touched, since readability must not cost a match.
5. **Check the whole.** For an ELF target, `decomp link` rebuilds the program from what passed and names the first place it differs from the target.
6. **Report.** A `MATCH_REPORT.md` listing what matched, what only partly matched, what wasn't attempted, and what is inferred.

The full workflow the LLM follows is in [Skills/SKILL.md](Skills/SKILL.md).

### What "matched" means

A percentage alone isn't the claim (97% of a wrong function is still wrong). Each function reaches a **tier**, and the project's `[gate] require` setting says which tier counts as done:

| Tier | Meaning |
|---|---|
| `structural` | Same length, same operations, same targets |
| `semantic` (default) | Plus every operand right, identical once register names are folded |
| `exact` | Plus identical bytes, ignoring only the fields the linker writes (call displacements, global addresses) |

The match percentage is shown as a progress indicator only. When a function falls short, the report says what is missing.

Two things can hold a function below the tier it otherwise reaches:

- **Unverified references.** If a global or callee has no name, size or readable bytes on either side, nothing proves the match there, so the unit stops at `structural`. Reproduce the object, decompile the callee so the ledger names it, or set `[gate] waive = "unverified"` for a target that cannot do better.
- **A different compiler.** `exact` is not claimed when the compiler here is not the one that made the file (another vendor, release, MSVC toolset, or target bitness). Byte differences across that gap are not something to iterate towards, so expect to stop at `semantic`.

## Layout

```
decomp/
  cli.py        commands: check, analyze, status, detect, show, find, ledger, try, link, types, symbols
  config.py     project.toml discovery, Ghidra install resolution, cache path rules
  check.py      startup checks, each naming the fix
  ghidra.py     the only JVM code: import, auto-analyse, export
  cache.py      the analysis cache (SQLite) and its read API
  toolchain.py  build flags per variant, the target's build note, -O inference
  discover.py   what a query names, what reaches it, what belongs with it
  compile.py    build the candidate source into an object file with the target's flags
  extract.py    pull one function out of either side: the cache (original) or the .o (candidate)
  normalize.py  decode both sides into one comparable token stream
  structures.py vtables, RTTI, constructors/destructors, field offsets, shared header
  diff.py       align, score, categorise, decide the tier
  fidelity.py   is the compiler here the one that made the file, and which flags beyond -O it names
  relink.py     `link`: compare a relinked program to the target, section by section
  spawn.py      subprocesses with deadlines that hold, and the Wine environment for MSVC tools
  symbols.py    PDB fetch from the Microsoft symbol server
  project.toml  default target config, used only when nothing closer is found
Docs/           design notes and setup details
Skills/         the workflow the LLM follows
Tests/          benchmark program, answer key and acceptance scripts
toolchains/     MSVC-under-Wine installer (optional)
cache/          analysis cache (gitignored)
```

The cache lives in `cache/ghproj/<key>/`, where `<key>` is a hash of the binary, so it follows the bytes and not the filename.

## Support

| Target | Analyse / find / show | `try` (scoring) | `types` | `link` |
|---|---|---|---|---|
| ELF, x86 32/64-bit (GCC/Clang) | yes | yes | yes | yes |
| PE, x86 32/64 bit (MSVC via `cl` under Wine) | yes | yes | yes | no |
| Other architectures (ARM, etc.) | partly | no | no | no |

Known limits:

- `-O1`/`-O2`/`-O3` can't be reliably told apart from the code alone (for MSVC, `/O1` and `/O2` are one class).
- A PE built with `/GL`+`/LTCG` can't be byte-reproduced from a single-file compile.
- `exact` is not available across a compiler release, toolset or bitness gap; `detect` and `try` say when there is one.
- A 32-bit PE has no `.pdata`, so a unit's extent comes from the analysis or `--size`, and `detect` samples it by cutting at every `ret` unless you pass `--sample` after `analyze`.
- `link` reads ELF only.

See [Docs/MSVC-Plan.md](Docs/MSVC-Plan.md), [Docs/MSVC-x86-Plan.md](Docs/MSVC-x86-Plan.md) and [Docs/byte-cleanup-plan.md](Docs/byte-cleanup-plan.md).

## More

- [Docs/Design-Plan.md](Docs/Design-Plan.md): plan, phases and design decisions
- [Docs/Setup.md](Docs/Setup.md): environment details and why it is set up that way
- [Docs/MSVC-Plan.md](Docs/MSVC-Plan.md): PE/MSVC support
- [Docs/MSVC-x86-Plan.md](Docs/MSVC-x86-Plan.md): 32-bit MSVC targets
- [Docs/byte-cleanup-plan.md](Docs/byte-cleanup-plan.md): the tiers, the match ledger, `link` and build fidelity
- [Tests/README.md](Tests/README.md): the benchmark that judges the loop

## Credits

- [REA](https://github.com/morluto/rea) by morluto: first agentic reverse engineering suite
- [LeanREA](https://github.com/aicodeking/leanrea) by aicodeking: initial skill base