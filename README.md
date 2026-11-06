![Decompile Anything](Images/DecompileAnythingBanner.png)

# DecompileAnything

DecompileAnything lets an LLM decompile a binary into **human-readable C/C++ that recompiles to the original bytes** (or, where exact matching isn't possible, to a similarity level you choose).

You ask for a feature ("decompile the input system"), not a list of functions. The tool finds the code that implements it, then the LLM recovers each function by looping: write source, compile it with the binary's own compiler and flags, diff against the original, refine. The `decomp` CLI does the analysis, compiling and scoring. It never edits source; the LLM does.

## Setup

**You need:**

- [Ghidra](https://ghidra-sre.org/) 12.x installed system-wide (e.g. `/opt/ghidra`), with `GHIDRA_INSTALL_DIR` set
- JDK 21+
- Python 3.11+
- `gcc`/`g++` (or `clang`) to build candidates

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

## Quick start

```sh
decomp detect Tests/build/gcc-o0/da_tests.stripped --write project.toml   # compiler + flags -> config
decomp analyze Tests/build/gcc-o0/da_tests.stripped -C project.toml       # run Ghidra once, cache the result
decomp find strncmp                                                       # search by name, string, address
decomp show 0x2834                                                        # everything known about a function
decomp try 0x2834 my/math.cpp --fn AbsDiff                                # compile, diff, score
```

Only `analyze` starts Ghidra. Everything else reads the cache and runs in about a second or less.

## Commands

| Command | What it does |
|---|---|
| `decomp check` | Verify Ghidra, JDK, Python, compilers |
| `decomp detect <bin>` | Read the compiler, flags and likely `-O` level from the file; can write a starting `project.toml` |
| `decomp analyze <bin>` | Run Ghidra once and cache everything |
| `decomp status` | List analysed binaries |
| `decomp find <query>` | Search names, strings, addresses, globals, vtables; `--family N` grows the match along the call graph |
| `decomp show <fn>` | Pseudo-code, assembly, references, callers/callees, class membership |
| `decomp try <fn> <file.cpp>` | Compile a candidate and diff it against the original |
| `decomp types` | C++ classes, vtables and field offsets the binary proves; `--write <dir>` emits a `types.h` |
| `decomp symbols <pe>` | Fetch a Windows binary's PDB from Microsoft's symbol server |

Addresses can be Ghidra's or the file addresses that `nm`/`objdump` print. If more than one binary is cached, pass `--bin <file>`.

Exit codes: `0` ok (for `try`: reached the gate), `1` failed or below the gate, `2` usage/config error, `3` nothing found.

## How decompilation works

1. **Set up.** `detect` and `analyze` fix the compiler, flags and pass mark for the project.
2. **Scope.** Turn the request into a function list: find a foothold (an import, string or constant the feature must touch) with `find`, then grow it with `--family` and `show`. Library code and CRT are listed as excluded.
3. **Recover.** For each function, leaves first: `show` it, write the source with the real signature and field offsets, `try` it, read the diff, and fix what it names. Repeat until it passes.
4. **Make it readable.** Group by class, add real types and names only where the binary proves them, comment provenance. Re-score everything touched, since readability must not cost a match.
5. **Report.** A `MATCH_REPORT.md` listing what matched, what only partly matched, what wasn't attempted, and what is inferred.

The full workflow the LLM follows is in [Skills/SKILL.md](Skills/SKILL.md).

### What "matched" means

A percentage alone isn't the claim (97% of a wrong function is still wrong). Each function reaches a **tier**, and the project's `[gate] require` setting says which tier counts as done:

| Tier | Meaning |
|---|---|
| `structural` | Same length, same operations, same targets |
| `semantic` (default) | Plus every operand right, identical once register names are folded |
| `exact` | Plus identical bytes, ignoring only the fields the linker writes (call displacements, global addresses) |

The match percentage is shown as a progress indicator only. When a function falls short, the report says what is missing.

## Layout

```
decomp/
  cli.py        commands: check, analyze, status, detect, show, find, try, types, symbols
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

| Target | Analyse / find / show | `try` (scoring) | `types` |
|---|---|---|---|
| ELF, x86 32/64-bit (GCC/Clang) | yes | yes | yes |
| PE, x86-64 (MSVC via `cl` under Wine) | yes | yes | yes |
| Other architectures (ARM, etc.) | partly | no | no |

Known limits: `-O1`/`-O2`/`-O3` can't be reliably told apart from the code alone, and a PE built with `/GL`+`/LTCG` can't be byte-reproduced from a single-file compile. See [Docs/MSVC-Plan.md](Docs/MSVC-Plan.md) and [Docs/byte-cleanup-plan.md](Docs/byte-cleanup-plan.md).

## More

- [Docs/Design-Plan.md](Docs/Design-Plan.md): plan, phases and design decisions
- [Docs/Setup.md](Docs/Setup.md): environment details and why it is set up that way
- [Docs/MSVC-Plan.md](Docs/MSVC-Plan.md): PE/MSVC support
- [Tests/README.md](Tests/README.md): the benchmark that judges the loop

## Credits

- [REA](https://github.com/morluto/rea) by morluto: first agentic reverse engineering suite
- [LeanREA](https://github.com/aicodeking/leanrea) by aicodeking: initial skill base