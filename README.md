# DecompileAnything

`decomp` is a CLI that lets an LLM decompile a function out of a compiled binary and keep
iterating until the candidate recompiles to the same bytes. The tool **never edits source**:
it reports facts about the original binary and scores a candidate the model wrote.

* [Docs/Design-Plan.md](Docs/Design-Plan.md) - the plan, phases, and the design decisions.
* [Docs/Setup.md](Docs/Setup.md) - the environment (Ghidra, JDK, venv) and why it is set up that way.
* [Tests/README.md](Tests/README.md) - the benchmark that judges the loop, independent of this tool.

## Status

| Phase | Deliverable | State |
|---|---|---|
| 1 | package, config, startup checks, `analyze`, analysis cache | **implemented** |
| 2 | `try`: compile -> extract -> normalise -> diff | not implemented |
| 3 | `find`: xref/vtable queries, compiler and flag inference | partial - name, string and address search work |
| 4 | `types`: vtables, RTTI, the shared header | not implemented |
| 5 | -O2 hardening, register-abstracted diff, Unicorn behaviour check | not implemented |

## Use it

```sh
.venv/bin/decomp check -C Tests/project.toml                  # Ghidra/JDK/Python/cache/compilers
.venv/bin/decomp analyze Tests/build/gcc-o0/da_tests.stripped --variant gcc-o0
.venv/bin/decomp status                                       # what is cached
.venv/bin/decomp find strncmp                                 # by name, 0xaddress, or string content
.venv/bin/decomp show FUN_00102834 --bin Tests/build/gcc-o0/da_tests.stripped
```

Only `analyze` starts Ghidra (about 10 s for a 193-function binary, once per binary).
`show`, `find` and `status` read the SQLite cache and finish in ~0.1 s, which is what makes
a stateless CLI usable inside an agent loop. `show`/`find` also accept the file addresses
that `nm` and `objdump` print (see "Address domains").

Exit codes: 0 ok, 1 a check or the work failed, 2 usage/config error, 3 nothing found (or a
command of a later phase).

## Layout

```
decomp/
  cli.py        typer commands: check, analyze, status, show, find, (try, types)
  config.py     project.toml discovery, Ghidra install resolution, cache path rules
  check.py      startup checks, each naming what it looked for and the fix
  ghidra.py     the only JVM code: import, auto-analyse, export
  cache.py      the analysis cache (SQLite) and its read API
  toolchain.py  build flags per variant, the target's build note (.comment / Rich header)
  normalize.py  shared disassembly (capstone, AT&T like objdump); the diff lands here in Phase 2
  project.toml  the default target config, used only when nothing closer is found
```

The cache lives in `cache/ghproj/<key>/` (`cache_dir` in `project.toml`; never under a path
element starting with `.`):

```
<key>/analysis.db    functions, instructions, resolved references, call graph, pseudo-code,
                     symbols, strings, sections, and the meta table (analysis facts)
<key>/target.gpr     the Ghidra project itself, so re-analysis is never needed
```

`<key>` is a content hash of the target, so the cache follows the bytes, not the filename.
Every write is one transaction whose last statement records `complete`; a half-written cache
is never mistaken for a usable one, and a cache written by another `CACHE_VERSION` is rebuilt.

## Address domains

Ghidra loads a PIE at `0x100000`, while `nm`, `objdump` and LIEF speak the file's own
addresses. `analyze` computes the offset from the section map and stores it in
`meta.address_offset`; `show` prints both forms and accepts either one:

```
; entry 0x102834 (file 0x2834)  size 33  section .text  kind function
```

Phase 2 needs this to be exact: it extracts original bytes by address from the file and
candidate bytes from a `.o`.

## Verified on the benchmark (measured here, 2026-11-03)

`python Tests/tools/check_analysis_cache.py` cross-checks the cache against
`Tests/build/<variant>/answer_key.json` (the true address and size of every unit, from the
unstripped build):

| variant | units found at their answer-key address | size exactly as the compiler's symbol | instructions / pseudo-code |
|---|---|---|---|
| gcc-o0 (x86-64) | 89 / 89 | 89 / 89 | all / all (8 units have no references - leaf functions) |
| gcc-o0-x86 (-m32, static) | 89 / 89 | 89 / 89 | all (analysed with `--no-pseudocode`) |
| gcc-o2 (x86-64) | 89 / 89 | 38 / 89 | all |

The cache is 1.2 MB for the x86-64 -O0 build, 13 MB for the static -m32 build.

The -O2 size differences are Ghidra's function detection at -O2 (trailing padding, tail
merging), not a mapping error: addresses still match. Two -O2 units (STR-04, STR-11) are
classified as thunks because their bodies are a tail call. Phase 2 has to cope with that
per variant, exactly like the benchmark's own `-O2` calibration does.

## Known gaps before Phase 2

* Ghidra's function boundaries at `-O2` differ from the compiler's; the diff must be
  scored per variant, and the answer key's sizes are the safer extraction range.
* `find` does not yet answer xref/vtable questions ("what touches this global") beyond the
  raw reference list, and flag inference (Phase 3) is not started.
* PE/MSVC targets are untested here: the ELF path works, the Rich-header note is written but
  unexercised, and `cl` is not installed on this machine.
* `[ghidra] language` in `project.toml` is validated but not wired into the importer;
  Ghidra's auto-selection is used and the chosen language is recorded.
