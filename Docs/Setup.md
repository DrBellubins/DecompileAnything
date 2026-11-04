# Setup

The environment the `decomp` CLI (see [Design-Plan.md](Design-Plan.md)) needs, and how this repo is set up on the dev machine. Every version and command below was run and verified working on **2026-11-03**; anything marked *optional* is only needed by a later phase.

Two layers: **system tools** (installed once, machine-wide, on `PATH`) and a **persistent project venv** at `.venv/` for the Python side. Set them up in that order — the venv's `pyghidra` install path is derived from the Ghidra install.

---

## 1. System tools

| Tool | Version in use | Needed for |
|---|---|---|
| **Ghidra** | 12.1.2 | analysis, function discovery, pseudo-code, xrefs, types (Phase 1+) |
| **JDK** | 21+ (OpenJDK 27 here; `java-21-openjdk` also installed) | runs Ghidra / PyGhidra's JVM |
| **Python** | 3.14 (Ghidra 12.1.2 supports 3.9–3.14) | the CLI itself |
| **gcc / g++** | 16.2.1, multilib verified (`-m32 -no-pie -static`) | build candidate `.o` files (Phase 2) |
| **clang / clang++** | 23.1.4 | alternate compiler for flag inference (Phase 3) |
| **binutils** | 2.47 (`objdump -dr`, `nm --print-size`, `c++filt`, `strip`, `readelf`) | extracting and normalising instruction streams |
| `capstone`, `pyelftools`, `pefile`, `click` | provided by the distro's site-packages | disassembly, `.o`/PE reading — reused by the venv |
| MSVC `cl` | *not installed* (checked 2026-11-04: no `cl`, no `lld-link`, no Windows SDK/MSVC STL headers — `clang-cl` exists but cannot compile `#include <vector>`) | real PE/MSVC targets only; the install recipe and the two tiers (real `cl` under Wine, or `clang-cl` + downloaded MSVC/SDK) are in [MSVC-Plan.md](MSVC-Plan.md) §5 and phase MS-2 |
| `objdiff-cli` | *not installed* | optional Phase 5 alternate diff backend |
| `wine` | 9.21 Staging (`wine64` works; `/usr/bin/wine` is a 32-bit ELF whose interpreter `/lib/ld-linux.so.2` is not installed, so it fails to exec) | running `cl.exe`/`link.exe` for MSVC targets — use `wine64`, and `msitools`/`winbind` are still missing (MSVC-Plan.md §5) |

### Ghidra must be a system install reachable from `/usr/bin`

Install Ghidra into the system location so `/usr/bin/ghidra`, `/usr/bin/ghidra-analyzeHeadless` and `/usr/bin/pyghidra` exist (on this machine they are symlinks into `/opt/ghidra`). Do **not** keep a `~/Downloads/ghidra_*.zip` extraction. This matters for three reasons:

1. `pyghidra` is not a normal PyPI dependency — it must be pip-installed **from the wheel bundled inside that same Ghidra tree** (§2), so the install path has to be stable and predictable.
2. The bundled `pyghidra` version is pinned to the Ghidra release; a path in `$HOME` breaks every other agent/harness that drives this tool.
3. Headless runs (`ghidra-analyzeHeadless`) and PyGhidra must be the *same* Ghidra, or the cached analysis project cannot be reopened.

Check the installed pairing before doing anything else:

```bash
cat /opt/ghidra/Ghidra/application.properties     # application.version, application.java.min, application.python.supported
which ghidra ghidra-analyzeHeadless pyghidra      # all three must resolve under /usr/bin
java -version                                     # >= 21
```

`application.python.supported` must list your Python (here `3.14` is first, i.e. the primary supported build).

---

## 2. Python environment — persistent venv at `.venv/`

The system Python is **PEP 668 externally-managed**, so `pip install` / `pip install --user` is refused. Everything goes in one venv, checked into no branch (`.venv/` is gitignored) and recreated only when the interpreter or Ghidra changes.

```bash
cd ~/Documents/Github/DecompileAnything

python3 -m venv --system-site-packages .venv
export GHIDRA_INSTALL_DIR=/opt/ghidra

.venv/bin/pip install \
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.1.0-py3-none-any.whl" \
  typer lief unicorn
```

Notes on that command:

- **`--system-site-packages` is deliberate.** It reuses the distro-provided `capstone`, `pyelftools`, `pefile`, `click` (all already satisfy the plan's "lief **or** pyelftools+pefile" and "typer **or** click" alternatives), so only what is genuinely missing gets installed. For a fully self-contained venv instead, drop the flag and add `capstone pyelftools pefile` to the install line.
- **Install `pyghidra` from the bundled wheel, never from PyPI.** PyPI currently serves `pyghidra` 3.2.0, which targets a newer Ghidra than 12.1.2 and will not load against it. Find the right file with:
  ```bash
  ls "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist"
  ```
  Use the `pyghidra-<ver>-py3-none-any.whl` that lives there. **PyGhidra has its own version number**: the wheel bundled with Ghidra 12.1.2 is `pyghidra-3.1.0`, so "matching Ghidra" means *the same wheel*, not the same version string — `decomp check` compares the installed module against the wheel in that directory and says exactly which is wrong. `jpype1` (1.5.2) is pulled in as a dependency; import name is `jpype`, package name `jpype1`.
- `typer` = CLI (plan's first choice); `lief` = `.o`/ELF/PE parsing (plan's first choice); `unicorn` = optional Phase 5 behavioural check.

Resulting pins verified working on CPython 3.14 (`pip freeze` excerpt):

```
pyghidra @ file:///opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.1.0-py3-none-any.whl
jpype1==1.5.2
lief==1.0.0
typer==0.27.3          # + rich==15.0.0, shellingham==1.5.4, typing_extensions==4.16.0
unicorn==2.1.4
# inherited from system site-packages:
capstone==5.0.9  click==8.5.0  pyelftools==0.33  pefile==2024.8.26
# stdlib only, no install needed: difflib, json, sqlite3 (3.54), tomllib
```

The venv also provides `pyghidra` / `pyghidraw` entry points in `.venv/bin`.

### The package itself (Phase 1 and later)

The `decomp` package lives in `decomp/` and is installed editable, so `.venv/bin/decomp` works from any directory (`Tests/` included); `python -m decomp` works without installing it.

```bash
.venv/bin/pip install -e . --no-build-isolation     # creates .venv/bin/decomp
```

`--no-build-isolation` avoids re-downloading setuptools, which the venv already has. `pyghidra` is deliberately **not** in `pyproject.toml`'s dependencies — it must come from the bundled wheel above.

---

## 3. Configuration

### `GHIDRA_INSTALL_DIR` — required, not optional

`pyghidra.start()` raises `ValueError: Please set the GHIDRA_INSTALL_DIR environment variable or 'install_dir' during the Launcher construction…` if it is unset. Persist it in the shell profile (`export GHIDRA_INSTALL_DIR=/opt/ghidra`), or make `decomp/ghidra.py` resolve it itself and pass `pyghidra.start(install_dir=Path(...))`.

Resolution order for `decomp` (and what its Phase 1 startup check must report on failure):

1. `GHIDRA_INSTALL_DIR` from the environment;
2. `[ghidra] install_dir` in the target's `project.toml`;
3. `/opt/ghidra`, then `which ghidra` resolved through its symlink — and error out naming each path tried.

The startup check must verify, before any analysis: Ghidra dir contains `Ghidra/application.properties`, its `application.version` is paired with the `pyghidra` wheel bundled in that install, `java -version >= 21`, and the configured compiler responds to `--version`. That is implemented in `decomp/check.py` and run by `.venv/bin/decomp check -C Tests/project.toml`; `decomp analyze` runs the same checks first (a missing compiler is only a warning there, since analysis needs none) and refuses to start the JVM on a failure.

### Per-target config: `project.toml`

Same shape as `Tests/project.toml` (which `Tests/eval.py` already reads) — `std`, `threshold = 97.0`, `cppflags`, `linkflags`, and `[variants.<name>]` with `compiler` / `optimize` / `arch`. Add the analysis side:

```toml
[ghidra]
install_dir = "/opt/ghidra"        # fallback for GHIDRA_INSTALL_DIR
cache_dir   = "cache/ghproj"       # one Ghidra project per target binary, keyed by content hash
language    = ""                   # empty = let Ghidra auto-select (x86:LE:64:default here)
```

### Analysis cache

`decomp analyze` writes one Ghidra project per target binary into `cache/ghproj/<hash>/` so later commands never re-run auto-analysis. Measured on `Tests/build/gcc-o0/da_tests.stripped`: import 1.6 s + auto-analysis 4.6 s for 193 functions, versus **1.1 s** to reopen the cached project — which is what makes the stateless-CLI design usable.

Two hard constraints from Ghidra's `ProjectLocator`, both of which raise unhelpful Java exceptions:

- the project directory must be passed as an **absolute path** (`IllegalArgumentException: Absolute path required`) — `decomp` resolves `cache_dir` against the project root;
- **no path element may start with `.`**, so `~/.cache/…` and a repo `.cache/…` are both rejected (`Path element starting with '.' is not permitted`). Hence `cache/ghproj/` (gitignored) — and `ghproj`, not `ghidra`, for the reason in §5.

---

## 4. Verify the setup

With the package installed, the tool verifies its own environment, and one analysis plus one
lookup proves the whole path works:

```bash
.venv/bin/decomp check -C Tests/project.toml
.venv/bin/decomp analyze Tests/build/gcc-o0/da_tests.stripped --variant gcc-o0
.venv/bin/decomp show 0x2834 --bin Tests/build/gcc-o0/da_tests.stripped   # reads the cache, no JVM
.venv/bin/python Tests/tools/check_analysis_cache.py                      # cache vs the answer key
```

Expected: every check `ok`; the analysis reports `153 bodies, 17 thunks, 23 external` for
this build and writes `cache/ghproj/601677537ac2f6d3/analysis.db`; `show` prints the
pseudo-code and the instruction stream of `FUN_00102834` (`pushq %rbp …`, matching
`objdump -d`); the acceptance script prints `89/89 units found … size exact 89` for the
-O0 variants. If any of that fails, the raw probe below is the ground truth to re-run.

### Raw probe (no `decomp` involved)

```bash
.venv/bin/python - <<'PY'
import importlib.metadata as md
for mod, dist in [("pyghidra","pyghidra"), ("jpype","jpype1"), ("lief","lief"), ("typer","typer"),
                  ("unicorn","unicorn"), ("capstone","capstone"), ("elftools","pyelftools"), ("pefile","pefile")]:
    __import__(mod)
    print(f"{mod:<10} {md.version(dist)}")
PY
```

Then prove the whole Ghidra path works (this is the flow `decomp/ghidra.py` should use — the non-deprecated PyGhidra 3.1 / Ghidra 12 API):

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra
.venv/bin/python - <<'PY'
from pathlib import Path
import pyghidra
from pyghidra.api import open_project, program_loader, analyze, task_monitor
BIN   = Path("Tests/build/gcc-o0/da_tests.stripped").resolve()
CACHE = Path("cache/ghproj/probe").resolve(); CACHE.mkdir(parents=True, exist_ok=True)
pyghidra.start()
mon  = task_monitor()
proj = open_project(CACHE, "probe", create=True)          # absolute path, no dot-prefixed element
res  = program_loader().project(proj).source(str(BIN)).name("da").monitor(mon).load()
prog = res.getPrimaryDomainObject()
analyze(prog, mon); res.save(mon); res.release(mon)
print(prog.getLanguage().getLanguageID(), hex(prog.getImageBase().getOffset()),
      prog.getFunctionManager().getFunctionCount())
PY
```

Expected: `x86:LE:64:default 0x100000 216` (216 is `FunctionManager.getFunctionCount()`, which includes external/thunk entries; iterating `getFunctions(True)` yields the 193 real bodies — the `analyze` export must filter them). Ghidra prints JVM warnings (`final field … mutated reflectively`, `sun.misc.Unsafe`) on startup; they are harmless. The block is safe to re-run — `create=True` on a project directory that already exists just reopens it (first run ≈8 s wall clock including the JVM, second run reuses the analyzed project).

Also confirmed working on the same build: LIEF symbol → section bytes → relocations with symbol names and types, capstone x86-64 disassembly of those bytes, Unicorn emulating a small function body, and typer's CLI/help behaviour.

---

## 5. API notes for this pinned pair (Ghidra 12.1.2 + PyGhidra 3.1.0)

Most tutorials online are Ghidra 11-era and do not work here.

- No `pyghidra.gopen`. `pyghidra.open_program(...)` still works but is **deprecated** → use `open_project()` + `program_loader()` / `program_context()`.
- `open_project(dir, name, create=True)`: `dir` must be **absolute** and contain **no dot-prefixed path element**.
- Builder quirks: `.source()` needs a `str` (ambiguous overload for `Path`), `.log()` takes a `MessageLog`, `.load()` takes **no** monitor (use `.monitor(mon)`), and `.load()` returns `LoadResults` → `.getPrimaryDomainObject()`.
- `program_context()` yields a raw `ProgramDB`, so there are no `FlatProgramAPI` shortcuts: use `prog.getFunctionManager().getFunctionAt(addr)`, `prog.getListing()`, `prog.getSymbolTable()`.
- `DecompInterface.decompileFunction()` returns `DecompileResults` directly (no wrapper getter): check `.isValid()` / `.getErrorMessage()`, then read the pseudo-code with `.getDecompiledFunction().getC()`; the type info is at `.getHighFunction()`.
- Renamed getters: `AddressSet.getNumAddresses()` (not `getNumElements`), `Language.getLanguageID()` (not `getID`); `Section` has no `.symbols`, use `binary.symbols` / `sym.section`.
- LIEF 1.0: `binary.relocations` spans the **whole file** (853 entries in `math.o`, incl. `.eh_frame`) — filter by `r.section.name`, exactly like the `objdump` section filter needed in `Tests/eval.py`.
- capstone: `disasm(code, count=0, offset=0)` → `offset` must be a keyword argument.
- Machine quirk: `/tmp` holds many scratch `.py` files that shadow stdlib modules (`dis.py` breaks `capstone`/`click`). Never run Python from `/tmp`.
Things `decomp/ghidra.py` needed that are not in Ghidra-11-era tutorials (all hit while building Phase 1):

- **Addresses/bodies.** `AddressSet` has no `getNumBytes()` and `AddressRange` no `getNumAddresses()`; use `getMinAddress()`/`getMaxAddress()` and iterate `function.getBody().getAddressRanges()` — bodies really are multi-range in real binaries (159 ranges across 153 functions in the benchmark). `Listing.getInstructions(body, True)` walks every range of an `AddressSetView`; still guard with `body.contains(addr)`.
- **References.** `CodeUnit.getReferencesFrom()` also yields stack/register references (`StackReferenceDB`), which have no `getProgramSymbol()` and no `isCall()`. Keep `reference.isMemoryReference()` and decide call/data/jump from `reference.getReferenceType()` (`RefType`), not from the Reference. `Listing.getReferencesFrom(addr)` does not exist.
- **Comments.** `CodeUnit.getComment()` requires a `CommentType`; block comments come from `listing.getComment(address, CommentType.PLATE)`.
- **Parameters.** `Parameter.getDataType().getName()` — there is no `getDataTypeName()`.
- **Functions.** `getMaxAddress()` not `getLastAddress()`; `getThunkedFunction(boolean)` needs the flag; `Symbol.getAnnotation()` does not exist; `FunctionStackFrame` has no `getTotalLocalSpaceSize()`.
- **Address spaces.** `AddressSpace` has no `isDefaultSpace()`; the default space is `program.getAddressFactory().getDefaultAddressSpace()` and is named `ram`. Imported symbols appear in `getFunctions(True)` as entries inside Ghidra's `EXTERNAL` memory block and are **not** flagged `isExternal()` — classify them by block name, keep them (that is what a libc call resolves to), and do not decompile them. Memory blocks use `getStart()`/`getEnd()`.
- **Language/executable facts.** `Language.isLittleEndian()` does not exist (endianness is part of the language id); `Program.getEntryPoint()` does not exist — take the entry point from the file headers (`decomp/toolchain.py` via LIEF).
- **Bytes.** `Memory.getBytes(Address, int)` does not exist: allocate `jpype.JArray(JByte)(n)` and call `getBytes(address, buf, 0, n)`. Java bytes are signed, so mask with `& 0xFF`.
- **Symbol iteration.** `SymbolTable.getSymbols(True)` returned nothing here; `getAllSymbols(True)` with `hasNext()/next()` works.
- Never put a directory named `ghidra` on the import path. JPype exposes Ghidra's packages as a pseudo-module `ghidra`, so a real `ghidra/` directory reachable from `sys.path[0]` (e.g. running a scratch script from inside `cache/ghidra/`) wins the lookup and `import` dies with `RecursionError: maximum recursion depth exceeded`. This is why the analysis cache is `cache/ghproj/`, not `cache/ghidra/`.
