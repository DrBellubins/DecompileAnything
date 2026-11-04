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
| MSVC `cl` | *not installed* (checked 2026-11-04: no `cl`, no `lld-link`, no Windows SDK/MSVC STL headers — `clang-cl` exists but cannot compile `#include <vector>`) | real PE/MSVC targets only; **§6** gives the setup steps for every toolchain era from VS2005 to VS2026, in both 32-bit and 64-bit form ([MSVC-Plan.md](MSVC-Plan.md) §5 and phase MS-2 are the why, §6 is the how) |
| `objdiff-cli` | *not installed* | optional Phase 5 alternate diff backend |
| `wine` | 9.21 Staging. `wine64` runs **64-bit** PE files (`x86_64-w64-mingw32-g++` probe prints, exit 0). It cannot start a **32-bit** PE: `/lib/ld-linux.so.2: could not open` — the Wine build does have 32-bit guests (`/usr/lib/wine/i386-windows` exists) but the host has no 32-bit ELF interpreter; `/usr/bin/wine` itself is that 32-bit ELF and fails to exec. | running `cl.exe`/`link.exe` for MSVC targets — `wine64` is enough for every toolset from VS2015 on (they all ship an x64-hosted `cl`), and *not* enough for the 32-bit-host tools of VS2013 and older; §6.7 fixes that |

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

---

## 6. MSVC toolchains: VS2005 → VS2026, 32-bit and 64-bit

Matching decomp needs *the compiler the target was built with*, not "a" compiler — a candidate
built by the wrong toolset era fails the byte gate for reasons that have nothing to do with the
candidate source (`Docs/MSVC-Plan.md` §6). So the setup goal is not "install MSVC" but "be able to
have several toolsets side by side, each one pinned, each one addressable by a variant".

Everything below is the **steps** for that. As of 2026-11-04 nothing has been automated in
`decomp/` and no toolchain is installed yet; §6.9 lists what the tool still has to learn.
What *was* done here is the research, and every command marked measured has its output quoted:
the manifest reads (§6.3), the MSI-extraction fallbacks (§6.3 item 3), the Wine/32-bit-PE and
SDK-version probes (§6.7), and the live-URL checks (§6.4).

### 6.1 Layout (decided, not yet created beyond the clone)

```
DecompileAnything/
  toolchains/
    msvc-wine/            # upstream installer scripts only - git clone, pinned SHA, keep it small
    msvc/<toolset-tag>/   # downloaded VC + Windows Kits - gitignored, ~1-2 GB each
    cache/                # msvc-wine --cache: the downloaded MSIs/VSIXs, shared by every toolset
  .wine/                  # WINEPREFIX - disposable, rebuilt by the steps below, gitignored
```

The two halves are deliberately separate: the toolchain is the expensive, version-pinned asset; the
prefix is a disposable runtime that any command may wipe. A prefix is **not relocatable** (it stores
absolute paths), so "move the repo" always means "recreate `.wine/`".

Recreate the scripts (already present at `toolchains/msvc-wine`, HEAD `514f8ea` — pin it in any
script so a re-run is reproducible; `gitignore` keeps the whole `toolchains/` tree out of the repo
precisely so this stays reproducible instead of checked in):

```sh
mkdir -p toolchains && cd toolchains
git clone https://github.com/mstorsjo/msvc-wine
git -C msvc-wine checkout 514f8ea        # vsdownload: Add option switches for each component
```

Create the prefix (once per checkout location):

```sh
export WINEPREFIX="$PWD/.wine" WINEARCH=win64 WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree,mshtml="    # no Mono/Gecko first-run prompts
wine64 wineboot -u
wineserver -p                               # keep it alive: cold-starting it per compile is the
                                            # single biggest latency hit in the refine loop
```

Use `/Z7` (C7 codeview), never `/Zi`, when compiling candidates: `/Zi` starts `mspdbsrv.exe`, which
is the usual source of flaky parallel builds under Wine, and PDBs are not needed to compare `.obj`
files.

### 6.2 Three questions decide how to install a toolset

| Question | Why it decides the method |
|---|---|
| **Is the release manifest-based?** (VS2017+) | `vsdownload.py` reads the VS installer's channel manifest (`https://aka.ms/vs/<major>/{release,pre}` — for 18+ the channel words are `{stable,insiders}`) and pulls payloads straight off Microsoft's CDN with **no Wine and no Windows installer**. Pre-2017 has no manifest: those come from an ISO/bootstrapper you extract yourself (§6.4, §6.5). |
| **Is the `cl.exe` we can use a 64-bit binary?** | From VS2015 on, every toolset ships an **x64-hosted** compiler for both target bitnesses (`VC/tools/msvc/<ver>/bin/Hostx64/{x86,x64}/cl.exe`) → `wine64` runs it. In VS2010–VS2013 the *default* x86-targeting compiler is a 32-bit host (`VC/bin/x86*`), but `VC/bin/amd64*` cross tools also exist and are 64-bit binaries. VC2005/VC2008 x86 targets really are 32-bit-host only → a 32-bit PE runner (§6.7). |
| **Which target bitness do we need?** | Independent of the two above: an x64-host `cl` emits 32-bit code (`/arch` is not how — the *host dir* picks it: `Hostx64/x86` is x64-host → x86-target). msvc-wine's `--architecture x86 x64` fetches the CRT/headers/libs for both. `install.sh` then generates a wrapper per target arch: `bin/<arch>/cl` → `vc/tools/msvc/$MSVCVER/bin/Host$host/$arch/cl.exe`, i.e. **`--host-arch x64 --architecture x86 x64` gives 32-bit and 64-bit targets with no 32-bit Wine at all**. |

Confirm the host bitness of any extracted compiler instead of trusting a table:
`file "<dir>/cl.exe"` → `PE32+ … x86-64` runs under `wine64`; `PE32 … Intel i386` needs §6.7.

### 6.3 VS2017 → VS2026: one `vsdownload.py` call per toolset

```sh
# one toolset, both target bitnesses, x64 host, shared download cache
.venv/bin/python toolchains/msvc-wine/vsdownload.py \
    --accept-license --cache toolchains/cache \
    --dest toolchains/msvc/v141 \
    --major 15 --msvc-version 15.5 \
    --architecture x86 x64 --host-arch x64
sh toolchains/msvc-wine/install.sh toolchains/msvc/v141
export PATH="$PWD/toolchains/msvc/v141/bin/x64:$PATH"      # or bin/x86 for 32-bit targets
```

`--msvc-version` takes a **VS** version, not a compiler version; `vsdownload.py` maps it to the
toolset package `Microsoft.VisualStudio.Component.VC.Tools.<toolversion>` and to the SDK that
workload shipped with (read the mapping in `vsdownload.py:202-280`). The supported pins, measured
by reading that file at the pinned SHA:

| `--major` | `--msvc-version` | toolset (`cl`) | default SDK | `_MSC_VER` |
|---|---|---|---|---|
| 15 (VS2017) | `15.4` … `15.9` | 14.11 … 14.16 (v141) | 10.0.16299 / 17134 / 17763 | 1910-1916 |
| 16 (VS2019) | `16.0` … `16.9` | 14.20 … 14.29 (v142) | 10.0.17763 … 10.0.19041 | 1920-1929 |
| 17 (VS2022) | `17.0` … `17.14` | 14.30 … 14.4x (v143) | 10.0.19041 … | 193x, 194x from 17.10 |
| 18 (VS2026, **the script's default**) | `18.0`, `latest`, `preview` | 14.5x (v145) | Windows 11 SDK (10.0.28000-era) | 195x |

(That table is what the pinned SHA supports; newer `--msvc-version` pins only appear by updating the
clone - re-read `vsdownload.py:202-280` after bumping it, or read a saved manifest.)

- The repo's own PE probe target (`Tests/Proprietary/notepad.exe`) is **linker 14.12, Rich build id
  25711** (`Docs/MSVC-Plan.md` §2), so the toolset to install first is `--major 15 --msvc-version
  15.5` → 14.12. This is what `decomp detect` should eventually emit as a command line rather than
  a guess.
- As of 2026-10 the newest shipped toolset is **MSVC Build Tools 14.51** (GA with VS2026 18.6,
  `cl 19.51.36243`); 14.52 is at RC. Sources: [compiler versioning](https://learn.microsoft.com/en-us/cpp/overview/compiler-versions),
  [what's new](https://learn.microsoft.com/en-us/cpp/overview/what-s-new-for-msvc),
  [14.51 GA](https://devblogs.microsoft.com/cppblog/msvc-version-1451-available/).
- Discovering what a channel offers (no download, ~5 s each; both verified here):
  ```sh
  .venv/bin/python toolchains/msvc-wine/vsdownload.py --major 15 --print-version
  #   Fetching https://aka.ms/vs/15/release/channel
  #   Got toplevel manifest for 15.9.84
  #   Loaded installer manifest for 15.9.84
  .venv/bin/python toolchains/msvc-wine/vsdownload.py --major 15 --accept-license --list-components
  .venv/bin/python toolchains/msvc-wine/vsdownload.py --major 15 --accept-license --save-manifest \
      toolchains/cache/manifest-15.json          # then grep it offline
  ```
  Note `--list-components`/`--print-selection` still demand `--accept-license`, and for major 15 the
  only `VC.<n>`-shaped component name is `Microsoft.VisualStudio.Component.VC.140` — that is the
  **VS2015 (v140) toolset, offered by the VS2017 channel**, which is the cheapest way to get a
  v140 compiler onto a Linux box (see §6.4).
- Smaller/faster knobs worth knowing for a repeatable script: `--only-download` / `--only-unpack`,
  `--language en`, `--skip-patch` (patches are applied only to major 18 by default),
  `--with-sdk=no` to reuse an SDK already installed by another toolset.

**Prerequisites — and the blocker on this machine.** The manifest route needs `wine64`, `python3`,
`msitools` ≥ 0.98 (`msiextract`) and `libgcab` ≥ 1.2, plus `winbind` for the MSVC C1902 "Program
database manager mismatch". `vsdownload.py` picks the extractor by platform only: `msiexec /a` on
Windows, `msiextract` everywhere else (`vsdownload.py:787-801`). Measured here (Arch, in a
container): `msiextract`/`msitools` are **absent** and cannot be installed — `sudo` refuses with
`The "no new privileges" flag is set` — so **the extraction step cannot run as-is**. Three ways
through, in order of preference:

1. Install the packages once, machine-wide (needs root): Arch `pacman -S msitools libgcab samba`
   (`samba` is what provides the `winbind` binary); Debian/Ubuntu `apt install msitools
   libgcab-1.0-0 winbind`; Fedora `dnf install msitools libgcab winbind`. This is the path the
   steps above assume.
2. Use the upstream container (`toolchains/msvc-wine/Dockerfile` installs exactly that set, and its
   CI runs `--major 15` + `--major 17` through `cl test/hello.c`) and copy the resulting `VC/` and
   `Windows Kits/` trees into `toolchains/msvc/<tag>/`.
3. Substitute an extractor that needs no root. Two that were verified end to end here:
   - `pip install python-msi` into the venv (no root; installed and removed again during this
     research, so §2's pin list is unchanged) → `.venv/bin/pymsi extract -o out x.msi`.
     On the VS2005 redist MSI it produced 96 files **including the external-cabinet payload**
     (`msvcr80.dll`, `msvcp80.dll`, …), so the extraction itself works. But its output paths are the
     MSI's *directory table* IDs (`ProgramFilesFolder/Common Files/...`, `WindowsFolder/winsxs/...`),
     not the layout `install.sh`'s `moveVCSDK` looks for (`VC`, `Windows Kits`) — a shim in place of
     `msiextract` must resolve those directory names, so this is not drop-in.
   - Wine's own installer, administrative mode, which needs nothing extra and *does* resolve
     directory names (`msdia80.dll` landed under a real `Program Files/...` path):
     ```sh
     wine64 msiexec /a "$(winepath -w pkg.msi)" TARGETDIR='z:/abs/dest' /qn
     ```
     (`7z`, `7za`, `bsdtar`, `cabextract` and `unzip` are all installed here as further fallbacks —
     but `7z` on an MSI yields `file00001.dat` names, because it ignores the file table.)

### 6.4 VS2013 – VS2016 (v120, v140): no manifest, so extract it yourself

Two routes, and try the first one first:

* **v140 through the VS2017 channel.** `--major 15 --accept-license
  Microsoft.VisualStudio.Component.VC.140 --with-sdk=yes --architecture x86 x64 --host-arch x64`
  real VS2015 toolset, fetched and laid out by the same scripts, x64-host compilers, no ISO. The
  component id is confirmed present in the 15.9.84 manifest (§6.3); the command line itself is not
  run end to end here, because extraction is still the blocker (§6.3).
* **v120 (VS2013) from an ISO.** These URLs answered `200` on 2026-11-04 (`curl -sSIL`):
  ```
  https://download.microsoft.com/download/A/A/D/AAD1AA11-FF9A-4B3C-8601-054E89260B78/vs2013.5_ce_enu.iso   # Community
  https://download.microsoft.com/download/F/2/E/F2EFF589-F7D7-478E-B3AB-15F412DA7DEB/vs2013.5_pro_enu.iso   # Professional
  ```
  Steps: download the ISO → `7z x vs2013.5_ce_enu.iso` → find the VC tool MSI(s) under `vc/` →
  extract with `msiextract` or with `wine64 msiexec /a … TARGETDIR=…` (§6.3 item 3) → keep
  `VC/` and the SDK tree, and write the environment by hand (msvc-wine's `install.sh` only knows
  the manifest-era layout): `INCLUDE=<vc>/include;<sdk>/include/...`,
  `LIB=<vc>/lib/<arch>;<sdk>/lib/<arch>/um/<arch>`, `LIBPATH`, `PATH=<vc>/bin/<hostdir>`.
  `VS2013 Update 5` is the release the community uses: `cl 18.00.40629`, `_MSC_VER 1800`.
  Then `file VC/bin/x86_amd64/cl.exe` → PE32 i386 → §6.7 applies.

For bootstrappers of these eras the alias set is live (2026-11-04, all resolve to
`download.visualstudio.microsoft.com/.../vs_BuildTools.exe`): `aka.ms/vs/15/release/vs_buildtools.exe`,
`/16/`, `/17/`. There is **no** `aka.ms/vs/18/...` alias — VS2026's installer is reached through its
own hub, which is why `--major 18` uses the `stable`/`insiders` channel words instead.

### 6.5 VS2005 – VS2012 (v80, v90, v100, v110): supply the toolchain, don't fetch it

No installer manifests, and the ISOs live behind the (paid) [Visual Studio older
downloads](https://visualstudio.microsoft.com/vs/older-downloads/) pages; GUID-shaped
`download.microsoft.com` links for them rot, so verify with `curl -sSIL` before scripting anything.
Plan for these as an **import**: get a toolchain from an install someone already made (a Windows VM,
an old CI image, an archive) and drop it in as `toolchains/msvc/<tag>/`, then set the environment
the way §6.4 describes. Expect:

| Era | toolset | `cl` | `_MSC_VER` | what the box must contain |
|---|---|---|---|---|
| VC2005 | v80 | 14.00 | 1400 | `VC/bin` is 32-bit only; x64 came from the separate "x64 & Itanium compilers" component |
| VC2008 SP1 | v90 | 15.00 | 1500 | same; the x64/IA64 compilers were a separate download |
| VS2010 | v100 | 16.00 | 1600 | `VC/bin/{amd64,amd64_x86,x86,x86_amd64}` — the amd64 ones are 64-bit binaries, so x86 *and* x64 targets run under `wine64` |
| VS2012 | v110 | 17.00 | 1700 | as VS2010 |

The practical consequence: **VS2010 is the oldest era where an amd64-host → x86-target cross
compiler (`VC/bin/amd64_x86`) is certainly present**, so x86 *and* x64 targets run under `wine64`
from there on. For VC2005/VC2008, check whether the x64 compiler package you got includes
`amd64_x86`; if it does not, an x86 target needs the 32-bit runner of §6.7. (Verify every
installation with `file` - do not trust this row.)

### 6.6 Which Windows SDK to pair with each toolset

Headers/libs are a separate asset from the compiler and are reusable across toolsets — install one
SDK per era and share it. The manifest route already picks the matching one (§6.3 table; override
with `--sdk-version 10.0.xxxx`). Older pairings: SDK 7.0/7.1 for v100, 8.0 for v110, 8.1 for v120,
and 8.1 **or** 10.0.x for v140 (the manifest route installs a 10.0.10150-era or newer one);
SDK 6.0/6.1 for v90; v80 shipped its CRT/headers inside the VC install itself. The pre-10 SDKs ship
as ISOs full of MSIs, so §6.3 item 3's extractor applies. ISO links: [Windows SDK
downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads) and the
[archive](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads-archive).
Watch the casing traps when merging trees by hand: the manifest-era layout
distinguishes `Build` from `build` (msvc-wine's `unpackWin10WDK` merges them), and `install.sh`
renames `HostX64` → `Hostx64`.

### 6.7 32-bit support: target and host are two different problems

1. **32-bit target** (`/Fo`-ing i386 code, which is what the 32-bit Windows binaries in this
   project need): no special setup from VS2010 on — `--architecture x86` (manifest route) or the
   `amd64_x86`/`Hostx64/x86` host directory (everything else). The compiler process itself is a
   64-bit binary.
2. **32-bit host tool** (VC2005/2008, and the x86-targeting `VC/bin/x86*` of VS2013 and older): the
   host must execute a PE32 (i386) process. On this machine that currently fails
   (§1: `wine64` + a 32-bit PE → `/lib/ld-linux.so.2: could not open`), so:
   - **Option A — make Wine 32-bit-capable** (needs root, and it is the fix if you also want to
     *run* 32-bit targets): install the 32-bit ELF interpreter and Wine's i386 build.
     Arch: enable `[multilib]` in `/etc/pacman.conf`, then `pacman -S lib32-glibc wine mesa`;
     Debian/Ubuntu: `dpkg --add-architecture i386 && apt install wine32 libwine:i386`;
     Fedora: `dnf install wine.i686`. Then `ldd /usr/bin/wine` must resolve
     `/lib/ld-linux.so.2`, and a **fresh prefix** (`WINEARCH=win32` or a WoW64 prefix) is needed —
     an existing prefix may not gain 32-bit support in place.
   - **Option B — wibo instead of Wine for 32-bit host tools.** [`decompals/wibo`](https://github.com/decompals/wibo)
     is a static single-binary PE loader (no prefix, no 32-bit Linux libraries, ~0 startup cost,
     which is why the decomp.me crowd uses it). Releases ship `wibo-x86_64` (Linux x86-64) and
     1.2.0 is current (2026-07); 64-bit host support is still the `winoah64` experimental line.
     For exactly our use case there is an open PR, [decompals/wibo#127](https://github.com/decompals/wibo/pull/127),
     that runs the **VS2013 Update 5 `VC/bin/x86_amd64/cl.exe` + `ml64.exe` toolchain byte-identically
     to native**, and its commit messages are the checklist of what to expect: the toolchain's own
     `msvcr120.dll` must be present and shipped alongside, `GetModuleHandleEx(…FROM_ADDRESS)` and
     the `1033\clui.dll` resource lookup must work, the guest must report Windows **6.1** (a 6.2
     report sends VS2013's c1.dll down a path that dead-ends on `Z:`-mapped volumes), and
     `cl.exe`'s c2.dll parallel codegen stresses locks/TLS hard.
   - Verify either option with the probe that cost us the discovery in the first place:
     ```sh
     i686-w64-mingw32-g++ -o /tmp/h32.exe -x c++ - <<'C'
     #include <stdio.h>
     int main(){printf("hello32\n");return 3;}
     C
     wine64 /tmp/h32.exe; echo "exit=$?"      # must print hello32
     ```
     (the 64-bit twin with `x86_64-w64-mingw32-g++` is the baseline — it passes here.)

### 6.8 Verifying a toolset after install (the probe every one must pass)

Never record a toolchain's identity from its directory name; ask the compiler. Put this next to the
toolchain as `msvc-probe.cpp` and compile it with each variant:

```cpp
#include <vector>          // proves the STL/SDK include path - the failure clang-cl hit here
#include <cstdio>
int main(){ printf("_MSC_VER=%d _MSC_FULL_VER=%d\n", _MSC_VER, _MSC_FULL_VER); }
```

Steps, for `<arch>` in `x86 x64` (both must pass for a toolset to back a variant of that arch):

1. `bin/<arch>/cl` banner prints `Version 19.xx.yyyy.z` → compare with the toolset `detect`
   reported for the target (Rich build id ↔ `cl` build: the probe target's 25711 is a 14.12-era
   build, `Docs/MSVC-Plan.md` §2).
2. compile + `link` a console exe, `/Z7`, and run it (x64 under `wine64`, i386 per §6.7) — a
   compile that links but cannot run is still broken for `try`.
3. print `_MSC_VER`/`_MSC_FULL_VER` from the probe; record it as the variant's identity.
4. the same probe compiled twice must produce byte-identical `.obj` files (`/Brepro`, or `/FR` off) —
   otherwise the refine loop's diffs are noise.

### 6.9 Not done yet (tool-side; these are the follow-ups, not part of setup)

* `.gitignore` must keep `toolchains/` and `.wine/` out of the repo (the toolchain is a
  downloaded, non-redistributable asset — Microsoft's licence is accepted per download, never
  bundled; `--accept-license` stays explicit).
* A `scripts/setup-msvc.sh` (or `decomp setup-msvc`) wrapping §6.1 + §6.3/§6.4 + §6.8, with
  `--vs/--msvc-version/--architectures` for the manifest route and `--from-existing <dir>` for the
  import route (§6.5), and no implicit download without `--accept-license`.
* `[msvc]` in `project.toml` next to `[ghidra]`: toolchain dir, expected `cl` version, target arch;
  and `[variants.msvc-v141-x86]` with `compiler = "cl"` resolved through the wrapper — today
  `cli.py` maps the `msvc` family to a bare `cl` on `PATH` (`Docs/MSVC-Plan.md` §1).
* All Windows path translation in one place (`decomp/toolchain.py`): run `cl` from the source
  directory with relative `/Fo`/`/I`, convert unavoidable absolute paths with `winepath -w`, and
  normalise diagnostics the way msvc-wine's wrappers do (strip `\r`, rewrite `z:\...`) —
  `compile.py` promises diagnostics verbatim, and that promise only holds if this is centralised.
* `decomp check` must report: the toolchain dir exists, the `cl` banner, whether a 32-bit host PE
  runs at all (§6.7), and that `#include <vector>` compiles — the last one is what catches a
  headers-without-compiler setup.
