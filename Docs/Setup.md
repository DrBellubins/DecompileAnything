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
| MSVC `cl` | *installed 2026-11-04 by §6.10*: `toolchains/msvc` — toolset v141 (`14.12.25827`) + Windows SDK 10.0.19041, driven through `toolchains/msvc/bin/x64/{cl,link,lib,dumpbin}` (`PATH=$PWD/toolchains/msvc/bin/x64:$PATH`, which is what the MSVC scripts set; a default shell has no `cl` and `decomp check` says so rather than saying there is no toolchain). **Target arches it can build: x64 and x86** — since the X86-1 re-run of 2026-11-07 the tree holds `bin/Hostx64/{x64,x86}` and `lib/{x64,x86}`, and the wrappers are `bin/x64/{cl,link,…}` **and** `bin/x86/{cl,link,…}`; use one at a time, because the *directory* is what picks the target (§6.2). Both `cl.exe`s print the same banner, `Version 19.12.25835`, one for x64 and one for x86. `clang-cl` is still refused as an impostor (§6.8). | real PE/MSVC targets only; **§6** gives the setup steps for every toolchain era from VS2005 to VS2026, in both 32-bit and 64-bit form ([MSVC-Plan.md](MSVC-Plan.md) §5 and phase MS-2 are the why, §6 is the how). What is and is not 32-bit-capable today, per target arch, is what `decomp check` prints (§6.9): the toolset half was closed by [MSVC-x86-Plan.md](MSVC-x86-Plan.md) X86-1 (2026-11-07), the tool half — `arch` picking that driver, reading i386 COFF — is X86-2/X86-3 |
| `objdiff-cli` | *not installed* | optional Phase 5 alternate diff backend |
| `wine` | 9.21 Staging. `wine64` runs **64-bit** PE files (`x86_64-w64-mingw32-g++` probe prints, exit 0). It cannot start a **32-bit** PE — re-measured 2026-11-07: `/lib/ld-linux.so.2: could not open`, and the reason is now the other half of what it was: the host *does* have a 32-bit ELF interpreter (`ldd /usr/bin/wine` resolves `/lib/ld-linux.so.2` → `/usr/lib/ld-linux.so.2`), but this Wine ships no i386 guest — `/usr/lib/wine` holds `x86_64-unix` and `x86_64-windows` only, and `/usr/bin/wine` itself still will not exec. Option A below fixes it with root; **Option B is installed** (`toolchains/wibo/wibo`, §6.7), which is what runs 32-bit PEs here. | running `cl.exe`/`link.exe` for MSVC targets — `wine64` is enough for every toolset from VS2015 on (they all ship an x64-hosted `cl`), and *not* enough for the 32-bit-host tools of VS2013 and older; §6.7 fixes that |

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

**Option B is installed (2026-11-07, Docs/MSVC-x86-Plan.md X86-4).** `toolchains/install_wibo.py`
fetches wibo 1.2.0 (`wibo-x86_64`, sha256 `13f86a2d…` pinned in the file — it is not the upstream
release's published checksum, it is the file this machine downloaded and tested), runs the probe
above — built `-static`, because a shared `libgcc_s_dw2-1.dll` is a DLL the guest has to be handed
separately and wibo answers `missing import __register_frame_info` without one — and installs it at
`toolchains/wibo/wibo` (gitignored, like the rest of `toolchains/`). `decomp.toolchain.wibo_path()`
is the single place that finds it (`$DECOMP_WIBO`, then PATH, then that path), used by `decomp check`
and by `Tests/eval.py`'s `runner()`, which prefers it only for an image whose optional header is
PE32 and keeps `wine64` for PE32+.

Measured here: `probe: wibo hello32.exe -> exit 3, stdout 'hello32'`; the 32-bit MSVC build of the
benchmark runs (`eval.py selfcheck --variant msvc-o0-x86` → `89 cases, 0 failures`, and its goldens
capture 89 cases); Option A is still uninstalled, and `decomp check` now says which of the two this
machine has (`run 32-bit PE`, next to the `msvc target x86` row, so the two facts cannot be quoted
as one). Nothing is *gated* on either: building a 32-bit target needs no guest at all, and a tool
that cannot run its target still analyses, matches and scores it.

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

Steps 1-3 now run at both target arches on their own, as `Tests/tools/check_msvc_x86_install.py`
(X86-1, 2026-11-07). Measured here on v141: `bin/x64/cl` and `bin/x86/cl` both print
`Version 19.12.25835`, one `for x64` and one `for x86` — one toolset, two targets, and the banner is
what says it (`cl` 19.12 is what a `14.12.25827` toolset answers, per §6.3's table); `#include
<vector>` compiles and a `/MT` console program links at both, with **no bitness flag anywhere** in
the command line, so the only thing that decides the target is which `cl.exe` ran; the `.obj`s read
back `I386/32` and `AMD64/64`. Step 2's *run* is done for x64 only — the i386 image is checked to be
a 32-bit PE and not executed (§6.7). Since X86-4 that half *could* be run here — wibo, §6.7
Option B, is what `Tests/eval.py` runs the 32-bit benchmark program through — and this script
deliberately still does not, so that it stays a check of the toolchain rather than of the guest.
Step 4 is not covered by that script.

### 6.9 Not done yet (tool-side; these are the follow-ups, not part of setup)

* `.gitignore` keeps `toolchains/` and `.wine/` out of the repo (done); the two files that drive
  the install, `toolchains/install_msvc.py` and `toolchains/msiextract.py`, are the exception and
  are committed - the toolchain is a downloaded, non-redistributable asset, the drivers are not.
* ~~A `scripts/setup-msvc.sh`~~ → `toolchains/install_msvc.py` (MS-2, 2026-11-04): it prunes the
  package selection to the toolset + SDK, puts `msiextract` on PATH (see §6.10), filters the SDK
  payload MSIs, runs `vsdownload`'s own extract/move and then `install.sh`. It has no
  `--from-existing` import path yet (§6.5) and no VS2005-2013 route (§6.4/§6.5).
* `decomp check` now reports the MSVC toolchain by banner: `cl`/`link`/`lib`/`dumpbin` versions
  and the toolset family they agree on, the impostors refused (`/usr/bin/link` = GNU coreutils,
  `clang-cl` = clang), whether the `cl` found is a Wine wrapper and whether Wine is there, and
  the state of the matching Windows SDK (`decomp/check.py`, `msvc_tools()`/`msvc_sdk()`).
  Since X86-0 (2026-11-07) it also says **which target bitness the installed toolchain can
  produce**, and finds a toolchain that is installed but off PATH:
  * `msvc_prefix()` → the prefix, plus *how* it was found (from the `cl` on PATH, or from
    `toolchains/msvc`, which is this machine's state - the old text reported "no `cl` on PATH"
    about a compiler that was sitting in the repo).
  * `msvc_target_arches(prefix)` → one `msvc target <arch>` line per arch in `x64 x86`: the
    `VC/Tools/MSVC/<v>/bin/Host<h>/<arch>/cl.exe` found, the toolset's `lib/<arch>` CRT import
    libraries, the Windows SDK's `Lib/<ver>/{ucrt,um}/<arch>`, the `<prefix>/bin/<arch>/cl`
    wrapper, and whether that wrapper is on PATH. `can_build` is all three of the first set.
    The bitness is read from the *directory*, because that is what carries it (§6.2, §6.7).
  * `msvc_sdk(arch=…)` → the same SDK question per target arch (a bare call still means x64).
    On this machine the x86 import libraries are installed and the x86 toolset half is not, so
    conflating the two would have been wrong twice over.
  * `variant_arch_gap(variant)` → a variant whose `arch` no installed driver can serve is named
    *before* any work starts (`arch <name>` in the report, a warning unless a build was asked
    for), naming which half is missing and which is present. `arch = "AVX2"` is an ISA level, not
    a bitness, and is not contradicted; a GCC `arch = "x86"` variant is named only when `-m32`
    actually fails (`gcc_multilib()`).
  What this does **not** claim: any 32-bit MSVC *compiling*.
  As of the X86-1 re-run of §6.10 (2026-11-07) that sentence only means the tool: the v141 tree now
  has `Hostx64/{x64,x86}` and `lib/{x64,x86}` and `decomp check` reports both as buildable; the
  earlier state (`Hostx64/x64` and `lib/x64` only, SDK x86 libraries present) is kept above because it
  is the example of why the answer has to be per arch. *Picking* that driver from
  `arch = "x86"` is X86-2; reading an i386 COFF object is X86-3. A 32-bit **guest** is answered since
  X86-4 (§6.7 Option B: wibo at `toolchains/wibo/wibo`, reported by `decomp check`'s
  `run 32-bit PE` row). Still not done: running a 32-bit **host** tool (VC2005/2008, or the
  `VC/bin/x86*` of VS2013 and older) — wibo starts 32-bit PE processes here now, and
  decompals/wibo#127 is the evidence that a VS2013 host `cl` can work under it, but nothing of that
  era has been measured on this machine. The `#include <vector>` probe *is* done: §6.8's steps 1-3 at
  both target arches are `Tests/tools/check_msvc_x86_install.py`.
* `[msvc]` in `project.toml` next to `[ghidra]`: **done by X86-2** — `config.msvc_prefix`, the
  `[msvc] prefix` table in `Tests/project.toml`, and `toolchain.compiler_for` resolving a variant's
  `arch` to `<prefix>/bin/<arch>/cl` by path, so neither `eval.py` nor `decomp try` needs `cl` on
  PATH. The half that is still open is the *expected `cl` version*: pinning the era `detect` found is
  MS-4's toolset reading.
* All Windows path translation in one place (`decomp/toolchain.py`): run `cl` from the source
  directory with relative `/Fo`/`/I`, convert unavoidable absolute paths with `winepath -w`, and
  normalise diagnostics the way msvc-wine's wrappers do (strip `\r`, rewrite `z:\...`) —
  `compile.py` promises diagnostics verbatim, and that promise only holds if this is centralised.
  One piece of this is done: `driver_form()` names the language for sources (`/Tp`/`/Tc`),
  because `cl` reads a bare `/home/…/x.cpp` as an option and the wrappers rewrite `/t/x…`.

### 6.10 The v141 install as it actually ran here (2026-11-04, no root)

```sh
.venv/bin/python toolchains/install_msvc.py            # --major 15 --msvc-version 15.5
.venv/bin/python toolchains/install_msvc.py --no-sdk   # the same without the Windows SDK
```

Measured, in the order it happened:

* `--msvc-version 15.5` selects `Microsoft.VisualStudio.Component.VC.Tools.14.12` in the 15.9.84
  channel and then fails on its pinned SDK: `WinSDK version 10.0.16299 not found / Available
  versions: 10.0.19041`. Pass `--sdk-version 10.0.19041` (the driver does).
* The default selection is **363 packages / 2.1 GB**; the toolset + its CRT + the SDK is
  **10 packages / 485 MB**. The IDE shell is a dependency of the toolset component in this
  manifest, so it has to be excluded by id, one `--ignore` per package - the driver computes
  that list from the selection instead of storing 351 ids.
* The toolset arrives as **Vsix** (zip) packages, extracted natively by vsdownload; only the
  Windows SDK uses MSIs. `VC/Tools/MSVC/14.12.25827/bin/Hostx64/x64/{cl,c1,c2,link,lib,dumpbin,
  ml64}.exe` was complete from those five packages, including the C++ static CRT (`libcpmt`,
  `libvcruntime`) - the `Microsoft.VisualCpp.CRT.*` (versionless, i.e. 14.16) packages are not
  needed and would add a second, newer `VC/tools/msvc` that `install.sh` prefers.
* The SDK's MSIs are the blocker: `wine64 msiexec /a pkg.msi /qn TARGETDIR=z:/abs` returns **91**
  with `err:msi:ITERATE_Actions Execution halted, action L"InstallAdminPackage" returned 1627`
  (measured on `Windows SDK EULA` and on `Universal CRT Headers Libraries and Sources`); a real
  install, `msiexec /i`, exits 0 and installs nothing. `msiextract` (msitools) is the tool
  vsdownload actually wants and it was not installable without root at the time - it is now
  installed, and §6.11 is what finishing the SDK then revealed. The 165 cabs cannot stand in:
  `7z l` shows their entries as `cat<hash>` - the file names live in each MSI's `File` table and
  the paths in its `Directory` table.
* `install.sh` refuses to build the wrappers without a `Windows Kits/10/include/10.*` directory,
  so `--no-sdk` creates an empty placeholder and says so; `decomp check` then reports
  `windows sdk FAIL ... libucrt.lib, kernel32.lib, oldnames.lib are not`.
* Use it with `PATH=$PWD/toolchains/msvc/bin/x64:$PATH WINEPREFIX=$PWD/.wine`. `WINEPREFIX` must
  be set for anything that shells out to `cl` (the wrappers otherwise use `~/.wine`). Clear a
  stuck prefix with `pkill -x wineserver` - never `pkill -f wineserver`, which matches the shell
  running that command.
* A half-initialised Wine prefix makes `msiexec` fail fast with 91; stale `wineboot.exe --init`
  processes from earlier sessions linger for days. Delete `.wine` and re-init instead of
  debugging a prefix.

* `decomp check` must report: the toolchain dir exists, the `cl` banner, whether a 32-bit host PE
  runs at all (§6.7), and that `#include <vector>` compiles — the last one is what catches a
  headers-without-compiler setup.

**The x86 target as it actually ran here (2026-11-07, X86-1).** The same command with
`--architecture x86 x64` (the default remains x64-only):

```sh
.venv/bin/python toolchains/install_msvc.py --architecture x86 x64
```

* The upstream selection barely moves (363 → 373 packages); the **pruned** one goes from
  **11 packages / 513.1 MB to 15 / 580.8 MB**. The four added packages are exactly the two halves
  X86-0 found missing: `Microsoft.VisualC.14.12.Tools.HostX64.TargetX86` (+ its `.Resources`, 9.2 MB
  of `cl`/`c1`/`c2`/`link`/`lib`/`ml`) and `Microsoft.VisualC.14.12.CRT.x86.(OneCore.)Desktop`
  (58.5 MB of import libraries). Nothing else was added — the SDK already had
  `Lib/10.0.19041.0/{ucrt,um}/x86`, which is why `SDK_KEEP` needed no x86 clause.
* `--print` answers the same question in either order (`x86 x64` and `x64 x86` both prune to 15 /
  580.8 MB), duplicates collapse, and `--architecture x86` on its own prunes to 11 / 502.4 MB, i.e.
  a 32-bit-only tree is installable — an x86 `cl` with no x64 one. Nothing recommends that: every
  existing MSVC variant here is x64.
* `keep_pattern()`'s CRT clause is what had to become arch-aware: `KEEP` admitted
  `crt\.(headers|source|x64\.(desktop|onecore\.desktop))`, so the x86 CRT packages were thrown away
  *after* `vsdownload --architecture x86 x64` had correctly admitted their toolset packages. The
  clause now names the requested arches, and `fill_missing_libs` runs per arch: 23 aliases were
  linked into `lib/x86` out of `lib/onecore/x86` in this run; the x64 directory needed the same
  treatment for 22 names when it was first installed (§6.11). Both desktop CRT packages ship 30 real
  files; it is the OneCore payload that differs between arches (40 names for x64, 41 for x86), which
  is why the two counts are not the same number.
* The tree went 1.1 GB → 1.4 GB; `VC/Tools/MSVC/14.12.25827` is 575 MB, of which `bin/Hostx64/x86`
  is 21.5 MB and `lib/x86` 129 MB. `install.sh` generated `bin/x86/{cl,link,lib,ml,…}` alongside
  `bin/x64/…`; it preserves its wrapper templates' mtimes, so every file in `bin/x86` dated the same
  as `bin/x64` — which is no evidence of anything, check the directory instead of the timestamps.
* Then §6.8 at x86, as recorded there: banner `19.12.25835 for x86`, `<vector>` compiles, `/MT`
  links, `I386/32` read back. `decomp check` went from `msvc target x86 warn - x64 only: no 32-bit
  target from this toolchain` to `msvc target x86 ok - can build x86 candidates`, naming
  `Hostx64/x86/cl.exe` for it. Acceptance: `Tests/tools/check_msvc_x86_install.py`.

### 6.11 Finishing the SDK: msitools and two package names (2026-11-04, same day)

`sudo pacman -S msitools` (msiextract 0.106) then re-running `toolchains/install_msvc.py` completed
the install: `Build msvctricks done.` from `install.sh`, `decomp check` all ok, and
`cl /MT /O2 hello.cpp` → `wine64 hello.exe` prints. Four things had to change, all measured:

* **msitools' `msiextract` is the tool vsdownload wants, and it does what Wine's `msiexec /a`
  could not**: it reads the MSI `File`/`Directory` tables itself and expands the external
  cabinets - `Universal CRT Headers Libraries and Sources` → 590 files / 284 MB in **0.85 s**, in
  the `Program Files/Windows Kits/10/...` layout `moveVCSDK` expects. `install_msvc.py` now uses
  `msiextract` from PATH when present and keeps `toolchains/msiextract.py` (the Wine shim) only as
  the fallback, printing which one it picked.
* **The desktop headers and the base import libraries are not in the payloads named "Desktop".**
  `Windows SDK Desktop Headers x64` has **3** files in its `File` table and `…Desktop Libs x64`
  has 346 - no `windows.h`, no `kernel32.lib`, no `user32.lib`, no `uuid.lib`, while `shell32.lib`
  and `Gdi32.Lib` are there. They ship in the payloads named **`Windows SDK for Windows Store Apps
  Headers` / `Libs` / `Contracts`**, which install into the same `Include/<v>/um` and
  `Lib/<v>/um/<arch>` trees (the `Libs` one is where `kernel32.Lib`, `User32.Lib`, `Uuid.Lib`,
  `WindowsApp.lib` and `OneCoreUAP*.Lib` come from). Adding those three names to the driver's
  `SDK_KEEP` took `Include/…/um` from 0 to 662 files and `Lib/…/um/x64` from 346 to 659.
* **The desktop CRT package does not ship every library `cl` auto-links.**
  `Microsoft.VisualC.14.12.CRT.x64.Desktop` holds 30 files under `lib/x64` - the static CRT, the
  concrt variants, `msvcmrt` - and every link, including msvc-wine's own `msvctricks.cpp`, stops
  at `LNK1104: cannot open file 'OLDNAMES.lib'`. `msvcrt.lib`, `msvcrtd.lib`, `oldnames.lib`,
  `msvcprt.lib`, `legacy_stdio_definitions.lib`, `vccorlib.lib`, `vcomp.lib` and the PGO/DIA libs
  are only in **`Microsoft.VisualC.14.12.CRT.x64.OneCore.Desktop`**, under `lib/onecore/x64`.
  The driver now keeps that package (11 packages / 513 MB) and links the 22 names the desktop
  directory lacks out of `lib/onecore/x64`, printing each one. Note that `oldnames.lib` is a *VC*
  library: an earlier version of `decomp check`'s SDK probe asked for it under
  `Windows Kits/10/Lib/…/um/x64`, where it has never been; the probe now asks for
  `Include/<v>/um/windows.h`, `Lib/<v>/ucrt/x64/libucrt.lib` and `Lib/<v>/um/x64/kernel32.lib`.
* **`install.sh` is not re-runnable over a partial install.** Its case-alias helper is
  `ln_s() { if [ ! -e "$2" ]; then ln -s "$1" "$2"; fi; }`; `-e` follows the link, so a *dangling*
  alias from an earlier run (which is what `MSVCRT.lib`/`OLDNAMES.lib` are when their targets were
  never shipped) passes the test and `ln -s` then fails with "File exists", which under `set -e`
  aborts the install. `install_msvc.py` prunes dangling symlinks under the prefix first and says
  what it removed.

### 6.12 A `cl` call that never comes back (2026-11-07)

`check_msvc_detect.py` and `check_msvc_toolchain.py` were being described as "slow, many minutes".
They are not slow; two separate things made a call never return, and both are now fixed in
`decomp/spawn.py`. Measured on this machine.

**1. Wine with no `WINEPREFIX` is not slow, it is stuck.** Every tool in `toolchains/msvc/bin/*`
and every built PE run under Wine needs a Windows prefix. §6 tells you to export
`WINEPREFIX=$PWD/.wine`; nothing checked it. With it unset, Wine falls back to `~/.wine`, which on
this machine is a live desktop/gaming prefix (yabridge hosts, a `winedbg --auto` from an old crash):

| what was run | result |
|---|---|
| `cl /?` with no `WINEPREFIX` | no output, no exit — stopped at a 100 s probe; the runs of 2026-11-07 that were reported as "hours per tool call" never printed a status at all |
| `cl /?` with `WINEPREFIX=$PWD/.wine` | **0.9 s** |
| `cl /?` with `WINEPREFIX=/tmp/definitely-not-a-prefix` (a prefix Wine must build from nothing) | never returns |
| `Tests/eval.py build --variant msvc-o0` with no `WINEPREFIX`, before the fix | the first `cl` hung; the goldens step hit the same wall later (`wine64 da_tests --golden`) |

So `spawn.wine_environment()` now supplies the repository's own prefix (`.wine` next to the tool, if
it looks initialised) for any command that goes through Wine — a wrapper script **or** `wine`/`wine64`
named directly, which is how a built program gets run — when the caller set none, and it says that it
did. An explicit `WINEPREFIX` always wins; nothing is set for commands that do not involve Wine.
`decomp check` has a `wine prefix` row that names which prefix is in effect, or warns that there is
none ("Wine falls back to ~/.wine, where a compiler call can hang forever").

**2. `subprocess.run(..., timeout=n)` is not a deadline.** When it fires, CPython kills the *direct*
child and calls `communicate()` again **with no timeout**. The direct child of an MSVC build is a
`bash` wrapper; behind it are `wine-msvc.sh`'s `sed` jobs over two `mkfifo`s, `wine64`, and the
`wineserver` those leave behind (see the `wineboot.exe`/`winedevice.exe` processes that outlive any
run here). Anything in that tree that inherited the capture pipe keeps it open, so the second
`communicate()` never sees EOF and the call never returns. Every timeout in the tool was therefore
nominal — and the banner probe (`check.Tool`) asks up to fourteen tools, up to three spellings each,
so fourteen nominal 120 s budgets are the "hours" that were being blamed on Ghidra.

`spawn.run()` bounds it for real, and that module is now the only way the tool or the test harness
starts a process:

* `Popen` with `start_new_session=True`, and on the deadline `os.killpg` — the wrapper, its `sed`s
  and its `wine64` all stop (a `wineserver`, which starts its own session, is left alone);
* both pipes are read by daemon threads, so a full pipe cannot deadlock and the child's exit is
  noticed even while a grandchild still holds the pipe open — the drain afterwards is bounded
  (3 s), and partial output is kept and labelled `partial`;
* measured: a `cl /?` that will never answer returns in exactly **25.0 s** at a 25 s deadline with
  `timed_out=True`, and the caller prints why (`compile.build` → "the compiler did not finish in 25s
  (cl) - <wine note>").

The effect on the scripts that were "slow" (PATH = `toolchains/msvc/bin/x64`, **no** `WINEPREFIX`
exported — the case that used to hang):

* `check_msvc_toolchain.py` → **exit 0** in ~50 s; `check_msvc_detect.py` → **exit 0** in ~50 s.
* `Tests/eval.py build --variant msvc-o0` → 2.5 s (89 units through `cl` + link + goldens); the
  `selfcheck` inside group 4 of `check_msvc_toolchain.py` is 0 s, 89 cases 0 failures.
* `decomp check -C Tests/project.toml` → 2.3 s, with the new `wine prefix` row.
* `check_coff_candidate.py` no longer waits out a single 120 s compiler timeout (its known
  pre-existing gate failure is unchanged).

`Tests/tools/check_msvc_x86_install.py` had already worked around (1) locally by setting
`os.environ["WINEPREFIX"]` from `REPO/.wine`; that is now the tool's job and the workaround is
redundant. Still open, and unaffected by this: several `Tests/tools/*.py` scripts call
`subprocess.run` directly (`check_pe_target`, `check_phase5_ledger`, `check_phase6_link`,
`check_phase7_fidelity`, `check_msvc_structures`, `check_phase4_structures`,
`check_msvc_x86_toolchain`, `check_msvc_x86_install`) — some with no timeout at all. They drive
`g++`/`objdump`/`python -m decomp` rather than Wine today, so they answer; converting them to
`decomp.spawn` is the same one-line change per call and is tracked as a follow-up.


### 6.13 Which `cl` a variant actually gets (2026-11-07, X86-2)

Nothing in this setup guide changes to make a 32-bit MSVC build work — §6.2's wrapper layout is the
whole requirement — but how the tool *finds* a driver is worth stating, because it is the difference
between "install cl" and "point the project at the toolchain".

A variant's `arch` is a machine fact, and from X86-2 on it selects the **driver**, never a flag: for
`cl`, `-m32` does not exist and `/arch:IA32` is not a bitness switch (it disables SSE). The target
bitness is decided by the directory the compiler sits in — `<prefix>/bin/x86/cl`, or the toolset's own
`VC/Tools/MSVC/<v>/bin/Hostx64/x86/cl.exe` — which is what `decomp.toolchain.driver_bitness` reads.

`decomp.toolchain.compiler_for(variant)` answers it once, in this order:

1. a driver the variant names **by path** (`[variants.*] compiler = "…/bin/x64/cl"`), honoured as
   written; if that contradicts `arch` the build warns and the object-level bitness check is what
   stops it — the safety net stays reachable on purpose;
2. a toolchain the project pins with `[msvc] prefix = "../toolchains/msvc"` in its `project.toml`
   (relative to the config file, like `cache_dir`): its `bin/<arch>/cl`. A pin is an answer about
   *that* toolchain — PATH is not consulted behind it — so a project built against one era of the
   compiler cannot drift to another by way of someone's shell;
3. the `cl` on PATH, when the directory it lives in is the bitness the variant asked for (this is
   what §6.3's `PATH=…/bin/<arch>` line is for, and it still works);
4. the installed toolchain `decomp check` reports finding — an install that is present but off PATH is
   used, and said to be used: `compiler msvc-o0 ok — cl -> /…/toolchains/msvc/bin/x64/cl (not on
   PATH; the driver is named by path)`;
5. nothing: then the answer is a sentence about which half is missing ("its arch = \"x86\" cannot be
   built here (toolchain at …): …"), and **no compiler is run** to find that out.

So the recommended setup is the one §6.2 already produces: leave `toolchains/msvc` where `install.sh`
put it and add the `[msvc]` block to the project (Tests/project.toml does). `PATH` is then only
needed for tools outside this one. `decomp check` and `decomp try` report the same driver, and
`decomp try`/`decomp link` print it before compiling:

```
driver    /home/…/toolchains/msvc/bin/x86/cl - targets x86, the toolchain installed at
          /home/…/toolchains/msvc has this target … (Docs/Setup.md §6.2)
build: ok (2.31s) -> cache/ghproj/candidates/candidate_probe.obj
```
