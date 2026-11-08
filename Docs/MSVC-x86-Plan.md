# 32-bit MSVC targets: bringing a 32-bit `cl` up to the `-m32` path

Date of the measurement this rests on: **2026-11-07**. Everything in §2 and §3 below was run on
this machine on that date; the code references are to the tree at that commit.

This is the 32-bit *target* track of the MSVC work. It does not replace
[MSVC-Plan.md](MSVC-Plan.md): MS-0…MS-5 are done and are about PE/COFF/`cl` in general, and every
one of them was measured at `x86-64`. Phases here are numbered **`X86-*`** so they renumber
nothing — not Design-Plan's Phases 1-7, not MSVC-Plan's MS-*.

---

## 1. The question, and the answer as measured

The operator asked whether 32-bit MSVC is behind 32-bit GCC *because no 32-bit MSVC compiler is
installed*, plus the other reasons found in an earlier session. The honest answer is **no, not only
that** — there are five separable causes, and one of them is a ceiling the two 32-bit paths share.

Short version: **reading** a 32-bit binary is bitness-aware everywhere in the tool. **Matching** one
is only implemented for GCC. A 32-bit MSVC target can be analysed, identified, and described; it
cannot be matched, because nothing in the candidate path can produce 32-bit COFF, and nothing in the
flag-inference path can describe an i386 MSVC body.

## 2. What 32-bit support is today, stated plainly

Reading a 32-bit binary works. Matching one exists for GCC only. Per command, on a 32-bit target:

| command | 32-bit GCC (`-m32`) | 32-bit MSVC (`cl` x86) |
|---|---|---|
| `analyze` / `find` / `show` / `status` | works (`x86:LE:32:default`, the ret-cut unit situation) | works — `deadrising2.exe` is analysed and listed |
| `types` (structure recovery) | works (Design-Plan Phase 4; `this` from `8(%ebp)`) | works (MSVC-Plan MS-5: RTTI in absolute 4-byte addresses, `this` from `%ecx`, 769 classes in the game) |
| `detect` | works | works **except** the `-O` inference: the x64 MSVC feature set reads zeros, and it refuses to probe ("cl is not installed here"). **Since X86-5 (same day):** that half works too — a PE32 is probed with the driver that emits i386 code (`[msvc] prefix`/`arch` resolves it, and the report names it), scored on an i386 feature set measured on that `cl` (the x64 set reads 0.000 here, which is now asserted), with the ret-cut sample's weakness and the toolset-era gap stated *inside* the answer |
| `check` | the variant, its arch and the compiler agree | *was:* reports no `cl`, or the x64 one; `msvc_sdk()` called the SDK complete because it looked at x64 paths only. **Since X86-0 (2026-11-07):** an installed-but-off-PATH toolchain is found and named as that, `msvc target x64` / `msvc target x86` state the bitness each installed toolchain can produce, `msvc_sdk(arch=…)` answers per arch, and an `arch = "x86"` MSVC variant is named before any work starts. **Since X86-1 (same day):** both rows say `ok can build x86 candidates` — the 32-bit target toolset is installed, so the report's remaining MSVC gap is tool-side, not machine-side. **Since X86-2:** the `compiler msvc-*` rows report the driver the variant resolves to (with its bitness and why), so an installed toolchain is `ok` with no `cl` on PATH, and the `arch <variant>` row is the resolver's own sentence — `check` and `try` cannot disagree |
| `try` | works, and is gated (a `MIN_EXACT` floor of 59 in `check_masked_bytes.py`) | **the driver exists and is now chosen**: since X86-1 the machine can produce 32-bit COFF, and since X86-2 (2026-11-07) `arch = "x86"` resolves to `bin/x86/cl`, whose object measures 32-bit, with no `-m32`/`/arch:IA32` in its flags. **Since X86-3 (same day)** there is something to score: `msvc-o0-x86` builds, is analysed and is read — 89/89 extents agree and `check_msvc_x86_candidate.py` holds the first floor (mean 99.75 %, 66/89 past the gate); the 23 that stop at `structural` do so for two reasons that are not i386 reading (naming, and the X86-6 operand shape) |
| `link` (whole-program, Phase 6) | tested on 64-bit ELF only (`check_phase6_link.py` measures `gcc-o0`); a 32-bit ELF relink is untested | untested for a 32-bit PE. Two of the three things it needed are done — i386 relocation reading (X86-3) and a link that can be run (X86-4, Setup.md §6.7 Option B: wibo runs a 32-bit PE here) — what remains is the x86 link form in `relink` |

The four "32-bit" things people mean, and their state:

| thing | state | evidence |
|---|---|---|
| reading a 32-bit file | **works** | `extract._bits_of` (extract.py:137) reads ELF `identity_class` and the COFF/PE `machine`; `deadrising2.exe` reports `PE I386 32-bit`; capstone decodes it; `normalize`'s slot and register patterns are `%(?:r|e)bp`-aware |
| structure recovery, 32-bit MSVC | **works** | `structures.Recovery` seeds `this` from `%ecx` at `bits == 32` (structures.py:1205-1213), tracks frame slots per frame register, and reads MSVC RTTI in "absolute 4-byte addresses" mode — 769 classes out of `deadrising2.exe` (MSVC-Plan MS-5) |
| matching a 32-bit **GCC** build | **works, at a known ceiling** | `gcc-o0-x86` is a first-class variant and a first-class gate: `check_analysis_cache.py`, `check_diff_accounting.py`, `check_gate_tiers.py`, `check_phase2_try.py`, and `check_masked_bytes.py` with a `MIN_EXACT` floor of 59. Tests/README.md records the ceiling: *"‑m32 normalisation is weak (87% ceiling)"* |
| matching a 32-bit **MSVC** build | **not implemented** | there is no `msvc-*-x86` variant or build anywhere; `check_coff_candidate.py` gates 89/89 at `msvc-o0` **x64 only**; `probe_signatures` refuses `bits != 64` for an MSVC driver (toolchain.py:1333) |

## 3. The failure chain, run end to end

`decomp detect` on a real 32-bit MSVC target, then `decomp try` with the config `detect --write`
produces for it. Reproduce with:

```
.venv/bin/python -m decomp detect Tests/Proprietary/deadrising2.exe
```

What comes back, and where it stops:

* `deadrising2.exe` is identified correctly: `PE I386 32-bit`, `built by msvc`, `MSVC link.exe 8.0`
  (with the honest note that the Rich header has no toolset table entry for that era, so the
  toolset comes from the optional header alone), the PDB GUID/age and the symbol-server URL, and
  `abi = MSVC CRT (no CRT DLL is imported: the CRT is in the file (/MT))`. `/guard:cf` is refused
  as x64-only. `/GS-` is claimed from shape. That half is in good shape.
* The shape block reads the x64 feature set against i386 code and gets nothing: `rspmem 0.000`,
  `argstore 0.000`, `gs 0.000` (only `calls 0.037` and `xmm 0.091` are non-zero, and those two are
  the features that mean the same thing on both ABIs). It samples `1515 bodies, cut at every ret`,
  because a 32-bit image has no function table to sample.
* It ends: `note: cl is not installed here - no probe for it, so no -O inference`.
* A config written from that note (`detect --write /tmp/dr2.toml`) is itself named
  `[variants.msvc-o0-x86]` and carries `compiler = "cl"`, `optimize = 0`, `arch = "x86"`
  (`starter_config`, toolchain.py:1110) — the variant name X86-4 adds is the one `detect` already
  picks. Its header comment says "Build a candidate with a `cl` of that era: … (this one is
  `--major 15 --msvc-version 15.5`)", i.e. it asks for a v141 compiler for a `link.exe 8.0` file
  (§8's era trap). Feeding that variant through the build path, measured:

  ```
  build_flags({'compiler': 'cl', 'optimize': 0, 'arch': 'x86', 'crt': 'mt'})
    -> ['/arch:IA32', '/std:c++17', '/Od', '/W3', '/EHsc', '/nologo', '/MT']
  build_flags({'compiler': '…/toolchains/msvc/bin/x86/cl', 'arch': 'x86'})
    -> ['-std=c++17', '-O0', '-Wall', '-Wextra', '-m32']
  ```

  The first asks for `/arch:IA32`, which is not a bitness switch (it disables SSE); the second is
  the same variant with the driver named by path and is compiled as **GCC**, with `-m32`. Neither is
  the flag set of a 32-bit MSVC build, and the second is not even the right *compiler*.
* What the CLI would then do, read off the code (not run to completion here, because no x86 driver
  is installed to ask): `cli` resolves an `msvc` family to a bare `cl` on `PATH` (cli.py:603) —
  which is whatever era is installed, never the x86 one, because there is none — and the object that
  comes back is refused by the bitness check (cli.py:1108): "the candidate object is 64-bit … but
  the analysis of this target is x86:32". With `cl` off `PATH` entirely, it stops earlier with
  `compiler 'cl' not found`.

The bitness check is the only thing in the chain that behaves correctly, and its message describes a
symptom: nothing upstream was ever asked to produce 32-bit code.

## 4. The five causes, named

1. **The machine had no 32-bit target toolset.** *(Closed by X86-1, 2026-11-07 — the tree now has
   `bin/Hostx64/{x64,x86}` and `lib/{x64,x86}`, the installer takes `--architecture x86 x64`, and
   `bin/x86/cl` exists. The paragraph is kept as the measurement the phase was written from.)*
   The installed v141 tree has
   `VC/Tools/MSVC/14.12.25827/bin/Hostx64/x64` and `lib/{x64,onecore}` only, and the wrappers are
   `toolchains/msvc/bin/x64`. `toolchains/install_msvc.py` hard-wires `--host-arch x64
   --architecture x64` (line 196) and its `KEEP` (line 57) admits `crt.(headers|source|x64.*
   .desktop)` but no `x86` CRT. The packages are in the manifest this install already used:
   `Microsoft.VisualC.14.12.Tools.HostX64.TargetX86` and `Microsoft.VisualC.14.12.CRT.x86.Desktop`
   / `.CRT.x86.OneCore.Desktop` are all present in `toolchains/15.9.84.manifest`. **Compiling
   32-bit needs no 32-bit Wine** — an x64-host `cl` emits i386 code (Setup.md §6.7 item 1). Only
   *running* a 32-bit PE needs §6.7's Option A or wibo.
2. **`arch` is a config string, not a machine fact.** `toolchain.msvc()` (toolchain.py:33) matches
   a bare `cl`/`cl.exe` name only, so a path-named driver is treated as GCC; nothing resolves
   `arch = "x86"` to `bin/x86/cl`; and `Tests/eval.py:98` has its own copy of the flag rule which
   turns `arch = "x86"` into `-m32` for every non-MSVC-name driver. Two places, already divergent.
3. **The MSVC shape profile was x64-shaped.** *(Closed by X86-5, 2026-11-07 — `FEATURES_MSVC_I386`
   and the i386 /GS reading are measured on this `cl`, `feature_family` is bitness-aware, and the
   probe runs on the driver the target's bitness asks for. The paragraph is kept as the measurement
   the phase was written from.)*
   `FEATURES_MSVC` (toolchain.py:1215) is `rspmem`,
   `argstore`, `gs` — locals off `%rsp`, parameters written to the 32-byte shadow space, the cookie
   xor-ed with `%rsp`. All three are properties of the Microsoft **x64** ABI and are identically
   zero on i386 code, which is what §3 measured.
4. **COFF i386 has not been read.** `_COFF_FIELD_WIDTH` (extract.py:44) names `ABSOLUTE`,
   `ADDR32(NB)`, `REL32`, `DIR64`, and the `AMD64_*` spellings — the i386 spellings LIEF emits are
   absent. Note that the *ELF* table right below it (extract.py:55) already carries the i386
   `R_386_*` widths, so the format work is one table and one test, not a redesign.
5. **The shared i386 ceiling.** Tests/README.md's known gap is the one both 32-bit paths inherit:
   *"‑m32 normalisation is weak (87% ceiling): 32-bit addressing forms (`movl 0x804a2c4`,
   `$displ,%eax` + `R_386_*`) are not all mapped to names. x86 is **not** a stand-in for MSVC"*.
   Any 32-bit MSVC target starts under that ceiling. This is also why the fix is worth doing: it
   lifts `gcc-o0-x86` at the same time.

Plus one reporting bug that is not a cause but should be fixed with X86-5: for an MSVC file the
fidelity block offers `-fstack-protector` (a GCC flag) as the finding — see the `deadrising2`
output above, which says `/GS-` two lines earlier and `-fstack-protector` in the flags list.
*(Closed by X86-5: an MSVC file gets a `/GS` finding; the x86-64 ISA spellings are behind a bitness
guard; the x86-64/x86 dialect of every finding is chosen from `note["compiler"]` and
`note["bits"]`.)*

## 5. The bar this plan is aiming at

"On par with the 32-bit GCC path" means these five claims are true and asserted by a script:

1. `Tests/build/msvc-o0-x86` exists and `Tests/eval.py build/selfcheck --variant msvc-o0-x86`
   reports its unit count, its unresolved count, and 0 selfcheck failures, with the unit source
   named.
2. `decomp try` on that target against a `cl`-built i386 candidate reaches a **comparison** — the
   bitness check never fires, because the right compiler was chosen.
3. A gate script scores every unit of that variant, with a `MIN_EXACT` floor recorded in it and in
   Tests/README.md, the way `gcc-o0-x86` has one.
4. `decomp detect` on a 32-bit MSVC target either answers `-O` or refuses **with a reason**, and the
   feature readings it prints are non-zero for i386 shapes (i.e. the profile measures something).
   *Done by X86-5 and asserted by `check_msvc_detect.py` group 7; the known-answer case — the
   `/Od` benchmark build detected as `/Od` — is in that group too.*
5. Nothing that the x64 MSVC path or the `-m32` GCC path asserts today moves (see §7).

What this plan does **not** aim at: matching a 32-bit MSVC target at `/O1` or `/O2`; matching a
shipped 32-bit game binary byte-for-byte; running a 32-bit PE; or pretending the 87% `-m32` ceiling
is gone.

---

## 6. Phases

Each phase is independently useful, each has a check in `Tests/tools/` in the style of the existing
scripts, and each says what it refuses to claim.

**X86-0: ask the machine what it has, per target arch.** *No new capability; new honesty.*

`check.msvc_sdk()` builds its wanted list from hardcoded x64 paths —
`Lib/<sdk>/ucrt/x64/libucrt.lib` and `Lib/<sdk>/um/x64/kernel32.lib` (check.py:467-468) — so it
reports the SDK complete while no x86 CRT import library exists, and nothing anywhere reports that
no x86-target `cl` exists.

* `msvc_sdk(arch=…)` takes the arch, and `msvc_tools()` reports, per target arch: whether
  `VC/Tools/MSVC/<v>/bin/Host<h>/{x86,x64}/cl.exe` exists, whether the CRT import libs for that
  target exist, whether `Windows Kits/10/Lib/<v>/{ucrt,um}/x86` exist. A toolchain that can only
  do x64 says **"x64 only: no 32-bit target from this toolchain"**, and says the command that would
  add it.
* `decomp check` prints that table; a variant whose `arch` no installed driver can serve is named
  before any work starts, which is the same principle `build_mismatch` applies to compilers
  (byte-cleanup-plan Phase 7).
* Acceptance: `Tests/tools/check_msvc_x86_toolchain.py`, group 0. It is written to pass **both
  before and after X86-1** — before, by asserting that x86 is reported missing; after, by asserting
  it is reported present. That is deliberate: the claim is about the report, not about the tree.
* Not claimed: anything about code generation. This phase only makes the gap visible.

**Done 2026-11-07.** In `decomp/check.py`: `msvc_prefix()` (finds a prefix from the `cl` on PATH
or from `toolchains/`, and says which), `msvc_target_arches(prefix)` and its helpers
(`toolset_dirs`, `_arch_crt`, `_arch_sdk`, `arch_on_path`), `msvc_sdk(arch="x64")`,
`arch_bitness()` (bitness values only — `AVX2` is not one), `gcc_multilib()` (a `-m32` probe, so
a GCC x86 variant is not falsely reported as a gap) and `variant_arch_gap(variant)`, wired into
`msvc_report()` and `check_all()` as `msvc target <arch>` and `arch <variant>` items.
The bitness is read from the *directory* the `cl.exe` lives in, never from a flag (§8 first trap).

Measured on this machine, before and after the change (`toolchains/msvc`, v141 `14.12.25827`):

* `msvc_prefix()` → `toolchains/msvc`, "installed there, not on PATH". Previously the only MSVC
  line was `msvc cl … not found on PATH`, i.e. the tool claimed there was no toolchain.
* `msvc target x64` → `can build x64 candidates`, naming `VC/Tools/MSVC/14.12.25827/bin/Hostx64/x64/cl.exe`,
  `lib/x64` + `lib/onecore/x64`, the SDK's x64 libraries, and `bin/x64/cl (not on PATH)`.
* `msvc target x86` → `cannot build x86 candidates - x64 only: no 32-bit target from this toolchain`;
  the toolset CRT half is named missing (`lib/x86` does not exist at all) while **the SDK half is
  reported present**, because `Lib/10.0.19041.0/{ucrt,um}/x86` really are installed. Conflating
  those two would have been wrong twice over, and it is why `msvc_sdk()` and the toolset probe are
  separate.
* A `[variants.msvc-o0-x86] arch = "x86"` variant is named as `arch msvc-o0-x86` *before* any
  compile, naming the missing half and the install command that would add it (`--architecture x86 x64
  --host-arch x64`, then `toolchains/msvc-wine/install.sh`). `arch = "x86-64"` and `arch = "AVX2"`
  produce no gap; a `gcc` `arch = "x86"` variant produces none either, because `-m32` works here.

`Tests/tools/check_msvc_x86_toolchain.py` (group 0): 38 checks, exit 0, run twice — default shell
(`cl` off PATH) and the documented `PATH=$PWD/toolchains/msvc/bin/x64`. It measures the tree itself
and compares, so it is not tied to this machine's answer: against a synthetic prefix that has
`Hostx64/x86` + `lib/x86` + `bin/x86/cl`, the same report code prints `can build x86 candidates`,
which is what X86-1 will produce. Exit 2 when there is no toolchain to judge.

Nothing in §7 moved: `check_masked_bytes` (gcc-o0 79 exact, gcc-o2 78, **gcc-o0-x86 59** = its
floor), `check_gate_tiers`, `check_diff_accounting`, `check_phase2_try`, `check_analysis_cache`,
`check_msvc_toolchain` (its `eval.py selfcheck --variant msvc-o0` still `89 cases, 0 failures`) and
`check_msvc_detect` all exit 0. `check_coff_candidate.py` exits 1 — **and did so identically with
`decomp/check.py` stashed at HEAD**: 19 of the 89 units score 100.00 % with `bytes +0 {}` yet land
at `structural` instead of `exact`. That is a pre-existing MS-3/MS-6 question, recorded here because
X86-0 is the phase that noticed it.

Docs: Setup.md §1's tool row now states the installed state and the x64-only target set; §6.9
records what `decomp check` reports per arch; Tests/README.md gains the group-0 section and a
Known-gaps bullet saying there is no 32-bit MSVC target here, and that any future 32-bit MSVC number
belongs next to the `-m32` row (a 32-bit PE has no `.pdata` answer key).

**X86-1: put a 32-bit target compiler on the machine.** *Machine-side.*

* `install_msvc.py`: `--architecture` (repeatable) instead of the hard-wired `x64` at line 196, and
  `KEEP` extended with `crt\.(x86\.desktop|x86\.onecore\.desktop)`. The tools half already passes
  KEEP once the architecture is requested (see §4.1 for the package ids in the manifest).
* `install.sh` then generates a wrapper per target arch, so the result is `toolchains/msvc/bin/x86/cl`
  → `VC/Tools/MSVC/14.12.25827/bin/Hostx64/x86/cl.exe` (Setup.md §6.2). No 32-bit Wine involved.
* Setup.md §6.10 gains the x86 run's real numbers (package count, size delta — the x86 CRT payload
  is small next to the 485 MB v141 tree, but measure it, don't assume it), and §1's Wine row keeps
  saying what it says today: 32-bit **guests** do not run here.
* Acceptance: the Setup.md §6.8 probe at `x86` — banner, `#include <vector>` compiles, a `/MT`
  console program **links**, and the resulting `.obj` is opened by `extract.CandidateObject` as
  `machine = I386`, `bits = 32`, no error. The i386 `.exe` it links is named as unrunnable on this
  machine (Setup.md §6.7), not run.
* Not claimed: what i386 `cl` emits. Nothing about flags or -O. This phase's only output is a
  compiler that can be asked.

**Done 2026-11-07.** In `toolchains/install_msvc.py`: `--architecture` (`nargs="+"`, choices
`x86`/`x64`, default `x64` — replacing the hard-wired `"--architecture", "x64"`), a `keep_pattern(
arches)` built from the requested arches in place of the static `KEEP` regex whose CRT clause named
only `x64\.…`, `fill_missing_libs` run per arch, and a final print that names each arch's wrapper
directory. `SDK_KEEP` was not touched, and that is the point: the SDK's x86 import libraries were
installed all along (§3), so the only keep-clause that was throwing anything away was the CRT one —
`vsdownload --architecture x86 x64` had already admitted the toolset packages, and `KEEP` dropped them
before a byte was downloaded.

Measured on this machine against the saved `toolchains/15.9.84.manifest` and the existing
cache, before and after the change:

* Selection: upstream 363 → 373 packages; **pruned 11 / 513.1 MB → 15 / 580.8 MB**. The four added
  packages are exactly `Microsoft.VisualC.14.12.Tools.HostX64.TargetX86` + `.Resources` (9.2 MB) and
  `Microsoft.VisualC.14.12.CRT.x86.Desktop` / `.OneCore.Desktop` (33.1 + 25.4 MB): the two halves
  X86-0 named, and nothing else. The x64-only selection still prints 11 / 513.1 MB.
* Tree: `VC/Tools/MSVC/14.12.25827/bin/Hostx64/x86/{cl,c1,c2,link,lib,ml,dumpbin,editbin}.exe` and
  `lib/x86` exist (21.5 MB and 129 MB); the prefix went 1.1 GB → 1.4 GB. `fill_missing_libs` linked
  **23** names into `lib/x86` out of `lib/onecore/x86` in this run (the x64 install had needed the
  same for 22 names, Setup.md §6.11; both desktop CRT packages ship 30 real files, while the OneCore
  payload holds 40 names for x64 and 41 for x86). `install.sh` built
  msvctricks and generated `bin/x86/{cl,link,lib,ml,…}` — so `bin/x86/cl` → `Hostx64/x86/cl.exe`, an
  x64-hosted cross compiler, no 32-bit Wine anywhere in the path.
* The §6.8 probe at both arches: `bin/x86/cl` answers `Version 19.12.25835 … **for x86**`, the same
  version as `bin/x64/cl` (`for x64`) — one toolset, two targets, and `cl`'s own banner is what says
  it. `#include <vector>` compiles at both, a `/MT` console program links at both, and
  `extract.CandidateObject` reads the x86 `.obj` as `machine I386 / bits 32` with no error, the x64
  one as `AMD64 / 64`. Neither command line contains a bitness flag (`build_flags` for a variant that
  names no `arch`): the only difference is which `cl.exe` ran, which is §8's first trap under test
  rather than in prose. The i386 `.exe` is asserted to be a 32-bit PE and **not run** (§6.7).
* `decomp check` needed no change: `msvc target x86` moved from `warn … no 32-bit target from this
  toolchain` to `ok can build x86 candidates`, naming `Hostx64/x86/cl.exe` and `lib/x86` +
  `lib/onecore/x86`. The tree changed, and X86-0's report reads the tree.

Acceptance: `Tests/tools/check_msvc_x86_install.py` (the §6.8 probe at both arches, plus the tree
and the two banners): 25 checks, exit 0, run twice — default shell (`cl` off PATH) and the documented
`PATH=$PWD/toolchains/msvc/bin/x64`. It exits 2 on a tree without an x86 half, so it is a check and
not a record of today. `check_msvc_x86_toolchain.py` still exits 0 with the new tree — the "after
X86-1" half of its contract is now the live one.

Not moved (§7): `check_masked_bytes` (gcc-o0 79 exact / 10 structural, gcc-o2 78 / 11, **gcc-o0-x86
59** = its floor), `check_gate_tiers` (gcc-o0-x86 `{exact: 59, structural: 19, none: 11}`),
`check_diff_accounting` (285 verdicts / 36 with a difference / 17 with a differing length),
`check_phase2_try`, `check_analysis_cache` — all exit 0 with unchanged numbers.

**The two "slow" MSVC scripts: they were not slow, they were stalled (2026-11-07, same day).**
`check_msvc_detect.py` and `check_msvc_toolchain.py` had been left out of the runs above because
they "take many minutes each" and in practice never returned a status. Both causes were found and
fixed; [Setup.md §6.12](Setup.md) is the write-up, `decomp/spawn.py` is the code.

* Wine with no `WINEPREFIX` never answers: `cl /?` in the fallback `~/.wine` produced nothing at
  100 s, the same call in this repository's own `.wine` takes **0.9 s**. `spawn.wine_environment()`
  now supplies the project prefix for any command that goes through Wine (wrapper or `wine64`
  directly) when the caller set none, and says so — `decomp check` has a `wine prefix` row.
* `subprocess.run(timeout=n)` is not a deadline: CPython kills the direct child (the `bash` wrapper)
  and then waits for pipe EOF that the wrapper's `sed` jobs / `wine64` / `wineserver` keep open.
  `spawn.run()` reads both pipes in threads and `killpg`s the group at the deadline — measured:
  a `cl /?` that will never answer comes back in exactly the deadline, labelled `timed_out`.
  Every tool-side call site (`check`, `compile`, `toolchain.probe_signatures`, `fidelity`,
  `normalize.demangle`) and `Tests/eval.py` now go through it; the banner probe is bounded at 20 s
  and cached per tool path instead of fourteen nominal 120 s waits.

Re-run after that, with `PATH=$PWD/toolchains/msvc/bin/x64` and **no `WINEPREFIX` exported** — the
exact shell that used to hang — both scripts now run to completion in **~50 s each, exit 0**:
`check_msvc_toolchain.py` all four groups (identity, probe compile at /Od and /O2 with different
bytes, probe link + run under Wine, and `eval.py build` 2.5 s / `selfcheck` **89 cases, 0
failures**), `check_msvc_detect.py` all six groups (Rich toolset anchor, language/runtime, std
bounds, flags, the /Od-vs-/O1|/O2 shape probe with 3 levels measured with `cl`, the `.pdata` unit
sample, and the unchanged ELF path). `check_msvc_x86_install.py` and `check_msvc_x86_toolchain.py`
still exit 0, `check_coff_candidate.py` is unchanged (same 19-unit gate failure, and it no longer
waits out one 120 s compiler timeout per unit).

**X86-1 is therefore closed.** The machine has a 32-bit target toolset, the report says so, and the
MSVC acceptance scripts are green against it in seconds rather than never. What is left is the tool
side: X86-2.

**X86-2: make `arch` choose the driver — once.** *The unblocking phase.*

* `msvc()` matches `Path(compiler).name`, so a path-named `cl` is recognised as `cl`
  (measured: today it is handed `-m32`).
* One resolver, `toolchain.compiler_for(variant)`, used by `compile.build`, `cli`, `relink`, and
  `Tests/eval.py`. It resolves `arch` to `bin/<arch>/cl` when a toolchain prefix is known (a new
  `[msvc]` block in `project.toml`, or the existing wrapper layout), and otherwise uses what is on
  `PATH` **and prints which driver it chose and what bitness it is**. Today `cli.py:603` maps the
  family to a bare `cl`; that stays as the fallback, never as a silent decision.
* `Tests/eval.py:94-110` stops carrying its own copy of the flag rule and calls
  `build_flags`/`link_flags`. Two copies of that rule have already drifted once (MSVC-Plan MS-2);
  this is the phase where there is one.
* `/arch:IA32` is removed as the mechanism for `arch = "x86"` (toolchain.py:97-98). It is not a
  bitness switch — it disables SSE and moves the codegen off the i386 default the target has.
  `/MACHINE:X86` belongs in `link_form` only if a link needs to be told, which it does not when the
  right `cl.exe` is the one running.
* The bitness refusal at cli.py:1108 keeps existing, and stops being the first thing you find out.
  Two changes:
  * **`try` says the reason before it builds.** Today a 32-bit request against this machine either
    fails in `compile.build` with `compiler 'cl' not found` (a generic "not on PATH"), or compiles
    x64 code for nothing and is refused by the bitness check afterwards, whose message — "the
    candidate object is 64-bit … but the analysis of this target is x86:32" — describes a symptom.
    With a resolver in place, the answer is known before any compiler runs: "this variant asks for
    `arch = "x86"`; the toolchain here has `Hostx64/x64` only, so no 32-bit MSVC object can be
    built — see `decomp check` / Docs/Setup.md §6.7". Same principle as `build_mismatch`: name the
    gap before the bytes, and don't spend a compile learning it. (This is the user-facing half of
    "we can't build it": the tool should say *which* half it can't do — no such compiler, or the
    wrong one installed.)
  * The refusal itself gets a cause: "the variant says `arch = "x86"`, the driver this resolved to is
    `…/bin/x64/cl`, which produces x86-64" — for the case where a driver *does* exist but the wrong
    one was picked.
* Acceptance: `check_msvc_x86_toolchain.py` asserts `build_flags({'compiler': 'cl', 'arch': 'x86'})`
  contains no `-m32` and no `/arch:IA32`; that the resolved driver for that variant produces an
  object with `bits == 32`; that a 32-bit request with no x86 driver present names the missing
  toolchain **without invoking a compiler**; and that the 64-bit-object-against-32-bit-analysis
  refusal still fires when the driver *is* wrong (that safety net stays).
* Not claimed: that any i386 candidate is any good yet. This phase makes one possible.

**Done 2026-11-07.** `arch` is a machine fact and is read in one place now.

*`decomp/toolchain.py`.* `msvc()` matches the driver's *file name*, so `toolchains/msvc/bin/x86/cl`
is the same driver as a bare `cl` (measured before the change: a path-named `cl` was treated as a
GCC driver and built with `g++ -m32`). New `arch_bitness` (moved out of `check.py`, which now
delegates to it), `driver_bitness` — the target bitness comes from the *directory* a compiler lives
in, `<prefix>/bin/x86/cl` or `VC/Tools/MSVC/<v>/bin/Hostx64/x86/cl.exe`, after resolving symlinks —
`msvc_wrapper`, and `compiler_for(variant, *, prefix, prefix_from)` returning a `Driver` (name,
bitness, how that bitness is known, why it was chosen, a `conflict`, what was `tried`, and a `gap`).
Its order is: a driver the variant names **by path** (honoured; a contradiction with `arch` is a
warning, because the object check must stay reachable) → a `[msvc] prefix` the project pins (its
`bin/<arch>/cl`; PATH is not consulted behind a pin, because pinning is how a project names an era) →
the `cl` on PATH when its directory is the requested bitness → the installed toolchain `decomp check`
reports, named by path → otherwise a gap, in the same words `decomp check` prints for that machine.
`build_flags` no longer turns `arch = "x86"` into anything for `cl`: `/arch:IA32` is gone (a variant
that means "no SSE" can still put it in its own `cppflags`), only ISA levels produce `/arch:`, and
GCC's `-m32` is untouched.

*`decomp/config.py`* gained `msvc_prefix(cfg)` for `[msvc] prefix` (relative to the config file, like
`cache_dir`). *`decomp/compile.py`*: `build`/`link` take `variant=`/`cfg=` and resolve the driver
themselves; a refused variant returns `refused=True` with an empty command and **runs nothing**;
`Build`/`Link` carry `driver`/`arch`/`why`, and `describe()` prints them first. *`decomp/cli.py`*:
`try` and `link` pass the variant instead of a bare compiler, print the driver line, record
`driver`/`driver_arch`/`driver_from` in `try --json` next to `flags`, stop with the gap before any
compiler runs, and the bitness refusal at the object keeps working *with the cause
named*. *`decomp/check.py`*: the `compiler <name>` rows report the driver `try` would resolve to
(the two cannot disagree now), and an installed-but-off-PATH toolchain is a fact rather than a
failure; `variant_arch_gap` returns the resolver's own sentence. *`Tests/eval.py`* no longer carries
a copy of the flag rule: it calls `toolchain.build_flags`/`link_flags`/`compiler_for` (and its stale
`/FS` and whole-string `is_msvc` went with it).

Measured (`Tests/tools/check_msvc_x86_toolchain.py`, exit 0, all nine groups; and the same rules
through real argv and exit codes in `Tests/tools/check_driver_resolution_cli.py`, exit 0):
`build_flags({'compiler':'cl','arch':'x86'})` = `['/std:c++17','/Od','/W3','/EHsc','/nologo','/MT']`
— no `-m32`, no `/arch:IA32`, and identical to the x64 variant's flags, because the difference is the
driver; `arch = "x86"` resolves to `toolchains/msvc/bin/x86/cl` and the object it builds is **32-bit**
(`extract.CandidateObject.bits == 32`), while `arch = "x86-64"` resolves to `bin/x64/cl` and 64; a
variant that names `bin/x64/cl` but asks for `arch = "x86"` is honoured, warned about, and then
refused at the object with "it was built with …/bin/x64/cl, which emits 64-bit code, while this
variant asks for arch = \"x86\""; a config that pins a prefix with no x86 driver is refused with
"its arch = \"x86\" cannot be built here (toolchain at …)" and `command == []` with nothing written.
`decomp check --config Tests/project.toml` with **no `cl` on PATH** now says `compiler msvc-o0 ok —
cl -> /…/toolchains/msvc/bin/x64/cl (not on PATH; the driver is named by path)` instead of the old
`FAIL … not found on PATH` and `arch msvc-o0 … not reachable`.

Not moved: `Tests/eval.py build --variant msvc-o0` still produces byte-identical code — `.text` is
`133904` bytes with md5 `1e773b94118b0360ae5deaf23c68f948`, the same as before the flag rule was
shared, and the answer key is still 89 units / selfcheck 89 cases. The `detect` probe driver is
untouched (X86-5).

Next: X86-3 (reading i386 COFF) and X86-4 (an `msvc-o0-x86` benchmark variant, which is where these
drivers get scored).

**X86-3: read COFF the way i386 spells it.** *MS-3's sibling.*

* `_COFF_FIELD_WIDTH`: `I386_DIR32`, `I386_DIR32NB`, `I386_REL32`, `I386_SECREL`, `I386_SECTION`,
  `I386_SECTIONOFFSET`, `I386_IMM`, `I386_HIGH`, plus LIEF's spelling of the same. One table
  (extract.py:44), next to the ELF one that already has the i386 widths.
* **i386 has no pc-relative data reference.** A reference to anything outside the body is an
  absolute 32-bit field with a `DIR32`, not a `REL32`. So `pc_relative()`/`pc_bias()`
  (extract.py:80-89) must not bias one, and `normalize.field_span`/`position_dependent` must treat a
  `[disp32]` memory operand and a `movl $disp32` immediate as the two shapes of the same thing —
  which the ELF side already models ("in a non‑PIE 32-bit object `pushl $0` is
  `pushl $_ZTI14CVehicleEntity` with an `R_386_32` sitting on the four bytes", normalize.py:632,
  867). Get this wrong and every data reference on both sides is shifted by the instruction length.
  The same rule read the other way, so it is not "any relocation on an operand names a data object":
  on x86-64 a `call`/`jmp` displacement carries an `R_X86_64_PC32`/`PLT32` and binds to a **function**,
  which is correct and must stay that way when the i386 forms are added.
* **Extents: measure, do not assume.** Whether `cl /Od` for x86 puts each function in its own
  `.text$mn` (i.e. whether `/Gy` is on by default there) decides whether MS-3's exact-COMDAT path or
  its "next function symbol minus the `int 3`/`nop` run" fallback applies. Both are already written
  and both are bitness-neutral; what is missing is the measurement, and `check_coff_candidate.py`'s
  group 1 — *for every unit, the extent read out of the `.obj` equals the extent the original side
  compares* — is the assertion to re-run at x86.
* **There is no `.pdata` here.** The x64 unwind directory does not exist for x86 except for EH
  code, so `extract.TargetImage._read_function_table` finds nothing and MS-1's compiler-authored
  unit table — the thing that fixed 12 split bodies on `notepad.exe` — is not available. This is
  exactly the situation `gcc-o0-x86` is in, and it is why an x86 MSVC number is comparable to the
  `-m32` numbers and not to `msvc-o0`'s.
* Acceptance: a new script `Tests/tools/check_msvc_x86_candidate.py` (the x64 script is already
  89/89 and should not be perturbed by adding a second arch to it), group 1 = extent equality for
  every unit, group 2 = scores, group 3 = the wrong candidates of
  `Tests/examples/candidate_math_bad.cpp` still reported as the kind of wrong they are.
* Not claimed: a `MIN_EXACT` floor before the first run. The floor is set *from* that run, in the
  same commit that records the number, as Phase 3 of the byte-cleanup plan did.

**Done 2026-11-07.** i386 COFF is read, and an i386 candidate is scored.

*`decomp/extract.py`.* One table: `_COFF_FIELD_WIDTH` gained the `IMAGE_REL_I386_*` names **as LIEF
spells them** (`I386_DIR32`, `I386_REL32`, `I386_DIR32NB`, `I386_SECREL`, `I386_SECREL7`, …),
because `relocation_width` keys on the part after the last `.` and an entry called `DIR32` would
never match `TYPE.I386_DIR32`. Measured on a `cl /Od` object of this benchmark: it emits
`TYPE.I386_DIR32` (400 records) and `TYPE.I386_REL32` (384) and nothing else, and **LIEF reports a
record `size` of 0 for every one of them**, so that table is the only source of a field width there.
Before: 0 of the 784 relocations in that object had a known width — every candidate reference lost
its offset, every link-filled field was *compared* instead of masked, and every unit carried an
"unknown field width" warning. After: 784 of 784.

Nothing else in the reader needed changing, and that was the question this phase asked:

* **The pc rule.** `reference()` already passes no bias for a COFF record; now both directions of the
  rule are asserted instead of assumed — an `I386_DIR32` is never classed as pc-relative, and an
  x86-64 `R_X86_64_PC32`/`PLT32` on a call keeps its `+4`. The two i386 spellings of one thing, a
  `[disp32]` memory operand and a relocated `$disp32` immediate, are found at the same offset at the
  same width (`field_span` = `(1, 4)` on both) and hidden by the same rule, while an *unresolved*
  immediate stays a constant — which is what keeps the rule from hiding everything.
* **Extents: measured, not assumed.** `cl /Od` for x86 does **not** put each function in its own
  COMDAT: one `.text$mn` (characteristics `0x60500020`, no `IMAGE_SCN_LNK_COMDAT`) holds 44 of
  `math.cpp`'s 84 functions, 5 are their own `.text$mn` COMDAT, and the rest are bounded by the next
  function symbol with the `int 3`/`nop` run cut off. The x64 object of the same source has the same
  shape, so MS-3's symbol-spacing path — not its exact-COMDAT one — is the live one on both arches.
  It is exact here: **89/89 units' candidate extent equals the extent the original side is compared
  over**, with no new extent code.
* **No unit table, as expected.** An i386 image carries `.xdata$x`/`.sxdata` and no `.pdata`, so 0
  units of it come from the file's own function table and `original_function` reads the analysis'
  body. That is the `gcc-o0-x86` situation, and why these numbers sit next to the `-m32` ones.

Two things the plan took as already true were not, and both stood between it and a measurement:

1. "the parser for [the map file] already exists and already knows … that `Rva+Base` is final" — it
   knew the column is final but read it as **16 hex digits**. A 32-bit link prints 8 (`004023c0`),
   so `msvc_map_names` found no rows at all and the image looked like it carried nothing.
2. `pe_symbols` *raising* on "no `.pdata`" was X86-4's item, and had to go here or nothing could be
   measured: `pe_symbols_without_unwind` builds the key from `link /MAP` with extents from symbol
   spacing and prints that it is the worse key (906 names → 89 units matched to the source markers).
   The asset came with it: `[variants.msvc-o0-x86]`, which `decomp check` reports as
   `ok cl -> toolchains/msvc/bin/x86/cl`.

Measured — `Tests/tools/check_msvc_x86_candidate.py`, exit 0 (~35 s once the target is analysed):
group 1 the field rules against one i386 object, no target needed; group 2 extents 89/89; group 3
89/89 units scored, **mean 99.75 %**, byte-identical 52, identical once the link-filled fields are
zeroed 86, tiers `{exact 66, structural 17, none 6}`, **66 past the gate**; group 4 the three wrong
candidates still reported as the kind of wrong they are (40.00 %, 38.10 %, 88.89 % with the expected
categories). The floor is taken from that run, in this commit, as the phase said it would be:
`{extents 89, pass 66, mean 99.75}`.

The 23 that stop short fall into two families, neither an i386 reading gap — both are already named
and owned elsewhere:

* 15 reach **100.00 % with identical masked bytes** but a callee neither side can name
  (`FUN_004076e0` against `?ToLowerChar@@YADD`), which caps the tier at `structural`. That is the
  PDB/ledger naming gap: the fetched `notepad.pdb`'s `S_PUB32` rows are stored and unread.
* 8 have operand differences, 7 of them one shape: the original reads `subss 0x41f488(%ecx), %xmm0`
  where the object has `subss (%ecx), %xmm0`, because in the `.obj` the base of that address is a
  relocation placeholder (0) and in the image it is the final address. The bytes are masked; the
  operand text is not. That is **X86-6**, and it is the same set of units that caps `gcc-o0-x86` —
  this phase makes that gap measurable on a second toolchain, which is what X86-6 meant by paying twice.

Not moved: `check_coff_candidate.py` (x64) is untouched and says what it said before this phase (89/89
extents, mean 100.00 %, the same 19-unit gate failure); `Tests/eval.py build --variant msvc-o0` still
writes a byte-identical answer key (md5 `d7add1c058c4e8ee544345e8eb7c22ad`) and selfcheck is 89 cases
/ 0 failures; `check_msvc_x86_toolchain.py`, `check_masked_bytes.py` and `check_phase2_try.py` exit 0.
Goldens for the new variant warn (`/lib/ld-linux.so.2: could not open` — this Wine cannot run a
32-bit image), which `crosscheck` already treats as "no goldens".

Next: X86-5 (shape/detect — independent), then X86-6, which is where those 23 units live.

**X86-4: a 32-bit MSVC reference build and its answer key.** *The test asset.*

*Closed 2026-11-07. Its variant and its answer key were pulled forward by X86-3, which cannot be
measured without a target — see that phase's Done block for the map file's pointer-size bug and the
`pe_symbols` raise. What follows is what this phase found in the asset itself, and the one thing it
said it would not attempt turning out to need no root.*

* `[variants.msvc-o0-x86]` in `Tests/project.toml` (`compiler = "cl"`, `arch = "x86"`,
  `optimize = 0`, `crt = "mt"`) with a comment saying it is the 32-bit twin of `msvc-o0` and why it
  exists.
* `eval.py`'s answer key: `pe_symbols` currently *raises* when a PE has no `.pdata` ("the answer key
  of an x64 PE is its function table", eval.py:345). For an i386 image that raise is wrong. The key
  becomes the map file `link /MAP` — the parser for which already exists and already knows that a
  "Publics by Value" row has no section-name column and that `Rva+Base` is final — with extents from
  symbol spacing. That is the worse answer and it has to be printed as such, the way the MinGW
  case prints "this PE was not built with…".
* No `strip` for a PE (already true), and `/MACHINE:X86` only if the link needs it.
* Goldens need *running* the 32-bit program, which this machine cannot do. `eval.py build` already
  treats a missing golden set as a warning rather than a failure, and `crosscheck` reports "no
  goldens" — so state it and move on; X86-6/§8 covers what it would take.
* Acceptance: `eval.py build --variant msvc-o0-x86` prints the unit count and where each extent
  came from; `selfcheck` reports 89 cases, 0 failures; the x64 variants' answer keys are unchanged.

**Done 2026-11-07.** The reference build, its answer key, and the question of running it. Three
things were wrong with the asset, all found by measuring it rather than by reading the code that
produces it; and the thing this phase refused to attempt turned out to need no root.

*One directory, one program.* `link` appends `.exe` to an extension-less `/Fe:` target, and the
rename guard in `cmd_build` is `if not binary.exists()` — so on any **second** build of a PE variant
the fresh link became `da_tests.exe`, the previous build's `da_tests` stayed, and everything after
the link (the strip copy, the answer key, the analysis, every score) read the **old** program while
the `da_tests.map` beside it described the new one. Measured: `Tests/build/{msvc-o0,msvc-o2,mingw-o0,
msvc-o0-x86}` each held a `da_tests` dated 2026-11-04 beside a fresh `da_tests.exe`/`da_tests.map`,
different md5s. Nothing noticed, because the only consistency check in that function is the
after-strip `.text` comparison — and a PE is not stripped, so it compares a file against its own
copy. Now the previous `da_tests`, `da_tests.exe` and `da_tests.map` are unlinked before linking,
and the build refuses if the map's own `Timestamp is …` header does not equal the image's
`TimeDateStamp`: that is the proof the map belongs to those bytes, and it costs one read.

*The answer key says where its extents came from.* Every entry the key is built from carries the
basis of its own extent, and `eval.py build` prints the tally under the count instead of leaving a
note two screens earlier: `answer key: 89 units …` then
`extents: 89 of 89 units came from a link /MAP name bounded by the next name (this PE carries no
function table)`. `build.json` records the same tally as `answer_key_extents`. Measured per variant
here: `msvc-o0-x86` 89 map+spacing, 0 from a function table; `msvc-o0` 77 `.pdata` + 12
next-boundary; `msvc-o2` 33 + 56 — more of this benchmark is a leaf at `/O2`, so more of it gets no
unwind record; `mingw-o0` 89 `.pdata`, and its fallback note no longer says “MSVC emits none”, which
was wrong for a GCC-built PE. The answer-key **files** are byte-identical to before the change: the
provenance is printed and recorded, not written into the key.

*No `/MACHINE:X86`, measured.* `linkflags` for `msvc-o0-x86` stay `["/SUBSYSTEM:CONSOLE"]`: every
input object is an i386 object and the linker under `Hostx64/x86` already defaults to that machine,
so a link is not told what its inputs already say. The assertion is on the file, not the flags — the
linked program is `machine 0x14c`, optional header PE32, 32-bit — with no bitness flag in either list.

*Running it: §6.7 Option B, no root.* This plan's trap said *32-bit target ≠ 32-bit guest* and that
nothing should be gated on running a 32-bit PE. Correct — and the guest half is installable without
root: [Setup.md §6.7](Setup.md) Option B, wibo. `toolchains/install_wibo.py` fetches wibo 1.2.0
(sha256 pinned in the file), runs §6.7's probe (`wibo hello32.exe -> exit 3, stdout 'hello32'`; the
probe has to be built `-static`, or wibo answers `missing import __register_frame_info`), and
installs `toolchains/wibo/wibo`. One lookup, `toolchain.wibo_path()` (`$DECOMP_WIBO` → PATH → that
path), used both by `decomp check` and by `eval.py`'s `runner()`, which prefers it for an image whose
optional header is PE32 and keeps `wine64` for PE32+. Without it `selfcheck` exits **2** naming the
option — not 1, because the reference program's expectations were not run and nothing is claimed
about them. With it: `goldens: 89 cases`, `selfcheck` → **`89 cases, 0 failures`**, and
`crosscheck: 0 differing cases across 7 variants` — the first time this benchmark can ask “is the
behaviour the same when a different compiler and bitness built the reference?” of a 32-bit MSVC
program, and the answer is yes (the two pre-existing cross-arch float differences are gcc-o0-x86's
and are still labelled expected). §1's Wine row was corrected in passing: the host's 32-bit ELF
interpreter is present now and this Wine ships no i386 guest, so that failure moved rather than went
away.

*`decomp check` keeps the two facts apart.* A `run 32-bit PE` row sits in the same block as
`msvc target x64`/`msvc target x86`: it names wibo, or an i386 Wine guest, or warns with the two
commands that fix it and the sentence “Building 32-bit code never needed either of them”. The arch
rows say what `cl` can build; that row says what this machine can execute.

Acceptance: `Tests/tools/check_msvc_x86_reference.py`, five groups, ~1 s, exit 0 (exit 2 when the
variant is not built). (1) no bitness flag in either flag list, and the image measures PE32/i386;
(2) one reference binary per directory, `.stripped` byte-identical to it, the map's stamp equal to
the image's `TimeDateStamp`, and **89/89 answer-key unit addresses inside an executable section of
that image** — the assertion the pre-X86-4 directories would have failed; (3) the recorded
provenance accounts for every unit, none of a 32-bit PE's units is claimed to come from a function
table, and `msvc-o0`/`msvc-o2` still answer from their own table (the i386 path must not become the
answer for a file that carries one); (4) `selfcheck` runs and passes, goldens exist and match the
unit count, `crosscheck` is clean — or, with no 32-bit guest installed, `selfcheck` exits 2 with the
§6.7 sentence; (5) the `run 32-bit PE` row agrees with what is installed.

Of §5's five claims: **1 is this phase** (the unit count, the extent source, 0 selfcheck failures);
2 was true after X86-2 (no bitness refusal fires — the right compiler is chosen); 3 is X86-3's gate
script and its floor, re-measured unchanged here; 5 is the regression list below; and 4 — `detect`
answering `-O` for a 32-bit MSVC file — is X86-5's, untouched by this one.

Not moved (§7), re-measured on this machine in the same session, one script at a time:

* `check_masked_bytes.py` 0 — gcc-o0 `{exact 79, structural 10}`, gcc-o2 `{78, 11}`,
  **gcc-o0-x86 59 exact = its MIN_EXACT floor**; `check_gate_tiers.py` 0 with the same three
  tier sets; `check_diff_accounting.py` 0 with `285 verdicts, 36 with a difference, 17 whose length
  differs`; `check_phase2_try.py`, `check_analysis_cache.py`, `check_phase6_link.py`,
  `check_phase3_discovery.py`, `check_phase4_evidence.py`, `check_phase4_structures.py`,
  `check_phase5_ledger.py`, `check_phase5_o2.py`, `check_pe_target.py` all 0.
* `check_coff_candidate.py` exits **1**, unchanged: 89/89 extents, 89/89 scored, **mean 100.00 %**,
  tiers `{exact 70, structural 19}`, and the same 19-unit gate failure X86-0 recorded.
  `check_msvc_detect.py` (with the documented `PATH`) 0 with its Rich pair intact (id 258 build
  25711 ↔ link.exe 14.12.25835.7) and its /Od-vs-/O1|/O2 probe unchanged; `check_msvc_toolchain.py`
  0, its `eval.py selfcheck --variant msvc-o0` still `89 cases, 0 failures`; `check_msvc_x86_install.py`,
  `check_msvc_x86_toolchain.py`, `check_driver_resolution_cli.py`, `check_phase7_fidelity.py` 0.
* `check_msvc_x86_candidate.py` 0 **against the fresh assets**: 89/89 extents, mean 99.75 %,
  `{exact 66, structural 17, none 6}`, 66 past the gate — X86-3's floors hold on a build that
describes one program.
* All seven `answer_key.json` files are byte-identical to before this phase (`msvc-o0`
  `d7add1c0…`, `msvc-o2` `26ee6b53…`, `mingw-o0` `5e160b49…`, `msvc-o0-x86` `f6876757…`), and the
  unit/`other_symbols` lists hash the same. Rebuilding a PE variant does change its *content hash*,
  so its analysis cache entry is new: re-run `decomp analyze` for a variant after rebuilding it, or
  the candidate-side checks exit 2 saying so.
* **One §7 item did move, and it is not this phase's.** `check_msvc_structures.py` now exits 1:
  its loop group asserts `STRUCT-24` (the `dynamic_cast` unit) passes the gate, and it lands at
  `structural` at 100.00 % — one unverified reference, the CRT helper `__RTDynamicCast` which the
  original side calls `FUN_14000e794` and "nothing on either side names". That is the same naming
  gap as the 19 units `check_coff_candidate.py` fails on, and it is reproducible with this phase's
  changes stashed at HEAD, so the phase did not cause it; what changed is that §7 was actually
  re-measured today, and the stale assets no longer hide which analysis a score came from. Its other
  five groups pass (769 classes recovered from `deadrising2.exe`, headers still compile).

Not claimed: any byte score — that is X86-3's, and its floors were re-measured unchanged against the
fresh assets (89/89 extents, mean 99.75 %, 66 past the gate); a `decomp link` relink of a 32-bit PE,
which is still untested; or that a 32-bit guest is required anywhere. It is a runner: the tool
analyses, matches and scores a 32-bit target without ever starting one.

**X86-5: say what an i386 MSVC build is.** *MS-4's sibling. Independent of X86-3/X86-4.*

* `probe_signatures` stops refusing `bits != 64` for an MSVC driver (toolchain.py:1333) — its
  present message, "no 32-bit x86 target from this machine's MSVC", is accurate today and becomes
  wrong the moment X86-1 lands. The probe's flags come from `build_flags` (X86-2's single source).
* **A new feature profile, measured on this `cl` at `/Od`, `/O1`, `/O2` for x86**, in the same way
  MSVC-Plan MS-4's x64 table was produced — every pattern read off the compiler's own output, and
  the table in this doc is the measurement, not a guess. What is expected, to be confirmed or
  refuted:
  * `rspmem` / `argstore` **are not features here.** There is no shadow space and no home-slot
    spill on i386; the caller pushes the arguments. A profile that keeps them will read zeros, which
    is exactly the `deadrising2` output in §3.
  * What separates `/Od` from the optimising levels on i386 is the frame: `push %ebp; mov %esp,%ebp`
    in every body at `/Od` and not in a leaf-able one at `/O1|/O2`, locals read through `N(%ebp)` on
    every use, `leave`/`pop %ebp` in the epilogue. Those are the *Itanium* features
    (`frame`/`framemem`/`leave`/`poprbp`), whose patterns are already bitness-aware
    (`%(?:r|e)bp`, toolchain.py:1165-1172). So an i386 MSVC profile is likely that set plus
    `calls`, `subrsp`, `xmm` — i.e. the MSVC-specific part of `FEATURES_MSVC` shrinks rather than
    grows. Confirm it.
  * `/GS` is neither the x64 cookie-xor-`%rsp` nor the Linux `%fs:` canary. Read what this compiler
    actually emits (an absolute slot for `_security_cookie`, the `gs:`-relative guarded-stack form, or
    a call to `__security_check_cookie`) and write that pattern. Note `_CANARY` is `%fs:|__stack_chk`
    — a pattern for a System V target — and that `deadrising2` reports `/GS-` from *shape*; if the
    game in fact guards, the pattern is what is wrong.
  * `/O1` vs `/O2` on i386 is expected to be **less** separable than on x64 (the `argstore` gap that
    did most of the x64 work is absent). Report the class and refuse to pick one, as MS-4 does for
    `notepad.exe`.
* The fidelity block must not speak one dialect to a file it identified as another: no
  `-fstack-protector` finding for a `built by msvc` file (use `/GS`), no `-march=x86-64-*` claim for
  a 32-bit image, no `.note.gnu.property` reasoning for a PE. Guard these on `note["compiler"]` and
  `note["bits"]`. Put the guard in the one place that answers "is this the toolchain that made this
  file", wherever that ends up living (`check.build_agreement`, check.py:209, and
  `fidelity.Verdict.build_mismatch` are two today) — bitness is a property of that answer, and if it
  is checked in only one of them then `check` and `try` disagree about whether a variant can match.
* Sampling is already honest about the missing table (the header says "cut at every ret"), but the
  answer has to carry the consequence: an `-O` inferred from a ret-cut sample of a file that names no
  function boundaries is weaker than MS-4's `.pdata` sample, and the output must say so in the same
  sentence, not two screens earlier.
* Acceptance: `check_msvc_detect.py` gains a 32-bit group: `detect Tests/Proprietary/deadrising2.exe
  --probe` answers an `optimize` or refuses with a stated reason; the i386 feature readings are
  non-zero; the era question is answered in the open (§8's last trap). The x64 group's numbers do
  not move.
* Not claimed: the `/O1` vs `/O2` distinction, and any `-O` answer for a file whose era differs from
  the compiler installed here (§8).

**Done 2026-11-07.** The i386 shape profile, measured; the probe driver chosen by the target's
bitness; and bitness inside the one answer that says "is this the toolchain that made this file".
What the bullets above expected, against what this `cl` produced — the table below *is* the
measurement (14.12.25835 through `toolchains/msvc/bin/x86/cl`, share of the 9 probe bodies), and
the last column is the X86-4 build, made here at `/Od`, so it is a known answer:

| feature | `/Od` | `/O1` | `/O2` | `msvc-o0-x86` (/Od, known) |
|---|---|---|---|---|
| `frame` (`push %ebp; mov %esp,%ebp`) | 1.00 | 0.22 | 0.00 | 0.75 |
| `framemem` (locals read through `%ebp`) | 0.46 | 0.11 | 0.00 | 0.31 |
| `poprbp` | 1.00 | 0.22 | 0.11 | 0.69 |
| `spill` (a store to `-N(%ebp)`) | 0.56 | 0.11 | 0.00 | 0.33 |
| `subrsp` | 0.56 | 0.11 | 0.11 | 0.36 |
| `gs_frame` (the /GS cookie xor-ed with the frame register) | 0.11 | 0.11 | 0.00 | 0.05 |
| `xmm` | 0.03 | 0.05 | 0.27 | 0.06 |
| `calls` | 0.01 | 0.01 | 0.00 | 0.05 |
| `rspmem` / `argstore` / `gs` — the x64 set | 0.00 | 0.00 | 0.00 | 0.00 |

* **Confirmed:** `rspmem`, `argstore` and the cookie-xor-`%rsp` form of `gs` are x64-ABI features.
  They read 0.000 at every level and on the real 32-bit target too, exactly as §3 measured for
  `deadrising2.exe`. They stay in `FEATURES_MSVC`, which is now the **x64** set.
* **Confirmed:** what separates the levels here is the Itanium frame set — `FEATURES_MSVC_I386` is
  `frame, framemem, poprbp, spill, subrsp, gs_frame, xmm, calls`, i.e. the MSVC-specific part
  shrank to a single new reading, as the bullet guessed. `/GS` on i386 is `_GS_XOR_FRAME`: the
  cookie comes from an absolute slot and is xor-ed with the *frame* register (`xorl %ebp, %eax`,
  or `%esp` where no frame pointer is used), stored to `-4(%ebp)`. Not `%fs:`, not the x64 form.
* **Refuted, by measurement:** two features the bullets expected to be useful. `leave` — this `cl`
  writes `popl %ebp; retl` and emits no `leave` at any level (0.000), so it is excluded from the
  set: it would add a constant to every distance. And an argument-push feature (`argpush`):
  measured 1.00/0.44/0.56 counting any `push`, and 0.11/0.00/0.00 once only pushes next to a
  `call` are counted — against 0.50 on the target. It reads what the *program* does (does it call,
  with what arguments), not what the flags did, so it is reported and not scored. `retimm`
  (`ret $N`, the callee pops) is likewise reported: 0.65 on `deadrising2.exe` against 0.12 on the
  benchmark, which is a calling-convention reading (C++ member functions), not an optimisation one.
* **`/O1` vs `/O2` is even less separable here than on x64**, as expected: on the i386 set the two
  probe profiles are **0.890** apart while `/Od` is **2.812** from `/O1`. The class machinery is
  unchanged and says so (`level_class`, and `confidence` quotes the frame readings, not `%rsp` ones
  — `_msvc_tells` is bitness-aware).
* **`probe_signatures`** no longer refuses `bits != 64` for an MSVC driver, and its flags now come
  from `build_flags` (X86-2's single source), so a probe cannot drift from what a variant would be
  built with. Nothing about bitness is in those flags, because for `cl` bitness never was a flag.
* **The probe driver.** `detect` resolves it through `toolchain.compiler_for` for the *file's*
  bitness (the X86-2 resolver), so a PE32 is probed with `toolchains/msvc/bin/x86/cl` — printed as
  `probe cl -> …/bin/x86/cl (target x86: bin/x86/cl is the directory this driver is installed for)`
  with the reason, carried in `--json` as `probe_drivers`, and used for the fidelity comparison too.
  When nothing can serve the target, the refusal is `check`'s own sentence and nothing is compiled.
* **One place, with bitness in it.** `fidelity.note_identity` carries the file's bitness (from the
  build note, and from `target_bits` in the cached analysis) and `installed_identity` carries what
  the driver's install directory says it emits; `version_agreement` answers a bitness gap
  (`what = "target bitness"`, `hard`) *before* the toolset question. `check.build_agreement`,
  `try`'s `verdict.build_mismatch` and `detect`'s fidelity block all read that one answer, so the
  disagreement §X86-5's bullet warned about cannot happen. A file whose linker has no table entry is
  now named as an era gap (`what = "toolset era"`, not `hard`) instead of "no comparison is made".
* **The dialect guards** (§4's trailing bug) are in `fidelity.flag_findings`: an MSVC file gets a
  `/GS` finding, never `-fstack-protector`; the x86-64 ISA spellings sit behind `bits == 64`. The
  `deadrising2.exe` output now says `/GS` under its own shape block and `/guard:cf is x64-only`.
* **A probe row names the compiler that answered.** The ranked `-O` rows printed `str(name)[-40:]`,
  and an absolute toolchain path sliced that way begins inside the project's own name
  (`mpileAnything/toolchains/msvc/bin/x86/cl`), which names no driver — exactly where X86-5 started
  printing absolute driver paths. `cli._driver_label` shows the path relative to the directory the
  tool is run from, or as given when it is elsewhere, and asserts nothing: group 7 opens the printed
  label and requires it to be the same file as the resolved driver.
* **Sampling, in the same sentence.** `confidence()` ends every branch with `sample_caveat()`, so a
  ret-cut sample is named in the answer itself, and `detect` names the better sample where one
  exists (`sample.hint`). The consequence is measured, not asserted away: on
  `Tests/build/msvc-o0-x86/da_tests.stripped` — built here at `/Od`, so the answer is known — a
  ret-cut sample ranks **/O1 first** (1.257 against /O0's 1.816) while saying it is a weaker sample,
  and the same file sampled from the cached analysis ranks **-O0 first and calls it `strong`**
  (1.248 against 1.776). For a 32-bit PE, the analysis *is* the only sample with real function
  boundaries: no `.pdata`, and a ret-cut stream cuts prologues off bodies. So `detect` says which
  sample it used and what that costs.
* **The era question, in the open.** `detect Tests/Proprietary/deadrising2.exe` answers
  `optimize = 2 - for the toolchain here, not the file's: the file names link.exe 8.0, which is
  outside the toolset table (v100 and newer)…` — one line, no v141 answer presented as that file's.
  `starter_config` writes the same warning in the config it produces, and keeps the
  "`--major 15 --msvc-version 15.5`" install line only for a file whose era the table can name.

**Measured (the acceptance bar).** `Tests/tools/check_msvc_detect.py` is now seven groups, 69 checks,
exit 0. The x64 group's probe shapes and `notepad.exe`'s target shape are identical to the run
before this change (0.537/1.0/0.111 and 0.118/0.037/0.156). Group 7 asserts: the x64 set reads
0.000 on i386 at every level; the i386 set separates `/Od` from `/O1|/O2` (a frame reading 78 points
wider) and `/O1` from `/O2` only by 0.890; the i386 `/GS` reading is non-zero at `/Od` and `/O1`;
the probe for a PE32 is a `bin/x86/cl` and is printed as a path that opens that driver; the shipped
32-bit target's readings are non-zero (1 515
bodies) and the era gap is inside the answer; the `/Od` benchmark build is detected as `/Od`,
`strong`, from the analysis sample; and the x64-driver-against-32-bit-file gap fires there and not
for the x86 driver. Regression, one suite at a time: `check_masked_bytes`/`check_gate_tiers`
{79,10} {78,11} {59,19,11}, `check_diff_accounting`, `check_phase2_try`, `check_analysis_cache`,
`check_phase3_discovery`, `check_phase4_evidence` (47), `check_phase4_structures`,
`check_phase5_ledger` (55), `check_phase5_o2`, `check_phase6_link` (43), `check_phase7_fidelity`
(56, unchanged), `check_pe_target`, `check_driver_resolution_cli`, `check_msvc_toolchain`,
`check_msvc_x86_toolchain`, `check_msvc_x86_install`, `check_msvc_x86_candidate` (89/89 · 99.75 % ·
66 past the gate) all rc=0; `check_coff_candidate`'s 19 unnamed units and `check_msvc_structures`'
STRUCT-24 are the same two known failures as before this work.

Not claimed here either: an `/O1`-vs-`/O2` answer on i386 (measured 0.890 apart, reported as a
class), any `-O` that belongs to `deadrising2`'s own era, or any movement in the X86-6 ceiling.

**X86-6: the i386 normalisation both 32-bit paths share.** *The phase that pays twice.*

This is the ceiling §4.5 describes, and it is the difference between an x86 MSVC variant that
"works" and one that is useful. Nothing here is MSVC-specific; it is listed last only because it is
the largest and the least certain.

* What exists: absolute memory operands and relocated immediates are already recognised as bindable
  slots (`normalize._slots`, the `abs` and `imm` kinds, normalize.py:623-636), `R_386_*` widths are
  known, and `structures.Recovery` already resolves vtables and type descriptors by section-relative
  identity.
* What is missing is the **name at the other end** of a 32-bit absolute reference on a stripped
  target, and the pairing of a candidate-side relocation against a *section* with a target-side
  reference against a *symbol* (or nothing).
* Order, by strength of evidence: (1) bind i386 absolute operands through the data the file does
  describe — the same wiring `decomp link` needs to stop calling named data thin
  (byte-cleanup-plan Phase 6, "wiring `structures.Recovery` in is the next step"); (2) pair by
  *content* where a name is impossible — a pooled constant is comparable by width and bytes, which
  is already Phase 4's model; (3) the same rule for a COFF `DIR32` against a section on the MSVC
  side, which is why this is one phase and not two.
* Acceptance: one table in the benchmark reached two ways — by a 32-bit absolute operand on the
  target side and by a `DIR32`/`R_386_32` on the candidate side — asserted to produce the same `Ref`.
  Then re-measure `check_masked_bytes.py`'s floors for **both** `-m32` and `msvc-o0-x86` and raise
  them in the same commit that raises the numbers, with Tests/README.md's "87% ceiling" bullet
  rewritten to whatever the new number is.
* Not claimed: that the ceiling disappears. It moves, and the new number is stated.

**X86-7 (optional): a real 32-bit MSVC target used as a project.** `deadrising2` through
`starter_config` → `try` → a first scope banked. Not a byte-matching promise — a shipped Havok-heavy
game at an unknown `/O` built by a toolchain era this machine may not have (§8). It is included as
the usability check: the config `detect` writes must be the config `try` can act on.

### Dependency order

```
X86-0 (report) -> X86-1 (compiler) -> X86-2 (arch resolves the driver) -> X86-3 (read COFF i386)
                                                            \-> X86-4 (reference build + key)
                                   X86-5 (shape/detect) —— independent of 3 and 4
                                   X86-6 (normalisation) —— independent, and lifts -m32 too
```

X86-2 is the one everything else waits on: without it, an installed x86 `cl` is still not chosen by
anything, and a path-named one is compiled as GCC.

---

## 7. What must not move

Re-measure and compare before/after every phase, as the existing scripts already do:

* `gcc-o0`, `gcc-o2`, `gcc-o0-x86`: `check_masked_bytes.py` (MIN_EXACT 59 for `-m32`),
  `check_gate_tiers.py`, `check_diff_accounting.py`, `check_phase2_try.py`,
  `check_analysis_cache.py`.
* `msvc-o0` x64: `check_coff_candidate.py`'s 89 of 89 and its 100.00 % mean;
  `check_msvc_detect.py`'s x64 answers and its Rich/toolset pair (id 258 build 25835 ↔ link.exe
  14.12.25835.7); `check_msvc_structures.py`'s six groups; `check_phase7_fidelity.py`'s 56 checks.
* The ELF path keeps sampling the ret-cut stream in `target_shape`, which `check_msvc_detect.py`
  group 6 asserts directly.
* X86-5's 32-bit answers, asserted by `check_msvc_detect.py` group 7: the x64 feature set reading
  0.000 on i386 (so it cannot be reused "because it's MSVC"), the i386 set separating `/Od` from
  `/O1|/O2` while `/O1` and `/O2` stay 0.890 apart, the probe for a PE32 being a `bin/x86/cl`, and
  the X86-4 `/Od` build being detected as `/Od` (`strong`) when sampled from the cached analysis.
* The bitness refusal at cli.py:1108 stays. Making it reachable more often is the opposite of
  weakening it.

## 8. Traps, written down before the work

* **`arch` is a wish, not a fact.** `msvc()` not matching a path is the first bug; `/arch:IA32` is
  not a bitness switch; the *directory the `cl.exe` lives in* is what picks the target
  (`Hostx64/x86`). Verify with `CandidateObject.bits`, never with the flags.
* **32-bit target ≠ 32-bit guest.** The first needs nothing from Wine (Setup.md §6.7 item 1); the
  second needs Option A (root) or wibo. Do not let `decomp check` blur them, and do not gate
  anything on running a 32-bit PE. *(X86-4 installed Option B, so the question can be asked here —
  and nothing is gated on it: the `run 32-bit PE` row reports it, `selfcheck` exits 2 without one.)*
* **No `.pdata`, no compiler-authored units.** Every x64 result that leans on MS-1's unit table has
  no x86 equivalent. Compare x86 numbers to the `-m32` numbers.
* **i386 relocations are absolute.** Applying a pc bias to a `DIR32` shifts every data reference by
  the instruction length, and it will look like a *source* difference.
* **The era question for the game.** `deadrising2.exe` reports `link.exe 8.0` — a VC2005-era file,
  and the config `detect` writes for it asks for a **v141** compiler (`--major 15
  --msvc-version 15.5`), because the toolset table has no entry for that era. A v141 x86 compiler is
  *a* 32-bit MSVC compiler, not *that* one; the v80 route in Setup.md §6.5 ships an x86-only host
  `cl`, which needs §6.7's Option A or wibo. So: `deadrising2` stays the analysis/structure target it
  already is, and the *gate* for this plan is a v141-built benchmark. Naming the toolset a target
  needs, and refusing to score across that gap, is MS-4's toolset reading — not something this plan
  fixes. What X86-5 must not do is print a v141 `-O` answer as though it applied to a v80 build.
* **x86 name decoration carries the calling convention** (`?Foo@C@@QAHH@Z` thiscall, `@@SAHH`
  static, `@@YAHH` C). The decorated string stays the comparison key (MSVC-Plan §8); only display
  changes. `structures`/`normalize`'s RTTI patterns (`??_R0`, `??_7X@@6B@`) are not bitness-encoded
  and should not need touching — if they do, that is a finding.
* **Do not reuse the x64 feature set "because it's MSVC".** That is the current bug, and the §3
  output is its measurement: three zeros and one `note:`.

## 9. Explicitly not in scope

32-bit MSVC at `/O1`/`/O2` as a gated variant (measure it in X86-5, hold no number to it);
running 32-bit PE programs or behaviourals for them; ARM/ARM64X; VS2013-and-older *host* toolchains
(Setup.md §6.4/§6.5 — different phases of Setup's own list); matching `deadrising2.exe` byte for
byte; and anything that would require changing what the x64 MSVC path or the ELF path claims today.
