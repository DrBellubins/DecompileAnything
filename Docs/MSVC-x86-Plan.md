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
| `detect` | works | works **except** the `-O` inference: the x64 MSVC feature set reads zeros, and it refuses to probe ("cl is not installed here") |
| `check` | the variant, its arch and the compiler agree | reports no `cl`, or the x64 one; `msvc_sdk()` would call the SDK complete because it looks at x64 paths only |
| `try` | works, and is gated (a `MIN_EXACT` floor of 59 in `check_masked_bytes.py`) | **cannot reach a comparison** — no driver can produce 32-bit COFF, and the flag set it would use is wrong (§3) |
| `link` (whole-program, Phase 6) | tested on 64-bit ELF only (`check_phase6_link.py` measures `gcc-o0`); a 32-bit ELF relink is untested | untested for a 32-bit PE: it needs the x86 link form, i386 relocation reading, and a link that can be run |

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

1. **The machine has no 32-bit target toolset.** The installed v141 tree has
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
3. **The MSVC shape profile is x64-shaped.** `FEATURES_MSVC` (toolchain.py:1215) is `rspmem`,
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

**X86-4: a 32-bit MSVC reference build and its answer key.** *The test asset.*

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
* The bitness refusal at cli.py:1108 stays. Making it reachable more often is the opposite of
  weakening it.

## 8. Traps, written down before the work

* **`arch` is a wish, not a fact.** `msvc()` not matching a path is the first bug; `/arch:IA32` is
  not a bitness switch; the *directory the `cl.exe` lives in* is what picks the target
  (`Hostx64/x86`). Verify with `CandidateObject.bits`, never with the flags.
* **32-bit target ≠ 32-bit guest.** The first needs nothing from Wine (Setup.md §6.7 item 1); the
  second needs Option A (root) or wibo. Do not let `decomp check` blur them, and do not gate
  anything on running a 32-bit PE.
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
