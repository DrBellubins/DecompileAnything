# PE / MSVC targets in `decomp`

Read this only when the target is a PE built by MSVC. Counts and versions below are a snapshot from when this was written; re-check with `decomp check` and `decomp status`.

**Consequence for the main workflow:** none different. Scope the request and score candidates
exactly as SKILL.md describes - `try` works on a PE target and a COFF candidate (since MS-3), for x64 and, since X86-0 to X86-6, for 32-bit images too (see *32-bit targets* below), and
since MS-5 `decomp types` works on a PE too: the MSVC RTTI graph is read as its own model, so a
class, its bases, its vftable and its type descriptors can be named on the target side, and a
unit that reaches one (a `dynamic_cast`) scores like any other.

## What works

- `decomp analyze`, `find`, `show` and `detect` work on a PE (x64 or i386). The reference example is `Tests/Proprietary/notepad.exe` (236 functions). `detect` names the v141 toolset from the Rich header build id, `/GL` + `/LTCG` from the debug directory, and the public PDB that holds that file's answer key.
- Since MS-4 the build report is much more specific, and its facts are worth reading before
  choosing a variant: the toolset is read from link.exe's own Rich record **and** the optional
  header (and it says whether they agree); the per-front-end compiland counts say how many C, C++
  and asm compilands the link had and how many went through `/GL`; the language is claimed from a
  decorated name and the CRT family from the imports (`/MD` vs `/MT`); `/std:` is stated as what
  that toolset bounds, never as a fact; and for a PE the `-O` shape sample walks `.pdata` units.
  If `detect` answers `/O1|/O2`, treat that as a class: try the other level before believing a
  bad score is the candidate's fault.
- `try` works on a PE target: the candidate is compiled to a `.obj` and read back with COFF
  semantics (extents derived from the object, relocations with no addend).
- `decomp types` works on a PE target (MS-5) and picks its model from the target's build note,
  not from the container: see the next section for what it can and cannot say.

## The MSVC toolchain (since MS-2)

- `cl` / `link` / `lib` / `dumpbin` **14.12.25835.7** (v141, the era `detect` names for the reference target) at `toolchains/msvc/bin/x64`, with a sibling `bin/x86` for 32-bit targets when installed. A shell needs `PATH=<that dir>:$PATH WINEPREFIX=$PWD/.wine`; `decomp` itself does not: a variant is resolved to its driver by path (see below), and the tool uses its own Wine prefix when `WINEPREFIX` is unset.
- It compiles, links and runs PE programs under Wine. `Tests/eval.py build --variant msvc-o0|msvc-o2` builds the benchmark's own test binary: 89/89 answer-key units, `selfcheck` 89 cases, 0 failures.
- `detect --probe` measures its `/Od`, `/O1`, `/O2` code shapes.
- Its `.obj` files hold one `.text$<name>` COMDAT per function **only with `/Gy`**; with the
  benchmark's flags every function shares one `.text$mn`, and a COFF symbol carries no size, so the
  extent is the next function symbol in the section minus the trailing `int 3`/`nop` padding. The
  tool derives that itself; if a report says the candidate's unit is longer than the original's by
  a dozen `int3`s, that is the tool, not the candidate.
- The candidate's name is decorated (`?AbsDiff@CMathTests@@SAHHH@Z`). `--fn` accepts the plain
  identifier (`AbsDiff`); the decorated form stays the comparison key, so do not be surprised by it
  in a report.
- A `.obj` keeps placeholder displacements where the link writes the final ones, so `bytes
  identical` is not reachable for a unit that reaches outside itself - at any `-O`, either format.
  The instruction stream and the symbol tokens are the score.
- Two argument rules: put `/link` last (everything after it goes to the linker), and put only the top source directory on the include path (a project `math.h` in an `-I` directory shadows the CRT's `<math.h>` for `cl`).
- `decomp check` identifies each tool by banner and refuses impostors (`/usr/bin/link` is GNU coreutils; `clang-cl` is clang). Read its `msvc *` rows before believing any MSVC variant is usable.

## 32-bit (i386) targets (X86-0 to X86-6)

- **Bitness is which `cl` runs, not a flag.** The wrapper directory is the target (`bin/x86/cl` vs `bin/x64/cl`; really `Hostx64/x86` vs `Hostx64/x64`). A variant's `arch` (`"x86"` or `"x86-64"`) picks the driver through one resolver shared by `try`, `link`, `detect` and `check`, so they cannot disagree about whether a variant is buildable. `/arch:IA32` is not a bitness switch and is no longer added.
- **Driver order:** a driver the variant names by path, then the toolchain `[msvc] prefix` pins in `project.toml`, then the `cl` on PATH if its directory matches the bitness, then the installed toolchain that `decomp check` reports. If none can serve the variant, the report says which half is missing and nothing is compiled. A `compiler`/`arch` disagreement on a path-named driver is a warning, and the object-level bitness check still refuses a wrong-width object.
- **`decomp check`** prints `msvc target x86` and `msvc target x64` rows (toolset `cl`, CRT libraries, SDK libraries, wrapper, on PATH or not) and a separate `run 32-bit PE` row. Building 32-bit code needs neither wibo nor an i386 Wine guest; only *running* a 32-bit PE (goldens, `eval.py selfcheck` for a 32-bit variant) does.
- **No `.pdata`.** An i386 PE carries no function table, so `analyze` reports "none" and a unit's extent is the analysis' body, or `--size`. The x64 notes under *The function table* do not apply.
- **`detect` samples differently.** With no function table the sample is the executable sections cut at every `ret`, which cuts prologues off some bodies and understates every prologue feature. `detect` says so next to the answer. After `analyze`, pass `--sample <name>` to sample the analysis' real function boundaries instead.
- **A different feature set scores `-O`.** The x64 features (`rspmem`, `argstore`, the `%rsp` form of `/GS`) read 0 on i386 at every level. A 32-bit target is scored on the `%ebp` frame, frame-slot reads, spills, `sub esp`, the frame-register form of `/GS` (`gs_frame`), `xmm` and calls. `/Od` against optimised is knowable; `/O1` against `/O2` is still a class. `ret $N` (stdcall/thiscall) and arguments pushed at call sites are reported but not scored: they describe the code, not the flags.
- **Decorated callee names.** An i386 object relocates against `@__security_check_cookie@4` where the linked image says `__security_check_cookie`; the tool strips that `@name@N` fastcall decoration on both sides, so such a callee compares by name. C++ decorations (`?Foo@@...`) are kept whole.
- **Operands that reach data.** On i386 every reference outside the body is a 4-byte absolute address, and the analysis does not always record one (`movss 0x41f488(,%eax,4)`, `movb 0x41fa74(%ecx)`). The tool resolves those operands from the file's own data sections and pairs them with the candidate's `DIR32` relocations. A `[reg + disp32]` operand is treated as a reference only when the file says that address is an object, so real field offsets are never hidden.
- **Era trap.** A file whose linker predates the toolset table (link.exe 8.0, say) names no era, and an `-O` reading taken from the v141 `cl` here describes *this* toolchain, not the file's. `detect` puts that in the answer line. Do not ask for a newer toolset than the file's; install one by version (Docs/Setup.md §6.5).
- **Unverified references.** An anonymous 32-bit global with no symbol on either side shows as `UNVERIFIED` and caps the tier at `structural`. Reproduce the object, or waive it for that target with `[gate] waive = "unverified"`.

## What a report about an MSVC target can and cannot say (MS-4)

- `/Od` against the optimising levels is knowable from the code (`cl /Od` keeps every local at
  `N(%rsp)` and writes every argument to its home slot; `/O1|/O2` do not). `/O1` against `/O2`
  is **not**: the only feature that separates them is whether `/O2` found a loop to vectorise.
  A `try` run at the wrong one of those two is not a broken candidate.
- `/GL` is said twice - the debug directory (POGO/LCTG) and the linker's own compiland records -
  and both mean the byte gate is off for that target: no single-file compile reproduces a
  link-time-regenerated image.
- `/GS` is reported from the shape (the cookie xor-ed with `%rsp`, or its check), because no
  header records it.
- At `/O2` the image's `.pdata` can name a **block** of a function rather than the function
  (hot/cold splitting, one COMDAT each), so a unit may be reported as a handful of bytes while
  the candidate holds the whole function. That is a known open gap in the tool, not a candidate
  bug - it is the 8 units `msvc-o2` does not pass.

## The C++ structure of a PE (MS-5)

`decomp types` reads MSVC's own type system. The entry point is the type-name string
(`.?AVCVehicleEntity@@` - `.?AV` class, `.?AU` union, `.?AE`/`.?AX` enum, `?$…` template); from
it the tool walks the type descriptor → the RTTICompleteObjectLocator that names it (its CHD must
carry a base-class descriptor for that same descriptor, which is what separates a locator from a
base-class descriptor) → the class hierarchy descriptor → the base-class descriptors, whose two
numbers are the subobject displacement and its vftable offset. A vftable begins after the slot
that holds a locator pointer.

What that means when you read or write a report:

- **Field widths come from the file.** x64 locators use 4-byte RVAs while vftable slots and the
  descriptor header hold absolute qwords; a 32-bit MSVC binary uses absolute 4-byte addresses
  everywhere. The tool probes and says which mode it read ("4-byte RVAs" / "absolute 4-byte
  addresses"); a claim about an offset is only as good as that probe.
- **MSVC's vtable has no offset-to-top and one destructor slot.** The benchmark's classes have 3
  slots there and 4 under g++; slot 0 is the *deleting* destructor, which writes no vptr itself -
  it calls the one that does, then frees. A derived class with nothing to clean up has a
  destructor that writes no vptr at all (`??1CVehicleEntity@@UEAA@XZ` is a stub calling the base's),
  so the evidence is a call chain, not a store.
- **Identical COMDAT folding is real and it is reported as what it is.** `??_ECVehicleEntity` and
  `??_ECCharacterEntity` are the same function referenced by two vftables, so the tool says the
  destructor slot is *shared* and refuses to name a destructor for either class. Do not "fix" that.
- **A pure slot is only claimed when `_purecall` is named**, which needs a `/MD` build. In `/MT`
  the shape (same target, two vftables, no call reaching it) is indistinguishable from a folded
  destructor - it mislabelled one, and that heuristic is gone.
- **`this` is `%rcx`** on MSVC x64 (and `%ecx` in 32-bit thiscall), and at `/Od` it is spilled to
  `8(%rsp)` and reloaded from `0x30(%rsp)` after `sub $0x28,%rsp`: a frame slot belongs to one
  stack-pointer value. Offsets through `%rbp`/`%ebp` do not move when `%rsp` does.
- **Nested names are stored innermost-first** (`.?AUSimpleMapping@hkaSkeletonMapper@@` →
  `hkaSkeletonMapper::SimpleMapping`); template names (`?$BasicArrayImplementation@E$00`) are kept
  verbatim and are *not* declarable, so they stay out of the generated header and out of base lists.
- **A PE is not an MSVC target.** A MinGW-built PE carries Itanium RTTI; the model is chosen from
  `compiler_hint` (the file's own build note) and only then from the analysis' variant, and a PE
  with neither is tried as MSVC and falls back with a note if no `.?AV` string exists.

## The function table (`.pdata`)

An **x64** PE carries the compiler's own function table in `.pdata` (an i386 PE has none; see *32-bit targets*) (186 units on the reference file) and the tool reads it:

- `analyze` caches it and prints the reconciliation with the analysis (on the reference file: 154 agree, 32 the analysis reports shorter, 35 entries the file names no unit for).
- A unit's extent is what a diff compares; `--size` still overrides it.
- `show` prints the unit, or names the gap an analysis-only function sits in.
- `find` marks analysis-only entries `<- not in .pdata`.
- Trust the unit boundary over the analysis' size; trust the analysis for instruction boundaries.
- A cache made before this feature has no unit table: `analyze --force` gives it one.

## Symbols, the match ledger and relinking

- `decomp symbols <pe>` reads the CodeView record, downloads the PDB from Microsoft's public symbol server when it publishes one, checks the GUID and TimeDateStamp, and keeps it in a symbol-store layout (`--url` prints the URL and makes no request). It needs network access.
- The match ledger (`decomp ledger`) works the same for a PE as for an ELF: a unit that passes the gate records its decorated candidate symbol, and later units are scored against it. A ledger entry is per variant, so a name proven at `/Od` says nothing about `/O2`.
- `decomp link` is ELF-only. For a PE the per-function `try` results and the ledger are the evidence.
