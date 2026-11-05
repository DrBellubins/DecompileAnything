# LLM Decompile Tool: Implementation Plan

## Goal
A Python CLI that lets an LLM decompile functions from a binary by iterating: write source, compile, diff against the original, refine until the match threshold is met.

## Required Tools

**External (non-Python)**
| Tool | Purpose |
|---|---|
| Ghidra (recent release, with PyGhidra) | Analysis, function discovery, pseudo-code, xrefs, types |
| JDK (version Ghidra requires, currently 21+) | Runs Ghidra |
| Compiler (`gcc`/`clang`, optionally MSVC `cl`) | Builds candidate source into `.o` files. `cl` is Windows-only; the two ways to have it on Linux, and what each costs, are in [Docs/MSVC-Plan.md](MSVC-Plan.md) §5 |

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

Status: **Phase 1, Phase 2 and Phase 3 are implemented.** What the commands do, the cache format, the
measured results on `Tests/`, and the open gaps are documented in [README.md](README.md). The
rest of this plan is unchanged and still authoritative for what comes next.

**Phase 1: Skeleton and analysis cache** - done, 2026-11-03
1. Set up the package, config file, and startup checks (Ghidra path, JDK, compiler).
2. `analyze`: open the binary via PyGhidra, run auto-analysis, export per function: name, address, size, bytes, instructions, resolved references, pseudo-code, and callers and callees.
3. Store in the cache so later commands never start Ghidra.

**Phase 2: Compile and diff (the core loop)** - done, 2026-11-03
1. `compile.py`: invoke the compiler with the configured flags, producing a `.o`. (Done: the
   flags come from the variant the analysis was recorded with; the compiler's diagnostics are
   returned verbatim and the object is kept for `objdump`.)
2. `extract.py`: pull the target function's bytes and relocation entries from the `.o` (LIEF),
   mapping relocations to symbol names. (Done, plus the two cases a `.o` has that a linked
   image does not: a relocation naming a *section* with the offset as its addend, and a call
   or address-of inside the same section, which needs no relocation at all.)
3. `normalize.py`: on the original side, replace call targets and global addresses with symbol
   names from the cache. Both sides now compare symbolically. (Done as one shared tokeniser:
   positional symbol tokens per side, names/bytes/sizes kept and compared, function-relative
   branch labels.)
4. `diff.py`: align instruction streams, compute a match ratio, and categorize differences
   (opcode, operand, register-only, relocation, size). (Done; `register` is reported and
   `--register-abstract` exists, but the -O2 register-allocation work stays in Phase 5.)
5. Output: match %, size delta, and the differing lines only, kept short for the LLM's
   context. (Done, plus a table of what every symbol token means on each side.)
6. Validate on one simple free function from your test program at `-O0`. (Done, and further:
   `Tests/tools/check_phase2_try.py` scores all 89 units of the benchmark through the tool's
   own path - 99.94% mean, 88/89 pass the gate at gcc -O0, above the independent harness's
   own 99.53%/83. Known gaps are named in README.md.)

**Phase 3: Discovery and compiler detection** - done, 2026-11-03
1. `toolchain.py`: detect the compiler via `.comment` (ELF) or the Rich header (PE), and write a starting `project.toml`. (Done as `decomp detect <bin> [--write path]`: `.comment`/Rich header/CodeView, the object type - PIE vs `-no-pie`, dynamic vs `-static` - the machine class, and the C++ ABI and lowest `-std` proved by `.dynstr`/`DT_NEEDED`. The written config separates facts from guesses in comments and its `[variants.*]` reproduces the flags the target was really built with, measured on all three benchmark variants.)
2. `find`: name and string search, plus xref queries ("functions touching this global/vtable") to support requests like "decompile the coin system". (Done: symbol/global/vtable search, xrefs with the instruction at each site, the pointer slots of a data object - a vtable's methods - and which vtables a function appears in, plus `--family <hops>`, which grows the match along the call graph and ranks the result by call edges and shared objects. New module `discover.py`; the pointers come from the link's relocations, because in a PIE the file bytes of `.data.rel.ro` are zeros.)
3. Flag inference helper: compile a few reference snippets at different optimization levels and compare prologue and epilogue patterns. (Done: `PROBE_SOURCE` is compiled at `-O0..-O3` with the installed toolchain and the target's own code is described the same way, then ranked. -O0 is separated strongly from everything else (0.94 vs 3.32, and 0.26 vs 3.08 for the -m32 build); -O1/-O2/-O3 are reported as "optimised code", not a level, because that is what the evidence carries. A statically linked image must be sampled with `--range`: its glibc outvotes the program, and the tool says so rather than answering confidently.)

What Phase 3 learned, for whoever extends it:

* LIEF returns section flags as an **int** for ELF/PE (`str(section.flags)` is `"6"`), which the
  Phase 2 code was string-matching: every ELF section was silently read as neither allocated
  nor writable, so `TargetImage.read()` never returned anything and `diff`'s byte comparison of
  referenced objects had never actually run. Fixed (`extract.section_capabilities`), and the
  byte rule is now sound: bytes count only where both sides know what object they are reading
  (a size on both, or a name on both), because two 16-byte windows out of two independently
  laid-out `.rodata` pools are not the same object. `check_phase2_try.py` is unchanged at
  88/89 with that rule.
* Dynamic relocations have `has_section == False`; `R_*_RELATIVE` ones carry a *nameless*
  pseudo-symbol whose value is the addend. Both are traps that silently drop every pointer in
  the image if written the obvious way.
* Ghidra's own labels (source DEFAULT/ANALYSIS) sit *inside* objects, so an object's extent is
  bounded by the next symbol the **file** names (source IMPORTED), not by the next label.
* `endbr64`/`__stack_chk_fail`/frame-pointer shares are worth reporting as facts about the
  build (`-fcf-protection`, `-fstack-protector-strong` vs `-all`, `-fno-omit-frame-pointer`);
  they came free with the shape profile.

**MS-0..MS-5: MSVC / PE targets, a separate track** - MS-0 through MS-3 implemented, MS-4/MS-5 not
Measured against a real MSVC binary (`Tests/Proprietary/notepad.exe`) in
[Docs/MSVC-Plan.md](MSVC-Plan.md), which is authoritative for that track: what a PE target already
gives the tool (its build note, and `.pdata` - the compiler's own table of 186 function ranges,
which MS-1 now caches, prefers for a unit's extent, and reports its disagreement with the
analysis over), what broke before MS-0 (`find`, `show`, `try`, `detect --range`), how to get `cl`
onto a Linux machine, and why the byte gate cannot be promised for a `/GL`+`/LTCG` target. MS-0
and MS-1 change nothing in the ELF path; MS-3 (COFF candidates) was the phase that makes `try`
work on PE at all, and it does: the untouched source through `decomp try` at `cl /Od` is
**100.00 % mean, 88 of 89 units past the gate**, with the COFF extent the tool derives matching
the compiler's for all 89 (`python Tests/tools/check_coff_candidate.py`).

**Phase 4: C++ structure recovery** - done, 2026-11-04
1. Identify vtables, constructors, and destructors from Ghidra data and RTTI where present.
   (Done, and RTTI is the anchor rather than Ghidra's naming: a `type_info` is recognised by
   "a pointer slot at +ptr resolves to a printable mangled type name", which works on a
   stripped binary; the bare type name (`16CCharacterEntity`) is demangled by asking for
   `_ZTV<name>` and dropping the "vtable for " the ABI puts in front. A vtable is offset-to-top
   at +0 with a `type_info` pointer at +ptr. Constructors are the functions that store
   `vtable + 2*ptr`; a deleting destructor calls `operator delete` and is called by one; a
   function that is itself a slot 0/1 of a vtable is a destructor. Measured: 3 classes in the
   stripped 64-bit build, 9 in the statically linked 32-bit one, against the answer key's own
   names and addresses.)
2. Maintain a shared header (`types.h`) that candidates include, updated as struct layouts are
   confirmed. (Done: `decomp types --write <dir>` writes it; the benchmark's own
   `include_dirs` already contains that dir, and `driver_form` adds every source's directory to
   the include path, so a candidate beside `types.h` compiles it without extra flags. The
   header is real C++ - `g++ -std=c++17 -fsyntax-only` accepts it - with bases, explicit
   padding, `void *vptr_`, placeholder field names (`f0x8`) whose *types* are labelled guesses,
   virtual signatures as comments, and `static_assert(sizeof(X) >= N)` lower bounds so a wrong
   layout fails the candidate's build rather than the tool's opinion.)
3. Expose it via `decomp types`. (Done, with `--class`, `--json`, `--limit`, `--write`;
   `decomp show` prints one `structure:` line for a function it can place, and `decomp try`
   says so when the target has no recoverable structure.)

The gap this phase existed for is closed: the `dynamic_cast` unit (STRUCT-24) reads three
`type_info` objects, and the `.o` named them while the linked image named pointer slots.
`normalize.Ref` now carries an `identity` for an object (a `type_info`/vtable is identified by
what it describes, not by the offset the code happens to read), the candidate side keys objects
by their symbol where a COMDAT section gives one, and the original side names them from RTTI -
so both sides print `typeinfo for CVehicleEntity`. That fix also gained the `-m32` row three
units: in a non-PIE 32-bit object, `pushl $_ZTI14CVehicleEntity` is an immediate of `0` with an
`R_386_32` on the four bytes, and an immediate operand was not a bindable slot before.
Acceptance is `Tests/tools/check_phase4_structures.py`: classes/bases/vtable slots/ctor-dtor
addresses/member offsets judged against `answer_key.json` and the layout in `structs.h`
(including the 32-bit one), the generated header compiled, and the opposite required of an MSVC
PE - Itanium RTTI is not that format, so claiming a class there would be a false positive.

**Phase 5: Hardening** - done for 1, 2026-11-05; 2 and 3 not started
1. Move to `-O2` test builds and handle inlining and register-allocation noise (register-abstracted comparison mode). (Done. **The extent, not the flags, was what -O2 broke.** At `-O2` a function's body is not contiguous: GCC orders it by hotness and pads between blocks, so Ghidra draws one unit as 2-5 ranges (51 of the 89), and puts the cold blocks of another in `.text.unlikely` as a second function. A range-based body is then the wrong byte string, and no amount of normalising fixes that: 65.88 % mean, 34 of 89 past the gate. What fixes it is the same thing MS-1 found in a PE: **the file already has a function table.** `extract._read_eh_frame()` parses the `.eh_frame` CIE/FDE records and `_read_symbol_sizes()` reads `st_size` where symbols survive, `TargetImage` keeps it (verified against `readelf --debug-dump=frames-interp`: 138 FDEs, 0 disagreements), `original_function()` prefers it over the analysis' ranges - explicit `--size` > the kept table > a live read of the file > the analysis' span > the analysis' body - and `decomp analyze` reports the disagreement instead of hiding it (on `-O2`: 73 units the analysis draws short, 7 analysis entries that are not units at all, made up in alignment gaps). Result: the untouched source at -O2 is **99.91 % mean, 88 of 89 past the gate**, above the independent harness's own ceiling of 98.27 % / 72; at -O0 nothing changed (100.00 %, 89/89) and neither did -m32 (99.38 %, 81/89). Acceptance is `python Tests/tools/check_phase5_o2.py`: it requires the tool's extent to equal the answer key's `(address, size)` for all 89 units of all three builds from the *stripped* file, requires the -O2 loop to hold, and demonstrates the two things the -O2 path needs: a body in two blocks tokenises with unit-relative labels (`jmp L6`/`jmp L0`, positions in the unit's byte stream, not addresses), and a register-only difference matches only under `--register-abstract` while a different register choice still does not.)
2. Optional: Unicorn-based behavioral check for functions that are semantically correct but not byte-identical. (Not started. Nothing measured here argues for it yet: the remaining differences in this benchmark are not semantic-equivalence cases - 8 of the 9 non-passing units are 32-bit data references through a shared section, and the 9th is a reference to an unnamed unit elsewhere in the binary.)
3. Optional: synthesize a target `.o` (via `.reloc`) so `objdiff-cli` can be used as an alternate backend. (Not started. Note for whoever does: objdiff's own function extents have the same problem this phase fixed - it uses the analysis' boundaries - so a synthesized `.o` needs the *unit table* carried across (`.eh_frame` for ELF, `.pdata` + `.pdata$x` for PE), not just the bytes.)

What Phase 5 learned, for whoever extends it:

* **A `.cold` partition is a separate unit, not half of one.** GCC emits it under its own symbol
  (`<mangled>.cold`) with its own FDE, and the *linked* image has it in `.text.unlikely`. So the
  file's table does not join it to the entry block, and neither does anything else have the right
  to: `symbols_for` excludes `.cold` symbols from name lookup (a `--fn CMathTests::RunSelfChecks`
  would otherwise match two), and the candidate side appends a `.cold` extent only when the
  original's own extent claims more bytes than the base symbol has.
* **A label is a position in the unit, not an address.** With extents in separate blocks, `L<addr
  - entry>` gives two different names for the same edge; `L<position in the concatenated byte
  stream>` gives one. Resolving the target means `ref.address` when the relocation names a symbol
  and the encoded operand otherwise - a `.o` call to a label in its own section has a placeholder
  displacement that only the relocation makes meaningful.
* **A section symbol is not an address.** `R_X86_64_PLT32 .rodata.cst16-4` names the whole section,
  so a constant pool label (`.LC13`) has no symbol of its own in a linked PIE either; naming such a
  target by the section it lives in removed a whole class of `-O2` operand differences (the float
  constants of `WrapAngle180`, `SineApprox`, `Atan2Approx`), and the `-4` in a PLT32 addend is the
  PC bias, not an offset - which is why a call into another section still resolves badly.
* The analysis' own numbers did not change and are not wrong about themselves:
  `check_analysis_cache.py` still reports 38 of 89 Ghidra function sizes matching the answer key's
  at -O2. That is the analysis describing its own boundaries; `try` no longer takes extents from it,
  and `decomp analyze` prints the disagreement in both directions.

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