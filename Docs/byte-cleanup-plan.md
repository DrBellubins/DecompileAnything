# Plan: closing the gap between the gate and "byte-for-byte identical"

Ordered by impact on the project's claim. Each phase is small enough to land and test on its own, and later phases build on earlier ones. I haven't run any of this, so each phase ends with an acceptance test you can run on your own binaries.

## Phase 1: Fix the `diff.compare` truncation bug
*Small effort, and everything downstream depends on correct counts.*

- In the `replace` branch, handle unequal block lengths: zip the common prefix, then report the leftover tail as `missing` (original longer) or `extra` (candidate longer), with addresses.
- Add a consistency invariant: `matched + sum(categories excluding hidden relocations) == max(len(left), len(right))` (or an equivalent that holds for your counting). Assert it in tests rather than at runtime.
- Delete the "below the threshold with no categorised difference" warning path once the invariant holds, or keep it as an internal error.

**Acceptance:** synthetic token streams with unequal `replace` blocks yield exact `missing`/`extra` counts, and the invariant holds on every function in your benchmark set.

**Done** (2026-11-06, `Tests/tools/check_diff_accounting.py`). The leftover tail is now reported,
and `Verdict` keeps `matched`/`replaced`/`hidden_relocations` so the counts can be checked
(`accounting()` / `accounting_problems()`; the runtime appends an "internal error in the
comparison" note only if they break, and the old "same shape but not the same length" warning
is gone). Two things the plan did not know:

* The stated invariant needs one correction. A region that turns N original lines into M
  candidate lines is one differing region but counts on **both** sides, so the exact form is
  `matched + categories(excl. hidden) == max(len, len) + min(missing, extra)`. `diff.py` states
  the two-sided identity (`matched + replaced + missing == len(original)`, same on the candidate
  side), which is what holds for any alignment.
* The bug was worse than the warning suggested: the warning only fired when *nothing* was
  categorised. A unit with any other difference reported "instructions 5 vs 3 (-2)" next to
  "missing 0, extra 0" and looked fine. The three negative controls gained the lines they had
  been dropping (MATH-02: `operand 6` → `operand 6, missing 5`; MATH-38: `+8 extra`;
  STR-01: `+3 extra`). Match percentages do not move - the bug was in the categories only.

Measured: 285 verdicts over all three ELF variants of the benchmark (untouched source, the wrong
candidates, and truncated extents) all satisfy the invariant; `check_phase2_try.py` still passes
with unchanged means (100.00 / 99.91 / 99.38) and the same 89/88/81 past the gate.

## Phase 2: Make the gate mean something
*Highest impact on trust. The 97% rule currently lets real errors pass.*

- Define explicit tiers in `Verdict` instead of one `passed` flag (implemented as `tier` /
  `require`; `passed` stays as the property that reads them, so no caller had to change):
  - **structural:** `opcode == relocation == missing == extra == 0`
  - **semantic:** structural, plus `operand == 0` and register-abstract comparison clean
  - **exact:** semantic, plus masked bytes equal (Phase 3)
- Keep the percentage purely as a progress indicator. Report the tier reached, and make the tier the exit code and the "done" criterion in `report_lines`.
- Run the register-abstract comparison on every `try`, not only with `--register-abstract`. Plain register renames pass; a different operand pairing (`subss %xmm1,%xmm0` vs `%xmm0,%xmm1`) fails. Report remaining plain register differences separately as "allocation only".
- Add a `[gate]` section to `project.toml` (`require = "semantic"`) so you can relax it per target, for example for LTCG MSVC images.
- Update the `Skills/DecompileAnything.md` guidance so the LLM loop targets the tier, not the percent.

**Acceptance:** a candidate with a swapped subtraction, a dropped `mulss`, or a wrong immediate no longer reaches "semantic". A pure register-allocation difference still does.

**Done** (2026-11-06, `Tests/tools/check_gate_tiers.py`). `Verdict` carries `tier` and
`require`; `passed` is "reaches the required tier" and is what the exit code and `report_lines`
follow. The `[gate] require = "semantic"` table is in both project.toml files, `--gate` overrides
it per call, `[variants.<name>] gate` per build flavour, and `percent` / `none` are the escape
hatches for a target where no tier can honestly be claimed. Two things the plan did not know:

* **First-appearance folding cannot see a bare swapped subtraction.** `subss %xmm1,%xmm0` and
  `subss %xmm0,%xmm1` fold to the same line, because folding is a renaming and a swap *is* a
  renaming in isolation. It is only caught once other instructions pin which register holds what
  (in a longer body, the fold makes the two sides disagree). So the swap is named where it is
  classified: a line pair whose register names are the same multiset in a different order, with
  the register that ends up written changed, is an `operand` difference, not a `register` one.
  A real allocation difference (different names, same positions) is unaffected. `leal
  (%rax,%rcx),%edx` vs `leal (%rcx,%rax),%edx` stays a rename - the written register did not
  change - so the rule does not cost real units.
* **`exact` already fires without Phase 3**, on the units whose body carries no relocation
  fields: the untouched source is byte-identical for 54 of 89 units at -O0, 55 at -O2, 58 at
  -m32. So Phase 3 is not needed to make the tier reachable at all, only to make it reachable
  for the bodies that do reference something. The report says the byte test is unmasked.

Measured, untouched source through `decomp try`'s own path, gate `semantic`: **-O0 89/89 (was
89), -O2 86/89 (was 88), -m32 77/89 (was 81)**. Nothing that was correct fell out; what fell out
was 6 units the percentage rule was tolerating, all of them an operand difference on a data or
callee reference the two sides cannot pair (`leaq SYM1(%rip)` vs `leaq SYM0(%rip)` at -O2,
`fldt DAT1` vs `DAT0` and a 32-bit absolute array reference at -m32). They are now in
`KNOWN_GAPS` with the reason, and Phase 5's ledger is what pairs them honestly. Match means are
unchanged (100.00 / 99.91 / 99.38), and the three negative controls are unchanged.

## Phase 3: Relocation-masked byte comparison
*Turns `bytes_equal` into something that can actually fire.*

- On the candidate side, zero the relocation fields (offset and width are already available: ELF from the relocation type, COFF from `_COFF_FIELD_WIDTH`).
- On the original side, zero the same fields using the `Slot.enc_offset` and 4-byte width of each address-carrying operand, including in-section calls that need no relocation.
- Compare the masked buffers and report `bytes_equal_masked`, plus the first differing offset with the instruction it falls in. This is also what gates the "exact" tier.
- Handle extents (cold partitions) by masking per extent before concatenation.

**Acceptance:** a function containing calls and rip-relative loads that you've matched by eye reports masked-identical. Changing one encoding choice (for example `lea` vs `mov`) is caught at the byte level even if the text compares close.

**Done** (2026-11-06, `Tests/tools/check_masked_bytes.py`). `diff.compare_bytes` zeroes each
side's fields and reports the first differing offset; `Verdict.bytes_equal_masked` is what gates
`exact` (`tier_for` takes the masked comparison, `tier_gaps`/`Verdict.gaps` quote the offset and
the instruction it falls in). The report prints the masked comparison under the raw byte line,
and `--json` carries `bytes_equal_masked`, `masked_byte_fields`, `masked_offsets` and
`masked_first_difference`. Fields are per extent (`normalize.body_blocks` carries the cursors
through `address_fields`, `relocation_fields` and `body_index`), so a `-O2` cold partition is
masked at its offset in the concatenated body.

Two things the plan did not know:

* **`Slot.enc_offset` is a convention, not a decoding.** It says "one byte past the opcode" for a
  branch - right for `e8`/`e9`, wrong for a `0f 8x` conditional jump, whose rel32 starts two
  bytes in - and "length minus four" for a displacement, which is wrong when an immediate follows
  it (`cmpb $0, x(%rip)` is `80 3d disp32 01`). Masking on the convention hides the wrong bytes.
  `normalize.field_span` therefore *checks* the recorded offset by decoding it against the address
  the slot recorded, and falls back to the encoding's real shape: a pc-relative or absolute field
  is 4 bytes wherever it sits, a branch's displacement is always the trailing bytes (so a rel8 is
  1 byte, not 4). An unrelocated `call 0` in a `.o` is still found as a 4-byte field, because the
  widths are tried widest first.
* **"Zero the same fields on both sides" cannot be one shared list.** A `.o` relocates a call to a
  helper in the same section and a self-recursive call whose entry sits inside the body, while a
  jump to an interior label of the body is resolved by the assembler and relocates nothing. So
  both sides run the same `position_dependent()` test over their own operands - pc-relative and
  absolute always, an immediate only when something resolves it, a call or a cross-body branch
  always, an in-body branch never - and the candidate masks every field its relocation table
  states as well, which is authoritative and gives the width from the relocation type. A field
  only one side has is compared against the other side's bytes, never hidden.

Measured, untouched source through `decomp try`'s own path, gate `semantic`, all three ELF
variants (identical bytes without masking, then with the fields the link writes zeroed):

| variant | raw byte test | masked byte test | below the gate |
| --- | --- | --- | --- |
| `-O0` | 54/89 | **89/89** `exact` (516 bytes of fields) | none |
| `-O2` | 55/89 | **86/89** `exact`, 3 `structural` (470 bytes) | STRUCT-22/23/24 |
| `-O0 -m32` | 58/89 | **77/89** `exact`, 11 `structural`, 1 `none` (348 bytes) | the 12 known gaps |

Every unit that reaches the gate now also proves its bytes: nothing is left between `semantic`
and `exact` on any variant, and the units below the gate are exactly Phase 2's `KNOWN_GAPS`,
unchanged. Two `-O2` units (`STR-04`, `STR-11`) mask a one-byte branch field on the original
side that the candidate's object file resolved without a relocation - a hot-to-cold `jmp` that
crosses extents in the linked file but not in the object. Their bytes are identical either way,
so the claim is unaffected, and the field counts on both sides are printed in the report so this
case stays visible.

One pre-existing bug was fixed on the way, because it blocked the CLI path this phase exists for:
`cache.status()` read the `meta` table of any directory under the cache root, and `try` writes
candidate objects plus a scratch `analysis.db` into `candidates*/`, so `cache.targets()` raised
`no such table: meta` and `decomp try <addr> <src>` failed before it reached the comparison (the
same cause as the `decomp status` crash recorded on 2026-11-05). Such a directory now reports
`{"complete": 0, "reason": "not an analysis database"}`; the acceptance tool asserts
`cache.targets()` still lists the benchmark target. The COFF path gained the same treatment:
`decomp try` on the `cl /Od` PE target now reports 54 units with literally identical bytes and
**89 of 89 `exact`** with the link's fields zeroed (`check_coff_candidate.py` prints both).

## Phase 4: Verify constants and rodata
*This is where DSP coefficients and string literals escape today.*

- Record the access width on each original-side `Ref`, derived from the mnemonic or register (`structures._width_of` already does most of this, so move it to `normalize`).
- In `refs_compatible`, compare `content[:width]` whenever both sides have bytes, even if neither has a size or name. For pooled constants the width is the evidence.
- Strings: use the cached string length on the original side and the NUL-terminated read on the candidate side.
- Add an `unverified` counter to `Verdict`: refs where neither side offered evidence. The "semantic" tier requires it to be 0 or explicitly waived. This replaces the silent "unknown means match" behaviour.
- Check that `.rodata.cst*` sections in the candidate object stay readable (`_read` refuses sections that have relocations).

**Acceptance:** changing one filter coefficient from `0.7071f` to `0.7072f` fails the gate, as does a one-character string change. `unverified` is reported in the output.

### Done 2026-11-06 — the plan did not know three things

**A PC-relative relocation does not point at the operand.** In a candidate's `.o`, a relocation
against a section symbol carries an addend measured from the *end of the instruction's field* (the
negative addend Ghidra prints), not the address: `R_X86_64_PC32` to `.LC0` names the object at
`addend + 4`. The candidate had been resolving every RIP-relative access four bytes past what the
instruction reads, and the pool comparisons that survived were surviving by accident, because both
sides were anchored the same wrong way. `extract.pc_bias` fixes it — Phase 4's evidence is only
meaningful on top of a read that names the right bytes.

**`.rodata.cst*` was not readable in practice.** `CandidateObject._read` refused any section that
carries relocations, and every constant pool does, so `content` was empty for exactly the sections
this phase wants. It refuses a *window* that overlaps a relocated field now — the same bytes Phase 3
masks at the byte level — which is what gave 351 float references their `bytes` evidence.

**Widths were already being derived, in the wrong module.** `structures.py` needs the same
mnemonic→width answer for its access map, so `access_width`/`register_width` live in `normalize` and
both call it. `width` was already a field on `Ref` and `Instruction`; what was missing was that
nothing set it.

`ref_evidence` then asks, in order: is this a string (the original's cached length plus its
terminator, against a candidate read that stops at its own NUL) → is it an object both sides can
describe and read (`content` at the width either side knows) → do both sides read the same number of
bytes (`width`). A match with no rung is counted in `Verdict.unverified`, which caps the tier at
`structural` unless the project says otherwise with `[gate] waive = "unverified"` (or `--waive` for
one command). `strings` and `layout` have their own truth tests, so a reference whose content comes
from a reproduced string or struct is not asked to prove itself twice.

Measured (untouched source, `decomp try`'s path, gate `semantic`):

| variant | past the gate before | after | what moved |
| --- | --- | --- | --- |
| `-O0` | 89 | 87 | MATH-13, STRUCT-21 stop at `structural`: 2 and 1 references to `.bss` data neither side can describe |
| `-O2` | 86 | 84 | the same two |
| `-m32` | 77 | 63 | 12 more capped the same way (PLT thunks whose import the stripped binary does not name, anonymous globals); 30 float/`cst8` references and MATH-20/MATH-21/MATH-27 now verified by bytes |

Nothing in the first two rows is a candidate problem, and saying so is the point: a reference to
`DAT_080de6e0` means nothing to either side, so it was *assumed*, and `semantic` should not rest on
that. The honest answer is the structures work (Docs/structures-plan.md) or the link-time tables
(Phase 5), not a waiver — and the 32-bit rows show what an unnamed `strncpy` through a thunk costs.
Two of the m32 regressions are a real bug this comparison exposed: at i386 a candidate's read window
in a plain `.rodata` double pool is anchored on the nearest symbol instead of the offset the
relocation addresses (MATH-21, MATH-27).

Acceptance: `Tests/tools/check_phase4_evidence.py` — MATH-20's `360.0f`→`359.0f` and STR-15's
`x%.1f`→`x%.2f` both fail the gate, naming the bytes and the instruction they are read at.

## Phase 5: Callee and global identity through a match ledger
*Fixes the "equal size, different helper" and first-use-order problems.*

- Add a `matches` table to the cache (original entry, candidate symbol name, tier, date). `try` writes to it on success.
- In `refs_compatible`, when the original callee has a ledger entry, require the candidate callee's name to equal the ledger's candidate symbol. When it has none, mark the ref `unverified` (feeding Phase 4's counter), and report the callee's size as weaker evidence.
- For globals, key data tokens by the ledger or by address where the ledger knows the object, so equivalence no longer depends on first-use order.
- Add a `decomp ledger` command (list, unmatched callees by caller count) so the LLM can pick what to decompile next.

**Acceptance:** two same-size helpers swapped in a candidate fail once either is in the ledger. `decomp ledger` lists the frontier of unmatched callees.

## Phase 6: Whole-program relink and compare
*The only real test of the stated goal. It covers vtables, static initialisers and data layout.*

- New command `decomp link`: compile every ledger-matched candidate source with the variant flags, link with `link_flags(variant)`, and compare against the target.
- Compare per function using the relocation-masked bytes at their linked addresses, then compare the final `.text` bytes where the layout agrees. Add `.rodata`, `.data` and vtable contents (the `structures` recovery gives you the vtable and RTTI shapes to compare).
- Report which sections diverge first and at what offset. Layout shifts from missing functions make later offsets meaningless, so the command should say which differences are consequences of an earlier divergence.
- Start with ELF and the static case, then extend to MSVC `link` with the toolset checks from Phase 7.

**Acceptance:** a fully matched benchmark program relinks to a byte-identical `.text`, or the report names exactly the first function that differs.

## Phase 7: Build fidelity
*Matters whenever the gate passes but the bytes won't match.*

- **Compiler version check:** in `check` and `try`, compare `build_note`'s GCC version or MSVC toolset against the installed compiler and warn (a hard failure for the "exact" tier).
- **Flag inference beyond `-O`:** detect from the file what can be detected, and surface the rest as a "try these" list when the byte comparison fails:
  - `-fPIC` (PLT/GOT use in code, `DYN` object with no interpreter)
  - `-fcf-protection` (`endbr`, already read)
  - `-fstack-protector` (canary, already measured)
  - `-mavx`/`-mfma` (VEX-encoded instructions in the instruction stream)
  - `-ffast-math` (visible as reciprocal/FMA patterns, unreliable)
  - MSVC `/arch`, `/fp`, `/guard:cf`
- Add `-fPIC` to `starter_config` for `DYN` files with no interpreter.
- Because these are guesses, record them as comments next to the generated line, as `starter_config` already does.

**Acceptance:** `decomp detect` on a shared plugin suggests `-fPIC` and the vector flags it can see, and a version mismatch is flagged before a single `try`.

## Phase 8: Platform coverage
*Scope decisions rather than bug fixes. Worth deciding explicitly.*

- **MSVC LTCG:** keep the honest "byte gate not promised" message, but make the tier explicit: LTCG targets cap at "semantic" in `[gate]`. Add `/OPT:ICF` awareness to unit scoring, using the identical-code-folding note that `structures.py` already produces.
- **ARM64 and Mach-O:** either add an ARM64 decoder and `__unwind_info` units, or state x86-only in the README and `check`. Silence is the worst option for plugin work.

## Phase 9: Cleanups and robustness
Land these opportunistically, alongside whichever phase touches the file.

- `extract.py`: remove the dead `"lea" if False else "nop"` expression and handle multi-byte `nop` forms. Review `hlt`/`pause` in `_PADDING_MNEMONICS`.
- `unit_reconciliation` and gap filling: skip jump-table data inside a unit's extent (use `.rodata` references from `switch` tables to bound it).
- `ghidra.py`: fix the double `external_count` increment, and validate `[ghidra] language` before creating the project.
- `discover.family` and other `IN (...)` queries: chunk the placeholder lists to stay under SQLite's variable limit.
- `cache.find`: escape `%` and `_` in `LIKE` patterns (`ESCAPE '\'`).
- `try` latency: persist the `structures.Recovery` result in the cache (bump `CACHE_VERSION`) instead of rebuilding it and re-parsing with LIEF each call.
- `try` config switching: print the config path in use and warn when the recorded one differs from the `project.toml` the user is looking at, rather than switching silently.

## Suggested order of work

Phases 1 and 2 give the biggest jump in trust for the least code, and they're likely to change which of your current "successes" still pass, so run them against your existing matched functions first and see what falls out. Phases 3 to 5 then fill in the evidence the stricter gate needs, and Phase 6 is the capstone.

I can turn any phase into a more detailed spec (data structures, function signatures, test cases) if you want to hand it to a coding agent.