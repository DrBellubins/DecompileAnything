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

- Define explicit tiers in `Verdict` instead of one `passed` flag:
  - **structural:** `opcode == relocation == missing == extra == 0`
  - **semantic:** structural, plus `operand == 0` and register-abstract comparison clean
  - **exact:** semantic, plus masked bytes equal (Phase 3)
- Keep the percentage purely as a progress indicator. Report the tier reached, and make the tier the exit code and the "done" criterion in `report_lines`.
- Run the register-abstract comparison on every `try`, not only with `--register-abstract`. Plain register renames pass; a different operand pairing (`subss %xmm1,%xmm0` vs `%xmm0,%xmm1`) fails. Report remaining plain register differences separately as "allocation only".
- Add a `[gate]` section to `project.toml` (`require = "semantic"`) so you can relax it per target, for example for LTCG MSVC images.
- Update the `Skills/DecompileAnything.md` guidance so the LLM loop targets the tier, not the percent.

**Acceptance:** a candidate with a swapped subtraction, a dropped `mulss`, or a wrong immediate no longer reaches "semantic". A pure register-allocation difference still does.

## Phase 3: Relocation-masked byte comparison
*Turns `bytes_equal` into something that can actually fire.*

- On the candidate side, zero the relocation fields (offset and width are already available: ELF from the relocation type, COFF from `_COFF_FIELD_WIDTH`).
- On the original side, zero the same fields using the `Slot.enc_offset` and 4-byte width of each address-carrying operand, including in-section calls that need no relocation.
- Compare the masked buffers and report `bytes_equal_masked`, plus the first differing offset with the instruction it falls in. This is also what gates the "exact" tier.
- Handle extents (cold partitions) by masking per extent before concatenation.

**Acceptance:** a function containing calls and rip-relative loads that you've matched by eye reports masked-identical. Changing one encoding choice (for example `lea` vs `mov`) is caught at the byte level even if the text compares close.

## Phase 4: Verify constants and rodata
*This is where DSP coefficients and string literals escape today.*

- Record the access width on each original-side `Ref`, derived from the mnemonic or register (`structures._width_of` already does most of this, so move it to `normalize`).
- In `refs_compatible`, compare `content[:width]` whenever both sides have bytes, even if neither has a size or name. For pooled constants the width is the evidence.
- Strings: use the cached string length on the original side and the NUL-terminated read on the candidate side.
- Add an `unverified` counter to `Verdict`: refs where neither side offered evidence. The "semantic" tier requires it to be 0 or explicitly waived. This replaces the silent "unknown means match" behaviour.
- Check that `.rodata.cst*` sections in the candidate object stay readable (`_read` refuses sections that have relocations).

**Acceptance:** changing one filter coefficient from `0.7071f` to `0.7072f` fails the gate, as does a one-character string change. `unverified` is reported in the output.

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