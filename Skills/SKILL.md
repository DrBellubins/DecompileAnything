---
name: decompileanything
description: 'Turn compiled software into human-readable source that is byte-matched to the original. Given a request like "decompile the input system in this game binary" or "decompile the malicious file access in this binary", find the code that implements it, recover it function by function as clean C/C++ that recompiles to the same bytes (scored by the `decomp` CLI, which combines Ghidra analysis with compile-and-diff), keep iterating until each function reaches the project''s match threshold (98%, 70%, whatever the project sets), and deliver a small codebase plus an honest match report. Also covers fast reverse engineering when the user only wants to understand a target: Electron/JS bundles, Mach-O/ELF/PE, Go/Rust/.NET/Flutter/WASM, APKs, SQLite, pcaps, firmware, websites. Use for any request to decompile, reverse, inspect, match, recreate or explain behaviour in a binary, bundle or app, even if no tool is named and even if the user describes a feature rather than naming functions.'
---

# Decompiling binaries into matching, readable source

## The goal

The user gives you a binary and a request that names a **feature or behaviour**, not a list of functions:

- "decompile the input system in this game binary"
- "decompile the malicious file access in this binary"
- "recover the save-file loader"

You produce **source code for exactly the code that implements that behaviour**, such that:

1. **Scoped**: every function that implements the behaviour is found, or is explicitly listed as excluded or not found.
2. **Matched**: each function, compiled with the binary's own compiler and flags, reaches the **project's gate tier** (`[gate] require`: same operations and targets, then every operand right, then the bytes equal once the fields the link writes are zeroed on both sides). A percentage is never the claim - a wrong operation, a wrong immediate or a wrong callee has to be named, not averaged away.
3. **Readable**: the result is a small codebase a human can read and extend (real types, grouped by class or module, comments with provenance), and it still scores the same after the readability pass.
4. **Honest**: the report says what matched, what only partly matched, what was not attempted, and which claims are inferred.

Pure "how does X work?" questions do not need all of this. Pick the mode first.

| The user wants | Mode | Where to go |
|---|---|---|
| source for a feature or functions that compiles back to the same bytes | **Match** (the default for "decompile ...") | The five steps below |
| to know what it is, how a feature works, what versions or dependencies it has, what changed between builds, or to rebuild a feature | **Understand** | Rules, then Understand mode |
| the whole program ("decompile everything", "full decompilation of this binary") | **Whole-binary** | The five steps, but ordered by *Whole-binary mode* below, not by Step 2's feature scoping |

Match jobs begin with a short Understand pass (inventory, strings, imports) to find the right functions. Understand mode is also the right tool for targets that are not native compiled code (JS bundles, .NET, APKs), where byte-matching does not apply.

## Rules (both modes)

- Work on a copy (`cp -c` on APFS is instant, plain `cp` elsewhere). Put each extraction in a new directory under `$TMPDIR/re/<name>` and reuse an extraction if one exists.
- Route by `file -b T` and the magic bytes first. Run the cheapest inventory next. Only then decompile or read code. Inventories are cheap and usually answer the question.
- `rg` skips hidden and ignored files, and bundlers hide code (Electron: `.webpack/`, `.vite/`). Always search extracted trees with `rg -uu`.
- Never print a big or minified file. Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | head`. Dump a disassembly once to a file, then search that file.
- Batch independent probes into ONE shell call with `;` and `echo '--- name'` markers (quote the marker: zsh expands a bare `==x`). Cap every output with `head` or `-m`.
- Answer from evidence. Mark each claim **seen** (cite file:offset, address, symbol or string) or **inferred**. A fact you did not find is **unknown**, not "absent". Static reading is not observed execution. This applies to names in the recovered source too (see Step 4).
- A missing tool is not a blocker: use the fallback in the same row, or install it if the user allows it (see Install).
- Round trips cost more than bytes. For an Understand question aim for 2-4 commands: one batched recon call, one or two targeted slices, then answer. Stop when every item asked has evidence, and do not re-verify what you already saw.
- The commands below are macOS-flavoured (`otool`, `lipo`, `codesign`). On Linux use `readelf`, `objdump -d`, `nm -D`; `llvm-objdump` and `llvm-nm` work on every format.

---

# Match mode: the five steps

```
request ──► 1 Set up ──► 2 Scope ──► 3 Recover ──► 4 Readable + assemble ──► 5 Report
            (threshold)   (function    (write, score,   (names, types,         (matched / partial /
                           list)        diff, repeat)    layout, re-score)      not done)
```

`decomp` reports facts and scores; it never edits source. You write the source, it tells you how far the compiled result is from the original. Everything except `analyze` reads a cache and runs in ~0.1 s, so iterate freely. Run it as `decomp` (it lives in the repo's `.venv/bin`; activate the venv or add that to PATH).

**Scoring support today:** `try` (the compile-and-diff step) works for x86, 32 and 64-bit, built by GCC/Clang-style toolchains **or by MSVC** (an ELF target with an ELF candidate, a PE target with a COFF candidate built by `cl`). For MSVC, target bitness is *which `cl` runs* (`bin/x86` vs `bin/x64`), never a flag: the variant's `arch` picks the driver, and a 32-bit variant this machine cannot build is refused up front with the reason, before anything compiles. For other architectures there is no scoring. See *When matching is not possible* before promising a match.

## Step 1: Set up the project and fix the threshold

```sh
decomp check                                      # first stop whenever anything fails: names the fix
decomp detect <bin> --write project.toml          # compiler, flags, starting config
decomp analyze <bin> --variant <name> -C project.toml   # runs Ghidra once (~10 s), fills the cache
```

- **Threshold.** The pass mark for every function comes from the project (`project.toml`). If the user states a number ("get them to 95%"), use theirs and record it in `project.toml`. If neither exists, ask once before starting, because it decides how long each function is worth working on. Always report the threshold you used.
- Trust the facts `detect` prints (compiler, PIE, static/dynamic, `-std`). The `-O` level is a ranked guess from comparing code shape against this machine's compilers, so read its `confidence` and margin before accepting it. A wrong `-O` makes every function look unmatchable.
- **Build fidelity.** `detect` also says whether the compiler on this machine is the one that made the file (vendor, release, MSVC toolset era, and target bitness), and lists the flags beyond `-O` that the file itself names (PIC, CET, ISA level, `/GS`, `/guard:cf`). Each finding is labelled as the file's own record, a reading of the code's shape, or a hint. Treat the "try these" list as builds to try, never as facts. A compiler or bitness mismatch caps the `exact` tier (see Reading a score), so it is worth knowing before a loop starts.
- **Toolchain.** `decomp check` prints which toolchains can build which target (`msvc target x86`, `msvc target x64`) and whether a 32-bit PE can be *run* here (`run 32-bit PE`): building 32-bit code needs neither wibo nor an i386 Wine guest, only running it does. `[msvc] prefix` in `project.toml` pins the toolchain a project is built with.
- For a PE with a CodeView record, `decomp symbols <bin>` fetches the public PDB it names (when Microsoft publishes one) and verifies its GUID. That is an answer key, not part of the match loop.
- For a **statically linked** target, narrow the sample with `--range 0xLO-0xHI` over the program's own code, otherwise the answer is mostly libc's flags (the tool warns when this happens).
- Re-running `analyze` on the same bytes is a no-op; `--force` rebuilds. Rebuild an older cache to get new tables.
- With several targets cached, pass `--bin <file>` or `--key <key>` (see `decomp status`).
- **Pass `-v <variant>` on every `try`, `ledger` and `link`.** They default to the variant `analyze` recorded. If that was a placeholder (for example `gcc-o0` on a PE), an un-flagged `try` silently builds with the wrong compiler, compares an ELF object to a PE, can never pass, and never writes to the ledger. Check `decomp status` for the recorded variant; if it is wrong, `analyze --force -v <right variant>`. `decomp ledger` prints the variant it is showing, and other variants' pair counts, so a ledger that looks empty may just be the wrong variant.

## Step 2: Scope the request into a function list

A request names behaviour; scoring needs functions. Bridge them with a foothold, then grow outward.

**Find a foothold.** Pick the imports, strings and constants such a feature must touch:

| The request sounds like | Footholds to search (imports, strings, constants) |
|---|---|
| File access, persistence, exfiltration | `open`, `fopen`, `CreateFile*`, `ReadFile`, `unlink`, `rename`, `opendir`, `FindFirstFile`, `mmap`; path strings, extensions, `%APPDATA%`, `/etc/`, `~/.ssh`, browser profile directories |
| Network, C2 | `socket`, `connect`, `send`, `recv`, `getaddrinfo`, WinHTTP/WinINet, curl; URLs, hostnames, user agents, ports |
| Process, privilege, injection | `fork`, `exec*`, `CreateProcess`, `ptrace`, `VirtualAlloc`, `mprotect`, `dlopen` |
| Input system | SDL/GLFW input calls, DirectInput, XInput, `GetAsyncKeyState`, RawInput, evdev (`/dev/input`), HID; key and button names, binding or config strings, action names |
| Save/load, config, serialization | file imports plus format magic, version tags, field-name strings |
| Crypto, licensing, checks | S-box and CRC tables, magic constants, "invalid key"-style strings, crypto API imports |
| Rendering, audio, physics | graphics or audio API imports, shader strings, float-heavy code and constant pools |
| Anything else | a string, error message or constant the feature would contain |

Run the Understand-mode inventory first (First move below) to get the imports and strings cheaply.

**Grow it into a unit list:**

```sh
decomp find <name | 0xaddr | string | global | vtable>   # locate the foothold
decomp find <x> --family 2                               # connected group around it
decomp find <vtable> --table                             # what a vtable points at
decomp find <fn> --members                               # the class a function belongs to
decomp show <fn>                                         # callers, callees, class membership
```

In a stripped binary there are no names: start from a string or an address and let `--family` and callers/callees build the group that "the input system" means.

**Write the scope list down** (a table in your notes or `SCOPE.md`: address, current name or `sub_xxxx`, role, status). It drives everything after this step.

- **Include** the code that implements the behaviour: its entry points, its helpers, and the classes it uses.
- **Exclude and name** library code, CRT, compiler thunks and anything the feature merely calls (for example `memcpy`). List them as excluded so the user can see the boundary.
- If the scope is large (roughly 30+ functions) or the boundary is a judgment call, say so, show the list, and propose a priority order (entry points and the most characteristic functions first) instead of silently truncating or silently expanding. That priority order is for what you *show the user*. It is not the recovery order: recovery is always leaves-first (Step 3). Never work entry-point-outward, because every caller then has unreproduced callees and cannot reach `semantic`. For a whole program, use *Whole-binary mode* instead of this step.
- Ask the user a question only when the request cannot be mapped to any foothold.

## Step 3: Recover each function

**Order of work.** Start with leaf functions and small functions, then work up to their callers. Callee signatures are then already known, which removes a whole class of `relocation` diffs, and early wins confirm the flags are right.

**The loop**, per function:

1. **Read it.** `decomp show <fn>` gives pseudo-code, the original instruction stream, resolved references, callers/callees and its place in its class. It accepts the addresses `nm` and objdump print as well as Ghidra's (a PIE is loaded at `0x100000`; the cache records the gap).
2. **Write the function** with its real signature and real field offsets (see *Writing the candidate*). `decomp types` shows the classes the binary proves, and `decomp types --write <dir>` produces a `types.h` to include (field names are placeholders like `f0x8`; the header says which types are guesses).
3. **Score it.** `decomp try <fn> cand.cpp --fn <Symbol>`. It builds with the target's own variant flags (same compiler, `-O`, `-std`, arch), so the comparison is like for like. Use `--include` for headers; put permanent ones in `[include_dirs]`. The printed object path lets you run `objdump -dr` on the candidate. `--fn` is needed unless the object defines exactly one function.
4. **Read the diff and change the thing it names**, then go back to 3.

**Done** (per function) when it reaches the project's **gate tier** - `[gate] require` in `project.toml`, default `semantic`. Tiers, lowest first: **structural** = same length, same operations, same targets (`opcode`, `relocation`, `missing`, `extra` all 0); **semantic** = that plus every operand right, plus the two streams identical once register names are folded; **exact** = that plus the bytes equal, with the fields the link writes zeroed on both sides (a candidate's come from its own relocation table, the original's from the address-carrying operands of its instructions) - so a call's displacement or a global's address is never what fails a unit, while opcodes, immediates and the length of each encoding are. A unit that reaches `exact` can be called byte-matched; say which tier, and when it falls short of `exact` the report names the first byte offset where the encodings differ and the instruction it falls in. The match percentage is progress only - 97 % of a wrong function is still a wrong function, and one wrong callee or table hides inside it. `try` exits 0 only when the unit reaches the gate tier, and its report leads with `tier <name> PASS/FAIL (gate: <name>)` and names what is missing. `--gate <tier>` overrides the tier for one run and `--waive unverified` waives that one check for one run.

**Remembering what passed.** A unit that reaches the gate writes what it proved into the match ledger (`--no-learn` skips this): its own symbol at that address, and the candidate's names for anonymous globals it reaches. Later units are scored against it, so a callee proven once cannot be named differently in the next unit. `decomp ledger` lists the pairs and, more usefully, the *frontier*: the callees the reproduced units reach most often that have no name yet. That is the answer to "what next" for a *feature-scoped* job whose ledger is already non-empty. It only counts callees of units already in the ledger, so early on it shows a handful of CRT functions called once each, and on an empty ledger it ranks every callee in the binary (`memcpy`, `free`, `__security_check_cookie` first). Do not `try` library or CRT code because the frontier or its `next:` line names it; for a whole program use the ready-set query in *Whole-binary mode*. If a reference is `UNVERIFIED` because the only evidence is "both bodies are the same size", decompile that callee first and let the ledger name it.

**Stuck** (three tries with no change in the match or the categories): re-read the `show` assembly around the first differing instruction and change your hypothesis, not the syntax. If only `register:` differences remain and the report says "allocation only", stop: they are not fixable from source. Otherwise record the best candidate with its remaining diff categories and move on. Do not loop on one function; the rest of the scope is waiting.

### Reading a score

| signal | meaning | do |
|---|---|---|
| `opcode: n` | wrong operation: cmov vs branch, imul vs shifts, signed vs unsigned load | fix the operation; `movzbl` vs `movsbl` and `idiv` vs `shrd` are the usual ones |
| `operand: n` | right operation, wrong offset, constant, type, or a register pair swapped | field offsets, struct layout, array element type, truncated buffer bound. This is the category that stops `semantic`, so it is always yours |
| `relocation: n` | same code shape reaching for something else: another callee, table, or different bytes in it | the `symbols` line names both sides; fix the callee or reproduce the data. Bytes are only compared when both sides know what object they are (an anonymous `.rodata` pool is laid out per build) |
| `tier semantic` while the gate asks `exact` | the operations, operands and targets all check out, and the bytes still differ where nothing was masked | the report names the first differing offset and the instruction it falls in: a `jmp short` where the original has `jmp rel32`, a different instruction length, an immediate, or a register choice that changes the encoding. Fix that encoding - the call displacements and global addresses there are already excluded, so do not go re-checking them |
| tier stops at `structural` with no operand difference, and the symbol table marks a reference `UNVERIFIED` | the two sides reach the same object but neither can describe it - an anonymous `.bss` global, a PLT thunk whose import the stripped binary does not name - so nothing proves the match, and `semantic` is not claimed on an assumption | that reference is the whole gap: reproduce the object (its name and its bytes) in the candidate, or say the target cannot name it with `[gate] waive = "unverified"` in `decomp.toml` / `--waive unverified` for one run. Do not "fix" it by changing a constant |
| `register: n` | register allocation, if the report says "allocation only" (the two streams are identical with registers folded) | not yours to fix, and it does not stop `semantic`. If the report says the streams still differ once folded, the operands are paired differently - that one is yours |
| `missing` / `extra` | control flow or size differs | loop form (counted vs conditional), hoisted invariant, inlined vs called helper, early return vs branch |
| `size_delta` large, % high | something is inlined or vectorised that should not be, or the reverse | confirm you are comparing at the variant's own `-O`; never compare -O0 asm to -O2 asm |

If the report (or `decomp detect`) says the compiler here is not the one that made the file - another vendor, another release, another MSVC toolset, or another target bitness - byte differences are not something to iterate towards: `exact` is not claimed across that gap. Stop at `semantic`, say why in the report, and install the matching toolchain only if the bytes matter.

At `-O2` the analysis' range for a function can be shorter than the compiler's (thunk-like bodies, tail jumps). If the sizes disagree, pass `--size <symbol size>`; a PE's `.pdata` unit is used automatically.

### Writing the candidate

- **Keep the real signature.** By-value vs by-reference struct arguments, a hidden return pointer and `this` are all visible in the first six instructions.
- **Reproduce the data.** Tables (lookup tables, CRC tables, alphabets), bounds and buffer capacities are part of the answer. The score matches data references by order and by what they reach, so wrong table bytes still show up as `relocation`, but values in `.rodata` are only confirmed by strings and your own checks.
- **Match the shape, not the compiler.** A counted loop and a conditional loop with the same body are different code, and `while (a > 180.0f) a -= 360.0f;` is not `fmodf`. Prefer what the branches and comparisons prove, and let the diff categories say which one the binary has.
- **Offsets are an oracle.** An `operand` diff at a field offset is telling you the struct layout; fix the header, then re-score. Unions share storage and padding is observable, so check both before trusting a layout.
- **Floats** are only comparable as bit patterns. x87 (`-m32` default) and SSE can differ in the last ulp for the same source, so do not "fix" a last-bit difference between variants.
- **Judge sizes per variant.** At `-O0` every function starts with a frame, so tiny units are 30+ bytes; the sub-32-byte bucket only appears at `-O2`.
- **Name globals by role** only when the code proves the role. Otherwise keep a neutral name and note the offset.

## Step 4: Make it readable and assemble the codebase

Matching comes first, readability second, and readability must never cost a match.

- **Layout.** Group functions by the class or module the binary proves (`decomp find --members`, `decomp types`), one `.cpp` per class or subsystem, shared declarations in `types.h` or per-class headers. Follow the project's existing layout if it has one. Default:

  ```
  <target>-recovered/
    project.toml          # variant, flags, threshold
    include/types.h       # recovered classes and structs
    src/<subsystem>.cpp   # matched functions, grouped
    SCOPE.md              # scope list and exclusions
    MATCH_REPORT.md       # Step 5
  ```

- **Names.** Rename a local, field, function or class only when something proves its role (an import it calls, a string it prints, an RTTI class name, a clear data flow). Otherwise keep the neutral name (`f0x8`, `sub_401230`) and leave a comment with the offset. A plausible but unproven name is **inferred**: mark it so in a comment instead of presenting it as fact.
- **Comments.** Put one header comment on each function: address, match score, any residual diff, and anything inferred. Example: `// 0x401230  match 100%  opcode 0 reloc 0`. Add short comments for non-obvious intent only; do not narrate the code.
- **Safe vs unsafe edits.** Renames, comments and whitespace do not change codegen. Anything that restructures control flow, reorders statements, changes types, or replaces a loop does. **Re-run `decomp try` on every function you touched in this step** and confirm the score is unchanged before moving on.
- **Whole-codebase check.** Before reporting, re-score every function once more from the assembled files, so the report reflects what is actually on disk. For an ELF target, `decomp link` also rebuilds the program from the sources the ledger recorded, with the target's own `linkflags`, and compares it section by section. Read it by the first difference: later differences that are only link-written addresses are consequences of it. A PE or Mach-O target is refused for now; per-function `try` is the evidence there.

## Step 5: Report

End with a `MATCH_REPORT.md` and a short summary in your reply. Be plain about status:

| Function | Address | Match | opcode | reloc | Status | Notes |
|---|---|---|---|---|---|---|
| `Input::PollKeys` | 0x401230 | 100% | 0 | 0 | matched | |
| `Input::Remap` | 0x401410 | 91% | 0 | 2 | partial | callee at 0x4020a0 unresolved |

- **matched**: `try` reached the project's gate tier (`[gate] require`, default `semantic`). Report the tier reached, not a percentage.
- **partial**: best candidate kept, with the diff categories left.
- **not attempted / not found / excluded**: say which, and why.
- State the gate tier the project uses (`[gate] require`) and the tier each function reached; state the variant (compiler and `-O`) and its `detect` confidence.
- Separate **seen** from **inferred** for names and for the claim that the scope list is complete. "I found no other callers" is **unknown** about code reached through function pointers or vtables you did not enumerate.
- For security-oriented requests ("malicious file access"), describe what the recovered code does as observed in the static code, and say clearly that it was never executed.

## Whole-binary mode: ordering thousands of functions

Steps 1-5 still apply per function. What changes is how work is chosen, because a whole program has thousands of units and the order decides whether anything can pass. A unit reaches `semantic` only when every callee it reaches is either named on both sides (an import, a CRT function with a symbol) or already in the ledger. A callee that is an anonymous `FUN_xxxxxxxx` is checked by size alone, is counted `UNVERIFIED`, and caps its caller at `structural`. So the rule is: **never attempt a function before the anonymous functions it calls are reproduced or excluded.**

**W1. Fix the project first (Step 1).** Right variant, passed with `-v` every time. Read `detect`'s fidelity block. If it reports `/GL` + `/LTCG`, say up front that `exact` is not available and set the gate to `semantic`. For a toolset or era gap, `exact` is not claimed; pin the matching toolchain with `[msvc] prefix` only if the bytes matter. Try `decomp symbols <bin>` for a PE: a published PDB names the library code and acts as an answer key.

**W2. Draw the program boundary once, and write it down.** Find where the program's own code ends and statically linked library code begins. In a typical PE or static ELF the CRT, STL and third-party code sit in one contiguous address range (often the end of `.text`). Use the PDB or symbols if you have them. Otherwise use named functions (`_free`, `_memcpy`, `__SEH_prolog4`, `__security_check_cookie`), strings from library code, and where named entries cluster in `decomp find` output. Record the range as `LIB_LO`-`LIB_HI` in `SCOPE.md` and mark everything in it **excluded**, including unnamed `FUN_` entries inside it. Do not `try` excluded code, and do not let `ledger`'s frontier or `next:` line send you there. Check a few addresses either side of the boundary with `decomp show` before trusting it.

**W3. Compute the ready set; do not guess it.** A function is *ready* when every callee is outside the program range (excluded) or already in the ledger for this variant. Query the cache read-only (path from `decomp status`, key from `--bin`), substituting the boundary and variant:

```sql
-- sqlite3 <cache_dir>/<key>/analysis.db
SELECT entry, size, name FROM (
  SELECT f.entry, f.size, f.name,
    (SELECT count(*) FROM calls c JOIN functions g ON g.id = c.callee
      WHERE c.caller = f.id AND g.entry <> f.entry
        AND g.entry < :LIB_LO
        AND g.entry NOT IN (SELECT entry FROM matches WHERE variant = :VARIANT)) AS pending
  FROM functions f
  WHERE f.kind = 'function' AND f.entry < :LIB_LO
    AND f.entry NOT IN (SELECT entry FROM matches WHERE variant = :VARIANT))
WHERE pending = 0 ORDER BY size LIMIT 50;
```

Adjust the bounds if the program range does not start at 0 or the library sits below it. The call graph comes from Ghidra and misses indirect calls (vtables, function pointers), so a function can be ready by this query and still reach an unreproduced vtable method; the diff will say so. Self-recursion is skipped. Mutual recursion never becomes ready: when the ready set is empty but unmatched functions remain, pick the smallest function in each strongly connected group and do them together.

**W4. Work the ready set smallest first.** The tiny functions (getters, one-line wrappers, thunks, destructors) are the bulk of any binary and the cheapest to pass, and each one that passes unlocks its callers. Per function use the Step 3 loop with a hard cap: write from `decomp show`'s pseudo-code and assembly, `try -v <variant>`, at most three fixes, then record it as partial with its remaining diff categories and move on. Re-run the ready query after each batch. This is "most-called first" done correctly: callers are scored against names the ledger already holds.

**W5. Group classes.** Run `decomp types --write <dir>` early and include the header. Do constructors, destructors and vtable slots of one class together; field offsets stop being `operand` diffs once the layout is in the header. Methods reached only through vtables are not in the call graph, so take them from `decomp find <vtable> --table`.

**W6. Parallelise.** Ready functions do not depend on one another. Give each worker a batch of 10-20 from the ready query with a short brief: the `--bin`, the `-v <variant>`, the excluded range, the gate, the three-fix cap, and the output convention (one candidate file per function, results to a shared table). Do not give workers the whole skill. Ledger writes are SQLite transactions, so if concurrent writers hit a lock, stagger them. The coordinator re-runs the ready query between batches.

**W7. Large functions last.** Largest functions have the most callees, the most inlining and the hardest diffs, and they depend on everything below them. Reading the ten largest *early* is a good Understand-style pass to find subsystems and shared helpers; matching them early is not. Once their callees are in the ledger, time-box each large function and mark failures partial.

**W8. Measure throughput and stop on stalls.** After each batch report: units attempted, units at the gate, ledger size for the variant, and the ready-set size. If a batch passes almost nothing, do not scale up. Check, in order: the variant, the program boundary, the era or `/GL` finding, and whether the failures share a diff category. If all failures show the same `relocation` difference on one callee, fix that callee (or the name mismatch behind it) once, rather than in every caller. Names that Ghidra and the compiler spell differently (for example `__alloca_probe` against `__chkstk`) can cause this.

**W9. Report the whole binary honestly (Step 5).** Give counts by status over the *program range* (matched, partial, not attempted) and the excluded range, with its size, as a separate line. Do not report a percentage of the file: library code is a large share of most binaries, and "0.045% decompiled" against total file size says nothing until the denominator is the program's own code.

## When matching is not possible

- **PE / MSVC targets.** `detect`, `analyze`, `find`, `show`, `try` and `types` all work, for 64-bit and 32-bit images - a candidate is compiled to a `.obj` and scored against the PE, and MSVC RTTI (type descriptors, locators, vftables) is read as its own model. Limits to name in the report rather than chase: an image built with `/GL` + `/LTCG` cannot be byte-matched by a single-file compile; a 32-bit PE has no `.pdata`, so unit extents come from the analysis or `--size`; `decomp link` is ELF-only. Read `references/msvc.md` for the toolchain, Wine setup, the 32-bit rules, `.pdata` behaviour and the COFF candidate rules.
- **Other architectures (ARM, etc.).** `analyze`, `find` and `show` may work, but there is no scoring. Same rule: deliver readable, **unscored** reconstructions, labelled as such.
- **Non-native targets** (JS, .NET, Java/Android, Python bytecode). Byte-matching does not apply. Use Understand mode and the router tools to recover source, and say that the result is a decompilation, not a byte-match.
- **Working on `decomp` itself or its benchmark** (not decompiling a user's target): read `references/decomp-dev.md`.

## How scoring works, and its limits

- `try` compares symbolically: branches inside the function become function-relative labels, and calls and data references become positional tokens (`SYM0`, `DAT0`) matched by order, then checked by what they reach (a real name both sides know, the bytes there, the size). The score therefore does not depend on the link address.
- `try --json` gives the whole report if you need to parse it.
- `decomp types` recovers C++ structure from the target's own RTTI (class names, bases, vtable slots, constructors and destructors, member offsets and widths). The model follows the file's build note: Itanium `type_info` for GCC/Clang, MSVC type descriptors and locators for MSVC, with the 4-byte field width probed (RVAs on x64, absolute addresses on x86). A folded destructor (identical COMDAT folding) is reported as shared, not guessed.
- `-m32` targets build with `-no-pie -fno-pic`; a PIE link on i386 turns the pc-thunk/GOT sequence into `%gs` addressing, so object code and linked code stop matching.
- Exit codes: 0 ok, 1 a check or the work failed, 2 bad usage or config, 3 nothing found (or a command of a later phase).

---

# Understand mode

Use this to answer "what is it / how does it work / what changed", to find the footholds for Match mode, and for targets that are not native compiled code.

## First move: one call each, paste and run

Native (Mach-O):

```sh
T=./bin; D=$TMPDIR/re/$(basename $T); mkdir -p $D; file $T; lipo -info $T; otool -L $T; echo '--- EXPORTS'; nm -gU $T | head -150; echo '--- IMPORTS'; nm -u $T | rg -v '^__Z|napi_' | tr '\n' ' '; echo; echo '--- STRINGS'; strings -a -n 6 $T | rg -v '^[_$.]' | head -400; otool -tV $T > $D/dis.txt; echo '--- FUNCS'; rg '^[_a-zA-Z].*:$' $D/dis.txt | rg -v '^_?_?Z?N?St3' | head -150
```

Then read one function:
`awk '/^FUNC_LABEL:$/{p=1;next} p&&/^[_a-zA-Z].*:$/{exit} p' $D/dis.txt | rg 'bl|b\.|cmp|literal|mov\s+w2'`.

Electron:

```sh
A=./app.asar; X=$TMPDIR/re/asar; rm -rf $X; npx -y @electron/asar extract $A $X && jq '{name,version,main}' $X/package.json; find $X -path '*/node_modules' -prune -o -type f \( -name '*.js' -o -name '*.node' \) -print | head -60; ls ${A}.unpacked/node_modules 2>/dev/null; rg -uu -l --glob '!node_modules' 'exposeInMainWorld' $X
```

Then slice the needle across the bundle:
`rg -uu -o --glob '!node_modules' '.{0,250}NEEDLE.{0,250}' $X | head -20`.

Go: `go version -m T` alone usually answers the question.

## Router

| Target (detect) | Fastest path |
|---|---|
| Electron app (`*.app/Contents/Resources/app.asar`) | `npx -y @electron/asar extract app.asar X` (also see `app.asar.unpacked/` for `.node` addons). Entry point: `jq .main X/package.json`. Surface: `rg -n -o '.{0,120}(ipcMain\.(handle|handleOnce|on|once)|ipcRenderer\.(invoke|send|sendSync|on)|contextBridge\.exposeIn(Main|Isolated)World|webPreferences|preload:|nodeIntegration|contextIsolation|sandbox|\.node\b).{0,160}' -uu X --glob '!node_modules'`. App-specific IPC wrappers often hide the channels, so also run `rg -uu -o '"[a-z]+:[a-z0-9:-]+"' X/<main> \| sort -u`. Fuses: `npx -y @electron/fuses read --app A.app`. |
| Web bundle / minified JS | Find `sourceMappingURL`. If the map has `sourcesContent`, dump the sources: `jq -r '.sources[]'`. For webpack, grep the module ids, then slice around the hit. For pretty-print: `npx -y prettier --parser babel F > F.pretty.js`, then read with line ranges. |
| Hermes / bytenode / V8 snapshot | Hermes magic is `c6 1f bc 03` (`index.android.bundle`): use `hermes-dec` / `hbc-decompiler`. `.jsc` (bytenode) cannot be decompiled: use strings and runtime hooks. |
| Mach-O (`file`: Mach-O) | `lipo -info` (thin first: `lipo -thin arm64 -o T1 T`). Then: `otool -L` (libs); `xcrun dyld_info -exports -imports`; `nm -gU` (exports) / `nm -u` (imports = the capability map); `strings -a -n 6`; `otool -l \| rg -A3 'LC_(RPATH\|BUILD_VERSION)'`; `codesign -d --entitlements :- T`; `otool -ov` (ObjC classes/methods); `xcrun swift-demangle --compact`. |
| Native code logic (to read, not to match) | `otool -tV T > $D/dis.txt` (or `llvm-objdump -d --no-show-raw-insn -C`). Find the function: `rg -n '^_?.*Name.*:$'`. Read the call/string trail: `awk '/^FUNC:/{p=1} p&&/^[_a-zA-Z].*:$/&&!/FUNC/{exit} p' dis.txt \| rg 'bl\|call\|literal\|cmp'`. otool labels string literals and stubs inline, which is often enough. For real pseudocode: Ghidra `analyzeHeadless $D p -import T -postScript DecompileAll.java -deleteProject` or `r2 -qc 'aaa; pdc @ sym.X' T`. To recover source that must recompile to the same bytes, use Match mode above instead. |
| ELF / PE | `readelf -hlSW`, `readelf -dW` (NEEDED), `nm -D --defined-only`, `objdump -d -M intel`. PE: `objdump -x`, `pefile`/`wrestool` for resources. checksec: `pwn checksec`. |
| Go (`__go_buildinfo`, `.go.buildinfo`) | `go version -m T` gives the toolchain, path, mod, deps and build flags in one call. Without Go: `strings -a T \| rg -m1 -A200 'Go buildinf' `. Symbols survive stripping: `go tool nm T \| rg main\.`. |
| Rust | Deps (cargo-auditable): `cargo audit bin T`, or extract `.dep-v0` / `__DATA,.dep-v0` and zlib-inflate it. Compiler: `strings -a T \| rg -o '/rustc/[0-9a-f]{40}' \| sort -u`. Crates from paths: `strings -a T \| rg -o '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src' \| sort -u`. |
| .NET (`file`: Mono/.Net) | `ilspycmd -p -o X T.dll` (install: `dotnet tool install -g ilspycmd`), then `rg`. P/Invoke: `rg DllImport X`. NativeAOT/IL2CPP are native: use the native rows. |
| Android APK | `jadx -d X --show-bad-code a.apk` then `rg`. Resources/manifest only: `apktool d --no-src -o X a.apk`. Quick look: `unzip -l a.apk`. `lib/*/libflutter.so` means Flutter (Dart AOT: `blutter`); `libhermes.so` means React Native (Hermes row). |
| Flutter snapshot hash | In `libapp.so`, find magic `f5 f5 dc dc`; the 32 hex chars at +20 are the snapshot hash. Map it to a Dart version. |
| WASM | `wasm-objdump -x`, `wasm2wat`, `wasm-decompile` (WABT). |
| SQLite | Copy the db, plus the `-wal` file if present. `sqlite3 'file:C?mode=ro' '.schema'`, then `SELECT * FROM t LIMIT 20`. |
| plist / nib / car | `plutil -p F`. Info.plist holds the bundle id, URL schemes and privacy strings. Asset catalogs: `assetutil --info Assets.car`. |
| pcap / HAR | `tshark -r C -q -z conv,tcp`; `tshark -r C -T fields -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.full_uri \| sort -u`. HAR: `jq -r '.log.entries[].request \| .method+" "+.url'`. |
| Firmware | `binwalk -e F` or `unblob -e X F`. Then route each extracted binary through this table. |
| Website | `curl -sL URL` for the HTML and script srcs, then fetch the JS and slice it. For runtime behavior, use a headless browser with a network log (Playwright `page.on('request')`) or Chrome `--remote-debugging-port`. |
| Running app / runtime | macOS: `lldb -p PID`, `dtrace`/`fs_usage`/`log stream --predicate 'process=="X"'`. Electron main: `--inspect` (only if the RunAsNode/inspect fuses allow it). Android: `adb logcat`, `frida -U -f pkg -l hook.js`. |

## Speed patterns

- Strings and imports first. On a small binary, `nm -u` + `strings` + the export list usually answer "what does it do" with no disassembly.
- To find who uses a string: get its address from `otool -tV` "literal pool for" comments, or `rg -n 'literal pool for: "X'`. Then find the enclosing function label above that line. In Match mode, `decomp find "<string>"` does this directly.
- A C++ name in a `bl` target already tells you the protocol (for example `getpeereid`, `write`, `std::hash`). Read the call sequence, not every instruction.
- For JS, go from the native/JS boundary inward: find the native call, then its caller class, then the IPC registration, then the renderer/preload.
- Comparing versions: diff the inventories (`nm`, the module list, `go version -m`) before you diff any code.
- Rebuilding a feature: write the minimal reimplementation, then test it against the original (same inputs, same outputs).

---

## Install (only if needed and not present; ask first)

`brew install jadx apktool radare2 binwalk wabt wireshark ghidra` · `npm i -g @electron/asar` · `dotnet tool install -g ilspycmd` · `cargo install cargo-audit`.

## Reference files

- `references/msvc.md`: PE/MSVC targets: what works, the MSVC toolchain under Wine, 32-bit (i386) targets, the `.pdata` function table, the COFF candidate rules. Read when the target is a PE built by MSVC.
- `references/decomp-dev.md`: building and checking `decomp` and its benchmark. Read only when editing the tool, the test binary or the benchmark, never when decompiling a user's target.