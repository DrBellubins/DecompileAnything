---
name: decompileanything
description: Iteratively decompile functions out of a compiled binary into source that recompiles to the same bytes, using the `decomp` CLI (Ghidra analysis plus compile-and-diff scoring). Use whenever the user wants to recover, decompile or reverse a function, class or subsystem from a binary (ELF or PE, stripped or not), make a decompiled candidate binary-accurate, or match original bytes, even if they never mention `decomp`.
---

# Decompile with `decomp`

`decomp` reports facts and scores; it never edits source. You write the source, it tells you
how far the compiled result is from the original bytes. Everything except `analyze` reads a
cache and runs in ~0.1 s, so iterate freely.

Run it as `decomp` (it lives in the repo's `.venv/bin`; activate the venv or add that to PATH).

## Setup, once per target

```sh
decomp check                                      # first stop whenever anything fails: names the fix
decomp detect <bin> --write project.toml          # compiler, flags, starting config
decomp analyze <bin> --variant <name> -C project.toml   # runs Ghidra once (~10 s), fills the cache
```

- Trust the facts `detect` prints (compiler, PIE, static/dynamic, `-std`). The `-O` level is a
  ranked guess from comparing code shape against this machine's compilers, so read its
  `confidence` and margin before accepting it.
- For a **statically linked** target, narrow the sample with `--range 0xLO-0xHI` over the
  program's own code, otherwise the answer is mostly libc's flags (the tool warns when this
  happens).
- Re-running `analyze` on the same bytes is a no-op; `--force` rebuilds. Rebuild an older cache
  to get new tables.
- With several targets cached, pass `--bin <file>` or `--key <key>` (see `decomp status`).

## The loop

1. **Pick the unit.** `decomp find <name | 0xaddr | string | global | vtable>`. In a stripped
   binary there are no names: start from a string or an address, then grow with
   `decomp find <x> --family 2` to get the connected group a request like "the coin system"
   means. `--table` lists what a vtable points at; `--members` shows the class a function
   belongs to.
2. **Read it.** `decomp show <fn>` gives pseudo-code, the original instruction stream, resolved
   references, callers/callees and its place in its class. It accepts the addresses `nm` and
   objdump print as well as Ghidra's.
3. **Write the function** with its real signature and real field offsets (see *Writing the
   candidate*). `decomp types` shows the classes the binary proves, and
   `decomp types --write <dir>` produces a `types.h` to include.
4. **Score it.** `decomp try <fn> cand.cpp --fn <Symbol>`. It builds with the target's own
   variant flags (same compiler, `-O`, `-std`, arch), so the comparison is like for like. Use
   `--include` for headers; put permanent ones in `[include_dirs]`. The printed object path
   lets you run `objdump -dr` on the candidate.
5. **Read the diff and change the thing it names**, then go back to 4.

**Done** when `match >= threshold` **and** `opcode: 0` **and** `relocation: 0`. A high percentage
alone is not done: one wrong callee or table can hide inside it.

**Stuck** (three tries with no change in the match or the categories): re-read the `show`
assembly around the first differing instruction and change your hypothesis, not the syntax. If
only `register:` differences remain, stop: they are not fixable from source. Otherwise report
the best candidate with its remaining diff categories instead of looping.

## Reading a score

| signal | meaning | do |
|---|---|---|
| `opcode: n` | wrong operation: cmov vs branch, imul vs shifts, signed vs unsigned load | fix the operation; `movzbl` vs `movsbl` and `idiv` vs `shrd` are the usual ones |
| `operand: n` | right operation, wrong offset, constant or type | field offsets, struct layout, array element type, truncated buffer bound |
| `relocation: n` | same code shape reaching for something else: another callee, table, or different bytes in it | the `symbols` line names both sides; fix the callee or reproduce the data. Bytes are only compared when both sides know what object they are |
| `register: n` | register allocation only | not yours to fix. `--register-abstract` is reported separately today and does not change the score yet |
| `missing` / `extra` | control flow or size differs | loop form (counted vs conditional), hoisted invariant, inlined vs called helper, early return vs branch |
| `size_delta` large, % high | something is inlined or vectorised that should not be, or the reverse | confirm you are comparing at the variant's own `-O` |

At `-O2` the analysis' range for a function can be shorter than the compiler's (thunk-like
bodies, tail jumps). If the sizes disagree, pass `--size <symbol size>`; a PE's `.pdata` unit is
used automatically.

## Writing the candidate

- **Keep the real signature.** By-value vs by-reference struct arguments, a hidden return
  pointer and `this` are all visible in the first six instructions.
- **Reproduce the data.** Tables (lookup tables, CRC tables, alphabets), bounds and buffer
  capacities are part of the answer. The score matches data references by order and by what
  they reach, so wrong table bytes still show up as `relocation`, but values in `.rodata` are
  only confirmed by strings and your own checks.
- **Match the shape, not the compiler.** A counted loop and a conditional loop with the same
  body are different code, and `while (a > 180.0f) a -= 360.0f;` is not `fmodf`. Prefer what
  the branches and comparisons prove, and let the diff categories say which one the binary has.
- **Offsets are an oracle.** An `operand` diff at a field offset is telling you the struct
  layout; fix the header, then re-score. Unions share storage and padding is observable, so
  check both before trusting a layout.
- **Floats** are only comparable as bit patterns. x87 (`-m32` default) and SSE can differ in the
  last ulp for the same source, so do not "fix" a last-bit difference between variants.
- **Name globals by role** only when the code proves the role. Otherwise keep a neutral name
  and note the offset.

## Notes

- Exit codes: 0 ok, 1 a check or the work failed, 2 bad usage or config, 3 nothing found (or a
  command of a later phase). `try` exits 0 only when the candidate passes.
- `try --json` gives the whole report if you need to parse it.
- `-m32` targets build with `-no-pie -fno-pic`; a PIE link on i386 turns the pc-thunk/GOT
  sequence into `%gs` addressing, so object code and linked code stop matching.
- **PE / MSVC targets:** `detect`, `analyze`, `find` and `show` work; `try` does not yet (no COFF
  candidate support). That is a known, planned gap, so do not debug it mid-task. Read
  `references/msvc.md` for the toolchain, Wine setup and `.pdata` behaviour.