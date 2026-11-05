---
name: decompileanything
description: Reverse engineer and decompile shipped software with plain local CLI tools. Two modes. (1) Understand a target fast - Electron/JS bundles, native Mach-O/ELF/PE, Go/Rust/.NET/Flutter/WASM binaries, APKs, SQLite, pcaps, firmware, websites - to explain how a feature works, extract versions and dependencies, compare builds, or rebuild a feature. (2) Matching decompilation - recover a function or class from a compiled binary as source that recompiles to the same bytes, using the `decomp` CLI (Ghidra analysis plus compile-and-diff scoring). Use for any request to reverse, decompile, inspect, match or recreate behaviour from a binary, bundle or app, even if no tool is named.
---

# Reverse engineering and decompilation

Pick the mode first; it decides how much work is worth doing.

| The user wants | Mode | Go to |
|---|---|---|
| to know what it is, how a feature works, what versions or dependencies it has, what changed between builds, or to rebuild a feature | **Understand** | Rules, First move, Router |
| source for specific functions that compiles back to the same bytes | **Match** | Matching decompilation (uses `decomp`) |

Most requests are Understand. Many Match jobs start with a short Understand pass to find the
right functions and the build settings.

## Rules

- Work on a copy (`cp -c` on APFS is instant, plain `cp` elsewhere). Put each extraction in a new
  directory under `$TMPDIR/re/<name>` and reuse an extraction if one exists.
- Route by `file -b T` and the magic bytes first. Run the cheapest inventory next. Only then
  decompile or read code. Inventories are cheap and usually answer the question.
- `rg` skips hidden and ignored files, and bundlers hide code (Electron: `.webpack/`, `.vite/`).
  Always search extracted trees with `rg -uu`.
- Never print a big or minified file. Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | head`. Dump a
  disassembly once to a file, then search that file.
- Batch independent probes into ONE shell call with `;` and `echo '--- name'` markers (quote the
  marker: zsh expands a bare `==x`). Cap every output with `head` or `-m`.
- Answer from evidence. Mark each claim **seen** (cite file:offset, symbol or string) or
  **inferred**. A fact you did not find is **unknown**, not "absent". Static reading is not
  observed execution.
- A missing tool is not a blocker: use the fallback in the same row, or install it if the user
  allows it (see Install).
- Round trips cost more than bytes. Aim for 2-4 commands for an Understand question: one batched
  recon call, one or two targeted slices, then answer. Stop when every item asked has evidence,
  and do not re-verify what you already saw.
- The commands below are macOS-flavoured (`otool`, `lipo`, `codesign`). On Linux use `readelf`,
  `objdump -d`, `nm -D`; `llvm-objdump` and `llvm-nm` work on every format.

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
| Native code logic (to read, not to match) | `otool -tV T > $D/dis.txt` (or `llvm-objdump -d --no-show-raw-insn -C`). Find the function: `rg -n '^_?.*Name.*:$'`. Read the call/string trail: `awk '/^FUNC:/{p=1} p&&/^[_a-zA-Z].*:$/&&!/FUNC/{exit} p' dis.txt \| rg 'bl\|call\|literal\|cmp'`. otool labels string literals and stubs inline, which is often enough. For real pseudocode: Ghidra `analyzeHeadless $D p -import T -postScript DecompileAll.java -deleteProject` or `r2 -qc 'aaa; pdc @ sym.X' T`. To recover source that must recompile to the same bytes, use Matching decompilation below instead. |
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

- Strings and imports first. On a small binary, `nm -u` + `strings` + the export list usually
  answer "what does it do" with no disassembly.
- To find who uses a string: get its address from `otool -tV` "literal pool for" comments, or
  `rg -n 'literal pool for: "X'`. Then find the enclosing function label above that line.
- A C++ name in a `bl` target already tells you the protocol (for example `getpeereid`, `write`,
  `std::hash`). Read the call sequence, not every instruction.
- For JS, go from the native/JS boundary inward: find the native call, then its caller class,
  then the IPC registration, then the renderer/preload.
- Comparing versions: diff the inventories (`nm`, the module list, `go version -m`) before you
  diff any code.
- Rebuilding a feature: write the minimal reimplementation, then test it against the original
  (same inputs, same outputs).

# Matching decompilation with `decomp`

Use this when the goal is source that recompiles to the same bytes. `decomp` reports facts and
scores; it never edits source. You write the source, it tells you how far the compiled result is
from the original. Everything except `analyze` reads a cache and runs in ~0.1 s, so iterate
freely. Run it as `decomp` (it lives in the repo's `.venv/bin`; activate the venv or add that
to PATH). It currently supports x86 (32 and 64-bit) for scoring.

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
   objdump print as well as Ghidra's (a PIE is loaded at `0x100000`; the cache records the gap).
3. **Write the function** with its real signature and real field offsets (see *Writing the
   candidate*). `decomp types` shows the classes the binary proves, and
   `decomp types --write <dir>` produces a `types.h` to include (field names are placeholders
   like `f0x8`; the header says which types are guesses).
4. **Score it.** `decomp try <fn> cand.cpp --fn <Symbol>`. It builds with the target's own
   variant flags (same compiler, `-O`, `-std`, arch), so the comparison is like for like. Use
   `--include` for headers; put permanent ones in `[include_dirs]`. The printed object path
   lets you run `objdump -dr` on the candidate. `--fn` is needed unless the object defines
   exactly one function.
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
| `relocation: n` | same code shape reaching for something else: another callee, table, or different bytes in it | the `symbols` line names both sides; fix the callee or reproduce the data. Bytes are only compared when both sides know what object they are (an anonymous `.rodata` pool is laid out per build) |
| `register: n` | register allocation only | not yours to fix. `--register-abstract` is reported separately today and does not change the score yet |
| `missing` / `extra` | control flow or size differs | loop form (counted vs conditional), hoisted invariant, inlined vs called helper, early return vs branch |
| `size_delta` large, % high | something is inlined or vectorised that should not be, or the reverse | confirm you are comparing at the variant's own `-O`; never compare -O0 asm to -O2 asm |

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
- **Judge sizes per variant.** At `-O0` every function starts with a frame, so tiny units are
  30+ bytes; the sub-32-byte bucket only appears at `-O2`.
- **Name globals by role** only when the code proves the role. Otherwise keep a neutral name
  and note the offset.

## How scoring works, and its limits

- `try` compares symbolically: branches inside the function become function-relative labels, and
  calls and data references become positional tokens (`SYM0`, `DAT0`) matched by order, then
  checked by what they reach (a real name both sides know, the bytes there, the size). The
  score therefore does not depend on the link address.
- `try --json` gives the whole report if you need to parse it.
- `decomp types` recovers C++ structure from Itanium-ABI RTTI (class names, bases, vtable slots,
  constructors and destructors, member offsets and widths). Nothing is claimed for MSVC/PE
  targets yet.
- `-m32` targets build with `-no-pie -fno-pic`; a PIE link on i386 turns the pc-thunk/GOT
  sequence into `%gs` addressing, so object code and linked code stop matching.
- Exit codes: 0 ok, 1 a check or the work failed, 2 bad usage or config, 3 nothing found (or a
  command of a later phase). `try` exits 0 only when the candidate passes.
- **PE / MSVC targets:** `detect`, `analyze`, `find` and `show` work; `try` does not yet (no COFF
  candidate support). That is a known, planned gap, so do not debug it mid-task. Read
  `references/msvc.md` for the toolchain, Wine setup and `.pdata` behaviour.
- Working on `decomp` itself or its benchmark: `references/decomp-dev.md`.

## Install (only on request)

`brew install jadx apktool radare2 binwalk wabt wireshark ghidra` · `npm i -g @electron/asar` ·
`dotnet tool install -g ilspycmd` · `cargo install cargo-audit`.
