"""X86-0 acceptance (Docs/MSVC-x86-Plan.md §6 X86-0): does the tool describe this machine's
MSVC toolchain honestly, per *target* arch?

	run: .venv/bin/python Tests/tools/check_msvc_x86_toolchain.py

This is a report check, not a compiler check. It compiles nothing, and it is written to pass
**both before and after X86-1**: for every target arch it measures the tree itself and asserts
that what `decomp check` says agrees with it, so the claim under test is the report, not the
machine. Before X86-1 this machine's v141 tree says "x64 only"; after X86-1 it must say
"can build x86 candidates" and the same assertions still hold, read off the new tree.

Groups:

1. **The prefix is found, and how it was found is stated.** A toolchain installed at
   `toolchains/msvc` with its wrappers off PATH is a different gap from a toolchain that is not
   installed, and reporting the second when the first is true is what made `decomp check` say
   "no `cl` on PATH" about a compiler that is sitting in the repo.
2. **Per-target-arch facts match the tree.** For x64 and x86: `VC/Tools/MSVC/<v>/bin/Host*/
   <arch>/cl.exe`, the toolset's `lib/<arch>` CRT import libraries, the SDK's
   `Windows Kits/10/Lib/<v>/{ucrt,um}/<arch>`, and the `<prefix>/bin/<arch>/cl` wrapper are each
   looked for twice - once by the tool, once here - and the answers must be the same.
   `can_build` only when the first three hold.
3. **The sentences.** A toolchain that can only do x64 has to say "no 32-bit target from this
   toolchain" and name the command that would add it; one that can do the arch has to name the
   compiler's own `Host<h>/<arch>` directory, because that - not a flag - is the bitness.
4. **`msvc_sdk(arch=…)` per arch.** The SDK half is its own question: on this machine the x86
   import libraries *are* installed, so "no 32-bit MSVC here" is a toolset gap, not an SDK gap.
   A call with no arch still means x64 (the pre-X86-0 behaviour the other scripts rely on).
5. **What `decomp check` prints for a variant.** A `[variants.*] arch = "x86"` MSVC variant is
   named before any work starts; `arch = "x86-64"` and an ISA-level `arch = "AVX2"` are not; a
   `-m32` GCC variant is named only when the driver really cannot do that target. From X86-2 the
   sentence is the resolver's own, so `check` and `decomp try` cannot disagree, and a toolchain
   that is installed but off PATH is no longer a gap - it is reached by path.

X86-2 (Docs/MSVC-x86-Plan.md §6 X86-2: "`arch` chooses the driver - once") adds:

6. **`arch` is not a flag.** `build_flags` for `cl` with `arch = "x86"` contains no `-m32` and no
   `/arch:IA32`; an ISA `arch` still produces `/arch:AVX2`; GCC's `-m32` is untouched; and a
   path-named `cl` is still an MSVC driver, so it is given `/c /Tp /Fo` and not `-c -o`.
7. **The resolver picks a driver per bitness, and the objects prove it.** For a bare `cl` it names
   `<prefix>/bin/x86/cl` and `bin/x64/cl` with the reason; compiling a real source through
   `compile.build(variant=…)` with each yields a 32-bit and a 64-bit object. A variant that names
   its driver by path is honoured, and a contradiction with `arch` is a warning rather than a
   refusal.
8. **A gap is named before any compiler runs.** A project that pins a toolchain without an x86
   driver gets a sentence about that toolchain, an empty command, and no object file - not a
   compiler error and not a 64-bit object.
9. **The bitness safety net still fires.** The same 32-bit target and a variant whose named driver
   emits x64 must still be refused at the object, with the driver and its bitness named as the
   cause (it was the only thing that knew; now it is the last line of defence, not the first).

Exit: 0 all passed, 1 something came out wrong, 2 there is no MSVC toolchain here to judge.

Run one of these scripts at a time, never several in parallel: they share `cache/ghproj/
candidates-*` and `Tests/build/`, and a sibling's object reads as a bitness mismatch here.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, check, cli, compile, config, extract, toolchain  # noqa: E402

failures: list[str] = []


def expect(ok: bool, detail: str) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def tree_cl(prefix: Path, arch: str) -> list[str]:
	"""An independent read of the same question: which `cl.exe` targets this arch?"""
	return sorted(glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "bin" / "Host*"
		/ arch / "cl.exe")))


def tree_crt(prefix: Path, arch: str) -> bool:
	"""Does the toolset have the CRT import libraries for this target arch?"""
	dirs = (glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "lib" / arch))
		+ glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "lib" / "onecore" / arch)))
	return all(any((Path(d) / name).is_file() for d in dirs) for name in check.MSVC_CRT_LIBS)


def tree_sdk(prefix: Path, arch: str) -> bool:
	"""Does the Windows SDK have its import libraries for this target arch?"""
	return all(bool(glob.glob(str(prefix / "Windows Kits" / "10" / "Lib" / "*" / part
		/ arch / name))) for part, name in check.MSVC_SDK_LIBS)


def wrapper_dir(prefix: Path, arch: str) -> list[str]:
	return sorted(glob.glob(str(prefix / "bin" / arch / "cl")))


def prefix_found() -> "Path | None":
	prefix, why = check.msvc_prefix()
	on_path = check.Tool("cl").found
	expect(prefix is not None, "a toolchain prefix is found: %s (%s)" % (prefix, why))
	if prefix is None:
		return None
	expect((prefix / "VC").is_dir() or (prefix / "Windows Kits").is_dir(),
		"the prefix named is a real toolchain root: %s" % prefix)
	if on_path:
		expect("from the cl on PATH" in why, "found from PATH, and says so: %s" % why)
	else:
		expect("not on PATH" in why,
			"an installed toolchain that is off PATH is reported as that, not as absent: %s" % why)
	return prefix


def per_arch(prefix: Path) -> None:
	targets = check.msvc_target_arches(prefix)
	for arch in check.MSVC_TARGET_ARCHES:
		entry = targets.get(arch)
		expect(entry is not None, "%s is answered for at all" % arch)
		if entry is None:
			continue
		cl, crt, sdk = tree_cl(prefix, arch), tree_crt(prefix, arch), tree_sdk(prefix, arch)
		expect(sorted(c["path"] for c in entry["compilers"]) == cl,
			"%s: the tool finds %s, the tree has %s" % (arch,
				", ".join(c["path"] for c in entry["compilers"]) or "no cl.exe",
				", ".join(cl) or "no cl.exe"))
		expect((not entry["crt"]["missing"]) == crt,
			"%s: toolset CRT libraries - tool says %s, the tree says %s"
			% (arch, "complete" if not entry["crt"]["missing"] else "missing",
			"complete" if crt else "missing"))
		expect((not entry["sdk"]["missing"]) == sdk,
			"%s: Windows SDK libraries - tool says %s, the tree says %s"
			% (arch, "complete" if not entry["sdk"]["missing"] else "missing",
			"missing" if not sdk else "complete"))
		expect(entry["can_build"] == (bool(cl) and crt and sdk),
			"%s: can_build=%s agrees with those three facts" % (arch, entry["can_build"]))
		expect(entry["on_path"] == (check.arch_on_path() == arch),
			"%s: on_path=%s is judged by the wrapper directory on PATH (%s)"
			% (arch, entry["on_path"], check.arch_on_path() or "no cl on PATH"))
		expect(bool(entry["wrapper"]) == bool(wrapper_dir(prefix, arch)),
			"%s: the wrapper is reported as %s, the tree has %s" % (arch,
				entry["wrapper"] or "none", ", ".join(wrapper_dir(prefix, arch)) or "none"))
		if entry["compilers"]:
			# The bitness is the directory the compiler lives in, so the report has to name it.
			expect(any("host" in c and c["host"].lower().startswith("host") for c in entry["compilers"]),
				"%s names the host directory of its cl.exe: %s"
				% (arch, ", ".join(c["host"] for c in entry["compilers"])))
			expect("cl for %s targets" % arch in entry["detail"],
				"%s: the line says which cl it found" % arch)
		else:
			expect("no cl.exe" in entry["detail"] or "no 32-bit target" in entry["detail"],
				"%s: the line names the missing compiler rather than a symptom" % arch)
			expect(bool(entry["fix"]), "%s: a missing target comes with the command to add it" % arch)
			if arch == "x86" and targets.get("x64", {}).get("compilers"):
				expect("x64 only: no 32-bit target from this toolchain" in entry["detail"],
					"x86 is called what it is: x64 only, not \"complete\"")
				expect("--architecture" in entry["fix"] and "install.sh" in entry["fix"],
					"the fix names the install that would add the target: %s" % entry["fix"][:160])
		# Which half is missing has to be separable: the SDK libraries for x86 are installed on
		# this machine, so an x86 gap here is the toolset's and the report must not blur them.
		if sdk != crt:
			expect(("Windows SDK libraries for %s: all of them are there" % arch in entry["detail"])
				== sdk, "%s: the SDK half is reported separately from the toolset half" % arch)


def sdk_per_arch(prefix: Path) -> None:
	x64 = check.msvc_sdk()
	expect(x64.get("arch") == "x64", "msvc_sdk() with no arch still answers about x64")
	expect(bool(x64.get("complete")) == tree_sdk(prefix, "x64"),
		"msvc_sdk() (x64) still agrees with the tree: %s" % x64.get("detail"))
	for arch in check.MSVC_TARGET_ARCHES:
		sdk = check.msvc_sdk(arch=arch)
		expect(sdk.get("arch") == arch and bool(sdk.get("complete")) == tree_sdk(prefix, arch),
			"msvc_sdk(arch=%s) = %s (%s)" % (arch, sdk.get("complete"), sdk.get("detail")))
		if not sdk.get("complete"):
			expect(arch in sdk.get("detail", "") or "placeholder" in sdk.get("detail", ""),
				"a negative SDK answer names what is missing for %s" % arch)


def report_for(variants: dict) -> list:
	"""Run the real startup check over a synthetic config; nothing here compiles anything."""
	with tempfile.TemporaryDirectory(prefix="x86check-") as directory:
		path = Path(directory) / "project.toml"
		body = ["[gate]\nrequire = \"none\"\n"]
		for name, values in variants.items():
			body.append("[variants.%s]\n" % name)
			body += ["%s = %r\n" % (key, value) for key, value in values.items()]
		path.write_text("".join(body))
		cfg = config.load(str(path))
		report = check.check_all(cfg, want_compilers=False)
	return [(item.name, item.level, item.detail) for item in report.items]


def variants_asked(prefix: Path) -> None:
	"""A variant whose arch no installed driver can serve is named before any work starts."""
	x64_ok = check.msvc_target_arches(prefix).get("x64", {}).get("can_build")
	x86 = check.msvc_target_arches(prefix).get("x86", {})
	items = report_for({
		"msvc-x86": {"compiler": "cl", "optimize": 0, "arch": "x86", "crt": "mt"},
		"msvc-x64": {"compiler": "cl", "optimize": 0, "arch": "x86-64"},
		"msvc-isa": {"compiler": "cl", "optimize": 2, "arch": "AVX2"},
		"gcc-m32": {"compiler": "g++", "optimize": 0, "arch": "x86"},
	})
	named = {name[len("arch "):]: (level, detail)
		for name, level, detail in items if name.startswith("arch ")}
	target_lines = {name: (level, detail) for name, level, detail in items
		if name.startswith("msvc target ")}
	expect(set(target_lines) == {"msvc target x64", "msvc target x86"},
		"`decomp check` prints the per-target-arch table: %s" % sorted(target_lines))
	expect(target_lines.get("msvc target x86", ("?",))[0] in ("warn", "ok"),
		"a toolchain that cannot do x86 is a fact, not a fault: %s"
		% target_lines.get("msvc target x86", ("absent",))[0])
	if not x86.get("can_build"):
		expect("msvc-x86" in named, "an arch the toolchain cannot serve is named per variant")
		level, detail = named.get("msvc-x86", ("?", ""))
		expect(level == "warn", "…as a warning, so reading a 32-bit target still works: %s" % level)
		expect("cannot be built here" in detail or "only half installed" in detail,
			"…saying which half is missing, not a symptom: %s" % detail[:200])
		if not tree_cl(prefix, "x86"):
			expect("no 32-bit target" in detail,
				"…and calling an x64-only toolchain that: %s" % detail[:200])
		known = {os.path.relpath(os.path.dirname(p), prefix) for p in tree_cl(prefix, "x64")}
		expect(any(where in detail for where in known) or "not on PATH" in detail,
			"…naming what this toolchain does have, so the gap is locatable: %s" % detail[:200])
	else:
		print("      (x86 is buildable here; the variant is only named if it is unreachable)")
	expect("msvc-x64" not in named or x64_ok is False
		or "not on PATH" in named["msvc-x64"][1],
		"an x64 MSVC variant is never told it cannot be built here when this toolchain serves "
		"x64: %s" % named.get("msvc-x64", ("not named", ""))[1][:200])
	expect("msvc-isa" not in named,
		"arch = \"AVX2\" is an ISA level, not a bitness, and is not contradicted (%s)"
		% sorted(named))
	multilib = subprocess.run(["g++", "-m32", "-x", "c", "-c", "-o", "/dev/null", "-"],
		input="", capture_output=True, text=True, timeout=120).returncode == 0
	expect(("gcc-m32" in named) != multilib,
		"a -m32 GCC variant is named only if the driver really cannot do it (multilib here: %s)"
		% multilib)

PROBE = "int da_probe(int a, int b) { return a + b * 3; }\n"


def flags_are_not_bitness() -> None:
	"""X86-2: `arch` selects a driver for `cl`; it is not a flag (Docs/MSVC-x86-Plan.md X86-2)."""
	x86 = toolchain.build_flags({"compiler": "cl", "optimize": 0, "arch": "x86", "crt": "mt"})
	x64 = toolchain.build_flags({"compiler": "cl", "optimize": 0, "arch": "x86-64", "crt": "mt"})
	expect("-m32" not in x86, "no GCC flag reaches cl: %s" % x86)
	expect("/arch:IA32" not in x86,
		"and no /arch:IA32 either - that is an ISA level, not a bitness: %s" % x86)
	expect(x86 == x64,
		"a 32-bit and a 64-bit MSVC variant differ in the driver, not in the flags: %s / %s"
		% (x86, x64))
	isa = toolchain.build_flags({"compiler": "cl", "optimize": 2, "arch": "AVX2"})
	expect("/arch:AVX2" in isa, "an ISA level is still a flag: %s" % isa)
	gcc = toolchain.build_flags({"compiler": "g++", "optimize": 0, "arch": "x86"})
	expect("-m32" in gcc, "GCC still asks for 32-bit the only way it can: %s" % gcc)
	expect(toolchain.msvc("toolchains/msvc/bin/x86/cl") and not toolchain.msvc("g++"),
		"a path-named cl is the same driver as a bare cl")
	command = toolchain.driver_form("toolchains/msvc/bin/x64/cl", ["/Od"], [Path("in.cpp")],
		Path("out.obj"))
	expect("/Tp in.cpp" not in command and "/Tcin.cpp" not in command
		and any(str(part).startswith("/Tp") for part in command)
		and any(str(part).startswith("/Fo") for part in command),
		"and it is given cl's own argument form: %s" % " ".join(command))


def resolver_picks_a_driver(prefix: Path) -> None:
	"""One resolver, one driver per bitness - and the objects it builds prove which is which."""
	x86 = toolchain.compiler_for({"compiler": "cl", "optimize": 0, "arch": "x86"})
	x64 = toolchain.compiler_for({"compiler": "cl", "optimize": 0, "arch": "x86-64"})
	expect(x86.name == str(prefix / "bin" / "x86" / "cl"),
		"arch = \"x86\" resolves to the x86 driver, not to whatever cl a shell has: %s" % x86.name)
	expect(x64.name == str(prefix / "bin" / "x64" / "cl"),
		"arch = \"x86-64\" resolves to the x64 driver: %s" % x64.name)
	expect(bool(x86.why) and str(prefix) in x86.why and bool(x86.arch_from),
		"and says where it came from: %s / %s" % (x86.why, x86.arch_from))
	expect(not x86.refused and not x64.refused, "neither is refused on this machine")
	with tempfile.TemporaryDirectory(prefix="x86driver-") as directory:
		here = Path(directory)
		source = here / "probe.cpp"
		source.write_text(PROBE)
		for variant, want, driver in (({"arch": "x86"}, 32, x86), ({"arch": "x86-64"}, 64, x64)):
			body = dict(variant, compiler="cl", optimize=0, crt="mt")
			result = compile.build([source], here / ("probe-%s.obj" % variant["arch"]),
				flags=toolchain.build_flags(body), variant=body)
			expect(result.ok and not result.refused,
				"the resolved driver runs: %s" % (result.diagnostics or "")[:200])
			expect(result.driver == driver.name and result.arch == toolchain.arch_bitness(variant["arch"]),
				"the build reports the driver it used: %s (%s)" % (result.driver, result.arch))
			object_file = extract.CandidateObject(here / ("probe-%s.obj" % variant["arch"]))
			expect(object_file.bits == want,
				"and the object really is %d-bit (it is %s): %s"
				% (want, object_file.bits, result.command[0]))
			expect(toolchain.driver_bitness(result.command[0])[0]
				== toolchain.arch_bitness(variant["arch"]),
				"the driver's own path says the bitness the object came out as")
	# A variant that names its driver by path is honoured, contradiction and all: the object-level
	# bitness check is what stops it, and that has to stay reachable (group 9).
	contradiction = toolchain.compiler_for({"compiler": str(prefix / "bin" / "x64" / "cl"),
		"optimize": 0, "arch": "x86"})
	expect(contradiction.name == str(prefix / "bin" / "x64" / "cl") and not contradiction.refused,
		"a named driver is not silently replaced: %s" % (contradiction.name or contradiction.gap))
	expect(bool(contradiction.conflict) and "x86" in contradiction.conflict,
		"the contradiction is said out loud: %s" % contradiction.conflict)
	# Rule order: on PATH first, then the installed toolchain by path, then a named gap.
	old_path = os.environ["PATH"]
	try:
		os.environ["PATH"] = str(prefix / "bin" / "x64") + os.pathsep + old_path
		on_path = toolchain.compiler_for({"compiler": "cl", "optimize": 0, "arch": "x86-64"})
		expect(on_path.name == str(prefix / "bin" / "x64" / "cl") and "PATH" in on_path.why,
			"a cl on PATH is the driver for that bitness: %s (%s)" % (on_path.name, on_path.why))
		off_path = toolchain.compiler_for({"compiler": "cl", "optimize": 0, "arch": "x86"})
		expect(off_path.name == str(prefix / "bin" / "x86" / "cl"),
			"a target the PATH driver cannot do is taken from the installed toolchain: %s"
			% off_path.name)
		expect(any("not on PATH" in item or "produces x64" in item for item in off_path.tried),
			"and the PATH driver that was ruled out is in the record: %s" % off_path.tried)
	finally:
		os.environ["PATH"] = old_path


def gap_before_any_compiler() -> None:
	"""A toolchain that cannot serve the variant is named, and no compiler is run (X86-2)."""
	with tempfile.TemporaryDirectory(prefix="x86gap-") as directory:
		here = Path(directory)
		pinned = here / "no-x86-toolchain"
		(pinned / "bin" / "x64").mkdir(parents=True)
		(pinned / "bin" / "x64" / "cl").write_text("#!/bin/sh\nexit 1\n")
		source = here / "probe.cpp"
		source.write_text(PROBE)
		(here / "project.toml").write_text(
			'[gate]\nrequire = "none"\n\n[msvc]\nprefix = %r\n\n[variants.msvc-x86]\n'
			'compiler = "cl"\noptimize = 0\narch = "x86"\n' % str(pinned))
		cfg = config.load(str(here / "project.toml"))
		prefix, whence = config.msvc_prefix(cfg)
		expect(prefix == pinned and "project.toml" in whence,
			"the config pins a toolchain, and says so: %s (%s)" % (prefix, whence))
		_name, body = config.variant(cfg, "msvc-x86")
		driver = toolchain.compiler_for(body, prefix=prefix, prefix_from=whence)
		expect(driver.refused and not driver.name, "the resolver refuses rather than guessing: %s"
			% (driver.name or driver.gap))
		expect("x86" in driver.gap and str(pinned) in driver.gap,
			"and names the target and the toolchain that lacks it: %s" % driver.gap)
		expect(any(str(pinned) in item for item in driver.tried),
			"the pin is in the record of what was looked at: %s" % driver.tried)
		object_path = here / "probe.obj"
		result = compile.build([source], object_path, flags=toolchain.build_flags(body),
			variant=body, cfg=cfg)
		expect(result.refused and result.command == [],
			"no compiler was invoked to learn this: %s" % result.command)
		expect(not object_path.exists(), "and nothing was written: %s" % object_path)
		expect("x86" in result.diagnostics, "the build result carries the reason: %s"
			% result.diagnostics)
		expect(any("cannot be built" in line or "none" in line
			for line in compile.describe(result)),
			"and the report says the same: %s" % compile.describe(result))


def safety_net_still_fires() -> None:
	"""The object-level bitness refusal is still there, now with the driver named as the cause."""
	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	stripped = TESTS / "build" / "gcc-o0-x86" / "da_tests.stripped"
	key = TESTS / "build" / "gcc-o0-x86" / "answer_key.json"
	if not stripped.is_file() or not key.is_file():
		print("      (no 32-bit benchmark here - Tests/eval.py build --variant gcc-o0-x86)")
		return
	identity = cache.target_key(stripped)
	status = store.status(identity["key"])
	if not status.get("complete"):
		print("      (this 32-bit target is not analysed here - decomp analyze it first)")
		return
	conn = cache.open_readonly(Path(status["db"]))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	row = None
	for unit in json.loads(key.read_text())["units"]:
		found = cache.resolve_function(conn, hex(int(unit["address"]) + offset))
		if found:
			row = found[0]
			break
	if row is None:
		expect(False, "no cached function to compare against in %s" % status["db"])
		return
	with tempfile.TemporaryDirectory(prefix="x86net-") as directory:
		here = Path(directory)
		(here / "project.toml").write_text(
			'[gate]\nrequire = "none"\n\n[ghidra]\ncache_dir = %r\n\n[variants.wrong-driver]\n'
			'compiler = %r\noptimize = 0\narch = "x86"\n'
			% (str(store.root), str(REPO / "toolchains" / "msvc" / "bin" / "x64" / "cl")))
		source = here / "probe.cpp"
		source.write_text(PROBE)
		guess = cli.score_candidate(config.load(str(here / "project.toml")), conn, meta, row,
			[source], variant="wrong-driver", fn="?da_probe@@YAHHH@Z",
			object_dir=here / "objects")
		message = guess.get("error") or ""
		expect(guess.get("verdict") is None and "64-bit" in message,
			"a 64-bit object against a 32-bit analysis is still refused: %s" % message[:200])
		expect("bin/x64/cl" in message,
			"and the driver that emitted it is named as the cause: %s" % message[:300])
		expect(guess.get("error_code") == cli.EXIT_USAGE,
			"as a usage error, not a failed decompilation: %s" % guess.get("error_code"))
		expect("arch" in message and "x86" in message,
			"with the variant that asked for the other one: %s" % message[:300])
	conn.close()


def main() -> int:
	print("=== 1. the prefix, and how it was found ===")
	prefix = prefix_found()
	if prefix is None:
		print("\nNo MSVC toolchain installed here (nothing on PATH, nothing under toolchains/).\n"
			"Nothing was judged - install one (Docs/Setup.md §6) and re-run this check.")
		return 2
	print("\n=== 2. per-target-arch facts (the tree is measured twice) ===")
	per_arch(prefix)
	print("\n=== 3. the sentences ===")
	targets = check.msvc_target_arches(prefix)
	for arch in check.MSVC_TARGET_ARCHES:
		print("  %s: %s" % (arch, targets[arch]["summary"]))
		print("      %s" % targets[arch]["detail"])
	print("\n=== 4. the Windows SDK, per target arch ===")
	sdk_per_arch(prefix)
	print("\n=== 5. what a variant is told before any work starts ===")
	variants_asked(prefix)
	print("\n=== 6. `arch` is not a flag (X86-2) ===")
	flags_are_not_bitness()
	print("\n=== 7. one resolver, one driver per bitness (X86-2) ===")
	resolver_picks_a_driver(prefix)
	print("\n=== 8. a gap named before any compiler runs (X86-2) ===")
	gap_before_any_compiler()
	print("\n=== 9. the bitness safety net still fires (X86-2) ===")
	safety_net_still_fires()

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_msvc_x86_toolchain: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
