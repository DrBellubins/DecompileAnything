"""MS-4 acceptance (Docs/MSVC-Plan.md §7): does the tool *say what an MSVC build is*?

	run: .venv/bin/python Tests/tools/check_msvc_detect.py

MS-0 made the PE path run, MS-1 read its function table, MS-2/MS-3 put a compiler on the
machine and read a COFF candidate. This is the report side: given a PE target, what can the
tool state, and does it state it from the file rather than from a guess. Seven groups:

1. **The toolset, read twice and compared.** The Rich header's product ids have names, and one
   of them (258, "Linker1400") is link.exe's own record: its build number *is* the fourth
   component of that linker's version. Asserted here two ways - on the shipped target
   (build 25711 reads as 14.12, which is what its optional header says, so `agree` is true),
   and on a PE linked on this machine by the toolchain of Docs/Setup.md §6, where the Rich
   build must equal the build `link.exe` prints in its own banner. The records that are not a
   tool (id 1) and the one whose build number is a constant of the linker's stub objects
   (id 147, build 30729) must *not* be used as an identity: the same 30729 appears in a
   Windows OS binary of 2018 and in a file built here today, which is the measurement that
   says so.
2. **The language and the runtime, from names.** A decorated import (`?terminate@@YAXXZ`)
   proves C++; an msvcrt.dll import does not. The CRT family says /MD vs /MT and which
   runtime generation. MS-0 deliberately left `language` unset for a PE; making the claim now
   means naming the evidence, so `language_proof` is asserted with it.
3. **The standard level it can honestly name.** MSVC decoration encodes no `/std:` level; what
   the toolset and the runtime bound is the level that generation defaults to and the levels
   it has a switch for.
4. **The flags a variant would have to carry**: /Od|/O1|/O2 are three different flags, /MT vs
   /MD, /GS-, /GL with /LTCG on the link - and the config `detect --write` produces for a PE
   parses and carries them.
5. **The shape profile for MSVC code**, measured with the installed `cl`: /Od must be far from
   /O1|/O2 on the MSVC features (locals off `%rsp`, arguments to their home slots), and
   `detect` on the shipped target must answer an optimising level while reporting /O1 against
   /O2 as a class, not a level. `/GS` on must be reported from the shape.
6. **Sampling real units**: the shape sample for a PE comes from `.pdata`, and every sampled
   body starts at a record the file names - not at a `ret` boundary. And the ELF path is
   unchanged: still the ret-cut sample, still scored on the Itanium features.
7. **A 32-bit MSVC target is described in its own dialect** (Docs/MSVC-x86-Plan.md X86-5).
   Measured on this machine's `bin/x86/cl`: the x64 feature set (`rspmem`, `argstore`, the
   cookie-xor-`%rsp` of /GS) reads 0.000 at /Od, /O1 and /O2, so it cannot carry an answer; the
   i386 set - the `%ebp` frame, locals read through it, the cookie xor-ed with the frame register -
   separates /Od from /O1|/O2 by a wide margin, while /O1 and /O2 stay close together. Asserted
   against a known answer: the `msvc-o0-x86` build of X86-4 was built here at /Od, and `detect`
   sampling the cached analysis (the only sample of a 32-bit PE with real function boundaries) has
   to answer 0. On the shipped 32-bit game the readings are non-zero, the probe driver is the x86
   one, and the era gap is stated *in the answer* - the file says `link.exe 8.0`, so a v141 `-O`
   reading is not that file's. Plus the dialect guards: no GCC flag for a `built by msvc` file, no
   x86-64 ISA claim for a 32-bit image, and the bitness disagreement between an x64 driver and a
   32-bit file answered in the one place `check`, `try` and `detect` all read from.

Exit: 0 everything passed, 1 a fact came out wrong, 2 the target or the MSVC toolchain is
missing (nothing was judged, which is not the tool failing).
"""

from __future__ import annotations

import sys
import tempfile
import tomllib
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, check, cli, config, extract, fidelity, spawn, toolchain  # noqa: E402

TARGET = TESTS / "Proprietary" / "notepad.exe"
X86_TARGET = TESTS / "Proprietary" / "deadrising2.exe"     # PE32, link.exe 8.0 (Docs/MSVC-x86-Plan.md §3)
X86_BUILD = TESTS / "build" / "msvc-o0-x86" / "da_tests.stripped"  # built here at /Od: known answer
GCC_STRIPPED = TESTS / "build" / "gcc-o0" / "da_tests.stripped"

# Docs/MSVC-Plan.md §2: what this file carries.
TOOL_BUILD = 25711
LINKER_VERSION = "14.12"
NOT_A_TOOL_BUILD = 30729  # id 147 (Implib900), the same in a file linked here today
DECORATED = "?terminate@@YAXXZ"  # imported from msvcrt.dll: a C++ runtime function
COMPILANDS = {"c": 23, "cpp": 5, "asm": 3, "ltcg-c": 25}

# One probe program built by the installed `cl`, twice through the driver (compile and link).
# A deadline, not an estimate: see `build_probe`.
PROBE_BUILD_TIMEOUT = 300
PROBE_FAILURE = ""  # why the last probe did not build, for whoever asks about it

failures: list[str] = []


def expect(ok: bool, detail: str) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def main() -> int:
	if not TARGET.is_file():
		print("%s: not here - gitignored; see Docs/MSVC-Plan.md §2" % TARGET)
		return 2
	cl = check.msvc_tools()["cl"]
	print("=== 1. the toolset, read twice (Rich product ids + the optional header) ===")
	note = check_toolset()
	print("\n=== 2. language and runtime, from the names the file carries ===")
	check_language(note)
	print("\n=== 3. the standard level an MSVC target can honestly be given ===")
	check_std(note)
	print("\n=== 4. the flags a variant has to carry, and the config they are written into ===")
	check_flags(note)
	if not cl.found:
		print("\nno `cl` on PATH: groups 5 and 6's probe need it. Install a toolset with\n"
			"  toolchains/install_msvc.py  and  PATH=<prefix>/bin/x64:$PATH\n"
			"Nothing above this line was judged by it.")
		print("\n%s" % ("FAILURES: " + ", ".join(failures) if failures else
			"checked what can be checked without a compiler - the MSVC probe was skipped"))
		return 1 if failures else 2
	with tempfile.TemporaryDirectory(prefix="ms4-") as directory:
		work = Path(directory)
		print("\n=== 5. the MSVC shape profile, measured with this toolchain ===")
		check_shape(work)
	print("\n=== 6. the ELF path: still its own sample, still its own features ===")
	check_elf_unchanged()
	with tempfile.TemporaryDirectory(prefix="ms4-x86-") as directory:
		print("\n=== 7. a 32-bit MSVC target, in its own dialect (X86-5) ===")
		check_i386(Path(directory))

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_msvc_detect: OK")
	return 0


# --------------------------------------------------------------------------------------
# 1. the toolset


def check_toolset() -> dict:
	note = toolchain.build_note(TARGET)
	expect(not note.get("error"), "the build note reads %s" % TARGET.name)
	toolset = note.get("toolset") or {}
	identity = toolset.get("rich") or {}
	linker = identity.get("linker") or {}
	expect(linker.get("id") == 258 and linker.get("build") == TOOL_BUILD,
		"the Rich header's linker record is id 258 (Linker1400) build %d: got %r"
		% (TOOL_BUILD, linker))
	expect(identity.get("linker_version") == LINKER_VERSION,
		"build %d reads as toolset %s" % (TOOL_BUILD, LINKER_VERSION))
	expect(toolset.get("agree") is True,
		"the Rich reading and the optional header's %s agree" % LINKER_VERSION)
	# The records that identify no toolset must stay out of the answer.
	records = {item["id"]: item for item in identity.get("records", [])}
	expect(records.get(1, {}).get("build") == 0,
		"id 1 (Import0) is recorded as a count, not a tool: build 0")
	expect(records.get(147, {}).get("build") == NOT_A_TOOL_BUILD and linker.get("id") == 258,
		"id 147 carries build %d, which is not the toolset - the identity comes from id 258"
		% NOT_A_TOOL_BUILD)
	counts = identity.get("compilands", {})
	expect(counts == COMPILANDS, "compiland counts from the front-end records: %r, the file "
		"says %r" % (counts, COMPILANDS))
	expect((counts.get("ltcg-c") or 0) > 0 and note.get("ltcg"),
		"/GL confirmed from the object side too (%d LTCG compiland records), independent of "
		"the POGO directory" % counts.get("ltcg-c", 0))
	for line in toolchain.note_lines(note)[:9]:
		print("    " + line)

	# The measured anchor: the tool that is installed here writes its own build into id 258,
	# and its banner says the same version. If this ever disagrees, the table is wrong.
	tool = check.msvc_tools()["link"]
	if tool.found and tool.version:
		banner = re_build(tool.version)
		probe = build_probe(EXE_SOURCE, "ms4_anchor")
		if probe:
			made = toolchain.build_note(probe)
			anchor = ((made.get("toolset") or {}).get("rich") or {}).get("linker") or {}
			expect(anchor.get("build") == banner,
				"this machine's link.exe %s writes Rich build %s: the table is anchored on a "
				"measured pair, not on a lookup" % (tool.version, banner))
			expect(toolchain.msvc_build_version(anchor.get("build")) ==
				(made.get("linker_version") or ""),
				"and build %s reads back as the version its header records (%s)"
				% (anchor.get("build"), made.get("linker_version")))
	return note


def re_build(version: str) -> int:
	"""The build component of a tool version - the number that goes in the Rich header.

	`14.12.25835.7`: the family is two components and the build is the five-digit one, so it
	is found by size rather than by position (a banner may or may not carry a fourth part).
	"""
	for part in str(version).split("."):
		if part.isdigit() and len(part) >= 4:
			return int(part)
	return -1


EXE_SOURCE = """
#include <cstdio>
int add(int a, int b) { return a + b; }
int main() { printf("%d\\n", add(2, 3)); return 0; }
"""

CPP_SOURCE = """
#include <vector>
#include <string>
#include <cstdio>
int sum(const std::vector<int>& v) { int s = 0; for (int x : v) s += x; return s; }
int main() { std::vector<int> v{1,2,3}; std::string s("x");
	printf("%d %zu\\n", sum(v), s.size()); return 0; }
"""


def build_probe(source: str, name: str, override: dict | None = None) -> Path | None:
	"""One PE built by the installed toolchain (the driver of `decomp`, not a hand-written
	line). `override` replaces variant keys - which is how a /MD program is built here when the
	benchmark's own MSVC variant is /MT on purpose.

	A probe that does not answer is reported, not waited for: the deadline is real because
	`decomp.spawn` kills the whole wrapper process group (see its docstring), which is the only
	way a `cl` under Wine with no Windows prefix ever stops.
	"""
	cfg = config.load(str(TESTS / "project.toml"))
	try:
		_name, variant = config.variant(cfg, "msvc-o0")
	except config.ConfigError:
		return None
	variant = dict(variant, **(override or {}))
	work = Path(tempfile.mkdtemp(prefix="ms4-probe-"))
	path = work / ("%s.cpp" % name)
	path.write_text(source)
	exe = work / ("%s.exe" % name)
	# /Fo names the object too: without it `cl` writes it into the *caller's* directory, which
	# is the repo when this runs from there.
	command = [variant["compiler"], "/Fe:%s" % exe, "/Fo%s" % (work / ("%s.obj" % name))] \
		+ toolchain.build_flags(variant) + ["/Tp%s" % path, "/link",
		*toolchain.link_flags(variant)]
	finished = spawn.run(command, timeout=PROBE_BUILD_TIMEOUT)
	if finished.returncode != 0:
		global PROBE_FAILURE
		PROBE_FAILURE = ("did not answer in %ds" % PROBE_BUILD_TIMEOUT if finished.timed_out
			else (finished.output or "the compiler printed nothing").splitlines()[0])
		if finished.note:
			PROBE_FAILURE += " - " + finished.note
		return None
	return exe


# --------------------------------------------------------------------------------------
# 2. language and runtime


def check_language(note: dict) -> None:
	expect(note.get("language") == "c++" and DECORATED in (note.get("decorated") or []),
		"C++ claimed from a decorated name: %r via %r"
		% (note.get("language"), note.get("language_proof")))
	expect(str(note.get("abi", "")).lower().startswith("msvc crt"),
		"the runtime is still reported as the runtime: %s" % note.get("abi"))
	expect("downlevel" in str(note.get("abi", "")),
		"msvcrt.dll named as the downlevel CRT, not as UCRT or a vcruntime")
	expect(not note.get("crt", {}).get("static_crt"),
		"importing a CRT means the CRT is not in the file")
	# cppflags is cleared because the benchmark's MSVC variant carries /MT in it, and `cl`
	# takes the last of the two: the point here is what the *CRT keys* produce.
	for name, override in (("ms4_cpp_md", {"crt": "md", "cppflags": []}),
		("ms4_cpp_mt", {"crt": "mt", "cppflags": []})):
		kind = name.split("_")[-1]
		built = build_probe(CPP_SOURCE, name, override)
		if built is None:
			expect(False, "a /%s C++ probe could not be built to test this against%s"
				% (kind.upper(), ": " + PROBE_FAILURE if PROBE_FAILURE else ""))
			continue
		made = toolchain.build_note(built)
		crt = made.get("crt") or {}
		if kind == "md":
			expect(made.get("language") == "c++" and "std@@" in " ".join(made["decorated"]),
				"a /MD C++ build: C++ from its STL imports (%s)" % made["decorated"][:2])
			expect("ucrt" in crt.get("dlls", {}) and crt.get("generation") == "v14x "
				"(VS2015 or newer)", "its runtime: UCRT, generation %s" % crt.get("generation"))
			expect(not crt.get("static_crt"), "and it imports that runtime, so it is /MD")
		else:
			expect(crt.get("static_crt") is True and not crt.get("dlls"),
				"a /MT build: no CRT DLL imported, so the CRT is in the file")
			expect(made.get("language") == "c++" and "front-end record" in
				str(made.get("language_proof")),
				"and with no imports to read, C++ is still said - from the link's front-end "
				"records, labelled as the coarser evidence it is: %s"
				% made.get("language_proof"))


# --------------------------------------------------------------------------------------
# 3. the standard level


def check_std(note: dict) -> None:
	hints = note.get("std_hints") or []
	expect(bool(hints) and hints[0]["std"] == "c++14",
		"the 14.12 toolset's default level is named as the bound, with its proof labelled: %r"
		% (hints[:1],))
	expect(hints and hints[0].get("proof") == "toolset, not name"
		and "c++17" not in hints[0].get("offered", []),
		"14.12 offers no /std:c++17 (that switch is 14.16 and later): %r"
		% (hints[0].get("offered") if hints else None,))
	for version, want in (("14.16", True), ("14.12", False)):
		borrowed = dict(note, linker_version=version)
		borrowed["toolset"] = dict(note.get("toolset") or {}, linker_version=version)
		borrowed["std_hints"] = []
		toolchain.language_evidence(borrowed)
		hint = (borrowed.get("std_hints") or [{}])[0]
		expect(("c++17" in hint.get("offered", [])) is want,
			"a %s toolset %s /std:c++17" % (version, "offers" if want else "does not offer"))


# --------------------------------------------------------------------------------------
# 4. flags


def check_flags(note: dict) -> None:
	def flags(**body):
		return toolchain.build_flags(dict(body, compiler="cl"))

	expect("/Od" in flags(optimize=0) and "/O1" in flags(optimize=1)
		and "/O2" in flags(optimize=2),
		"three optimisation levels are three flags, not /Od or /O2")
	expect("/MT" in flags(crt="mt") and "/MD" in flags(crt="md"), "/MT vs /MD are named")
	expect("/GS-" in flags(guard=False) and "/GS-" not in flags(guard=True)
		and "/GS" in flags(guard=True), "/GS and /GS- are both sayable")
	expect("/GL" in flags(ltcg=True) and "/LTCG" in toolchain.link_flags(
		{"compiler": "cl", "ltcg": True}), "/GL is answered on the link too (/LTCG)")
	expect("/Gy" in flags(comdat=True) and "/Gy" not in flags(optimize=2),
		"/Gy is opt-in at /Od, never implied by the tool")
	expect("/std:c++20" in flags(std="c++20"), "/std: carries the level")
	with tempfile.TemporaryDirectory(prefix="ms4-cfg-") as directory:
		path = Path(directory) / "project.toml"
		path.write_text(toolchain.starter_config(TARGET, note, {"optimize": 1,
			"level_class": "/O1|/O2", "sampled": 135, "distance": 0.268, "runner_up": 0.514,
			"runner_up_optimize": 2, "confidence": "a class, not a level"}))
		try:
			parsed = tomllib.loads(path.read_text())
			table = parsed["variants"]["msvc-o1"]
			produced = toolchain.build_flags(dict(table, std=parsed["std"]))
		except Exception as exc:  # noqa: BLE001
			expect(False, "the config `detect` writes for a PE does not work: %s" % exc)
			return
		expect(table["compiler"] == "cl" and "/O1" in produced and "ltcg = true"
			in path.read_text(), "the written config names cl, the level, and /GL")
		expect("v141" in path.read_text() and "14.12" in path.read_text()
			and "--msvc-version" in path.read_text(),
			"and it names the toolset era a candidate has to be built with")
		expect('crt = "md"' in path.read_text() and "/MT" not in produced,
			"and the CRT it read (imported, so /MD) reaches the flags")


# --------------------------------------------------------------------------------------
# 5. the MSVC shape profile and `detect` on a real MSVC target


def check_shape(work: Path) -> None:
	signatures, problems = toolchain.probe_signatures("cl", 64, levels=(0, 1, 2),
		work_dir=work)
	expect(bool(signatures) and len(signatures) == 3,
		"cl probed at /Od, /O1, /O2 with this machine's toolchain (%s)"
		% ",".join("O%d" % item["optimize"] for item in signatures))
	for problem in problems:
		print("      note: %s" % problem)
	by = {item["optimize"]: item["profile"] for item in signatures}
	family = toolchain.FEATURES_MSVC
	print("      probe shapes: " + "  ".join("/O%d %s" % (level, {name: round(by[level][name], 3)
		for name in family}) for level in sorted(by)))
	gap = min(by[1]["rspmem"] + by[1]["argstore"], by[2]["rspmem"] + by[2]["argstore"])
	expect(by[0]["rspmem"] - gap >= 0.3,
		"/Od addresses its locals off %%rsp %d%% more of the time than /O1|/O2 do (%.3f): the "
		"two classes are far apart" % (round((by[0]["rspmem"] - gap) * 100), by[0]["rspmem"]))
	expect(by[0]["argstore"] >= 0.5 and by[1]["argstore"] <= 0.25
		and by[2]["argstore"] <= 0.25,
		"/Od stores the argument registers to their home slots in %d%% of bodies, /O1|/O2 in "
		"%d%%/%d%%" % (round(by[0]["argstore"] * 100), round(by[1]["argstore"] * 100),
			round(by[2]["argstore"] * 100)))
	# A COFF object gives every function its own `.text$mn`, and a name cannot key them: the
	# probe must see every function of the probe source, not one collapsed body.
	expect(min(by[level]["bodies"] for level in by) >= 8,
		"the probe read %d..%d separate bodies per level (a COFF object names several sections "
		"`.text$mn`: keying them by name collapses them)"
		% (min(by[level]["bodies"] for level in by), max(by[level]["bodies"] for level in by)))

	outcome = cli.detect_target(TARGET, levels=(0, 1, 2))
	guess, profile = outcome["guess"], outcome["profile"]
	expect(guess and guess["optimize"] >= 1,
		"detect on the shipped /O2 /GL target answers an optimising level: %s"
		% (guess and guess["optimize"]))
	expect(bool(guess and guess.get("level_class")),
		"and says /O1 against /O2 is a class, not an answer: %r"
		% (guess and guess.get("level_class")))
	expect(bool(guess and "/O1 and /O2" in guess.get("confidence", "")),
		"the confidence text says which question the shapes do answer")
	lines = toolchain.msvc_shape_flags(profile)
	expect(any("/GS" in line for line in lines),
		"/GS reported from the shape: %s" % (lines or "nothing said"))
	print("      target shape: " + str({name: round(profile[name], 3) for name in family}))

	# 6. the sample is the file's units, not a disassembly cut at every `ret`.
	expect(".pdata" in str(profile.get("sample_source")),
		"the sample came from the file's own function table: %r" % profile.get("sample_source"))
	rng = (0x140012000, 0x140018000)
	narrow, _note, problems = toolchain.target_shape(TARGET, rng=rng)
	import lief

	records = extract.pdata_records(lief.parse(str(TARGET)))
	in_range = [item for item in records if rng[0] <= item[0] + extract.file_address_base(
		lief.parse(str(TARGET))) < rng[1]]
	expect(not problems and 0 < narrow["bodies"] <= len(in_range),
		"in 0x140012000-0x140018000 it sampled %d bodies out of %d .pdata records there - "
		"never more than the file names" % (narrow["bodies"], len(in_range)))
	_bad, _note, problems = toolchain.target_shape(TARGET, rng=(0x90000, 0x91000))
	expect(any("--range" in item for item in problems),
		"a range outside the image is still reported as empty: %r" % problems)


# --------------------------------------------------------------------------------------
# 6. the ELF path


def check_elf_unchanged() -> None:
	if not GCC_STRIPPED.is_file():
		print("  skipped: %s is not built" % GCC_STRIPPED)
		return
	build = TESTS / "build" / "gcc-o0" / "build.json"
	low, high = 0x1000, 0x2000
	if build.is_file():
		import json

		answer = json.loads(build.read_text())
		units = answer.get("units") or []
		if units:
			low = min(int(item["address"]) for item in units)
			high = max(int(item["address"]) + int(item["size"]) for item in units)
	outcome = cli.detect_target(GCC_STRIPPED, range_text="0x%x-0x%x" % (low, high),
		levels=(0, 1, 2))
	guess = outcome["guess"]
	expect(bool(guess) and guess["optimize"] == 0,
		"the ELF -O0 build is still detected as -O0: %s" % (guess and guess["optimize"]))
	expect(bool(guess) and guess.get("features") == list(toolchain.FEATURES),
		"scored on the Itanium features, not the MSVC ones")
	expect("ret" in str(outcome["profile"].get("sample_source")),
		"and sampled the way it always has: %r" % outcome["profile"].get("sample_source"))
	expect(not toolchain.msvc(outcome["note"].get("compiler")),
		"the note still says gcc: %s" % outcome["note"].get("compiler"))


# --------------------------------------------------------------------------------------
# 7. a 32-bit MSVC target, in its own dialect (Docs/MSVC-x86-Plan.md X86-5)


def check_i386(work: Path) -> None:
	cfg = config.load(str(TESTS / "project.toml"))
	prefix, prefix_from = config.msvc_prefix(cfg)
	driver = toolchain.compiler_for({"compiler": "cl", "arch": "x86"}, prefix=prefix,
		prefix_from=prefix_from)
	expect(bool(driver.name), "an `arch = \"x86\"` MSVC driver resolves here: %s (%s)"
		% (driver.name or "none", driver.gap or driver.why))
	if not driver.name:
		return

	# The ranked `-O` rows print this name. Slicing its last 40 characters left
	# `mpileAnything/toolchains/msvc/bin/x86/cl`, which names no driver, so whatever the tool
	# prints for a probe has to be a path that still opens the file it names.
	label = cli._driver_label(driver.name)
	try:
		opens = Path(label).samefile(driver.name)
	except OSError:
		opens = False
	expect(opens, "the label `detect` prints for a probe driver is that driver: %s" % label)

	signatures, problems = toolchain.probe_signatures(driver.name, 32, levels=(0, 1, 2),
		work_dir=work)
	expect(len(signatures) == 3,
		"the 32-bit driver probes at /Od, /O1, /O2 - the old `bits != 64` refusal is gone: %s %r"
		% (",".join("O%d" % item["optimize"] for item in signatures), problems))
	if len(signatures) < 3:
		return
	by = {item["optimize"]: item["profile"] for item in signatures}
	i386_set = toolchain.FEATURES_MSVC_I386
	print("      the x64 set on i386 code: " + "  ".join("/O%d %s" % (level, {name:
			by[level][name] for name in toolchain.FEATURES_MSVC if name != "calls" and name != "xmm"})
			for level in sorted(by)))
	expect(all(by[level][name] == 0.0 for level in by for name in ("rspmem", "argstore", "gs")),
		"the x64 ABI readings are 0.000 at every level here, which is why they cannot be the "
		"feature set for a 32-bit target (the §3 measurement, asserted)")
	print("      the i386 set: " + "  ".join("/O%d %s" % (level, {name: round(by[level][name], 3)
			for name in i386_set}) for level in sorted(by)))
	expect(by[0]["frame"] >= 0.9 and by[0]["framemem"] >= 0.3 and by[0]["poprbp"] >= 0.9,
		"/Od on i386 sets up a %%ebp frame in %d%% of bodies and reads locals through it in %d%% of "
		"its instructions" % (round(by[0]["frame"] * 100), round(by[0]["framemem"] * 100)))
	expect(by[0]["gs_frame"] > 0.0 and by[1]["gs_frame"] > 0.0,
		"/GS on i386 is read from the cookie xor-ed with the frame register: %d%%/%d%% of the "
		"/Od|/O1 bodies carry it" % (round(by[0]["gs_frame"] * 100), round(by[1]["gs_frame"] * 100)))
	gap = max(by[1]["frame"], by[2]["frame"])
	expect(by[0]["frame"] - gap >= 0.6,
		"/Od stands up a frame in %d%% more bodies than /O1|/O2 do (%.3f): the classes separate on "
		"i386 as well, on the frame rather than the shadow space" % (round((by[0]["frame"] - gap) * 100),
			by[0]["frame"]))
	distance = lambda a, b: sum(abs(a[name] - b[name]) for name in i386_set)  # noqa: E731
	expect(distance(by[1], by[2]) < distance(by[0], by[1]),
		"/O1 and /O2 are %.3f apart on this set against /Od's %.3f: even more of a class than on "
		"x64, where the argstore gap did half the separating"
		% (distance(by[1], by[2]), distance(by[0], by[1])))

	# `detect` on a real 32-bit MSVC target: its own dialect, its own driver, and the era gap
	# stated rather than papered over.
	if not X86_TARGET.is_file():
		print("  skipped: %s is not here - gitignored; see Docs/MSVC-x86-Plan.md §3" % X86_TARGET)
	else:
		outcome = cli.detect_target(X86_TARGET, levels=(0, 1, 2), cfg=cfg)
		profile, note, guess = outcome["profile"], outcome["note"], outcome["guess"]
		expect(toolchain.feature_family(note.get("compiler"), note.get("bits")) == i386_set,
			"a 32-bit MSVC target is scored on the i386 set: %s" % (i386_set,))
		expect(profile.get("bodies", 0) > 100 and any(profile[name] > 0.0 for name in i386_set),
			"the readings on the shipped 32-bit target are non-zero: %s over %d bodies"
			% ({name: round(profile[name], 3) for name in i386_set}, profile.get("bodies", 0)))
		drivers = outcome.get("probe_drivers") or []
		expect(bool(drivers) and drivers[0].get("arch") == "x86"
			and str(drivers[0].get("driver", "")).replace("\\", "/").endswith("/bin/x86/cl"),
			"the probe for a 32-bit PE is the driver that emits 32-bit code: %s"
			% ([(item.get("driver"), item.get("arch")) for item in drivers] or "none"))
		expect(bool(guess) or any("no -O inference" in item for item in outcome["problems"]),
			"detect answers an optimize, or refuses with the reason: %s"
			% ("optimize=%s" % guess["optimize"] if guess else outcome["problems"][:2]))
		if guess:
			stated = guess.get("toolset_gap") or ""
			family = str((note.get("toolset") or {}).get("family") or "")
			# Two halves to the era question, and they are no longer the same answer. The file's own
			# era is a fact now: link.exe 8.00 names v80, which is in the table since the 32-bit
			# eras became a real request (Docs/x86-32bit-issues.md §14). What still has to be stated
			# in the open is the gap to the compiler installed here.
			expect("v80 (Visual Studio 2005)" in family,
				"a link.exe 8.00 file is named by era from its own linker version: %s"
					% (family or "nothing"))
			expect(bool(stated) and "compiler of the same era" in stated,
				"and the reading is still labelled as this toolchain's, not that file's: this file is "
				"link.exe %s - %s" % (note.get("linker_version"), stated or "nothing said"))
			expect("ret" in str(profile.get("sample_source") or "")
				and "ret" in str(guess.get("confidence", "")),
				"a ret-cut sample says so in the same sentence as the answer: %r"
					% str(guess.get("confidence", ""))[:150])
		lines = toolchain.msvc_shape_flags(profile, bits=32)
		expect(any("/GS" in line for line in lines),
			"the stack guard of a 32-bit MSVC target is spoken of as /GS, not as a canary: %s"
			% (lines or "nothing said"))
		findings = outcome["fidelity"]["flags"]["findings"]
		expect(not any(item["flag"].startswith("-fstack-protector") for item in findings),
			"no GCC stack-protector finding for a file this tool identified as `built by msvc` "
			"(the §4 bug): %s" % [item["flag"] for item in findings])
		expect(not any("x86-64" in item["flag"] for item in findings),
			"no x86-64 ISA level claimed for a 32-bit image: %s" % [item["flag"] for item in findings])

	# A 32-bit build made *here*, so its flag is a known answer. Sampled from the cached analysis,
	# which is the only sample of a 32-bit PE whose bodies start at real function boundaries.
	if not X86_BUILD.is_file():
		print("  skipped: %s is not built (Tests/eval.py build --variant msvc-o0-x86)" % X86_BUILD)
		return
	store = cache.Cache(config.cache_dir(cfg))
	status = store.status(cache.target_key(X86_BUILD)["key"])
	if not status.get("complete"):
		print("  skipped: %s is not analysed here, and the analysis is the only sample of a 32-bit "
			"PE with real function boundaries" % X86_BUILD.name)
		return
	conn = cache.open_readonly(Path(status["db"]))
	try:
		known = cli.detect_target(X86_BUILD, sample="FUN_", conn=conn, levels=(0, 1, 2), cfg=cfg)
	finally:
		conn.close()
	answer, known_profile = known["guess"], known["profile"]
	expect("cached analysis" in str(known["sample"].get("source", "")),
		"the sample of a file with no function table came from the cached analysis: %r"
		% known["sample"].get("source"))
	expect(bool(answer) and answer["optimize"] == 0,
		"the /Od 32-bit MSVC build of X86-4 is detected as /Od: %s"
		% (answer and "-O%d distance %.3f next %.3f" % (answer["optimize"], answer["distance"],
			answer.get("runner_up", 0.0))))
	expect(bool(answer) and "strong" in str(answer.get("confidence", "")),
		"and the answer says it is strong, because that sample has real boundaries: %s"
		% str(answer and answer.get("confidence"))[:120])

	# One place answers \"is this the toolchain that made this file\", and bitness is part of it.
	x64_driver = toolchain.compiler_for({"compiler": "cl", "arch": "x86-64"}, prefix=prefix,
		prefix_from=prefix_from)
	agreement = fidelity.version_check(X86_BUILD, x64_driver.name)
	expect(agreement["what"] == "target bitness" and agreement["hard"],
		"an x64 driver against a 32-bit file is named as a bitness gap: %s" % agreement["detail"])
	same = fidelity.version_check(X86_BUILD, driver.name)
	expect(same["what"] != "target bitness",
		"and the same question about the driver that serves this bitness does not fire: %s"
		% same["detail"])


if __name__ == "__main__":
	sys.exit(main())
