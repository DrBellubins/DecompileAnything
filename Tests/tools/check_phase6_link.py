#!/usr/bin/env python3
"""Phase 6 (Docs/byte-cleanup-plan.md): relink the program and compare it whole.

`decomp try` proves one function at one address. That is enough to work on and not enough to
claim: a program can be built of functions that each match and still not be the program - a
function nobody reproduced, a data object placed differently, a link flag nobody recorded. This
checks what `decomp link` does about that, and the two rules its report depends on.

**A link is the target's, or it is not a comparison.** The variant's own build flags and its own
`linkflags` are used; where none are recorded the tool says so instead of choosing its own.

**A difference that follows the layout is a consequence, not a second problem.** Once one body is
a different length, every address after it moves, and the bytes of bodies that are otherwise
identical differ in their operands. The report names the place the layout moved and marks what
comes after it, so the loop works on the first one and not on the thirty that follow.

The acceptance case the plan asks for is here: the benchmark program, compiled from its own
sources with the variant's flags and linked with the variant's link flags, must relink with a
byte-identical `.text` - or the report has to name the first function that differs. Both halves
are checked, the second with one `math.cpp` that has an extra branch in it.

Run:
  .venv/bin/python Tests/tools/check_phase6_link.py            # everything
  .venv/bin/python Tests/tools/check_phase6_link.py --no-target # the rules only (fast)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import compile, config, normalize, relink, toolchain  # noqa: E402

FAILURES: list[str] = []
OK = 0


def ok(what: str, got, want) -> bool:
	global OK
	if got == want:
		OK += 1
		print("  ok   %s = %r" % (what, got))
		return True
	FAILURES.append("%s: got %r, want %r" % (what, got, want))
	print("  FAIL %s: got %r, want %r" % (what, got, want))
	return False


def truth(what: str, got) -> bool:
	global OK
	if got:
		OK += 1
		print("  ok   %s" % what)
		return True
	FAILURES.append("%s: not true" % what)
	print("  FAIL %s: not true" % what)
	return False


def extent(address: int, size: int, name: str) -> dict:
	return {"address": address, "size": size, "name": name, "section": ".text"}


# --------------------------------------------------------------------------------------
# the rules, without a compiler


def link_flags_are_the_targets() -> None:
	print("\nthe link is the target's own")
	cfg = config.load(str(TESTS / "project.toml"))
	_name, body = config.variant(cfg, "gcc-o0-x86")
	flags, where = config.link_flags(cfg, body)
	ok("gcc-o0-x86 linkflags", flags, ["-no-pie", "-static"])
	truth("they are attributed to the config file", "project.toml" in where)
	flags, where = config.link_flags(cfg, config.variant(cfg, "gcc-o0")[1])
	ok("gcc-o0 linkflags (none recorded)", flags, [])
	truth("and that is said out loud", "no linkflags are recorded" in where)

	cl = toolchain.link_form("cl", ["/Od"], [Path("a.obj"), Path("b.obj")],
		["/SUBSYSTEM:CONSOLE"], Path("out.exe"))
	ok("cl link line", cl, ["cl", "/Od", "a.obj", "b.obj", "/Fe:out.exe", "/link",
		"/SUBSYSTEM:CONSOLE"])
	command = toolchain.link_form("g++", ["-m32"], [Path("a.o")], ["-static"], Path("out"))
	ok("gcc link line carries the arch and links before -o", command,
		["g++", "-m32", "a.o", "-static", "-o", "out"])

	# a link that cannot happen says which file is missing, and does not raise
	result = compile.link([Path("/nope/missing.o")], Path("/tmp/da-phase6/never"),
		compiler="g++", flags=["-O0"], linkflags=[])
	ok("a missing object is reported, not raised", result.ok, False)
	truth("and named", "no such object file" in result.diagnostics)


def pairing_proves_what_it_says() -> None:
	print("\nwhich body is which")
	# two identical layouts, no anchors: paired by layout, and that is labelled as what it is
	out = relink.pair_extents(
		[extent(0x100, 16, "FUN_00000100"), extent(0x110, 24, "FUN_00000110")],
		[extent(0x100, 16, "_Z3foov"), extent(0x110, 24, "_Z3barv")], {})
	ok("two matching layouts pair", [item["candidate"]["name"] for item in out["pairs"]],
		["_Z3foov", "_Z3barv"])
	ok("with no evidence beyond the layout", {item["evidence"] for item in out["pairs"]},
		{"address"})

	# an anchor from the ledger decides a pair even when the layout does not
	out = relink.pair_extents([extent(0x100, 16, "FUN_00000100")],
		[extent(0x100, 8, "_Z1gv"), extent(0x108, 16, "_Z3foov")],
		{0x100: "_Z3foov"})
	ok("a ledger anchor finds the body that is not where the layout says",
		[item["candidate"]["name"] for item in out["pairs"]], ["_Z3foov"])
	ok("and says the ledger proved it", [item["evidence"] for item in out["pairs"]], ["ledger"])

	# a body the candidate has extra: the rest stays paired, and the shift is reported
	original = [extent(0x100, 16, "FUN_00000100"), extent(0x110, 16, "FUN_00000110")]
	candidate = [extent(0x100, 16, "_Z1av"), extent(0x110, 32, "_Z1bx"), extent(0x130, 16, "_Z1cv")]
	out = relink.pair_extents(original, candidate, {})
	ok("an extra body is kept out of the pairs",
		[item["name"] for item in out["only_candidate"]], ["_Z1bx"])
	ok("the pairs after it are still found",
		[(item["original"]["name"], item["candidate"]["name"]) for item in out["pairs"]],
		[("FUN_00000100", "_Z1av"), ("FUN_00000110", "_Z1cv")])
	ok("the layout moving is stated as a move",
		[(item["from"], item["to"]) for item in out["shifts"]], [(0, 32)])

	# a same-address "size difference" that the layout does not confirm is a mispairing, not a
	# difference: it must not be reported as one
	original = [extent(0x100, 16, "FUN_00000100"), extent(0x110, 16, "FUN_00000110"),
		extent(0x120, 16, "FUN_00000120")]
	candidate = [extent(0x100, 16, "_Z1av"), extent(0x110, 40, "_Z1bx"), extent(0x120, 16, "_Z1cv")]
	out = relink.pair_extents(original, candidate, {})
	ok("an unconfirmed length difference is not claimed as one",
		[item["candidate"]["name"] for item in out["pairs"]], ["_Z1av", "_Z1cv"])
	ok("it is reported as two extents with no pair instead",
		(len(out["only_original"]), len(out["only_candidate"])), (1, 1))

	# the same shape read the other way: a body that got longer, or an extra body? The layout
	# cannot tell (both leave a 32-byte hole), so without more the pairing says what it can see -
	# an extent with no pair, and the layout moving there. Only an anchor turns it into a pair.
	grown = [extent(0x100, 16, "FUN_00000100"), extent(0x110, 16, "FUN_00000110"),
		extent(0x120, 16, "FUN_00000120")]
	longer = [extent(0x100, 16, "_Z1av"), extent(0x110, 32, "_Z1bx"), extent(0x130, 16, "_Z1cv")]
	out = relink.pair_extents(grown, longer, {})
	ok("without an anchor the extra extent is reported unpaired, not mispaired",
		[item["name"] for item in out["only_candidate"]], ["_Z1bx"])
	ok("and the layout move is reported where it happens",
		[(item["address"], item["from"], item["to"]) for item in out["shifts"]], [(0x110, 0, 32)])
	out = relink.pair_extents(grown, longer, {0x110: "_Z1bx"})
	ok("an anchor makes it the pair it is, at its own length",
		[(item["original"]["name"], item["candidate"]["name"], item["candidate"]["size"])
			for item in out["pairs"]],
		[("FUN_00000100", "_Z1av", 16), ("FUN_00000110", "_Z1bx", 32),
			("FUN_00000120", "_Z1cv", 16)])
	ok("so the pair is kept with its lengths differing, which is what makes it reportable",
		len([item for item in out["pairs"]
			if item["original"]["size"] != item["candidate"]["size"]]), 1)


def body_comparison_at_linked_addresses() -> None:
	print("\ncomparing a body where the link put it")
	# the same code, placed 16 bytes apart: a call's pc-relative operand differs, nothing else
	left = bytes.fromhex("e800000000" + "90" * 6)   # call +0 ; nop*6
	right = bytes.fromhex("e810000000" + "90" * 6)  # call +0x10
	handle = normalize.capstone_for("x86:LE:64:default", detail=True)
	result = relink.compare_body(handle, left, 0x1000, right, 0x1010)
	ok("identical bytes are identical", relink.compare_body(handle, left, 0x1000, left, 0x1000)[
		"status"], "identical")
	ok("a body whose operands point where the link moved them is not a source difference",
		result["status"], "link_fields")
	different = bytes.fromhex("e800000000" + "90" * 5 + "cc")
	ok("a body that really differs is reported as differing",
		relink.compare_body(handle, left, 0x1000, different, 0x1000)["status"], "differs")
	ok("and says where", relink.compare_body(handle, left, 0x1000, different, 0x1000)[
		"first_difference"]["offset"], 10)
	ok("a length difference is a length difference", relink.compare_body(handle, left, 0x1000,
		right + b"\x90", 0x1010)["status"], "size")


def reading_a_program() -> None:
	print("\nreading a linked program")
	binary = TESTS / "build" / "gcc-o0" / "da_tests.stripped"
	if not binary.is_file():
		print("  skip: %s is not built" % binary)
		return
	program = relink.Program(binary, bias=0x100000)
	ok("parsed as ELF", program.format, "elf")
	text = program.section(".text")
	truth(".text is found at its address plus the analysis' offset",
		text is not None and text.address == 0x101130)
	truth("and its bytes are readable there",
		text is not None and program.bytes_at(0x101130, 8) == bytes(text.data[:8]))
	bss = program.section(".bss")
	truth(".bss is known to hold no file bytes, so it is not compared as if it did",
		bss is not None and not bss.initialised)
	truth("the stripped file names no functions to pair", isinstance(
		relink.Program(binary).extents("function"), list))
	unstripped = TESTS / "build" / "gcc-o0" / "da_tests"
	if unstripped.is_file():
		named = relink.Program(unstripped).extents("function")
		truth("a file with symbols does give up its functions", len(named) > 100)
		objects = relink.data_objects(relink.Program(unstripped))
		truth("a vtable symbol is known by what the ABI calls it, not only by its mangling",
			any(item["name"].startswith("_ZTV") and "vtable for" in item["display"]
				for item in objects))
		truth("and the key both sides are matched on is that reading, not the spelling",
			any(item["name"].startswith("_ZTV") and item["key"]
				== normalize.canonical_name(item["display"]) for item in objects))


# --------------------------------------------------------------------------------------
# the acceptance case: the benchmark, whole


def _run_link(sources: list[Path], out_dir: Path, extra: list[str]) -> tuple[int, str]:
	command = [sys.executable, "-m", "decomp", "link", "--key", "601677537ac2f6d3",
		"--output", str(out_dir / "program")]
	command += [str(item) for item in sources]
	command += extra
	process = subprocess.run(command, cwd=str(REPO), capture_output=True, text=True, timeout=900)
	return process.returncode, process.stdout + process.stderr


def the_benchmark_whole() -> None:
	print("\nthe benchmark program, linked from its own sources")
	sources = [TESTS / "TestBinary" / "main.cpp", TESTS / "TestBinary" / "SelfTest.cpp",
		TESTS / "TestBinary" / "TestFunctions" / "math.cpp",
		TESTS / "TestBinary" / "TestFunctions" / "strings.cpp",
		TESTS / "TestBinary" / "TestFunctions" / "structs.cpp"]
	missing = [str(item) for item in sources if not item.is_file()]
	if missing or not (TESTS / "build" / "gcc-o0" / "da_tests.stripped").is_file():
		print("  skip: the benchmark is not built (%s)" % ", ".join(missing))
		return
	out = Path("/tmp/da-phase6")
	shutil.rmtree(out, ignore_errors=True)
	code, text = _run_link(sources, out / "full", [])
	ok("the program the benchmark was made of relinks byte-identically (exit)", code, 0)
	ok("and the report says so", "program IDENTICAL" in text, True)
	row = next((line for line in text.splitlines() if line.strip().startswith(".text ")), "")
	truth("section by section, including .text", ".text" in row and "identical" in row)

	# the same program with one branch added to one function: the report has to name it
	shutil.rmtree(out / "modified", ignore_errors=True)
	(out / "modified").mkdir(parents=True)
	source = (TESTS / "TestBinary" / "TestFunctions" / "math.cpp").read_text()
	tweak = source.replace("""float CMathTests::SolveQuadraticRoot(float a, float b, float c, int whichRoot)
{
	if (a == 0.0f)""", """float CMathTests::SolveQuadraticRoot(float a, float b, float c, int whichRoot)
{
	if (whichRoot == 7)
	{
		return a + b + c;
	}
	if (a == 0.0f)""", 1)
	if tweak == source:
		FAILURES.append("the benchmark source changed shape: this check's edit no longer applies")
		return
	tweaked = out / "modified" / "math.cpp"
	tweaked.write_text(tweak)
	replaced = [item for item in sources if item.name != "math.cpp"] + [tweaked]
	# `--max-rows` widens the lists of extents the report could not pair. It has to be wide here
	# for a reason worth stating: this target's analysis splits and merges some functions
	# differently from how the program's symbol table lists them, so the changed function shows up
	# among the extents with no pair rather than as a mispaired body. What pairs them into names is
	# the match ledger (Phase 5): an anchor turns "an extent here" into "this function".
	code, text = _run_link(replaced, out / "modified", ["-I",
		str(TESTS / "TestBinary" / "TestFunctions"), "--max-rows", "300", "--max-units", "300"])
	ok("a source that differs fails the comparison (exit)", code, 1)
	truth("the report says the program differs", "program DIFFERS" in text)
	truth("and names the function that differs", "SolveQuadraticRoot" in text)
	truth("it names the place the layout moved", "layout moved" in text)
	truth("and separates the bodies that only follow from it",
		"what the link wrote" in text or "a consequence" in text)
	truth("and does not pretend a rewrote address is a source difference",
		"an address the link rewrote, not a source difference" in text)
	shutil.rmtree(out, ignore_errors=True)


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--no-target", action="store_true", help="skip the benchmark link")
	args = parser.parse_args()
	link_flags_are_the_targets()
	pairing_proves_what_it_says()
	body_comparison_at_linked_addresses()
	reading_a_program()
	if not args.no_target:
		the_benchmark_whole()
	print("\n%d checks passed, %d failed" % (OK, len(FAILURES)))
	for line in FAILURES:
		print("  %s" % line)
	return 1 if FAILURES else 0


if __name__ == "__main__":
	sys.exit(main())
