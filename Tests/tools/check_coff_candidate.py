"""MS-3 acceptance (Docs/MSVC-Plan.md §7): the COFF candidate side - `try` on a PE.

	run: PATH=<msvc prefix>/bin/x64:$PATH .venv/bin/python Tests/tools/check_coff_candidate.py
	     [--variant msvc-o0] [--limit N] [--no-controls]

`check_pe_target.py` is the target side and needs no compiler; this is the candidate side, and
it needs the toolchain of MS-2. Three groups:

1. **Extents.** A COFF symbol has no size, so the tool has to derive one (`.text$…` COMDAT, or
   the next function symbol in the section with `cl`'s inter-function padding cut off). This
   requires, for every unit of the benchmark, that the extent the tool derives from the `.obj`
   is the extent the *original* side reads - the linked image's own `.pdata` where the file has
   a record for the function, the analysis' body where it does not.
2. **The loop.** The untouched source through `decomp try`'s own path for every unit, which is
   the PE port of `check_phase2_try.py`: same call (`cli.score_candidate`), same judge (the
   threshold and the opcode rule), same KNOWN_GAPS discipline.
3. **The negative controls.** The deliberately wrong candidates of
   `Tests/examples/candidate_math_bad.cpp` must still be reported as the kind of wrong they
   are, on a PE and compiled by `cl`.

Exit: 0 all passed, 1 something came out wrong, 2 there is no `cl`, no PE build, or no analysis
of it to judge (which is not a failure of the tool).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from decomp import cache, cli, compile as build_, config, extract, toolchain  # noqa: E402

# The MSVC toolchain of Docs/Setup.md §6 lives in the repo; put its wrappers on PATH so the
# check runs with no shell setup, and says which prefix it used.
PREFIX = REPO / "toolchains" / "msvc" / "bin"

# The same three probes as `check_phase2_try.py`, judged the same way - the unit must not pass,
# and one of the listed categories must be what the report says. Only the category sets differ,
# because what a category looks like depends on how the two instruction streams align, and `cl`
# at /Od aligns them differently than GCC: `LengthOfProbe`'s counted loop shows up as a
# different opcode here, where at GCC -O0 it reads as instructions the original does not have.
# Measured, not guessed.
NEGATIVE_CONTROLS = [
	("MATH-02", "ClampRangeProbe", {"operand"}, "the inverted-range guard is gone, bounds compared the wrong way"),
	("MATH-38", "ParityOfProbe", {"opcode", "missing"}, "counts bits instead of folding them"),
	("STR-01", "LengthOfProbe", {"opcode"}, "a counted loop instead of the sentinel test"),
]

# Units the untouched original source does not score through on this target, with the reason,
# so the gate stays exact and the gap stays visible. A variant with **no entry here is measured
# but not gated** (it prints its numbers and fails nothing): `msvc-o2` is that case, and Docs/
# MSVC-Plan.md MS-3 says why - `cl /O2` splits a function into hot and cold COMDAT blocks, so
# the image's own `.pdata` unit is a block rather than the function, which is MS-4's question and
# not this phase's.
KNOWN_GAPS: dict[str, dict[str, str]] = {
	"msvc-o0": {
		# ClassifyEntity compares three type descriptors. The `.obj` names each one by its COFF
		# symbol (`??_R0?AVCVehicleEntity@`), which is right; the target side can only repeat the
		# *data type* Ghidra applied to all three (`RTTI_Type_Descriptor`), so nothing pairs one
		# descriptor with the other side's. That is MS-5: the MSVC RTTI model
		# (`RTTICompleteObjectLocator`, `.?AV…` descriptors), not a candidate or extent problem.
		"STRUCT-24": "MSVC RTTI descriptors: the target names a type, the object names each descriptor",
	},
}


def gated() -> bool:
	"""Is this variant held to the numbers, or are they only being reported?"""
	return VARIANT_NAME in KNOWN_GAPS


def _objects_for(store: cache.Cache, suffix: str = "") -> Path:
	"""A candidate-object directory per variant. `compile.object_name` names an object after its
	source, so two variants of one source would otherwise read each other's `.obj` - and a
	`/Od` candidate scored against an `/O2` object looks like a broken tool."""
	return store.root / ("candidates-ms3-%s%s" % (VARIANT_NAME, suffix))


def expect(ok: bool, detail: str, failures: list[str]) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def object_for(source: Path, work: Path) -> tuple[Path, str]:
	"""Build one translation unit of the benchmark with the variant's own flags."""
	object_path = work / ("%s.obj" % source.stem)
	built = build_.build([source], object_path, compiler=VARIANT["compiler"],
		flags=toolchain.build_flags(VARIANT),
		includes=config.include_dirs(CONFIG, VARIANT))
	if not built.ok:
		print("  %s did not compile: %s" % (source.name,
			(built.diagnostics or "no output").splitlines()[:6]))
	return object_path, "" if built.ok else "the benchmark source did not compile"


def extents(cfg: dict, conn, meta: dict, answer: dict, work: Path, failures: list[str]) -> None:
	"""The extent a COFF candidate symbol gets vs the extent the original side is read over."""
	by_file: dict[str, list[dict]] = {}
	for unit in answer["units"]:
		by_file.setdefault(unit["file"], []).append(unit)
	objects: dict[str, extract.CandidateObject] = {}
	same = 0
	rows: list[str] = []
	for name, units in sorted(by_file.items()):
		source = TESTS / "TestBinary" / name
		object_path, problem = object_for(source, work)
		if problem:
			failures.append("%s: %s" % (name, problem))
			continue
		candidate = extract.CandidateObject(object_path)
		if candidate.error:
			failures.append("%s: %s" % (name, candidate.error))
			continue
		objects[name] = candidate
		expect(candidate.machine.upper() in ("AMD64", "I386") and candidate.bits in (32, 64),
			"%s opens as a COFF object: machine %s, %d-bit, no error"
			% (object_path.name, candidate.machine, candidate.bits), failures)
		expect(bool(candidate.functions),
			"%s defines %d functions with extents (a COFF symbol names none of this itself)"
			% (object_path.name, len(candidate.functions)), failures)
		for unit in units:
			row = cache.resolve_function(conn, hex(unit["address"] + OFFSET))
			if not row:
				rows.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"])))
				continue
			original = extract.original_function(conn, meta, row[0])
			try:
				symbol = candidate.function(unit["mangled"])
			except extract.SymbolNotFound as exc:
				rows.append("%s: %s" % (unit["id"], exc))
				continue
			if symbol.size == original.size:
				same += 1
			else:
				rows.append("%s %-40s original %d bytes (%s), candidate %d in %s+%s"
					% (unit["id"], unit["name"], original.size, "the file's .pdata"
						if cache.unit_at(conn, int(row[0]["entry"])) else "the analysis' body",
						symbol.size, symbol.section, hex(symbol.address)))
	if same == len(answer["units"]):
		print("  ok   every one of the %d units: the extent read out of the COFF object equals the "
			"extent the original side is compared over" % len(answer["units"]))
	elif gated():
		failures.append("the extent read out of the COFF object is not the extent compared, for "
		"%d of %d units" % (len(answer["units"]) - same, len(answer["units"])))
		print("  FAIL %d of %d units: the extent read out of the COFF object is not the extent the "
		"original side is compared over" % (len(answer["units"]) - same, len(answer["units"])))
	else:
		print("  measured, not gated (%s is not in KNOWN_GAPS): %d of %d units agree; the rest are "
		"the file's own unit table describing a *block* of a function, not the function (Docs/"
		"MSVC-Plan.md MS-3)" % (VARIANT_NAME, same, len(answer["units"])))
	for item in rows[:10]:
		print("   %s" % item)
	# What the extents came from: COMDAT section, or symbol spacing minus the padding.
	comdat = sum(1 for candidate in objects.values()
		for symbol in candidate.functions if symbol.section in candidate._comdat)
	joined = sum(len(candidate.functions) for candidate in objects.values())
	print("   %d candidate functions across %d objects; %d of them are their own COMDAT section"
		" (the exact extent, `/Gy`), %d bounded by the next symbol in their section"
		% (joined, len(objects), comdat, joined - comdat))


def the_loop(cfg: dict, store: cache.Cache, answer: dict, limit: int, failures: list[str]) -> None:
	"""The untouched source through `decomp try`, for every unit of the PE."""
	conn = cache.open_readonly(Path(store.db_path(KEY)))
	meta = cache.meta(conn)
	units = answer["units"][:limit] if limit else answer["units"]
	scores, below, broken = [], [], []
	for unit in units:
		row = cache.resolve_function(conn, hex(unit["address"] + OFFSET))
		if not row:
			broken.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"])))
			continue
		outcome = cli.score_candidate(cfg, conn, meta, row[0],
			[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"],
			object_dir=_objects_for(store))
		verdict = outcome["verdict"]
		if verdict is None:
			broken.append("%s: %s" % (unit["id"], outcome["error"]))
			continue
		scores.append(verdict)
		if not verdict.passed:
			below.append("%s %-42s %6.2f%% bytes %+d %s" % (unit["id"], unit["name"],
				verdict.match_percent, verdict.size_delta_bytes,
				{k: v for k, v in verdict.categories.items() if v}))
		outcome["object"].unlink(missing_ok=True)
	conn.close()
	if not scores:
		failures.append("nothing scored (%d problems)" % len(broken))
		return
	percent = [item.match_percent for item in scores]
	print("   %d/%d units scored, mean %.2f%%, byte-identical %d, pass the gate %d"
		% (len(scores), len(units), sum(percent) / len(percent),
			sum(1 for item in scores if item.bytes_equal),
			sum(1 for item in scores if item.passed)))
	for item in broken[:8]:
		print("   BROKEN %s" % item)
	for item in below[:12]:
		print("   FAIL %s" % item)
	if len(below) > 12:
		print("   ... %d more" % (len(below) - 12))
	if broken:
		failures.append("%d units could not be scored" % len(broken))
	gaps = KNOWN_GAPS.get(VARIANT_NAME, {})
	failing = [item for item in below if item.split()[0] not in gaps]
	for item in below:
		if item.split()[0] in gaps:
			print("   KNOWN GAP %s: %s" % (item.split()[0], gaps[item.split()[0]]))
	if not gated():
		print("   measured, not gated (%s is not in KNOWN_GAPS): %d of %d past the gate" % (
			VARIANT_NAME, sum(1 for item in scores if item.passed), len(scores)))
		return
	expect(not failing, "the untouched source passes the gate for every unit but the %d named"
		" ones (%d failing)" % (len(gaps), len(failing)), failures)


def controls(cfg: dict, store: cache.Cache, answer: dict, failures: list[str]) -> None:
	"""The wrong candidates, compiled by `cl`, must be reported as the kind of wrong they are."""
	units = {unit["id"]: unit for unit in answer["units"]}
	conn = cache.open_readonly(Path(store.db_path(KEY)))
	meta = cache.meta(conn)
	bad = 0
	for unit_id, symbol, wanted, why in NEGATIVE_CONTROLS:
		unit = units.get(unit_id)
		if unit is None:
			print("   no such unit %s" % unit_id)
			bad += 1
			continue
		row = cache.resolve_function(conn, hex(unit["address"] + OFFSET))
		outcome = cli.score_candidate(cfg, conn, meta, row[0],
			[TESTS / "examples" / "candidate_math_bad.cpp"], fn=symbol,
			object_dir=_objects_for(store))
		verdict = outcome["verdict"]
		if verdict is None:
			print("   controls %s: %s" % (unit_id, outcome["error"]))
			bad += 1
			continue
		missing = [name for name in sorted(wanted) if not verdict.categories[name]]
		print("   controls %s vs %-22s %6.2f%% %-9s categories %s  (%s) %s"
			% (unit_id, symbol, verdict.match_percent,
				"not-passed" if not verdict.passed else "PASSED!",
				{k: v for k, v in verdict.categories.items() if v}, why,
				"ok" if not missing and not verdict.passed else "WRONG REPORT"))
		if missing or verdict.passed:
			if missing:
				print("     expected %s to be reported, got none of them" % ", ".join(missing))
			bad += 1
		outcome["object"].unlink(missing_ok=True)
	conn.close()
	if not gated():
		print("   measured, not gated (%s is not in KNOWN_GAPS)" % VARIANT_NAME)
		return
	expect(bad == 0, "the wrong candidates are still classified correctly on a PE", failures)


VARIANT = {}
VARIANT_NAME = ""
CONFIG: dict = {}
KEY = ""
OFFSET = 0


def main() -> int:
	global VARIANT, VARIANT_NAME, CONFIG, KEY, OFFSET
	parser = argparse.ArgumentParser(prog="check_coff_candidate.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variant", default="msvc-o0")
	parser.add_argument("--limit", type=int, default=0)
	parser.add_argument("--no-controls", action="store_true")
	args = parser.parse_args()

	CONFIG = config.load(str(TESTS / "project.toml"))
	try:
		VARIANT_NAME, VARIANT = config.variant(CONFIG, args.variant)
	except config.ConfigError as exc:
		print("no variant to judge: %s" % exc)
		return 2
	if not toolchain.msvc(VARIANT.get("compiler", "")):
		print("%s is not an MSVC variant (compiler = %s) - Docs/MSVC-Plan.md §1"
			% (VARIANT_NAME, VARIANT.get("compiler")))
		return 2
	if PREFIX.is_dir():
		os.environ["PATH"] = str(PREFIX / "x64") + os.pathsep + os.environ.get("PATH", "")
	if not shutil.which(VARIANT["compiler"]):
		print("no `%s` on PATH: install the toolset of Docs/Setup.md §6 and put <prefix>/bin/x64"
			" on PATH. Nothing was judged - this is not a failure of the tool."
			% VARIANT["compiler"])
		return 2

	answer_path = TESTS / "build" / VARIANT_NAME / "answer_key.json"
	stripped = TESTS / "build" / VARIANT_NAME / "da_tests.stripped"
	if not answer_path.is_file() or not stripped.is_file():
		print("build it first: Tests/eval.py build --variant %s" % VARIANT_NAME)
		return 2
	store = cache.Cache(config.cache_dir(CONFIG))
	KEY = cache.target_key(stripped)["key"]
	status = store.status(KEY)
	if not status.get("complete"):
		print("not analysed: decomp analyze %s --variant %s" % (stripped, VARIANT_NAME))
		return 2
	answer = json.loads(answer_path.read_text())
	conn = cache.open_readonly(Path(status["db"]))
	meta = cache.meta(conn)
	OFFSET = int(meta.get("address_offset") or 0)
	print("target %s\nvariant %s: %s" % (stripped, VARIANT_NAME, " ".join(
		toolchain.build_flags(VARIANT))))

	failures: list[str] = []
	print("\n=== 1. the extent a COFF object gives for each unit (MS-3's whole claim) ===")
	extents(CONFIG, conn, meta, answer, _objects_for(store, "extent"), failures)
	conn.close()
	print("\n=== 2. the untouched source through decomp try, every unit ===")
	the_loop(CONFIG, store, answer, args.limit, failures)
	if not args.no_controls:
		print("\n=== 3. the deliberately wrong candidates ===")
		controls(CONFIG, store, answer, failures)

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_coff_candidate: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
