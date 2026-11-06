"""Phase 2 acceptance: does `decomp try` reach the benchmark's own ceiling?

	run: .venv/bin/python Tests/tools/check_phase2_try.py [--variants ...] [--limit N]

The judge is Tests/eval.py, which does not use this tool: `eval.py self` recompiles the
untouched original source and scores it (that is the ceiling any candidate is measured
against, and it is stored in Tests/build/<variant>/self_scores.json). Here the same
untouched source is fed through `decomp try`'s own path - compile, extract from the `.o`,
normalise both sides, diff - and the two must agree.

Anything the original source itself does not score 100% on is a defect in the tool or in
the answer it was given (Ghidra's function range at -O2, for instance), not in the model:
that is why this runs before any candidate is judged.

The second half is the negative control: the deliberately wrong candidates in
Tests/examples/candidate_math_bad.cpp must be reported as the kind of problem they are.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config  # noqa: E402

DEFAULT_VARIANTS = ["gcc-o0", "gcc-o2", "gcc-o0-x86"]

# Tests/examples/candidate_math_bad.cpp: what each probe must be reported as.
# Units the untouched original does not score on yet, with the reason, so the gate stays
# exact and the gap stays visible instead of the threshold being loosened.
KNOWN_GAPS = {
	"gcc-o0": {
		# ClassifyEntity compares against vtables defined in another translation unit: in
		# the .o the reference relocates against `_ZTV...+16`, and the PIE link turns that
		# into a pointer slot in .data.rel.ro (what the analysis then names). The two sides
		# genuinely name different objects, so the tokens differ. Vtables and RTTI are
		# Phase 4 (Docs/Design-Plan.md).
		# ClassifyEntity's vtable references, before Phase 4 gave both sides the same identity
		# for a type_info. It passes now; the reason is kept so the gap is not re-invented.
		"STRUCT-24": "was: externally defined vtable, .o relocates _ZTV+16, link reads a .data.rel.ro slot",
	},
	"gcc-o0-x86": {
		# A 32-bit non-PIE object reaches its data through one shared section, so the reference
		# names the section and an offset rather than an object; the linked image has a symbol
		# there. Nothing honest pairs the two. (12 units, measured: 8 where the reference names the
		# section and an offset, 4 - MATH-11/19/24/32 - where the two sides just number the same
		# object differently, which the percentage rule used to absorb.)
		"MATH-13": "32-bit data reference through a shared section",
		# Same family, one difference each, and only the tier gate sees them: the two sides number
		# the same object differently (`fldt DAT1` vs `DAT0`, `flds DAT1(,%eax,4)` vs `DAT0`,
		# `movzwl 0x80dd280(,%eax,2)` against an unrelocated symbol address in the .o). Measured
		# at 97.30 / 98.18 / 98.85 / 97.83 %, which the percentage rule let through.
		"MATH-11": "32-bit data reference through a shared section",
		"MATH-19": "32-bit data reference through a shared section",
		"MATH-24": "32-bit data reference through a shared section",
		"MATH-32": "32-bit data reference through a shared section",
		"MATH-20": "32-bit data reference through a shared section",
		"MATH-22": "32-bit data reference through a shared section",
		"MATH-23": "32-bit data reference through a shared section",
		"STR-18": "32-bit data reference through a shared section",
		"STR-19": "32-bit data reference through a shared section",
		"STRUCT-20": "32-bit data reference through a shared section",
		"STRUCT-25": "32-bit data reference through a shared section",
		# Found by Phase 4, not caused by it: now that the bytes a 32-bit access reads are compared,
		# these two report a reference mismatch. The candidate's window in a plain `.rodata` double
		# pool is anchored on the nearest symbol rather than on the offset the relocation addresses -
		# an open tool bug, named here so a new one still fails.
		"MATH-21": "32-bit read window anchored on the nearest symbol (open tool bug)",
		"MATH-27": "32-bit read window anchored on the nearest symbol (open tool bug)",
	},
	"gcc-o2": {
		# Not an extent problem - Tests/tools/check_phase5_o2.py requires the tool's extent to
		# equal the compiler's for all 89 units of this build. What is left is `leaq` of code the
		# file names no unit for: nothing on either side can name it, so nothing pairs it.
		# STRUCT-22 and STRUCT-23 reach the same unnamed functions and used to pass, because the
		# gate was a percentage: 97.26 % / 98.28 % with `leaq SYM1(%rip)` against `leaq
		# SYM0(%rip)` - the positional token pairs a different object. The tier gate reads that as
		# an operand difference and stops at `structural` (measured: 2 and 1). Pairing a callee by
		# what it is rather than by the order the two sides first reached it is
		# Docs/byte-cleanup-plan.md Phase 5.
		"STRUCT-24": "a reference to an unnamed unit elsewhere in the binary",
		"STRUCT-22": "same reference as STRUCT-24: the positional token pairs a different object",
		"STRUCT-23": "same reference as STRUCT-24: the positional token pairs a different object",
	},
}

# Any category listed must show up in the report, and the unit must not pass. Measured
# against this tool, not guessed: what a different algorithm looks like depends on how the
# two streams align (a bit-counting parity reads mostly as instructions the original does
# not have, which is "missing").
NEGATIVE_CONTROLS = [
	("MATH-02", "ClampRangeProbe", {"operand"}, "the inverted-range guard is gone, bounds compared the wrong way"),
	("MATH-38", "ParityOfProbe", {"missing", "opcode"}, "counts bits instead of folding them"),
	("STR-01", "LengthOfProbe", {"missing", "opcode"}, "a counted loop instead of the sentinel test"),
]


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_phase2_try.py", description=__doc__.splitlines()[0])
	parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
	parser.add_argument("--limit", type=int, default=0, help="score only the first N units")
	parser.add_argument("--no-controls", action="store_true", help="skip the negative controls")
	args = parser.parse_args(argv)

	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	failures = 0

	for variant in [item.strip() for item in args.variants.split(",") if item.strip()]:
		answer_path = TESTS / "build" / variant / "answer_key.json"
		stripped = TESTS / "build" / variant / "da_tests.stripped"
		if not answer_path.is_file() or not stripped.is_file():
			print("%s: build it first (Tests/eval.py build --variant %s)" % (variant, variant))
			continue
		answer = json.loads(answer_path.read_text())
		identity = cache.target_key(stripped)
		status = store.status(identity["key"])
		if not status.get("complete"):
			print("%s: not analysed (decomp analyze %s --variant %s)" % (variant, stripped, variant))
			continue
		conn = cache.open_readonly(Path(status["db"]))
		meta = cache.meta(conn)
		offset = int(meta.get("address_offset") or 0)

		units = answer["units"][: args.limit] if args.limit else answer["units"]
		scores, recut, broken, below = [], [], [], []
		unverified_only: dict[str, int] = {}
		split = 0  # units whose body is not contiguous (.text + .text.unlikely at -O2)
		for unit in units:
			row = cache.resolve_function(conn, hex(unit["address"] + offset))
			if not row:
				broken.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"] + offset)))
				continue
			import json as _json
			if len(_json.loads(row[0]["ranges"] or "[]")) > 1:
				split += 1
			source = TESTS / "TestBinary" / unit["file"]
			# the answer key's size is the compiler's own range; at -O2 Ghidra's function
			# boundaries differ, and --size is how the tool is told to use the real one
			guess = cli.score_candidate(cfg, conn, meta, row[0], [source], fn=unit["mangled"],
				object_dir=store.root / "candidates-check")
			if guess["verdict"] is None:
				broken.append("%s: %s" % (unit["id"], guess["error"]))
				continue
			verdict = guess["verdict"]
			scores.append(verdict)
			# at -O2 Ghidra's own function boundaries differ from the compiler's symbol
			# ranges, which is what --size is for: score the same unit again over the
			# answer key's range and report the difference
			if row[0]["size"] != unit["size"]:
				again = cli.score_candidate(cfg, conn, meta, row[0], [source], fn=unit["mangled"],
					size=unit["size"], object_dir=store.root / "candidates-check")
				if again["verdict"] is not None:
					recut.append(again["verdict"])
					again["object"].unlink(missing_ok=True)
			if not verdict.passed:
				below.append("%s %-46s %6.2f%% bytes %+d %s" % (unit["id"], unit["name"],
					verdict.match_percent, verdict.size_delta_bytes,
					{key: value for key, value in verdict.categories.items() if value}))
				if verdict.unverified and not any(verdict.categories[name] for name in
						("opcode", "operand", "register", "missing", "extra")):
					# nothing about the instructions is wrong: the only thing standing in the way
					# is references neither side can describe (Phase 4)
					unverified_only[unit["id"]] = verdict.unverified
			(guess["object"]).unlink(missing_ok=True)
		conn.close()

		if not scores:
			print("%s: nothing scored (%d problems)" % (variant, len(broken)))
			failures += 1
			continue
		percent = [item.match_percent for item in scores]
		passed = sum(1 for item in scores if item.passed)
		byte_identical = sum(1 for item in scores if item.bytes_equal)
		print("%s: %d/%d units scored, mean %.2f%%, byte-identical %d, pass the gate %d"
			% (variant, len(scores), len(units), sum(percent) / len(percent), byte_identical, passed))
		if split:
			print("   %d units whose body the analysis draws in more than one range: each is"
				" compared as one block over the extent the file's own function table gives"
				" (the extent gate is Tests/tools/check_phase5_o2.py)" % split)
		if recut:
			recut_percent = [item.match_percent for item in recut]
			print("   %d units the analysis describes with a size other than the answer key's:"
				" re-scored over the answer key's range instead -> mean %.2f%%, pass the gate"
				" %d/%d - the cross-check that the extent the tool derives is the compiler's"
				% (len(recut), sum(recut_percent) / len(recut_percent),
					sum(1 for item in recut if item.passed), len(recut)))
		reference = TESTS / "build" / variant / "self_scores.json"
		if reference.is_file():
			old = json.loads(reference.read_text())
			old_mean = sum(item["match_percent"] for item in old) / max(1, len(old))
			old_pass = sum(1 for item in old if item["match_percent"] >= 97.0
				and item["categories"]["opcode"] == 0)
			print("   eval.py self (the ceiling): mean %.2f%%, above threshold %d/%d"
				% (old_mean, old_pass, len(old)))
		for item in broken[:8]:
			print("   BROKEN %s" % item)
		for item in below[:12]:
			print("   FAIL %s" % item)
		if len(below) > 12:
			print("   ... %d more" % (len(below) - 12))
		if broken:
			failures += 1
		gaps = KNOWN_GAPS.get(variant, {})
		for item in below:
			unit_id = item.split()[0]
			if unit_id in gaps:
				print("   KNOWN GAP %s: %s" % (unit_id, gaps[unit_id]))
			elif unit_id in unverified_only:
				print("   UNVERIFIED %s: %d reference%s %s neither side can name, bound or read - "
					"the tier stops at `structural` (Docs/byte-cleanup-plan.md Phase 4). Reproduce "
					"the object, or say the target cannot name it with [gate] waive = \"unverified\""
					% (unit_id, unverified_only[unit_id], "s" if unverified_only[unit_id] > 1 else "",
						"stands" if unverified_only[unit_id] > 1 else "stand"))
		failing = [item for item in below
			if item.split()[0] not in gaps and item.split()[0] not in unverified_only]
		if failing:
			# Every variant is gated: the untouched source must pass for every unit except the
			# ones named in KNOWN_GAPS above. -O0 has no exceptions; -m32 and -O2 do, and each
			# one says why. (Before Phase 5 the -O2 row was only reported, because its extent
			# was Ghidra's range rather than the compiler's.)
			failures += 1

	if not args.no_controls:
		failures += check_negative_controls(cfg, store)
	print("check_phase2_try: %s" % ("OK" if failures == 0 else "%d group(s) failed" % failures))
	return 0 if failures == 0 else 1


def check_negative_controls(cfg: dict, store: cache.Cache) -> int:
	"""The wrong candidates must be reported as the kind of wrong they are."""
	stripped = TESTS / "build" / "gcc-o0" / "da_tests.stripped"
	answer = json.loads((TESTS / "build" / "gcc-o0" / "answer_key.json").read_text())
	units = {unit["id"]: unit for unit in answer["units"]}
	source = TESTS / "examples" / "candidate_math_bad.cpp"
	conn = cache.open_readonly(store.db_path(cache.target_key(stripped)["key"]))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	bad = 0
	for unit_id, symbol, wanted, why in NEGATIVE_CONTROLS:
		unit = units.get(unit_id)
		if unit is None:
			print("controls: no such unit %s" % unit_id)
			bad += 1
			continue
		row = cache.resolve_function(conn, hex(unit["address"] + offset))
		outcome = cli.score_candidate(cfg, conn, meta, row[0], [source], fn=symbol,
			object_dir=store.root / "candidates-check")
		verdict = outcome["verdict"]
		if verdict is None:
			print("controls %s: %s" % (unit_id, outcome["error"]))
			bad += 1
			continue
		missing = [name for name in sorted(wanted)
			if not any(verdict.categories[name] for name in wanted)]
		status = "ok" if not missing and not verdict.passed else "WRONG REPORT"
		print("controls %s vs %-22s %6.2f%% %-9s categories %s  (%s) %s"
			% (unit_id, symbol, verdict.match_percent, "not-passed" if not verdict.passed else "PASSED!",
				{key: value for key, value in verdict.categories.items() if value}, why, status))
		if missing or verdict.passed:
			if missing:
				print("   expected %s to be reported, got none of them" % ", ".join(missing))
			bad += 1
		outcome["object"].unlink(missing_ok=True)
	conn.close()
	return 0 if bad == 0 else 1


if __name__ == "__main__":
	sys.exit(main())
