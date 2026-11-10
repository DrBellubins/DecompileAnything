#!/usr/bin/env python3
"""Range-level progress: where a percentage is a true statement.

	run: .venv/bin/python Tests/tools/check_range_progress.py [--no-target]

A project is asked for a number ("get this range to 90 %"). Per function that number cannot be the
claim: a wrong function at 97 % is still a wrong function, and in float-heavy code a wrong field
offset hides inside the percentage. What *is* true is a statement about a scope - "x % of these
bytes are reproduced by source that reaches the project's gate tier" - and `decomp progress`
computes it from the cache. What that takes, and what this checks:

1. **the denominator is the scope, not the file.** A scope is a list of spans with spans
   subtracted, because a program's own code is interleaved with the runtime its image linked.
   The count is the analysis' units inside those spans and nothing else.
2. **the numerator counts bytes at the gate only.** Units scored at `structural`, `semantic` and
   `exact` against a gate of `semantic`: the first is attempted, not counted. Tightening the gate
   to `exact` lowers the number without re-scoring anything - the tier is the claim, so the number
   follows the claim.
3. **the attempt, not just the success, has to be recorded.** `decomp try` writes a row for a unit
   that fails the gate too; that is the only thing that separates "attempted, below the gate" from
   "never tried", and a report that cannot tell them apart is not a progress report. The record
   holds the current state of a unit: a re-score replaces it, in either direction.
4. **a byte reached at another variant is not a byte reached here.** Attempts are keyed by variant;
   the count names the one it used.
5. **the match ledger counts as a floor, and says so.** Work gated before the score record existed
   left claims about entities, not a score row; those units count when the claim reaches the gate,
   and the report says where the knowledge came from.
6. **`percent` reproduces the old rule** from the stored categories, so a project still gating on a
   percentage sees its own rule, not a reinterpreted one.
7. **the two records of a project's status agree, or the tool names the stale row.** A scope table
   is a human's sheet; it is never a source of numbers.

The real half runs `decomp try` on a unit of the benchmark and shows the range figure go from 0
bytes at the gate to that unit's bytes - and shows that `--no-record` leaves it at 0.

Exit: 0 all passed, 1 something came out wrong, 2 the real half could not run.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, diff  # noqa: E402

FAILURES: list[str] = []
OK = 0

VARIANT = "gcc-o0"
# a scope of two spans with one span cut out of the first, so nothing in this check can pass by
# reading one contiguous low/high pair
CONFIG = """
threshold = 90.0
[gate]
require = "semantic"
[scope]
range = ["0x10000-0x1ffff", "0x30000-0x3ffff"]
exclude = ["0x18000-0x18fff"]
percent = "bytes at the gate / the scope's bytes"
"""
SPANS = [(0x10000, 0x1FFFF), (0x30000, 0x3FFFF)]
EXCLUDES = [(0x18000, 0x18FFF)]

# 600 B of scope: A + B + C + D. The 300 B unit sits in the excluded span, the 400 B one outside
# both, and neither is part of any number below.
UNITS = [
	(0x10000, 100, "UNIT_A"),
	(0x11000, 200, "UNIT_B"),
	(0x18000, 300, "UNIT_HOLE"),
	(0x20000, 400, "UNIT_OUTSIDE"),
	(0x30000, 50, "UNIT_C"),
	(0x31000, 250, "UNIT_D"),
]
SCOPE_BYTES = 600
SIZES = {entry: size for entry, size, _name in UNITS}

cfg: dict = {}
db: sqlite3.Connection


def ok(what: str, got, want) -> bool:
	global OK
	good = got == want
	print("%s %-66s %r" % ("  ok  " if good else " FAIL ", what, got))
	if good:
		OK += 1
	else:
		FAILURES.append("%s: got %r, want %r" % (what, got, want))
	return good


def truth(what: str, got) -> bool:
	return ok(what, bool(got), True)


def note(label: str, value) -> None:
	print("  note %s: %s" % (label, value))


def seed(tmp: Path) -> None:
	"""A temp project.toml and an analysis cache holding UNITS - nothing else is needed to check
	the arithmetic, and nothing here starts Ghidra or a compiler."""
	root = tmp / "project"
	root.mkdir(parents=True, exist_ok=True)
	(root / "project.toml").write_text(CONFIG)
	global cfg, db
	cfg = config.load(str(root / "project.toml"))
	db = cache.create(tmp / "analysis.db")
	for entry, size, name in UNITS:
		db.execute("INSERT INTO functions (name, entry, size, kind) VALUES (?,?,?,'function')",
			(name, entry, size))
		db.execute("INSERT INTO units (source, entry, end, size, unwind, section)"
			" VALUES ('test',?,?,?,0,'.text')", (entry, entry + size, size))
	db.execute("INSERT INTO meta (key, value) VALUES ('variant', ?)", (VARIANT,))
	db.commit()


def score(entry: int, tier: str, *, variant: str = VARIANT, match: float = 0.0,
	cats: dict | None = None, byte_percent: float = 0.0) -> None:
	"""One attempt in the record, written through the same call `decomp try` makes."""
	with db:
		cache.record_score(db, {"variant": variant, "entry": entry, "name": "?",
			"original_size": SIZES[entry], "candidate_size": SIZES[entry], "gate": "semantic",
			"tier": tier, "tier_rank": diff.tier_rank(tier), "passed": False,
			"match_percent": match, "byte_percent": byte_percent, "cats": cats or {},
			"at": "2026-01-01"})


def report(**kwargs) -> dict:
	kwargs.setdefault("variant", VARIANT)
	return cli.range_progress(cfg, db, {"variant": VARIANT}, SPANS,
		kwargs.pop("excludes", EXCLUDES), **kwargs)


def unit_of(out: dict, entry: int) -> dict:
	return next(item for item in out["units"] if item["entry"] == entry)


def denominator() -> None:
	print("\ndenominator: the scope's own units, and nothing else")
	out = report()
	ok("units in the two spans, minus the hole", out["totals"]["units"], 4)
	ok("bytes in the scope", out["totals"]["bytes"], SCOPE_BYTES)
	ok("the unit outside every span is not counted",
		[hex(item["entry"]) for item in out["units"]],
		["0x10000", "0x11000", "0x30000", "0x31000"])
	wide = cli.range_progress(cfg, db, {"variant": VARIANT}, [(0x10000, 0x3FFFF)],
		[(0x18000, 0x18FFF)], variant=VARIANT)
	ok("one wide span with the hole cut says the same thing plus the unit between the spans",
		(wide["totals"]["units"], wide["totals"]["bytes"]), (5, SCOPE_BYTES + 400))
	narrow = report(excludes=[])
	ok("no exclusion adds the hole back", (narrow["totals"]["units"], narrow["totals"]["bytes"]),
		(5, SCOPE_BYTES + 300))
	ok("identical function tables dispute nothing", out["extent_conflicts"], 0)
	ok("the scope in the config is what the tool would use",
		[config.scope(cfg)["ranges"], config.scope(cfg)["excludes"]],
		[["0x10000-0x1ffff", "0x30000-0x3ffff"], ["0x18000-0x18fff"]])


def numerator() -> None:
	print("\nnumerator: bytes at the gate, following the gate the project states")
	score(0x10000, "structural", match=100.0, cats={"opcode": 0, "operand": 1})
	score(0x30000, "semantic", match=100.0)
	score(0x31000, "exact", match=100.0)
	t = report()["totals"]
	ok("at the gate (semantic + exact)", (t["at_gate"], t["at_gate_bytes"]), (2, 300))
	ok("attempted but below the gate (structural)", (t["attempted"], t["attempted_bytes"]),
		(1, 100))
	ok("never attempted", (t["unattempted"], t["unattempted_bytes"]), (1, 200))
	ok("the percentage is bytes at the gate over the scope", t["percent"],
		round(100.0 * 300 / SCOPE_BYTES, 2))
	ok("the tier histogram names only what was counted at the gate", t["tiers"],
		{"semantic": 1, "exact": 1})
	ok("and the units below it are counted separately", t["tiers_below"], {"structural": 1})
	full = report()
	ok("the bar is the project's, and this range is not at it", (full["bar"], full["met"]),
		(90.0, False))

	tight = report(require="exact")
	ok("gate `exact` moves the number without re-scoring",
		(tight["totals"]["at_gate"], tight["totals"]["at_gate_bytes"], tight["totals"]["attempted"]),
		(1, 250, 2))
	mid = report(require="structural")
	ok("a lower gate counts every attempt", (mid["totals"]["at_gate"], mid["totals"]["attempted"]),
		(3, 0))
	off = report(require="none")
	ok("`none` turns the gate off: anything attempted counts",
		(off["totals"]["at_gate"], off["totals"]["unattempted"]), (3, 1))

	other = report(variant="gcc-o2")
	ok("an attempt at another variant is not a byte reached here",
		(other["totals"]["at_gate"], other["totals"]["attempted"]), (0, 0))
	truth("and the report says the record holds attempts at another variant",
		any("gcc-o0" in line for line in other["notes"]))
	try:
		report(require="nonsense")
		ok("an unknown gate is a config error, not a silent default", "no error", "ConfigError")
	except config.ConfigError:
		ok("an unknown gate is a config error, not a silent default", "ConfigError", "ConfigError")


def current_state() -> None:
	print("\nthe record is the current state of a unit, not its history")
	ok("this unit has no attempt yet", (unit_of(report(), 0x11000)["state"],
		report()["totals"]["unattempted"]), ("unattempted", 1))
	score(0x11000, "structural", match=60.0)
	ok("an attempt below the gate is reported as attempted, not as untried",
		(unit_of(report(), 0x11000)["state"], report()["totals"]["unattempted"]),
		("attempted", 0))
	score(0x11000, "semantic", match=100.0)
	ok("a later attempt that reaches the gate replaces it",
		unit_of(report(), 0x11000)["state"], "at_gate")
	score(0x11000, "structural", match=40.0)
	ok("and so does a regression - the number is what the source reaches now",
		unit_of(report(), 0x11000)["state"], "attempted")
	score(0x11000, "exact", match=100.0, variant="gcc-o2")
	ok("across variants, the reading that reached the highest tier is what `any` answers",
		cache.score_index(db, variant="")[0x11000]["tier"], "exact")
	score(0x11000, "structural", match=100.0, byte_percent=100.0)
	out = report()
	ok("every byte reproduced but the tier short is counted as capped, not as untried",
		out["totals"]["byte_complete_capped"], 1)


def percent_gate() -> None:
	print("\nthe old percentage rule, kept honestly")
	for match, cats, want in ((95.0, {"opcode": 0, "relocation": 0}, True),
			(95.0, {"opcode": 1, "relocation": 0}, False), (89.0, {}, False)):
		score(0x11000, "none", match=match, cats=cats)
		ok("gate `percent` at %s %% with %s" % (match, cats or "no categories"),
			unit_of(report(require="percent"), 0x11000)["state"] == "at_gate", want)


def ledger_floor() -> None:
	print("\nthe match ledger: a floor for work gated before the record existed")
	with db:
		db.execute("INSERT INTO matches (variant, entry, kind, candidate, evidence, tier, unit,"
			" unit_entry, source, at) VALUES (?,?,?,?,?,?,?,?,?,?)",
			(VARIANT, 0x20000, "function", "thing", "unit", "semantic", "UNIT_OUTSIDE", 0x10000,
				"", "2026-01-01"))
	out = report()
	unit = unit_of(out, 0x10000)
	ok("a claim this unit proved at the gate tier counts", unit["state"], "at_gate")
	ok("and the record says the knowledge came from the ledger", unit["known_from"], "ledger")
	ok("a ledger claim below the gate requested does not count",
		unit_of(report(require="exact"), 0x10000)["state"], "attempted")


def scope_sheet() -> None:
	print("\nthe project's own scope sheet is checked, never used")
	with db:
		# a clean record: what the sheet claims is then all the sheet's
		db.execute("DELETE FROM scores")
		db.execute("DELETE FROM matches")
	sheet = Path(tempfile.mkdtemp()) / "SCOPE.md"
	sheet.write_text("# scope\n\n| # | entry | size | status |\n|---|---|---:|---|\n"
		"| 1 | `10000` | 100 | matched semantic |\n"
		"| 2 | `11000` | 200 | partial 87.50% - one clamp instruction |\n"
		"| 3 | `31000` | 250 | todo |\n")
	check = report(scope_table=sheet)["scope_table"]
	ok("the sheet's rows are read", check["rows"], 3)
	ok("a `matched` row with nothing behind it is named as stale",
		[hex(entry) for entry, _status, _why in check["stale"]], ["0x10000"])
	ok("a row describing an attempt the record lacks is counted", check["unrecorded_attempts"], 1)
	score(0x31000, "exact")
	check = report(scope_table=sheet)["scope_table"]
	ok("an at-the-gate unit the sheet still calls `todo` is named the other way",
		[hex(entry) for entry, _status, _tier in check["undocumented"]], ["0x31000"])
	ok("the record, not the sheet, is what the numbers come from",
		report(scope_table=sheet)["totals"]["at_gate_bytes"], 250)
	truth("and a disagreement is what the note says",
		any("scope table disagrees" in line for line in report(scope_table=sheet)["notes"]))
	fixed = sheet.with_name("SCOPE-agrees.md")
	score(0x11000, "structural", match=60.0)  # the record now matches the sheet below
	fixed.write_text("| # | entry | size | status |\n|---|---|---:|---|\n"
		"| 1 | `10000` | 100 | todo |\n"
		"| 2 | `11000` | 200 | partial 60.00% - operand diff |\n"
		"| 3 | `31000` | 250 | matched exact |\n")
	agree = report(scope_table=fixed)
	ok("a sheet that matches the record contradicts nothing",
		[bool(agree["scope_table"]["stale"] or agree["scope_table"]["undocumented"]),
			agree["scope_table"]["unrecorded_attempts"]], [False, 0])
	truth("and says so", any("agrees with the record" in line for line in agree["notes"]))


# --------------------------------------------------------------------------------------
# the real thing: `decomp try` writing the record, and `decomp progress` reading it


def target_run() -> int:
	print("\nreal target: decomp try records the attempt, pass or fail")
	stripped = TESTS / "build" / "gcc-o0" / "da_tests.stripped"
	answer_path = TESTS / "build" / "gcc-o0" / "answer_key.json"
	if not stripped.is_file() or not answer_path.is_file():
		print("  skip: build it first (Tests/eval.py build --variant gcc-o0)")
		return 2
	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	key = cache.target_key(stripped)["key"]
	if not store.status(key).get("complete"):
		print("  skip: not analysed (decomp analyze %s --variant gcc-o0)" % stripped)
		return 2

	def scope_progress() -> dict:
		conn = cache.open_readonly(store.db_path(key))
		try:
			meta = cache.meta(conn)
			return cli.range_progress(cfg, conn, meta, span, [], variant="gcc-o0")
		finally:
			conn.close()

	conn = cache.open_readonly(store.db_path(key))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	pick = min(json.loads(answer_path.read_text())["units"], key=lambda unit: unit["size"])
	row = cache.resolve_function(conn, hex(pick["address"] + offset))
	conn.close()
	if not row:
		print("  skip: no cached function for %s" % pick["id"])
		return 2
	entry = int(row[0]["entry"])
	size = int(row[0]["size"])
	span = [(entry, entry + size - 1)]
	# the check writes into the shared benchmark cache, so it starts by removing its own record:
	# "nothing attempted" has to mean that, not "nobody has run this check before"
	with sqlite3.connect(store.db_path(key)) as w:
		cache.ensure_scores(w)
		gone = w.execute("DELETE FROM scores WHERE variant = ? AND entry = ?",
			("gcc-o0", entry)).rowcount
	if gone:
		note("a previous run's record for this unit was removed first", "%d row" % gone)
	base = [sys.executable, "-m", "decomp", "try", hex(entry),
		str(TESTS / "TestBinary" / pick["file"]), "--bin", str(stripped),
		"-C", str(TESTS / "project.toml"), "-v", "gcc-o0", "--no-learn",
		"--fn", pick["mangled"]]

	before = scope_progress()
	ok("one unit in the scope, nothing at the gate before the run",
		(before["totals"]["units"], before["totals"]["bytes"], before["totals"]["at_gate"]),
		(1, size, 0))
	run = subprocess.run(base + ["--no-record"], capture_output=True, text=True)
	ok("--no-record: the unit is scored anyway (exit %d)" % run.returncode,
		run.returncode in (0, 1), True)
	kept = scope_progress()
	ok("--no-record leaves the scope at 0 bytes at the gate", kept["totals"]["at_gate"], 0)
	ok("and the unit still reads as never attempted",
		unit_of(kept, entry)["state"], "unattempted")
	run = subprocess.run(base, capture_output=True, text=True)
	ok("the same run without --no-record (exit %d)" % run.returncode, run.returncode in (0, 1),
		True)
	after = scope_progress()
	tier = unit_of(after, entry)["tier"]
	ok("the attempt is now in the record", bool(unit_of(after, entry)["at"]), True)
	at_gate = after["totals"]["at_gate_bytes"]
	ok("counted at the gate exactly when it reaches it", at_gate,
		size if tier in ("semantic", "exact") else 0)
	ok("the scope's percentage follows", after["totals"]["percent"],
		100.0 if at_gate == size and size else round(100.0 * at_gate / size, 2))
	note("%s at %s" % (pick["id"], hex(entry)),
		"tier %s; the scope is %d B, of which %d B at the gate" % (tier, size, at_gate))
	return 0


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_range_progress.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--no-target", action="store_true", help="the rules only, no benchmark")
	args = parser.parse_args(argv)

	seed(Path(tempfile.mkdtemp(prefix="decomp-range-check")))
	denominator()
	numerator()
	current_state()
	percent_gate()
	ledger_floor()
	scope_sheet()
	db.close()
	rc = 0
	if not args.no_target:
		rc = target_run()
		if rc == 2:
			print("\nthe rules passed, but the record was never exercised through `decomp try`")
	print()
	if FAILURES:
		print("%d FAILED:" % len(FAILURES))
		for failure in FAILURES:
			print("  %s" % failure)
		return 1
	print("%d checks passed" % OK)
	return rc


if __name__ == "__main__":
	sys.exit(main())
