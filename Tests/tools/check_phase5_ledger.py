#!/usr/bin/env python3
"""Phase 5 (Docs/byte-cleanup-plan.md): callee identity through a match ledger.

Two bodies of code that call a helper of the same size are not known to call the *same* helper.
Until now the comparison said "equal size" and moved on, and the token for an anonymous callee was
its position in whichever body was being compared - so `SYM3` in one unit and `SYM3` in the next
named unrelated things, and nothing the loop learned about one function carried to the next.

This checks the two rules that replace that.

**A same-size match is not evidence.** It is counted with the references that are not verified, so
a unit that calls an unnamed helper stops at `structural` and the report says what is missing: go
and reproduce the callee first.

**What has been shown is a claim.** `decomp try` records, for a unit that reached the gate, which
candidate symbol reproduces which entity in the original's addresses (`matches` in the analysis
cache, keyed by variant). From then on every unit that reaches that entity is scored against it:
the token is the ledger's, the candidate has to name it that way, and a candidate that names a
different same-size helper *fails*. `decomp ledger` prints the pairs and the frontier - the callees
the already-reproduced units reach that the ledger has no name for - which is the answer to "what
do I decompile next".

Run:
  .venv/bin/python Tests/tools/check_phase5_ledger.py            # everything
  .venv/bin/python Tests/tools/check_phase5_ledger.py --no-target # the rules only (fast)
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, diff, normalize  # noqa: E402

FAILURES: list[str] = []
OK = 0
VARIANT = "gcc-o0"
# -O0 is where the same-size case is unavoidable: the unit calls a helper in its own translation
# unit, the stripped binary gives it a made-up name, and both bodies are 60-some bytes.
UNIT = "MATH-24"


def ok(what: str, got, want) -> bool:
	global OK
	good = got == want
	print("%s %-62s %r" % ("  ok  " if good else " FAIL ", what, got))
	if good:
		OK += 1
	else:
		FAILURES.append("%s: got %r, want %r" % (what, got, want))
	return good


def truth(what: str, got) -> bool:
	return ok(what, bool(got), True)


def stream(lines: list[str]) -> list[normalize.Token]:
	return [normalize.Token(text=text, mnemonic=text.split()[0], address=0x1000 + 4 * index)
		for index, text in enumerate(lines)]


def score(left: normalize.Ref, right: normalize.Ref, *, ledger: dict[int, list[dict]] | None = None,
		text: str = "call FUN_0", token: str = "SYM0") -> diff.Verdict:
	"""One call instruction, reaching `left` on the original and `right` in the candidate."""
	a, b = stream([text]), stream([text])
	a[0].refs.append(left)
	b[0].refs.append(right)
	vocabulary = normalize.Vocabulary()
	vocabulary.entries["original"].append((token, left))
	vocabulary.entries["candidate"].append((token, right))
	return diff.compare(a, b, vocabulary, threshold=0.0, ledger=ledger)


def row(entry: int, name: str, *, kind: str = "function", evidence: str = "unit",
		unit: str = "FUN_00103392") -> dict:
	"""A ledger row in the shape `cache.match_rows` returns."""
	return {"variant": VARIANT, "entry": entry, "kind": kind, "candidate": name,
		"evidence": evidence, "tier": "exact", "unit": unit, "unit_entry": 0x103392,
		"at": "2026-11-06"}


# --------------------------------------------------------------------------------------
# 1. equal size is not a name

HELPER_SIZE = 60


def size_is_not_a_name() -> None:
	helper = normalize.Ref(kind="function", raw="FUN_00102e1e", address=0x102e1e,
		size=HELPER_SIZE)
	other = normalize.Ref(kind="function", name="_ZN10CMathTests16SquareRootNewtonEf",
		raw="_ZN10CMathTests16SquareRootNewtonEf", size=HELPER_SIZE)
	verdict = score(helper, other)
	symbol = verdict.symbols[0]
	ok("a same-size callee still matches (nothing says it is wrong)", symbol["ok"], True)
	ok("but it is named as resting on size alone", symbol["evidence"], "size")
	ok("and it is counted with the references that are not verified", verdict.unverified, 1)
	ok("so the tier stops at structural", (verdict.tier, verdict.passed), ("structural", False))
	truth("the gap says which reference and what to do about it",
		any("SYM0" in line and "same size" in line and "decompile the callee first" in line
			for line in verdict.gaps("semantic")))
	truth("and so does the report", any("same size" in line and "match ledger" in line
		for line in diff.report_lines(verdict, "orig", "cand")))
	ok("a thunk to an import is the same case", score(
		normalize.Ref(kind="external", raw="FUN_080563e0", address=0x80563e0, size=16),
		normalize.Ref(kind="external", name="__dynamic_cast", raw="__dynamic_cast",
			size=16)).unverified, 1)
	ok("size is not something the ledger will bank on", "size" in diff.PROVEN_EVIDENCE, False)
	ok("name, string and bytes are",
		[item in diff.PROVEN_EVIDENCE for item in ("name", "string", "bytes", "ledger")],
		[True] * 4)
	# Phase 4's counter is untouched: an unnamed object with no width is still the other reason,
	# and the report has to tell the two apart because the fixes are different.
	in_memory = normalize.Ref(kind="data", raw="DAT_080de6e0", address=0x80de6e0)
	counters = normalize.Ref(kind="data", name="g_counters", raw="g_counters")
	alone = score(in_memory, counters, text="movl DAT0, %eax", token="DAT0")
	ok("an unnamed object is still unverified, and says so differently",
		(alone.unverified, alone.unverified_refs[0]["why"] == "nothing on either side names it"),
		(1, True))
	# a unit that has both in it is told about both, because the two have different fixes
	left = stream(["call FUN_0", "movl DAT0, %eax"])
	right = stream(["call FUN_0", "movl DAT0, %eax"])
	left[0].refs.append(helper)
	right[0].refs.append(other)
	left[1].refs.append(in_memory)
	right[1].refs.append(counters)
	vocabulary = normalize.Vocabulary()
	vocabulary.entries["original"] = [("SYM0", helper), ("DAT0", in_memory)]
	vocabulary.entries["candidate"] = [("SYM0", other), ("DAT0", counters)]
	mixed = diff.compare(left, right, vocabulary, threshold=0.0)
	ok("a unit with both kinds counts both", mixed.unverified, 2)
	truth("and the report names both reasons",
		any("neither side can name, bound or read it" in line and "same size" in line
			for line in mixed.gaps("semantic")))


# --------------------------------------------------------------------------------------
# 2. once something has been shown, the candidate has to name it that way

def the_ledger_decides() -> None:
	helper = normalize.Ref(kind="function", raw="FUN_00102e1e", address=0x102e1e,
		size=HELPER_SIZE)
	proven = "_ZN10CMathTests16SquareRootNewtonEf"
	wrong = "_ZN10CMathTests12Vec3LengthSqERK5CVec3"
	known = {0x102e1e: [row(0x102e1e, proven)]}
	candidate = normalize.Ref(kind="function", name=proven, raw=proven, size=HELPER_SIZE)

	verdict = score(helper, candidate, ledger=known)
	ok("the ledger turns the same-size match into evidence",
		(verdict.symbols[0]["evidence"], verdict.unverified, verdict.tier, verdict.passed),
		("ledger", 0, "semantic", True))
	swapped = score(normalize.Ref(kind="function", name=wrong, raw=wrong, size=HELPER_SIZE),
		candidate, ledger=known)
	# both sides carry real names, so the name rule already refused this one - the ledger is the
	# only way to tell it for an anonymous original, which is the case below
	ok("two named callees that differ were never allowed", swapped.symbols[0]["ok"], False)

	# the plan's acceptance: two same-size helpers, swapped. The original is anonymous (a stripped
	# binary), the candidate names one of them, and the ledger has the other.
	swapped = score(helper, normalize.Ref(kind="function", name=wrong, raw=wrong,
		size=HELPER_SIZE), ledger=known)
	truth("a swapped same-size helper fails once either is in the ledger",
		not swapped.symbols[0]["ok"] and "the ledger says" in swapped.symbols[0]["why"])
	truth("and it names the unit that showed the pair",
		"FUN_00103392" in swapped.symbols[0]["why"])
	ok("so the tier stops at none", (swapped.tier, swapped.passed), ("none", False))
	truth("the report repeats it", any("the ledger says" in line
		for line in diff.report_lines(swapped, "orig", "cand")))

	# a candidate that reaches nothing by name claims nothing, so nothing is refuted: that is the
	# frontier, and it has to show up as unverified rather than as a pass
	blank = score(helper, normalize.Ref(kind="function", raw="", size=HELPER_SIZE), ledger=known)
	ok("a candidate that names nothing is not refuted, just unverified",
		(blank.symbols[0]["ok"], blank.unverified, blank.tier), (True, 1, "structural"))

	# the ledger is evidence, not a licence: a size difference is still a difference
	clash = score(normalize.Ref(kind="function", raw="FUN_00102e1e", address=0x102e1e,
		size=HELPER_SIZE),
		normalize.Ref(kind="function", name=proven, raw=proven, size=HELPER_SIZE - 2),
		ledger=known)
	truth("it does not rescue a different-sized body",
		not clash.symbols[0]["ok"] and "bytes there" in clash.symbols[0]["why"])

	# an entity the ledger knows is one entity: a second row for the same address (the same
	# helper, named by another unit) agrees with the first and changes nothing
	two_rows = score(helper, candidate, ledger={0x102e1e: [
		row(0x102e1e, proven), row(0x102e1e, proven, unit="FUN_001034d4")]})
	ok("two units proving the same pair is not a contradiction",
		(two_rows.symbols[0]["evidence"], two_rows.symbols[0]["ok"]), ("ledger", True))
	# ... and two rows that disagree are the interesting case: the first one that matches wins,
	# and a candidate matching either is not failed for the other's sake
	either = score(helper, normalize.Ref(kind="function", name=wrong, raw=wrong,
		size=HELPER_SIZE),
		ledger={0x102e1e: [row(0x102e1e, wrong, unit="FUN_001034d4")]})
	ok("a different unit's proof is a proof too", either.symbols[0]["evidence"], "ledger")


# --------------------------------------------------------------------------------------
# 3. one entity is one token, in every unit

def tokens_are_stable() -> None:
	rows = [row(0x102e1e, "_ZN10CMathTests16SquareRootNewtonEf")]
	helper = normalize.Ref(kind="function", raw="FUN_00102e1e", address=0x102e1e)
	callee = normalize.Ref(kind="function", name="_ZN10CMathTests16SquareRootNewtonEf",
		raw="_ZN10CMathTests16SquareRootNewtonEf")

	first = normalize.Vocabulary()
	first.seed_ledger(rows)
	second = normalize.Vocabulary()
	second.seed_ledger(rows)
	ok("the callee the ledger knows gets the same token in two different units",
		(first.token_for("original", helper), second.token_for("original", helper)), ("SYM0", "SYM0"))
	ok("and the candidate meets it there, by the name the ledger recorded",
		first.token_for("candidate", callee), first.token_for("original", helper))

	third = normalize.Vocabulary()
	third.seed_ledger(rows)
	other = normalize.Ref(kind="function", raw="FUN_001033e4", address=0x1033e4)
	ok("an unnamed helper in the same body is still a different token",
		(third.token_for("original", helper), third.token_for("original", other)),
		("SYM0", "SYM1"))
	# seeded tokens are numbered ahead of whatever either side counts later, so a seeded token can
	# never be handed out twice
	late = normalize.Vocabulary()
	late.token_for("original", normalize.Ref(kind="function", raw="x", address=1))
	late.token_for("original", normalize.Ref(kind="function", raw="y", address=2))
	late.seed_ledger(rows)
	ok("seeding after positional tokens were handed out does not collide",
		late.token_for("original", helper), "SYM2")

	# the guard on the name side: a candidate reference resolved to an offset inside a section is
	# named there by whatever symbol sits nearest before it, which is not a claim about the entity
	data_row = [row(0x110040, "k_lodDistances", kind="data", evidence="bytes")]
	data = normalize.Vocabulary()
	data.seed_ledger(data_row)
	ok("a data row does not seed a token (the pool carries no key back to the address)",
		data.token_for("candidate", normalize.Ref(kind="data", name="k_lodDistances",
			raw="k_lodDistances", address=0x280, identity="section:.rodata+0x280")), "DAT0")
	guard = normalize.Vocabulary()
	guard.seed_ledger(rows)
	# the seeded number is reserved, so a reference that does not take it is counted after it
	ok("and a function reference resolved to a section offset is not read as the ledger's entity",
		guard.token_for("candidate", normalize.Ref(kind="function", name=rows[0]["candidate"],
			raw="_ZL9helperPdf+0x10", identity="section:.text+0x40")), "SYM1")
	ok("while the symbol itself takes the ledger's token", guard.token_for("candidate", callee),
		guard.token_for("original", helper))
	# the identity merge still comes first: two offsets of one object meet at one token whichever
	# of them the ledger happens to know
	vtable = normalize.Vocabulary()
	vtable.seed_ledger([row(0x110040, "_ZTV9CVehicle", kind="data")])
	ok("an object named by identity is one token even with a row for one offset",
		vtable.token_for("candidate", normalize.Ref(kind="data", name="_ZTV9CVehicle",
			raw="_ZTV9CVehicle+16", identity="symbol:_ZTV9CVehicle")),
		vtable.token_for("candidate", normalize.Ref(kind="data", name="_ZTV9CVehicle",
			raw="_ZTV9CVehicle+40", identity="symbol:_ZTV9CVehicle")))


# --------------------------------------------------------------------------------------
# 4. the real target: what `try` banks, and what banking buys

def target_run() -> int:
	"""Score one real unit with no ledger, then with the pairs `try` would have written."""
	binary = TESTS / "build" / VARIANT / "da_tests.stripped"
	answer = TESTS / "build" / VARIANT / "answer_key.json"
	if not binary.is_file() or not answer.is_file():
		print("  note %s not built (Tests/eval.py build --variant %s)" % (VARIANT, VARIANT))
		return 0
	source_cfg = config.load(str(TESTS / "project.toml"))
	measured = cache.Cache(config.cache_dir(source_cfg))
	key = cache.target_key(binary)["key"]
	if not measured.status(key).get("complete"):
		print("  note %s not analysed (decomp analyze ... --variant %s)" % (VARIANT, VARIANT))
		return 0

	# A copy of the analysis, so writing a ledger here cannot change what the other suites measure:
	# the ledger is per target and per variant, and it changes scores by design.
	scratch = REPO / "cache" / "phase5-ledger"
	unit_dir = scratch / key
	if unit_dir.is_dir():
		shutil.rmtree(unit_dir)
	unit_dir.parent.mkdir(parents=True, exist_ok=True)
	shutil.copytree(measured.root / key, unit_dir)
	db = unit_dir / "analysis.db"
	# The copy starts with the shared cache's ledger, and that is not empty: any suite that ran
	# `try` against the real analysis banked rows there (the same rows are in `decomp ledger` for the
	# project). This suite measures what *it* banks, so the inherited rows are cleared here - not
	# asserted away. (Docs/x86-32bit-issues.md §21.)
	fresh = sqlite3.connect(db)
	try:
		fresh.execute("DELETE FROM matches")
		fresh.commit()
	finally:
		fresh.close()
	# The config has to sit next to the project's own: its include and build paths are relative to
	# it. Only `cache_dir` moves, to the copy above.
	scratch_cfg = TESTS / "phase5-scratch.toml"
	scratch_cfg.write_text((TESTS / "project.toml").read_text().replace(
		'cache_dir = "../cache/ghproj"', 'cache_dir = "../cache/phase5-ledger"'))
	cfg = config.load(str(scratch_cfg))
	units = {item["id"]: item for item in json.loads(answer.read_text())["units"]}
	unit = units[UNIT]
	conn = cache.open_readonly(db)
	at = int(unit["address"]) + int(cache.meta(conn).get("address_offset") or 0)
	conn.close()

	def score_unit(label):
		"""Score the answer key's source for this unit and say what the verdict claims."""
		conn = cache.open_readonly(db)
		try:
			meta = cache.meta(conn)
			row = cache.resolve_function(conn, hex(int(unit["address"])
				+ int(meta.get("address_offset") or 0)))[0]
			outcome = cli.score_candidate(cfg, conn, meta, row,
				[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"],
				object_dir=scratch / "candidates")
			if outcome["verdict"] is None:
				raise SystemExit("check_phase5_ledger: %s could not be scored: %s"
					% (UNIT, outcome["error"]))
			outcome["object"].unlink(missing_ok=True)
			print("  note %s: %s passed=%s unverified=%d" % (label, outcome["verdict"].tier,
				outcome["verdict"].passed, outcome["verdict"].unverified))
			return row, outcome
		finally:
			conn.close()

	def bank(rows):
		"""Write ledger rows the way `try` does, then close so readers see them."""
		writable = sqlite3.connect(db)
		try:
			count = cache.record_matches(writable, rows)
		finally:
			writable.commit()
			writable.close()
		return count

	def rows_written():
		conn = cache.open_readonly(db)
		try:
			return cache.match_rows(conn, VARIANT)
		finally:
			conn.close()

	def run(*argv):
		finished = subprocess.run([sys.executable, "-m", "decomp", *argv], cwd=str(REPO),
			capture_output=True, text=True, timeout=900)
		return finished.returncode, finished.stdout + finished.stderr

	ok("a copied analysis starts with an empty ledger", rows_written(), [])
	bare_row, bare = score_unit("no ledger")
	bare_verdict = bare["verdict"]
	callees = [item for item in bare_verdict.symbols
		if item["evidence"] == "size" and item["original"].get("address")]
	ok("this unit rests on same-size callees alone", len(callees) >= 1, True)
	ok("so it stops short of the gate", (bare_verdict.tier, bare_verdict.passed),
		("structural", False))
	# with nothing banked there is no frontier, so the honest answer is every callee in the
	# analysis, most-called first - which is what `decomp ledger` prints in that state
	conn = cache.open_readonly(db)
	seeds = cache.callees_of(conn, among=None, exclude=set(), limit=10)
	conn.close()
	ok("the seed list is ordered by how many functions call it",
		[item["callers"] for item in seeds],
		sorted((item["callers"] for item in seeds), reverse=True))
	truth("and it is real code: %d callees, the first reached by %d functions"
		% (len(seeds), seeds[0]["callers"] if seeds else 0), len(seeds) >= 5)

	# `--no-learn` is the switch for people who want to score a guess without the loop remembering
	# it; a unit that does not reach the gate writes nothing either way
	code, out = run("try", hex(at), str(TESTS / "TestBinary" / unit["file"]),
		"--config", str(scratch_cfg), "--variant", VARIANT, "--fn", unit["mangled"],
		"--no-learn")
	ok("`try --no-learn` leaves the ledger alone", (bool(callees), len(rows_written())),
		(True, 0))
	ok("and a unit that does not reach the gate is not banked either",
		(code != 0, len(rows_written())), (True, 0))

	# what `try` banks for a unit that reaches the gate: its own name at this address, and nothing
	# it only matched on size
	written = cli._learn(db, bare_row, VARIANT, bare_verdict, bare["candidate"])
	banked = rows_written()
	ok("`try` banks the unit's own symbol at the original's address",
		[(item["entry"], item["candidate"], item["evidence"]) for item in banked
			if item["entry"] == at], [(at, bare["candidate"].raw_name, "unit")])
	ok("in a stripped binary that pair is the only thing that names this function",
		[str(item["kind"]) for item in banked if item["entry"] == at], ["function"])
	ok("and nothing is banked on the strength of equal size",
		[item["evidence"] for item in banked if item["evidence"] == "size"], [])
	ok("everything banked is evidence the ledger accepts",
		{item["evidence"] for item in banked} <= set(diff.PROVEN_EVIDENCE) | {"unit"}, True)
	ok("the note the report prints counts the same rows", written["written"], len(banked))

	# the frontier: what the units already banked reach that the ledger has no name for. This is the
	# whole point of the ledger for the loop - it names the next thing to decompile.
	conn = cache.open_readonly(db)
	known = cache.matched_entries(conn, VARIANT)
	frontier = cache.callees_of(conn, among=known, exclude=known, limit=20)
	conn.close()
	ok("the frontier excludes what the ledger already knows",
		[bool({item["entry"]} & known) for item in frontier], [False] * len(frontier))
	ok("and it names the very callee that capped this unit",
		callees[0]["original"]["address"] in {item["entry"] for item in frontier}, True)
	ok("ordered by how many functions call it", [item["callers"] for item in frontier],
		sorted((item["callers"] for item in frontier), reverse=True))
	for item in frontier[:5]:
		print("  note frontier: %s %s (%s bytes) called by %d functions, %d sites"
			% (hex(item["entry"]), item.get("name"), item.get("size"), item["callers"],
				item["sites"]))

	# now the pairs those helpers would bank themselves - what `try` writes when each helper is
	# decompiled and passes, one row per helper, keyed by the helper's own entry
	helpers = [{"variant": VARIANT, "entry": item["original"]["address"], "kind": "function",
		"candidate": item["candidate"]["name"], "evidence": "unit", "tier": "exact",
		"unit": item["candidate"]["name"], "unit_entry": item["original"]["address"],
		"at": "2026-11-06"} for item in callees]
	ok("the helper pairs are banked with the names the candidate already used",
		bank(helpers), len(helpers))
	_, filled = score_unit("with the ledger")
	filled_verdict = filled["verdict"]
	ok("the same unit now reaches the top tier",
		(filled_verdict.tier, filled_verdict.passed, filled_verdict.unverified),
		("exact", True, 0))
	ok("and every callee reference says the ledger proved it",
		{item["evidence"] for item in filled_verdict.symbols
			if item["original"].get("address") in {row["entry"] for row in helpers}}, {"ledger"})
	conn = cache.open_readonly(db)
	known = cache.matched_entries(conn, VARIANT)
	still = {item["entry"] for item in cache.callees_of(conn, among=known, exclude=known, limit=20)}
	conn.close()
	ok("a name that is banked comes off the frontier", helpers[0]["entry"] in still, False)

	# the same thing through the CLI: this unit now passes, so `try` banks it and says so
	code, out = run("try", hex(at), str(TESTS / "TestBinary" / unit["file"]),
		"--config", str(scratch_cfg), "--variant", VARIANT, "--fn", unit["mangled"])
	ok("`try` on a unit that reaches the gate says what it learned",
		(code, "learned:" in out and "decomp ledger" in out), (0, True))
	ok("and the row it wrote is the unit's own symbol",
		[(item["entry"], item["candidate"]) for item in rows_written() if item["entry"] == at],
		[(at, bare["candidate"].raw_name)])
	code, out = run("ledger", "--bin", str(binary), "--config", str(scratch_cfg),
		"--variant", VARIANT)
	ok("`decomp ledger` lists the pairs and the frontier",
		(code, "matched (" in out, "frontier" in out, unit["mangled"] in out), (0, True, True, True))
	print("  note `decomp ledger` says:")
	for line in out.splitlines():
		print("       %s" % line)
	code, out = run("ledger", "--bin", str(binary), "--config", str(scratch_cfg), "--json")
	payload = json.loads(out) if code == 0 else {}
	ok("--json carries the pairs, the variant they were proven under, and the frontier",
		(payload.get("pairs", 0) > 0, payload.get("variant") == VARIANT, "frontier" in payload,
			"other_variants" in payload), (True, True, True, True))

	# the plan's acceptance, on real bytes: swap one of those helpers for a name the candidate never
	# used at that address. The unit that calls it has to fail, not merely stop.
	writable = sqlite3.connect(db)
	writable.execute("UPDATE matches SET candidate = ?, unit = 'FUN_wrong' WHERE variant = ?"
		" AND entry = ? AND kind = 'function' AND candidate = ?",
		(helpers[0]["candidate"] + "_not", VARIANT, helpers[0]["entry"], helpers[0]["candidate"]))
	writable.commit()
	writable.close()
	_, swapped = score_unit("one helper renamed in the ledger")
	ok("a same-size helper swapped in the candidate now fails", swapped["verdict"].passed, False)
	truth("and the report says what the ledger says about that address",
		any("the ledger says" in line for line in diff.report_lines(
			swapped["verdict"], "orig", "cand", max_symbols=40)))
	return 0


def main() -> int:
	ap = argparse.ArgumentParser()
	ap.add_argument("--no-target", action="store_true", help="the rules only, no benchmark")
	args = ap.parse_args()
	size_is_not_a_name()
	the_ledger_decides()
	tokens_are_stable()
	if not args.no_target:
		target_run()
	print()
	if FAILURES:
		print("%d FAILED:" % len(FAILURES))
		for failure in FAILURES:
			print("  %s" % failure)
		return 1
	print("%d checks passed" % OK)
	return 0


if __name__ == "__main__":
	sys.exit(main())


