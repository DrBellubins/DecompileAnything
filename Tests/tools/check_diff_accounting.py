"""Phase 1 acceptance: the category counts add up to the streams they came from.

	run: .venv/bin/python Tests/tools/check_diff_accounting.py [--variants ...] [--limit N] [--no-benchmark]

`Docs/byte-cleanup-plan.md` Phase 1. A `replace` region whose two sides are different lengths
used to be zipped, so the leftover lines were counted nowhere: "instructions 13 vs 11 (+-2)"
next to "missing 0, extra 0", and the only thing the report could say about a failed unit was
that the streams were "the same shape but not the same length". What is checked:

1. **the leftover lines are reported.** Synthetic streams with deliberately unbalanced replace
   regions - three original lines against one, three against four, and a diff that shrinks in
   one place and grows in another. `missing`/`extra` carry exact counts and the addresses of
   the lines that went away or appeared.
2. **the invariant holds, as an assertion.** `matched + replaced + missing == len(original)`
   and the same on the candidate side, `sum(categories) - hidden == replaced + missing +
   extra`, `len(diff) == sum(categories)`, and `size_delta == extra - missing`. The plan's
   `matched + all categories == max(len, len)` shorthand is asserted in the exact form that
   holds when a diff shrinks in one place and grows in another: `== max + min(missing, extra)`.
3. **every real verdict.** Each unit of each built ELF variant, plus the deliberately wrong
   candidates, through `decomp try`'s own path: `accounting_problems` empty, no internal-error
   note, and no verdict with a different instruction count on the two sides and nothing in
   `missing`/`extra` - which is the signature of the bug this phase removed.

Exit: 0 all passed, 1 something came out wrong, 2 no benchmark build is present.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, diff, normalize  # noqa: E402

DEFAULT_VARIANTS = ["gcc-o0", "gcc-o2", "gcc-o0-x86"]

failures: list[str] = []
notes: list[str] = []


def check(label: str, got, want) -> None:
	if got != want:
		failures.append("%s: got %r, want %r" % (label, got, want))
	else:
		print("  ok   %s = %r" % (label, got))


def note(label: str, value) -> None:
	notes.append("%s: %s" % (label, value))
	print("  note %s: %s" % (label, value))


def stream(lines: list[str]) -> list[normalize.Token]:
	"""One token per line, at 4-byte addresses, so a leftover line can be named by address."""
	return [normalize.Token(text=text, mnemonic=text.split()[0], address=0x1000 + 4 * index)
		for index, text in enumerate(lines)]


def score(original_lines: list[str], candidate_lines: list[str],
	refs: list[tuple[normalize.Ref, normalize.Ref]] | None = None):
	"""`diff.compare` over synthetic token streams. `refs` pairs the tokens that reach something."""
	left, right = stream(original_lines), stream(candidate_lines)
	for index, (a, b) in enumerate(refs or []):
		left[index].refs.append(a)
		right[index].refs.append(b)
	return diff.compare(left, right, normalize.Vocabulary(), threshold=97.0)


def identity(label: str, verdict) -> None:
	"""Every assertion that has to hold for any verdict, whatever its shape."""
	acc = diff.accounting(verdict)
	missing, extra = verdict.categories["missing"], verdict.categories["extra"]
	check("%s: every original line counted" % label,
		acc["matched"] + acc["replaced"] + missing, verdict.original_instructions)
	check("%s: every candidate line counted" % label,
		acc["matched"] + acc["replaced"] + extra, verdict.candidate_instructions)
	check("%s: the categories come from those lines" % label, acc["visible_differences"],
		acc["replaced"] + missing + extra)
	check("%s: no unaccounted count" % label, diff.accounting_problems(verdict), [])
	check("%s: one diff entry per counted line" % label, len(verdict.diff),
		sum(verdict.categories.values()))
	check("%s: the size delta is the leftover lines" % label, verdict.size_delta_instructions,
		extra - missing)
	check("%s: the plan's identity, in its exact form" % label,
		acc["matched"] + acc["visible_differences"],
		max(verdict.original_instructions, verdict.candidate_instructions) + min(missing, extra))
	check("%s: no internal error reported" % label, verdict.warnings, [])
	if verdict.original_instructions != verdict.candidate_instructions:
		# The signature of the bug: a candidate of a different length that reports no lines
		# going away or appearing.
		check("%s: a different length names its lines" % label, bool(missing or extra), True)


# --------------------------------------------------------------------------------------
# 1. unbalanced replace regions


FRAME = ["pushq %rbp", "movq %rsp,%rbp"]


def leftover_lines() -> int:
	print("1. a replace region of unequal length reports the leftover lines")

	# three original lines answered by one: one differing pair, and two lines the candidate
	# does not have
	shrink = score(FRAME + ["subq $0x10,%rsp", "movl $0x0,-0x4(%rbp)", "movl %eax,%edx"],
		FRAME + ["xorl %eax,%eax"])
	check("shrink: matched", shrink.matched, 2)
	check("shrink: paired as one difference", shrink.replaced, 1)
	check("shrink: opcode", shrink.categories["opcode"], 1)
	check("shrink: missing", shrink.categories["missing"], 2)
	check("shrink: extra", shrink.categories["extra"], 0)
	check("shrink: the missing lines are named with their addresses",
		[item["original_address"] for item in shrink.diff if item["category"] == "missing"],
		[0x100c, 0x1010])
	check("shrink: no candidate line invented for them",
		[item["candidate_address"] for item in shrink.diff if item["category"] == "missing"],
		[None, None])
	identity("shrink", shrink)

	# three original lines answered by four: three differing pairs and two extra lines
	grow = score(FRAME + ["movl %eax,%ebx", "movl %ebx,%ecx", "movl %ecx,%edx"],
		FRAME + ["call one", "call two", "call three", "call four", "ret"])
	check("grow: matched", grow.matched, 2)
	check("grow: paired", grow.replaced, 3)
	check("grow: opcode", grow.categories["opcode"], 3)
	check("grow: extra", grow.categories["extra"], 2)
	check("grow: missing", grow.categories["missing"], 0)
	check("grow: the extra lines are named with their addresses",
		[item["candidate_address"] for item in grow.diff if item["category"] == "extra"],
		[0x1014, 0x1018])
	identity("grow", grow)

	# shrinks in one region and grows in another: the form the plan's max(len, len) shorthand
	# cannot reach
	mixed = score(["p0", "p1", "p2", "p3", "p4"], ["p0", "q1", "p3", "p4", "q5", "q6"])
	check("mixed: paired", mixed.replaced, 1)
	check("mixed: missing", mixed.categories["missing"], 1)
	check("mixed: extra", mixed.categories["extra"], 2)
	note("mixed: matched + all categories", "%d vs max(len) %d" % (
		mixed.matched + diff.accounting(mixed)["visible_differences"],
		max(mixed.original_instructions, mixed.candidate_instructions)))
	identity("mixed", mixed)
	return 0


# --------------------------------------------------------------------------------------
# 2. the identity on every shape of diff


def shapes() -> int:
	print("2. the invariant on every shape of diff")
	cases = [
		("identical", FRAME, FRAME),
		("one operand changed", FRAME + ["movl $0x1,%eax"], FRAME + ["movl $0x2,%eax"]),
		("one opcode changed", FRAME + ["addl %eax,%ebx"], FRAME + ["subl %eax,%ebx"]),
		("candidate empty", FRAME + ["ret"], []),
		("original empty", [], FRAME + ["ret"]),
		("prologue replaced by nothing", FRAME, ["ret"]),
		("shrink inside the body", FRAME + ["a1", "a2", "a3", "ret"], FRAME + ["b1", "ret"]),
		("grow inside the body", FRAME + ["a1", "ret"], FRAME + ["b1", "b2", "b3", "ret"]),
		("two shrinks", ["a1", "a2", "a3", "x1", "x2", "x3", "c1", "c2", "c3"],
			["a1", "b2", "x1", "b2", "c1", "b2"]),
		("shrink then grow", ["a1", "a2", "a3", "z1", "z2"], ["a1", "b1", "z1", "b2", "b3"]),
		("grow then shrink", ["a1", "z1", "z2", "a2", "a3"], ["a1", "b1", "b2", "z1", "b3"]),
		("interleaved", ["a1", "a2", "a3", "a4", "a5", "a6"],
			["a1", "b2", "a3", "b4", "b5", "a6", "b7", "b8"]),
	]
	for label, left, right in cases:
		identity(label, score(left, right))

	# a pair of lines that match textually but reach different objects is a hidden
	# relocation: it counts as a difference without being a line of either side
	hidden = score(["call SYM0", "ret"], ["call SYM0", "ret"],
		refs=[(normalize.Ref(kind="function", name="puts"),
			normalize.Ref(kind="function", name="abort"))])
	check("hidden: matched lines are still both matched", hidden.matched, 2)
	check("hidden: counted as relocation", hidden.categories["relocation"], 1)
	check("hidden: it re-counts a matched line", hidden.hidden_relocations, 1)
	check("hidden: no other category moved",
		{key: value for key, value in hidden.categories.items() if key != "relocation"},
		{"opcode": 0, "operand": 0, "register": 0, "missing": 0, "extra": 0})
	identity("hidden", hidden)

	# and one of each at once
	both = score(["call SYM0", "a1", "a2", "a3", "ret"],
		["call SYM0", "b1", "ret"],
		refs=[(normalize.Ref(kind="function", name="puts"),
			normalize.Ref(kind="function", name="abort"))])
	check("all at once: categories", both.categories,
		{"opcode": 1, "operand": 0, "register": 0, "relocation": 1, "missing": 2, "extra": 0})
	identity("all at once", both)

	# what the report prints has to be the same count as the categories
	printed = "\n".join(diff.report_lines(both, "orig", "cand"))
	check("the report's differing-instruction count matches the categories",
		"differing instructions (%d" % sum(both.categories.values()) in printed, True)
	return 0


# --------------------------------------------------------------------------------------
# 3. every function of the benchmark set


def variants_through_try(cfg_path: str, variants: list[str], limit: int) -> int:
	"""Score each unit through `decomp try`'s own path and require the identity of each verdict."""
	cfg = config.load(cfg_path)
	store = cache.Cache(config.cache_dir(cfg))
	scored, differing, resized = 0, 0, 0
	problems: list[str] = []
	for variant in variants:
		answer_path = TESTS / "build" / variant / "answer_key.json"
		stripped = TESTS / "build" / variant / "da_tests.stripped"
		if not answer_path.is_file() or not stripped.is_file():
			note(variant, "not built (Tests/eval.py build --variant %s)" % variant)
			continue
		status = store.status(cache.target_key(stripped)["key"])
		if not status.get("complete"):
			note(variant, "not analysed (decomp analyze %s --variant %s)" % (stripped, variant))
			continue
		conn = cache.open_readonly(Path(status["db"]))
		meta = cache.meta(conn)
		offset = int(meta.get("address_offset") or 0)
		units = json.loads(answer_path.read_text())["units"][:limit or None]
		bad = 0
		for unit in units:
			row = cache.resolve_function(conn, hex(unit["address"] + offset))
			if not row:
				problems.append("%s %s: no cached function at %s" % (variant, unit["id"],
					hex(unit["address"] + offset)))
				continue
			source = TESTS / "TestBinary" / unit["file"]
			# the untouched source (mostly a self-match, which must still add up), then the
			# deliberately wrong candidate for the three units that have one: the wrong ones
			# are what exercise unbalanced alignment on a real function
			candidates = [(source, unit["mangled"], 0)]
			if unit["id"] in ("MATH-02", "MATH-38", "STR-01"):
				candidates.append((TESTS / "examples" / "candidate_math_bad.cpp",
					{"MATH-02": "ClampRangeProbe", "MATH-38": "ParityOfProbe",
						"STR-01": "LengthOfProbe"}[unit["id"]], 0))
			if unit["id"] in ("MATH-13", "STR-18", "STRUCT-24"):
				# a truncated extent: the candidate is then longer than the unit being
				# compared, so the leftover is a whole tail of instructions
				candidates.append((source, unit["mangled"], max(8, unit["size"] - 12)))
			for src, symbol, size in candidates:
				outcome = cli.score_candidate(cfg, conn, meta, row[0], [src], fn=symbol,
					size=size or None, object_dir=store.root / "candidates-accounting")
				outcome["object"].unlink(missing_ok=True)
				verdict = outcome["verdict"]
				if verdict is None:
					# a unit the tool cannot score at all is check_phase2_try's problem, not
					# a count that is wrong here
					continue
				scored += 1
				if sum(verdict.categories.values()):
					differing += 1
				if verdict.size_delta_instructions:
					resized += 1
				for problem in diff.accounting_problems(verdict):
					problems.append("%s %s %s: %s" % (variant, unit["id"], symbol, problem))
				if verdict.warnings and "internal error" in " ".join(verdict.warnings):
					problems.append("%s %s %s: %s" % (variant, unit["id"], symbol,
						verdict.warnings))
		conn.close()
		print("  ok   %s: %d units, %d verdicts checked" % (variant, len(units), scored))
	if not scored:
		return 2
	check("benchmark: every verdict accounts for its lines", problems[:6], [])
	check("benchmark: verdicts checked", scored > 0, True)
	note("benchmark", "%d verdicts, %d with a difference, %d whose length differs" % (
		scored, differing, resized))
	if differing == 0:
		failures.append("benchmark: nothing differed, so this group proved nothing")
	return 0


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_diff_accounting.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
	parser.add_argument("--limit", type=int, default=0, help="only the first N units of a variant")
	parser.add_argument("--no-benchmark", action="store_true", help="synthetic groups only")
	args = parser.parse_args(argv)

	rc = leftover_lines()
	rc += shapes()
	if not args.no_benchmark:
		result = variants_through_try(str(TESTS / "project.toml"),
			[item.strip() for item in args.variants.split(",") if item.strip()], args.limit)
		if result == 2:
			print("\nno benchmark build was scored - the synthetic groups passed, but the "
				"invariant was not checked on real functions")
			return 2
		rc += result
	print()
	for line in notes:
		print("  %s" % line)
	if failures:
		print("\n%d FAILED:" % len(failures))
		for line in failures:
			print("  %s" % line)
		return 1
	print("all groups passed")
	return 0


if __name__ == "__main__":
	sys.exit(main())
