"""Phase 2 acceptance: the gate is a tier, not a percentage.

	run: .venv/bin/python Tests/tools/check_gate_tiers.py [--variants ...] [--limit N] [--no-target]

`Docs/byte-cleanup-plan.md` Phase 2. A unit used to be "done" at `match >= 97 %` with no
`opcode` and no `relocation` difference, which let a wrong immediate, a dropped instruction and
a swapped subtraction through as long as enough lines matched. What is checked instead:

1. **the negative controls do not reach `semantic`.** A candidate with a swapped subtraction
   (`subss %xmm1,%xmm0` vs `subss %xmm0,%xmm1`), a dropped `mulss`, a wrong immediate, or a
   line that reaches a different object.
2. **a pure register-allocation difference does reach it.** `movl %eax,%ecx` / `addl %ecx,%eax`
   vs `movl %r9d,%r8d` / `addl %r8d,%r9d` is the same computation in other registers: it is
   counted `register`, reported as "allocation only", and the register-folded comparison comes
   out identical. A different register *choice* (a third register, a different pair) does not.
3. **`exact` needs the bytes.** Same instructions with equal bytes is `exact`; the same
   instructions with the bytes unproven stop at `semantic`.
4. **the gate is configuration.** `[gate] require` in the target config, and `--gate`, select
   what a unit has to reach; `percent` reproduces the old rule, an unknown name is a config
   error, and the tier - not the percent - is what the exit code follows.
5. **what falls out on real functions.** Every unit of each built ELF variant, scored with the
   untouched source through `decomp try`'s own path: the tier histogram, and the difference
   between the tier gate and the old percentage rule.

Exit: 0 all passed, 1 something came out wrong, 2 no target was scored.
"""

from __future__ import annotations

import argparse
import collections
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
	return [normalize.Token(text=text, mnemonic=text.split()[0], address=0x1000 + 4 * index)
		for index, text in enumerate(lines)]


# What the tool has to say when `exact` is asked for and the bytes do not speak for it. With no
# bytes at all the test could not run; with bytes and no field lists it ran on every byte, which
# is the pre-Phase-3 rule and only honest for a body that references nothing.
NO_BYTES = "the bytes cannot be compared (one of the two bodies is missing)"
UNMASKED = ("the bytes are not equal, and no relocation fields were given, so this byte test is "
	"unmasked")


def score(original_lines: list[str], candidate_lines: list[str], *,
		refs: list[tuple[normalize.Ref, normalize.Ref]] | None = None,
		original_bytes: bytes = b"", candidate_bytes: bytes = b"",
		original_fields=None, candidate_fields=None, require: str = diff.GATE_DEFAULT):
	left, right = stream(original_lines), stream(candidate_lines)
	for index, (a, b) in enumerate(refs or []):
		left[index].refs.append(a)
		right[index].refs.append(b)
	return diff.compare(left, right, normalize.Vocabulary(), threshold=97.0,
		original_bytes=original_bytes, candidate_bytes=candidate_bytes,
		original_fields=original_fields, candidate_fields=candidate_fields, require=require)


def expect(label: str, verdict, tier: str, categories: dict) -> None:
	"""The tier, and the categories behind it."""
	check("%s: tier" % label, verdict.tier, tier)
	check("%s: categories" % label,
		{key: value for key, value in verdict.categories.items() if value}, categories)


# --------------------------------------------------------------------------------------
# 1. what does not reach semantic


def negative_controls() -> int:
	# a swapped subtraction, in a stream that is otherwise identical: 40 of 41 lines match, so
	# the percentage is above the old threshold and the old rule passed it. It is not a rename:
	# the same registers appear the other way round and a different one is left written.
	filler = ["nop"] * 40
	swapped = score(filler + ["subss %xmm1, %xmm0"], filler + ["subss %xmm0, %xmm1"])
	expect("swapped subtraction", swapped, "structural", {"operand": 1})
	check("swapped subtraction: above the old threshold, which is the point", swapped.match_percent
		>= swapped.threshold, True)
	check("swapped subtraction: the folded streams are identical, so the fold alone would miss it",
		swapped.abstract_clean, True)
	check("swapped subtraction: named as a pairing, not a rename", swapped.gaps("semantic"),
		["1 operand differences"])

	# ... and once earlier instructions pin which register holds what, the register-folded
	# comparison sees the same swap: a rename is consistent over the whole unit
	anchored = score(["movss DAT0(%rip), %xmm0", "addss %xmm1, %xmm0", "subss %xmm1, %xmm0"],
		["movss DAT0(%rip), %xmm0", "addss %xmm1, %xmm0", "subss %xmm0, %xmm1"])
	expect("swapped subtraction, with context", anchored, "structural", {"operand": 1})
	check("swapped subtraction, with context: the folded streams differ too",
		anchored.abstract_clean, False)

	# a dropped mulss: one line of the original is not in the candidate
	dropped = score(
		["movss DAT0(%rip), %xmm0", "mulss %xmm2, %xmm0", "movss %xmm0, DAT1(%rip)"],
		["movss DAT0(%rip), %xmm0", "movss %xmm0, DAT1(%rip)"])
	expect("dropped mulss", dropped, "none", {"missing": 1})

	# a wrong immediate
	immediate = score(["movl $7, (%rax)"], ["movl $8, (%rax)"])
	expect("wrong immediate", immediate, "structural", {"operand": 1})

	# a different callee, with the lines identical: the hidden relocation path
	reached = score(["call SYM0"], ["call SYM0"], refs=[(
		normalize.Ref(kind="function", name="puts"),
		normalize.Ref(kind="function", name="abort"))])
	expect("different callee", reached, "none", {"relocation": 1})

	# a different register choice, not a rename: a third register enters the stream
	choice = score(["movl %eax, %ecx", "addl %ecx, %eax"], ["movl %eax, %edx",
		"addl %edx, %ecx"])
	expect("different register choice", choice, "structural", {"register": 2})
	check("different register choice: the folded streams are not identical",
		choice.abstract_clean, False)
	return 0


# --------------------------------------------------------------------------------------
# 2. what does reach it


def allocations() -> int:
	renamed = score(["movl %eax, %ecx", "addl %ecx, %eax"],
		["movl %r9d, %r8d", "addl %r8d, %r9d"],
		original_bytes=b"\x89\xc1\x01\xc8", candidate_bytes=b"\x41\x89\xc8\x41\x01\xc1")
	expect("register allocation", renamed, "semantic", {"register": 2})
	check("register allocation: reported as allocation only", renamed.register_only, 2)
	check("register allocation: the folded streams are identical", renamed.abstract_clean, True)
	check("register allocation: nothing stands between it and the gate",
		renamed.gaps("semantic"), [])
	check("register allocation: it still says what is missing for exact",
		renamed.gaps("exact"), [UNMASKED])

	# the same width-changing pattern must not hide behind the aliases: %eax and %rax are one
	# register, so `movl` vs `movq` is an opcode difference, not a rename
	width = score(["movl %eax, %ecx"], ["movq %rax, %rcx"])
	check("width change is not a rename", width.categories["opcode"], 1)
	check("width change: tier", width.tier, "none")

	# two of the original's values share one register in the candidate: that is not a renaming,
	# and folding the names shows it - the two lines stop agreeing
	shared = score(["movl %eax, %ecx", "addl %ecx, %edx"], ["movl %r9d, %ecx",
		"addl %ecx, %r9d"])
	check("two values share a register: tier", shared.tier, "structural")
	check("two values share a register: the folded streams differ", shared.abstract_clean, False)

	# same instructions, equal bytes: exact. Same instructions, bytes unproven: semantic.
	same = score(["ret"], ["ret"], original_bytes=b"\xc3", candidate_bytes=b"\xc3")
	expect("equal bytes", same, "exact", {})
	unproven = score(["ret"], ["ret"])
	expect("bytes unproven", unproven, "semantic", {})
	check("exact is the top tier, so nothing is asked for", unproven.gaps("exact"), [NO_BYTES])
	return 0


# --------------------------------------------------------------------------------------
# 3. the gate is configuration, and the exit code follows the tier


def gates() -> int:
	filler = ["nop"] * 40
	swapped = score(filler + ["subss %xmm1, %xmm0"], filler + ["subss %xmm0, %xmm1"],
		require="structural")
	check("gate structural: a swapped subtraction passes", swapped.passed, True)
	check("gate structural: the tier is still named", swapped.tier, "structural")
	check("gate semantic: the same verdict fails", score(
		filler + ["subss %xmm1, %xmm0"], filler + ["subss %xmm0, %xmm1"]).passed, False)
	none = score(["movl %eax, %ecx"], ["addl %ecx, %eax"], require="none")
	check("gate none: nothing is asked", none.passed, True)
	# the pre-Phase-2 rule, for a target where no tier can honestly be claimed: the swapped
	# subtraction above passes it, which is exactly what Phase 2 was for
	old = score(["nop"] * 40 + ["subss %xmm1, %xmm0"], ["nop"] * 40 + ["subss %xmm0, %xmm1"],
		require="percent")
	check("gate percent: the old rule passes the swapped subtraction", (old.passed,
		old.tier), (True, "structural"))
	# an unknown name falls back to the default rather than silently gating on nothing
	fallback = score(["ret"], ["ret"], require="exact-ish")
	check("unknown gate name: falls back to the default", (fallback.require, fallback.passed),
		(diff.GATE_DEFAULT, True))

	# what a target config says, and what `--gate` does to it
	cfg = config.load(str(TESTS / "project.toml"))
	for variant in ("gcc-o0", "gcc-o2", "gcc-o0-x86"):
		_name, body = config.variant(cfg, variant)
		check("config: [gate] require for %s" % variant, config.gate(cfg, body)[0], "semantic")
	note("config: where it came from", config.gate(cfg)[1])
	packed = config.load(str(REPO / "decomp" / "project.toml"))
	check("config: the packaged default also asks for semantic", config.gate(packed)[0],
		"semantic")
	# a variant that relaxes it (the shape Docs/byte-cleanup-plan.md asks for, e.g. MSVC LTCG)
	relaxed = {"gate": "structural"}
	check("config: a variant gate key wins", config.gate(cfg, relaxed)[0], "structural")
	bad = config.load(str(TESTS / "project.toml"))
	bad["raw"]["gate"] = {"require": "mostly"}
	try:
		config.gate(bad)
		failures.append("config: an unknown gate name was accepted")
	except config.ConfigError as exc:
		check("config: an unknown gate name is a config error", "not a gate" in str(exc), True)

	# the report leads with the tier and says what is missing from the gate
	report = "\n".join(diff.report_lines(swapped, "orig", "cand"))
	check("report: names the tier and the gate", ("tier structural" in report,
		"(gate: structural)" in report), (True, True))
	check("report: the percent is labelled progress", "progress only" in report, True)
	strict = score(filler + ["subss %xmm1, %xmm0"], filler + ["subss %xmm0, %xmm1"])
	report = "\n".join(diff.report_lines(strict, "orig", "cand"))
	check("report: a failing unit is told which tier it reached and which is asked for",
		("this unit reaches structural and the gate asks for semantic" in report,
			"1 operand differences" in report), (True, True))
	check("report: the allocation-only case says so",
		"allocation only" in "\n".join(diff.report_lines(score(
			["movl %eax, %ecx"], ["movl %r9d, %r8d"]), "a", "b")), True)
	return 0


# --------------------------------------------------------------------------------------
# 4. the real targets: what the tier gate keeps, and what it drops


def targets(cfg_path: str, variants: list[str], limit: int) -> int:
	"""Score every unit with its untouched source, and count tiers next to the old rule."""
	cfg = config.load(cfg_path)
	store = cache.Cache(config.cache_dir(cfg))
	scored = 0
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
		require, _where = config.gate(cfg, config.variant(cfg, variant)[1])
		units = json.loads(answer_path.read_text())["units"][:limit or None]
		histogram: collections.Counter[str] = collections.Counter()
		old_rule = 0
		low: list[str] = []
		for unit in units:
			row = cache.resolve_function(conn, hex(unit["address"] + offset))
			if not row:
				problems.append("%s %s: no cached function at %s" % (variant, unit["id"],
					hex(unit["address"] + offset)))
				continue
			outcome = cli.score_candidate(cfg, conn, meta, row[0],
				[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"],
				object_dir=store.root / "candidates-tiers")
			outcome["object"].unlink(missing_ok=True)
			verdict = outcome["verdict"]
			if verdict is None:
				problems.append("%s %s: %s" % (variant, unit["id"], outcome["error"]))
				continue
			scored += 1
			histogram[verdict.tier] += 1
			# the same verdict under the rule this project used before Phase 2
			if (verdict.match_percent >= verdict.threshold and not verdict.categories["opcode"]
					and not verdict.categories["relocation"]):
				old_rule += 1
			if verdict.tier != "exact":
				low.append("%s %-40s %6.2f%% %-10s %s" % (unit["id"], unit["name"],
					verdict.match_percent, verdict.tier,
					{key: value for key, value in verdict.categories.items() if value}))
		conn.close()
		tiers = ", ".join("%s %d" % (name, histogram.get(name, 0))
			for name in reversed(diff.TIERS))
		print("  ok   %s: %d units, gate %s -> %s; the old percentage rule would have passed %d"
			% (variant, len(units), require, tiers, old_rule))
		for line in sorted(low)[:12]:
			print("       below exact: %s" % line)
		note("%s tiers" % variant, dict(histogram))
	if not scored:
		return 2
	check("targets: no scored unit is missing a tier", problems[:6], [])
	check("targets: units scored", scored > 0, True)
	return 0


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_gate_tiers.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
	parser.add_argument("--limit", type=int, default=0, help="only the first N units of a variant")
	parser.add_argument("--no-target", action="store_true", help="synthetic groups only")
	args = parser.parse_args(argv)

	negative_controls()
	allocations()
	gates()
	rc = 0
	if not args.no_target:
		result = targets(str(TESTS / "project.toml"),
			[item.strip() for item in args.variants.split(",") if item.strip()], args.limit)
		if result == 2:
			print("\nno target was scored - the synthetic groups passed, but the tier gate was "
				"never run against a real function")
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
