"""Phase 5 acceptance: `-O2` units, their real extents, and a register-abstracted diff.

	run: .venv/bin/python Tests/tools/check_phase5_o2.py [--variants ...] [--limit N]

Three things are judged here, none of them against this tool's own opinion:

1. **The extent.** At `-O2` a function's body is not what a disassembler draws: the compiler
   splits it at alignment padding, splits the cold blocks off into `.text.unlikely`, and orders
   the result by hotness. The file still says where every unit begins and ends - `.eh_frame`'s
   FDEs, and `st_size` where symbols survive - so `extract` reads that table and `try` scores the
   unit it names. The answer key's `(address, size)` comes from the *unstripped* build's symbol
   table, which is the answer; the tool is only allowed the stripped file.

2. **The loop.** The untouched original source is fed through `decomp try`'s own path for every
   unit of the `-O2` build, as in Phase 2, and has to pass the gate. `Tests/eval.py self` (the
   binutils-only ceiling for the same source) is printed next to it.

3. **Register abstraction.** Each side's register names are replaced by the order they first
   appear in, so the same choice in different registers compares equal. Since Phase 2 this runs on
   every comparison, not only under `--register-abstract` (which is accepted and ignored): a pair
   of streams that differ only in register choice compares equal and is reported as "allocation
   only", a *different* choice still does not match, and the untouched source has no register
   differences to hide (so the gate is unaffected).

The `-O0` and `-m32` rows are not re-gated here - `check_phase2_try.py` gates those.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, extract, normalize  # noqa: E402

DEFAULT_VARIANTS = ["gcc-o2", "gcc-o0", "gcc-o0-x86"]

# What the untouched source has to reach at -O2 through this tool's own path. Measured here:
# 99.91% mean, 84 of 89 past the tier gate as of Phase 4 (86 under Phase 3's rules, 88 under the
# percentage rule that existed before Phase 2) - above the independent harness's own 98.27% / 72,
# which is the ceiling for any candidate. The units below it are named in KNOWN_GAPS.
MIN_MEAN = 99.0
# Phase 5 costs six more, all of them the same thing: these units call helpers of their own
# translation unit, and in a stripped binary nothing names those helpers. A same-size match is no
# longer evidence, so they are counted unverified and stop at `structural` until the helper has a
# name in the match ledger - which is what `decomp ledger` exists to find, and what
# Tests/tools/check_phase5_ledger.py shows unblocking them. Nothing about their instructions, bytes
# or operands changed: 78/89, mean unchanged at 99.91%.
MIN_PAST_GATE = 78

KNOWN_GAPS = {
	"gcc-o2": {
		# `leaq` of two tiny unnamed functions (0x109ee0, 0x109f10) that belong to another unit of
		# the binary. The original side can only name them by the address Ghidra drew them at
		# (`FUN_00109ee0`); the candidate, whose layout differs, resolves both to the object that
		# happens to cover those offsets in its own section. No name pairs them, and pretending one
		# matches the other would be the invention the diff exists to catch.
		# These three are the same reference. STRUCT-22 and STRUCT-23 used to pass, because the
		# gate was a percentage (97.26 % / 98.28 % with `leaq SYM1(%rip)` vs `leaq SYM0(%rip)`
		# counted as enough matching lines); the tier gate reads that as an operand difference and
		# stops at `structural`. Pairing a callee by what it is rather than by the order the two
		# sides first reached it is Docs/byte-cleanup-plan.md Phase 5.
		"STRUCT-24": "a reference to an unnamed unit elsewhere in the binary - nothing to pair on",
		"STRUCT-22": "same reference as STRUCT-24: the positional token pairs a different object",
		"STRUCT-23": "same reference as STRUCT-24: the positional token pairs a different object",
		# Phase 4 (Docs/byte-cleanup-plan.md) asks what a reference *is*, and counts the ones
		# neither side can name, bound or read. These two reach nothing but such objects: MATH-13
		# a `.bss` CRC table and its ready-flag, STRUCT-21 the state machine's counters. Both sides
		# reach them, both are anonymous in the stripped binary, and no source can change that -
		# which is what `[gate] waive = "unverified"` is for, and what reproducing the object
		# (Docs/structures-plan.md) would fix properly. They used to pass because a reference
		# nothing could describe was accepted silently.
		"MATH-13": "two anonymous `.bss` objects - counted unverified, so `semantic` is not claimed",
		"STRUCT-21": "anonymous state-machine data - counted unverified, as above",
		# Phase 5 (Docs/byte-cleanup-plan.md) finished what Phase 4 started: two function bodies of
		# the same measured size stopped being evidence for *which* helper is called. These six call
		# a helper of their own translation unit - anonymous in the stripped binary, byte-identical
		# in the candidate - and now stop at `structural` on that reference alone. The fix is not in
		# the candidate: reproduce the helper first, and the ledger carries its name into every unit
		# that calls it (`decomp ledger` lists those helpers by how many functions call them).
		"MATH-24": "calls SquareRootNewton (0x103c30), same size, unnamed there - decompile it first",
		"MATH-27": "as above: Vec3LengthSq (0x104070) and SquareRootNewton",
		"MATH-29": "as above: Vec3Cross (0x1040a0), Vec3LengthSq, SquareRootNewton",
		"STR-07": "as above: LengthOf (0x105c40)",
		"STR-08": "as above: FindSubstring (0x105de0)",
		"STRUCT-25": "as above: CompareDescriptorCost (0x107920), the static qsort comparator",
	},
}


def check_extents(variant: str, conn, meta: dict, units: list[dict]) -> tuple[list[str], dict]:
	"""Does the tool get the compiler's extent for every unit, from the stripped file alone?"""
	bad: list[str] = []
	offset = int(meta.get("address_offset") or 0)
	exact = 0
	multi = 0
	sources: dict[str, int] = {}
	for unit in units:
		row = cache.resolve_function(conn, hex(unit["address"] + offset))
		if not row:
			bad.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"] + offset)))
			continue
		function = extract.original_function(conn, meta, row[0])
		ranges = json.loads(row[0]["ranges"] or "[]")
		if len(ranges) > 1:
			multi += 1
			if len(function.extents) != 1 or function.extents[0][1] != function.size:
				bad.append("%s: %d ranges were not read as one block (%r)"
					% (unit["id"], len(ranges), function.extents))
		if function.address != unit["address"] + offset or function.size != unit["size"]:
			bad.append("%s: extent %s+%d, the compiler says %s+%d (the analysis' body is %d)"
				% (unit["id"], hex(function.address), function.size,
					hex(unit["address"] + offset), unit["size"], row[0]["size"]))
			continue
		exact += 1
		named = next((claim for claim in function.warnings if "compiler's own boundary" in claim), "")
		for source in (".eh_frame", ".pdata", "symtab"):
			if source in named:
				sources[source] = sources.get(source, 0) + 1
	print("   extent: %d/%d units match the compiler's (address, size); %d of them had a body the"
		" analysis split into ranges, read as one block" % (exact, len(units), multi))
	if sources:
		print("   the extent came from the file's own table where the analysis' body differed: %s"
			% ", ".join("%s %d" % item for item in sorted(sources.items())))
	for item in bad[:6]:
		print("   WRONG %s" % item)
	if len(bad) > 6:
		print("   ... %d more" % (len(bad) - 6))
	return bad, {"exact": exact, "multi": multi, "sources": sources}


def check_loop(variant: str, cfg: dict, conn, meta: dict, store: cache.Cache,
	units: list[dict]) -> tuple[list[str], list]:
	"""The untouched source, scored by this tool's own path, at the target's own -O."""
	bad: list[str] = []
	scores: list = []
	for unit in units:
		row = cache.resolve_function(conn, hex(unit["address"]
			+ int(meta.get("address_offset") or 0)))
		if not row:
			continue
		source = TESTS / "TestBinary" / unit["file"]
		outcome = cli.score_candidate(cfg, conn, meta, row[0], [source], fn=unit["mangled"],
			object_dir=store.root / "candidates-phase5")
		outcome["object"].unlink(missing_ok=True)
		if outcome["verdict"] is None:
			bad.append("%s: %s" % (unit["id"], outcome["error"]))
			continue
		scores.append((unit, outcome["verdict"]))
	if not scores:
		return ["nothing scored"], []
	percent = [verdict.match_percent for _unit, verdict in scores]
	past = sum(1 for _unit, verdict in scores if verdict.passed)
	identical = sum(1 for _unit, verdict in scores if verdict.bytes_equal)
	registers = sum(verdict.categories["register"] for _unit, verdict in scores)
	print("   loop: %d/%d past the gate, mean %.2f%%, byte-identical %d, register differences %d"
		% (past, len(scores), sum(percent) / len(percent), identical, registers))
	if sum(percent) / len(percent) < MIN_MEAN:
		bad.append("mean %.2f%% is below the %.2f%% this machine measures" % (
			sum(percent) / len(percent), MIN_MEAN))
	if past < MIN_PAST_GATE:
		bad.append("%d units past the gate, want %d" % (past, MIN_PAST_GATE))
	if registers:
		bad.append("%d register differences between the untouched source and itself" % registers)
	gaps = KNOWN_GAPS.get(variant, {})
	for unit, verdict in scores:
		if verdict.passed:
			continue
		categories = {key: value for key, value in verdict.categories.items() if value}
		if unit["id"] in gaps:
			print("   KNOWN GAP %s %-40s %6.2f%% %s - %s" % (unit["id"], unit["name"],
				verdict.match_percent, categories, gaps[unit["id"]]))
			continue
		bad.append("%s %s %.2f%% %s" % (unit["id"], unit["name"], verdict.match_percent,
			categories))
	reference = TESTS / "build" / variant / "self_scores.json"
	if reference.is_file():
		old = json.loads(reference.read_text())
		old_mean = sum(item["match_percent"] for item in old) / max(1, len(old))
		old_pass = sum(1 for item in old if item["match_percent"] >= config.threshold(cfg)
			and item["categories"]["opcode"] == 0)
		print("   eval.py self (the ceiling): mean %.2f%%, above threshold %d/%d"
			% (old_mean, old_pass, len(old)))
	return bad, [verdict for _unit, verdict in scores]


def check_two_blocks() -> list[str]:
	"""A unit in two blocks: the entry block and a cold block elsewhere, one label space."""
	handle = normalize.capstone_for("x86:LE:64:default", detail=True)
	if handle is None:
		return ["no x86 decoder to build a two-block body with"]
	bad: list[str] = []
	# One body, two blocks: the entry block at 0x1000 and a cold block at 0x9000 - where a -O2
	# cold partition actually sits after a link - with an edge from one to the other and back.
	entry, cold = 0x1000, 0x9000
	def jump_to(source: int, target: int) -> bytes:
		return b"\xe9" + (target - source - 5).to_bytes(4, "little", signed=True)
	body = jump_to(entry, cold) + b"\x90" + jump_to(cold, entry) + b"\x90"
	extents = [(entry, 6), (cold, 6)]
	words = normalize.decode_function(handle, entry, body, extents=extents)
	vocabulary = normalize.Vocabulary()
	text = [token.text for token in normalize.normalize_function(vocabulary, "candidate", words,
		lambda _i: {}, entry, len(body), extents=extents)]
	if text != ["jmp L6", "nop", "jmp L0", "nop"]:
		bad.append("a two-block body did not tokenise with unit-relative labels: %r" % text)
	else:
		print("   two blocks: a body at 0x1000 and 0x9000 tokenises as %s - the edge between the"
			" blocks is one label on both sides, whatever the link put between them" % " ".join(text))

	# A register-only difference is the same stream once abstracted; a different choice is not.
	def body_of(*lines_text):
		return [normalize.Instruction(0, 1, mnemonic, operands)
			for mnemonic, operands in lines_text]

	left = body_of(("movl", "%eax, %ecx"), ("addl", "%ecx, %eax"))
	right = body_of(("movl", "%r9d, %r8d"), ("addl", "%r8d, %r9d"))
	other = body_of(("movl", "%eax, %edx"), ("addl", "%edx, %ecx"))

	def stream(instructions, side: str, vocabulary, **kwargs):
		return [token.text for token in normalize.normalize_function(vocabulary, side,
			instructions, lambda _i: {}, 0, 8, **kwargs)]

	strict = normalize.Vocabulary()
	if stream(left, "original", strict) == stream(right, "candidate", strict):
		bad.append("a register-only difference matched without --register-abstract")
	abstracted = normalize.Vocabulary()
	same = stream(left, "original", abstracted, register_abstract=True)
	same_right = stream(right, "candidate", abstracted, register_abstract=True)
	if same != same_right or "{r0}" not in same[0]:
		bad.append("--register-abstract did not make the same choice in different registers match:"
			" %r vs %r" % (same, same_right))
	else:
		print("   registers: %r vs %r -> %s with --register-abstract"
			% (stream(left, "original", strict)[0], stream(right, "candidate", strict)[0], same[0]))
	another = normalize.Vocabulary()
	different = stream(other, "candidate", another, register_abstract=True)
	if same == different:
		bad.append("--register-abstract hid a different choice: %r" % different)
	else:
		print("   registers: a different choice stays different (%s vs %s)" % (same[1], different[1]))
	return bad



def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_phase5_o2.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
	parser.add_argument("--limit", type=int, default=0, help="score only the first N units")
	parser.add_argument("--no-loop", action="store_true", help="check extents only (fast)")
	args = parser.parse_args(argv)

	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	failures = 0
	for variant in [item.strip() for item in args.variants.split(",") if item.strip()]:
		stripped = TESTS / "build" / variant / "da_tests.stripped"
		answer_path = TESTS / "build" / variant / "answer_key.json"
		if not answer_path.is_file() or not stripped.is_file():
			print("%s: build it first (Tests/eval.py build --variant %s)" % (variant, variant))
			continue
		status = store.status(cache.target_key(stripped)["key"])
		if not status.get("complete"):
			print("%s: not analysed (decomp analyze %s --variant %s)" % (variant, stripped, variant))
			continue
		print(variant)
		units = json.loads(answer_path.read_text())["units"]
		units = units[: args.limit] if args.limit else units
		conn = cache.open_readonly(Path(status["db"]))
		meta = cache.meta(conn)
		try:
			bad, _counts = check_extents(variant, conn, meta, units)
			if variant == "gcc-o2" and not args.no_loop:
				loop_bad, _scores = check_loop(variant, cfg, conn, meta, store, units)
				bad += loop_bad
		finally:
			conn.close()
		report(variant, bad)
		failures += 1 if bad else 0

	bad = check_two_blocks()
	report("a body in two blocks and register abstraction", bad)
	failures += 1 if bad else 0
	print("check_phase5_o2: %s" % ("OK" if not failures else "%d group(s) failed" % failures))
	return 0 if not failures else 1


def report(name: str, bad: list[str]) -> None:
	print("%s: %s" % (name, "ok" if not bad else "%d wrong" % len(bad)))
	for item in bad:
		print("   WRONG %s" % item)


if __name__ == "__main__":
	sys.exit(main())
