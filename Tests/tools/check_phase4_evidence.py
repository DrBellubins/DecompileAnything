#!/usr/bin/env python3
"""Phase 4 (Docs/byte-cleanup-plan.md): a data reference is compared at the width it is read.

Three things are claimed here.

**At the width the instruction reads.** `decomp normalize` records how wide an access is from its
mnemonic and register, both sides' references carry it, and two references to the same object are
the same object only if the bytes *actually read* match. So a float constant changed by one unit in
the last place, or a string literal changed by one character, is a reference difference - not
something a merged `.rodata.cst*` pool can hide behind an extent the linker arranged.

**Only where there is evidence.** Bytes count at the width when both sides have it; a string counts
at its length plus the terminator, which the original caches and the candidate reads to its NUL; a
known object counts at its size. A reference both sides reach but *neither* can name, bound or read
is counted in `unverified`, and `semantic` needs that to be zero - or a waiver in the target config,
because a stripped binary's anonymous `.bss` global is not something a candidate can fix.

**That a candidate `.o` can be read at all.** A PC-relative relocation points at `addend + width`,
not at `addend`; and one relocated word in a constant pool used to make the whole section
unreadable. Both were invisible while nothing compared data bytes.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TESTS.parent))
sys.path.insert(0, str(TESTS / "tools"))

from decomp import cache, cli, config, diff, extract, normalize  # noqa: E402

X86_64 = "x86:LE:64:default"
FAILURES: list[str] = []
OK = 0


def ok(what: str, got, want) -> bool:
	global OK
	good = got == want
	print("%s %-58s %r" % ("  ok  " if good else " FAIL ", what, got))
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


def score(left: normalize.Ref, right: normalize.Ref, *, text: str = "movl DAT0, %eax",
	token: str = "DAT0", **kw) -> diff.Verdict:
	"""One instruction, reaching `left` on the original and `right` in the candidate."""
	a, b = stream([text]), stream([text])
	a[0].refs.append(left)
	b[0].refs.append(right)
	vocabulary = normalize.Vocabulary()
	# what the pipeline's symbol table holds: one entry per token, per side
	vocabulary.entries["original"].append((token, left))
	vocabulary.entries["candidate"].append((token, right))
	return diff.compare(a, b, vocabulary, threshold=0.0, **kw)


# ---------------------------------------------------------------- the width comes from the code

def widths() -> None:
	handle = normalize.capstone_for(X86_64, detail=True)
	# movss 0x1100(%rip),%xmm1 ; movzbl 0x20(%rbx),%eax ; movq $0,%rax ; leaq 0x8(%rip),%rcx
	body = (b"\xf3\x0f\x10\x0d\x00\x11\x00\x00" + b"\x0f\xb6\x43\x20" + b"\x48\xc7\xc0\x00\x00"
		b"\x00\x00" + b"\x48\x8d\x0d\x08\x00\x00\x00")
	instructions = normalize.decode_function(handle, 0x1000, body)
	got = [normalize.access_width(item.mnemonic, item.operands, handle) for item in instructions]
		# A `lea` reads no memory: its width is that of the register it writes.
	ok("width of each access, from the mnemonic and the register", got, [4, 1, 8, 8])
	ok("and it lands on the operand that carries it",
		[(slot.operand, slot.width) for slot in instructions[0].slots], [(0, 4)])
	ok("an immediate operand carries no width of its own",
		[(slot.operand, slot.width) for slot in instructions[2].slots], [(0, 0)])

	# 0.7071f -> 0.7072f: not one instruction moves, and the bytes at the four the instruction
	# reads are different.
	verdict = score(normalize.Ref(kind="data", raw="DAT0",
			content=struct.pack("<f", 0.7071), width=4),
		normalize.Ref(kind="data", raw="DAT0",
			content=struct.pack("<f", 0.7072), width=4))
	ok("a changed float constant is a reference difference", verdict.symbols[0]["ok"], False)
	truth("and the tool names the bytes it read",
		"the bytes there differ" in verdict.symbols[0]["why"]
		and "4 bytes this instruction reads" in verdict.symbols[0]["why"])
	ok("a changed constant caps the tier - a reference is part of the shape",
		(verdict.tier, verdict.passed), ("none", False))
	ok("it is a reference, not an instruction",
		(verdict.categories["relocation"], verdict.categories["opcode"]), (1, 0))
	ok("one byte different in a four-byte read is enough", diff.refs_compatible(
		normalize.Ref(content=b"\x00" * 4, width=4),
		normalize.Ref(content=b"\x01\x00\x00\x00", width=4))[0], False)
	ok("with no width, no size and no name, a difference far into a pool is not claimed",
		diff.refs_compatible(normalize.Ref(content=b"\x00" * 16),
			normalize.Ref(content=b"\x00" * 15 + b"\x01"))[0], True)
	ok("but the width of one side alone does not make an unreadable object comparable",
		diff.refs_compatible(normalize.Ref(content=b"\x00" * 4, width=4),
			normalize.Ref(width=4))[0], True)


def strings() -> None:
	"""A literal compared at its length plus the NUL - where one character shows up."""
	original = normalize.Ref(kind="data", content=b"hello world\x00", string=11)
	for what, other, want in (
			("the same literal matches", normalize.Ref(kind="data", content=b"hello world\x00"),
			 True),
			("one character changed is a difference",
			 normalize.Ref(kind="data", content=b"hello worlD\x00"), False),
			("the literal grown by one character is a difference",
			 normalize.Ref(kind="data", content=b"hello worlds\x00"), False),
			("the terminator moved is a difference",
			 normalize.Ref(kind="data", content=b"hello world!x\x00"), False)):
		ok(what, diff.refs_compatible(original, other)[0], want)
	ok("the window is the string plus its terminator",
		diff.content_window(original, normalize.Ref(kind="data", content=b"hello world\x00")),
		(12, "the 11-byte string there"))


# ---------------------------------------------------------------- a candidate .o stays readable

def candidate_object() -> None:
	ok("a PC-relative relocation points past its addend",
		[extract.pc_bias(kind) for kind in
			("R_X86_64_PC32", "X86_64_PC32", "R_X86_64_REX_GOTPCRELX", "R_X86_64_32S",
			 "R_X86_64_PLT32", "IMAGE_REL_AMD64_REL32", "R_AARCH64_PREL32", "")],
		[4, 4, 4, 0, 4, 0, 4, 0])

	# A merged pool with one relocated pointer in it: the words away from that record are final at
	# assembly time, and reading them is what makes a float pool comparable at all.
	obj = extract.CandidateObject.__new__(extract.CandidateObject)
	obj._sections = {".rodata.cst8": b"\x00" * 8 + b"\xff" * 8}
	obj._writable, obj._no_bytes = set(), set()
	obj._relocs, obj._coff = {".rodata.cst8": [(0, "R_X86_64_64", "g", 0)]}, False
	ok("the word under a relocation is refused", obj._read(".rodata.cst8", 0, 8), None)
	ok("the word beside it is read", obj._read(".rodata.cst8", 8, 8), b"\xff" * 8)
	ok("a window that runs into a relocation is refused", obj._read(".rodata.cst8", 4, 8), None)
	# a string-like object is read to its NUL, not for a fixed probe
	obj._sections = {".rodata.str1.1": b"hello world\x00garbage garbage"}
	obj._relocs = {}
	ok("a literal in `.rodata.str1.1` is read to its terminator",
		obj._read_data(".rodata.str1.1", 0, 0, ".L5"), b"hello world\x00")
	ok("a decorated MSVC literal is recognised as one",
		extract._looks_like_string("??_C@_0BA@HELLO", ".rdata"), True)
	ok("a pool is not", extract._looks_like_string(".LC0", ".rodata.cst4"), False)
	obj._sections = {".rodata.cst4": b"\x00\x00\xb4\x43\x00\x00\x34\x43"}
	ok("a constant pool is read at the probe, not to a NUL",
		obj._read_data(".rodata.cst4", 0, 0, ".LC0"), b"\x00\x00\xb4\x43\x00\x00\x34\x43")


# ---------------------------------------------------------------- what the tool cannot check

def unverified() -> None:
	anonymous = (normalize.Ref(kind="data", name="DAT_001120c0", raw="DAT0"),
		normalize.Ref(kind="data", raw="DAT0"))
	verdict = score(*anonymous)
	ok("an object neither side can describe is counted", verdict.unverified, 1)
	ok("and named", verdict.unverified_refs[0]["token"], "DAT0")
	ok("it stops the unit claiming `semantic`", (verdict.tier, verdict.passed),
		("structural", False))
	ok("the report says so", any("assumed, not proven" in line for line in
		diff.report_lines(verdict, "o", "c", max_symbols=20)), True)
	waived = score(*anonymous, waive=("unverified",))
	ok("a waived reference still reaches the gate", (waived.tier, waived.passed),
		("semantic", True))
	ok("and stays visible in the report", any("waived" in line for line in
		diff.report_lines(waived, "o", "c", max_symbols=20)), True)
	ok("the gap text names the rule", any("neither side can name, bound or read" in line
		for line in verdict.gaps("semantic")), True)

	for what, left, right in (
			("a name both sides know is evidence",
			 normalize.Ref(kind="data", name="g_player_health", raw="DAT0"),
			 normalize.Ref(kind="data", name="g_player_health", raw="DAT0")),
			("bytes at the width are evidence",
			 normalize.Ref(content=b"\x01" * 4, width=4),
			 normalize.Ref(content=b"\x01" * 4, width=4)),
			("a string both sides can read is evidence",
			 normalize.Ref(content=b"abc\x00", string=3), normalize.Ref(content=b"abc\x00"))):
		ok(what, (score(left, right).unverified, score(left, right).tier), (0, "semantic"))
	# Two bodies of the same size used to be the weakest rung here. Since Phase 5 it is not a rung:
	# "equal size, different helper" is exactly the mistake this comparison exists to catch, and once
	# any unit has been shown that helper and passed, the match ledger says what it is called. That
	# rule and the ledger are checked in Tests/tools/check_phase5_ledger.py.
	same_size = score(normalize.Ref(kind="function", size=8, raw="FUN0"),
		normalize.Ref(kind="function", size=8, raw="FUN0"))
	ok("two function bodies of the same size no longer clear the counter",
		(same_size.unverified, same_size.tier, same_size.symbols[0]["evidence"]),
		(1, "structural", "size"))
	truth("and the report says what is missing there", any("same size" in line
		for line in diff.report_lines(same_size, "o", "c", max_symbols=20)))

	a, b = stream(["movl DAT0, %eax", "movl DAT1, %eax"]), stream(["movl DAT0, %eax"])
	a[0].refs.append(normalize.Ref(kind="data", name="g_a", raw="DAT0"))
	a[1].refs.append(normalize.Ref(kind="data", name="g_b", raw="DAT1"))
	b[0].refs.append(normalize.Ref(kind="data", name="g_a", raw="DAT0"))
	vocabulary = normalize.Vocabulary()
	vocabulary.entries["original"] = [("DAT0", a[0].refs[0]), ("DAT1", a[1].refs[0])]
	vocabulary.entries["candidate"] = [("DAT0", b[0].refs[0])]
	only_one = diff.compare(a, b, vocabulary, threshold=0.0)
	ok("a reference only one side reaches is a missing line, not an unverified count",
		(only_one.unverified, only_one.categories["missing"]), (0, 1))

	cfg = config.load(str(TESTS / "project.toml"))
	ok("a target config waves nothing aside by default", config.gate_waivers(cfg), ([], ""))
	cfg["raw"]["gate"] = {"require": "semantic", "waive": "unverified"}
	ok("and the waiver is read from it", config.gate_waivers(cfg)[0], ["unverified"])
	cfg["raw"]["gate"] = {"waive": ["not-a-thing"]}
	try:
		config.gate_waivers(cfg)
		ok("a waiver that is not waivable is a config error", "accepted", "error")
	except config.ConfigError:
		ok("a waiver that is not waivable is a config error", True, True)


# ---------------------------------------------------------------- the real target

def real(variant: str = "gcc-o0") -> None:
	"""Change one constant, or one character of a string, in real source: it must fail."""
	cfg = config.load(str(TESTS / "project.toml"))
	root = TESTS / "build" / variant
	stripped = root / "da_tests.stripped"
	if not stripped.exists():
		print("  skip %s: not built (Tests/eval.py build --variant %s)" % (variant, variant))
		return
	status = cache.Cache(config.cache_dir(cfg)).status(cache.target_key(stripped)["key"])
	if not status.get("complete"):
		print("  skip %s: not analysed" % variant)
		return
	conn = cache.open_readonly(Path(status["db"]))
	meta = cache.meta(conn)
	shift = int(meta.get("address_offset") or 0)
	units = {item["id"]: item for item in json.loads((root / "answer_key.json").read_text())
		["units"]}

	def score_source(unit: dict, text: str) -> diff.Verdict:
		# beside the original, so the candidate's own `#include "..."` lines still resolve
		path = (TESTS / "TestBinary" / unit["file"]).with_name(
			"phase4-%s.cpp" % unit["id"].lower())
		path.write_text(text, encoding="utf-8")
		try:
			row = cache.resolve_function(conn, hex(int(unit["address"]) + shift))
			outcome = cli.score_candidate(cfg, conn, meta, row[0], [path], fn=unit["mangled"],
				object_dir=TESTS / "build" / "phase4-objects")
		finally:
			path.unlink(missing_ok=True)
		if outcome["verdict"] is None:
			raise SystemExit("%s: %s" % (unit["id"], outcome["error"]))
		return outcome["verdict"]

	print("  %s" % variant)
	unit = units["MATH-20"]          # a function that reads 360.0f and 180.0f out of the pool
	source = (TESTS / "TestBinary" / unit["file"]).read_text()
	untouched = score_source(unit, source)
	ok("%s: the untouched source reaches the gate" % unit["id"], untouched.passed, True)
	ok("%s: its constants are verified by the four bytes read there" % unit["id"],
		sum(1 for item in untouched.symbols if "bytes" in item["evidence"]), 3)
	text = source.replace("360.0f", "359.0f", 1)
	truth("%s: the source has the constant to change" % unit["id"], "359.0f" in text)
	changed = score_source(unit, text)
	ok("%s: one constant changed by one unit fails the gate" % unit["id"],
		(changed.passed, changed.categories["relocation"] > 0, changed.categories["opcode"]),
		(False, True, 0))
	truth("%s: the report names the bytes and where they are read" % unit["id"],
		any("the bytes there differ" in item["why"] for item in changed.symbols))

	unit = units["STR-15"]           # a function that reaches the format string "%s:%d x%.1f"
	source = (TESTS / "TestBinary" / unit["file"]).read_text()
	untouched = score_source(unit, source)
	print("       %s untouched: tier %s, %d unverified" % (unit["id"], untouched.tier,
		untouched.unverified))
	text = source.replace("x%.1f", "x%.2f", 1)
	truth("%s: the source has a format string to change" % unit["id"], text != source)
	changed = score_source(unit, text)
	ok("%s: one character of a string literal fails the gate" % unit["id"],
		(changed.passed, changed.categories["relocation"] > 0), (False, True))
	truth("%s: the report names the string bytes" % unit["id"],
		any("the bytes there differ" in item["why"] for item in changed.symbols))
	conn.close()


def main() -> int:
	widths()
	strings()
	candidate_object()
	unverified()
	if "--no-target" not in sys.argv:
		real(next((item for item in sys.argv[1:] if not item.startswith("-")), "gcc-o0"))
	if "--full" in sys.argv:
		for variant in ("gcc-o2", "gcc-o0-x86"):
			real(variant)
	print()
	if FAILURES:
		print("%d FAILED:" % len(FAILURES))
		for line in FAILURES:
			print("  %s" % line)
		return 1
	print("%d checks passed" % OK)
	return 0


if __name__ == "__main__":
	sys.exit(main())
