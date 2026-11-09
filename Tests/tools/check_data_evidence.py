#!/usr/bin/env python3
"""Phase 4b (Docs/byte-cleanup-plan.md): the byte comparison has a data side.

Phase 4 made a *constant* verifiable: the bytes an instruction reads out of a pool, at the width the
instruction states. It said nothing about a **global** - the writable object a body reads and writes.
On a stripped image a global has no name, and an object file gives it no bytes when it has no
initial value, so every reference to one used to be counted `unverified`: a tier could not be claimed
over it, and no unit that touched one could ever anchor its callers. That is the rule that made a
whole subsystem of a symbol-less target unreachable, and these are the claims that replace it.

**A file that stores nothing for an object states its value.** An ELF `.bss` is `SHT_NOBITS`, a COFF
`.bss` is IMAGE_SCN_CNT_UNINITIALIZED, a PE maps `.data` far past the bytes it stores, a Mach-O
section is zero-fill. All four say: this object is zero when the process starts. LIEF hands back
bytes for every one of them anyway - whatever follows the section in the file - so reading those
bytes is reading nothing, and that is checked here before anything is compared on them.

**The comparison is about values, not about which file kept the bytes.** MSVC writes zero-initialised
globals *into* `.data`; GCC and `cl`'s own objects put them in a section with no bytes. Those two
agree, and agreeing is what has to be recognised. Storing `1` where the other side stores nothing is
a difference, and is named as one.

**Nothing distinguishing them is nothing proving them.** A unit that reads two globals of the same
shape - same access width, both zero - has not shown which symbol is which, because swapping them
changes no byte anywhere. Layout is what can settle it: if the distance between the two objects in
the image equals the distance between the two symbols in the candidate, the pairing is the only one
the layout allows. Layout never *refutes* (a link reorders, and one candidate holds one translation
unit of a bigger program), so a pair it cannot settle is counted with the unverified ones. This is
the data-side twin of refusing "both bodies are the same size" about a call.

**The runtime's own objects are named by what the unit does with them.** `__security_cookie` is not
the program's, and no symbol table in a shipped .exe names it. It is identified by the check the
program calls with its value - a name both sides already agree on.

Exit: 0 all passed, 1 something came out wrong, 2 no build to judge.
"""

from __future__ import annotations

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


def score(*refs, text: str = "movl DAT0, %eax", token: str = "DAT0",
		extra: list[tuple[str, normalize.Ref, str, normalize.Ref]] = (),
		**kw) -> diff.Verdict:
	"""One instruction reaching `refs[0]` on the original and `refs[1]` in the candidate, plus any
	`extra` lines, each given as (token, original ref, text, candidate ref)."""
	vocabulary = normalize.Vocabulary()
	left, right = [], []
	lines = [(token, refs[0], text, refs[1])] + list(extra)
	for one_token, one_left, one_text, one_right in lines:
		a = normalize.Token(text=one_text, mnemonic=one_text.split()[0], address=0x1000 + 4 * len(left))
		a.refs.append(one_left)
		left.append(a)
		b = normalize.Token(text=one_text, mnemonic=one_text.split()[0],
			address=0x2000 + 4 * len(right))
		b.refs.append(one_right)
		right.append(b)
		vocabulary.entries["original"].append((one_token, one_left))
		vocabulary.entries["candidate"].append((one_token, one_right))
	return diff.compare(left, right, vocabulary, threshold=0.0, **kw)


# ------------------------------------------------- what a file says about an object it stores nothing for

def what_the_file_says() -> None:
	"""`section_extents`: memory, and how much of it the file has bytes for."""

	class Stub:
		"""A section as LIEF hands one over: ELF says `flags` and `type`, PE and COFF say
		`characteristics`, and only the ELF one has a `type` to ask."""

		def __init__(self, name, size, virtual=0, flags=None, type_=None, characteristics=None):
			self.name, self.size, self.virtual_size = name, size, virtual
			if flags is not None:
				self.flags = flags
			if characteristics is not None:
				self.characteristics = characteristics
			if type_ is not None:
				self.type = type_

	# ELF: a PROGBITS section is all bytes; NOBITS has none, and its `size` is the memory size.
	# The flag word carries no NOBITS bit, so the type is the only answer (`section.type` is what
	# LIEF spells `...NOBITS`).
	ok("an ELF .rodata is stored whole",
		extract.section_extents("ELF", Stub(".rodata", 40, flags=0x2)), (40, 40))
	ok("an ELF .bss is memory with no bytes",
		extract.section_extents("ELF", Stub(".bss", 1088, flags=0x3, type_="NOBITS")), (1088, 0))
	ok("a PE .data mapped past what the file stores",
		extract.section_extents("PE", Stub(".data", 14336, virtual=647052,
			characteristics=0xc0000040)), (647052, 14336))
	ok("a COFF .bss is named by its flag, not its size",
		extract.section_extents(None, Stub(".bss", 8, characteristics=0xc0300080)), (8, 0))
	ok("a Mach-O zero-fill section has no bytes either",
		extract.section_extents("MACH_O", Stub("__bss", 64, characteristics=0)), (64, 0))

	# The `.bss` answer is the one that matters: LIEF's `content` for such a section is the bytes of
	# whatever follows it, so `_read` has to refuse the section rather than read it.
	obj = extract.CandidateObject.__new__(extract.CandidateObject)
	obj._sections = {".bss": b"GCC: (GN", ".data": b"\x07\x00\x00\x00"}
	obj._writable, obj._no_bytes = {".bss", ".data"}, {".bss"}
	obj._relocs, obj._coff = {}, False
	ok("no-bytes: the bytes LIEF invented for it are not read", obj._read(".bss", 0, 8), None)
	ok("a writable section that does have bytes is read", obj._read(".data", 0, 4),
		b"\x07\x00\x00\x00")
	ok("and a window under a relocation still is not",
		(setattr(obj, "_relocs", {".data": [(0, "R_X86_64_64", "g", 0)]}) or obj._read(".data",
			0, 4)), None)


# ------------------------------------------------------------------- values, not stored-bytes

def values() -> None:
	zeroed_there = normalize.Ref(kind="data", name="DAT_001120c0", raw="DAT0", initialised=False,
		width=4)
	stored_zeros = normalize.Ref(kind="data", raw="DAT0", content=b"\x00" * 4,
		initialised=True, width=4)
	# The two spellings of "zero-initialised" in the wild: an ELF/COFF section with no bytes, and
	# MSVC writing the zeros into `.data`. They agree, and a rule that called them different would
	# refute half the programs this tool scores.
	zeroed_here = normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4)
	ok("one side stores nothing, the other stores zeros: the same value",
		score(stored_zeros, zeroed_here).symbols[0]["ok"], True)
	ok("and the evidence names what it rests on", score(stored_zeros,
		zeroed_here).symbols[0]["evidence"], "zeroed")
	ok("both files omit the bytes: the same value",
		score(zeroed_there, zeroed_here).symbols[0]["evidence"], "zeroed")
	ok("a candidate that initialises it is a difference", score(
		normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4),
		normalize.Ref(kind="data", raw="DAT0", content=b"\x01\x00\x00\x00", initialised=True,
			width=4)).symbols[0]["ok"], False)
	truth("named as an initial value, not as a blob of bytes", any("initial values differ" in item[
		"why"] for item in score(normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4),
			normalize.Ref(kind="data", raw="DAT0", content=b"\x01\x00\x00\x00", initialised=True,
				width=4)).symbols))
	ok("the same in the other direction", score(
		normalize.Ref(kind="data", raw="DAT0", content=b"\x01\x00\x00\x00", initialised=True,
			width=4),
		normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4)).symbols[0]["ok"], False)
	ok("a difference in the value caps the tier", (score(
		normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4),
		normalize.Ref(kind="data", raw="DAT0", content=b"\x01\x00\x00\x00", initialised=True,
			width=4)).tier, score(
		normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4),
		normalize.Ref(kind="data", raw="DAT0", content=b"\x01\x00\x00\x00", initialised=True,
			width=4)).passed), ("none", False))
	# `initialised` is a fact a file states or does not. Nothing stated is still nothing known.
	silent = normalize.Ref(kind="data", raw="DAT0", width=4)
	ok("a file that says nothing about the address states no value",
		(score(silent, zeroed_here).unverified, score(silent, zeroed_here).tier), (1, "structural"))
	ok("neither does a read whose width the instruction does not state", score(
		normalize.Ref(kind="data", raw="DAT0", initialised=False),
		normalize.Ref(kind="data", raw="DAT0", initialised=False)).unverified, 1)
	ok("and a width on one side alone still says nothing about the object", score(
		normalize.Ref(kind="data", raw="DAT0", initialised=False, width=4),
		normalize.Ref(kind="data", raw="DAT0", initialised=False)).unverified, 1)
	# A constant in a read-only pool is still compared the Phase 4 way: the data side must not let a
	# pool with no name be waved through as "both zero".
	ok("a read-only pool is not a global: no value is claimed for it", score(
		normalize.Ref(kind="data", raw="SYM0", content=b"\x00" * 4, width=4),
		normalize.Ref(kind="data", raw="SYM0", content=b"\x00" * 4, width=4)).symbols[0][
			"evidence"], "bytes")


# ------------------------------------------------------- two globals of the same shape are one question

def interchangeable() -> None:
	"""A unit that reads two same-shaped zeroed globals has not said which is which."""

	def global_ref(address, section=".bss", width=4):
		return normalize.Ref(kind="data", name="DAT_%x" % address, raw="DAT0", address=address,
			section=section, initialised=False, width=width)

	def symbol(address, name, section=".bss", width=4):
		return normalize.Ref(kind="data", name=name, raw=name, address=address, section=section,
			initialised=False, width=width)

	line = "movl DAT0, %eax"
	pair_a = (global_ref(0x53d50c), symbol(0, "_g_osMinor"))
	pair_b = (global_ref(0x53d510), symbol(4, "_g_osMajor"))
	# The image has the two 4 bytes apart in that order, and so does the candidate object: the
	# pairing is the only one the layout allows, so both are answered.
	matched = score(*pair_a, extra=[("DAT1", global_ref(0x53d510), "movl DAT1, %eax",
		symbol(4, "_g_osMajor"))])
	ok("a layout that fits the pairing answers both", [item["evidence"] for item in
		matched.symbols], ["zeroed", "zeroed"])
	# Put the same two symbols the other way round: the stream is unchanged, the bytes are unchanged,
	# and the pairing is now a guess. Nothing here *refutes* it - the link could have reordered them
	# - but nothing proves it either, and a proof is what the gate asks for.
	swapped = score(*pair_a, extra=[("DAT1", global_ref(0x53d510), "movl DAT1, %eax",
		symbol(0, "_g_osMajor"))])
	ok("a pairing the layout does not fit is not proven", swapped.unverified, 2)
	ok("and it is not counted as a difference", any(not item["ok"] for item in swapped.symbols),
		False)
	truth("the report says what is missing", any("the layout does not say which is which" in line
		for line in swapped.gaps("semantic")))
	ok("it caps the tier", (swapped.tier, swapped.passed), ("structural", False))
	# Two globals of different shapes are two different questions: a byte flag is not interchangeable
	# with a DWORD, so neither is held back by the other.
	mixed = score(*pair_a, extra=[("DAT1", global_ref(0x53d508, width=1), "movzbl DAT1, %eax",
		symbol(16, "_g_flag", width=1))])
	ok("objects of different shapes do not hold each other back", [item["evidence"] for item in
		mixed.symbols], ["zeroed", "zeroed"])
	# And the rule is about the unit's own references: an unnamed *global* is still answered on its
	# own when nothing else in the unit looks like it.
	ok("a single same-shaped global is answered", score(*pair_a).symbols[0]["evidence"], "zeroed")


# ------------------------------------------------------------- the runtime's own objects

def runtime_objects() -> None:
	cookie = normalize.Ref(kind="data", name="___security_cookie", raw="___security_cookie")
	guard = normalize.Ref(kind="function", name="__security_check_cookie", raw="SYM18")

	def unit(name_left="DAT_004d8620", cookie_ref=cookie, check=guard):
		return score(
			normalize.Ref(kind="data", name=name_left, raw="DAT0", address=0x4d8620,
				section=".data", initialised=True, content=b"N\xe6@\xbb", width=4),
			cookie_ref,
			extra=[("SYM18", normalize.Ref(kind="external", name=check.name, raw=check.name),
				"call SYM18", normalize.Ref(kind="external", name=check.name, raw=check.name))])

	ok("the CRT's cookie, named by the check the unit calls with it",
		unit().symbols[0]["evidence"], "runtime")
	ok("without the check in the unit it is not claimed",
		score(normalize.Ref(kind="data", name="DAT_004d8620", raw="DAT0", address=0x4d8620,
			section=".data", initialised=True, content=b"N\xe6@\xbb", width=4),
			cookie).unverified, 1)
	ok("a decoration difference is the same pair",
		unit(cookie_ref=normalize.Ref(kind="data", name="__security_cookie",
			raw="__security_cookie")).symbols[0]["evidence"], "runtime")
	# Only for an object the candidate does not define. If it defines one under that name, it is
	# asked about the definition like any other global.
	ok("a symbol the candidate defines is not the runtime's", score(
		normalize.Ref(kind="data", name="DAT_004d8620", raw="DAT0", address=0x4d8620,
			section=".data", initialised=True, content=b"N\xe6@\xbb", width=4),
		normalize.Ref(kind="data", name="___security_cookie", raw="___security_cookie",
			address=0x18, section=".data", initialised=True, content=b"N\xe6@\xbb",
			width=4),
		extra=[("SYM18", normalize.Ref(kind="external", name="__security_check_cookie"),
			"call SYM18", normalize.Ref(kind="external", name="__security_check_cookie"))
		]).symbols[0]["evidence"], "bytes")
	ok("gcc's spelling is in the same table", "stackchkguard" in diff.RUNTIME_OBJECT_PAIRS, True)


# ------------------------------------------------------------------------ the real targets

def real(variant: str = "gcc-o0") -> None:
	"""MATH-13 reads a 1024-byte `.bss` table and a `.bss` flag. Untouched, both objects are now
	answered; give the flag an initial value the image does not have, and the unit must fail."""
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
	import json
	units = {item["id"]: item for item in json.loads((root / "answer_key.json").read_text())
		["units"]}

	def score_source(unit, text):
		path = (TESTS / "TestBinary" / unit["file"]).with_name(
			"phase4b-%s.cpp" % unit["id"].lower())
		path.write_text(text, encoding="utf-8")
		try:
			row = cache.resolve_function(conn, hex(int(unit["address"]) + shift))
			outcome = cli.score_candidate(cfg, conn, meta, row[0], [path], fn=unit["mangled"],
				object_dir=TESTS / "build" / "phase4b-objects")
		finally:
			path.unlink(missing_ok=True)
		if outcome["verdict"] is None:
			raise SystemExit("%s: %s" % (unit["id"], outcome["error"]))
		return outcome["verdict"]

	print("  %s" % variant)
	unit = units["MATH-13"]
	source = (TESTS / "TestBinary" / unit["file"]).read_text()
	untouched = score_source(unit, source)
	by_name = {item["candidate"]["name"]: item for item in untouched.symbols}
	flag = next((name for name in by_name if "Ready" in name), "")
	table = next((name for name in by_name if "crcTable" in name and name != flag), "")
	truth("%s: the two globals it reads are named by the candidate" % unit["id"],
		bool(table) and bool(flag))
	ok("%s: both objects are answered by what both files say about them" % unit["id"],
		[by_name[flag]["evidence"], by_name[table]["evidence"]], ["zeroed", "zeroed"])
	ok("%s: the objects are not counted against the unit" % unit["id"],
		len([item for item in untouched.unverified_refs
			if "crcTable" in (item["candidate"] or {}).get("name", "")]), 0)
	truth("%s: the only thing left is the helper it calls" % unit["id"],
		untouched.unverified == 1 and "callee" in diff._why_unverified(untouched.unverified_refs))

	text = source.replace("static bool g_crcTableReady = false;",
		"static bool g_crcTableReady = true;", 1)
	truth("%s: the source has the flag to initialise" % unit["id"], text != source)
	changed = score_source(unit, text)
	ok("%s: giving the flag a value the image does not have fails it" % unit["id"],
		changed.passed, False)
	truth("%s: and the report names the two values" % unit["id"], any(
		"initial values differ" in item["why"] for item in changed.symbols))
	conn.close()


def real_image() -> None:
	"""The same two `.bss` objects, on a target built by a linker that stores their zeros in
	`.data`: an uninitialised COFF object and a zero-filled PE section have to agree."""
	for name in ("gcc-o0", "msvc-o0"):
		path = TESTS / "build" / name / "da_tests"
		if not path.exists():
			print("  skip %s: not built" % name)
			continue
		image = extract.TargetImage(path, 0)
		bss = [(n, start, size) for n, start, size, _w in image.uninitialised]
		print("  %-9s file-backed sections: %s" % (name, [n for n, *_x in image.sections]))
		print("  %-9s allocated, not stored:   %s" % (name, [(n, hex(s), hex(z))
			for n, s, z in bss]))
		ok("%s: a section with no bytes in the file is not readable" % name,
			[n for n, *_x in image.sections if n in (".bss", ".bss!")], [])
	# And the read that used to answer with the bytes of the following section.
	elf = TESTS / "build" / "gcc-o0" / "da_tests"
	if elf.exists():
		image = extract.TargetImage(elf, 0)
		gap = image.uninitialised[0][1] if image.uninitialised else 0
		ok("reading an unallocated place gives nothing, not its neighbour's bytes",
			image.read_data(gap, 8) if gap else None, None)
		ok("and the answer about it is `no initial value`",
			image.initialised_at(gap) if gap else None, False)


def main() -> int:
	what_the_file_says()
	values()
	interchangeable()
	runtime_objects()
	if "--no-target" not in sys.argv:
		real_image()
		real(next((item for item in sys.argv[1:] if not item.startswith("-")), "gcc-o0"))
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
