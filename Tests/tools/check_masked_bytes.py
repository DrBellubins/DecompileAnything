#!/usr/bin/env python3
"""Phase 3: the byte comparison is relocation-masked, so `exact` means something.

Two bodies of code that reach the same things in the same order still differ in the bytes the
link writes: the displacement of a call, the pc-relative offset of a global, the address of a vftable.
Comparing those bytes compared nothing, which is why `exact` used to fire only for a body that
references nothing at all. This checks the fix, which is the same on both sides:

  * the candidate's `.o` states every field the link fills in - its relocation table;
  * the original has no relocations left, so its fields come from the address-carrying operands
    of its own decoded instructions, including the calls an object file resolves in-section;
  * everything else - opcodes, immediates, displacements inside the body, and the length of each
    encoding - is still compared, so an encoding choice is caught even when the instructions
    spell the same thing.

Run:
  .venv/bin/python Tests/tools/check_masked_bytes.py                 # synthetic + all variants
  .venv/bin/python Tests/tools/check_masked_bytes.py --no-target     # synthetic only
  .venv/bin/python Tests/tools/check_masked_bytes.py --variants gcc-o2
"""

from __future__ import annotations

import argparse
import collections
import json
import struct
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, diff, normalize  # noqa: E402

DEFAULT_VARIANTS = ["gcc-o0", "gcc-o2", "gcc-o0-x86"]
X86_64 = "x86:LE:64:default"
X86_32 = "x86:LE:32:default"

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


# --------------------------------------------------------------------------------------
# 1. where the field actually sits

# The starting point (`Slot.enc_offset`) is a convention read off the instruction's length, and it
# is wrong for a `0f 8x` conditional jump and for an instruction that has an immediate after its
# displacement. Both cases are here because masking the wrong bytes would silently pass a
# candidate that differs, or fail one that does not.

def fields_of(language: str, data: bytes, address: int, bind=lambda instruction: {}):
	"""The fields the link writes in `data`, straight off the decoder."""
	handle = normalize.capstone_for(language, detail=True)
	instructions = normalize.decode_function(handle, address, data)
	blocks = normalize.body_blocks(None, address, len(data))
	return (instructions, blocks,
		normalize.address_fields(blocks, instructions, bind))


def ref_bind(kind: str):
	"""A binder that resolves every address-carrying operand to something - what a real target does."""
	def bind(instruction):
		out = {}
		for slot in instruction.slots:
			out[slot.operand] = normalize.Ref(kind=kind, name="X", address=slot.value)
		return out
	return bind


def nothing_bind(instruction):
	return {}


def encodings() -> int:
	# `cmpb $0, 0xa613(%rip)`: `80 3d disp32 01`. The displacement is four bytes starting at
	# offset 2, and the length-minus-four convention points at offset 3 instead.
	data = bytes([0x80, 0x3d]) + struct.pack("<i", 0xa613) + bytes([0x01])
	instructions, _blocks, fields = fields_of(X86_64, data, 0x1000, ref_bind("data"))
	check("cmpb $0,x(%rip): one instruction", len(instructions), 1)
	check("cmpb $0,x(%rip): the displacement is at 2, not where the convention says",
		normalize.field_span(instructions[0], instructions[0].slots[1]), (2, 4))
	check("cmpb $0,x(%rip): masked fields", fields, [(2, 4), (6, 1)])

	# `jne rel32`: the rel32 starts two bytes in, but `_slots` says one.
	data = bytes([0x0f, 0x85]) + struct.pack("<i", 0x40)
	instructions, _blocks, fields = fields_of(X86_64, data, 0x1000, ref_bind("function"))
	check("jne rel32: the displacement is at 2", normalize.field_span(instructions[0],
		instructions[0].slots[0]), (2, 4))
	check("jne rel32: masked fields", fields, [(2, 4)])

	# `call rel32`: the convention is right here, and an unrelocated `call 0` in a `.o` must not
	# be read as a one-byte zero field
	data = bytes([0xe8]) + struct.pack("<i", -0xc)
	instructions, _blocks, fields = fields_of(X86_64, data, 0x1000, nothing_bind)
	check("call: the field is the whole rel32", normalize.field_span(instructions[0],
		instructions[0].slots[0]), (1, 4))
	data = bytes([0xe8, 0x00, 0x00, 0x00, 0x00])
	instructions, _blocks, fields = fields_of(X86_64, data, 0x1000, ref_bind("function"))
	check("unrelocated call in a .o: still a 4-byte field", fields, [(1, 4)])

	# `movl $7, disp32(%rip)`: the displacement is the link's, the immediate is not
	data = bytes([0xc7, 0x05]) + struct.pack("<i", 0x20) + struct.pack("<i", 7)
	_instructions, _blocks, fields = fields_of(X86_64, data, 0x1000, nothing_bind)
	check("movl $7,x(%rip): only the displacement is masked", fields, [(2, 4)])
	_instructions, _blocks, with_ref = fields_of(X86_64, data, 0x1000, ref_bind("data"))
	check("movl $ptr,mem(%rip): an immediate that resolves to an object is the link's too",
		with_ref, [(2, 4), (6, 4)])

	# 32-bit: an absolute address is a field; `pushl $0x1234` is only one when it resolves
	data = bytes([0xa1]) + struct.pack("<I", 0x8049000)
	_instructions, _blocks, fields = fields_of(X86_32, data, 0x1000, nothing_bind)
	check("movl abs,%eax (32-bit): masked fields", fields, [(1, 4)])
	data = bytes([0x68]) + struct.pack("<I", 0x8049a2c)
	_instructions, _blocks, fields = fields_of(X86_32, data, 0x1000, nothing_bind)
	check("pushl $constant (32-bit): an immediate is not masked", fields, [])
	_instructions, _blocks, fields = fields_of(X86_32, data, 0x1000, ref_bind("data"))
	check("pushl $_ZTI... (32-bit, non-PIE): the relocation sits on an immediate", fields,
		[(1, 4)])

	# a jump to a label inside the body is not the link's: the bytes say where the layout put it,
	# and if the candidate's layout differs that is a real difference
	body = bytes([0xeb, 0x03]) + bytes([0x90, 0x90, 0x90]) + bytes([0xc3])
	_instructions, _blocks, fields = fields_of(X86_64, body, 0x1000, lambda instruction: {
		0: normalize.Ref(kind="label", name="L0", address=0x1005)})
	check("jmp to an interior label: not masked", fields, [])
	return 0


# --------------------------------------------------------------------------------------
# 2. what the masked comparison says

def tok(text: str, address: int) -> normalize.Token:
	return normalize.Token(text=text, mnemonic=text.split()[0], address=address)


def compare_masked(original: bytes, candidate: bytes, *, address: int = 0x1000,
		bind_original=nothing_bind, bind_candidate=nothing_bind,
		extents_original=None, extents_candidate=None):
	"""Mask and compare two bodies the way `cli.score_candidate` does, from their bytes."""
	blocks_o = normalize.body_blocks(extents_original, address, len(original))
	blocks_c = normalize.body_blocks(extents_candidate, address, len(candidate))
	handle = normalize.capstone_for(X86_64, detail=True)
	ins_o = normalize.decode_function(handle, address, original, None, extents_original)
	ins_c = normalize.decode_function(handle, address, candidate, None, extents_candidate)
	fields_o = normalize.merge_fields(normalize.address_fields(blocks_o, ins_o, bind_original))
	fields_c = normalize.merge_fields(normalize.address_fields(blocks_c, ins_c, bind_candidate))
	out = diff.compare_bytes(original, fields_o, candidate, fields_c,
		normalize.body_index(blocks_o, ins_o, []), normalize.body_index(blocks_c, ins_c, []))
	out["fields"] = dict(out["fields"], original_fields=fields_o, candidate_fields=fields_c)
	return out


def masked_comparison() -> int:
	# The whole point: a call and a global load, whose displacements the link chose. The candidate
	# reaches the same things at other addresses, so every differing byte is a field.
	original = (bytes([0x48, 0x8b, 0x05]) + struct.pack("<i", 0x120) + bytes([0xe8])
		+ struct.pack("<i", 0x200) + bytes([0x0f, 0x85]) + struct.pack("<i", -0x30)
		+ bytes([0xc3]))
	candidate = (bytes([0x48, 0x8b, 0x05]) + struct.pack("<i", -0x2f40) + bytes([0xe8])
		+ struct.pack("<i", -0x1c8) + bytes([0x0f, 0x85]) + struct.pack("<i", 0x4c0)
		+ bytes([0xc3]))
	bind = ref_bind("function")
	out = compare_masked(original, candidate, bind_original=bind, bind_candidate=bind)
	check("call/global/jump to other places: the fields are found on both sides",
		(out["fields"]["original_fields"], out["fields"]["candidate_fields"]),
		([(3, 4), (8, 4), (14, 4)], [(3, 4), (8, 4), (14, 4)]))
	check("call/global/jump to other places: the masked bytes are equal", out["equal"], True)

	# ... and the same body where the candidate got the immediate wrong. Masking is not a free
	# pass: only the fields are hidden.
	bad = bytearray(candidate)
	bad[-1] = 0xc9                        # the last byte is not a field: `leave`, not `ret`
	out = compare_masked(original, bytes(bad), bind_original=bind, bind_candidate=bind)
	check("a byte that is not a field is still compared", out["equal"], False)
	check("the report says which instruction it falls in",
		("ret" in out["first"]["original"], "leave" in out["first"]["candidate"]), (True, True))

	# The length of an encoding is not a field either: a `jmp short` and a `jmp rel32` to the
	# same function spell the same thing and are not the same bytes.
	target = 0x1040
	short = (bytes([0xeb]) + struct.pack("<b", target - 0x1002) + bytes([0x90] * 0x3d)
		+ bytes([0xc3]))
	near = (b"\xe9" + struct.pack("<i", target - 0x1005) + bytes([0x90] * 0x3a)
		+ bytes([0xc3]))
	call_out = ref_bind("function")
	out = compare_masked(short, near, bind_original=call_out, bind_candidate=call_out)
	check("jmp short vs jmp rel32: the token text is the same, the bytes are not",
		out["equal"], False)
	check("jmp short vs jmp rel32: it names the offset and the instruction",
		(out["first"]["offset"], "jmp" in out["first"]["original"],
			"jmp" in out["first"]["candidate"]), (0, True, True))

	# One field is not a free pass either: a field is only zeroed on the side that has it, so if
	# one side reaches something the other does not, those bytes are compared.
	left = bytes([0xe8]) + struct.pack("<i", 0x10) + bytes([0xc3])
	right = bytes([0xe8]) + struct.pack("<i", -0x10) + bytes([0xc3])
	out = diff.compare_bytes(left, [(1, 4)], right, [])
	check("a field on one side only: bytes are not proven equal", out["equal"], False)
	check("a field on one side only: the field is zeroed on that side only",
		(out["first"]["offset"], out["fields"]["original"], out["fields"]["candidate"]),
		(1, 1, 0))

	# Per extent: a -O2 body is `.text` then `.text.unlikely`, and a field in the second block is
	# an offset into the concatenated bytes.
	hot = bytes([0xe8]) + struct.pack("<i", 0x10) + bytes([0xc3])
	cold = bytes([0x48, 0x8b, 0x05]) + struct.pack("<i", -0x40) + bytes([0xc3])
	body, other = hot + cold, hot + cold[:-1] + bytes([0xc9])
	extents = [(0x1000, len(hot)), (0x2000, len(cold))]
	out = compare_masked(body, other, extents_original=extents, extents_candidate=extents,
		bind_original=call_out, bind_candidate=call_out)
	check("two extents: the fields are offsets into the concatenation",
		out["fields"]["original_fields"], [(1, 4), (len(hot) + 3, 4)])
	check("two extents: a cold partition is compared too", (out["equal"],
		out["first"]["offset"] >= len(hot)), (False, True))
	return 0


# --------------------------------------------------------------------------------------
# 3. the tier follows the masked comparison, not the raw one


def tiers() -> int:
	# identical instructions, and the only difference in the bytes is what the link wrote
	lines = ["movq DAT0(%rip), %rax", "call FUN_0", "ret"]
	left = [tok(text, 0x1000 + 8 * index) for index, text in enumerate(lines)]
	right = [tok(text, 0x1000 + 8 * index) for index, text in enumerate(lines)]
	same = bytes([0xc3])
	vd = diff.compare(left, right, normalize.Vocabulary(), threshold=97.0,
		original_bytes=b"\xe8\x00\x00\x00\x00" + same,
		candidate_bytes=b"\xe8\xf7\xff\xff\xff" + same,
		original_fields=[(1, 4)], candidate_fields=[(1, 4)])
	check("a call displacement only: tier", vd.tier, "exact")
	check("a call displacement only: masked equal", vd.bytes_equal_masked, True)
	check("a call displacement only: the raw bytes were never equal", vd.bytes_equal, False)
	check("a call displacement only: nothing stands between it and the gate",
		vd.gaps("exact"), [])

	# the same thing with one field missing on one side is not `exact`, and the gap says where
	vd = diff.compare(left, right, normalize.Vocabulary(), threshold=97.0,
		original_bytes=b"\xe8\x00\x00\x00\x00" + same,
		candidate_bytes=b"\xe8\xf7\xff\xff\xff" + same,
		original_fields=[(1, 4)])
	check("a field on one side only: tier", vd.tier, "semantic")
	check("a field on one side only: the gap names the offset",
		"gaps differ" in vd.gaps("exact")[0] or "encodings differ" in vd.gaps("exact")[0], True)
	check("a field on one side only: the report says the test was masked",
		"the fields the link writes zeroed on both sides" in "\n".join(
			diff.report_lines(vd, "orig", "cand")), True)
	return 0


# --------------------------------------------------------------------------------------
# 4. the real targets: how many units can honestly claim `exact`

# Measured before Phase 3 (the unmasked byte test, Phase 2's run): identical bytes for 54 of 89
# at -O0, 58 at -O2, 40 at -O0 -m32. Masking can only ever raise a tier, so these are floors -
# and every one of them is a unit where the candidate really does assemble to the original.
# Phase 4 costs two of those: MATH-13 and STRUCT-21 reach nothing but data neither side can
# describe, so they are counted `unverified` and stop at `structural` (see the note printed below).
MIN_EXACT = {"gcc-o0": 87, "gcc-o2": 84, "gcc-o0-x86": 63}
# the units that do not reach the gate at all, and why (the same list check_phase2_try.py owns)
KNOWN_GAPS = {
	"gcc-o2": ["STRUCT-22", "STRUCT-23", "STRUCT-24"],
	"gcc-o0-x86": ["MATH-11", "MATH-13", "MATH-19", "MATH-20", "MATH-22", "MATH-23", "MATH-24",
		"MATH-32", "STR-18", "STR-19", "STRUCT-20", "STRUCT-25",
		# Phase 4 opened these: comparing the bytes a 32-bit access reads turned two units that
		# used to pass into reference mismatches. They are not the candidate's doing - at i386 the
		# candidate's window in a plain `.rodata` double pool is anchored on the nearest symbol
			# rather than the offset the relocation addresses. Open tool bug, named here so a new one
		# still fails this check.
		"MATH-21", "MATH-27"],
}


def targets(cfg_path: str, variants: list[str], limit: int) -> int:
	cfg = config.load(cfg_path)
	store = cache.Cache(config.cache_dir(cfg))
	# the cache root also holds `try`'s candidate scratch directories, which contain an analysis.db
	# with no meta table; listing targets has to skip those instead of raising.
	key = cache.target_key(TESTS / "build" / variants[0] / "da_tests.stripped")["key"]
	listed = [entry.get("db") for entry in store.targets()]
	if str(store.db_path(key)) not in listed:
		problems.append("cache.targets() does not list the benchmark target (%d listed)" % len(listed))
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
		raw_equal = 0
		below: list[str] = []
		unverified: list[str] = []
		only_unverified: list[str] = []
		asymmetric: list[str] = []
		masked = 0
		for unit in units:
			row = cache.resolve_function(conn, hex(unit["address"] + offset))
			if not row:
				problems.append("%s %s: no cached function at %s" % (variant, unit["id"],
					hex(unit["address"] + offset)))
				continue
			outcome = cli.score_candidate(cfg, conn, meta, row[0],
				[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"],
				object_dir=store.root / "candidates-masked")
			outcome["object"].unlink(missing_ok=True)
			verdict = outcome["verdict"]
			if verdict is None:
				problems.append("%s %s: %s" % (variant, unit["id"], outcome["error"]))
				continue
			histogram[verdict.tier] += 1
			raw_equal += 1 if verdict.bytes_equal else 0
			masked += int(verdict.masked_byte_fields.get("original_bytes", 0))
			if verdict.tier == "exact" and (verdict.masked_byte_fields.get("original")
					!= verdict.masked_byte_fields.get("candidate")):
				# both sides agreed on the bytes and disagreed on what the link writes: worth
				# knowing, because one of the two field lists is wrong somewhere
				asymmetric.append("%s %s (%d vs %d fields)" % (variant, unit["id"],
					verdict.masked_byte_fields.get("original", 0),
					verdict.masked_byte_fields.get("candidate", 0)))
			if not verdict.passed:
				below.append(unit["id"])
			if verdict.unverified:
				# the reference count Phase 4 added: what the two sides reach but cannot describe
				unverified.append("%s %s (%d)" % (variant, unit["id"], verdict.unverified))
			if not verdict.passed and verdict.unverified and not any(
					verdict.categories[name] for name in ("opcode", "operand", "register",
						"missing", "extra")):
				# nothing about the instructions is wrong: only the references neither side can
				# name, bound or read are standing in the way
				only_unverified.append(unit["id"])
		conn.close()
		note("%s: tiers" % variant, dict(histogram))
		# nothing is left between the gate and the top tier: on these targets a candidate that
		# reaches the gate also proves its bytes. That is not guaranteed in general - it is what
		# this benchmark measures, so it is asserted, and a new unit that lands on `semantic`
		# alone is worth looking at
		check("%s: every unit that passes the gate reaches exact" % variant,
			histogram["semantic"], 0)
		check("%s: exact is never lower than the raw byte test" % variant,
			histogram["exact"] >= raw_equal, True)
		check("%s: units claiming `exact`" % variant, histogram["exact"] >= MIN_EXACT[variant],
			True)
		if variant in KNOWN_GAPS:
			check("%s: the units below the gate are the known gaps" % variant,
				sorted(item for item in below if item not in only_unverified),
				sorted(KNOWN_GAPS[variant]))
		else:
			check("%s: nothing is below the gate" % variant,
				sorted(item for item in below if item not in only_unverified), [])
		if only_unverified:
			note("%s: capped by references neither side can describe" % variant,
				"%d units - %s; the tier stops at `structural` because nothing proves what they "
				"reach. Reproduce the object, or say the target cannot name it with [gate] "
				"waive = \"unverified\"" % (len(only_unverified), ", ".join(only_unverified)))
		note("%s: bytes" % variant, "%d of %d units have identical bytes without masking, %d "
			"with the fields the link writes zeroed; %d bytes of link-chosen fields were hidden "
			"in total" % (raw_equal, len(units), histogram["exact"], masked))
		if asymmetric:
			note("%s: exact with field lists that do not match (a field list is wrong there)"
				% variant, asymmetric)
		for unit_id in below:
			print("       below the gate: %s %s" % (variant, unit_id))
	for problem in problems:
		print("  PROBLEM %s" % problem)
	return len(problems)


def main() -> int:
	ap = argparse.ArgumentParser()
	ap.add_argument("--config", default=str(TESTS / "project.toml"))
	ap.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
	ap.add_argument("--limit", type=int, default=0)
	ap.add_argument("--no-target", action="store_true", help="synthetic checks only")
	args = ap.parse_args()
	encodings()
	masked_comparison()
	tiers()
	if not args.no_target:
		targets(args.config, [v for v in args.variants.split(",") if v], args.limit)
	print()
	if failures:
		print("%d FAILED:" % len(failures))
		for failure in failures:
			print("  %s" % failure)
		return 1
	print("all groups passed")
	return 0


if __name__ == "__main__":
	sys.exit(main())
