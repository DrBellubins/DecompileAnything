"""Align two instruction streams, score them, and say what kind of difference each is.

The percentage is only there to show how far off a candidate is. What the loop uses is the
category of each difference: an `opcode` difference means the operation is wrong, an
`operand` difference means the operation is right but an offset or constant is not, a
`register` difference is register allocation (Phase 5's problem, not the model's), a
`relocation` difference means the same shape of code reaches for a different function or
object, and `missing`/`extra` mean the control flow or size differs.

What gates a unit is the **tier** it reaches (Docs/byte-cleanup-plan.md, Phase 2), not the
ratio. The ratio is a progress indicator: 97 % of a wrong function is still a wrong function.

  none        the streams differ in shape or in operations
  structural  same length, same operations, same targets
              (`opcode == relocation == missing == extra == 0`)
  semantic    structural, no operand is wrong, and the streams are identical once every register
              name is folded to the order it first appears in
  exact       semantic, and the bytes are equal once the fields the link chooses are zeroed on
              both sides (Phase 3). What is masked is exactly the bytes a relocation in the
              candidate covers, plus the operands that reach an address on the original side:
              calls, jumps out of the body, pc-relative and absolute addresses. Everything else -
              opcodes, immediates, displacements inside the body, the length of each encoding - is
              compared.

The register-abstract comparison runs on every `try`, not only with `--register-abstract`. That
is what separates a register-allocation difference (`movl %eax,%ecx` vs `movl %r9d,%r8d`, not
the model's fault) from a different operand pairing (`subss %xmm1,%xmm0` vs `subss %xmm0,%xmm1`,
it is): folding both sides makes the first identical and leaves the second different. Remaining
plain `register` differences are reported as "allocation only" when the abstracted streams are
clean, and as a real difference when they are not.

The tier a unit has to reach comes from `[gate] require` in the target's project.toml
(`structural`, `semantic`, `exact`, or the older `percent` rule / `none` as escape hatches).

The counts add up exactly (Docs/byte-cleanup-plan.md, Phase 1). Every line of either stream is
either matched or appears in `diff` once: a replaced pair counts once as a difference and on
both sides, a `missing` line on the original side only, an `extra` line on the candidate side
only, and a `replace` block whose two sides are different lengths reports its leftover tail as
`missing`/`extra` instead of dropping it. `accounting()`/`accounting_problems()` state that
identity: the tests assert it, the runtime only complains when it breaks.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from .normalize import (Ref, REGISTER_ALIASES, Token, abstract_registers, canonical_name,
	mask_body, mask_registers, register_names)

CATEGORIES = ("opcode", "operand", "register", "relocation", "missing", "extra")
# The categories that mean "this is not the same computation". None of them may be non-zero for
# a unit to be more than `none`.
SHAPE = ("opcode", "relocation", "missing", "extra")

# Ordered, lowest first. `percent` and `none` are not tiers: they are the pre-Phase-2 gate and
# no gate at all, kept as escape hatches for a target where no tier can honestly be claimed (an
# LTCG MSVC image, a toolchain this machine cannot reproduce).
TIERS = ("none", "structural", "semantic", "exact")
GATE_MODES = ("none", "percent") + TIERS
GATE_DEFAULT = "semantic"

TIER_MEANING = {
	"none": "the instruction stream is not the same shape or not the same operations",
	"structural": "same length, same operations, same targets - the operands are not proven right",
	"semantic": "same operations, operands and targets, in whatever registers - the bytes are not "
		"proven equal",
	"exact": "the candidate assembles to the original bytes, with the fields the link writes left "
		"out",
}


def tier_rank(name: str) -> int:
	return TIERS.index(name if name in TIERS else "none")


@dataclass
class Verdict:
	require: str
	threshold: float
	match_percent: float
	categories: dict[str, int]
	diff: list[dict] = field(default_factory=list)
	symbols: list[dict] = field(default_factory=list)
	original_instructions: int = 0
	candidate_instructions: int = 0
	original_bytes: int = 0
	candidate_bytes: int = 0
	# How the categories were arrived at, kept so the counts can be checked against the stream
	# lengths: `matched` lines are identical on both sides, `replaced` is the number of one-to-one
	# differing pairs, `hidden_relocations` re-counted lines already counted as matched.
	matched: int = 0
	replaced: int = 0
	hidden_relocations: int = 0
	identical: bool = False
	bytes_equal: bool = False
	# the same comparison with the fields the link chooses zeroed on both sides (Phase 3). This is
	# what gates `exact`: two bodies that reach the same things in the same order differ in those
	# bytes whatever the source said, because the link wrote them.
	bytes_equal_masked: bool = False
	bytes_comparable: bool = False   # both bodies are known, so the byte test can be run at all
	bytes_masked: bool = False       # False = no field lists were given, so the test is unmasked
	masked_byte_fields: dict = field(default_factory=dict)
	masked_first_difference: dict = field(default_factory=dict)
	# the same comparison over streams with every register name folded to first-appearance
	# order, kept so "allocation only" can be told from a different operand pairing
	abstract_categories: dict[str, int] = field(default_factory=lambda: {n: 0 for n in CATEGORIES})
	tier: str = "none"
	warnings: list[str] = field(default_factory=list)

	@property
	def register_only(self) -> int:
		"""`register` differences that are only register allocation: the abstracted streams are
		clean, so the same operation happened in different registers."""
		return 0 if not self.abstract_clean else self.categories["register"]

	@property
	def abstract_clean(self) -> bool:
		return not any(self.abstract_categories.values())

	@property
	def tier_ok(self) -> bool:
		"""Does this verdict reach the tier the gate asks for?"""
		if self.require == "none":
			return True
		if self.require == "percent":
			return (self.match_percent >= self.threshold and self.categories["opcode"] == 0
				and self.categories["relocation"] == 0)
		return tier_rank(self.tier) >= tier_rank(self.require)

	@property
	def passed(self) -> bool:
		"""The gate, kept under its old name because every caller already reads it."""
		return self.tier_ok

	def gaps(self, want: str) -> list[str]:
		"""What stands between this verdict and tier `want`, in the order to fix it."""
		return tier_gaps(self.categories, self.abstract_categories, self.bytes_equal_masked, want,
			self.byte_gap)

	@property
	def byte_gap(self) -> str:
		"""Why the bytes are not proven equal, in the form the loop can act on."""
		if not self.bytes_comparable:
			return "the bytes cannot be compared (one of the two bodies is missing)"
		if not self.bytes_masked:
			return ("the bytes are not equal, and no relocation fields were given, so this byte "
				"test is unmasked")
		if not (self.masked_byte_fields.get("original") or self.masked_byte_fields.get(
				"candidate")):
			return ("no field of either body belongs to the link, so every byte of it is "
				"compared")
		first = self.masked_first_difference or {}
		if first.get("offset") is None:
			return "the two bodies are different lengths (%d vs %d bytes)" % (self.original_bytes,
				self.candidate_bytes)
		return "at byte offset 0x%x the encodings differ (%s / %s)" % (int(first["offset"]),
			first.get("original") or "nothing there", first.get("candidate") or "nothing there")

	@property
	def size_delta_instructions(self) -> int:
		return self.candidate_instructions - self.original_instructions

	@property
	def size_delta_bytes(self) -> int:
		return self.candidate_bytes - self.original_bytes

	@property
	def worst(self) -> str:
		ranked = sorted(self.categories.items(), key=lambda item: -item[1])
		return ranked[0][0] if ranked and ranked[0][1] else ""


# --------------------------------------------------------------------------------------
# the counts have to add up


def accounting(verdict: Verdict) -> dict[str, int]:
	"""The line-count identity `compare` is required to satisfy:

		matched + replaced + missing == original_instructions
		matched + replaced + extra   == candidate_instructions
		sum(categories) - hidden_relocations == replaced + missing + extra

	Those two imply, for any alignment, the form `Docs/byte-cleanup-plan.md` Phase 1 asks for,
	with the one correction that makes it exact:

		matched + sum(categories) - hidden == max(len, len) + min(missing, extra)

	A region that turns N original lines into M candidate lines is one differing region but
	counts on both sides, so the plan's `== max(len, len)` holds only when the differences are
	all on one side (min(missing, extra) == 0). Pairing both sides through `replaced` is the
	equivalent that holds for this counting either way.
	"""
	visible = sum(verdict.categories[name] for name in CATEGORIES) - verdict.hidden_relocations
	return {
		"matched": verdict.matched,
		"replaced": verdict.replaced,
		"hidden_relocations": verdict.hidden_relocations,
		"visible_differences": visible,
		"original_lines_accounted": verdict.matched + verdict.replaced + verdict.categories["missing"],
		"candidate_lines_accounted": verdict.matched + verdict.replaced + verdict.categories["extra"],
	}


def accounting_problems(verdict: Verdict) -> list[str]:
	"""Why the counts do not add up - empty for a verdict that accounts for every line."""
	acc = accounting(verdict)
	problems = []
	missing, extra = verdict.categories["missing"], verdict.categories["extra"]
	for side, total, name in (("original", verdict.original_instructions, "missing"),
			("candidate", verdict.candidate_instructions, "extra")):
		count = acc["%s_lines_accounted" % side]
		if count != total:
			problems.append("%s side: matched %d + replaced %d + %s %d = %d, but the stream has %d "
				"instructions" % (side, acc["matched"], acc["replaced"], name,
					verdict.categories[name], count, total))
	if acc["visible_differences"] != acc["replaced"] + missing + extra:
		problems.append("%d categorised differences do not come from %d replaced pairs + %d "
			"missing + %d extra" % (acc["visible_differences"], acc["replaced"], missing, extra))
	if any(value < 0 for value in verdict.categories.values()):
		problems.append("a category is negative")
	if acc["hidden_relocations"] > acc["matched"]:
		problems.append("%d hidden relocations is more than the %d matched lines" % (
			acc["hidden_relocations"], acc["matched"]))
	return problems


# --------------------------------------------------------------------------------------
# do two symbol tokens mean the same thing?


def refs_compatible(a: Ref, b: Ref) -> tuple[bool, str]:
	"""Conservative: a difference is only claimed when both sides have evidence.

	A name only counts against a candidate when both sides know a real name (an import, or a
	symbol of an unstripped target); bytes only count when both sides know what object they
	are reading (a size on both, or a name on both); a size only counts when both sides know
	one. Anything unknown stays an accepted match, and the symbol table says so, rather than
	being guessed at.
	"""
	if a.cls != b.cls:
		return False, "%s on the original, %s in the candidate" % (a.kind, b.kind)
	if a.named and b.named and canonical_name(a.name) != canonical_name(b.name):
		return False, "reaches %s, the candidate reaches %s" % (a.name, b.name)
	# Bytes only count when both sides are reading *the same kind of thing*: an object whose
	# extent both sides know (a size on both), or one both sides name. A `.rodata` pool that
	# neither side can bound is laid out per build - the same constants at different offsets -
	# so two 16-byte windows out of it are not the same object twice, and a difference there
	# would be the linker's layout, not the candidate's.
	bounded = bool(a.size and b.size)
	if a.content and b.content and (bounded or (a.named and b.named)):
		shared = min(len(a.content), len(b.content), int(min(a.size, b.size)) if bounded else 1 << 30)
		if shared and a.content[:shared] != b.content[:shared]:
			return False, "the bytes there differ (%s vs %s)" % (
				a.content[:shared].hex(), b.content[:shared].hex())
	# a size is only the same kind of quantity when both sides know the object by name, or
	# when it is a function body: a `.rodata` object that holds several merged string
	# literals is bigger than the one string Ghidra measured inside it
	if a.size and b.size and a.size != b.size and (
			a.kind == "function" or (a.named and b.named)):
		return False, "%d bytes there, %d in the candidate" % (a.size, b.size)
	return True, ""


def _pair(vocab_side_original, vocab_side_candidate):
	"""Match positional tokens across the sides: SYM0 with SYM0, DAT3 with DAT3, and a real
	symbol name with the same name."""
	left = {token: ref for token, ref in vocab_side_original}
	right = {token: ref for token, ref in vocab_side_candidate}
	pairs = []
	for token in left:
		if token in right:
			pairs.append((token, left[token], right[token]))
	return pairs


def _pair_registers(a, b) -> tuple[str, str]:
	"""A line pair whose only difference is register names: a rename, or a different pairing?

	`movl %eax, %ecx` vs `movl %r9d, %r8d` is the same operation on different registers - not
	the model's doing. `subss %xmm1, %xmm0` vs `subss %xmm0, %xmm1` is not a rename: the same
	registers appear in a different order, and the one that ends up written (the last operand in
	AT&T) changes, which is a different computation. The first-appearance folding cannot tell
	those apart on its own - a swap folds to the same line - so the swap is named here.
	"""
	left = [REGISTER_ALIASES.get(name, name) for name in register_names(a.text)]
	right = [REGISTER_ALIASES.get(name, name) for name in register_names(b.text)]
	if left != right and sorted(left) == sorted(right) and left[-1:] != right[-1:]:
		return "operand", "the same registers in a different order: %s vs %s" % (a.text, b.text)
	return "register", "same operation, different registers"


def _difference(a, b) -> tuple[str, str]:
	"""The category of one differing line pair, and why."""
	if a.mnemonic != b.mnemonic:
		return "opcode", "%s vs %s" % (a.mnemonic, b.mnemonic)
	if mask_registers(a.text) == mask_registers(b.text):
		return _pair_registers(a, b)
	paired = list(zip(a.refs, b.refs))
	if paired:
		for left, right in paired:
			ok, why = refs_compatible(left, right)
			if not ok:
				return "relocation", why
	return "operand", "operands differ"


# --------------------------------------------------------------------------------------
# the tiers, and what a verdict is missing


def tier_for(categories: dict, abstract: dict, bytes_equal: bool) -> str:
	"""The tier a pair of comparisons reaches - see the module docstring.

	`bytes_equal` is the *masked* byte comparison (`compare_bytes`): the raw one only fires for a
	body that references nothing, which is most of why `exact` was out of reach before Phase 3.
	"""
	if any(categories[name] for name in SHAPE):
		return "none"
	if categories["operand"] or any(abstract.values()):
		return "structural"
	return "exact" if bytes_equal else "semantic"


def _say(categories: dict, names: tuple[str, ...] = CATEGORIES) -> str:
	return ", ".join("%s %d" % (name, categories[name]) for name in names if categories[name])


def compare_bytes(original: bytes, original_fields, candidate: bytes, candidate_fields,
		original_at: dict | None = None, candidate_at: dict | None = None) -> dict:
	"""Compare two bodies with the fields the link chose zeroed on each side.

	Each side's fields come from its own evidence: for a candidate `.o`, its relocation table (the
	width from the relocation type); for the original, the address-carrying operands of its own
	decoded instructions (`normalize.address_fields`), including the calls that need no relocation
	in an object file but whose displacement the link fills in anyway. A field is only zeroed on
	the side that has it, which makes this stricter than one shared list, never looser: if one
	side reaches something the other does not, the bytes there are compared against zero and the
	report says where.
	"""
	original_fields, candidate_fields = (None if original_fields is None else list(original_fields),
		None if candidate_fields is None else list(candidate_fields))
	# `None` means the caller has no field lists at all, so the test runs on every byte; an empty
	# list means it looked and found none, which is a different thing to say
	given = original_fields is not None or candidate_fields is not None
	original_fields, candidate_fields = original_fields or [], candidate_fields or []
	left = mask_body(original, original_fields) if given else bytes(original or b"")
	right = mask_body(candidate, candidate_fields) if given else bytes(candidate or b"")

	def width_of(items):
		return sum(int(width) for _offset, width in items)

	out = {
		"given": given,
		"fields": {"original": len(original_fields), "candidate": len(candidate_fields),
			"original_bytes": width_of(original_fields), "candidate_bytes": width_of(candidate_fields)},
		"equal": bool(original) and left == right,
		"first": {},
	}
	if out["equal"]:
		return out
	common = min(len(left), len(right))
	offset = next((index for index in range(common) if left[index] != right[index]), common)
	out["first"] = {"offset": offset, "original_length": len(left), "candidate_length": len(right),
		"original": (original_at or {}).get(offset, ""),
		"candidate": (candidate_at or {}).get(offset, "")}
	return out


def tier_gaps(categories: dict, abstract: dict, bytes_equal: bool, want: str,
		byte_gap: str = "") -> list[str]:
	"""What stands between a verdict and tier `want`, in the order the loop should fix it.

	Shape first (an operation, a target, or a whole line is wrong), then operands, then the
	thing only the abstracted comparison can see: a stream that still differs once registers are
	renamed is a different pairing of operands, not a register allocation.
	"""
	gaps: list[str] = []
	if tier_rank(want) < tier_rank("structural"):
		return gaps
	for name in SHAPE:
		if categories[name]:
			gaps.append("%d %s differences" % (categories[name], name))
	if tier_rank(want) >= tier_rank("semantic"):
		if categories["operand"]:
			gaps.append("%d operand differences" % categories["operand"])
		if any(abstract.values()):
			gaps.append("the stream still differs once registers are renamed (%s)" % _say(abstract))
	if tier_rank(want) >= tier_rank("exact") and not bytes_equal:
		gaps.append(byte_gap or "the bytes are not equal")
	return gaps


# --------------------------------------------------------------------------------------
# the two comparisons


def _align(original: list, candidate: list) -> dict:
	"""Align two token streams and categorise every difference.

	Run twice by `compare`: once on the tokens as written, once with the registers folded. Only
	the strict pass feeds `diff` and the counts that `accounting()` checks.
	"""
	left = [token.text for token in original]
	right = [token.text for token in candidate]
	matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
	categories = {name: 0 for name in CATEGORIES}
	diff: list[dict] = []
	replaced = 0
	for tag, i1, i2, j1, j2 in matcher.get_opcodes():
		if tag == "equal":
			continue
		if tag == "replace":
			# The two blocks are not necessarily the same length. Pair the common prefix, then
			# report the leftover tail of whichever side is longer as missing/extra: `zip` alone
			# dropped it, so a candidate that turned three original lines into one reported one
			# difference and never said two lines went away - `missing + extra == 0` read as
			# "same length" and was wrong.
			a_block, b_block = original[i1:i2], candidate[j1:j2]
			for a, b in zip(a_block, b_block):
				kind, why = _difference(a, b)
				categories[kind] += 1
				replaced += 1
				diff.append({"category": kind, "original": a.text, "candidate": b.text,
					"original_address": a.address, "candidate_address": b.address, "why": why})
			for a in a_block[len(b_block):]:
				categories["missing"] += 1
				diff.append({"category": "missing", "original": a.text, "candidate": None,
					"original_address": a.address, "candidate_address": None, "why": ""})
			for b in b_block[len(a_block):]:
				categories["extra"] += 1
				diff.append({"category": "extra", "original": None, "candidate": b.text,
					"original_address": None, "candidate_address": b.address, "why": ""})
		elif tag == "delete":
			categories["missing"] += i2 - i1
			for a in original[i1:i2]:
				diff.append({"category": "missing", "original": a.text, "candidate": None,
					"original_address": a.address, "candidate_address": None, "why": ""})
		elif tag == "insert":
			categories["extra"] += j2 - j1
			for b in candidate[j1:j2]:
				diff.append({"category": "extra", "original": None, "candidate": b.text,
					"original_address": None, "candidate_address": b.address, "why": ""})

	# A pair of identical lines can still hide a difference: two positional tokens matched by
	# order, but pointing at a different object. Check every aligned equal pair.
	hidden = 0
	for block in matcher.get_matching_blocks():
		for step in range(block.size):
			a, b = original[block.a + step], candidate[block.b + step]
			for left_ref, right_ref in zip(a.refs, b.refs):
				ok, why = refs_compatible(left_ref, right_ref)
				if not ok:
					hidden += 1
					diff.append({"category": "relocation", "original": a.text, "candidate": b.text,
						"original_address": a.address, "candidate_address": b.address,
						"why": "the lines match but not what they reach: " + why, "hidden": True})
	categories["relocation"] += hidden
	return {"matched": sum(block.size for block in matcher.get_matching_blocks()),
		"replaced": replaced, "hidden": hidden, "categories": categories, "diff": diff,
		"original_instructions": len(left), "candidate_instructions": len(right)}


def _fold_registers(tokens: list, side: str, vocabulary) -> list[Token]:
	"""The same stream with each side's registers named by order of first appearance, so
	`%rax` on one side and `%r9` on the other are both that side's `r0`.

	Symbol tokens, data tokens and unit-relative labels are untouched: this only folds register
	*names*, so a different pairing of operands still shows.
	"""
	return [Token(text=abstract_registers(token.text, vocabulary, side), mnemonic=token.mnemonic,
		address=token.address, refs=token.refs) for token in tokens]


def compare(original: list, candidate: list, vocabulary, *, threshold: float,
		original_bytes: bytes = b"", candidate_bytes: bytes = b"",
		original_fields=None, candidate_fields=None, original_at: dict | None = None,
		candidate_at: dict | None = None, require: str = GATE_DEFAULT) -> Verdict:
	"""Score a candidate against the original and name the tier it reaches.

	`require` is the gate from the target's `[gate]` table; `verdict.passed` is "this reaches
	it". The tokens have to be the un-folded ones: the register-abstract comparison happens
	here, on every call, so a verdict always knows whether its register differences are
	allocation or a different operand pairing.

	`original_fields` / `candidate_fields` are the (offset, width) pairs of each body the link
	writes (`normalize.address_fields`, `extract.CandidateObject.relocation_fields`), and
	`original_at` / `candidate_at` map a body offset to the instruction it falls in, so a byte
	difference can be named. Leave them `None` and the byte test runs unmasked, which is what the
	synthetic callers do; pass empty lists to say "looked, there are none in this body".
	"""
	strict = _align(original, candidate)
	abstract = _align(_fold_registers(original, "original", vocabulary),
		_fold_registers(candidate, "candidate", vocabulary))
	left = [token.text for token in original]
	right = [token.text for token in candidate]
	denominator = max(len(left), len(right), 1)
	percent = round(100.0 * strict["matched"] / denominator, 2)
	categories = strict["categories"]
	diff = strict["diff"]
	hidden_relocations = strict["hidden"]

	symbols = []
	for token, left_ref, right_ref in _pair(vocabulary.entries["original"], vocabulary.entries["candidate"]):
		ok, why = refs_compatible(left_ref, right_ref)
		symbols.append({"token": token, "ok": ok, "why": why,
			"original": _describe(left_ref), "candidate": _describe(right_ref)})
	for token, ref in vocabulary.entries["original"]:
		if not any(item["token"] == token for item in symbols):
			symbols.append({"token": token, "ok": False, "why": "the candidate never reaches it",
				"original": _describe(ref), "candidate": None})
	for token, ref in vocabulary.entries["candidate"]:
		if not any(item["token"] == token for item in symbols):
			symbols.append({"token": token, "ok": False, "why": "the original never reaches it",
				"original": None, "candidate": _describe(ref)})

	require = require if require in GATE_MODES else GATE_DEFAULT
	verdict = Verdict(
		require=require, threshold=float(threshold), match_percent=percent, categories=categories,
		diff=diff, symbols=symbols, original_instructions=len(left),
		candidate_instructions=len(right), original_bytes=len(original_bytes),
		candidate_bytes=len(candidate_bytes), abstract_categories=abstract["categories"],
		identical=left == right,
		bytes_equal=bool(original_bytes) and original_bytes == candidate_bytes,
	)
	verdict.matched, verdict.replaced, verdict.hidden_relocations = (
		strict["matched"], strict["replaced"], strict["hidden"])
	byte_check = compare_bytes(original_bytes, original_fields, candidate_bytes, candidate_fields,
		original_at, candidate_at)
	verdict.bytes_comparable = bool(original_bytes) and bool(candidate_bytes)
	verdict.bytes_masked = byte_check["given"]
	verdict.masked_byte_fields = byte_check["fields"]
	verdict.masked_first_difference = byte_check["first"]
	# "the candidate assembles to the original bytes, apart from what the link wrote" is the claim
	# `exact` makes; bytes equal outright imply it
	verdict.bytes_equal_masked = bool(original_bytes) and (
		verdict.bytes_equal or byte_check["equal"])
	verdict.tier = tier_for(categories, abstract["categories"], verdict.bytes_equal_masked)
	# Falling short of the threshold always has a categorised difference now, so the only way to
	# fail with nothing categorised is a count that went wrong here.
	problems = accounting_problems(verdict)
	if problems:
		verdict.warnings.append("internal error in the comparison: " + "; ".join(problems))
	return verdict


def _describe(ref: Ref) -> dict:
	return {"kind": ref.kind, "name": ref.name or ref.raw or "?",
		"section": ref.section, "size": ref.size,
		"named": ref.named,
		"content": ref.content[:16].hex() if ref.content else None}


# --------------------------------------------------------------------------------------
# the compact text form (kept short on purpose: an LLM reads this)


def report_lines(verdict: Verdict, original_name: str, candidate_name: str, *,
	max_diff: int = 16, max_symbols: int = 12, with_symbols: bool = True) -> list[str]:
	gate = verdict.require
	lines = ["tier %s  %s   (gate: %s)" % (verdict.tier, "PASS" if verdict.passed else "FAIL",
		gate)]
	lines.append("  %s" % TIER_MEANING.get(verdict.tier, ""))
	lines.append("  match %.2f%% - progress only, the tier is what gates (the old threshold was "
		"%.0f%%)" % (verdict.match_percent, verdict.threshold))
	lines.append("  %s  vs  %s" % (original_name, candidate_name))
	lines.append("  bytes %d vs %d (%+d)%s" % (verdict.original_bytes, verdict.candidate_bytes,
		verdict.size_delta_bytes, "  IDENTICAL" if verdict.bytes_equal else ""))
	fields = verdict.masked_byte_fields
	if verdict.bytes_comparable and (not verdict.bytes_equal or fields.get("original")
			or fields.get("candidate")):
		if not verdict.bytes_masked:
			lines.append("  bytes with the link-chosen fields zeroed: UNMASKED (no relocation "
				"fields were given, so every byte is compared)")
		elif not (fields.get("original") or fields.get("candidate")):
			lines.append("  no field of either body belongs to the link: every byte of it was "
				"compared")
		else:
			lines.append("  bytes with the fields the link writes zeroed on both sides (%d in the "
				"original, %d in the candidate: calls, jumps out of the body, pc-relative and "
				"absolute addresses): %s" % (fields.get("original", 0), fields.get("candidate", 0),
					"IDENTICAL" if verdict.bytes_equal_masked else
					"differ - " + verdict.byte_gap))
	lines.append("  instructions %d vs %d (%+d)  categories: %s" % (
		verdict.original_instructions, verdict.candidate_instructions, verdict.size_delta_instructions,
		", ".join("%s %d" % (name, verdict.categories[name]) for name in CATEGORIES)))
	if verdict.register_only:
		lines.append("  %d register differences are allocation only: with every register name "
			"folded to the order it first appears in, the two streams are identical, so the same "
			"operation happened in different registers" % verdict.register_only)
	elif verdict.categories["register"]:
		lines.append("  %d register differences are not allocation only: the streams still differ "
			"with registers folded, so the operands are paired differently" % verdict.categories[
				"register"])
	lines.append("  with registers folded: %s" % ("identical" if verdict.abstract_clean
		else _say(verdict.abstract_categories)))
	if verdict.bytes_equal and verdict.match_percent == 100.0:
		lines.append("  the candidate assembles to exactly the original bytes")
	elif verdict.bytes_equal_masked and verdict.match_percent == 100.0:
		lines.append("  the candidate assembles to the original bytes: every byte but the %d the "
			"link fills in matches"
			% (verdict.masked_byte_fields.get("candidate_bytes", 0)))
	if with_symbols and verdict.symbols:
		bad = [item for item in verdict.symbols if not item["ok"]]
		shown = bad[:max_symbols] + [item for item in verdict.symbols if item["ok"]][:
			max(0, max_symbols - len(bad))]
		if shown:
			lines.append("  symbols this function reaches (%d, differing first):" % len(verdict.symbols))
			for item in shown:
				left = (item["original"] or {}).get("name", "-")
				right = (item["candidate"] or {}).get("name", "-")
				lines.append("    %-6s %-34s %-34s %s" % (item["token"], "original: " + left,
					"candidate: " + right, "ok" if item["ok"] else "DIFFERS - " + item["why"]))
	hidden = sum(1 for item in verdict.diff if item.get("hidden"))
	if hidden:
		lines.append("  %d of those differences are only visible in what the lines reach, "
			"not in the lines" % hidden)
	if verdict.diff:
		lines.append("  differing instructions (%d%s):" % (len(verdict.diff),
			", %d hidden" % hidden if hidden else ""))
		for item in verdict.diff[:max_diff]:
			if item["original"] is not None:
				lines.append("    -%s  %s" % (_at(item["original_address"]), item["original"]))
			if item["candidate"] is not None:
				lines.append("    +%s  %s" % (_at(item["candidate_address"]), item["candidate"]))
			if item["why"]:
				lines.append("     ! %s: %s" % (item["category"], item["why"]))
		if len(verdict.diff) > max_diff:
			lines.append("    ... %d more differing instructions (raise --max-diff)"
				% (len(verdict.diff) - max_diff))
	else:
		lines.append("  no differing instructions")
	if verdict.warnings:
		lines += ["  note: %s" % warning for warning in verdict.warnings]
	if not verdict.passed:
		gaps = verdict.gaps(verdict.require)
		lines.append("  next: this unit reaches %s and the gate asks for %s - %s. (the categories "
			"and what they mean are in Skills/DecompileAnything.md; the percent is not what you are "
			"aiming at)" % (verdict.tier, verdict.require,
				"; ".join(gaps) if gaps else "nothing is categorised, so see the symbols above"))
	elif verdict.tier != "exact":
		lines.append("  next tier: %s - %s" % (TIERS[tier_rank(verdict.tier) + 1],
			"; ".join(verdict.gaps(TIERS[tier_rank(verdict.tier) + 1])) or "nothing"))
	return lines


def _at(address) -> str:
	return "%8s" % ("0x%x" % address if address is not None else "")
