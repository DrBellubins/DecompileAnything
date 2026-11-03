"""Align two instruction streams, score them, and say what kind of difference each is.

The percentage is only there to show how far off a candidate is. What the loop uses is the
category of each difference: an `opcode` difference means the operation is wrong, an
`operand` difference means the operation is right but an offset or constant is not, a
`register` difference is register allocation (Phase 5's problem, not the model's), a
`relocation` difference means the same shape of code reaches for a different function or
object, and `missing`/`extra` mean the control flow or size differs.

A unit counts as done at `match >= threshold` **and** no `opcode` and no `relocation`
differences (Docs/Design-Plan.md, Key Design Decisions): the ratio alone can be met by code
that does something else.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from .normalize import Ref, canonical_name, mask_registers

CATEGORIES = ("opcode", "operand", "register", "relocation", "missing", "extra")


@dataclass
class Verdict:
	passed: bool
	threshold: float
	match_percent: float
	categories: dict[str, int]
	diff: list[dict] = field(default_factory=list)
	symbols: list[dict] = field(default_factory=list)
	original_instructions: int = 0
	candidate_instructions: int = 0
	original_bytes: int = 0
	candidate_bytes: int = 0
	identical: bool = False
	bytes_equal: bool = False
	warnings: list[str] = field(default_factory=list)

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
# do two symbol tokens mean the same thing?


def refs_compatible(a: Ref, b: Ref) -> tuple[bool, str]:
	"""Conservative: a difference is only claimed when both sides have evidence.

	A name only counts against a candidate when both sides know a real name (an import, or a
	symbol of an unstripped target); bytes only count when both sides could read them; a size
	only counts when both sides know one. Anything unknown stays an accepted match, and the
	symbol table says so, rather than being guessed at.
	"""
	if a.cls != b.cls:
		return False, "%s on the original, %s in the candidate" % (a.kind, b.kind)
	if a.named and b.named and canonical_name(a.name) != canonical_name(b.name):
		return False, "reaches %s, the candidate reaches %s" % (a.name, b.name)
	if a.content and b.content:
		shared = min(len(a.content), len(b.content))
		if a.content[:shared] != b.content[:shared]:
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


def _difference(a, b) -> tuple[str, str]:
	"""The category of one differing line pair, and why."""
	if a.mnemonic != b.mnemonic:
		return "opcode", "%s vs %s" % (a.mnemonic, b.mnemonic)
	if mask_registers(a.text) == mask_registers(b.text):
		return "register", "same operation, different registers"
	paired = list(zip(a.refs, b.refs))
	if paired:
		for left, right in paired:
			ok, why = refs_compatible(left, right)
			if not ok:
				return "relocation", why
	return "operand", "operands differ"


def compare(original: list, candidate: list, vocabulary, *, threshold: float,
	original_bytes: bytes = b"", candidate_bytes: bytes = b"") -> Verdict:
	"""Score a candidate against the original."""
	left = [token.text for token in original]
	right = [token.text for token in candidate]
	matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
	matched = sum(block.size for block in matcher.get_matching_blocks())
	denominator = max(len(left), len(right), 1)
	percent = round(100.0 * matched / denominator, 2)

	categories = {name: 0 for name in CATEGORIES}
	diff: list[dict] = []
	for tag, i1, i2, j1, j2 in matcher.get_opcodes():
		if tag == "equal":
			continue
		if tag == "replace":
			for a, b in zip(original[i1:i2], candidate[j1:j2]):
				kind, why = _difference(a, b)
				categories[kind] += 1
				diff.append({"category": kind, "original": a.text, "candidate": b.text,
					"original_address": a.address, "candidate_address": b.address, "why": why})
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

	verdict = Verdict(
		passed=percent >= threshold and categories["opcode"] == 0 and categories["relocation"] == 0,
		threshold=float(threshold), match_percent=percent, categories=categories, diff=diff,
		symbols=symbols, original_instructions=len(left), candidate_instructions=len(right),
		original_bytes=len(original_bytes), candidate_bytes=len(candidate_bytes),
		identical=left == right, bytes_equal=bool(original_bytes) and original_bytes == candidate_bytes,
	)
	if not verdict.passed and not verdict.worst:
		verdict.warnings.append("below the threshold with no categorised difference - the "
			"streams are the same shape but not the same length")
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
	lines = ["match %.2f%% (threshold %.0f%%) %s" % (verdict.match_percent, verdict.threshold,
		"PASS" if verdict.passed else "FAIL")]
	lines.append("  %s  vs  %s" % (original_name, candidate_name))
	lines.append("  bytes %d vs %d (%+d)%s" % (verdict.original_bytes, verdict.candidate_bytes,
		verdict.size_delta_bytes, "  IDENTICAL" if verdict.bytes_equal else ""))
	lines.append("  instructions %d vs %d (%+d)  categories: %s" % (
		verdict.original_instructions, verdict.candidate_instructions, verdict.size_delta_instructions,
		", ".join("%s %d" % (name, verdict.categories[name]) for name in CATEGORIES)))
	if verdict.bytes_equal and verdict.match_percent == 100.0:
		lines.append("  the candidate assembles to exactly the original bytes")
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
		lines.append("  next: fix the %s differences above; a unit is done at >= %.0f%% with "
			"opcode 0 and relocation 0 (the categories and what they mean are in "
			"Skills/DecompileAnything.md)" % (verdict.worst or "size", verdict.threshold))
	return lines


def _at(address) -> str:
	return "%8s" % ("0x%x" % address if address is not None else "")
