"""One instruction stream -> one token stream, for both sides of a diff.

This is where the original and the candidate become comparable. Both sides are decoded with
the same capstone handle in AT&T syntax (what `objdump -d` prints), then every operand that
carries an *address* is replaced by a symbol token:

  branch inside the function      `jmp 0x10288d`   ->  `jmp L57`      (function-relative)
  call/jmp to something else      `callq 0x1068c0` ->  `SYM0` / `strlen`
  rip-relative or absolute data   `movl DAT(%rip)` ->  `DAT0(%rip)`

What a token means is recorded in a `Ref` and the two sides are compared through a shared
`Vocabulary`, so a difference in *which* function or object is referenced is reported as a
relocation difference rather than silently accepted because the address happened to line up.

Phase 1 used `capstone_for`/`decode` to store the original instruction stream in the cache.
Phase 2 adds the tokeniser on top; the decoder stays the same, so `decomp show` and
`decomp try` print the same instruction text.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from capstone import (
	CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_OP_IMM, CS_OP_MEM,
	CS_OPT_SYNTAX_ATT, Cs,
)
from capstone import x86 as csx86
from dataclasses import dataclass, field

# Ghidra language ids look like x86:LE:64:default.
_MODES = {"16": CS_MODE_16, "32": CS_MODE_32, "64": CS_MODE_64}

# capstone's x86 register id for %rip; a mem operand with this base is pc-relative.
_RIP = csx86.X86_REG_RIP


def capstone_for(language_id: str, detail: bool = False) -> Cs | None:
	"""A decoder for a Ghidra language id, or None when this arch is not supported yet.

	`detail` turns on capstone's operand structures, which the tokeniser needs to know which
	operand carries an address. It costs a little per instruction, so the analysis export
	leaves it off.
	"""
	parts = (language_id or "").split(":")
	if len(parts) < 3 or parts[0] != "x86":
		return None
	mode = _MODES.get(parts[2])
	if mode is None:
		return None
	if parts[1] != "LE":
		return None
	handle = Cs(CS_ARCH_X86, mode)
	handle.syntax = CS_OPT_SYNTAX_ATT
	handle.detail = bool(detail)
	return handle


def decode(handle: Cs, data: bytes, address: int) -> tuple[str, str, int] | None:
	"""Decode exactly one instruction at `address`: (mnemonic, operand text, length)."""
	for instruction in handle.disasm(data, address, count=1):
		return instruction.mnemonic, instruction.op_str, instruction.size
	return None


def format_instruction(mnemonic: str, operands: str) -> str:
	return ("%s %s" % (mnemonic, operands)).strip()


# --------------------------------------------------------------------------------------
# names: the rules both sides share, so "the same callee" reads as the same token


# Names invented by a tool (Ghidra, the assembler) carry no information the other side has,
# so they can never be compared by name - they become positional tokens instead.
_SYNTHETIC = (
	re.compile(r"^(FUN|DAT|LAB|s|u|x|ptr)_[0-9a-fA-F]{4,}$"),           # Ghidra, no symbol
	re.compile(r"^(PTR_|s_|u_).*_[0-9a-fA-F]{4,16}$"),                  # Ghidra, named data
	re.compile(r"^(switch|casegroup|block|switchcasegroup|thin|noextend)[_.]"),
	re.compile(r"^\.(L|LC|LFB|LFE|BB)"),                                # assembler locals
	re.compile(r"^\.text\.|^\.data\.|^\.bss\."),                        # section names as names
)

# `_ZN10CMathTests8AbsDiffEii+0x15`, `strlen@plt`, `foo@@GLIBC_2.2.5`, `.LC0-0x18`.
_ADDEND = re.compile(r"[-+](0x)?[0-9a-f]+$")
_AT = re.compile(r"@@?[A-Za-z0-9_.-]*$")


def demangle(names: list[str]) -> dict[str, str]:
	"""Mangled -> demangled, in one `c++filt` call. Falls back to the raw name."""
	need = sorted({name for name in names if name and name.startswith("_Z")})
	if not need:
		return {}
	if shutil.which("c++filt") is None:
		return {name: name for name in need}
	try:
		proc = subprocess.run(["c++filt"], input="\n".join(need), capture_output=True, text=True)
	except OSError:  # pragma: no cover
		return {name: name for name in need}
	lines = proc.stdout.splitlines()
	if len(lines) != len(need):
		return {name: name for name in need}
	return dict(zip(need, lines))


def simple_name(demangled: str) -> str:
	"""`CMathTests::AbsDiff(int, int)` -> `CMathTests::AbsDiff` (as Tests/eval.py does)."""
	text = re.sub(r"\s+(const|noexcept|volatile)\b.*$", "", demangled or "")
	paren = text.find("(")
	if paren > 0:
		text = text[:paren]
	return text.strip()


_clean_cache: dict[str, str] = {}


def clean_symbol(text: str) -> str:
	"""A symbol as a tool printed it -> the name to compare and show."""
	text = (text or "").strip()
	if not text:
		return ""
	if text in _clean_cache:
		return _clean_cache[text]
	name = _AT.sub("", _ADDEND.sub("", text))
	name = name.replace("@plt", "").replace("@PLT", "")
	if name.startswith("_Z"):
		name = simple_name(demangle([name]).get(name, name))
	_clean_cache[text] = name
	return name


def is_synthetic(name: str) -> bool:
	"""True when a name was invented by a tool and so cannot match across sides."""
	name = (name or "").strip()
	if not name:
		return True
	return any(pattern.match(name) for pattern in _SYNTHETIC)


def canonical_name(name: str) -> str:
	"""The comparison form of a real name: `CMathTests.AbsDiff(void*)` and
	`CMathTests::AbsDiff()` are the same callee spelled by two tools."""
	return re.sub(r"[^A-Za-z0-9]", "", clean_symbol(name) or "").lower()


# --------------------------------------------------------------------------------------
# decoded instructions, symbol references, tokens


@dataclass
class Ref:
	"""What one operand refers to, as understood on one side."""

	kind: str = "unknown"        # function | external | data | label | unknown
	raw: str = ""                # as the tool named it
	name: str = ""               # cleaned (demangled, no addend/@plt)
	address: int | None = None
	# The object a *name* identifies, when a name does: a vtable or a type_info reached at
	# different offsets is one object, and both sides have to count it as one (Phase 4).
	identity: str = ""
	section: str = ""
	size: int | None = None      # declared size in bytes when known
	content: bytes | None = None  # the bytes there, when it is meaningful to compare them

	@property
	def named(self) -> bool:
		"""A name both sides could have produced (imports, symbols of an unstripped target)."""
		return bool(self.name) and not is_synthetic(self.name)

	@property
	def cls(self) -> str:
		return "sym" if self.kind in ("function", "external") else "data"


@dataclass
class Slot:
	"""An operand position that carries an address, and what that address is."""

	operand: int                 # operand index, as capstone counts them
	kind: str                    # call | branch | imm | rip | abs
	value: int | None            # the address it encodes, when it can be computed
	enc_offset: int              # where the encoded field sits (for relocation matching)


@dataclass
class Instruction:
	address: int
	length: int
	mnemonic: str
	operands: str
	bytes: bytes = b""
	slots: list[Slot] = field(default_factory=list)


@dataclass
class Token:
	"""One instruction, post-substitution: the comparison text plus what it referenced."""

	text: str
	mnemonic: str
	address: int
	refs: list[Ref] = field(default_factory=list)


class Vocabulary:
	"""The token names for one diff, shared by both sides.

	A name that exists on both sides (an imported libc function, a symbol of an unstripped
	target) is used directly. Everything a tool invented is replaced by a positional token
	(`SYM0`, `DAT0`, ...) counted per side, and the `Ref` behind it is kept so `diff.py` can
	check that both tokens really mean the same thing.
	"""

	def __init__(self) -> None:
		self.entries: dict[str, list[tuple[str, Ref]]] = {"original": [], "candidate": []}
		self._tokens: dict[tuple[str, str, str], str] = {}
		# counted per side, so the n-th callee of the original and of the candidate meet at
		# the same token and `diff` can compare what they each mean
		self._next = {side: {"SYM": 0, "DAT": 0} for side in ("original", "candidate")}
		# ... and the same for registers, in --register-abstract mode: the k-th register this
		# side touches is r<k>, so two sides that made the same choice in different registers
		# meet, and one that made a different choice (a different operand pair) still differs
		self._registers: dict[str, dict[str, str]] = {side: {} for side in ("original", "candidate")}

	def register_name(self, side: str, register: str) -> str:
		"""This side's name for a register: first appearance wins, aliases of one register
		(%rax/%eax/%ax/%al) count as one, so a width-changing instruction is not hidden."""
		key = REGISTER_ALIASES.get(register, register)
		table = self._registers[side]
		if key not in table:
			table[key] = "r%d" % len(table)
		return table[key]

	def token_for(self, side: str, ref: Ref) -> str:
		"""A positional token per side: the n-th function this body calls, the n-th object it
		reads. Names are not used as the token because one side usually has one and the other
		does not (a stripped binary vs a `.o`); they are kept in the `Ref` and compared by
		`diff.refs_compatible`, which only claims a difference when both sides have evidence."""
		prefix = "SYM" if ref.cls == "sym" else "DAT"
		# keyed by the address where one exists: a side may name a whole array while the
		# other names each element inside it, and they have to meet element by element. An
		# object a name identifies wins over that: reading `vtable+16` and `vtable+40` is
		# reading one object twice, and the other side may only ever name the symbol.
		key = (ref.identity or (("0x%x" % ref.address) if ref.address is not None
			else (ref.raw or ref.name or "?")))
		cached = self._tokens.get((side, prefix, key))
		if cached:
			return cached

		token = "%s%d" % (prefix, self._next[side][prefix])
		self._next[side][prefix] += 1
		self._tokens[(side, prefix, key)] = token
		self.entries[side].append((token, ref))
		return token


# --------------------------------------------------------------------------------------
# decoding a function body, with the instruction boundaries either side really has


def decode_function(handle: Cs, base: int, data: bytes,
	boundaries: list[tuple[int, int]] | None = None,
	extents: list[tuple[int, int]] | None = None) -> list[Instruction]:
	"""Decode a function body.

	`boundaries` = [(address, length), ...] to honour - the original side passes the
	instruction boundaries from the analysis cache, which are Ghidra's and match how
	`decomp show` prints the same function. Without them the bytes are swept linearly, which
	is what a `.o` gives.

	`extents` = [(address, length), ...], the blocks `data` is made of, in the order they are
	compared (entry block first, a -O2 cold partition second). Without it `data` is one block
	starting at `base`. Each block is decoded in its own address domain, and the streams are
	concatenated in that order - which is how the same split in the candidate's `.o`
	(`.text` then `.text.unlikely`) lines up with it.
	"""
	if not extents:
		extents = [(base, len(data))]
	out: list[Instruction] = []
	offset = 0
	for address, length in extents:
		chunk = data[offset:offset + length]
		offset += length
		if chunk:
			out.extend(_decode_block(handle, address, chunk, boundaries))
	return out


def _decode_block(handle: Cs, base: int, data: bytes,
	boundaries: list[tuple[int, int]] | None = None) -> list[Instruction]:
	out: list[Instruction] = []
	if boundaries:
		for address, length in boundaries:
			offset = address - base
			if offset < 0 or offset + length > len(data):
				continue
			chunk = data[offset:offset + length]
			decoded = _decode_one(handle, chunk, address)
			if decoded is not None:
				out.append(decoded)
		if out:
			return _fill_gaps(handle, data, base, out)
	for instruction in handle.disasm(data, base):
		out.append(_instruction(handle, instruction))
	return out


def _fill_gaps(handle: Cs, data: bytes, base: int, known: list[Instruction]) -> list[Instruction]:
	"""Decode any bytes the given boundaries did not cover.

	Two ways to get them: a `--size` re-cut at -O2, or a unit of the file's own function table
	(Docs/MSVC-Plan.md MS-1), whose extent includes bytes the analysis left out of its ranges -
	alignment padding, a jump table, a tail block. Whatever they decode to, they are compared: an
	invention here shows up as `extra` in the diff rather than going unmeasured. Capstone's own
	instruction objects are converted to this module's, since that is what the caller walks.
	"""
	covered = [(item.address, item.length) for item in known]
	extra: list[Instruction] = []
	address = base
	end = base + len(data)
	while address < end:
		gap_start = address
		for start, length in covered:
			if start <= address < start + length:
				address = start + length
				break
		else:
			stop = min([start for start, _ in covered if start > address] + [end])
			for item in handle.disasm(data[address - base:stop - base], address):
				decoded = _decode_one(handle, data[item.address - base:stop - base], item.address)
				if decoded is None:
					address = item.address + max(item.size, 1)
					continue
				extra.append(decoded)
				address = item.address + max(item.size, 1)
			address = max(address, gap_start + 1)
	known.extend(extra)
	known.sort(key=lambda item: item.address)
	return known


def _decode_one(handle: Cs, chunk: bytes, address: int) -> Instruction | None:
	for instruction in handle.disasm(chunk, address, count=1):
		return _instruction(handle, instruction)
	return None


def _instruction(handle: Cs, instruction) -> Instruction:
	out = Instruction(address=instruction.address, length=instruction.size,
		mnemonic=instruction.mnemonic, operands=instruction.op_str,
		bytes=bytes(instruction.bytes))
	out.slots = _slots(handle, instruction)
	return out


_BRANCH = re.compile(r"^(j[a-z]{0,3}|loop[a-z]*|call[a-z]*|jmp|ret)$")


def _slots(handle: Cs, instruction) -> list[Slot]:
	"""Which operands carry an address, and what address they encode."""
	slots: list[Slot] = []
	if not handle.detail:  # the analysis export decodes without detail
		return slots
	mnemonic = instruction.mnemonic
	control = bool(_BRANCH.match(mnemonic))
	is_call = mnemonic.startswith("call") or mnemonic.startswith("jmp")
	for index, operand in enumerate(instruction.operands):
		if operand.type == CS_OP_MEM:
			mem = operand.mem
			if mem.base == _RIP:
				# capstone prints the raw displacement; the address it means is here:
				value = instruction.address + instruction.size + mem.disp
				slots.append(Slot(index, "rip", value, instruction.size - 4))
			elif mem.base == 0 and (mem.index == 0 or mem.disp):
				# absolute addressing (32-bit code) and `*table(, %rax, 4)` jump tables
				slots.append(Slot(index, "abs", mem.disp, instruction.size - 4))
		elif operand.type == CS_OP_IMM and control:
			kind = "call" if is_call else "branch"
			slots.append(Slot(index, kind, operand.imm, 1))
		elif operand.type == CS_OP_IMM:
			# An immediate can carry a relocation: in a non-PIE 32-bit object `pushl $0` is
			# `pushl $_ZTI14CVehicleEntity` with an R_386_32 sitting on the four bytes, and
			# before the link the value is 0. Low-address immediates in position-dependent code
			# are relocated addresses for the same reason high ones are. These slots are last in
			# line when relocations are paired with operands, so a memory operand still wins.
			slots.append(Slot(index, "imm", operand.imm, instruction.size - 4))
	return slots


# --------------------------------------------------------------------------------------
# the tokeniser


_LITERAL = re.compile(r"-?(?:0x[0-9a-f]+|\d+)")
_REGISTER = re.compile(
	r"\b(e[a-d]x|[a-d][sl][pi]|r[abcd]x|r\d{1,2}[wdb]?|sip|dil|sil|bpl|spl|al|cl|dl|bl|"
	r"xmm\d+|ymm\d+|st\(\d\)|mm\d+)\b")

# The same physical register under its widths: abstracting a register *choice* must not also
# abstract away the width an instruction works at, or `movl %eax, %edx` and `movq %rax, %rdx`
# would read as the same operation.
_GPR_WIDTHS = [("rax", "eax", "ax", "al", "ah"), ("rbx", "ebx", "bx", "bl", "bh"),
	("rcx", "ecx", "cx", "cl", "ch"), ("rdx", "edx", "dx", "dl", "dh"),
	("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
	("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl")] + [
	("r%d" % index, "r%dd" % index, "r%dw" % index, "r%db" % index)
	for index in range(8, 16)]
REGISTER_ALIASES = {alias: base for base, *others in _GPR_WIDTHS for alias in [base] + others}


def _operand_spans(operands: str) -> list[tuple[int, int]]:
	"""Split capstone's AT&T operand text into operand spans (commas inside a memory
	operand - `-0x10(%rdi, %rax, 8)` - do not separate operands)."""
	spans: list[tuple[int, int]] = []
	start = 0
	depth = 0
	index = 0
	text = operands
	for position, char in enumerate(text):
		if char in "([":
			depth += 1
		elif char in ")]":
			depth = max(0, depth - 1)
		elif char == "," and depth == 0 and index + 1 < len(text) and text[index + 1] == " ":
			spans.append((start, position))
			start = position + 2
		index += 1
	if text.strip():
		spans.append((start, len(text)))
	return spans


def normalize_function(vocab: Vocabulary, side: str, instructions: list[Instruction],
	bind, base: int, size: int, register_abstract: bool = False,
	extents: list[tuple[int, int]] | None = None) -> list[Token]:
	"""Tokenise one function.

	`bind(instruction) -> {operand index: Ref}` says what each address operand refers to:
	the original side answers from the analysis cache's resolved references, the candidate
	side from the `.o`'s relocation entries. That is the only difference between the sides.

	A branch inside the unit becomes `L<offset>`, the offset being the target's position in the
	bytes being compared (`extents`) rather than a raw address: a unit whose cold half was
	linked into another part of `.text`, and a candidate whose cold half sits in
	`.text.unlikely`, then agree on the same label for the same edge.
	"""
	blocks = list(extents) if extents else [(base, size)]

	def position_of(value: int) -> int | None:
		cursor = 0
		for start, length in blocks:
			if start <= value < start + length:
				return cursor + (value - start)
			cursor += length
		return None

	tokens: list[Token] = []
	for instruction in instructions:
		bound = bind(instruction) or {}
		operands = instruction.operands
		spans = _operand_spans(operands)
		refs: list[Ref] = []
		# rewrite from the last operand backwards so earlier offsets stay valid
		for slot in sorted([slot for slot in instruction.slots if slot.operand < len(spans)],
			key=lambda slot: -slot.operand):
			ref = bound.get(slot.operand)
			start, stop = spans[slot.operand]
			text = operands[start:stop]
			# Where does this operand really point? On the original side the analysis answers;
			# on the candidate side an unrelocated `call` in a `.o` encodes a displacement of 0
			# (the link fills it in), so its encoded value is the next instruction and only the
			# relocation behind the reference says where it goes.
			target = ref.address if (ref is not None and ref.address is not None) else slot.value
			here = position_of(target) if target is not None else None
			replacement = None
			if here is not None and slot.kind in ("branch", "call") and (
					ref is None or ref.kind != "external"):
				# a jump or call that lands inside this unit is an edge inside the unit, not a
				# symbol: made relative to the start of the unit, so a moved function or a
				# different link address does not read as a change, a body in two blocks reads the
				# same on both sides, and a self-recursive call reads as a call to a label on both.
				# What the analysis happened to call the target does not matter: a tail jump to an
				# address the file puts *inside this unit* is inside it, however many functions the
				# disassembler drew there - and the candidate's own body agrees by jumping to it
				replacement = "L%x" % here
			elif ref is not None:
				replacement = vocab.token_for(side, ref)
				refs.append(ref)
			if replacement is None:
				continue
			match = _LITERAL.search(text)
			if match is not None:
				operands = (operands[:start + match.start()] + replacement
					+ operands[start + match.end():])
			elif slot.kind in ("rip", "abs"):
				# capstone writes a zero displacement as nothing: `movss (%rip), %xmm0` is
				# what a relocation-backed reference looks like before the link
				operands = operands[:start] + replacement + operands[start:]
		text = format_instruction(instruction.mnemonic, operands.strip())
		if register_abstract:
			text = _REGISTER.sub(lambda match: "{" + vocab.register_name(side, match.group(0))
				+ "}", text)
		tokens.append(Token(text=text, mnemonic=instruction.mnemonic, address=instruction.address,
			refs=refs))
	return tokens


def mask_registers(text: str) -> str:
	"""The token with every register replaced by a placeholder - two lines that differ only
	after this are a register-allocation difference, not a different operation."""
	return _REGISTER.sub("{r}", text)


def symbols(text: str) -> list[str]:
	"""The symbol tokens used by one line (SYM0, DAT1, an external name, a branch label)."""
	return re.findall(r"\b(SYM\d+|DAT\d+|L[0-9a-f]+)\b", text)
