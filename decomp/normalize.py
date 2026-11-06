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


# --------------------------------------------------------------------------------------
# MSVC names: decorations, and the RTTI objects a decoration identifies
#
# A PE has no symbol table, so the only names an MSVC target carries for its vtables and type
# descriptors are the decorated symbols a *candidate's* `.obj` relocates against
# (`??_R0?AVCVehicleEntity@@@8`, `??_7CVehicleEntity@@6B@`). Those decorations say exactly what
# the object is, and MSVC's RTTI in the target says the same thing from the data side
# (`.?AVCVehicleEntity@@`, an RTTICompleteObjectLocator). Reading both into the words c++filt
# already gives for Itanium names - "typeinfo for X", "vtable for X" - is what lets one object
# be named on both sides (Docs/MSVC-Plan.md MS-5).

# A type name as MSVC's RTTI writes it: `.?AVCEntityBase@@`, `.?AUSimpleMapping@hkaBone@@`,
# `.?AV?$hkSingleton@VhkReferencedObject@@`. V = class, U = struct (a unique tag), E = enum.
_MSVC_TYPE = re.compile(r"^\.?\?A([VUE])(.{1,300}?)@@$")
# The same encoding inside a decorated symbol name.
_MSVC_TYPE_ANYWHERE = re.compile(r"\?A([VUE])(.{1,300}?)@@")
_MSVC_RTTI_SYMBOL = re.compile(r"^\?\?_R([0-4])")
# `??_7X@@6B@` is a vftable, `??_8` a vbtable, `??_9` a vftable closure.
_MSVC_TABLE_SYMBOL = re.compile(r"^\?\?_([789])([A-Za-z0-9_$?@.]+)@@")

_MSVC_RTTI_WORDS = {
	"0": "typeinfo",                    # ??_R0 = RTTITypeDescriptor
	"1": "complete object locator",     # ??_R1 = RTTICompleteObjectLocator
	"2": "base class array",            # ??_R2 = RTTIBaseClassArray
	"3": "class hierarchy descriptor",  # ??_R3 = RTTIClassHierarchyDescriptor
	"4": "base class descriptor",       # ??_R4 = RTTIBaseClassDescriptor
}
_MSVC_TABLE_WORDS = {"7": "vtable", "8": "vbtable", "9": "vftable closure"}


def msvc_type_name(text: str) -> tuple[str, str]:
	"""`.?AUSimpleMapping@hkaSkeletonMapper@@` -> ('struct', 'hkaSkeletonMapper::SimpleMapping').

	MSVC writes a nested name innermost-first with `@` between the components, so the components
	are reversed. A template argument list (`?$hkSingleton@V…`) is not a scope chain, and there
	it is shown as written rather than invented into one.
	"""
	match = _MSVC_TYPE.match((text or "").strip())
	if not match:
		return "", ""
	kind = {"V": "class", "U": "struct", "E": "enum"}.get(match.group(1), "")
	encoded = match.group(2)
	if not encoded:
		return kind, ""
	parts = encoded.split("@")
	if any(not part or part.startswith(("$", "?")) for part in parts):
		return kind, encoded
	return kind, "::".join(reversed(parts))


def msvc_object_name(text: str) -> str:
	"""An MSVC RTTI or vftable symbol -> "typeinfo for X" / "vtable for X" ('' for anything
	else, including an ordinary decorated function name, which stays the decorated name)."""
	text = (text or "").strip()
	match = _MSVC_RTTI_SYMBOL.match(text)
	if match:
		words = _MSVC_RTTI_WORDS.get(match.group(1), "")
		name = ""
		if match.group(1) in ("1", "2"):
			# the locator and partial-locator symbols put four fixed numbers between the record
			# kind and the class name: `??_R1A@?0A@EA@CVehicleEntity@@8`
			fields = re.match(r"^\?\?_R[12][A-Z][A-Z0-9?@-]*@([A-Za-z_?][^@]*)@@\d*$", text)
			name = fields.group(1) if fields else ""
		else:
			inner = _MSVC_TYPE_ANYWHERE.search(text)
			if inner is not None:
				_name, name = msvc_type_name("." + inner.group(0))
		return "%s for %s" % (words, name) if words and name else ""
	table = _MSVC_TABLE_SYMBOL.match(text)
	if table:
		words = _MSVC_TABLE_WORDS.get(table.group(1), "")
		_kind, name = msvc_type_name(".?AV%s@@" % table.group(2))
		return "%s for %s" % (words, name) if words and name else ""
	return ""


def msvc_type_symbol(role: str, encoded: str) -> str:
	"""The reverse: the decorated name of one of those objects, as the `.obj` would write it.

	`encoded` is the name exactly as the type descriptor's own string carries it
	(`.?AVCVehicleEntity@@`), which is what the symbol embeds after the `??_R<kind>` prefix.
	"""
	body = (encoded or "").lstrip(".")
	if not body:
		return ""
	if role == "typeinfo":
		return "??_R0%s@8" % body
	if role == "vtable":
		_kind, name = msvc_type_name(encoded)
		return "??_7%s@@6B@" % name.replace("::", "@") if name else ""
	return ""


_clean_cache: dict[str, str] = {}


def clean_symbol(text: str) -> str:
	"""A symbol as a tool printed it -> the name to compare and show."""
	text = (text or "").strip()
	if not text:
		return ""
	if text in _clean_cache:
		return _clean_cache[text]
	if text.startswith("??_"):
		# before any of the addend/`@` trimming: an MSVC RTTI name ends in `@@8`, which that
		# trimming would eat, and the decoration itself is what says what the object is
		object_name = msvc_object_name(text)
		if object_name:
			_clean_cache[text] = object_name
			return object_name
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
# how wide an access is, read off the instruction that makes it
#
# The size a memory operand is read at is the last piece of evidence available for a constant in
# a merged `.rodata.cst*` pool: the pool's extent is the linker's arrangement of several values,
# so two windows out of it are not the same object twice - but the four bytes `movss SYM(%rip)`
# reads *are* that constant, and so is the eight of a `movsd`. Same for a jump-table slot
# (`mov 0x0(,%rax,4),%eax` reads four bytes) and for a narrow field (`movzbl` reads one).

# How wide one access is, from the mnemonic where the size is written in it.
_SUFFIX_WIDTH = {"b": 1, "w": 2, "l": 4, "q": 8}


def register_width(name: str) -> int:
	"""`%rax`->8, `%eax`->4, `%ax`->2, `%al`->1, `%xmm0`->16. A bare `mov` says its size only
	in the register it moves to."""
	name = (name or "").lower()
	if name.startswith(("xmm", "zmm")):
		return 16
	if name.startswith("ymm"):
		return 32
	if name.startswith("st"):
		return 10
	if re.fullmatch(r"r[abcd]x|r\d{1,2}[wbl]?|r(?:[sd][ip]|[b-s][p])l?", name):
		return 8
	if re.fullmatch(r"e[abcd][sd]x|e[ds][ip]|ebp|esp", name):
		return 4
	if re.fullmatch(r"[a-d][xl]p?|[ds]i|[b-s]p", name):
		return 2
	if re.fullmatch(r"[a-d]l|ah|bh|ch|dh|[sd]il|[b-s]pl", name):
		return 1
	return 0


def access_width(mnemonic: str, operands, handle) -> int:
	"""How many bytes this instruction touches, 0 when it does not say.

	`structures` uses this to lay out a class's fields; the tokeniser records it on every address
	operand so `diff` can compare the bytes an access actually reads (Phase 4).
	"""
	suffix = ""
	for key in sorted(_SUFFIX_WIDTH, key=lambda k: -len(k)):
		if mnemonic.endswith(key) and mnemonic != key:
			suffix = key
			break
	if mnemonic.startswith(("movs", "movz")):
		pair = [c for c in mnemonic[4:] if c in _SUFFIX_WIDTH]
		if pair:
			return min(_SUFFIX_WIDTH[c] for c in pair)
	if suffix:
		return _SUFFIX_WIDTH[suffix]
	if mnemonic.endswith("ss"):
		return 4
	if mnemonic.endswith("sd"):
		return 8
	if mnemonic.startswith(("movaps", "movups", "movapd", "movupd")):
		return 16
	if mnemonic.startswith(("fld", "fst")):
		# flds/fsts are the 32-bit x87 spellings of a float, fldl/fstl of a double
		return 4 if mnemonic.endswith("s") else 8 if mnemonic.endswith("l") else 8
	# a bare `mov`/`add`/... : the size is in the register on the other side
	from capstone import CS_OP_REG
	for operand in operands:
		if operand.type == CS_OP_REG:
			width = register_width(handle.reg_name(operand.reg))
			if width:
				return width
	return 0


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
	# How wide the access this reference came out of is (`access_width`, from the mnemonic or the
	# register it writes). For a constant in a `.rodata.cst` pool this is the only evidence that
	# two sides read the same thing: the pool's extent is the linker's arrangement of several
	# constants, but the four bytes *this* instruction reads are the constant (Phase 4).
	width: int | None = None
	# A string this side knows the length of, in bytes without the terminator: on the original
	# side, the cached string record. It is what makes a string literal comparable at all - the
	# length says how many bytes to read, and the candidate side reads to its NUL (Phase 4).
	string: int | None = None

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
	width: int = 0               # what the instruction touches there, 0 when it does not say


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
		# What the match ledger already knows (Phase 5): {"0x…": token} for the entities a unit that
		# passed the gate already reproduced. Keyed by the entity's address in the original's
		# addresses, which is what the ledger is keyed by - and by the candidate symbol the ledger
		# pairs it with, because a candidate's own call reaches that name, not that address.
		self._from_ledger: dict[str, str] = {}
		self._by_ledger_name: dict[tuple[str, str], str] = {}

	def seed_ledger(self, rows) -> None:
		"""Give the callees the match ledger knows the same token in every unit (Phase 5).

		`rows` = the ledger's rows, in the order the pairs were proven. Without this the token for a
		callee is its position in whichever body is being compared now, so `SYM3` in one unit and
		`SYM3` in the next name unrelated things, and nothing the loop learned about one function
		carries over to the next. With it, "the helper `main` calls twice" has a name the loop can
		refer to - in a report, in the ledger, and in the next unit's symbol table.

		Both sides take it from the same numbering: the original reaches the entity at its address,
		the candidate reaches it by the symbol the ledger recorded, and those two have to meet at one
		token or the symbol table is two columns of unrelated names again.

		Only callees - a `function` or `external` row. Data is deliberately left to the positional
		counting and the identity merge above, because the ledger cannot key an object both sides
		agree on: it stores one candidate *name*, and what the candidate actually reads is an offset
		in a merged `.rodata` pool or one element of an array, which carries no key back to the
		original's address. Keying the original's side by address and the candidate's by position
		moves the numbers apart and mis-pairs constants that the byte comparison was already getting
		right (measured on the benchmark: MATH-24 and MATH-29, whose pool constants met at the right
		width before). A data row still counts as *evidence* in `diff.ref_evidence` once a pair is
		formed; it just does not name the token.
		"""
		for row in rows or ():
			entry = row.get("entry")
			if entry is None or row.get("kind") not in ("function", "external"):
				continue
			key = "0x%x" % int(entry)
			if key in self._from_ledger:
				continue
			prefix = "SYM"
			# numbered ahead of whatever either side has already counted, so a seeded token can never
			# collide with a positional one handed out later
			token = "%s%d" % (prefix, max(self._next["original"][prefix], self._next["candidate"][prefix]))
			self._next["original"][prefix] = self._next["candidate"][prefix] = int(token[len(prefix):]) + 1
			self._from_ledger[key] = token
			name = canonical_name(row.get("candidate") or "")
			if name:
				self._by_ledger_name.setdefault((prefix, name), token)

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
		# An entity the ledger already has a name for keeps the token the ledger gave it: the pair
		# was proven once, and renumbering it per body is what stops a target being described as
		# one set of things (Phase 5). The identity merge above still comes first - reading
		# `vtable+16` and `vtable+40` is one object, whichever of the two the ledger happens to know.
		seeded = self._from_ledger.get("0x%x" % ref.address) if ref.address is not None else None
		if seeded is None and ref.name and not (ref.identity and not ref.identity.startswith("symbol:")):
			# the candidate reaches its own helpers by name, not by the original's addresses. Only a
			# name that *is* the object counts: a reference resolved to an offset in a section
			# (`.rodata+0x280`) is named there by whatever symbol sits nearest before it, and that
			# guess must not be read as a claim about an entity the ledger already has a name for.
			seeded = self._by_ledger_name.get((prefix, canonical_name(ref.name)))
		token = seeded or "%s%d" % (prefix, self._next[side][prefix])
		if not seeded:
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
	"""Which operands carry an address, and what address they encode.

	`enc_offset` is where the field is expected to sit, read from the instruction's length: the
	last four bytes for a displacement or immediate, one past the opcode for a branch. That is a
	convention, not a decoding - it is wrong for a `0f 8x` conditional jump and for an instruction
	with an immediate after its displacement (`cmpb $0, x(%rip)`) - so `field_span` treats it as a
	starting point and checks it against the bytes before anything is masked on its authority.
	"""
	slots: list[Slot] = []
	if not handle.detail:  # the analysis export decodes without detail
		return slots
	mnemonic = instruction.mnemonic
	control = bool(_BRANCH.match(mnemonic))
	is_call = mnemonic.startswith("call") or mnemonic.startswith("jmp")
	# How wide this instruction's access is, recorded on every slot so whichever side builds a `Ref`
	# out of it can carry the width forward: the width of the read is what makes a pooled constant
	# comparable (Phase 4).
	touching = access_width(mnemonic, instruction.operands, handle)
	for index, operand in enumerate(instruction.operands):
		if operand.type == CS_OP_MEM:
			mem = operand.mem
			if mem.base == _RIP:
				# capstone prints the raw displacement; the address it means is here:
				value = instruction.address + instruction.size + mem.disp
				slots.append(Slot(index, "rip", value, instruction.size - 4, touching))
			elif mem.base == 0 and (mem.index == 0 or mem.disp):
				# absolute addressing (32-bit code) and `*table(, %rax, 4)` jump tables
				slots.append(Slot(index, "abs", mem.disp, instruction.size - 4, touching))
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
			text = abstract_registers(text, vocab, side)
		tokens.append(Token(text=text, mnemonic=instruction.mnemonic, address=instruction.address,
			refs=refs))
	return tokens


# --------------------------------------------------------------------------------------
# the fields an instruction leaves for the link
#
# A body's bytes are not all evidence about the source. The bytes of a `call`, a pc-relative
# load or a 32-bit absolute address are whatever the *link* decided: in a `.o` they are
# placeholders a relocation record describes, in a linked file they are final displacements that
# depend on where everything was placed. Zeroing exactly those fields on both sides is what
# makes "the candidate assembles to the original bytes" a claim that can be true (and only
# those: a short jump and a rel32 jump say the same thing symbolically and are different bytes,
# and that difference belongs to the candidate).

_FIELD_WIDTHS = (1, 2, 4, 8)


def body_blocks(extents: list[tuple[int, int]] | None, base: int, size: int) -> list[tuple[int, int, int]]:
	"""(start, length, offset in the concatenated body) for each block of a body.

	The same split `decode_function` and `normalize_function` walk, in one place: the entry block
	first, then a -O2 cold partition. An address outside every block belongs to no body.
	"""
	blocks: list[tuple[int, int, int]] = []
	cursor = 0
	for start, length in (extents or [(base, size)]):
		blocks.append((int(start), int(length), cursor))
		cursor += int(length)
	return blocks


def block_of(blocks: list[tuple[int, int, int]], address: int):
	"""The block an address falls in, or None."""
	for block in blocks:
		if block[0] <= int(address) < block[0] + block[1]:
			return block
	return None


def _encodes(field: bytes, expected: int, width: int | None = None) -> bool:
	"""Do these bytes say this number? (two's complement, little endian)

	`width` is the field's width in bytes; without it the bytes handed in are taken to be exactly
	the field. Pass it when looking for a field inside a longer run of bytes.
	"""
	if not field:
		return False
	if width is not None:
		if len(field) < width:
			return False
		field = field[:width]
	mask = (1 << (8 * len(field))) - 1
	return (int.from_bytes(field, "little") & mask) == (int(expected) & mask)


def field_span(instruction, slot) -> tuple[int, int] | None:
	"""Where in an instruction the address an operand carries sits, and how wide it is.

	`Slot.enc_offset` is where that field was read from, and is the starting point. It is a
	convention though, not a fact about the encoding: `_slots` uses offset 1 for a branch or call,
	which is right for `e8`/`e9` and wrong for a `0f 8x` conditional jump, whose rel32 starts two
	bytes in. So the recorded offset is *checked* by decoding the bytes it points at against the
	address the slot recorded, and the field is located by decoding instead when it does not
	reproduce it (the rel8/rel16/rel32 of a branch is always the trailing bytes).
	"""
	data = bytes(instruction.bytes or b"")
	length = int(instruction.length or len(data))
	if not data or len(data) != length or slot.value is None:
		return None            # no bytes to mask: a stream built from text alone
	# What the field has to contain. A pc-relative or branch operand says how far away the target
	# is, measured from the end of the instruction; an absolute or immediate one says the address.
	if slot.kind in ("rip", "call", "branch"):
		expected = int(slot.value) - (int(instruction.address) + length)
	else:
		expected = int(slot.value)
	# the recorded offset first, then the widest trailing field (an unrelocated `call 0` in a `.o`
	# also "matches" as a one-byte zero if the short forms are tried first), then any other field
	# of the width that form always has
	order = [(slot.enc_offset, length - slot.enc_offset)]
	if slot.kind in ("rip", "abs"):
		# a pc-relative or absolute displacement is a fixed 4-byte field wherever the encoding puts
		# it: `cmpb $0, x(%rip)` is `80 3d disp32 00`, with the immediate after the displacement,
		# so the trailing-bytes rule would miss it
		order += [(offset, 4) for offset in range(1, length - 3)]
	else:
		order += sorted([(length - width, width) for width in _FIELD_WIDTHS
			if 0 < length - width < length])
		order += [(offset, width) for width in _FIELD_WIDTHS
			for offset in range(1, length - width + 1) if 0 < offset]
	for offset, width in order:
		if offset <= 0 or width not in _FIELD_WIDTHS or offset + width > length:
			continue
		if _encodes(data[offset:], expected, width):
			return offset, width
	return None


def position_dependent(instruction, slot, ref, block) -> bool:
	"""Does this operand's field depend on where things were linked, i.e. must both sides hide it?

	The rule is the same on both sides, so a field is only hidden when *both* would have written
	something different there. It is symmetric by construction: a `.o` leaves a field for the link
	exactly when the operand reaches outside the body it sits in, and a linked file has the value
	the linker chose there. The one case that is not visible from the bytes alone is a call to a
	function - including a self-recursive one - whose entry happens to be inside the body: the
	object file still relocates it, so what the analysis called the target decides (a reference to
	a function or an import is a symbol; a jump to an interior label of this body is not).
	"""
	if slot.kind in ("rip", "abs"):
		# a pc-relative or absolute address is the linker's choice wherever it appears
		return True
	if slot.kind == "imm":
		# an immediate is a constant unless something resolves it to an object: in a non-PIE
		# 32-bit object `pushl $_ZTI14CVehicleEntity` is an R_386_32 sitting on an immediate
		return ref is not None
	start, length, _cursor = block
	target = ref.address if (ref is not None and ref.address is not None) else slot.value
	if target is None:
		return True
	if not (start <= int(target) < start + length):
		return True            # another function, an object, or the other half of this body
	return bool(ref is not None and ref.kind in ("function", "external"))


def address_fields(blocks: list[tuple[int, int, int]], instructions: list, bind) -> list[tuple[int, int]]:
	"""The (offset, width) pairs of a concatenated body where an operand leaves an address.

	`bind` is the same function the tokeniser is given, so a field is hidden on exactly the
	operands that were tokenised as references. Offsets are in the concatenated body, per extent,
	which is what `Function.bytes` is indexed by.
	"""
	fields: list[tuple[int, int]] = []
	for instruction in instructions:
		block = block_of(blocks, instruction.address)
		if block is None:
			continue
		bound = bind(instruction) or {}
		for slot in instruction.slots:
			ref = bound.get(slot.operand)
			if not position_dependent(instruction, slot, ref, block):
				continue
			span = field_span(instruction, slot)
			if span is None:
				continue
			offset, width = span
			fields.append((block[2] + (int(instruction.address) - block[0]) + offset, width))
	return sorted(fields)


def merge_fields(primary, *more) -> list[tuple[int, int]]:
	"""One sorted, non-overlapping field list out of several. Earlier groups win: a byte an
	earlier group already covers is not extended by a later one.

	For a candidate that is the relocation table first (it states the exact offset and width), and
	the decoder's fields second - which is what adds the calls to a helper in the same section that
	a `.o` resolves without a relocation record.
	"""
	spans: list[tuple[int, int]] = []
	covered: set[int] = set()
	for group in (primary, *more):
		for offset, width in sorted((item for item in group if int(item[1]) > 0)):
			if any(step in covered for step in range(int(offset), int(offset) + int(width))):
				continue
			covered.update(range(int(offset), int(offset) + int(width)))
			spans.append((int(offset), int(width)))
	return sorted(spans)


def mask_body(data: bytes, fields: list[tuple[int, int]]) -> bytes:
	"""A body with the given (offset, width) ranges set to zero."""
	out = bytearray(data)
	for offset, width in fields:
		for step in range(int(width)):
			if 0 <= offset + step < len(out):
				out[offset + step] = 0
	return bytes(out)


def body_index(blocks: list[tuple[int, int, int]], instructions: list, tokens: list) -> dict[int, str]:
	"""Every byte offset of a body -> the instruction it falls in, for byte-level reports."""
	by_address = {int(token.address): token for token in tokens}
	out: dict[int, str] = {}
	for instruction in instructions:
		block = block_of(blocks, instruction.address)
		if block is None:
			continue
		token = by_address.get(int(instruction.address))
		text = (token.text if token is not None else format_instruction(
			instruction.mnemonic, instruction.operands))
		label = "0x%x  %s" % (int(instruction.address), text)
		start = block[2] + (int(instruction.address) - block[0])
		for step in range(int(instruction.length)):
			out[start + step] = label
	return out


def abstract_registers(text: str, vocab: Vocabulary, side: str) -> str:
	"""One line with each register name replaced by this side's name for it (first appearance
	wins): `movl %eax, %ecx` and `movl %r9d, %r8d` become the same line, `movl %eax, %edx`
	does not. `diff.compare` runs a whole stream through this on every comparison, which is how
	an allocation difference is told from a different pairing of operands."""
	return _REGISTER.sub(lambda match: "{" + vocab.register_name(side, match.group(0)) + "}", text)


def register_names(text: str) -> list[str]:
	"""The register names in a line, in the order they appear - positionwise comparable, so a
	line that pairs its registers up differently can be told from one that renamed them."""
	return [match.group(0) for match in _REGISTER.finditer(text)]


def mask_registers(text: str) -> str:
	"""The token with every register replaced by a placeholder - two lines that differ only
	after this are a register-allocation difference, not a different operation."""
	return _REGISTER.sub("{r}", text)


def symbols(text: str) -> list[str]:
	"""The symbol tokens used by one line (SYM0, DAT1, an external name, a branch label)."""
	return re.findall(r"\b(SYM\d+|DAT\d+|L[0-9a-f]+)\b", text)
