"""The C++ structure inside a target: vtables, RTTI, constructors, destructors, and the
layouts that follow from them (Docs/Design-Plan.md, Phase 4).

Everything here comes from what the file itself carries - no Ghidra, no source, no names:

* **RTTI is the anchor.** A class with a key function emits a `type_info` object holding the
  *mangled name of the type* as a string, and its vtable points at that object. Both are
  data, so they survive stripping. The Itanium ABI fixes the shapes:

      vtable    = [offset-to-top, type_info*, method*, ...]   (an object's vptr = +2*ptr)
      type_info = [its own vptr, char* name, (base type_info*, ...)]

  so "a pointer slot whose target has a mangled type name at +ptr" identifies both ends and
  says what the class is called. The imported vtable the vptr points at
  (`__class_type_info` / `__si_` / `__vmi_`) says whether it has a base; where that name is
  not there (a static link) the number of base pointers the object carries says it instead.
* **The link's pointer slots are the table.** In a PIE, `.data.rel.ro` holds what the linker
  wrote and the loader rebases, so a slot is read from the dynamic relocation when there is
  one (the only source for a slot the file leaves zeroed), from the file bytes otherwise, and
  from the symbol when the target is an import.
* **A constructor is a function that stores a vptr.** Nothing else in an object does that. A
  destructor is the same shape but sits in the vtable (slots 0/1, the D1/D2 pair) - a
  constructor never appears in a vtable at all.
* **Fields come from `this`.** A class's own constructors, destructors and virtual methods
  touch its members through `this`, so the displacements those bodies use off it are the
  field offsets, with the width from the instruction. `this` is followed through register
  copies and through the stack slot `-O0` spills it to; nothing else is guessed.

Every claim carries the evidence for it, and a slot the file leaves null is reported as null:
measured on this benchmark, `structs.cpp`'s abstract base has a user-provided virtual
destructor and both of its vtable's destructor slots are null in the linked file, with no
relocation at them.
"""

from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import cache, normalize
from .extract import TargetImage

# A vtable longer than this is a jump table or a GOT, not a class.
MAX_SLOTS = 64
MAX_OBJECT_BYTES = 0x400
# Sections that can hold a vtable or a type_info (see extract._POINTER_SECTIONS).
_HOLDING = (".data.rel.ro", ".rodata", ".rdata", ".data", ".got")

# A mangled *type* name as type_info stores it: `14CVehicleEntity`, or the nested `N..E`
# form. `_Z..` appears for a type that is itself a declaration (a function or array type).
_TYPE_NAME = re.compile(r"^(?:[0-9]{1,3}[A-Za-z_][A-Za-z0-9_]*"
	r"|N(?:[0-9]{1,3}[A-Za-z_][A-Za-z0-9_]*|.[0-9]{1,3}[A-Za-z_][A-Za-z0-9_]*)+E"
	r"|_Z[A-Za-z0-9_]{4,})$")
# An imported libstdc++ type_info vtable names the exact type_info kind.
_TYPE_INFO_VTABLE = re.compile(r"__cxxabiv1::(_*(?:class|si_class|vmi_class|fundamental)_type_info)")
# A slot that cannot be a method: the start of the next vtable/type_info object.
_NOT_A_METHOD = re.compile(r"^(vtable|typeinfo) for ")

# MSVC's RTTI (Docs/MSVC-Plan.md MS-5). The type name in the file is `.?AVX@@`; every other
# MSVC RTTI object hangs off it as a chain of 4-byte references, and the widths differ by
# architecture in the way that plan's §8 says to expect:
#
#   type descriptor            = [its vftable pointer, zero, ".?AVX…@@"]  (a 2*ptr header)
#   RTTICompleteObjectLocator  = [signature(0|1), vftable offset, cdOffset,
#                                 type descriptor, class hierarchy descriptor(, itself)]
#   class hierarchy descriptor = [signature, attributes, base count, base class array]
#   base class descriptor      = [type descriptor, contained bases, disp, vftable offset,
#                                  vbase offset, attributes, class hierarchy descriptor]
#   vftable                    = [<the locator>, method*, …]  (an object's vptr = slot 0)
#
# On x64 those 4-byte fields are RVAs (from the image base) and a vftable slot is a full
# pointer; on x86 every one of them is an absolute address. Both measured, both handled.
_MSVC_TYPE_STRING = re.compile(rb"\.?\?A[VUE][\x20-\x7e]{1,300}?@@")
# The CRT's pure-virtual thunk: importable by name (/MD), unnamed once it is linked in.
_MSVC_PURECALL = re.compile(r"^_?_?purecall$", re.IGNORECASE)

# How wide one access is, from the mnemonic where the size is written in it.
_SUFFIX_WIDTH = {"b": 1, "w": 2, "l": 4, "q": 8}
# Mnemonics whose memory operand is the destination (AT&T writes them first, capstone lists
# them last: its operand list is source-then-destination).
_STORE_PREFIXES = ("mov", "fld", "fst", "add", "sub", "xor", "and", "or", "adc", "sbb",
	"shl", "shr", "sar", "sal", "inc", "dec", "neg", "not", "imul", "idiv", "div", "mul",
	"cvtsi2", "cvtss2", "cvtsd2", "movs", "movz")


# --------------------------------------------------------------------------------------
# names and sizes


def type_name(text: str) -> str:
	"""A type_info name string -> the class name (`14CVehicleEntity` -> `CVehicleEntity`).

	c++filt will not demangle a bare type encoding, but every type encoding `S` is the body of
	the symbol `_ZTV<S>`, which does demangle - to `vtable for <name>` - so that is what gets
	asked. The hand-written fallback reads the length-prefixed encoding directly.
	"""
	text = (text or "").strip()
	if not _TYPE_NAME.match(text):
		return ""
	demangled = normalize.clean_symbol("_ZTV" + text)
	if demangled.lower().startswith("vtable for "):
		return demangled[len("vtable for "):].strip()
	body = text[1:] if text.startswith("N") else text
	parts, position = [], 0
	while position < len(body) and body[position].isdigit():
		start = position
		while position < len(body) and body[position].isdigit():
			position += 1
		number = int(body[start:position])
		component = body[position:position + number]
		if not component:
			break
		parts.append(component)
		position += number
	return "::".join(parts)


def _reg_width(name: str) -> int:
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


def _width_of(mnemonic: str, operands, handle) -> int:
	"""How many bytes this instruction touches, 0 when it does not say."""
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
			width = _reg_width(handle.reg_name(operand.reg))
			if width:
				return width
	return 0


def _kind_of(mnemonic: str) -> str:
	"""What kind of value the access looks like - a hint, and labelled as one."""
	m = mnemonic
	if m.endswith("ss") or m.startswith(("cvtss", "cvtsi2ss", "fld", "fst")):
		return "float"
	if m.endswith("sd") or m.startswith(("cvtsd", "cvtsi2sd")):
		return "double"
	if m.startswith(("movaps", "movups", "movapd", "movupd")):
		return "block"
	if m.startswith(("movz", "movs")) and len(m) > 4:
		return "narrow-int"
	return "int"


# --------------------------------------------------------------------------------------
# what was recovered


@dataclass
class Method:
	index: int
	offset: int                    # offset inside the vtable object
	kind: str                      # function | pure | null | import
	address: int | None = None
	name: str = ""
	deleting: bool = False         # calls operator delete: the D2 form


@dataclass
class Field:
	offset: int
	size: int = 0
	kind: str = "unknown"
	reads: int = 0
	writes: int = 0
	sites: list[str] = field(default_factory=list)


@dataclass
class Klass:
	name: str
	mangled: str = ""
	typeinfo: int | None = None
	vtable: int | None = None
	bases: list[str] = field(default_factory=list)
	methods: list[Method] = field(default_factory=list)
	constructors: list[int] = field(default_factory=list)
	destructors: list[int] = field(default_factory=list)
	roles: dict[int, str] = field(default_factory=dict)   # what a member function is, and why
	fields: dict[int, Field] = field(default_factory=dict)
	notes: list[str] = field(default_factory=list)
	evidence: list[str] = field(default_factory=list)

	@property
	def polymorphic(self) -> bool:
		return self.vtable is not None

	@property
	def pure_count(self) -> int:
		return sum(1 for method in self.methods if method.kind == "pure")

	@property
	def lower_bound(self) -> int:
		"""Smallest size the code proves: the highest offset touched, plus its width."""
		base = 2 * 8 if self.polymorphic else 0
		return max([base] + [item.offset + max(item.size, 1) for item in self.fields.values()])

	def owns(self, entry: int) -> str:
		"""What this function is to this class ('' when it is nothing)."""
		for method in self.methods:
			if method.address != entry:
				continue
			if method.kind == "pure":
				return "pure virtual method (slot %d)" % method.index
			role = self.roles.get(entry, "")
			if role:
				return "%s, and it is vtable slot %d" % (role, method.index)
			return "virtual method (slot %d)" % method.index
		return self.roles.get(entry, "")

	def at(self, offset: int) -> Field | None:
		return self.fields.get(offset)


# --------------------------------------------------------------------------------------
# the pass


class Recovery:
	"""What one target's file says about its C++ classes.

	Built once per analysis and read as a lookup afterwards. It never raises: a target with no
	C++ in it returns nothing and says so.
	"""

	def __init__(self, conn, meta: dict, image: TargetImage | None = None) -> None:
		self.conn = conn
		self.meta = meta
		self.offset = cache.address_offset(meta)
		language = str(meta.get("language_id") or "")
		self.bits = 32 if ":32:" in language else (64 if ":64:" in language else 0)
		self.ptr = self.bits // 8
		self.image = image or TargetImage(Path(str(meta.get("target_path") or "")), self.offset)
		self.image_base = int(str(meta.get("image_base") or 0) or 0) or (
			self.image.file_address_base() if not self.image.error else 0)
		# Two RTTI models, chosen by what the target says it is (MSVC-Plan §1: a PE built by GCC
		# is not an MSVC target, and its RTTI is the Itanium one).
		self.abi = self._choose_abi()
		# What to call the two objects, in the model that was chosen for this file. They are the
		# same idea to a reader and different structures to the compiler, and the words matter:
		# "vtable" and "type_info" are Itanium, "vftable" and "type descriptor" are MSVC's.
		self.words = {"table": "vftable" if self.abi == "msvc" else "vtable",
			"type": "type descriptor" if self.abi == "msvc" else "type_info"}
		self.classes: dict[str, Klass] = {}
		self.vtables: dict[int, dict] = {}
		self.typeinfos: dict[int, dict] = {}
		self.notes: list[str] = []
		self.seconds = 0.0
		self.probed = 0
		self._data: list[tuple[int, int, bytes]] = []
		self._probing: set[int] = set()
		self._built = False

	def _choose_abi(self) -> str:
		"""Which RTTI this target's file carries: the Itanium one or MSVC's.

		The build note answers it when the analysis recorded one: `compiler_hint` comes from the
		file's own `.comment`/Rich header, which is evidence about the *target*. The variant the
		analysis was configured with is only a guess about the target (a proprietary binary is
		often analysed under a stand-in variant), so it comes second, and a PE with neither is
		tried as MSVC first because that is what a PE without a build note usually is - and
		`_msvc_read` says so out loud when the file turns out to carry no type descriptors.
		"""
		hint = str(self.meta.get("compiler_hint") or "").lower()
		driver = str(self.meta.get("variant_compiler") or "").lower()
		for name in (hint, driver):
			if name in ("msvc", "cl", "cl.exe") or name.endswith("-cl"):
				return "msvc"
			if name in ("gcc", "g++", "clang", "clang++") or "mingw" in name:
				return "itanium"
		if str(self.meta.get("target_format") or "").upper() == "PE":
			return "msvc"
		return "itanium"

	def build(self) -> "Recovery":
		if self._built:
			return self
		self._built = True
		started = time.time()
		if not self.ptr:
			self.notes.append("this target is %s, so no vtable layout is known for it"
				% (self.meta.get("language_id") or "an unknown language"))
			return self._finish(started)
		self._load_data()
		if self.abi == "msvc":
			self._msvc_read()
			if not self.typeinfos:
				# Nothing in the file is MSVC's RTTI. A PE with no build note is usually one, but
				# a GCC-built PE (Docs/MSVC-Plan.md §1) is not, and the Itanium model is the one
				# that can read it - so ask the file, and say which answer it gave.
				self.notes.append("no MSVC type descriptor in this file either: its RTTI is not "
					"MSVC's, so the Itanium model was tried in its place")
				self.abi = "itanium"
				self._itanium_probe()
		else:
			self._itanium_probe()
		self._link_classes()
		self._classify_members()
		self._recover_fields()
		return self._finish(started)

	def _itanium_probe(self) -> None:
		"""The Itanium pass: probe every address that could be a vtable or a type_info."""
		queue = list(dict.fromkeys(self._seeds()))
		rounds = 0
		while queue and rounds < 8:
			rounds += 1
			next_round: list[int] = []
			for address in queue:
				for start in self._candidate_starts(address):
					if self._probe(start):
						next_round.extend(self._found(start))
			queue = [item for item in dict.fromkeys(next_round) if item and item not in
				self.typeinfos and item not in self.vtables]
		self._find_unreferenced_vtables()

	def _finish(self, started: float) -> "Recovery":
		self.seconds = round(time.time() - started, 3)
		return self

	# -- reading pointer slots -----------------------------------------------------------

	def _load_data(self) -> None:
		if self._data:
			return
		if self.image.error:
			self.notes.append("the file could not be read (%s), so no vtable can be recovered"
				% self.image.error)
			return
		for name, address, size in self.image.data_sections():
			if size <= 0 or size > 8 * 1024 * 1024:
				continue
			if not any(name.startswith(h) for h in _HOLDING):
				continue
			chunk = self.image.read_data(address, size)
			if chunk:
				self._data.append((address, len(chunk), chunk))
		if not self._data:
			self.notes.append("no readable %s section in %s" % ("/".join(_HOLDING),
				self.image.path))
		elif self.abi == "msvc":
			# Measured: cl puts the type descriptors and the locators in `.data` (a /MT build of
			# this benchmark) and the vftables in `.rdata`; a DLL-CRT build puts them in `.rdata`.
			# Both are in the list above, and MSVC never uses a `.data.rel.ro`.
			pass

	def _bytes_at(self, address: int, length: int) -> bytes | None:
		for start, size, chunk in self._data:
			if start <= address < start + size:
				return chunk[address - start:address - start + length]
		return None

	def _string_at(self, address: int, limit: int = 512) -> str:
		"""The NUL-terminated printable text at an address ('' when there is none)."""
		if not address:
			return ""
		for start, size, chunk in self._data:
			if not start <= address < start + size:
				continue
			tail = chunk[address - start:address - start + limit]
			end = tail.find(b"\0")
			if end <= 0:
				return ""
			try:
				text = tail[:end].decode("ascii")
			except UnicodeDecodeError:
				return ""
			return text if all(32 <= ord(char) < 127 for char in text) else ""
		return ""

	def _slot(self, address: int) -> tuple[int | None, str]:
		"""What a pointer slot holds: (the address it points at, the import it names).

		The relocation the link recorded wins when there is one - it is the only source for a
		slot whose bytes are zero - then the file bytes, which is what a non-PIE writes and
		also what a PIE has before the loader rebases it.
		"""
		target = self.image.pointers.get(address)
		named = self.image.named_pointers.get(address) or ""
		raw = self._bytes_at(address, self.ptr)
		raw_value = int.from_bytes(raw, "little") if raw else 0
		# the bytes are in the file's own addresses; the analysis' are those plus the offset
		# `analyze` recorded. A zero stays zero - it is a null slot, not a pointer to 0x100000.
		value = raw_value + self.offset if raw_value else 0
		if value:
			return value, named
		if target:
			return target, named
		return (None, named)

	# -- the tests -----------------------------------------------------------------------

	def _seeds(self):
		"""Every address that could be inside a vtable or a type_info.

		The names the file has (an unstripped target says `_ZTV`/`_ZTI` directly), and every
		data address the code itself reads: a constructor's `lea` names a vptr, a
		`dynamic_cast` names a type_info, a virtual call reads a slot. Then whatever those
		point at, one step at a time - a base class is reachable only through the class that
		names it as its base.
		"""
		seeds: list[int] = []
		for row in self.conn.execute("SELECT address FROM symbols WHERE (name LIKE '_ZTV%'"
			" OR name LIKE '_ZTI%' OR name LIKE '_ZTC%') AND source IN ('IMPORTED','EXTERNAL')"):
			seeds.append(int(row["address"]))
		for row in self.conn.execute("SELECT DISTINCT to_address FROM refs WHERE to_address IS"
			" NOT NULL"):
			seeds.append(int(row["to_address"]))
		return [seed for seed in seeds if seed]

	def _candidate_starts(self, address: int):
		"""Where an object containing `address` could begin.

		`lea vtable+16(%rip)` names the vptr, not the object, so a reference can sit up to a
		few slots inside it; a `dynamic_cast` names a type_info at its first byte.
		"""
		aligned = address - (address % max(self.ptr, 1))
		return [aligned - step * self.ptr for step in range(0, 4)]

	def _probe(self, start: int) -> bool:
		"""Try to read one address as a type_info, then as a vtable."""
		if start in self.typeinfos or start in self.vtables:
			return True
		self.probed += 1
		if self._typeinfo_at(start):
			return True
		return bool(self._vtable_at(start))

	def _found(self, start: int):
		out: list[int] = []
		info = self.typeinfos.get(start)
		if info:
			out.append(info["name_address"])
			out.extend(info["bases"])
		table = self.vtables.get(start)
		if table:
			out.append(table["typeinfo"])
			out.extend(slot["address"] for slot in table["slots"] if slot["address"])
		return [item for item in out if item]

	def _typeinfo_at(self, address: int) -> dict | None:
		"""Is this a `type_info` object? The test is a mangled type name at +ptr."""
		if address in self.typeinfos:
			return self.typeinfos[address]
		if address in self._probing:
			return None
		self._probing.add(address)
		try:
			name_address, _named = self._slot(address + self.ptr)
			text = self._string_at(name_address) if name_address else self._string_at(
				address + self.ptr)
			pretty = type_name(text)
			if not pretty:
				return None
			vptr, named = self._slot(address)
			kind, bases = self._typeinfo_shape(address, vptr, named)
			record = {"address": address, "mangled": text, "name": pretty, "kind": kind,
				"bases": bases, "vptr": vptr, "name_address": name_address,
				"length": self.ptr * (2 + len(bases)),
				"symbol": self._symbol_at(address)}
			self.typeinfos[address] = record
			return record
		finally:
			self._probing.discard(address)

	def _typeinfo_shape(self, address: int, vptr: int | None, named: str) -> tuple[str, list[int]]:
		"""`class_type_info` / `__si_` / `__vmi_`, and where the base pointers sit.

		Two independent ways to know. The imported vtable the vptr names says it exactly, and
		is there whenever libstdc++ is a shared library. Otherwise the object's own shape says
		it: zero base pointers, one, or (for `__vmi_`) a count and flag pair and then a
		pointer/offset pair per base. If both answers exist they are cross-checked.
		"""
		by_name = ""
		for spelling in [named] + ([normalize.clean_symbol(str(cache.nearest_symbol(
				self.conn, vptr)[0]))] if vptr and cache.nearest_symbol(self.conn, vptr) else []):
			match = _TYPE_INFO_VTABLE.search(normalize.clean_symbol(spelling) or spelling or "")
			if match:
				by_name = match.group(1)
				break
		bases: list[int] = []
		position = address + 2 * self.ptr
		while len(bases) < 16:
			value, _named = self._slot(position)
			if not value or not self._is_typeinfo(value):
				break
			bases.append(value)
			position += self.ptr
		if not bases:
			# __vmi_class_type_info: two int32s (base count, flags), then {base*, offset} pairs
			pair = self._bytes_at(address + 2 * self.ptr, 8)
			if pair:
				count, flags = struct.unpack("<II", pair)
				if 1 <= count <= 16 and flags <= 0xFFFF:
					position = address + 4 * self.ptr
					for _ in range(count):
						value, _named = self._slot(position)
						if value and self._is_typeinfo(value):
							bases.append(value)
						position += 2 * self.ptr
		if by_name:
			expected = 1 if by_name == "__si_class_type_info" else 0
			if by_name == "__vmi_class_type_info":
				expected = len(bases)
			if len(bases) != expected:
				self.notes.append("the type_info at 0x%x names %s but carries %d base pointer(s)"
					% (address, by_name, len(bases)))
			return by_name, bases
		if not bases:
			return "class_type_info", bases
		return ("si_class_type_info" if len(bases) == 1 else "vmi_class_type_info"), bases

	def _is_typeinfo(self, address: int) -> bool:
		return address in self.typeinfos or bool(self._typeinfo_at(address))

	def _vtable_at(self, start: int) -> dict | None:
		"""Is this a vtable? +0 is an offset-to-top (a small int, never a pointer) and +ptr
		points at a type_info; the rest are methods."""
		if start in self.vtables:
			return self.vtables[start]
		offset_to_top, _named = self._slot(start)
		if offset_to_top and offset_to_top > 0x1000:
			return None
		typeinfo_address, _named = self._slot(start + self.ptr)
		if not typeinfo_address or not self._is_typeinfo(typeinfo_address):
			return None
		bound = min(start + MAX_OBJECT_BYTES, start + (MAX_SLOTS + 2) * self.ptr)
		next_object = cache.next_own_symbol(self.conn, start)
		if next_object:
			bound = min(bound, int(next_object))
		slots: list[dict] = []
		blanks = 0
		position = start + 2 * self.ptr
		while position < bound:
			value, named = self._slot(position)
			if named and _NOT_A_METHOD.match(normalize.clean_symbol(named) or named):
				break                    # the next vtable/type_info object starts here
			if named:
				blanks = 0
				slots.append({"offset": position - start, "kind": "import", "address": None,
					"name": normalize.clean_symbol(named) or named,
					"pure": "pure_virtual" in named})
			elif value and (cache.function_at(self.conn, value) or
					cache.inside_function(self.conn, value)):
				blanks = 0
				slots.append({"offset": position - start, "kind": "function", "address": value,
					"name": "", "pure": False})
			elif not value:
				if blanks >= 2:
					break      # the nulls the ABI itself puts in a vtable are the two destructor
							   # positions; three in a row is the next object, not this one
				blanks += 1
				slots.append({"offset": position - start, "kind": "null", "address": None,
					"name": "", "pure": False})
			else:
				break
			position += self.ptr
		if any(slot["kind"] != "null" for slot in slots):
			while len(slots) > 1 and slots[-1]["kind"] == "null":
				slots.pop()              # trailing zeros are alignment, not slots
		if not slots:
			# A vtable whose every method slot the file leaves null is still a vtable: the
			# header (offset-to-top + a type_info pointer) is proved, and its vptr address is
			# what identifies the constructors. Measured: the abstract base's vtable is all
			# nulls in the -m32 and -O2 builds of this benchmark, and its methods are only
			# reachable through the derived classes' vtables.
			for _ in range(2):
				slots.append({"offset": position - start + self.ptr, "kind": "null",
					"address": None, "name": "", "pure": False})
			slots = slots[:2]
		record = {"address": start, "typeinfo": typeinfo_address, "slots": slots,
			"vptr": start + 2 * self.ptr, "length": position - start,
			"offset_to_top": offset_to_top, "symbol": self._symbol_at(start)}
		self.vtables[start] = record
		return record

	# -- the MSVC model (Docs/MSVC-Plan.md MS-5) ---------------------------------------
	#
	# A parallel implementation of the pass above, not a generalisation of it: MSVC's type
	# system is a graph of small records that reference each other by 4-byte fields (RVAs on
	# x64, absolute addresses on x86), and its vftable has no header at all - an object's vptr
	# is slot 0, and the one slot *before* the table points at the class's
	# RTTICompleteObjectLocator. So the anchor here is the `.?AV<name>@@` type-name string, and
	# everything else is reached from it.

	def _msvc_word(self, address: int, width: int) -> int | None:
		raw = self._bytes_at(address, width)
		if raw is None or len(raw) < width:
			return None
		return int.from_bytes(raw, "little")

	def _msvc_field(self, address: int, width: int) -> tuple[int | None, str]:
		"""One reference stored in an RTTI record: (the address it names, how it is encoded).

		A field the width of a pointer holds an address; a 4-byte field holds an RVA on x64 and
		an address on x86. Measured: the type descriptors of a `/MT` build of this benchmark are
		in `.data`, each with a full vftable pointer and a zero pad, and its locators reference
		them by RVA; `deadrising2.exe`, a 32-bit MSVC binary, references everything absolutely.
		"""
		value = self._msvc_word(address, width)
		if not value:
			return None, ""
		if width == self.ptr or self.ptr == 4:
			return value + self.offset, "address" if width == self.ptr else "absolute"
		return value + self.image_base + self.offset, "rva"

	def _msvc_mapped(self, address: int | None, width: int = 1) -> bool:
		return bool(address) and self._bytes_at(address, width) is not None

	def _msvc_typeinfo_at(self, string_address: int, text: str) -> dict | None:
		"""The type descriptor whose name string is at `string_address`.

		The header is two fields of one width, and only one width puts the string where the name
		belongs and lands the pointer in front of it on a real section: that is what decides the
		form, so a target built by another toolset era is read the same way.
		"""
		address = string_address - 2 * self.ptr
		if address in self.typeinfos:
			return self.typeinfos[address]
		_kind, pretty = normalize.msvc_type_name(text)
		if not pretty:
			return None
		for width in dict.fromkeys([self.ptr, 4]):
			header = 2 * width
			at = string_address - header
			vptr, form = self._msvc_field(at, width)
			pad = self._msvc_word(at + width, width)
			if pad or not self._msvc_mapped(vptr, self.ptr):
				continue
			record = {"address": at, "mangled": text, "name": pretty, "kind":
				"MSVC type descriptor (%s)" % text, "bases": [], "vptr": vptr, "form": form,
				"name_address": string_address, "symbol": self._symbol_at(at),
				"length": header + len(text) + 1, "col": None, "chd": None, "claims": [],
				"msvc": True}
			self.typeinfos[at] = record
			return record
		return None

	def _msvc_chd(self, chd: int | None) -> tuple[int, list[tuple[int, int, int]]] | None:
		"""One RTTIClassHierarchyDescriptor -> (the count it states, its base-class descriptors).

		A descriptor is [signature, attributes, base count, array of base-class descriptors] and
		each of those is [type descriptor, contained bases, displacement, vftable offset, vbase
		offset, attributes, class hierarchy descriptor]. The displacement is the field that
		matters here: it is where the base subobject sits inside the derived class, which is what
		a multiple-inheritance thunk adjusts `this` by.
		"""
		if not self._msvc_mapped(chd, 16):
			return None
		if (self._msvc_word(chd, 4) or 0) > 1:
			return None
		count = self._msvc_word(chd + 8, 4) or 0
		array, _form = self._msvc_field(chd + 12, 4)
		if not 1 <= count <= MAX_SLOTS or not self._msvc_mapped(array, 4 * count):
			return None
		descriptors: list[tuple[int, int, int]] = []
		for step in range(count):
			bcd, _form = self._msvc_field(array + 4 * step, 4)
			if not self._msvc_mapped(bcd, 0x1c):
				continue
			typeinfo, _form = self._msvc_field(bcd, 4)
			descriptors.append((typeinfo or 0, _signed(self._msvc_word(bcd + 8, 4)),
				_signed(self._msvc_word(bcd + 0xc, 4))))
		return count, descriptors

	def _msvc_class_of(self, locator: int) -> tuple[int, dict] | None:
		"""An RTTICompleteObjectLocator -> (its type descriptor, what the locator states).

		Accepted only when the class hierarchy it names carries a descriptor for this very type:
		the first entry of a class's own base-class array describes the class itself, and that is
		what separates a locator from the base-class descriptor that references the same type
		descriptor at its own offset 0.
		"""
		typeinfo, _form = self._msvc_field(locator + 0xc, 4)
		if typeinfo not in self.typeinfos:
			return None
		signature = self._msvc_word(locator, 4)
		if signature not in (0, 1):
			return None
		parsed = self._msvc_chd(self._msvc_field(locator + 0x10, 4)[0])
		if not parsed or all(item[0] != typeinfo for item in parsed[1]):
			return None
		count, descriptors = parsed
		self_reference = self._msvc_word(locator + 0x14, 4)
		if signature == 1 and self_reference not in (
				locator - self.image_base - self.offset, locator - self.offset):
			self.notes.append("the locator at %#x states signature 1 but carries no self-reference "
				"at +0x14" % locator)
		return typeinfo, {"locator": locator, "signature": signature,
			"offset": _signed(self._msvc_word(locator + 4, 4)),
			"cd_offset": _signed(self._msvc_word(locator + 8, 4)),
			"chd": self._msvc_field(locator + 0x10, 4)[0], "count": count,
			"bases": [item for item in descriptors if item[0] != typeinfo],
			"self": [item for item in descriptors if item[0] == typeinfo]}

	def _msvc_vftable(self, slot: int, locator: int, typeinfo: int) -> dict | None:
		"""The vftable that starts one slot after a pointer to its locator. The slots run until
		something that is not a function of this image, which is where the next object starts.
		"""
		if slot in self.vtables:
			return self.vtables[slot]
		slots: list[dict] = []
		position = slot
		bound = min(slot + MAX_OBJECT_BYTES, slot + MAX_SLOTS * self.ptr)
		while position + self.ptr <= bound:
			value, _form = self._msvc_field(position, self.ptr)
			if not value or value == locator:
				break
			if not (cache.function_at(self.conn, value) or cache.inside_function(self.conn,
					value)):
				break
			slots.append({"offset": position - slot, "kind": "function", "address": value,
				"name": "", "pure": False})
			position += self.ptr
		if not slots:
			return None
		record = {"address": slot, "typeinfo": typeinfo, "slots": slots, "vptr": slot,
			"length": position - slot, "offset_to_top": None, "col": locator,
			"symbol": self._symbol_at(slot)}
		self.vtables[slot] = record
		return record

	def _msvc_read(self) -> None:
		"""Type descriptors first, then the locators that name them, then the vftables that name
		those. Three passes over the file's initialised data; nothing is guessed between them.
		"""
		if self.image.error:
			return
		strings: list[tuple[int, str]] = []
		for start, size, chunk in self._data:
			for match in _MSVC_TYPE_STRING.finditer(chunk):
				text = match.group(0).decode("ascii", "replace")
				strings.append((start + match.start(),
					text if text.startswith(".") else "." + text))
		if not strings:
			self.notes.append("no `.?AV…` type-name string in this file, so it carries no MSVC "
				"RTTI and no class can be recovered from it (C code, or built with /GR-)")
			return
		for string_address, text in strings:
			self.probed += 1
			self._msvc_typeinfo_at(string_address, text)
		# every 4-byte field in the data that names a type descriptor: a locator (at -0xc) or a
		# base-class descriptor (at -0). `_msvc_class_of` tells those apart by structure.
		wanted = set()
		for address in self.typeinfos:
			wanted.add(address - self.offset)                    # absolute
			wanted.add(address - self.image_base - self.offset)  # RVA
		locators: dict[int, dict] = {}
		for start, size, chunk in self._data:
			for offset in range(0, max(0, size - 0x18), 4):
				value = int.from_bytes(chunk[offset:offset + 4], "little")
				if value not in wanted:
					continue
				parsed = self._msvc_class_of(start + offset - 0xc)
				if parsed is None:
					continue
				typeinfo, claims = parsed
				locators[claims["locator"]] = dict(claims, typeinfo=typeinfo)
				info = self.typeinfos[typeinfo]
				info["col"] = claims["locator"]
				info["chd"] = claims["chd"]
				info["bases"] = [item[0] for item in claims["bases"]
					if item[0] in self.typeinfos]
				info.setdefault("claims", []).append(claims)
		# the vftable is the object whose first slot follows a pointer to its locator
		wanted = {locator - self.offset for locator in locators}
		found = 0
		for start, size, chunk in self._data:
			for offset in range(0, max(0, size - self.ptr), self.ptr):
				value = int.from_bytes(chunk[offset:offset + self.ptr], "little")
				if value not in wanted:
					continue
				claims = locators.get(value + self.offset)
				if claims is None:
					continue
				# the vftable starts where the pointer to its locator ends - at the *slot*, not at
				# the address the slot holds
				if self._msvc_vftable(start + offset + self.ptr, value + self.offset,
						claims["typeinfo"]):
					found += 1
		if not locators:
			self.notes.append("%d type descriptor(s) and no RTTICompleteObjectLocator naming any "
				"of them: nothing in this file takes the address of a vtable for those types, so "
				"their vftables and method slots are unknown" % len(self.typeinfos))
		self.notes.append("MSVC RTTI read from the file: %d type descriptor(s), %d locator(s), "
			"%d vftable(s); the records reference each other by %s" % (len(self.typeinfos),
				len(locators), found, "absolute 4-byte addresses" if self.ptr == 4 else "4-byte RVAs"))

	def _find_unreferenced_vtables(self) -> None:
		"""Look for the vtable of any type_info no vtable has been found for.

		A vtable is by definition the object whose second slot is a type_info, and a class the
		code never constructs - an abstract base, used only through pointers - may have no
		reference to its vtable anywhere in the program. The only way to find that one is to ask
		the data sections: who holds a pointer to this type_info?
		"""
		known = {table["typeinfo"] for table in self.vtables.values()}
		wanted = {address for address in self.typeinfos if address not in known}
		if not wanted:
			return
		for start, size, _chunk in self._data:
			for offset in range(0, size - self.ptr, self.ptr):
				value, _named = self._slot(start + offset)
				if value in wanted:
					self._probe(start + offset - 2 * self.ptr)

	def _symbol_at(self, address: int) -> str:
		row = self.conn.execute("SELECT name FROM symbols WHERE address = ? AND source IN"
			" ('IMPORTED','EXTERNAL') LIMIT 1", (address,)).fetchone()
		return row["name"] if row else ""

	# -- joining it into classes ---------------------------------------------------------

	def _link_classes(self) -> None:
		for address, info in sorted(self.typeinfos.items()):
			klass = self.classes.get(info["name"])
			if klass is None:
				klass = self.classes[info["name"]] = Klass(name=info["name"],
					mangled=info["mangled"], typeinfo=address)
			if info.get("msvc"):
				klass.evidence.append(
					"MSVC type descriptor at %s: the name string at %s is %r, which is the "
					"decoration for a %s named %s; its own vftable pointer is %s (%s-encoded)"
					% (_hex(address), _hex(info["name_address"]), info["mangled"],
						"class" if info["mangled"].startswith(".?AV") else
						"struct" if info["mangled"].startswith(".?AU") else "type",
						info["name"], _hex(info["vptr"]) if info["vptr"] else "unresolved",
						info.get("form", "")))
				for claims in info.get("claims", []):
					klass.evidence.append(
						"RTTICompleteObjectLocator at %s (signature %d, vftable offset %d, cdOffset "
						"%d) names it, and its RTTIClassHierarchyDescriptor at %s carries %d base "
						"class descriptor(s)"
						% (_hex(claims["locator"]), claims["signature"], claims["offset"],
							claims["cd_offset"], _hex(claims["chd"]) if claims["chd"] else "unresolved",
							len(claims["bases"])))
					for typeinfo, where, vftable_offset in claims["bases"]:
						base = self.typeinfos.get(typeinfo)
						if base is None:
							continue
						klass.evidence.append(
							"the base-class descriptor for %s states displacement %d and vftable "
								"offset %d: that is where the %s subobject sits inside a %s, and what a "
							"thunk adjusts `this` by when one of its methods is reached through it"
							% (base["name"], where, vftable_offset, base["name"], klass.name))
			else:
				klass.evidence.append(
					"type_info at %s: name string %s is %r, its own vptr is %s, so it is a %s"
					% (_hex(address), _hex(info["name_address"]), info["mangled"],
						_hex(info["vptr"]) if info["vptr"] else "unresolved", info["kind"]))
			for base in info["bases"]:
				target = self.typeinfos.get(base)
				if target and target["name"] not in klass.bases:
					klass.bases.append(target["name"])
		for start, table in sorted(self.vtables.items()):
			info = self.typeinfos.get(table["typeinfo"])
			if info is None:
				continue
			klass = self.classes.get(info["name"])
			if klass is None:
				continue
			if klass.vtable is not None and not self._primary_table(table):
				continue      # a second vftable of one class: reported, but not the object's vptr
			klass.vtable = start
			if self.abi == "msvc":
				klass.evidence.append(
					"vftable at %s, %d slot%s: an object's vptr is its first slot (+0x%x) and the "
					"locator for this class sits in the slot before it at %s%s"
					% (_hex(start), len(table["slots"]), "" if len(table["slots"]) == 1 else "s",
						0, _hex(table.get("col")) if table.get("col") else "nowhere",
						"; the file names it " + table["symbol"] if table["symbol"] else ""))
			else:
				klass.evidence.append(
					"vtable at %s, %d slot%s, vptr = +%#x, offset-to-top %s%s"
					% (_hex(start), len(table["slots"]), "" if len(table["slots"]) == 1 else "s",
						2 * self.ptr, table["offset_to_top"],
						"; the file names it " + table["symbol"] if table["symbol"] else ""))
			for index, slot in enumerate(table["slots"]):
				method = Method(index=index, offset=slot["offset"],
					kind="pure" if slot["pure"] else slot["kind"], address=slot["address"],
					name=slot["name"] or self._method_name(slot["address"]))
				klass.methods.append(method)
				if slot["kind"] == "null":
					klass.notes.append("vtable slot +%#x is null in this file: no relocation and"
						" zero bytes there" % slot["offset"])
			if self.abi == "msvc":
				self._msvc_pure_slots(klass, table)
		for klass in self.classes.values():
			if klass.vtable is None:
				klass.notes.append("no vtable pointing at this type_info was found in the file: the "
					"code never refers to it, and every pointer slot that could hold one read as "
					"empty here - so the method slots and their order are unknown")
			for base in klass.bases:
				parent = self.classes.get(base)
				if parent and parent.vtable and klass.vtable and klass.vtable > parent.vtable:
					klass.evidence.append("its vtable sits after %s's in the file, which is what "
						"a derived class's does" % base)

	def _primary_table(self, table: dict) -> bool:
		"""Is this the vftable an object's vptr points at? A class with multiple inheritance has
		one per base subobject, and only the one its locator places at offset 0 is the primary.
		"""
		info = self.typeinfos.get(table["typeinfo"], {})
		for claims in info.get("claims", []):
			if claims.get("locator") == table.get("col"):
				return claims.get("offset") == 0
		return True

	def _msvc_pure_slots(self, klass: "Klass", table: dict) -> None:
		"""Which MSVC vftable slots are pure virtuals, and on what evidence.

		MSVC puts the CRT's `_purecall` in the slot of a pure virtual function. That name is only
		in a PE when the CRT is a DLL (a `/MD` build imports it); once the CRT is linked in (`/MT`)
		the image gives the function no name at all, and then a pure slot and an inherited one, or
		one the linker folded into another class's, look the same from the data: the same address,
		in more than one vftable, unreached by any call. Nothing distinguishes them, so only the
		name is claimed and the rest is said as a limit.
		"""
		unnamed = False
		for slot in table["slots"]:
			target = slot["address"]
			if not target:
				continue
			name = (self._method_name(target) or "").replace(".", "_")
			if _MSVC_PURECALL.match(name):
				slot["pure"] = True
				klass.evidence.append("vtable slot %d points at %s, the CRT's pure-virtual thunk"
					% (slot["offset"] // max(self.ptr, 1), name))
				continue
			calls = self.conn.execute("SELECT COUNT(*) FROM refs WHERE to_address = ? AND ref_type"
				" LIKE '%CALL'", (target,)).fetchone()[0]
			if not calls:
				unnamed = True
		if unnamed:
			klass.notes.append("one or more slots point at a function no call in this image "
				"reaches; a pure virtual's `_purecall` slot has exactly that shape, and with the "
				"CRT linked in this file names no function, so those slots are reported as slots "
				"and not claimed pure")

	def _method_name(self, address: int | None) -> str:
		"""The name of the function a slot points at, if one exists to be had."""
		if not address:
			return ""
		row = cache.function_at(self.conn, address)
		if row is None:
			symbol = cache.nearest_symbol(self.conn, address)
			return symbol[0] if symbol else ""
		namespace = row["namespace"] or ""
		if namespace in ("", "Global", "<root>"):
			return row["name"]
		return "%s::%s" % (namespace.replace("::", "."), row["name"])

	def _classify_members(self) -> None:
		"""Constructors and destructors, from the one thing only they do: they store a vptr.

		The vptr value written is `vtable + 2*ptr`, which is exactly the address the cache's
		resolved references name, so "which functions store this class's vptr" is a lookup.
		What they are is decided by what else they do:

		* calling `operator delete` is the deleting destructor (the D2 form) - nothing else a
		  class emits does that;
		* a function one of those calls is a destructor too (the D1/D0 form of the same class);
		* a function that stores a vptr and *is* a vtable slot is a destructor: a constructor is
		  never in a vtable;
		* what is left stores a vptr and is nowhere else explained. A derived constructor calls
		  the base constructor and a derived destructor calls the base destructor, and both write
		  the base's vptr, so without a name the two are not separable - and it says "constructor
		  or destructor" rather than picking one.

		On a PE nothing has a name, so the last rule would leave every constructor and destructor
		unseparated. MSVC's vtable shape settles it: the destructor slot holds the deleting form,
		which calls the function that writes the vptr (see `_classify_members`'s `msvc_pairs`).
		"""
		in_vtables: dict[int, tuple[int, int]] = {}
		for start, table in self.vtables.items():
			for index, slot in enumerate(table["slots"]):
				if slot["address"]:
					in_vtables.setdefault(slot["address"], (start, index))
		writers: dict[int, list[tuple[int, int | None]]] = {}
		for start, table in sorted(self.vtables.items()):
			for entry in cache.xrefs_to(self.conn, [table["vptr"]], 200):
				where = int(entry["entry"])
				slot = in_vtables.get(where)
				if slot and slot[0] != start:
					continue      # it writes another class's vptr: a base sub-object, not this one
				writers.setdefault(where, []).append((start, slot[1] if slot else None))
		# A function that frees through `operator delete` is the deleting form of a destructor.
		# It is not always one of the vptr writers itself (the D2 form calls the D1, which is
		# what writes the vptr), so collect every one of them and look at both directions.
		frees = set()
		for row in self.conn.execute("SELECT DISTINCT f.entry AS entry FROM refs r JOIN functions"
			" f ON f.id = r.fn WHERE r.to_name LIKE '%dlPv%' OR r.to_name LIKE '%daPv%'"
			" OR r.to_name LIKE '%erator.delete%' OR r.to_name LIKE '%erator%delete%'"):
			frees.add(int(row["entry"]))
		deleting = {entry for entry in writers if entry in frees}
		called_by_deleting = set()
		for entry in writers:
			row = cache.function_at(self.conn, entry)
			if row is None:
				continue
			if any(int(caller["entry"]) in frees for caller in cache.callers(self.conn, row["id"])):
				called_by_deleting.add(entry)
			# On a PE nothing of this is named, so the same relation is read the other way: an
			# MSVC vftable's destructor slot holds the *deleting* destructor, which does not store
			# the vptr itself - it calls the one that does, then frees the storage. So a slot of a
			# class's own vftable that reaches a destructor of that class or of one of its bases is
			# the deleting destructor, and the function it calls directly is the destructor.
		msvc_pairs: dict[int, tuple[int, int, int]] = {}
		msvc_shared: dict[int, list[str]] = {}
		if self.abi == "msvc":
			writers_of: dict[int, set[int]] = {}
			for entry, targets in writers.items():
				for start, _slot in targets:
					writers_of.setdefault(start, set()).add(entry)
			for name, klass in sorted(self.classes.items()):
				tables = [klass.vtable] if klass.vtable else []
				seen_bases: list[str] = []
				queue = list(klass.bases)
				while queue:
					base = queue.pop(0)
					if base in seen_bases:
						continue
					seen_bases.append(base)
					parent = self.classes.get(base)
					if parent is None:
						continue
					if parent.vtable:
						tables.append(parent.vtable)
					queue += parent.bases
				reaching = set().union(*[writers_of.get(table, set()) for table in tables]) \
					if tables else set()
				for table in [klass.vtable] if klass.vtable else []:
					for index, slot in enumerate(self.vtables[table]["slots"]):
						entry = slot["address"]
						if not entry or entry in writers_of.get(table, set()):
							continue      # it stores this class's vptr: the slot rule covers it
						callee = self._msvc_reaches(entry, reaching)
						if not callee:
							continue
						owners = sorted({other.name for other in self.classes.values()
							if other.vtable and any(item["address"] == entry
								for item in self.vtables[other.vtable]["slots"])})
						if len(owners) > 1:
							msvc_shared.setdefault(entry, owners)
							continue
						msvc_pairs[entry] = (table, index, callee)
						called_by_deleting.add(callee)
		for entry, targets in sorted(writers.items()):
			for start, slot in targets:
				info = self.typeinfos.get(self.vtables[start]["typeinfo"])
				klass = self.classes.get(info["name"]) if info else None
				if klass is None:
					continue
				if entry in deleting:
					role = "deleting destructor"
					why = "it stores this class's vptr and calls operator delete"
				elif entry in called_by_deleting:
					role = "destructor"
					why = "the deleting destructor of the same class calls it"
				elif slot is not None:
					role = "destructor"
					why = ("it stores a vptr and is vtable slot %d, and a constructor is never in "
						"a vtable" % slot)
				else:
					role = "constructor or destructor"
					why = ("it stores this class's vptr (%s = vtable +%#x) and is not in any vtable"
						% (_hex(self.vtables[start]["vptr"]),
							0 if self.abi == "msvc" else 2 * self.ptr))
				klass.roles[entry] = role
				claim = "%s at %s: %s" % (role, _hex(entry), why)
				if role in ("deleting destructor", "destructor"):
					if entry not in klass.destructors:
						klass.destructors.append(entry)
				elif entry not in klass.constructors:
					klass.constructors.append(entry)
				if claim not in klass.evidence:
					klass.evidence.append(claim)   # the same vptr is written twice in a real body
		for entry, (start, index, callee) in sorted(msvc_pairs.items()):
			info = self.typeinfos.get(self.vtables[start]["typeinfo"])
			klass = self.classes.get(info["name"]) if info else None
			if klass is None:
				continue
			klass.roles[entry] = "deleting destructor"
			if entry not in klass.destructors:
				klass.destructors.append(entry)
			for method in klass.methods:
				if method.address == entry:
					method.deleting = True
			klass.evidence.append("deleting destructor at %s: it is vtable slot %d and it calls %s, "
				"which reaches a destructor of this class or of one of its bases - the destructor "
				"form that frees the storage" % (_hex(entry), index, _hex(callee)))
			if klass.roles.get(callee) in (None, "", "constructor or destructor"):
				if callee in klass.constructors:
					klass.constructors.remove(callee)
				klass.roles[callee] = "destructor"
				if callee not in klass.destructors:
					klass.destructors.append(callee)
				klass.evidence.append("destructor at %s: the deleting destructor in this class's "
					"vftable calls it directly" % _hex(callee))
		for entry, owners in sorted(msvc_shared.items()):
			for name in owners:
				klass = self.classes.get(name)
				if klass is not None:
					klass.notes.append("its vftable's destructor slot (%s) is shared with %s: the "
						"linker folded the two identical deleting destructors into one, so this file "
						"cannot say which destructor it runs for this class"
						% (_hex(entry), ", ".join(sorted(set(owners) - {name}))))
		for klass in self.classes.values():
			for method in klass.methods:
				if method.address in deleting:
					method.deleting = True
				# the Itanium ABI puts the destructor pair in the first two slots, so when one of
				# them is identified and its neighbour is not, the neighbour is the other half -
				# stated as a reading of the ABI next to the fact, never as a claim of its own. MSVC
				# has one destructor slot, so its neighbour is just the next virtual function.
				if self.abi == "msvc" or method.index > 1 or method.kind != "function" or \
						not method.address or klass.roles.get(method.address):
					continue
				if any(other.index == method.index - 1 and other.address and
						klass.roles.get(other.address, "") in ("destructor", "deleting destructor")
						for other in klass.methods):
					klass.roles[method.address] = "destructor (the other half of the pair)"
					if method.address not in klass.destructors:
						klass.destructors.append(method.address)
					klass.evidence.append("destructor at %s: vtable slot %d, directly after the slot "
						"this class's destructor is in" % (_hex(method.address), method.index))

	def _msvc_reaches(self, entry: int, reaching: set[int], depth: int = 3) -> int:
		"""The first function `entry` calls on a chain that reaches one of `reaching`.

		A derived class with nothing of its own to clean up has a destructor that stores no vptr:
		at `/Od` it is a stub whose only call is the base class's destructor. So "the vftable's
		destructor slot calls the thing that stores this class's vptr" has to be followed through
		the call or two in between, and the function at the other end of that first hop is the
		class's own destructor.
		"""
		frontier, parents = [(entry, 0)], {entry: 0}
		while frontier:
			here, steps = frontier.pop(0)
			if steps >= depth:
				continue
			row = cache.function_at(self.conn, here)
			if row is None:
				continue
			for item in cache.targets_of(self.conn, row["id"]):
				target = int(item["address"] or 0)
				if not target or target in parents:
					continue
				parents[target] = here
				if target in reaching:
					node = target
					while parents[node] != entry:
						node = parents[node]
					return node
				frontier.append((target, steps + 1))
		return 0

	def _calls_operator_delete(self, entry: int) -> bool:
		"""Does this function free storage through `operator delete`? Only the deleting form of
		a destructor does that."""
		row = cache.function_at(self.conn, entry)
		if row is None:
			return False
		for target in cache.targets_of(self.conn, row["id"]):
			name = str(target.get("name") or "")
			# the names this comes from differ by tool: the ELF symbol is `_ZdlPv`/`_ZdlPvm`,
			# c++filt says "operator delete(void*)", Ghidra says "operator.delete"
			spelling = (normalize.clean_symbol(name) or name).lower().replace(".", " ")
			if "dlpv" in name.lower() or "dapv" in name.lower() or "operator delete" in spelling:
				return True
		return False

	# -- field layouts -------------------------------------------------------------------

	def _member_functions(self, klass: Klass) -> list[tuple[int, bytes, str]]:
		"""(entry, bytes, name) for the functions attributed to this class.

		Attributed means evidenced: it is in this class's vtable, or it writes one of its
		vptrs. A name is never evidence in a stripped binary, and "it takes a pointer" is not
		either - that would put every method of every class in the wrong place.
		"""
		out, seen = [], set()
		candidates = [method.address for method in klass.methods if method.address]
		candidates += list(klass.constructors) + list(klass.destructors)
		for address in candidates:
			row = cache.function_at(self.conn, address)
			if row is None or row["id"] in seen:
				continue
			seen.add(row["id"])
			body = self.conn.execute("SELECT bytes FROM functions WHERE id = ?", (row["id"],)) \
				.fetchone()
			blob = bytes((body["bytes"] if body else b"") or b"")
			if blob:
				out.append((int(row["entry"]), blob, self._method_name(address)))
		return out

	def _recover_fields(self) -> None:
		"""The offsets a class's own code reaches through `this`.

		`this` is the first argument register (rdi on x86-64 SysV, ecx in the 32-bit thiscall
		ABI). `-O0` spills it to the frame and reloads it, so the tracking follows a tainted
		register through a `mov` and through the frame slot it was stored to - which is where
		most of the offsets in an -O0 build are. A register that is written any other way, or
		a call, stops the trail; an indexed access is an array element, not a field, and is
		left out rather than guessed at.
		"""
		handle = normalize.capstone_for(str(self.meta.get("language_id") or ""), detail=True)
		from capstone import CS_OP_MEM, CS_OP_REG
		from capstone.x86 import (X86_REG_EBP, X86_REG_ECX, X86_REG_ESP, X86_REG_RBP,
			X86_REG_RCX, X86_REG_RDI, X86_REG_RSP)
		# Where `this` starts: %rdi in the 64-bit SysV ABI, %rcx in the Microsoft x64 one. On
		# 32-bit x86 the Microsoft thiscall puts it in %ecx, and GCC passes it on the stack (the
		# frame-slot seeding below covers that).
		this_register = {64: X86_REG_RCX if self.abi == "msvc" else X86_REG_RDI,
			32: X86_REG_ECX}.get(self.bits)
		# -O0 spills `this` to the frame and reloads it: follow it there, or almost every
		# field offset in an -O0 build stays invisible. The frame register differs by width.
		frame = {X86_REG_EBP, X86_REG_ESP} if self.bits == 32 else {X86_REG_RBP, X86_REG_RSP}
		stack_register = {32: X86_REG_ESP, 64: X86_REG_RSP}.get(self.bits)
		for klass in self.classes.values():
			if handle is None or not this_register:
				klass.notes.append("no decoder for this target, so the field offsets could not "
					"be read out of the instruction streams")
				continue
			bodies = self._member_functions(klass)
			if not bodies:
				klass.notes.append("no member function could be attributed to it, so its field "
					"layout is unknown")
				continue
			for entry, blob, name in bodies:
				# Where `this` starts: %rdi in the 64-bit SysV ABI, %rcx in the Microsoft x64 one.
				# On 32-bit x86 GCC passes it on the stack, so the value to follow is the one at
				# 8(%ebp) - the first argument - and %ecx as well, which is where the Microsoft
				# 32-bit thiscall puts it.
				tainted = {this_register}
				# Frame slots are keyed by the register they are offsets *from*: a `-m32` build
				# reaches `this` through `8(%ebp)`, and an MSVC x64 `/Od` body spills it to
				# `8(%rsp)` and then moves %rsp. Mixing the two domains, or shifting a %rbp-relative
				# slot because %rsp moved, loses the trail.
				frame_register = X86_REG_EBP if self.bits == 32 else X86_REG_RBP
				slots: dict[int, set[int]] = ({frame_register: {8}} if self.bits == 32
					else {})
				for instruction in handle.disasm(blob, entry):
					operands = list(instruction.operands)
					memory = [item for item in operands if item.type == CS_OP_MEM]
					last_is_memory = bool(operands) and operands[-1].type == CS_OP_MEM
					stores = instruction.mnemonic.startswith(_STORE_PREFIXES) and last_is_memory
					reads = bool(memory) and not stores
					shift = _stack_adjustment(instruction, operands, stack_register)
					if shift and stack_register in slots:
						# `cl` at /Od keeps no frame pointer: it spills `this` to `8(%rsp)`, then
						# `sub $0x28,%rsp` and reaches it as `0x30(%rsp)`. A slot is an offset from
						# one *stack pointer value*, so moving the pointer moves every slot recorded
						# against it - without this, the spill and the reload never meet.
						slots[stack_register] = {item + shift for item in slots[stack_register]}
					for item in memory:
						if item.mem.base not in tainted or item.mem.index or item.mem.disp < 0:
							continue
						self._add_field(klass, item.mem.disp, _width_of(instruction.mnemonic,
							operands, handle), _kind_of(instruction.mnemonic), stores, name,
							instruction.address)
					if not memory and len(operands) == 2 and operands[0].type == CS_OP_REG and \
							operands[1].type == CS_OP_REG and operands[0].reg in tainted and \
							instruction.mnemonic.startswith("mov"):
						tainted.add(operands[1].reg)      # `mov %rdi, %rbx`: the trail follows
					for item in memory:
						if item.mem.base in frame and len(operands) == 2:
							known = slots.get(item.mem.base, set())
							if stores and operands[0].type == CS_OP_REG and \
									operands[0].reg in tainted:
								slots.setdefault(item.mem.base, set()).add(item.mem.disp)
							elif not stores and operands[-1].type == CS_OP_REG and \
									item.mem.disp in known:
								tainted.add(operands[-1].reg)
					for reg, _size in _written_regs(instruction, handle):
						if operands and operands[-1].type == CS_OP_REG and \
								operands[-1].reg == reg and instruction.mnemonic.startswith(
									"mov"):
							continue
						tainted.discard(reg)
			klass.fields = dict(sorted(klass.fields.items()))

	def _add_field(self, klass: Klass, offset: int, width: int, kind: str, write: bool,
		name: str, at: int) -> None:
		existing = klass.fields.get(offset) or klass.fields.setdefault(offset, Field(offset))
		if width:
			existing.size = max(existing.size, width)
		if kind not in ("int", "unknown") and existing.kind in ("unknown", "int"):
			existing.kind = kind
		existing.writes += 1 if write else 0
		existing.reads += 0 if write else 1
		site = "%s @ %s" % (name or "0x%x" % at, _hex(at))
		if site not in existing.sites:
			existing.sites.append(site)

	# -- asking it -----------------------------------------------------------------------

	def object_at(self, address: int) -> dict | None:
		"""What a data address is, when it is a vtable or a type_info object.

		This is what lets the two sides of a diff name the same object: the `.o` relocates
		against `_ZTI14CVehicleEntity` (on an MSVC target, `??_R0?AVCVehicleEntity@@@8`), and RTTI
		in the stripped image says the very same thing about the pointer slot the linked code
		reads - in the target's own RTTI format, on either ABI. `address` may be any byte in the
		object.
		"""
		self.build()
		for start, table in self.vtables.items():
			if start <= address < start + table["length"]:
				info = self.typeinfos.get(table["typeinfo"], {})
				name = info.get("name", "")
				return {"role": "vtable", "class": name,
					"name": ("vtable for %s" % name) if name else "",
					"mangled": table["symbol"] or (
						normalize.msvc_type_symbol("vtable", info["mangled"]) if info.get("msvc")
						else ("_ZTV" + info["mangled"] if info.get("mangled") else "")),
					"address": start, "size": table["length"]}
		for start, info in self.typeinfos.items():
			if start <= address < start + info["length"]:
				return {"role": "typeinfo", "class": info["name"],
					"name": "typeinfo for %s" % info["name"],
					"mangled": normalize.msvc_type_symbol("typeinfo", info["mangled"])
						if info.get("msvc") else "_ZTI" + info["mangled"],
					"address": start, "size": info["length"]}
			# an MSVC `dynamic_cast` can reach the locator or the class hierarchy record instead of
			# the type descriptor; every one of them names one class, so every one is nameable
			for claims in info.get("claims", []):
				for record, words, size in ((claims.get("locator"), "complete object locator", 0x18),
						(claims.get("chd"), "class hierarchy descriptor", 16)):
					if record and record <= address < record + size:
						return {"role": words, "class": info["name"],
							"name": "%s for %s" % (words, info["name"]), "mangled": "",
							"address": record, "size": size}
		return None

	def show_lines(self, entry: int) -> list[str]:
		"""What this function is to the structure, in the words `decomp show` prints."""
		self.build()
		lines = []
		for role in self.role_of(entry):
			klass = self.classes.get(role["class"])
			if klass is None:
				continue
			lines.append("%s of %s (%s %s, %s %s)" % (role["role"], role["class"],
				self.words["table"], _hex(klass.vtable), self.words["type"], _hex(klass.typeinfo)))
			for field in klass.fields.values():
				if any(site.endswith("@ %s" % _hex(entry)) for site in field.sites):
					lines.append("touches %s +%#x (%d bytes)" % (role["class"], field.offset,
						field.size))
		for start, table in self.vtables.items():
			for index, slot in enumerate(table["slots"]):
				if slot["address"] == entry:
					info = self.typeinfos.get(table["typeinfo"], {})
					lines.append("vtable slot %d (+%#x) of %s at %s" % (index, slot["offset"],
						info.get("name", "?"), _hex(start)))
		return lines

	def role_of(self, entry: int) -> list[dict]:
		"""What this function is to the structure: a method, a constructor, a destructor."""
		self.build()
		out = []
		for klass in self.classes.values():
			role = klass.owns(entry)
			if role:
				out.append({"class": klass.name, "role": role, "vtable": klass.vtable,
					"typeinfo": klass.typeinfo})
		return out

	def summary(self) -> dict:
		self.build()
		return {"target": self.meta.get("target_path"), "target_key": self.meta.get("target_key"),
			"abi": self.abi, "bits": self.bits, "classes": len(self.classes),
			"vtables": len(self.vtables), "typeinfos": len(self.typeinfos),
			"probed": self.probed, "seconds": self.seconds,
			"notes": self.notes,
			"names": sorted(self.classes)}

	def as_json(self) -> dict:
		self.build()
		def klass_data(klass: Klass) -> dict:
			return {"name": klass.name, "mangled": klass.mangled, "bases": klass.bases,
				"typeinfo": klass.typeinfo, "vtable": klass.vtable,
				"methods": [method.__dict__ for method in klass.methods],
				"constructors": klass.constructors, "destructors": klass.destructors,
				"fields": [item.__dict__ for item in klass.fields.values()],
				"notes": klass.notes, "evidence": klass.evidence,
				"size_at_least": klass.lower_bound}
		return {**self.summary(), "detail": [klass_data(klass)
			for _, klass in sorted(self.classes.items())]}

	# -- the shared header (Docs/Design-Plan.md Phase 4 item 2) -------------------------

	def ordered_classes(self) -> list:
		"""The classes in the order a header needs them: a base before anything deriving from
		it, and names in order within that."""
		remaining = dict(sorted(self.classes.items()))
		out = []
		while remaining:
			ready = [name for name, klass in remaining.items()
				if all(base not in remaining for base in klass.bases)]
			if not ready:                      # a cycle, which the ABI does not make: take one anyway
				ready = [sorted(remaining)[0]]
			for name in sorted(ready):
				out.append((name, remaining.pop(name)))
		return out

	def header(self, *, include_guard: str = "DECOMP_RECOVERED_TYPES_H") -> str:
		"""A header a candidate can `#include`: the classes this file proves, with every
		offset where the code shows it and the evidence in the comment next to it.

		Field *names* are not recoverable from a stripped binary, so they are placeholders, and
		the value types are labelled as the guesses they are. Wrap each class in its own
		`#ifndef` so a candidate that declares the class itself can opt out of it.
		"""
		self.build()
		pointer_width = self.ptr or 8
		lines = ["// types.h - the C++ structure `decomp types` recovered from this target.",
			"// target: %s (key %s)" % (self.meta.get("target_path"),
				self.meta.get("target_key")),
			"// %s: %d/%d, classes: %d. Regenerate with: decomp types --write THIS"
				% ("vftables/type descriptors" if self.abi == "msvc" else "vtables/type_info",
					len(self.vtables), len(self.typeinfos), len(self.classes)),
			"//",
			"// Every offset below is a fact about the file and says which code proves it. The",
			"// field names are placeholders - the real ones are what the decompilation is for.",
			"// The value types are a guess from how the value is moved; the offsets and widths",
			"// are not. Delete a `vptr_` member when you declare the class's own virtual",
			"// functions: that is what puts a vptr there. Each class is behind an #ifndef so a",
			"// candidate that defines it can `#define DECOMP_CLASS_<name>` before including.",
			"#ifndef %s" % include_guard,
			"#define %s" % include_guard,
			""]
		for name in sorted(self.classes):
			if _identifiable(name):
				lines.append("class %s;" % name)
		lines.append("")
		for name, klass in self.ordered_classes():
			if not _identifiable(name):
				lines.append("// %s - this file says what the type is, but its name is nested or"
					% name)
				lines.append("// carries template arguments, so it is not one identifier and cannot "
					"be declared here.")
				lines.append("//   %s" % (klass.evidence[0] if klass.evidence else "from its RTTI"))
				continue
			lines.extend(self._class_header(klass, pointer_width))
			lines.append("")
		lines.append("#endif // %s" % include_guard)
		return "\n".join(lines) + "\n"

	def _class_header(self, klass: Klass, pointer_width: int) -> list[str]:
		# A name that is not one identifier (`.?AUX@Y@@` nests, `?$T@U@@` carries template
		# arguments) cannot appear in a base list either, so those bases stay in the comment.
		declared = [base for base in klass.bases if base in self.classes
			and _identifiable(base)]
		skipped = [base for base in klass.bases if not _identifiable(base)]
		base_clause = ""
		if declared:
			base_clause = " : public %s" % ", public ".join(declared)
		lines = ["// %s - %s" % (name_or(klass.name), klass.evidence[0] if klass.evidence else
			"recovered from its RTTI")]
		for extra in klass.evidence[1:] + klass.notes:
			lines.append("//   %s" % extra)
		for base in skipped:
			lines.append("//   base: %s - named by this file, but not declarable here" % base)
		lines.append("#ifndef DECOMP_CLASS_%s" % _macro(klass.name))
		lines.append("class %s%s" % (klass.name, base_clause))
		lines.append("{")
		lines.append("public:")
		if klass.methods:
			lines.append("\t// the vtable, in slot order. Signatures are not recoverable, so")
			lines.append("\t// these are comments: declare them yourself (and then delete vptr_).")
			for method in klass.methods:
				target = method.name or ("<null in this file>" if method.kind == "null"
					else "?")
				kind = {"pure": "pure virtual", "null": "no slot content", "import": "slot names",
					"function": "slot -> "}[method.kind]
				lines.append("\t//   slot %d +%#04x  %s %s%s" % (method.index, method.offset,
					kind, target, "  [calls operator delete: the deleting form]"
						if method.deleting else ""))
		if klass.pure_count:
			lines.append("\t// %d of %d slots are the CRT's pure-call thunk (%s), so this class is "
				"abstract." % (klass.pure_count, len(klass.methods),
					"_purecall" if self.abi == "msvc" else "__cxa_pure_virtual"))
		if klass.constructors:
			lines.append("\t// constructed at: %s" % ", ".join(_hex(item)
				for item in klass.constructors))
		if klass.destructors:
			lines.append("\t// destructors: %s" % ", ".join(_hex(item)
				for item in klass.destructors))
		lines.append("")
		# the file cannot say what the access specifier was, and a scaffold a candidate
		# has to use is more useful public than private
		lines.append("public:")
		if klass.polymorphic:
			lines.append("\tvoid *vptr_;%s// +0x00 the vptr (%s bytes here)"
				% ("\t" * (pointer_width == 4), pointer_width))
			next_offset = pointer_width
		else:
			next_offset = 0
		if not klass.fields:
			lines.append("\t// no field offset could be attributed to this class")
		for offset, item in klass.fields.items():
			if offset < next_offset:
				continue
			if offset > next_offset:
				lines.append("\tunsigned char pad_%#x_[%d];%s// +%#x..%#x, never addressed"
					% (next_offset, offset - next_offset, "\t", next_offset, offset - 1))
			type_, field = _c_type(item), _macro_field(item)
			if "[" in type_:
				# moved as one 16-byte block (an SSE store), so it is a member of that size and
				# no scalar type fits it - declared as bytes, which is what the file shows
				field, type_ = "%s[%d]" % (field, item.size), "unsigned char"
			lines.append("\t%s %s;%s// +%#x  %s%s%s" % (
				type_, field, "\t" if len(type_) < 12 else "",
				offset, _width_text(item), _kind_text(item), _sites_text(item.sites)))
			next_offset = offset + max(item.size, 1)
		lines.append("};")
		lines.append("#endif // DECOMP_CLASS_%s" % _macro(klass.name))
		# The size the class above lays out is a fact about this file; a claim that the code
		# reaches further than that is a fact about an object that is not this class - a base
		# subobject inside a derived one, or an array element - so it is said, not asserted.
		if klass.lower_bound and klass.lower_bound > next_offset:
			lines.append("// the code reaches offset %#x through this class's `this`, which the"
				% (klass.lower_bound - 1))
			lines.append("// members above do not account for: it is a base subobject inside a")
			lines.append("// derived object, or an element past the last member. No size is claimed.")
		elif next_offset:
			lines.append("static_assert(sizeof(%s) >= %d, \"the code reaches %s\");" % (klass.name,
				next_offset, "offset %#x" % (next_offset - 1)))
		return lines


# --------------------------------------------------------------------------------------
# header text helpers


def name_or(name: str) -> str:
	return name or "<unnamed>"


def _hex(value) -> str:
	"""An address as this tool writes it everywhere else."""
	return "0x%x" % value if isinstance(value, int) else str(value)


def _macro(name: str) -> str:
	return re.sub(r"[^A-Za-z0-9]", "_", name)


def _identifiable(name: str) -> bool:
	"""Can this name be written in a header at all? A nested C++ name (`Outer::Inner`) or an
	MSVC template argument list (`?$hkSingleton@V…`) is not one identifier, and declaring such a
	"class" would make the header fail to build instead of telling anyone anything.
	"""
	return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name or ""))


def _signed(value) -> int:
	"""A 32-bit field as the number it means: MSVC writes a `-1` vftable offset as 0xffffffff."""
	if not value:
		return 0
	return value - 0x100000000 if value >= 0x80000000 else value


def _macro_field(item: Field) -> str:
	return "f%#x" % item.offset


def _c_type(item: Field) -> str:
	# The type has to be as wide as the access, or the header lays the class out smaller than
	# the offsets it claims: a `movaps` through `this` is a 16-byte member, not a float.
	if item.kind == "float" and item.size == 4:
		return "float"
	if item.kind == "double" and item.size == 8:
		return "double"
	if item.size == 1:
		return "unsigned char"
	if item.size == 2:
		return "short"
	if item.size == 4:
		return "int"
	if item.size == 8:
		return "unsigned long"
	return "unsigned char[%d]" % item.size


def _width_text(item: Field) -> str:
	if not item.size:
		return "width unknown"
	return "%d bytes" % item.size


def _kind_text(item: Field) -> str:
	if item.kind in ("float", "double"):
		return ", moved as %s" % item.kind
	if item.kind == "block":
		return ", moved as a 16-byte block"
	return ""


def _sites_text(sites: list[str]) -> str:
	if not sites:
		return ""
	shown = ", ".join(sites[:3])
	return " (seen at: %s%s)" % (shown, "" if len(sites) <= 3 else ", +%d more"
		% (len(sites) - 3))


def _written_regs(instruction, handle) -> list[tuple[int, int]]:
	"""The registers an instruction writes (capstone's own answer)."""
	try:
		_read, written = instruction.regs_access()
	except Exception:  # noqa: BLE001 - a decoder without register info
		return []
	return [(reg, 0) for reg in written]


def _stack_adjustment(instruction, operands, stack_register) -> int:
	"""How much this instruction moved the stack pointer, 0 when it did not touch it.

	AT&T writes `subq $0x28,%rsp` as (imm, reg) and `addq $0x28,%rsp` the same way; a `sub`
	lowers the pointer, so every offset measured from it grows.
	"""
	from capstone import CS_OP_IMM, CS_OP_REG
	if not stack_register or len(operands) != 2 or not instruction.mnemonic.startswith(
			("add", "sub")):
		return 0
	if operands[1].type != CS_OP_REG or operands[0].type != CS_OP_IMM or \
			operands[1].reg != stack_register:
		return 0
	amount = operands[0].imm
	return amount if instruction.mnemonic.startswith("sub") else -amount
