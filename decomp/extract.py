"""Pull one function's bytes and its references out of a file, on either side of a diff.

Original side (`original_function`): the analysis cache already has the function's bytes,
Ghidra's instruction boundaries, and every reference resolved to a name - that is what makes
`decomp try` work on a stripped binary with no JVM running. Where a *value* is needed (the
bytes of a string or a table the function reads) it is read from the target file itself,
which needs the Ghidra-to-file address offset `analyze` recorded.

Candidate side (`CandidateObject`): a `.o` built by `decomp compile`. A relocatable object
has no final addresses, so the names come from its symbol and relocation tables instead -
which is exactly the other half of "both sides compare symbolically".
"""

from __future__ import annotations

import json
import sqlite3
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import cache, normalize
from .normalize import Ref, clean_symbol, demangle, is_synthetic

# Reading the bytes at a reference is only meaningful where the file and the object hold the
# same bytes: read-only initialised sections. A pointer in .data/.got is link-relative.
_COMPARABLE = (".rodata", ".rdata", ".text", ".data.rel.ro")

# ELF section flags (SHF_*).
_SHF_WRITE, _SHF_ALLOC, _SHF_EXECINSTR = 0x1, 0x2, 0x4
# PE and COFF share one flag word (IMAGE_SCN_*).
_SCN_CNT_UNINITIALIZED, _SCN_CNT_CODE = 0x00000080, 0x00000020
_SCN_MEM_DISCARDABLE, _SCN_MEM_WRITE, _SCN_MEM_EXECUTE = 0x00008000, 0x80000000, 0x20000000


def _section_flags(section) -> tuple[object, str]:
	"""A section's flag word, and how this format spells it: ELF says `flags`, PE and COFF
	both say `characteristics`. Reading the wrong one is an AttributeError out of a working
	tool, which is what happened to every command that touches a PE."""
	for attribute, spelling in (("flags", "elf"), ("characteristics", "pe")):
		try:
			value = getattr(section, attribute)
		except AttributeError:
			continue
		if value is not None:
			return value, spelling
	return None, ""


def _machine_name(header) -> str:
	"""The machine a header names, however this format spells it (ELF says `machine_type`,
	PE and COFF say `machine`)."""
	for attribute in ("machine_type", "machine"):
		try:
			value = getattr(header, attribute)
		except AttributeError:
			continue
		if value is not None:
			return str(value).rsplit(".", 1)[-1]
	return ""


def _bits_of(header, machine: str) -> int:
	"""32 or 64. ELF and PE say it in `identity_class`; a COFF object header has no such field
	(it says `kind` = EXEC/OBJ instead), so there the machine has to say it."""
	try:
		text = str(header.identity_class)
	except AttributeError:
		text = ""
	if "64" in text:
		return 64
	if "32" in text:
		return 32
	name = machine.upper()
	if name in ("AMD64", "ARM64", "ARM64EC", "IA64"):
		return 64
	if name in ("I386", "ARM", "ARMNT", "THUMB"):
		return 32
	return 0


def section_capabilities(fmt, section) -> tuple[bool, bool, bool]:
	"""(allocated, writable, executable) of a section, however this format spells its flags.

	LIEF hands back an int for ELF, PE and COFF (`str(section.flags)` is literally "6") and an
	enum elsewhere, so the flag test is done per format here rather than by string matching -
	which matters: string matching silently read every ELF section as neither allocated nor
	writable. `fmt` may be None: a COFF object has no `binary.format`.
	"""
	raw, spelling = _section_flags(section)
	if not isinstance(raw, int):
		text = str(raw).upper()
		return ("ALLOC" in text or "MEM" in text), "WRITE" in text, ("EXEC" in text or "CODE" in text)
	format_name = str(fmt or "").upper()
	if spelling == "elf" or "ELF" in format_name:
		return bool(raw & _SHF_ALLOC), bool(raw & _SHF_WRITE), bool(raw & _SHF_EXECINSTR)
	if spelling == "pe" or "PE" in format_name or "COFF" in format_name:
		# A PE/COFF section has no ALLOC bit: the loader maps whatever it is given bytes for.
		# What is not mapped is a discardable section and an initialised-but-empty one
		# (IMAGE_SCN_CNT_UNINITIALIZED, a `.bss`), which has no file bytes to read. And
		# IMAGE_SCN_MEM_EXECUTE and IMAGE_SCN_CNT_CODE both say "code" - the first is what the
		# loader enforces, the second what the compiler wrote - so they are alternatives here,
		# never a pair to AND together.
		return (not raw & (_SCN_MEM_DISCARDABLE | _SCN_CNT_UNINITIALIZED),
			bool(raw & _SCN_MEM_WRITE),
			bool(raw & _SCN_MEM_EXECUTE) or bool(raw & _SCN_CNT_CODE))
	return True, False, False


# Where an object's data lives: pointer tables (vtables, GOT-like tables) and ordinary data.
_POINTER_SECTIONS = (".data.rel.ro", ".rodata", ".rdata", ".data", ".got", ".got.plt",
	".init_array", "__DATA")

# The function table a file carries itself. An x64 PE's `.pdata` is the unwind table the loader
# reads: (begin, end, unwind) for every function, with no symbols, after stripping - the
# compiler's own answer to "where does this unit end", and the only one a shipped proprietary
# binary gives (Docs/MSVC-Plan.md §4). ELF answers the same question twice: `.eh_frame`'s FDEs
# (one per function *partition*, so a hot/cold split at -O2 gives two), and `st_size` where the
# file kept its symbols. Phase 5 reads both; Mach-O carries neither.
_PDATA_RECORD = struct.Struct("<III")

# DW_EH_PE_* - the pointer encodings `.eh_frame` writes its pc values in (DWARF §7.6.4, and the
# Itanium C++ ABI's LSDA chapter, which is where GCC and LLVM take them). Two spellings of the
# *signed* forms are in the wild (DWARF >= 3 numbers them 0x05..0x08, the older libdwarf table
# 0x09..0x0c); both are accepted here, because a real GCC object writes 0x1b = pcrel|sdata4
# while a DWARF-spelled one writes 0x17 for the same thing.
_PE_FORMAT = 0x0f
_PE_PC_REL, _PE_TEXTREL, _PE_DATA_REL, _PE_FUNC_REL, _PE_INDIRECT = 0x10, 0x20, 0x30, 0x40, 0x80
_PE_ULEB, _PE_SLEB, _PE_PTR = "uleb", "sleb", "ptr"
_PE_FORMS = {
	0x00: (_PE_PTR, False), 0x01: (_PE_ULEB, False), 0x02: (2, False), 0x03: (4, False),
	0x04: (8, False), 0x05: (_PE_SLEB, True), 0x06: (2, True), 0x07: (4, True),
	0x08: (8, True), 0x09: (_PE_SLEB, True), 0x0a: (2, True), 0x0b: (4, True), 0x0c: (8, True),
}


def _sleb(data: bytes, position: int) -> tuple[int, int]:
	value = 0
	shift = 0
	while position < len(data):
		octet = data[position]
		position += 1
		value |= (octet & 0x7f) << shift
		shift += 7
		if not octet & 0x80:
			if octet & 0x40:
				value -= 1 << shift
			return value, position
	raise ValueError("truncated SLEB in .eh_frame")


def _uleb(data: bytes, position: int) -> tuple[int, int]:
	value = 0
	shift = 0
	while position < len(data):
		octet = data[position]
		position += 1
		value |= (octet & 0x7f) << shift
		if not octet & 0x80:
			return value, position
		shift += 7
	raise ValueError("truncated ULEB in .eh_frame")


def _read_encoded(data: bytes, position: int, encoding: int, *, at: int, pointer_size: int) -> tuple[int | None, int]:
	"""One `.eh_frame` pointer value: (the address it means, the next position).

	`at` is the section offset of the field itself, which is what a pc-relative value is added
	to. The next position is returned even when the value cannot be resolved: an indirect slot
	or one the link still has to write is a location in the table, not a pc, but its *size* is
	still what says where the next field starts.
	"""
	form, signed = _PE_FORMS.get(encoding & _PE_FORMAT, (_PE_PTR, False))
	if form is _PE_ULEB:
		value, position = _uleb(data, position)
	elif form is _PE_SLEB:
		value, position = _sleb(data, position)
	elif isinstance(form, int):
		if position + form > len(data):
			raise ValueError("truncated encoded pointer in .eh_frame")
		value = int.from_bytes(data[position:position + form], "little", signed=signed)
		position += form
	else:
		width = pointer_size
		if position + width > len(data):
			raise ValueError("truncated encoded pointer in .eh_frame")
		value = int.from_bytes(data[position:position + width], "little", signed=signed)
		position += width
	if encoding & _PE_PC_REL:
		value += at
	elif encoding & (_PE_TEXTREL | _PE_DATA_REL | _PE_FUNC_REL):
		# relative to a base only the runtime knows (a shared library's text/data base, a
		# function's start): unresolvable in the file, and never used for an FDE pc by GCC
		return None, position
	if encoding & _PE_INDIRECT:
		return None, position
	return value, position

# How many bytes of a referenced object are compared when its size is not recorded.
_PROBE = 16
_WINDOW = 64


@dataclass
class Function:
	"""One function's bytes in one address domain, plus how to read its references."""

	display: str                      # what to call it to a human
	raw_name: str                     # as the file named it
	address: int                      # address `bytes` decode at
	size: int
	bytes: bytes = b""
	section: str = ""
	boundaries: list[tuple[int, int]] = field(default_factory=list)
	# Where the body actually sits: (address, length) per block, the entry block first. A unit
	# whose bytes are contiguous has one; a `-O2` function with a cold partition has two, in the
	# order its blocks are compared (Phase 5). Empty means `address`/`size`, i.e. one block.
	extents: list[tuple[int, int]] = field(default_factory=list)
	language_note: str = ""           # arch/format, for error messages
	warnings: list[str] = field(default_factory=list)

	def __post_init__(self) -> None:
		if not self.extents:
			self.extents = [(self.address, self.size)]


# --------------------------------------------------------------------------------------
# the original side: the analysis cache, plus the target file for values


def file_address_base(binary) -> int:
	"""What has to be added to this file's section addresses to get the addresses everything
	here is keyed by: the analysis' addresses, and the ones objdump prints.

	A PE section header gives an RVA and its loader adds the image base; Ghidra loads the image
	at that same image base, so the answer for a PE is `imagebase` and the address offset the
	analysis records is 0. ELF and Mach-O section headers already carry load addresses, so it is
	0 there. (Docs/MSVC-Plan.md §8: this is the bias that, forgotten once, makes every address
	in the tool "no such function".)
	"""
	import lief

	try:
		if isinstance(binary, lief.PE.Binary):
			return int(getattr(binary, "imagebase", 0) or 0)
	except (AttributeError, TypeError):  # pragma: no cover - a LIEF without PE support
		pass
	return 0


class TargetImage:
	"""Byte access into the analysed file, by the address the *analysis* uses."""

	def __init__(self, path: Path, address_offset: int = 0) -> None:
		self.path = path
		self.offset = int(address_offset)
		self.sections: list[tuple[str, int, int, int, bool, bool]] = []
		self.error = ""
		# The file's own function table, in the *file's* addresses (the same domain
		# `self.sections` is in): `analysis_units()` biases it into the analysis' ones.
		self.units: list[dict] = []
		self.unit_source = ""
		self.unit_note = ""
		# slot address (in the analysis' domain) -> what the link writes there. In a PIE the
		# file bytes of .data/.data.rel.ro are zeros and the value lives in the relocation's
		# addend, so a pointer table can only be read from the relocations.
		self.pointers: dict[int, int] = {}
		# ... and the slots whose value is an imported symbol (a pure-virtual slot, a method
		# of another translation unit): no address to read, only a name.
		self.named_pointers: dict[int, str] = {}
		try:
			import lief
		except ImportError as exc:  # pragma: no cover - `decomp check` reports this
			self.error = "lief is not importable: %s" % exc
			return
		try:
			binary = lief.parse(str(path))
		except Exception as exc:  # noqa: BLE001
			self.error = "lief could not parse %s: %s" % (path.name, exc)
			return
		if binary is None:
			self.error = "lief could not parse %s" % path.name
			return
		for section in binary.sections:
			if not section.size:
				continue
			allocated, writable, _executable = section_capabilities(
				getattr(binary, "format", None), section)
			self.sections.append((str(section.name),
				int(section.virtual_address) + file_address_base(binary), int(section.size),
				int(section.offset), allocated, writable))
		try:
			self._read_pointers(binary)
		except Exception:  # noqa: BLE001 - pointer tables are a discovery nicety, not a requirement
			self.pointers = {}
		try:
			self._read_function_table(binary)
		except Exception as exc:  # noqa: BLE001 - a unit table is an extra source of truth, not a
			self.units = []  # requirement, and a LIEF that cannot read .pdata must not break `try`
			self.unit_note = "reading the function table failed: %s" % exc

	def _read_function_table(self, binary) -> None:
		"""The function table the file carries itself, in the file's own addresses.

		Two formats answer this, and neither is the disassembler's guess: an x64 PE's `.pdata`
		gives (begin, end, unwind) per function, and an ELF's `.eh_frame` gives one FDE per
		function *partition* - so a `-O2` function with a cold partition has two, which is how
		Phase 5 learns where its second half is. Where the file still has symbols, `st_size`
		corroborates both. Every address in it is in the same domain as `self.sections`: for a
		PE that means the image base is added (`file_address_base`), the bias MS-0 put in one
		place for exactly this reason (Docs/MSVC-Plan.md §8).
		"""
		import lief

		if isinstance(binary, lief.PE.Binary):
			self._read_pdata(binary)
			return
		if isinstance(binary, lief.ELF.Binary):
			found = 0
			try:
				found += self._read_eh_frame(binary)
			except Exception as exc:  # noqa: BLE001 - an unwinder table is evidence, not a requirement
				self.unit_note = "reading .eh_frame failed: %s" % exc
			found += self._read_symbol_sizes(binary)
			if not found:
				self.unit_note = ("no .eh_frame and no symbol sizes: this ELF carries no function "
					"table, so a unit's extent comes from the analysis alone")
			return
		self.unit_note = "this file format carries no function table the tool knows"

	def _add_unit(self, source: str, entry: int, end: int, unwind: int = 0) -> int:
		"""One unit, merged with what another table says about the same entry.

		`st_size` and an FDE usually agree; where they do not, the wider one is kept, because a
		symbol's size stops at a hot partition while an FDE's range covers a whole one. The
			sources are recorded so the disagreement can be reported rather than hidden.
		"""
		if end <= entry:
			return 0
		for unit in self.units:
			if unit["entry"] != entry:
				continue
			if source not in unit["sources"]:
				unit["sources"] += [source]
			if end > unit["end"]:
				unit["end"], unit["size"], unit["source"] = end, end - entry, source
			return 0
		self.units.append({"source": source, "sources": [source], "entry": entry, "end": end,
			"size": end - entry, "unwind": int(unwind), "section": self._section_name(entry)})
		return 1

	def _read_pdata(self, binary) -> None:
		"""`.pdata`, the (begin, end, unwind) table an x64 PE carries.

		Only the bytes the file initialises are walked: a PE section's `size` is its virtual
		size, which pads past the table, and reading that padding as records would invent
		zero-length units.
		"""
		section = next((item for item in binary.sections if str(item.name) == ".pdata"), None)
		if section is None or not section.size:
			self.unit_note = "no .pdata section: this PE carries no function table"
			return
		data = bytes(section.content)
		bias = file_address_base(binary)
		count = skipped = 0
		for position in range(0, len(data) - len(data) % _PDATA_RECORD.size, _PDATA_RECORD.size):
			begin, end, unwind = _PDATA_RECORD.unpack_from(data, position)
			if end <= begin:
				skipped += 1
				continue
			count += self._add_unit(".pdata", int(begin) + bias, int(end) + bias,
				int(unwind) + bias)
		self.unit_source = ".pdata"
		if not count:
			self.unit_note = ".pdata holds no readable function record"
		elif skipped:
			self.unit_note = "%d .pdata record(s) skipped: end <= begin" % skipped

	def _read_eh_frame(self, binary) -> int:
		"""Every FDE in `.eh_frame`: (initial pc, address range) for one partition of a function.

		The unwinder table is what bounds a unit in a *stripped* ELF - `st_size` is gone, but the
		exception handling data is not, because the runtime still needs it. A `-O2` build splits
		the cold blocks of a function into their own FDE (measured on `Tests/build/gcc-o2`:
		`RunSelfChecks` has one at 0x44d0..0x5c15 and one at 0x1140..0x1768), which is the other
		half of a body the analysis reports as two ranges.
		"""
		section = next((item for item in binary.sections if str(item.name) == ".eh_frame"), None)
		if section is None or not section.size:
			return 0
		data = bytes(section.content)
		base = int(section.virtual_address) + file_address_base(binary)
		bits = getattr(getattr(binary, "header", None), "identity_class", None)
		pointer_size = 8 if "64" in str(bits) else 4
		encodings: dict[int, int] = {}
		position = 0
		count = failed = 0
		while position + 12 <= len(data):
			length = int.from_bytes(data[position:position + 4], "little")
			if length == 0:
				position += 4
				continue
			if length < 4 or position + length + 4 > len(data):
				break
			identifier = int.from_bytes(data[position + 4:position + 8], "little")
			if identifier == 0:
				encoding = self._read_cie(data, position, pointer_size)
				if encoding is not None:
					encodings[position] = encoding
			else:
				# a CIE is named by how far back its start sits from the byte after this field
				cie = position + 8 - identifier
				encoding = encodings.get(cie, _PE_PC_REL | 0x0b)
				try:
					pc, next_position = _read_encoded(data, position + 8, encoding,
						at=base + position + 8, pointer_size=pointer_size)
					# the range uses the same form as the pc, without its pc-relative bit (the Itanium
					# ABI's FDE layout, which is what GCC and LLVM write for a C++ .eh_frame)
					size, _ = _read_encoded(data, next_position, encoding & _PE_FORMAT,
						at=0, pointer_size=pointer_size)
				except ValueError:
					failed += 1
					pc, size = None, 0
				if pc is not None and size:
					count += self._add_unit(".eh_frame", pc, pc + size, position)
			position += length + 4
		if count:
			self.unit_source = self.unit_source or ".eh_frame"
		self.units.sort(key=lambda unit: unit["entry"])
		if failed:
			self.unit_note = "%d FDE(s) could not be decoded" % failed
		return count

	@staticmethod
	def _read_cie(data: bytes, position: int, pointer_size: int) -> int | None:
		"""The FDE pointer encoding a CIE declares (its augmentation's `R` parameter)."""
		try:
			version = data[position + 8]
			cursor = position + 9
			end = position + 4 + int.from_bytes(data[position:position + 4], "little")
			stop = data.index(0, cursor)
			augmentation = data[cursor:stop].decode("ascii", "replace")
			cursor = stop + 1
			if version == 1:
				_cursor, _ = _uleb(data, cursor)  # code alignment factor
				cursor = _cursor
				cursor, _ = _sleb(data, cursor)  # data alignment factor
				cursor, _ = _uleb(data, cursor)  # return address register
			else:
				cursor, _ = _uleb(data, cursor)  # return address register
				cursor, _ = _uleb(data, cursor)  # code alignment factor
				cursor, _ = _sleb(data, cursor)  # data alignment factor
			if augmentation.startswith("z"):
				cursor += 1  # the LSDA encoding, which is one byte in every form in use
				if version >= 2:
					augment, cursor = _uleb(data, cursor)
					end = min(end, cursor + augment)
				if "P" in augmentation[1:]:
					_, cursor = _read_encoded(data, cursor, data[cursor], at=cursor,
						pointer_size=pointer_size)
			for character in augmentation[1:]:
				if character == "R":
					return data[cursor] if cursor < end else None
				if character in "SL":
					_, cursor = _read_encoded(data, cursor, data[cursor], at=cursor,
						pointer_size=pointer_size)
				else:
					cursor += 1
		except (ValueError, IndexError):
			return None
		return None

	def _read_symbol_sizes(self, binary) -> int:
		"""`st_size` of every function symbol - what the file's own names say about a unit.

		A symbol's size covers its hot partition only, so it never *widens* an FDE; `_add_unit`
		keeps the wider of the two and notes both. In a linked image `st_value` is an address,
		which is the domain `self.sections` is in; in a `.o` it is an offset in a section, and
		that case never reaches here (`TargetImage` is only built for the target file).
		"""
		count = 0
		for symbol in binary.symbols:
			try:
				if not symbol.size or not symbol.is_function:
					continue
				entry = int(symbol.value)
			except Exception:  # noqa: BLE001 - a symbol with no section carries nothing
				continue
			count += self._add_unit("symtab", entry, entry + int(symbol.size))
		if count:
			self.unit_source = self.unit_source or "symtab"
		return count

	def unit_at(self, entry: int) -> dict | None:
		"""The unit the file's table says *starts* here, in the *analysis'* addresses.

		`original_function` uses this when the cache has no unit table of its own (a cache written
		before Phase 5 added the ELF one), so an old cache still gets the compiler's extent.
		"""
		for unit in self.units:
			if unit["entry"] + self.offset == int(entry):
				return {**unit, "entry": unit["entry"] + self.offset,
					"end": unit["end"] + self.offset}
		return None

	def _section_name(self, file_address: int) -> str:
		for name, virtual, size, _offset, allocated, _writable in self.sections:
			if allocated and virtual <= file_address < virtual + size:
				return name
		return ""

	def analysis_units(self) -> list[dict]:
		"""The file's function table in the addresses the *analysis* uses (add the offset).

		For a PE the offset is 0 - Ghidra loads the image at its own image base - but writing the
		units into the cache without biasing them is how a unit ends up "no such function".
		"""
		return [{**unit, "entry": unit["entry"] + self.offset, "end": unit["end"] + self.offset,
			"unwind": unit["unwind"] + self.offset} for unit in self.units]

	def _read_pointers(self, binary) -> None:
		"""The pointer slots a linked image writes at load time (R_*_RELATIVE and friends).

		A dynamic relocation has no section (`has_section` is False there), so the slots are
		found by address, and a candidate target is kept only if it lands inside the image -
		which is what separates a pointer slot from a GOT offset or an import.
		"""
		mapped = [(virtual, virtual + size) for _name, virtual, size, _offset, allocated, _writable
			in self.sections if allocated and size]
		for source in ("dynamic_relocations", "object_relocations"):
			try:
				items = list(getattr(binary, source, []))
			except Exception:  # noqa: BLE001
				continue
			for item in items:
				try:
					slot = int(item.address) + self.offset
					target = int(item.addend)
					if item.has_symbol and item.symbol is not None:
						try:
							value = int(item.symbol.value)
						except Exception:  # noqa: BLE001 - an import has no value to read
							value = 0
						if not value:
							# a symbol with no address: an import (a pure-virtual slot, a
							# helper of another translation unit). Note that LIEF attaches a
							# nameless pseudo-symbol to R_*_RELATIVE relocations, whose value
							# *is* the addend, so only a named one counts as an import.
							name = str(item.symbol.name or "")
							if name:
								self.named_pointers[slot] = name
								continue
						else:
							target = value + target
					if target <= 0 or not any(low <= target < high for low, high in mapped):
						continue
					self.pointers[slot] = target + self.offset
				except Exception:  # noqa: BLE001
					continue

	def _locate(self, address: int, any_section: bool = False):
		file_address = address - self.offset
		for name, virtual, size, file_offset, allocated, writable in self.sections:
			if not allocated or not virtual <= file_address < virtual + size:
				continue
			if not any_section:
				if writable or not name.startswith(_COMPARABLE):
					continue
			elif not name.startswith(_POINTER_SECTIONS):
				continue
			return name, file_offset + (file_address - virtual), size - (file_address - virtual)
		return None

	def read(self, address: int, length: int) -> bytes | None:
		"""The initialised, read-only bytes at an analysed address, or None."""
		return self._read(address, length, any_section=False)

	def read_data(self, address: int, length: int) -> bytes | None:
		"""Bytes of an initialised data section, writable ones included (in a PIE the values
		there are still zeros - see `pointers`)."""
		return self._read(address, length, any_section=True)

	def _read(self, address: int, length: int, any_section: bool) -> bytes | None:
		where = self._locate(address, any_section)
		if where is None or self.error:
			return None
		_, offset, available = where
		try:
			with self.path.open("rb") as handle:
				handle.seek(offset)
				return handle.read(min(int(length), max(0, available)))
		except OSError:  # pragma: no cover
			return None

	def data_sections(self) -> list[tuple[str, int, int]]:
		"""(name, address, size) of the initialised data sections, in the analysis' domain."""
		return [(name, virtual + self.offset, size) for name, virtual, size, _offset, allocated,
			_writable in self.sections
			if allocated and size and name.startswith(_POINTER_SECTIONS)]


def _hexkey(value) -> str:
	return "%x" % value if isinstance(value, int) else str(value)


def _string_lengths(conn: sqlite3.Connection, addresses: list[int]) -> dict[int, tuple[int, str]]:
	if not addresses:
		return {}
	marks = ",".join("?" * len(addresses))
	rows = conn.execute("SELECT address, length, value FROM strings WHERE address IN (%s)" % marks,
		addresses)
	return {row["address"]: (int(row["length"] or 0), row["value"]) for row in rows}


def _hex(value) -> str:
	return "0x%x" % int(value)


# A gap between two of the analysis' ranges this wide is alignment padding inside one block:
# Ghidra ends a function before the padding the compiler put after it and resumes it after, so
# the ranges are one block of one unit. Wider than any function alignment and the blocks are
# genuinely elsewhere - a cold partition of the same function, which is its own extent.
_PAD_GAP = 0x40


def _entry_block(ranges: list[list[int]], entry: int, size: int) -> tuple[int, int]:
	"""The block of one unit that the entry sits in, ranges and padding gaps merged."""
	block = next(([start, stop] for start, stop in ranges if start <= entry < stop), None)
	if block is None:
		block = list(ranges[0]) if ranges else [entry, entry + size]
	changed = True
	while changed:
		changed = False
		for start, stop in ranges:
			if start <= block[1] + _PAD_GAP and block[0] <= stop + _PAD_GAP:
				if start < block[0] or stop > block[1]:
					block = [min(block[0], start), max(block[1], stop)]
					changed = True
	return block[0], block[1]


def original_function(conn: sqlite3.Connection, meta: dict, row: sqlite3.Row,
	size: int | None = None) -> Function:
	"""The cached bytes and instruction boundaries of one analysed function.

	What a unit *is* - how many bytes, in how many pieces - is decided here, in this order:

	1. `size`, when the caller named a range (a `.o`'s symbol size, an answer key);
	2. the function table the file carries itself - `.pdata`, an ELF's `.eh_frame`, `st_size` -
	   which is the compiler's own boundary rather than a disassembler's recovery (MS-1 for a PE,
	   Phase 5 for ELF, where it is what makes a stripped `-O2` target scoreable at all);
	3. the analysis' own ranges, read as one block across the padding gaps between them; and
	4. the analysis' body, alone.

	A range the analysis puts outside that block stays a separate extent: a `-O2` function's cold
	blocks are linked into another part of `.text` entirely (and built into `.text.unlikely` in
	the candidate's `.o`), so the two sides are compared as entry block then cold block.
	"""
	entry = int(row["entry"])
	full = int(row["size"])
	warnings: list[str] = []
	try:
		ranges = sorted(([int(a), int(b)] for a, b in json.loads(row["ranges"] or "[]")))
	except (ValueError, TypeError):  # pragma: no cover - written by us
		ranges = []
	image = None

	start, end = _entry_block(ranges, entry, full)
	source = "the analysis' own ranges"
	if size:
		start, end, source = entry, entry + int(size), "--size"
	else:
		unit = cache.unit_at(conn, entry)
		live = False
		if unit is None:
			# a cache written before this table existed: read it from the file now rather than
			# losing the compiler's boundary to an old analysis
			image = TargetImage(Path(meta.get("target_path") or ""), cache.address_offset(meta))
			unit = image.unit_at(entry)
			live = unit is not None
		if unit is not None and int(unit["end"]) - entry != end - start:
			if live:
				warnings.append("this analysis cache has no unit table (it predates `analyze` "
					"reading one), so the boundary below was read from %s now" % meta.get("target_path"))
			warnings.append("the analysis' body of this function is %d bytes but %s says the unit "
				"is %d (%s..%s): the %d bytes between are inside the unit, so they are compared "
				"too - %s is the compiler's own boundary, not a disassembler's recovery"
				% (end - start, unit["source"], int(unit["end"]) - entry, _hex(entry),
					_hex(int(unit["end"])), abs(int(unit["end"]) - entry - (end - start)),
					unit["source"]))
			start, end, source = entry, int(unit["end"]), unit["source"]
		elif len(ranges) > 1 and end - start != full:
			warnings.append("the analysis records %d ranges for this function, split at alignment "
				"padding; they are read as one %d byte block (%s..%s) because the bytes between "
				"them are inside the unit and the candidate has them too"
				% (len(ranges), end - start, _hex(start), _hex(end)))

	# Blocks the analysis assigns to this function but outside the entry block: a cold partition.
	extents = [(start, end - start)]
	for other_start, other_stop in ranges:
		if other_stop <= start or other_start >= end:
			extents.append((other_start, other_stop - other_start))
			warnings.append("the analysis places a %d byte block of this function at %s..%s, away "
				"from its entry block (a -O2 cold partition; in the candidate this is the symbol's "
				".cold part): it is compared after the entry block, and branches to it are "
				"compared by their position in the unit"
				% (other_stop - other_start, _hex(other_start), _hex(other_stop)))

	bodies: list[bytes] = []
	for index, (where, length) in enumerate(extents):
		if index == 0 and (where, length) == (entry, full) and row["bytes"]:
			bodies.append(bytes(row["bytes"]))
			continue
		image = image or TargetImage(Path(meta.get("target_path") or ""),
			cache.address_offset(meta))
		data = image.read(where, length)
		if data is None or len(data) < length:
			if index == 0 and row["bytes"]:
				warnings.append("the unit's bytes could not be read from %s%s, so the analysis' own "
					"%d bytes are compared instead" % (meta.get("target_path"),
						(": " + image.error) if image.error else "", full))
				bodies.append(bytes(row["bytes"]))
				extents = [(entry, full)]
				break
			warnings.append("the %d bytes at %s could not be read from %s%s, so that block is not "
				"compared" % (length, _hex(where), meta.get("target_path"),
					(": " + image.error) if image.error else ""))
			continue
		bodies.append(data)
	body = b"".join(bodies)
	if not body:
		warnings.append("nothing to compare: the cache holds no bytes for this function and %s "
			"could not supply them" % meta.get("target_path"))

	covered = [(where, where + length) for where, length in extents]
	boundaries = [(int(item["address"]), int(item["length"]))
		for item in cache.instructions(conn, row["id"])
		if any(where <= int(item["address"]) < stop for where, stop in covered)]
	return Function(display=row["name"], raw_name=row["name"], address=start, size=len(body),
		bytes=body, section=row["section"] or "", boundaries=boundaries, extents=extents,
		language_note=meta.get("language_id") or "", warnings=warnings)


def _unit_size(conn: sqlite3.Connection, image, entry: int) -> int | None:
	"""How big the file's own tables say the unit starting here is, if they name one.

	The same three sources as `original_function`, in the same order of trust. A call to a
	*neighbour* in the same file is compared by that callee's size, so both sides have to be
	measuring it the same way - the analysis' body of a `-O2` function is not the compiler's
	size of it, which is what makes a matching call look like a difference.
	"""
	row = cache.unit_at(conn, int(entry))
	if row is not None:
		return int(row["size"]) or None
	if image is not None:
		unit = image.unit_at(int(entry))
		if unit is not None:
			return int(unit["size"]) or None
	return None


def original_bindings(conn: sqlite3.Connection, meta: dict, row: sqlite3.Row,
	image: TargetImage | None = None, structures=None) -> tuple[callable, list[Ref]]:
	"""A `bind(instruction)` for the tokeniser, built from the resolved references.

	Each cached reference knows the instruction it came from and the address it points at, so
	it binds to the operand that encodes that same address - no guessing.

	`structures` (a `decomp.structures.Recovery`) is what lets a reference to a vtable or a
	type_info be named: in a stripped PIE those objects are `PTR_vtable_00111d78` to the
	analysis, while the candidate's `.o` relocates against `_ZTI14CVehicleEntity`. RTTI says
	the same thing about the same bytes, so both sides can say "typeinfo for CVehicleEntity"
	and a difference there means something (Phase 4).
	"""
	rows = cache.refs(conn, row["id"])
	by_address: dict[int, list[sqlite3.Row]] = {}
	for item in rows:
		by_address.setdefault(int(item["address"]), []).append(item)
	targets = sorted({int(item["to_address"]) for item in rows if item["to_address"] is not None})
	sizes = _string_lengths(conn, targets)
	functions = {int(item["entry"]): item
		for item in conn.execute("SELECT id, entry, name, size, kind, bytes FROM functions"
			" WHERE entry IN (%s)" % ",".join("?" * len(targets)), targets)} if targets else {}
	if image is None:
		image = TargetImage(Path(meta.get("target_path") or ""), cache.address_offset(meta))
	ranked = {"address": 0, "label": 1, "function": 2, "external": 3}
	seen: dict[str, Ref] = {}
	used: list[Ref] = []

	def build(item: sqlite3.Row) -> Ref:
		key = "%s:%s" % (item["ref_type"], item["to_address"])
		if key in seen:
			return seen[key]
		kind = item["to_kind"] or "unknown"
		to_address = int(item["to_address"]) if item["to_address"] is not None else None
		name = clean_symbol(item["to_name"] or "") if kind != "address" else ""
		if kind == "address":
			name = ""
		function = functions.get(to_address)
		ref = Ref(kind=kind, raw=item["to_name"] or "", name=name, address=to_address,
			section=item["section"] or "")
		if structures is not None and to_address is not None and kind != "function":
			object_ = structures.object_at(to_address)
			if object_:
				# the file's own name for this object, as the candidate's symbol names it
				ref.name = object_["name"] or ref.name
				ref.identity = "%s@%s" % (object_["role"], _hexkey(object_["address"]))
				ref.size = ref.size or object_["size"]
				ref.content = None   # a vtable is pointers; its bytes are never comparable
		if function is not None:
			# a body's bytes are not comparable (in a `.o` the references inside it are
			# still placeholders), but its size is, and that is what catches "same shape,
			# different helper" - so it has to be the size the compiler said, from the file's
			# own table where the file carries one
			ref.size = _unit_size(conn, image, to_address) or int(function["size"]) or None
		elif to_address is not None:
			declared, _value = sizes.get(to_address, (0, ""))
			ref.size = declared or None
			ref.content = image.read(to_address, declared or _PROBE)
		seen[key] = ref
		used.append(ref)
		return ref

	def bind(instruction) -> dict[int, Ref]:
		here = by_address.get(int(instruction.address), [])
		if not here or not instruction.slots:
			return {}
		chosen: dict[int, Ref] = {}
		slots = list(instruction.slots)
		# exact first: the operand encodes the address this reference points at
		for slot in slots:
			if slot.value is None:
				continue
			# a reference with no address (an import) is not the same thing as an operand that
			# encodes address 0, so the comparison is made only on real addresses
			match = sorted((item for item in here if item["to_address"] is not None
				and int(item["to_address"]) == int(slot.value)),
				key=lambda item: -ranked.get(item["to_kind"] or "address", 0))
			if match:
				chosen[slot.operand] = build(match[0])
		# then anything left over, only when the pairing is unambiguous
		left = [item for item in here if item["to_address"] is not None and not any(
			int(item["to_address"]) == slot.value for slot in slots if slot.value is not None)]
		free = [slot for slot in slots if slot.operand not in chosen and slot.kind != "imm"]
		if not free:
			free = [slot for slot in slots if slot.operand not in chosen]
		if left and len(left) == 1 and len(free) == 1:
			chosen[free[0].operand] = build(left[0])
		return chosen

	return bind, used


# --------------------------------------------------------------------------------------
# the candidate side: a relocatable object produced by decomp.compile


def _hex(value) -> str:
	return "0x%x" % int(value)


class SymbolNotFound(Exception):
	"""No candidate symbol matched (or several did) - the message names what is there."""


@dataclass
class CandidateSymbol:
	mangled: str
	name: str                      # demangled
	simple: str                    # demangled without the parameter list
	value: int
	size: int
	section: str


class CandidateObject:
	"""Symbols, bytes and relocations of a `.o`, as needed to score one function."""

	def __init__(self, path: Path) -> None:
		self.path = Path(path)
		self.error = ""
		self.machine = ""
		self.bits = 0
		self.functions: list[CandidateSymbol] = []
		self._sections: dict[str, bytes] = {}
		self._writable: set[str] = set()
		self._by_section_address: dict[tuple[str, int], CandidateSymbol] = {}
		self._all_symbols: dict[str, tuple[str, int, int, bool]] = {}
		self._relocs: dict[str, list[tuple[int, str, str, int]]] = {}
		# the (section, address, length) of the last function handed back by `function()`, which
		# is what its relocations have to be looked up in (a -O2 candidate spans two sections)
		self._extent_sections: list[tuple[str, int, int]] = []
		try:
			import lief
		except ImportError as exc:  # pragma: no cover
			self.error = "lief is not importable: %s" % exc
			return
		try:
			binary = lief.parse(str(self.path))
		except Exception as exc:  # noqa: BLE001
			self.error = "lief could not parse %s: %s" % (self.path.name, exc)
			return
		if binary is None:
			self.error = "lief could not parse %s" % self.path.name
			return
		try:
			header = binary.header
			self.machine = _machine_name(header)
			self.bits = _bits_of(header, self.machine)
			for section in binary.sections:
				if not section.size:
					continue
				name = str(section.name)
				if section_capabilities(getattr(binary, "format", None), section)[1]:
					self._writable.add(name)
				self._sections[name] = bytes(section.content)
			self._read_symbols(binary)
			self._read_relocations(binary)
		except Exception as exc:  # noqa: BLE001
			self.error = "while reading %s: %s" % (self.path.name, exc)

	def _read_symbols(self, binary) -> None:
		raw = []
		for symbol in binary.symbols:
			try:
				section = symbol.section.name if symbol.section is not None else ""
				if not section or section.startswith(".rel"):
					continue
				raw.append((str(symbol.name), int(symbol.value), int(symbol.size), str(section),
					bool(symbol.is_function)))
			except Exception:  # noqa: BLE001 - section-less symbols carry nothing
				continue
		table = demangle([item[0] for item in raw if item[0]])
		for name, value, size, section, is_function in raw:
			if name:
				self._all_symbols[name] = (section, value, size, is_function)
			if is_function and size:
				demangled = table.get(name, name)
				symbol = CandidateSymbol(mangled=name, name=demangled,
					simple=normalize.simple_name(demangled), value=value, size=size, section=section)
				self.functions.append(symbol)
				self._by_section_address[(section, value)] = symbol
			elif name and not name.startswith(".:"):
				# `.LC0` and friends are size-less local symbols, but they are what a
				# relocation against a section names, so they are indexed too
				known = self._by_section_address.get((section, value))
				if known is None or (not known.size and size):
					self._by_section_address[(section, value)] = CandidateSymbol(
						mangled=name, name=name, simple=name, value=value, size=size, section=section)
		self.functions.sort(key=lambda item: (item.section, item.value))

	def _read_relocations(self, binary) -> None:
		# (offset in the section, relocation type, symbol named, addend). The addend is the
		# offset inside a section when the relocation names the section itself.
		for source in ("object_relocations", "dynamic_relocations"):
			try:
				items = list(getattr(binary, source))
			except Exception:  # noqa: BLE001 - not every file has both kinds
				continue
			for item in items:
				try:
					if not item.has_section:
						continue
					symbol_name = item.symbol.name if item.has_symbol else ""
					# a relocation usually names the object; in an object file it often names
					# the *section* (a section symbol, empty name) with the offset inside it
					# as the addend. Keep both.
					symbol_section = ""
					if item.has_symbol and item.symbol.section is not None:
						symbol_section = str(item.symbol.section.name)
					self._relocs.setdefault(str(item.section.name), []).append(
						(int(item.address), str(item.type), str(symbol_name), int(item.addend),
							symbol_section))
				except Exception:  # noqa: BLE001
					continue

	def is_partition(self, symbol: CandidateSymbol) -> bool:
		"""Is this symbol a -O2 partition of another one (`<name>.cold`)?

		It demangles to the same name as its base symbol, so it must never make `--fn` ambiguous
		- but it is a real unit of the file too (it has its own FDE), so asking for it by its
		exact mangled name still finds it, and `function()` reaches it as a second extent.
		"""
		return bool(symbol.mangled.endswith(".cold")) and symbol.mangled[:-5] in self._all_symbols

	def symbols_for(self, wanted: str | None, expect_size: int | None = None) -> list[CandidateSymbol]:
		"""The candidate symbols that could be the function being scored."""
		if wanted:
			text = wanted.strip()
			if any(symbol.mangled == text for symbol in self.functions):
				return [symbol for symbol in self.functions if symbol.mangled == text]
			own = [symbol for symbol in self.functions if not self.is_partition(symbol)]
			for key in (lambda s: s.name == text, lambda s: s.simple == text,
				lambda s: s.simple.rsplit("::", 1)[-1] == text or s.simple.rsplit(".", 1)[-1] == text):
				found = [symbol for symbol in own if key(symbol)]
				if found:
					return found
			needle = text.lower()
			return [symbol for symbol in own
				if needle in symbol.simple.lower() or needle in symbol.mangled.lower()]
		if expect_size:
			sized = [symbol for symbol in self.functions
				if symbol.size == expect_size and not self.is_partition(symbol)]
			if len(sized) == 1:
				return sized
		return [symbol for symbol in self.functions if not self.is_partition(symbol)]

	def function(self, wanted: str | None, expect_size: int | None = None) -> Function:
		"""Pick the candidate function (one match, or say what is there)."""
		if self.error:
			raise SymbolNotFound(self.error)
		candidates = self.symbols_for(wanted, expect_size)
		if not candidates:
			available = ", ".join(symbol.simple for symbol in self.functions[:40]) or "none"
			raise SymbolNotFound("no symbol in %s matches %r; this object defines: %s"
				% (self.path.name, wanted or "<any single function>", available))
		if len(candidates) > 1:
			raise SymbolNotFound("%r matches %d symbols in %s; pass --fn with the exact one:%s%s"
				% (wanted or "", len(candidates), self.path.name, "",
					"\n  " + "\n  ".join("%s  (%d bytes)" % (s.simple, s.size) for s in candidates[:20])))
		symbol = candidates[0]
		sections = [symbol.section]
		extents = [(symbol.value, symbol.size)]
		data = self._sections.get(symbol.section, b"")[symbol.value:symbol.value + symbol.size]
		warnings: list[str] = []
		# -O2 splits the cold blocks of a function into a second symbol, `<name>.cold`, in its own
		# section (.text.unlikely). The linked original splits the same way, and says so by the
		# extent it asks for: when that is longer than the hot part, the cold block is what fills
		# it, and both sides are then compared as entry block then cold block (Phase 5). When the
		# original's own tables bound the unit at the hot part, so is this.
		want = int(expect_size or 0)
		for suffix in (".cold", ".cold.1"):
			sibling = self._all_symbols.get(symbol.mangled + suffix)
			if sibling is None or want and want <= sum(length for _, length in extents):
				continue
			section, value, size, _is_function = sibling
			if not size or section in sections:
				continue
			chunk = self._sections.get(section, b"")[value:value + size]
			if not chunk:
				continue
			sections.append(section)
			extents.append((value, len(chunk)))
			data += chunk
			warnings.append("this candidate's cold blocks are in %s (%d bytes at %s): they are "
				"compared after its entry block, as the linked original's are"
				% (section, len(chunk), _hex(value)))
		self._extent_sections = [(section, where, length) for section, (where, length)
			in zip(sections, extents)]
		return Function(display=symbol.simple or symbol.mangled, raw_name=symbol.mangled,
			address=symbol.value, size=len(data), bytes=data, section=symbol.section,
			extents=extents, warnings=warnings)

	def _in_section(self, function: Function, address: int) -> str:
		"""A symbol defined in this same section at `address`.

		A call or jump to something in the same section needs no relocation - the
		displacement is final at compile time - so objdump names it from the symbol table and
		so must this: the original side resolves the very same callee through the analysis.
		"""
		symbol = self._by_section_address.get((function.section, address))
		return symbol.mangled if symbol is not None else ""

	def bindings(self, function: Function) -> tuple[callable, list[Ref]]:
		"""A `bind(instruction)` built from this object's relocations.

		A relocation sits on the encoded field (for a call that is one byte past the opcode),
		so it binds to the address operand of the instruction containing it.
		"""
		relocs: list[tuple[int, str, str, int, str]] = []
		for section, where, length in self._extent_sections or [
				(function.section, function.address, function.size)]:
			relocs += [item for item in self._relocs.get(section, [])
				if where <= item[0] < where + length]
		used: list[Ref] = []
		seen: dict[str, Ref] = {}

		def reference(offset: int, kind: str, symbol_name: str, addend: int,
			symbol_section: str = "") -> Ref:
			key = "%s:%s:%d" % (offset, symbol_name, addend)
			if key in seen:
				return seen[key]
			target = self._target(symbol_name, addend, symbol_section)
			# a relocation against a section symbol names no object: the object defined at the
			# addend's offset does, and `_target` looked it up
			named = target.get("name") or symbol_name or target["display"]
			where = target["address"]
			ref = Ref(kind=target["kind"], identity=target.get("identity", ""),
				raw=named or ("%s at %s+0x%x" % (kind, target["section"] or "?", addend)),
				name=clean_symbol(named) if named else (
					"%s+0x%x" % (target["section"], where) if where is not None else ""),
				address=where, section=target["section"], size=target["size"],
				content=target["content"])
			seen[key] = ref
			used.append(ref)
			return ref

		def bind(instruction) -> dict[int, Ref]:
			slots = list(instruction.slots)
			if not slots:
				return {}
			chosen: dict[int, Ref] = {}
			here = sorted((item for item in relocs
				if instruction.address <= item[0] < instruction.address + instruction.length),
				key=lambda item: item[0])
			if not here:
				# nothing for the link to fix up, so the displacement is already final and the
				# target is a symbol of this very object: a call to a helper in the same file,
				# or taking that helper's address. The analysis resolves the same target from
				# the reference Ghidra recorded, so both sides have to name it.
				for slot in slots:
					if slot.kind == "imm":
						continue          # with no relocation to fix it up, an immediate is a constant
					named = self._in_section(function, slot.value) if slot.value is not None else ""
					if named:
						chosen[slot.operand] = reference(slot.value, "in-section", named, 0)
				return chosen
			# An immediate is the least likely thing a relocation belongs to: pair the address
			# operands first, and fall back to an immediate only when a relocation is left over
			# with nothing else that could carry it - which is how a non-PIE 32-bit object
			# writes `pushl $_ZTI14CVehicleEntity`: an R_386_32 on an immediate of 0.
			address_slots = [slot for slot in slots if slot.kind != "imm"]
			immediates = [slot for slot in slots if slot.kind == "imm"]
			taken: list = []
			if len(address_slots) == len(here):
				# one relocation per remaining address operand, in the same order (usual case)
				for slot, item in zip(address_slots, here):
					chosen[slot.operand] = reference(*item)
					taken.append(item)
			elif len(address_slots) == 1:
				chosen[address_slots[0].operand] = reference(*here[0])
				taken.append(here[0])
			else:
				for slot in address_slots:
					near = min(here, key=lambda item: abs(
						item[0] - (instruction.address + slot.enc_offset)))
					chosen[slot.operand] = reference(*near)
					taken.append(near)
			left = [item for item in here if item not in taken]
			if len(left) == 1 and len(immediates) == 1 and immediates[0].operand not in chosen:
				chosen[immediates[0].operand] = reference(*left[0])
			return chosen

		return bind, used

	def _target(self, symbol_name: str, addend: int, symbol_section: str = "") -> dict:
		"""What a relocation names: kind, address, section, size, comparable content, display.

		A name is tried as a *symbol* first: `.LC3` and `.LFB1` are local labels, and GCC also
		relocates against them with an addend (`R_X86_64_PC32 .LC13 - 4`, because the merged
		`.rodata.cst4` pool is sorted and the constant sits before the label). Treating such a
		name as a section makes every one of them the same object at offset -4, which collapses
		seven constants into one symbol token and then mis-pairs the two sides' n-th object.

		A relocation that really does name a *section* (a section symbol, or `.rodata.cst8`)
		carries the offset inside it as the addend; the object defined at that offset (`.LC0`, a
		table, a vtable) is what the instruction really reads, so it is looked up there - for its
		name, while the geometry stays the offset itself.
		"""
		found = self._all_symbols.get(symbol_name)
		section_named = symbol_name if symbol_name.startswith(".") else symbol_section
		if found is None and section_named and not symbol_name.startswith("_"):
			display = self._nearest_in(section_named, addend)
			# the object defined at that offset is what the instruction reads, so it is the name
			# to compare - `.data.rel.ro+0x18` is a section, and the other side has no such thing
			return {"kind": "data", "address": addend, "section": section_named, "size": None,
				"content": self._read(section_named, addend, _PROBE), "display": display,
				"name": display,
				# in an object file every section is addressed from 0, so an offset alone names
				# nothing: `.rodata+0x18` and `.rodata.cst4+0x18` are different objects
				"identity": "%s+0x%x" % (section_named, addend)}
		if found is None:
			# not defined here: an import (libc, or a function of another translation unit).
			# Its name is the only thing the two sides share - which is also what makes it
			# comparable, because a compiler reproduces that name on both sides.
			return {"kind": "external", "address": None, "section": "", "size": None,
				"content": None, "display": symbol_name}
		section, value, size, is_function = found
		if is_function:
			# the body's bytes are not safe evidence: outside PIC they encode absolute
			# addresses the link has to fix up, so compare the size instead
			return {"kind": "function", "address": value, "section": section, "size": size or None,
				"content": None, "display": symbol_name}
		# the addend is an offset inside the named object: `_ZTV9CEntityBase+16` is the first
		# slot of that vtable, not its header
		own = self._names_section(symbol_name, section)
		where = value + addend
		return {"kind": "data", "address": (None if own else where), "section": section,
			"size": size or None, "content": self._read(section, where, size or _PROBE),
			"display": symbol_name,
			"identity": ("symbol:%s" % symbol_name) if own else "%s+0x%x" % (section, where)}

	def _names_section(self, symbol_name: str, section: str) -> bool:
		"""Is this object its own section? (`.data.rel.ro._ZTI14CVehicleEntity`, or the
		`.data.rel.ro.local._ZTV…` form.)

		GCC emits a vtable or type_info as a COMDAT of one symbol, so the symbol sits at
		offset 0 of a section named after it and an "address" of 0 says nothing - three
		different type_infos would all look like the same object. There, the name is the
		identity, and `normalize.Vocabulary` keys the token by that instead.
		"""
		return bool(symbol_name) and (section == symbol_name or
			section.endswith("." + symbol_name))

	def _nearest_in(self, section: str, offset: int) -> str:
		"""The name of the symbol defined at (or just below) an offset inside a section."""
		exact = self._by_section_address.get((section, offset))
		if exact is not None:
			return exact.mangled
		best = None
		for (name, value), symbol in self._by_section_address.items():
			if name == section and value <= offset and (best is None or value > best[0]):
				best = (value, symbol.mangled)
		return best[1] if best else ""

	def _read(self, section: str, offset: int, length: int) -> bytes | None:
		# a section that carries relocations has placeholders where the link will write
		# values, so its bytes are not comparable with a linked image's
		if section in self._writable or section in self._relocs or not section.startswith(_COMPARABLE):
			return None
		data = self._sections.get(section)
		if data is None:
			return None
		return data[offset:offset + length] or None

	def names(self) -> list[str]:
		return [symbol.simple or symbol.mangled for symbol in self.functions]
