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
import re
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
_SCN_LNK_COMDAT = 0x00001000

# COFF storage classes (winnt.h). Only C_EXT matters here: an undefined entry with that class
# is an import, and its type says whether the import is a function or a piece of data.
_IMAGE_SYM_CLASS_EXTERNAL = 2

# How wide the field a COFF relocation fixes is, for the types that matter here (IMAGE_REL_*).
# A COFF relocation has no addend field, so the width is what says how many bytes of the object
# to read as the implied one (MS-3).
_COFF_FIELD_WIDTH = {
	"ABSOLUTE": 0, "ADDR32": 4, "ADDR32NB": 4, "HIGH": 2, "HIGHADJ": 2, "INSTANCE_OFFSET": 4,
	"SECTION_OFFSET": 2, "REL32": 4, "DIR64": 8, "REL64": 8, "IMM16": 2, "SEGOFST": 2,
	"SREL32": 4, "PAIR": 0, "FRACTL": 0, "SECREL": 4,
	# how LIEF spells the same types
	"AMD64_REL32": 4, "AMD64_ADDR32NB": 4, "AMD64_ADDR32": 4, "AMD64_REL64": 8,
	"AMD64_DIR64": 8, "AMD64_IMMGREL32": 4, "AMD64_SECREL": 4,
	# i386 (IMAGE_REL_I386_*, winnt.h), as LIEF names them - measured on a `cl /Od` object of
	# this benchmark, which emits `TYPE.I386_REL32` (384 records) and `TYPE.I386_DIR32` (400) and
	# nothing else, and reports a record `size` of 0 for all of them. The names are prefixed per
	# machine here exactly as they are in the ELF table below: `DIR32` alone would not match the
	# key `relocation_width` reads out of `TYPE.I386_DIR32`. Without these, an i386 candidate
	# reads every reference with no field at all - no addend, no masked bytes, and a warning about
	# an unknown type (Docs/MSVC-x86-Plan.md X86-3).
	"I386_ABSOLUTE": 0, "I386_SECTION": 4, "I386_ADDR32": 4, "I386_REL32": 4,
	"I386_SECTIONOFFSET": 2, "I386_IMMEDIATE": 4, "I386_SECIMAGE_REL32": 0, "I386_SECREL": 4,
	"I386_IMM_SECREL": 4, "I386_LITERAL": 4, "I386_FILE": 0, "I386_MACH": 4, "I386_IMPREL": 0,
	"I386_DIR32": 4, "I386_DIR32NB": 4, "I386_SECREL7": 1, "I386_REL32BF": 4,
}

# The same for ELF (R_*): the type says the width of the field it fixes. LIEF spells these
# `TYPE.X86_64_PC32`, so the key is the part after the last dot, as for COFF.
_ELF_FIELD_WIDTH = {
	"X86_64_PC32": 4, "X86_64_32": 4, "X86_64_32S": 4, "X86_64_PLT32": 4, "X86_64_64": 8,
	"X86_64_GOTPCREL": 4, "X86_64_GOTPCRELX": 4, "X86_64_REX_GOTPCRELX": 4,
	"X86_64_GOT32": 4, "X86_64_GOT64": 8, "X86_64_PC64": 8,
	"X86_32": 4, "X86_PC32": 4, "X86_GOT32": 4, "X86_GOTOFF": 4, "X86_PLT32": 4,
	"X86_PC16": 2, "X86_16": 2, "X86_8": 1, "NONE": 0, "NUM": 0,
}


def relocation_width(kind) -> int:
	"""How many bytes a relocation rewrites (0 = unknown, or a record that fixes nothing).

	Phase 3's byte comparison needs this on the candidate side: the bytes a relocation covers are
	the link's choice, not the candidate's, so they are the only ones the two bodies are allowed to
	disagree in.
	"""
	text = str(kind or "")
	key = text.rsplit(".", 1)[-1].strip()
	key = key[2:] if key.startswith("R_") else key
	for table in (_ELF_FIELD_WIDTH, _COFF_FIELD_WIDTH):
		if key in table:
			return table[key]
	return 0


def pc_relative(kind) -> bool:
	"""Does this relocation type resolve against the address *after* its own field?"""
	name = str(kind or "").upper()
	return "PC" in name or "PREL" in name or "PLT" in name


def pc_bias(kind) -> int:
	"""How far past its addend a PC-relative relocation actually points.

	The assembler writes the addend as `target - width` (`R_X86_64_PC32 .rodata+0x280` where the
	constant is at +0x284) because the field is resolved against the address after it, so the byte
	the instruction reads is `addend + width`. A COFF relocation has no addend - the number in the
	bytes is already relative to the field - and `REL32` does not match `pc_relative`.
	"""
	if not pc_relative(kind):
		return 0
	width = relocation_width(kind)
	if width:
		return width
	# A PC-relative type the width tables do not know: the number in its own name is its field
	# size (`R_AARCH64_PREL32`), which is what the assembler subtracted.
	match = re.search(r"(\d+)$", str(kind or ""))
	return int(match.group(1)) // 8 if match else 0


# What `cl` fills the space between functions with, and what a linker pads an aligned section
# with. Decoding to these and no further is how a COFF candidate's extent is found (MS-3).
_PADDING_MNEMONICS = {"nop", "int3", "pause", "hlt", "lea" if False else "nop"}


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
# How far to read for something that looks like a string literal: the comparison reads the
# literal plus its terminator, so a 20-character string needs more than a probe window.
_STRING_PROBE = 256


def _looks_like_string(symbol_name: str, section: str) -> bool:
	"""Does this object sit where compilers put string literals?

	GCC and Clang: `.rodata.str1.1`, `.str1`, and the `.data.rel.ro`-style COMDATs named after a
	`.LCn` label are not. MSVC: string literals are decorated `??_C@_0A@…`, whatever section they
	land in. Used only to decide how far to read, never to claim what the bytes are.
	"""
	return ".str" in (section or "") or str(symbol_name or "").startswith("??_C@")
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


def pdata_records(binary) -> list[tuple[int, int, int]]:
	"""(begin, end, unwind) for every `.pdata` record, in the **file's own** addresses.

	Only the bytes the file initialises are walked: a PE section's `size` is its virtual size,
	which pads past the end of the table, and reading that padding as records would invent
	zero-length units (Docs/MSVC-Plan.md MS-1). The records are RVAs: bias them by
	`file_address_base` to meet the addresses the analysis and this tool use.
	"""
	section = next((item for item in binary.sections if str(item.name) == ".pdata"), None)
	if section is None or not section.size:
		return []
	data = bytes(section.content)
	records = []
	for position in range(0, len(data) - len(data) % _PDATA_RECORD.size, _PDATA_RECORD.size):
		begin, end, unwind = _PDATA_RECORD.unpack_from(data, position)
		if end > begin:
			records.append((int(begin), int(end), int(unwind)))
	return records


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
		# ... and, for a PE, every slot of the import-address table: the import directory names them
		# whether or not a relocation points at them (`self.offset`-biased, like `self.pointers`).
		self.import_slots: dict[int, str] = {}
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
			self._read_imports(binary)
		except Exception:  # noqa: BLE001 - an unreadable import directory must not break `try`
			self.import_slots = {}
		try:
			self._read_function_table(binary)
		except Exception as exc:  # noqa: BLE001 - a unit table is an extra source of truth, not a
			self.units = []  # requirement, and a LIEF that cannot read .pdata must not break `try`
			self.unit_note = "reading the function table failed: %s" % exc

	def _read_imports(self, binary) -> None:
		"""What the file's own import directory says each IAT slot holds (a PE only).

		A 32-bit PE reaches an API through a pointer slot - `call *[0x4c515c]` - and the analysis
		shows a label in `.rdata` named after the *value* Ghidra resolved there
		(`PTR_WideCharToMultiByte_004c515c`). That name is the disassembler's, so it is synthetic to
		the comparison, and a candidate object relocates the same operand against `__imp__...` - so
		no call through a PE's IAT could ever be proven and no unit of such a file could reach
		`exact`. The import directory is the file's own statement about those slots, and it names
		them the way the candidate does once the `__imp_` prefix is off. Ordinals carry no name and
		are left out: a number matches nothing on the other side. (Docs/x86-32bit-issues.md §20.)
		"""
		import lief

		if not isinstance(binary, lief.PE.Binary):
			return
		base = file_address_base(binary)
		for imported in binary.imports:
			try:
				entries = list(imported.entries)
			except Exception:  # noqa: BLE001 - one unreadable descriptor must not lose the rest
				continue
			for entry in entries:
				try:
					name = str(entry.name or "")
					slot = int(entry.iat_address) + base + self.offset
				except Exception:  # noqa: BLE001
					continue
				if name:
					self.import_slots[slot] = name

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

		The walk itself is `pdata_records` below, so that a caller which wants the file's units
		without a byte index - `toolchain.target_shape`, which samples them - reads exactly the
		table `try` compares against.
		"""
		records = pdata_records(binary)
		if not records:
			self.unit_note = "no .pdata section: this PE carries no function table"
			return
		bias = file_address_base(binary)
		count = 0
		for begin, end, unwind in records:
			count += self._add_unit(".pdata", int(begin) + bias, int(end) + bias,
				int(unwind) + bias)
		self.unit_source = ".pdata"
		if not count:
			self.unit_note = ".pdata holds no readable function record"

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


def _forwarded_call(conn: sqlite3.Connection, image, row) -> sqlite3.Row | None:
	"""The body a forwarding body jumps to, if this one is nothing but a jump.

	MSVC puts calls to some of its own helpers behind a small forwarding body: `jmp rel32`, sometimes
	behind a `mov edi,edi / push ebp / mov esp,ebp / pop ebp` no-op, or `jmp *[abs]` through a
	pointer. The analysis on i386 leaves such a body as a function of its own with no name, so a call
	that is `free()` in the source reads as a call to an unnamed 11-byte body, and a candidate's
	`call _free` can never pair with it (Docs/x86-32bit-issues.md §30). The jump's own bytes say
	where it goes, which the file answers without re-analysing anything.

	Only a body that is *nothing but* the jump is followed. A body that adjusts `this` first
	(`movl -0x10(%ebp),%ecx / addl $8,%ecx / jmp <dtor>`) is a constructor or destructor thunk: a
	unit with its own address, and the thing a source-level call really targets. Jumping through that
	would invent a callee the source never names, and lose the member offset the thunk records.
	"""
	if row is None:
		return None
	body = row["bytes"] if "bytes" in row.keys() else None
	entry = int(row["entry"])
	if not body and image is not None:
		body = image.read(entry, 16)
	if not body:
		return None
	for prefix in (b"", b"\x8b\xff\x55\x8b\xec\x5d"):
		fill = len(prefix)
		if len(body) != fill + 5 or not body.startswith(prefix) or body[fill] != 0xE9:
			continue          # a real body that happens to begin with a jump is not a forwarder
		offset = int.from_bytes(body[fill + 1:fill + 5], "little", signed=True)
		landed = entry + fill + 5 + offset
		target = conn.execute("SELECT id, entry, name, size, kind, bytes FROM functions"
			" WHERE entry=?", (landed,)).fetchone()
		return target if target is not None and int(target["entry"]) != entry else None
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

	def describe_object(ref: Ref) -> None:
		"""Name a reference by the object the file's own data says is there (Phase 4)."""
		# The import directory comes first, and answers even without a structure recovery: an IAT
		# slot is named by the file itself, which is the one kind of `.rdata` label a candidate can
		# also name. Its bytes are the loader's to write, so they are not comparable.
		imported = (getattr(image, "import_slots", None) or {}).get(ref.address or -1)
		if imported:
			ref.name = imported
			ref.identity = "iat@%s" % _hexkey(ref.address)
			ref.content = None
			return
		if structures is None or ref.address is None or ref.kind == "function":
			return
		object_ = structures.object_at(ref.address)
		if not object_:
			return
		# the file's own name for this object, as the candidate's symbol names it
		ref.name = object_["name"] or ref.name
		ref.identity = "%s@%s" % (object_["role"], _hexkey(object_["address"]))
		ref.size = ref.size or object_["size"]
		ref.content = None   # a vtable is pointers; its bytes are never comparable

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
		forwarded = _forwarded_call(conn, image, function)
		if forwarded is not None:
			# The call in the source is to what the forwarder jumps to, and the file says so; the
			# forwarder's own body stays visible as the address the instruction encodes.
			to_address = int(forwarded["entry"])
			function = forwarded
			if to_address not in functions:
				functions[to_address] = forwarded
			kind = "function"
		ref = Ref(kind=kind, raw=item["to_name"] or "", name=name, address=to_address,
			section=item["section"] or "")
		describe_object(ref)
		if function is not None:
			if forwarded is not None:
				name = clean_symbol(function["name"] or "")
				ref.name = name
				ref.kind = "function"
			# a body's bytes are not comparable (in a `.o` the references inside it are
			# still placeholders), but its size is, and that is what catches "same shape,
			# different helper" - so it has to be the size the compiler said, from the file's
			# own table where the file carries one
			ref.size = _unit_size(conn, image, to_address) or int(function["size"]) or None
		elif to_address is not None:
			declared, _value = sizes.get(to_address, (0, ""))
			ref.size = declared or None
			if declared:
				# The analysis recognised a string here. Its length is the evidence that makes a
				# literal comparable at all: it says how many bytes to read, and one past them is
				# read as well, so a candidate whose literal is one character longer or shorter does
				# not compare equal over the shared prefix (Phase 4).
				ref.string = int(declared)
				ref.content = image.read(to_address, int(declared) + 1)
			else:
				ref.content = image.read(to_address, _PROBE)
		seen[key] = ref
		used.append(ref)
		return ref

	# --- the file's own data, for a reference the analysis never attached -----------------
	# On i386 every reference to something outside the body is a four-byte address written into the
	# instruction, and a disassembler does not always record a reference for it: for
	# `subss 0x41f488(, %eax, 4)` Ghidra names the elements it inferred (0x41f48c, 0x41f490) and not
	# the base, and for `movb 0x41fa74(%ecx)` it names nothing at all. The section and the bytes there
	# are the file's own answer, and they are what lets that operand be compared with a candidate's
	# `DIR32`/`R_386_32` against the same object - the whole of Docs/MSVC-x86-Plan.md X86-6. The
	# address has to be *inside a data section of this file*: a displacement off a base register is a
	# frame or field offset until the file says otherwise, so a `[reg + disp]` operand is only ever
	# hidden or tokenised when the file agrees it names an object.
	data_ranges: list[tuple[int, int, str]] = [(start, start + int(size), name)
		for name, start, size in image.data_sections() if size]

	def reaches_file(slot) -> Ref | None:
		if slot.value is None:
			return None
		key = "file:%s" % _hex(int(slot.value))
		if key in seen:
			return seen[key]
		address = int(slot.value)
		hit = next((item for item in data_ranges if item[0] <= address < item[1]), None)
		if hit is None:
			return None
		_end, section = hit[1], hit[2]
		symbol = cache.symbol_rows(conn, addresses=[address], limit=1)
		name = symbol[0]["name"] if symbol and int(symbol[0]["address"]) == address else ""
		ref = Ref(kind="data", raw=name or _hex(address),
			name=clean_symbol(name) if name else "", address=address, section=section)
		describe_object(ref)
		if ref.content is None:
			# read no further than the section does; the width of the access is what
			# `diff.content_window` compares when neither side can name the object (Phase 4)
			ref.size = min(_PROBE, _end - address) or None
			ref.content = image.read_data(address, _PROBE)
		seen[key] = ref
		used.append(ref)
		return ref

	def bind(instruction) -> dict[int, Ref]:
		here = by_address.get(int(instruction.address), [])
		if not instruction.slots:
			return {}
		chosen: dict[int, Ref] = {}
		slots = list(instruction.slots)

		def claim(slot, ref: Ref) -> Ref:
			# how wide this access is, carried onto the reference: for a constant in a merged
			# `.rodata.cst` pool that width is the only thing saying the two sides read the same
			# object, so the bytes it reads have to be compared (Phase 4)
			if slot.width and not ref.width:
				ref.width = int(slot.width)
			return ref

		# exact first: the operand encodes the address this reference points at
		for slot in slots:
			if slot.value is None:
				continue
			if slot.kind == "disp" and reaches_file(slot) is None:
				# a `[reg + disp]` displacement is a field offset, not a reference, unless the file
				# says it is an object at that address
				continue
			# a reference with no address (an import) is not the same thing as an operand that
			# encodes address 0, so the comparison is made only on real addresses
			match = sorted((item for item in here if item["to_address"] is not None
				and int(item["to_address"]) == int(slot.value)),
				key=lambda item: -ranked.get(item["to_kind"] or "address", 0))
			if match:
				chosen[slot.operand] = claim(slot, build(match[0]))
		# then anything left over, only when the pairing is unambiguous
		left = [item for item in here if item["to_address"] is not None and not any(
			int(item["to_address"]) == slot.value for slot in slots if slot.value is not None)]
		free = [slot for slot in slots if slot.operand not in chosen and slot.kind != "imm"
			and not (slot.kind == "disp" and reaches_file(slot) is None)]
		if not free:
			free = [slot for slot in slots if slot.operand not in chosen
				and not (slot.kind == "disp" and reaches_file(slot) is None)]
		if left and len(left) == 1 and len(free) == 1:
			chosen[free[0].operand] = claim(free[0], build(left[0]))
		# and last, an absolute operand that nothing in the analysis explains: the file describes the
		# object itself, so the reference is stated rather than left as a bare number
		for slot in slots:
			if slot.operand in chosen or slot.kind not in ("abs", "disp"):
				continue
			ref = reaches_file(slot)
			if ref is not None:
				chosen[slot.operand] = claim(slot, ref)
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
		# which of those addresses are *function* entries: what a section-relative reference naming
		# one reaches, rather than an object it is an offset inside
		self._function_keys: set[tuple[str, int]] = set()
		self._all_symbols: dict[str, tuple[str, int, int, bool]] = {}
		self._relocs: dict[str, list[tuple[int, str, str, int, str]]] = {}
		# the (section, address, length) of the last function handed back by `function()`, which
		# is what its relocations have to be looked up in (a -O2 candidate spans two sections)
		self._extent_sections: list[tuple[str, int, int]] = []
		# COFF: sections keyed in file order (a COFF object may name two sections the same -
		# `link` puts one COMDAT per `.text$mn` and they all carry that name), and a
		# relocation names a symbol *table index*, so the section it lives in is known exactly.
		self._section_order: list[str] = []
		self._comdat: set[str] = set()
		# an undefined COFF external -> whether its own type says it is a function
		self._undefined: dict[str, bool] = {}
		self._coff = False
		self._handle = None
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
			self._coff = isinstance(binary, getattr(getattr(lief, "COFF", None), "Binary", ()) or ())
			seen: dict[str, int] = {}
			for section in binary.sections:
				if not section.size:
					self._section_order.append("")
					continue
				name = str(section.name)
				key = name
				if self._coff and name in seen:
					# `.text$mn`, `.pdata`, `.xdata`: MSVC really does emit several sections with
					# one name, so a name cannot be the key. Disambiguate only where it is needed,
					# so an ELF key stays exactly the section name it always was.
					seen[name] += 1
					key = "%s#%d" % (name, seen[name])
				seen.setdefault(name, 0)
				self._section_order.append(key)
				if section_capabilities(getattr(binary, "format", None), section)[1]:
					self._writable.add(key)
				if self._coff and int(_section_flags(section)[0] or 0) & _SCN_LNK_COMDAT:
					self._comdat.add(key)
				self._sections[key] = bytes(section.content)
			if self._coff:
				self._handle = normalize.capstone_for("x86:LE:%d:default" % (self.bits or 64))
			self._read_symbols(binary)
			self._read_relocations(binary)
		except Exception as exc:  # noqa: BLE001
			self.error = "while reading %s: %s" % (self.path.name, exc)

	def _section_of_index(self, index: int) -> str:
		"""A COFF section number (1-based, as the symbol table writes it) -> this object's key."""
		if 1 <= index <= len(self._section_order):
			return self._section_order[index - 1]
		return ""

	def _code_extent(self, chunk: bytes) -> int:
		"""Where a COFF function's code ends inside its section.

		A COFF symbol has no size, so the only boundary the object gives is the next function
		symbol in the same section - and `cl` aligns functions to 16 bytes and fills between them
		with `int 3`/`nop` (measured on `Tests/build/msvc-o0/math.o`: `AbsDiff` is 49 bytes and
		the next symbol is 64 along). Those bytes are not part of the unit - the linked image's
		own `.pdata` stops at the `ret`, and that is the extent the original side is read over -
		so the run is cut by *decoding*, not by counting filler bytes: a greedy byte run also ate
		12 units whose last real instruction happens to end in 0xcc or 0x90 (measured).
		"""
		if self._handle is None or not chunk:
			return len(chunk)
		end = 0
		try:
			for instruction in self._handle.disasm(chunk, 0):
				if instruction.mnemonic not in _PADDING_MNEMONICS:
					end = instruction.address + instruction.size
		except Exception:  # noqa: BLE001 - capstone stops at an undecodable byte
				return len(chunk)
		return end or len(chunk)

	def _read_symbols_coff(self, binary) -> None:
		"""The symbol table of a COFF object: names and addresses, no sizes, no function flag.

		Two things an ELF `.o` does not have to do (Docs/MSVC-Plan.md MS-3): a symbol says *what*
		it is through its type bits, which LIEF reads as `is_function`, and it says nothing about
		how long the thing is - the extent is the section, when the function is its own COMDAT
		(`/Gy`, and then it is exact, better than ELF's `st_size`), or the next function symbol in
		the section with `cl`'s inter-function padding cut off it.
		"""
		raw: list[tuple[str, str, int, bool]] = []
		for symbol in binary.symbols:
			try:
				name = str(symbol.name)
				index = int(symbol.section_idx)
			except Exception:  # noqa: BLE001
				continue
			# a COFF section number of 0 means "not in a section" (undefined, absolute, a file
			# record or a `.drectve` directive): it has no bytes to mean anything about. An
			# undefined *external* still carries a type, and that is worth keeping: it is how the
			# object says whether a reference reaches a function or a piece of data.
			if not name:
				continue
			if index < 1:
				if int(getattr(symbol, "storage_class", 0) or 0) == _IMAGE_SYM_CLASS_EXTERNAL:
					try:
						self._undefined[name] = bool(symbol.is_function)
					except Exception:  # noqa: BLE001
						pass
				continue
			key = self._section_of_index(index)
			if not key:
				continue
			try:
				is_function = bool(symbol.is_function)
			except Exception:  # noqa: BLE001 - a symbol table LIEF cannot fully type
				is_function = False
			raw.append((name, key, int(symbol.value), is_function))
		table = demangle([item[0] for item in raw if item[0]])
		by_section: dict[str, list[tuple[int, str]]] = {}
		for name, key, value, is_function in raw:
			self._all_symbols.setdefault(name, (key, value, 0, is_function))
			if not is_function:
				# `$LN3` and `.str$…` labels: no extent, but they are what a relocation against
				# this section names, so they are indexed like an ELF local label is.
				self._by_section_address.setdefault((key, value), CandidateSymbol(
					mangled=name, name=name, simple=name, value=value, size=0, section=key))
				continue
			by_section.setdefault(key, []).append((value, name))
		for key, items in by_section.items():
			items.sort()
			data = self._sections.get(key, b"")
			for position, (value, name) in enumerate(items):
				if self._all_symbols.get(name, ("", 0, 0, False))[0] != key:
					continue  # a second symbol of this name in another section: first one names it
				bound = items[position + 1][0] if position + 1 < len(items) else len(data)
				if self._is_comdat(key):
					# one COMDAT per function (`/Gy`): the section *is* the function, and the
					# compiler's own extent - no guessing at a boundary
					bound = max(bound, len(data)) if value == 0 else bound
				size = self._code_extent(data[value:bound])
				if not size:
					continue
				demangled = table.get(name, name)
				symbol = CandidateSymbol(mangled=name, name=demangled,
						simple=normalize.simple_name(demangled), value=value, size=size, section=key)
				self.functions.append(symbol)
				self._by_section_address[(key, value)] = symbol
		self.functions.sort(key=lambda item: (item.section, item.value))

	def _is_comdat(self, key: str) -> bool:
		return key in self._comdat

	def _read_symbols(self, binary) -> None:
		if self._coff:
			self._read_symbols_coff(binary)
			return
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
				self._function_keys.add((section, value))
			elif name and not name.startswith(".:"):
				# `.LC0` and friends are size-less local symbols, but they are what a
				# relocation against a section names, so they are indexed too
				known = self._by_section_address.get((section, value))
				if known is None or (not known.size and size):
					self._by_section_address[(section, value)] = CandidateSymbol(
						mangled=name, name=name, simple=name, value=value, size=size, section=section)
		self.functions.sort(key=lambda item: (item.section, item.value))

	def _read_relocations(self, binary) -> None:
		if self._coff:
			self._read_relocations_coff(binary)
			return
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
					addend = int(item.addend)
					if not addend and (not symbol_name or symbol_name in self._sections) and not (
							pc_relative(str(item.type))):
						# A `.rel` (SHT_REL) record carries no explicit addend: the offset is the value
						# already sitting in the field the relocation is on. A non-PIE 32-bit object says
						# `movzbl 0x44(%eax)` against the `.rodata` section symbol for "the object 0x44
						# bytes into that section", and taking the addend as 0 gives every such reference
						# the first object in the section - the wrong name, the wrong identity, and the
						# wrong bytes to compare (Docs/MSVC-x86-Plan.md X86-6). A pc-relative record is
						# left alone: its in-place value already has P subtracted out of it, which is a
						# different sum from the one `_target` is asked for.
						addend = self._field_value(str(item.section.name), int(item.address),
							relocation_width(str(item.type)) or 4)
					self._relocs.setdefault(str(item.section.name), []).append(
						(int(item.address), str(item.type), str(symbol_name), addend,
							symbol_section))
				except Exception:  # noqa: BLE001
					continue

	def _field_value(self, section: str, offset: int, width: int) -> int:
		"""What the bytes a relocation sits on currently say (the in-place addend of a `.rel`)."""
		data = self._sections.get(section) or b""
		if width <= 0 or offset < 0 or offset + width > len(data):
			return 0
		return int.from_bytes(data[offset:offset + width], "little")

	def _coff_symbol_table(self, binary) -> dict[int, tuple[str, str, int]]:
		"""COFF symbol-table index -> (name, this object's section key, value).

		A COFF symbol record is 18 bytes and the ones with auxiliaries (a section definition, an
		external name, a `.file`) occupy more than one record; a relocation names the index of a
		record in that raw table. LIEF's `symbols` *folds the auxiliary entries into their primary
		one*, so its list position is not that index - measured on `Tests/cache/.../math.obj`: the
		`AMD64_REL32` of the self-recursive call in `FibonacciRecursive` names index 251, which is
		that function in the file and a symbol ten further on in LIEF's list. Reading the index
		directly gives every call in the object the wrong callee. Rebuild the index by walking the
		table and adding each entry's own auxiliary count.
		"""
		table: dict[int, tuple[str, str, int]] = {}
		position = 0
		for symbol in binary.symbols:
			try:
				auxiliaries = len(list(symbol.auxiliary_symbols))
			except Exception:  # noqa: BLE001 - an entry LIEF cannot enumerate auxiliaries for
				auxiliaries = 0
			try:
				name = str(symbol.name)
				section = self._section_of_index(int(symbol.section_idx))
				value = int(symbol.value)
			except Exception:  # noqa: BLE001
				name, section, value = "", "", 0
			table[position] = (name, section, value)
			position += 1 + max(auxiliaries, 0)
		return table

	def _read_relocations_coff(self, binary) -> None:
		"""A COFF object's relocations: one list per section, and **no addend field**.

		An ELF `.o` relocation carries its own addend (`R_X86_64_PC32 sym-4`); a COFF one only
		says "fix the field at this offset against this symbol", so the number already sitting in
		the bytes *is* the implied addend - which is why this object's `.pdata` record reads as
		(0, 0x3c, 0) with an ADDR32NB on each field. The symbol is named by *table index*, so the
		section it lives in is known exactly - the thing a name cannot promise in a COFF object,
		where several sections really do share one name.
		"""
		try:
			symbols = self._coff_symbol_table(binary)
		except Exception:  # noqa: BLE001
			return
		for position, section in enumerate(binary.sections):
			key = self._section_of_index(position + 1)
			if not key:
				continue
			data = self._sections.get(key, b"")
			try:
				items = list(section.relocations)
			except Exception:  # noqa: BLE001 - a section with no relocation table
				continue
			for item in items:
				try:
					offset = int(item.address)
					index = int(item.symbol_idx)
				except Exception:  # noqa: BLE001
					continue
				name = ""
				symbol_section = ""
				entry = symbols.get(index)
				if entry is not None:
					name, symbol_section, _value = entry
				width = int(getattr(item, "size", 0) or 0)
				if width not in (1, 2, 4, 8):
					# LIEF does not always fill it; the type says how wide the field is.
					width = relocation_width(item.type)
				addend = 0
				if width and offset + width <= len(data):
					addend = int.from_bytes(data[offset:offset + width], "little", signed=True)
				self._relocs.setdefault(key, []).append(
					(offset, str(item.type), name, addend, symbol_section or key))

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
				lambda s: s.simple.rsplit("::", 1)[-1] == text or s.simple.rsplit(".", 1)[-1] == text,
				# an MSVC decorated name puts the identifier first (`?AbsDiff@CMathTests@@SAHHH@Z`),
				# so a caller who knows the source name and not the decoration still finds it. The
				# decorated form stays the comparison key: `c++filt` cannot read it (MSVC-Plan §8).
				lambda s: s.mangled.startswith("?") and s.mangled[1:].split("@")[0] == text):
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
			symbol_section: str = "", width: int = 0) -> Ref:
			key = "%s:%s:%d" % (offset, symbol_name, addend)
			if key in seen:
				existing = seen[key]
				if width and not existing.width:
					existing.width = int(width)
				return existing
			target = self._target(symbol_name, addend + (0 if self._coff else pc_bias(kind)),
				symbol_section)
			# a relocation against a section symbol names no object: the object defined at the
			# addend's offset does, and `_target` looked it up
			named = target.get("name") or symbol_name or target["display"]
			where = target["address"]
			ref = Ref(kind=target["kind"], identity=target.get("identity", ""),
				raw=named or ("%s at %s+0x%x" % (kind, target["section"] or "?", addend)),
				name=clean_symbol(named) if named else (
					"%s+0x%x" % (target["section"], where) if where is not None else ""),
				address=where, section=target["section"], size=target["size"],
				content=target["content"], width=int(width) or None,
				string=target.get("string") or None)
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
					# An immediate with no relocation on it is a constant, and a `[reg + 0]` operand means
					# the pointer held in that register - not address 0 of this section. A memory operand
					# that encodes address 0 with nothing to fill it in is the same kind of nothing:
					# `lea 0x0(,%rax,4)` computes `rax*4`, and the function that happens to sit at offset 0
					# of this section is not what it refers to. A branch or call is different - capstone
					# resolves its target to a section-relative address, and 0 there is the first function
					# of the section, which is the call `callq 0` in a non-PIE object really is.
					if slot.kind in ("imm", "disp") or (slot.kind == "abs" and not slot.value):
						continue
					named = self._in_section(function, slot.value) if slot.value is not None else ""
					if named:
						chosen[slot.operand] = reference(slot.value, "in-section", named, 0,
							width=slot.width)
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
					chosen[slot.operand] = reference(*item, width=slot.width)
					taken.append(item)
			elif len(address_slots) == 1:
				chosen[address_slots[0].operand] = reference(*here[0], width=address_slots[0].width)
				taken.append(here[0])
			else:
				for slot in address_slots:
					near = min(here, key=lambda item: abs(
						item[0] - (instruction.address + slot.enc_offset)))
					chosen[slot.operand] = reference(*near, width=slot.width)
					taken.append(near)
			left = [item for item in here if item not in taken]
			if len(left) == 1 and len(immediates) == 1 and immediates[0].operand not in chosen:
				chosen[immediates[0].operand] = reference(*left[0], width=immediates[0].width)
			return chosen

		return bind, used

	def relocation_fields(self, function: Function) -> list[tuple[int, int]]:
		"""The (offset, width) pairs of `function.bytes` that the link rewrites.

		Every relocation whose field falls inside one of the function's extents, translated from
		section offsets to offsets in the concatenated body (per extent, before concatenation - a
		-O2 candidate's `.text.unlikely` block is a different section and its own address domain).
		This is the authoritative list for the candidate side of the byte comparison: a field a
		relocation covers is a value the link chooses, so it is not evidence about the source.
		A record whose type gives no width is skipped and said so in the function's warnings.
		"""
		fields: list[tuple[int, int]] = []
		unknown = 0
		cursor = 0
		for section, where, length in (self._extent_sections
				or [(function.section, function.address, function.size)]):
			for item in self._relocs.get(section, []):
				offset = int(item[0])
				if not where <= offset < where + length:
					continue
				width = relocation_width(item[1])
				if not width:
					unknown += 1
					continue
				fields.append((cursor + (offset - where), width))
			cursor += length
		if unknown:
			function.warnings.append("%d relocation(s) in this function have a type this tool does "
				"not know a field width for, so their bytes are compared rather than masked"
				% unknown)
		return sorted(fields)

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
		if found is not None and self._coff and symbol_section in self._sections and (
				found[0] != symbol_section):
			# A COFF relocation names a symbol *table index*, so the section that symbol lives in
			# is known exactly - which its name is not, since several sections of one object may
			# carry the same name (`.text$mn`, `.pdata`). Trust the index.
			found = (symbol_section, found[1], found[2], found[3])
		section_named = symbol_name if symbol_name.startswith(".") else symbol_section
		if found is None and section_named and not symbol_name.startswith("_") and not (
				self._coff and symbol_name):
			# (An ELF `.o` relocates against a section with the offset inside it as the addend, so
			# a name that is not a symbol of this object still says where to look.) A COFF
			# relocation always names a symbol by table index - `strncpy` in `strings.obj` is the
			# CRT's, not an offset in `.text$mn` - so when it names one, the object at that offset
			# is not what the instruction reaches.
			display = self._nearest_in(section_named, addend)
			# A section-relative reference can name a *function* too: a non-PIE 32-bit object pushes
			# the address of its `qsort` comparator as an `R_386_32` against the `.text` section symbol
			# with the function's offset in the field. Classing that as data makes the two sides
			# disagree about what kind of thing the reference reaches.
			owner = self._by_section_address.get((section_named, addend))
			if owner is not None and (section_named, addend) in self._function_keys:
				return {"kind": "function", "address": addend, "section": section_named,
					"size": owner.size or None, "content": None, "display": display,
					"name": display, "identity": "%s+0x%x" % (section_named, addend)}
			# the object defined at that offset is what the instruction reads, so it is the name
			# to compare - `.data.rel.ro+0x18` is a section, and the other side has no such thing
			return {"kind": "data", "address": addend, "section": section_named, "size": None,
				"content": self._read_data(section_named, addend, 0, display), "display": display,
				"name": display,
				# in an object file every section is addressed from 0, so an offset alone names
				# nothing: `.rodata+0x18` and `.rodata.cst4+0x18` are different objects
				"identity": "%s+0x%x" % (section_named, addend)}
		if found is None:
			# not defined here: an import (libc, or a function of another translation unit).
			# Its name is the only thing the two sides share - which is also what makes it
			# comparable, because a compiler reproduces that name on both sides. A COFF object
			# types its undefined externals, so when it says the import is data (`__security_cookie`,
			# which `/GS` reaches through a rip-relative slot) this is a data reference and must be
			# compared as one: the linked image has the object itself, not an import.
			kind = "external" if self._undefined.get(symbol_name, True) else "data"
			return {"kind": kind, "address": None, "section": "", "size": None,
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
			"size": size or None,
			"content": self._read_data(section, where, size or 0, symbol_name),
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
			section.endswith("." + symbol_name) or
			# a COFF COMDAT is named `<section>$<selector>` (`.rdata$.str1`, `.text$?Foo@…`), so
			# the section is named after its one object just the same - with `$`, not `.`
			(self._coff and "$" in section and section.split("$", 1)[1] == symbol_name))

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

	def _relocated(self, section: str, offset: int, length: int) -> bool:
		"""Does a relocation of this section rewrite a byte of this window?"""
		start, stop = int(offset), int(offset) + max(int(length), 1)
		for item in self._relocs.get(section, []):
			where = int(item[0])
			if where < stop and where + (relocation_width(item[1]) or 4) > start:
				return True
		return False

	def _read_data(self, section: str, where: int, size: int, symbol_name: str = "") -> bytes | None:
		"""The bytes of a data object, read far enough for the comparison to use.

		A literal `size`-wide read is not enough for a string: the comparison reads a literal plus
		its terminator (Phase 4), so for something that sits where string literals live the read goes
		on to the NUL.
		"""
		data = self._read(section, where, max(int(size or 0), _PROBE))
		if not _looks_like_string(symbol_name, section):
			return data
		wider = self._read(section, where, _STRING_PROBE)
		if not wider:
			return data
		end = wider.find(b"\0")
		return wider[:end + 1] if end >= 0 else wider

	def _read(self, section: str, offset: int, length: int) -> bytes | None:
		# A section that carries relocations has placeholders where the link will write values, so
		# the bytes *under one of them* are not comparable with a linked image's. It used to be the
		# whole section that was refused on the strength of one record anywhere in it, which threw
		# away every constant in a `.rodata.cst*` pool that shares its section with a pointer: what
		# sits away from the relocations is final at assembly time (Phase 4).
		if section in self._writable or not section.startswith(_COMPARABLE):
			return None
		if self._relocated(section, offset, length):
			return None
		data = self._sections.get(section)
		if data is None:
			return None
		return data[offset:offset + length] or None

	def names(self) -> list[str]:
		return [symbol.simple or symbol.mangled for symbol in self.functions]
