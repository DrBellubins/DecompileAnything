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
# binary gives (Docs/MSVC-Plan.md §4). ELF answers the same question with symbol sizes, which
# Design-Plan Phase 5 reads; Mach-O carries neither.
_PDATA_RECORD = struct.Struct("<III")

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
	language_note: str = ""           # arch/format, for error messages
	warnings: list[str] = field(default_factory=list)


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
		"""`.pdata`, the (begin, end, unwind) table an x64 PE carries, in the file's addresses.

		The RVAs in it are relative to the image base, so every value goes through
		`file_address_base()` - the bias MS-0 put in one place for exactly this reason
		(Docs/MSVC-Plan.md §8). Only the bytes the file initialises are walked: a PE section's
		`size` is its virtual size, which pads past the table, and reading that padding as records
		would invent zero-length units.
		"""
		import lief

		if not isinstance(binary, lief.PE.Binary):
			return
		section = next((item for item in binary.sections if str(item.name) == ".pdata"), None)
		if section is None or not section.size:
			self.unit_note = "no .pdata section: this PE carries no function table"
			return
		data = bytes(section.content)
		bias = file_address_base(binary)
		units, skipped = [], 0
		for position in range(0, len(data) - len(data) % _PDATA_RECORD.size, _PDATA_RECORD.size):
			begin, end, unwind = _PDATA_RECORD.unpack_from(data, position)
			if end <= begin:
				skipped += 1
				continue
			units.append({"source": ".pdata", "entry": int(begin) + bias, "end": int(end) + bias,
				"size": int(end) - int(begin), "unwind": int(unwind) + bias,
				"section": self._section_name(int(begin) + bias)})
		self.units = units
		self.unit_source = ".pdata"
		if not units:
			self.unit_note = ".pdata holds no readable function record"
		elif skipped:
			self.unit_note = "%d .pdata record(s) skipped: end <= begin" % skipped

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


def _string_lengths(conn: sqlite3.Connection, addresses: list[int]) -> dict[int, tuple[int, str]]:
	if not addresses:
		return {}
	marks = ",".join("?" * len(addresses))
	rows = conn.execute("SELECT address, length, value FROM strings WHERE address IN (%s)" % marks,
		addresses)
	return {row["address"]: (int(row["length"] or 0), row["value"]) for row in rows}


def original_function(conn: sqlite3.Connection, meta: dict, row: sqlite3.Row,
	size: int | None = None) -> Function:
	"""The cached bytes and instruction boundaries of one analysed function."""
	entry = int(row["entry"])
	full = int(row["size"])
	wanted = int(size or full)
	warnings: list[str] = []
	try:
		ranges = json.loads(row["ranges"] or "[]")
	except (ValueError, TypeError):  # pragma: no cover - written by us
		ranges = []
	if len(ranges) > 1:
		warnings.append("the analysis records %d separate ranges for this function; only the "
			"first (%s..%s) is compared" % (len(ranges), hex(ranges[0][0]), hex(ranges[0][1])))
		wanted = min(wanted, ranges[0][1] - ranges[0][0]) if ranges else wanted
	start = ranges[0][0] if ranges else entry
	body = bytes(row["bytes"] or b"")
	if body and start != entry:  # pragma: no cover - entry is the first range min
		start = entry
	image = None

	# The file's own function table (MS-1) is the compiler's extent of the unit, gaps and all, so
	# it is what `try` should score. Its bytes are read back out of the file contiguously, which
	# is also the fix for a body the analysis split into ranges: the unit is one range. A caller
	# who passed `--size` asked for a range, so that answer wins over this one, and any
	# disagreement is reported rather than taken silently.
	unit = cache.unit_at(conn, entry)
	if unit is not None and not size:
		extent = int(unit["end"]) - entry
		if extent != full:
			warnings.append("the analysis' body of this function is %d bytes but %s says the unit is "
				"%d (%s..%s): the %d bytes between are inside the unit, so they are compared too - "
				"%s is the compiler's own boundary, not a disassembler's recovery"
				% (full, unit["source"], extent, hex(entry), hex(int(unit["end"])),
					abs(extent - full), unit["source"]))
			image = image or TargetImage(Path(meta.get("target_path") or ""),
				cache.address_offset(meta))
			whole = image.read(entry, extent)
			if whole is not None and len(whole) == extent:
				body, wanted, start = whole, extent, entry
			else:
				warnings.append("those bytes could not be read from %s%s, so only the analysis' range "
					"is compared" % (meta.get("target_path"),
						(": " + image.error) if image.error else ""))
	if len(body) < wanted:
		# the cache stores the body, but a `--size` re-cut can ask past it: read the rest
		# straight from the file the analysis was made of
		image = image or TargetImage(Path(meta.get("target_path") or ""),
			cache.address_offset(meta))
		more = image.read(entry + len(body), wanted - len(body))
		if more:
			body += more
		if not body:
			warnings.append("the cache holds no bytes for this function and %s could not supply "
				"them%s" % (meta.get("target_path"), (": " + image.error) if image.error else ""))
	body = body[:wanted]

	boundaries = [(int(item["address"]), int(item["length"]))
		for item in cache.instructions(conn, row["id"])
		if entry <= int(item["address"]) < entry + wanted]
	return Function(display=row["name"], raw_name=row["name"], address=start, size=wanted,
		bytes=body, section=row["section"] or "", boundaries=boundaries,
		language_note=meta.get("language_id") or "", warnings=warnings)


def original_bindings(conn: sqlite3.Connection, meta: dict, row: sqlite3.Row,
	image: TargetImage | None = None) -> tuple[callable, list[Ref]]:
	"""A `bind(instruction)` for the tokeniser, built from the resolved references.

	Each cached reference knows the instruction it came from and the address it points at, so
	it binds to the operand that encodes that same address - no guessing.
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
		if function is not None:
			# a body's bytes are not comparable (in a `.o` the references inside it are
			# still placeholders), but its size is, and that is what catches "same shape,
			# different helper"
			ref.size = int(function["size"]) or None
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
			match = sorted((item for item in here if int(item["to_address"] or 0) == int(slot.value)),
				key=lambda item: -ranked.get(item["to_kind"] or "address", 0))
			if match:
				chosen[slot.operand] = build(match[0])
		# then anything left over, only when the pairing is unambiguous
		left = [item for item in here if not any(int(item["to_address"] or 0) == slot.value
			for slot in slots if slot.value is not None)]
		free = [slot for slot in slots if slot.operand not in chosen]
		if left and len(left) == 1 and len(free) == 1:
			chosen[free[0].operand] = build(left[0])
		return chosen

	return bind, used


# --------------------------------------------------------------------------------------
# the candidate side: a relocatable object produced by decomp.compile


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

	def symbols_for(self, wanted: str | None, expect_size: int | None = None) -> list[CandidateSymbol]:
		"""The candidate symbols that could be the function being scored."""
		if wanted:
			text = wanted.strip()
			for key in (lambda s: s.mangled == text, lambda s: s.name == text,
				lambda s: s.simple == text,
				lambda s: s.simple.rsplit("::", 1)[-1] == text or s.simple.rsplit(".", 1)[-1] == text):
				found = [symbol for symbol in self.functions if key(symbol)]
				if found:
					return found
			needle = text.lower()
			return [symbol for symbol in self.functions
				if needle in symbol.simple.lower() or needle in symbol.mangled.lower()]
		if expect_size:
			sized = [symbol for symbol in self.functions if symbol.size == expect_size]
			if len(sized) == 1:
				return sized
		return list(self.functions)

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
		body = self._sections.get(symbol.section, b"")
		data = body[symbol.value:symbol.value + symbol.size]
		return Function(display=symbol.simple or symbol.mangled, raw_name=symbol.mangled,
			address=symbol.value, size=symbol.size, bytes=data, section=symbol.section)

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
		relocs = [item for item in self._relocs.get(function.section, [])
			if function.address <= item[0] < function.address + function.size]
		used: list[Ref] = []
		seen: dict[str, Ref] = {}

		def reference(offset: int, kind: str, symbol_name: str, addend: int,
			symbol_section: str = "") -> Ref:
			key = "%s:%s:%d" % (offset, symbol_name, addend)
			if key in seen:
				return seen[key]
			target = self._target(symbol_name, addend, symbol_section)
			named = symbol_name or target["display"]
			where = target["address"]
			ref = Ref(kind=target["kind"],
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
					named = self._in_section(function, slot.value) if slot.value is not None else ""
					if named:
						chosen[slot.operand] = reference(slot.value, "in-section", named, 0)
				return chosen
			free = list(slots)
			if len(free) == len(here):
				# one relocation per remaining address operand, in the same order (usual case)
				for slot, item in zip(free, here):
					chosen[slot.operand] = reference(*item)
			elif len(free) == 1:
				chosen[free[0].operand] = reference(*here[0])
			else:
				for slot in free:
					near = min(here, key=lambda item: abs(item[0] - (instruction.address + slot.enc_offset)))
					chosen[slot.operand] = reference(*near)
			return chosen

		return bind, used

	def _target(self, symbol_name: str, addend: int, symbol_section: str = "") -> dict:
		"""What a relocation names: kind, address, section, size, comparable content, display.

		A relocation that names a *section* (a section symbol, or `.rodata.cst8`) carries the
		offset inside it as the addend; the object defined at that offset (`.LC0`, a table, a
		vtable) is what the instruction really reads, so it is looked up there - for its name,
		while the geometry stays the offset itself.
		"""
		section_named = symbol_name if symbol_name.startswith(".") else symbol_section
		if section_named and not symbol_name.startswith("_"):
			display = self._nearest_in(section_named, addend)
			return {"kind": "data", "address": addend, "section": section_named, "size": None,
				"content": self._read(section_named, addend, _PROBE), "display": display}
		found = self._all_symbols.get(symbol_name)
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
		return {"kind": "data", "address": value + addend, "section": section,
			"size": size or None, "content": self._read(section, value + addend, size or _PROBE),
			"display": symbol_name}

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
