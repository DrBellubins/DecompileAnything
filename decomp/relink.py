"""Phase 6 (Docs/byte-cleanup-plan.md): link what the loop has reproduced, and compare programs.

`decomp try` answers a question about one function. This answers the question the project's claim
actually rests on: put every reproduced source back through the target's own compiler and linker,
and compare the result to the target - not a body at a time, but section by section, at the
addresses the link gave them.

What is compared, and what each part can prove:

* **Code sections** (`.text`, `.init`, `.plt`, `.fini`) are compared as bytes, and paired to
  functions so a difference can be named. A pair is *identical* when the bytes are literally
  equal - no masking: in a linked program the fields Phase 3 had to zero are already resolved, and
  if the layout agrees they hold the same values. A pair whose bytes differ only in the fields a
  pc-relative or absolute operand carries is reported as `only what the link wrote`: the body is
  the same and something *else* moved, which is a consequence, not a second problem.
* **Data sections** (`.rodata`, `.data`, `.data.rel.ro`, `.got*`, `.init_array`, `.eh_frame`,
  `.gcc_except_table`) are compared as bytes too - which is what covers vtables, `type_info`
  objects and pooled constants without a special case - and are annotated with the objects the
  tool can name, from the target's own symbol table, from the candidate's, or from the structure
  the `structures` recovery recovered out of the RTTI. `.bss` has no file bytes, so only its size
  is comparable.
* **The dynamic relocation table** (`.rela.dyn`, `.rela.plt`) is compared as a table: which slot
  holds a runtime pointer, and what it points at. In a PIE the file bytes of a pointer table are
  zeros and the value lives in the relocation's addend, so this is the only honest way to compare
  a vtable's slots or a static initialiser's pointers.

Pairing a target unit to a candidate function carries the same discipline as the match ledger:
`name` (both files name it), `ledger` (an earlier unit showed which symbol reproduces it), or
`address` (the surrounding layout puts this body here and its length agrees - which says nothing
about identity, and is labelled as such).

ELF only for now: a PE's sections, COFF symbols and `link` command need the toolset checks of
Phase 7, and saying so beats comparing a PE with the wrong assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import diff, extract, normalize

# Sections a program's content lives in. What is skipped is metadata the link writes *about* the
# program rather than out of its sources: the symbol and string tables, the dynamic section and
# its hash and version tables, the interpreter, notes, comments, debug sections, and the
# relocation tables themselves - those are compared as tables, not as bytes, because their entries
# name symbols rather than holding addresses the source chose.
_SKIPPED = (".symtab", ".strtab", ".shstrtab", ".dynsym", ".dynstr", ".dynamic", ".hash",
	".gnu.hash", ".gnu.version", ".gnu.version_r", ".rela", ".rel.", ".interp", ".note",
	".comment", ".debug", ".llvm", ".GCC.command.line", ".gpt")
# The sections that hold code: these are the ones worth pairing to functions.
_CODE_SECTIONS = (".text", ".init", ".fini", ".plt", "__text")


def comparable(name: str) -> bool:
	"""Is this section's content part of the program?"""
	return bool(name) and not name.startswith(_SKIPPED)


def _hex(value) -> str:
	return "0x%x" % int(value) if isinstance(value, int) else str(value)


def _nobits(section) -> bool:
	"""Is this `SHT_NOBITS` - a section that reserves space and stores no bytes?

	Read through `warnings`: a LIEF build that does not know a newer section type randers a
	RuntimeWarning on `section.type`, which here is noise - an unknown type is not NOBITS.
	"""
	import warnings
	try:
		with warnings.catch_warnings():
			warnings.simplefilter("ignore")
			return "NOBITS" in str(getattr(section, "type", "") or "").upper()
	except Exception:  # noqa: BLE001
		return False


# --------------------------------------------------------------------------------------
# reading a program: sections, symbols, runtime relocations


@dataclass
class Section:
	name: str
	address: int           # in this Program's domain (see `bias`)
	size: int
	offset: int            # where the file keeps it
	data: bytes | None     # None: no bytes in the file (.bss), or unreadable
	initialised: bool      # False: the section reserves space and stores no bytes (SHT_NOBITS)
	alloc: bool
	writable: bool
	executable: bool


@dataclass
class Symbol:
	name: str              # as the file spells it
	address: int
	size: int
	kind: str              # function | object | other


class Program:
	"""One linked program: its sections, the symbols it carries, its runtime relocations.

	`bias` puts every address in the domain the caller wants. For the target that is the analysis'
	domain (`cache.address_offset`, the same offset every other command speaks), so an entry from
	`decomp find` can be compared directly. For the program this command just linked it is 0.
	"""

	def __init__(self, path: Path, bias: int = 0) -> None:
		self.path = Path(path)
		self.bias = int(bias)
		self.error = ""
		self.format = ""
		self.bits = 0
		self.sections: list[Section] = []
		self.symbols: list[Symbol] = []
		self.relocs: list[dict] = []
		self._by_name: dict[str, Section] = {}
		binary = self._parse()
		if binary is None:
			return
		for section in binary.sections:
			name = str(section.name)
			size = int(section.size or 0)
			if not size:
				continue
			allocated, writable, executable = extract.section_capabilities(
				getattr(binary, "format", None), section)
			# A NOBITS section has a size and no file bytes; LIEF still hands back bytes read at
			# its file offset, which belong to whatever section is stored there. `.bss` compared
			# against `.shstrtab` is worse than saying it cannot be compared.
			initialised = not _nobits(section)
			try:
				content = bytes(section.content) if section.content else b""
			except Exception:  # noqa: BLE001 - a section LIEF cannot read is reported, not fatal
				content = b""
			item = Section(name=name, address=int(section.virtual_address) + self.bias, size=size,
				offset=int(section.offset), data=content or None, initialised=initialised,
				alloc=allocated, writable=writable, executable=executable)
			self.sections.append(item)
			self._by_name[name] = item
		self._read_symbols(binary)
		self._read_relocs(binary)

	def _parse(self):
		try:
			import lief
		except ImportError as exc:  # pragma: no cover - `decomp check` reports this
			self.error = "lief is not importable: %s" % exc
			return None
		try:
			binary = lief.parse(str(self.path))
		except Exception as exc:  # noqa: BLE001
			self.error = "lief could not parse %s: %s" % (self.path.name, exc)
			return None
		if binary is None:
			self.error = "lief could not parse %s" % self.path.name
			return None
		format_name = str(getattr(binary, "format", "") or "")
		self.format = format_name.split(".")[-1].lower() if "." in format_name else format_name
		if self.format not in ("elf",):
			self.error = ("%s is %s: the relink comparison reads ELF sections for now "
				"(Docs/byte-cleanup-plan.md Phase 6); individual functions are still scored by "
				"`decomp try`" % (self.path.name, self.format or "an unknown format"))
			return None
		try:
			self.bits = int(getattr(binary.header, "address_size", 0) or 0) * 8
		except Exception:  # noqa: BLE001
			self.bits = 0
		return binary

	def _read_symbols(self, binary) -> None:
		try:
			symbols = list(binary.symbols)
		except Exception:  # noqa: BLE001 - a stripped file has none, which is an answer
			return
		import lief
		want = {getattr(lief.ELF.Symbol.TYPE, "FUNC", None): "function",
			getattr(lief.ELF.Symbol.TYPE, "OBJECT", None): "object"}
		for symbol in symbols:
			try:
				kind = want.get(symbol.type, "other")
				value = int(symbol.value or 0)
			except Exception:  # noqa: BLE001
				continue
			if not value or kind == "other":
				continue
			self.symbols.append(Symbol(name=str(symbol.name or ""), address=value + self.bias,
				size=int(symbol.size or 0), kind=kind))

	def _read_relocs(self, binary) -> None:
		"""The runtime relocations: the slots the loader fills in, and what each one names."""
		try:
			items = list(binary.dynamic_relocations)
		except Exception:  # noqa: BLE001 - a static file has none
			return
		for entry in items:
			try:
				name = entry.symbol.name if entry.has_symbol else ""
				target = int(entry.addend or 0)
			except Exception:  # noqa: BLE001
				name, target = "", int(getattr(entry, "addend", 0) or 0)
			self.relocs.append({"address": int(entry.address or 0) + self.bias,
				"kind": str(entry.type or ""), "symbol": str(name or ""), "target": target})

	# -- lookups ----------------------------------------------------------------------

	def section(self, name: str) -> Section | None:
		return self._by_name.get(name)

	def comparable_sections(self) -> list[Section]:
		return [item for item in self.sections if item.alloc and comparable(item.name)]

	def bytes_at(self, address: int, size: int) -> bytes | None:
		"""The file's bytes at an address in this Program's domain.

		`section.content` covers the section in almost every case; where it does not, the file is
		read at `offset + (address - virtual_address)` instead of assuming the two differ by a
		constant, which is the bias that makes a PE or Mach-O address read wrong.
		"""
		for item in self.sections:
			if not item.address <= address < item.address + item.size:
				continue
			step = address - item.address
			if item.data is not None and step + size <= len(item.data):
				return item.data[step:step + size]
			if item.offset:
				try:
					with self.path.open("rb") as handle:
						handle.seek(item.offset + step)
						return handle.read(size)
				except OSError:  # pragma: no cover
					return None
			return None
		return None

	def _section_of(self, address: int) -> str:
		for item in self.sections:
			if item.address <= address < item.address + item.size:
				return item.name
		return ""

	def extents(self, kind: str = "function") -> list[dict]:
		"""The objects this file names, by section, with extents filled in where it can.

		A symbol's `size` is what the compiler recorded; where it is zero (a local symbol, or a
		format that does not carry sizes) the next symbol in the same section bounds it, which is
		the same fallback `extract.CandidateObject._code_extent` uses for a candidate `.o`.
		"""
		grouped: dict[str, list[Symbol]] = {}
		for symbol in self.symbols:
			if symbol.kind != kind:
				continue
			grouped.setdefault(self._section_of(symbol.address), []).append(symbol)
		out: list[dict] = []
		for section, items in grouped.items():
			items.sort(key=lambda item: item.address)
			for index, symbol in enumerate(items):
				size = symbol.size
				if not size and index + 1 < len(items):
					size = items[index + 1].address - symbol.address
				if size <= 0:
					continue
				out.append({"address": symbol.address, "size": size, "name": symbol.name,
					"section": section})
		return sorted(out, key=lambda item: item["address"])



# --------------------------------------------------------------------------------------
# pairing: which body on one side is which body on the other


def pair_extents(original: list[dict], candidate: list[dict], anchors: dict[int, str]) -> dict:
	"""Walk two extent lists in address order and say which body is which.

	Three things decide a pair, in order of how much they prove:

	* an **anchor** - the target names this symbol and so does the candidate, or the match ledger
	  says this candidate symbol reproduces this address (Phase 5). That is a claim about identity.
	* **the layout**: the running difference between the two sides' addresses, which only moves at
	  a place where one side has something the other does not, or something of a different length.
	  A pair made that way is labelled `address`: it says these bytes are here, not that they mean
	  the same thing.
	* **agreement on length**, which is what makes a shifted pair plausible at all.

	A pair whose lengths differ is kept and reported as a size difference: that is the event that
	moves everything after it, and naming it is the whole point of the report.
	"""
	pairs: list[dict] = []
	only_original: list[dict] = []
	only_candidate: list[dict] = []
	shifts: list[dict] = []
	wanted: dict[str, int] = {}
	for item in original:
		name = anchors.get(item["address"])
		if name:
			wanted.setdefault(normalize.canonical_name(name), item["address"])
	delta: int | None = None
	i = j = 0
	while i < len(original) and j < len(candidate):
		left, right = original[i], candidate[j]
		anchor = anchors.get(left["address"])
		if anchor and normalize.canonical_name(anchor) != normalize.canonical_name(right["name"]):
			# this candidate body belongs to a later one; whatever is here is not paired
			only_candidate.append(right)
			j += 1
			continue
		if anchor is None and wanted.get(normalize.canonical_name(right["name"])) is not None:
			only_candidate.append(right)
			j += 1
			continue
		if delta is None or left["address"] + delta != right["address"]:
			delta = right["address"] - left["address"]
		if left["size"] != right["size"] and anchor is None:
			# before calling it a size difference, check for an insertion: one extra body on
			# either side realigns everything after it. A lengthened body and an inserted one
			# look identical to the layout, which is why an anchor - a name, or the match
			# ledger - skips this: it says what this body is, whatever its length.
			if (i + 1 < len(original) and original[i + 1]["size"] == right["size"]
					and original[i + 1]["size"] != left["size"]):
				only_original.append(left)
				i += 1
				continue
			if (j + 1 < len(candidate) and candidate[j + 1]["size"] == left["size"]
					and candidate[j + 1]["size"] != right["size"]):
				only_candidate.append(right)
				j += 1
				continue
		evidence = "address"
		if anchor:
			evidence = "ledger" if normalize.canonical_name(anchor) != normalize.canonical_name(
				left.get("name") or "") else "name"
		elif normalize.canonical_name(left.get("name") or "") == normalize.canonical_name(
				right["name"]) and not normalize.is_synthetic(left.get("name") or ""):
			evidence = "name"
		pairs.append({"original": left, "candidate": right, "evidence": evidence,
			"delta": right["address"] - left["address"]})
		i += 1
		j += 1
	only_original.extend(original[i:])
	only_candidate.extend(candidate[j:])
	# A pair whose length differs is only a claim if the layout moves there and *stays* moved. If
	# the next body sits at the old offset again, the two lists simply do not name the same
	# functions there - an analysis' unit table and a program's symbol table never agree exactly
	# through the CRT start-up code - and calling that a size difference would send the reader to
	# a function that is fine. Such a pair becomes two unpaired extents instead.
	kept: list[dict] = []
	for index, pair in enumerate(pairs):
		if (pair["original"]["size"] != pair["candidate"]["size"]
				and pair["evidence"] == "address"):
			before = pairs[index - 1]["delta"] if index else None
			after = pairs[index + 1]["delta"] if index + 1 < len(pairs) else None
			if after is None or after == before:
				only_original.append(pair["original"])
			only_candidate.append(pair["candidate"])
			continue
		kept.append(pair)
	pairs = kept
	# The layout moves are read off the pairs that survived, so a shift is never claimed at a
	# place this function has just decided it cannot pair.
	for index, pair in enumerate(pairs):
		if index and pair["delta"] != pairs[index - 1]["delta"]:
			shifts.append({"address": pair["original"]["address"], "from": pairs[index - 1]["delta"],
				"to": pair["delta"], "after": pairs[index - 1]["original"]})
	only_original.sort(key=lambda item: item["address"])
	only_candidate.sort(key=lambda item: item["address"])
	return {"pairs": pairs, "only_original": only_original, "only_candidate": only_candidate,
		"shifts": shifts}


# --------------------------------------------------------------------------------------
# comparing one body at its linked address


def _instruction_index(blocks: list, instructions: list) -> dict:
	"""Body offset -> the instruction it falls in, for byte-level reports."""
	out: dict[int, str] = {}
	for instruction in instructions:
		block = normalize.block_of(blocks, int(instruction.address))
		if block is None:
			continue
		label = "%s  %s" % (_hex(int(instruction.address)), normalize.format_instruction(
			instruction.mnemonic, instruction.operands))
		start = block[2] + (int(instruction.address) - block[0])
		for step in range(int(instruction.length or 0)):
			out[start + step] = label
	return out


def compare_body(handle, left_bytes: bytes, left_at: int, right_bytes: bytes, right_at: int) -> dict:
	"""Compare two bodies the link placed at two addresses.

	Unlike `decomp try` this needs no masking to be meaningful: both sides are final linked code,
	so the fields Phase 3 zeroes hold real addresses on both sides, and equal source plus equal
	layout means equal bytes. The masked comparison is still run when the raw one fails, because
	that is what separates *this body differs* from *this body is the same and something else
	moved* - the second is a consequence, and saying so is what stops the loop chasing it.
	"""
	out = {"status": "", "first_difference": {}, "fields": {}}
	if not left_bytes or not right_bytes:
		out["status"] = "unreadable"
		return out
	if left_bytes == right_bytes:
		out["status"] = "identical"
		return out
	if len(left_bytes) != len(right_bytes):
		out["status"] = "size"
		out["first_difference"] = {"offset": min(len(left_bytes), len(right_bytes)),
			"lengths": [len(left_bytes), len(right_bytes)]}
		return out
	if handle is None:
		out["status"] = "differs"
		return out
	blocks_left = normalize.body_blocks(None, left_at, len(left_bytes))
	blocks_right = normalize.body_blocks(None, right_at, len(right_bytes))
	ins_left = normalize.decode_function(handle, left_at, left_bytes, extents=None)
	ins_right = normalize.decode_function(handle, right_at, right_bytes, extents=None)
	if not ins_left or not ins_right:
		out["status"] = "differs"
		return out
	# `bind` resolves nothing on either side. That is symmetric, and for linked code it is right:
	# every pc-relative and absolute operand already holds the address the linker chose, and an
	# in-body branch stays compared.
	fields_left = normalize.merge_fields(normalize.address_fields(blocks_left, ins_left, lambda i: {}))
	fields_right = normalize.merge_fields(normalize.address_fields(blocks_right, ins_right, lambda i: {}))
	result = diff.compare_bytes(left_bytes, fields_left, right_bytes, fields_right,
		_instruction_index(blocks_left, ins_left), _instruction_index(blocks_right, ins_right))
	out["fields"] = result["fields"]
	if result["equal"]:
		out["status"] = "link_fields"
		return out
	out["status"] = "differs"
	offset = int(result["first"].get("offset") or 0)
	out["first_difference"] = {"offset": offset, "address": left_at + offset,
		"original": result["first"].get("original") or "",
		"candidate": result["first"].get("candidate") or "",
		"bytes": [left_bytes[offset:offset + 8].hex(), right_bytes[offset:offset + 8].hex()]}
	return out


# --------------------------------------------------------------------------------------
# comparing a whole program


def _section_bytes(program: Program, name: str) -> bytes:
	item = program.section(name)
	if item is None:
		return b""
	if item.data is not None:
		return bytes(item.data)
	found = program.bytes_at(item.address, item.size)
	return bytes(found or b"")


def compare_program(target: Program, candidate: Program, *, units: list[dict],
		anchors: dict[int, str] | None = None, language: str = "", objects: list[dict] | None = None,
		only: list[str] | None = None) -> dict:
	"""Relinked program against target, section by section.

	`units` are the target's own function units ({entry,size,name,section}) in the target Program's
	address domain; `objects` are the target's named data objects ({address,size,name}) where the
	target or its recovered structure names them; `anchors` maps a unit's address to the candidate
	symbol an earlier unit showed reproduces it (the match ledger, Phase 5).
	"""
	anchors = anchors or {}
	handle = normalize.capstone_for(language, detail=True)
	cand_objects = data_objects(candidate)
	names = [item.name for item in target.comparable_sections() + candidate.comparable_sections()]
	wanted = [name for name in dict.fromkeys(names) if comparable(name)
		and (not only or name in only)]
	# Code sections are compared first on purpose: the layout shifts they show are what lets a
	# later data section's differing bytes be recognised as pointers to what moved rather than
	# as different data.
	wanted = ([name for name in sorted(wanted) if name in _CODE_SECTIONS]
		+ [name for name in sorted(wanted) if name not in _CODE_SECTIONS])
	report = {"sections": [], "warnings": [], "first_difference": {}, "summary": {}}
	moved: dict[int, dict] = {}
	counts = {"identical": 0, "differs": 0, "missing": 0, "units": 0, "units_identical": 0,
		"units_link_fields": 0, "units_differ": 0, "consequences": 0, "unpaired": 0}
	for name in sorted(wanted):
		left, right = target.section(name), candidate.section(name)
		entry = {"name": name, "original_size": left.size if left else 0,
			"candidate_size": right.size if right else 0, "units": [], "shifts": [],
			"only_original": [], "only_candidate": [], "named": [], "first_difference": {},
			"relocations": {}}
		if left is None or right is None:
			entry["status"] = "missing_original" if left is None else "missing_candidate"
			counts["missing"] += 1
			report["sections"].append(entry)
			continue
		if not left.initialised or not right.initialised:
			# An uninitialised section (`.bss`) has no bytes in the file at all, so there is
			# nothing to compare but how much of the program it reserves. Reading the file where
			# its header points is worse than saying so: it reads whatever section shares that
			# file offset.
			entry["status"] = "identical" if left.size == right.size else "size"
			entry["note"] = "no file bytes (uninitialised): the size is all a link writes here"
			counts["identical" if entry["status"] == "identical" else "differs"] += 1
			report["sections"].append(entry)
			continue
		left_bytes, right_bytes = _section_bytes(target, name), _section_bytes(candidate, name)
		if name in _CODE_SECTIONS and units:
			group = [item for item in units
				if (item.get("section") or target._section_of(int(item["entry"]))) == name]
			grouped = [{"address": item["entry"], "size": item["size"], "name": item["name"],
				"section": name, "kind": item.get("kind") or ""} for item in group]
			grouped.sort(key=lambda item: item["address"])
			paired = pair_extents(grouped,
				[item for item in candidate.extents("function") if item["section"] == name], anchors)
			for pair in paired["pairs"]:
				body = compare_body(handle, target.bytes_at(pair["original"]["address"],
					pair["original"]["size"]) or b"", pair["original"]["address"],
					candidate.bytes_at(pair["candidate"]["address"], pair["candidate"]["size"]) or b"",
					pair["candidate"]["address"])
				body.update({"original": pair["original"], "candidate": pair["candidate"],
					"evidence": pair["evidence"]})
				if body["status"] == "link_fields":
					before = [shift for shift in paired["shifts"]
						if shift["address"] <= pair["original"]["address"]]
					body["consequence_of"] = before[0]["address"] if before else paired["shifts"][
						0]["address"] if paired["shifts"] else None
					counts["consequences"] += 1
				entry["units"].append(body)
			entry["shifts"] = paired["shifts"]
			for shift in paired["shifts"]:
				if not shift.get("oscillated"):
					moved.setdefault(shift["to"] - shift["from"], {
						"address": shift["address"], "section": name})
			entry["only_original"] = paired["only_original"]
			entry["only_candidate"] = paired["only_candidate"]
			# The first *bytes* that differ and the first *body* that differs are not the same
			# thing, and only the second one is worth working on: an absolute operand inside a
			# function that merely points at something that moved differs in bytes while its code
			# is the same. Keep both, labelled.
			first_body = next((item for item in entry["units"]
				if item["status"] in ("differs", "size")), None)
			if first_body is not None:
				entry["first_body"] = {"address": first_body["original"]["address"],
					"name": first_body["original"].get("name") or "?",
					"candidate": first_body["candidate"].get("name") or "?",
					"status": first_body["status"], "size": first_body["original"]["size"],
					"candidate_size": first_body["candidate"]["size"]}
			counts["unpaired"] += len(paired["only_original"]) + len(paired["only_candidate"])
		for item in objects or ():
			if item.get("section") and item["section"] != name:
				continue
			key = normalize.canonical_name(item.get("match") or item["name"])
			match = next((other for other in cand_objects if other["key"] == key), None)
			if match is None:
				entry["named"].append({"name": item["name"], "address": item["address"],
					"status": "unmatched", "evidence": "name"})
				continue
			a = target.bytes_at(item["address"], int(item["size"])) or b""
			b = candidate.bytes_at(match["address"], int(match["size"])) or b""
			entry["named"].append({"name": item["name"], "address": item["address"],
				"candidate": match["name"], "candidate_address": match["address"],
				"size": len(a), "candidate_size": len(b), "evidence": "name",
				"status": "identical" if a and a == b else ("size" if len(a) != len(b) else "differs")})
		if name.startswith(".rela"):
			entry["relocations"] = compare_relocations(target, candidate)
		if left_bytes == right_bytes:
			entry["status"] = "identical"
			counts["identical"] += 1
			if entry["only_original"] or entry["only_candidate"] or entry["shifts"] or any(
					item["status"] != "identical" for item in entry["units"]):
				# The bytes say the whole section matches end to end. Whatever the pairing could
				# not line up is a limit of naming (the target's unit list against this program's
				# symbol table), and saying that beats leaving a reader to wonder what the
				# unpaired extents mean.
				entry["pairing_note"] = ("the section's bytes are identical end to end: what this "
					"report could not pair names a limit of the pairing, not a difference")
		else:
			common = min(len(left_bytes), len(right_bytes))
			offset = next((step for step in range(common) if left_bytes[step] != right_bytes[step]),
				common)
			entry["status"] = "size" if len(left_bytes) != len(right_bytes) else "differs"
			found = _name_at(entry, left.address + offset)
			entry["first_difference"] = {
				"offset": offset, "address": left.address + offset,
				"inside": found,
				"bytes": [left_bytes[offset:offset + 8].hex(), right_bytes[offset:offset + 8].hex()]}
			covering = next((item for item in entry["units"] if item["original"]["address"]
				<= left.address + offset < item["original"]["address"] + item["original"]["size"]), None)
			if covering is not None and covering["status"] == "link_fields":
				entry["first_difference"]["kind"] = "link_rewritten"
			elif covering is not None and covering["status"] in ("differs", "size"):
				entry["first_difference"]["kind"] = "body"
			else:
				entry["first_difference"]["kind"] = "unpaired"
			# A data byte that differs by exactly the amount a body moved is a pointer to that
			# body, not different data. Say which, because the second is work and the first is a
			# consequence of it.
			for width in (8, 4):
				a = int.from_bytes(left_bytes[offset:offset + width], "little")
				b = int.from_bytes(right_bytes[offset:offset + width], "little")
				step = b - a
				if step in moved and a and target.bytes_at(a, 1) is not None:
					entry["first_difference"].update({"kind": "pointer_to_moved",
						"points_at": a, "step": step,
						"explained_by": moved[step]})
					break
			counts["differs"] += 1
		for body in entry["units"]:
			counts["units"] += 1
			counts["units_" + body["status"]] = counts.get("units_" + body["status"], 0) + 1
		real = entry.get("first_body") or entry.get("first_difference")
		if real and (not report["first_difference"]
				or int(real.get("address") or 0) < int(report["first_difference"].get("address") or 0)):
			report["first_difference"] = dict(real, section=name)
		report["sections"].append(entry)
	report["sections"].sort(key=lambda item: item["name"])
	report["summary"] = counts
	report["identical"] = bool(report["sections"]) and counts["differs"] == 0 and counts[
		"missing"] == 0 and not report["first_difference"]
	return report


def _name_at(entry: dict, address: int) -> str:
	"""What a differing byte sits in, from the pairing and the named objects of that section."""
	for body in entry["units"]:
		low = body["original"]["address"]
		if low <= address < low + body["original"]["size"]:
			return "%s at %s" % (body["original"].get("name") or "?", _hex(low))
	for item in entry["named"]:
		low = item.get("address") or 0
		if low <= address < low + int(item.get("size") or 0):
			return "%s at %s" % (item.get("name") or "?", _hex(low))
	return ""


def compare_relocations(target: Program, candidate: Program) -> dict:
	"""The runtime relocation tables, compared as tables.

	In a PIE the file bytes of `.data`/`.data.rel.ro` are zeros: the value of a vtable slot or a
	static initialiser's pointer is the relocation's addend. So this is the only place those
	objects can be compared at all - and the only one that also compares `.plt` thunks, which is
	where an unresolved import shows up.
	"""
	by_slot = {}
	for entry in target.relocs:
		by_slot.setdefault(entry["address"], []).append(entry)
	other = {}
	for entry in candidate.relocs:
		other.setdefault(entry["address"], []).append(entry)
	out = {"original": len(target.relocs), "candidate": len(candidate.relocs), "differing": [],
		"only_original": sorted(set(by_slot) - set(other)), "only_candidate": sorted(
			set(other) - set(by_slot))}
	for address in sorted(set(by_slot) & set(other)):
		for a, b in zip(by_slot[address], other[address]):
			if a["kind"] != b["kind"] or normalize.canonical_name(a["symbol"] or "") != normalize.canonical_name(
					b["symbol"] or "") or (not a["symbol"] and not b["symbol"]
					and a["target"] != b["target"]):
				out["differing"].append({"address": address, "original": a, "candidate": b})
	return out


def demangle_names(names: list[str]) -> dict[str, str]:
	"""What the C++ ABI says these symbols are (`_ZTV7CFoo` -> `vtable for CFoo`)."""
	try:
		return normalize.demangle(list(names))
	except Exception:  # noqa: BLE001 - no c++filt on this machine: match on the raw spelling
		return {}


def data_objects(program: Program) -> list[dict]:
	"""The named data objects of a program, with the key both sides can be matched on.

	A vtable is the same object in two files under two spellings: one calls it `_ZTV7CFoo`, the
	other (a stripped target, named out of its RTTI) calls it `vtable for CFoo`. Both are the
	same thing to `canonical_name`, which is what lets a recovered structure be compared to a
	candidate symbol without either side pretending to know the other's names.
	"""
	items = program.extents("object")
	demangled = demangle_names([item["name"] for item in items])
	for item in items:
		item["display"] = demangled.get(item["name"]) or item["name"]
		item["key"] = normalize.canonical_name(item["display"]) or normalize.canonical_name(
			item["name"])
	return items


def report_lines(result: dict, *, max_units: int = 12, max_rows: int = 8) -> list[str]:
	"""The relink report, in the compact form an LLM reads."""
	lines: list[str] = []
	summary = result.get("summary", {})
	lines.append("program %s" % ("IDENTICAL" if result.get("identical") else "DIFFERS"))
	lines.append("  sections compared %d: %d identical, %d differ, %d missing on one side" % (
		len(result.get("sections", [])), summary.get("identical", 0), summary.get("differs", 0),
		summary.get("missing", 0)))
	lines.append("  functions compared at their linked addresses %d: %d byte-identical, %d differ only "
		"in what the link wrote (a consequence of layout), %d differ, %d a different length; %d "
		"extents on one side with no pair%s" % (summary.get("units", 0),
			summary.get("units_identical", 0), summary.get("consequences", 0),
			summary.get("units_differs", 0), summary.get("units_size", 0), summary.get("unpaired", 0),
			" - those last two are counts of what this report could not *name*, not of bytes that "
			"differ: the section rows say what differs"
			if (summary.get("unpaired") or summary.get("units_size")) else ""))
	first = result.get("first_difference") or {}
	if first:
		if first.get("name"):
			lines.append("  first function whose own code differs: %s at %s in section %s (%s, %d "
				"bytes vs %d)" % (first["name"], _hex(first["address"]), first.get("section"),
					first["status"], first.get("size", 0), first.get("candidate_size", 0)))
			lines.append("    paired to the candidate's %s - that is the one to work on" % (
				first.get("candidate") or "?"))
		else:
			lines.append("  first difference: section %s at offset 0x%x (%s)%s" % (first.get("section"),
				first.get("offset", 0), _hex(first.get("address", 0)),
				" - inside %s" % first["inside"] if first.get("inside") else ""))
			if first.get("bytes"):
				lines.append("    bytes there: original %s / candidate %s" % tuple(first["bytes"]))
	for entry in result.get("sections", []):
		if entry["status"] == "identical":
			lines.append("  %-18s %7d  identical" % (entry["name"], entry["original_size"]))
			continue
		lines.append("  %-18s %7d vs %-7d %s" % (entry["name"], entry["original_size"],
			entry["candidate_size"], entry["status"]))
		if entry.get("note"):
			lines.append("      %s" % entry["note"])
		if entry.get("pairing_note"):
			lines.append("      %s" % entry["pairing_note"])
		gap = entry.get("first_difference") or {}
		if gap:
			if gap.get("kind") == "pointer_to_moved":
				lines.append("      first bytes that differ at offset 0x%x (%s) - a pointer to %s, "
					"which moved by %+d bytes at %s in %s: a consequence, not different data" % (
						gap.get("offset", 0), _hex(gap.get("address", 0)), _hex(gap["points_at"]),
						gap["step"], _hex(gap["explained_by"]["address"]),
						gap["explained_by"]["section"]))
			else:
				label = {"link_rewritten": "an address the link rewrote, not a source difference",
					"body": "inside a body whose own code differs",
					"unpaired": "in a region this report could not pair"}.get(gap.get("kind"), "")
				lines.append("      first bytes that differ at offset 0x%x (%s)%s%s" % (
					gap.get("offset", 0), _hex(gap.get("address", 0)),
					" - inside %s" % gap["inside"] if gap.get("inside") else "",
					" - %s" % label if label else ""))
		body = entry.get("first_body")
		if body:
			lines.append("      first function whose own code differs: %s at %s (%s, %d bytes vs %d)"
				% (body["name"], _hex(body["address"]), body["status"], body.get("size", 0),
					body.get("candidate_size", 0)))
		for shift in entry.get("shifts", [])[:max_rows]:
			lines.append("      layout moved from %+d to %+d bytes at %s%s - everything after that "
				"offset is compared at the new one" % (shift["from"], shift["to"],
					_hex(shift["address"]),
					" (the length of %s changed)" % ((shift.get("after") or {}).get("name") or "?")
					if shift.get("after") else ""))
		for body in ([item for item in entry.get("units", []) if item["status"] != "identical"]
				if entry["status"] != "identical" else [])[:max_units]:
			lines.append("      %-9s %s  original %s  candidate %s" % (body["status"],
				_hex(body["original"]["address"]), body["original"].get("name") or "?",
				body["candidate"].get("name") or "?"))
			lines.append("        %d bytes vs %d, paired by %s%s" % (body["original"]["size"],
				body["candidate"]["size"], body["evidence"],
				"  (consequence of the layout change at %s - this body's own bytes are the same)"
				% _hex(body["consequence_of"]) if body.get("consequence_of") else ""))
			found = body.get("first_difference") or {}
			if found.get("bytes"):
				lines.append("        at offset 0x%x (%s): %s / %s" % (found.get("offset", 0),
					found.get("address") and _hex(found["address"]), found["bytes"][0],
					found["bytes"][1]))
				if found.get("original") or found.get("candidate"):
					lines.append("          original:  %s" % (found.get("original") or "?"))
					lines.append("          candidate: %s" % (found.get("candidate") or "?"))
		for item in (entry.get("only_original", []) if entry["status"] != "identical" else [])[
				:max_rows]:
			lines.append("      only in the target at %s: %s (%d bytes)" % (_hex(item["address"]),
				item.get("name") or "?", item["size"]))
		for item in (entry.get("only_candidate", []) if entry["status"] != "identical" else [])[
				:max_rows]:
			lines.append("      only in the candidate at %s: %s (%d bytes)" % (_hex(item["address"]),
				item.get("name") or "?", item["size"]))
		for item in [item for item in entry.get("named", []) if item["status"] != "identical"][
				:max_rows]:
			lines.append("      %s %-52s %s" % (item["status"], item.get("name") or "?",
				"%s vs %s" % (_hex(item.get("address") or 0), _hex(item.get("candidate_address") or 0))))
		relocs = entry.get("relocations") or {}
		if relocs:
			lines.append("      runtime relocations: %d vs %d, %d differ%s%s" % (relocs["original"],
				relocs["candidate"], len(relocs["differing"]),
				", %d slots only in the target" % len(relocs["only_original"])
				if relocs["only_original"] else "",
				", %d only in the candidate" % len(relocs["only_candidate"])
				if relocs["only_candidate"] else ""))
			for row in relocs["differing"][:max_rows]:
				lines.append("        %s  original %s -> %s   candidate %s -> %s" % (
					_hex(row["address"]), row["original"]["kind"],
					row["original"]["symbol"] or _hex(row["original"]["target"]),
					row["candidate"]["kind"], row["candidate"]["symbol"] or _hex(
						row["candidate"]["target"])))
	for warning in result.get("warnings", []):
		lines.append("  note: %s" % warning)
	if not result.get("identical"):
		lines.append("  next: the first section that differs is the one to work on, and within it the "
			"first function whose bytes differ - a body that differs only in what the link wrote is "
			"not a problem, it is where an earlier difference moved the layout")
	return lines
