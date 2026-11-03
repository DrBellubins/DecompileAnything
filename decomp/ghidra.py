"""PyGhidra wrapper: open a target, run auto-analysis, export the facts the cache stores.

The only module that touches the JVM, and the only command that needs it (`analyze`). All
`ghidra.*` imports happen inside functions: PyGhidra exposes Ghidra's packages as pseudo-
modules that exist only after `pyghidra.start()`.

API notes for the pinned pair (Ghidra 12.1.2 / PyGhidra 3.1.0), all verified - see
Docs/Setup.md §5, which also explains why the project path may not contain a dot-prefixed
element and why `open_project` insists on an absolute path:

	* no `pyghidra.gopen`; `open_program()` is deprecated -> `open_project()` + `program_loader()`
	* `program_loader().source()` needs a **str**, `.load()` takes no monitor (use `.monitor()`),
	  and returns `LoadResults` -> `.getPrimaryDomainObject()`
	* `DecompInterface.decompileFunction()` returns `DecompileResults` directly: `isValid()`,
	  `getErrorMessage()`, then `.getDecompiledFunction().getC()`
	* `AddressSet` has no `getNumBytes()`; use the address ranges
	* `getReferencesFrom()` also yields stack/register references - keep `isMemoryReference()`
	  and read the call/data/jump-ness off `ReferenceType`, not off the Reference
"""

from __future__ import annotations

import time
from pathlib import Path

from . import cache, config, normalize

DECOMPILE_TIMEOUT_SECONDS = 30
MAX_STRING_LENGTH = 512
MAX_STRINGS = 20000


class GhidraError(Exception):
	pass


def started() -> bool:
	import pyghidra

	return pyghidra.started()


def start(install_dir: Path) -> None:
	"""Start the JVM once for this process."""
	if started():
		return
	import pyghidra

	pyghidra.start(install_dir=Path(install_dir))


def analyze_target(cfg: dict, target: Path, entry_dir: Path, want_pseudocode: bool = True,
	progress=None) -> tuple[dict, dict]:
	"""Import, auto-analyse and export one target. Returns (analysis, timings).

	The Ghidra project is created in `entry_dir` and saved, which is what makes the second
	`decomp analyze` of the same bytes unnecessary rather than merely faster.
	"""
	from pyghidra.api import analyze, open_project, program_loader, task_monitor

	start_time = time.time()
	language = config.language(cfg)
	mon = task_monitor()
	project = open_project(str(entry_dir), cache.PROJECT_NAME, create=True)
	loader = program_loader().project(project).source(str(target)).name(cache.PROGRAM_NAME).monitor(mon)
	if language:
		raise GhidraError("[ghidra] language=%s is not wired up yet - Ghidra's auto-selection is used "
			"(setting it is Phase 3, Docs/Design-Plan.md)" % language)
	timings: dict[str, float] = {}
	step = time.time()
	results = loader.load()
	timings["import"] = time.time() - step
	program = results.getPrimaryDomainObject()
	if program is None:
		raise GhidraError("Ghidra imported %s but produced no program" % target)

	if progress:
		progress("auto-analysis ...")
	step = time.time()
	analyze(program, mon)
	timings["analyze"] = time.time() - step

	analysis, export_timings = export(program, mon, want_pseudocode, progress)
	timings.update(export_timings)
	results.save(mon)
	results.release(mon)
	timings["total"] = time.time() - start_time
	return analysis, timings


def export(program, mon, want_pseudocode: bool = True, progress=None) -> tuple[dict, dict]:
	"""Everything Phase 1 promises per function: name, address, size, bytes, instructions,
	resolved references, pseudo-code, and callers and callees."""
	from ghidra.app.decompiler import DecompInterface
	from ghidra.program.model.listing import CommentType
	from jpype import JArray, JByte

	step = time.time()
	timings: dict[str, float] = {}
	language = program.getLanguage()
	language_id = str(language.getLanguageID())
	function_manager = program.getFunctionManager()
	listing = program.getListing()
	symbol_table = program.getSymbolTable()
	memory = program.getMemory()
	# Addresses live in the factory's default space ("ram") unless they are external or in an
	# artificial space (EXTERNAL, .shstrtab, ...); those names are worth recording as-is.
	default_space = str(program.getAddressFactory().getDefaultAddressSpace().getName())
	decoder = normalize.capstone_for(language_id)

	def block_name(address) -> str | None:
		block = memory.getBlock(address)
		if block is None:
			space = address.getAddressSpace()
			name = str(space.getName())
			return name if name != default_space else None
		return str(block.getName())

	def read_bytes(start_address, length: int) -> bytes:
		if length <= 0:
			return b""
		buffer_ = JArray(JByte)(length)
		try:
			memory.getBytes(start_address, buffer_, 0, length)
		except Exception:  # noqa: BLE001 - unmapped range: keep the address span honest
			return b"\x00" * length
		return bytes(int(value) & 0xFF for value in buffer_)

	def plate_comment(address) -> str | None:
		"""The block comment Ghidra shows above an address, when there is one."""
		try:
			value = listing.getComment(address, CommentType.PLATE)
		except Exception:  # noqa: BLE001 - comments are a nicety
			return None
		return str(value) if value else None

	def jbytes(values) -> bytes:
		return bytes(int(value) & 0xFF for value in values)

	def resolve_target(address) -> tuple[int, str, str, str | None]:
		"""(address, name, kind, section) for a reference target, named the way a reader would."""
		offset = int(address.getOffset())
		function = function_manager.getFunctionAt(address)
		if function is not None:
			if function.isThunk():
				thunked = function.getThunkedFunction(True)
				name = str(thunked.getName()) if thunked is not None else str(function.getName())
				return offset, name, "external", None
			return offset, str(function.getName()), "function", block_name(address)
		symbol = symbol_table.getPrimarySymbol(address)
		if symbol is not None:
			return offset, str(symbol.getName()), "label", block_name(address)
		return offset, "0x%x" % offset, "address", block_name(address)

	sections = []
	for block in memory.getBlocks():
		sections.append({"name": str(block.getName()), "start": int(block.getStart().getOffset()),
			"end": int(block.getEnd().getOffset()), "executable": bool(block.isExecute()),
			"writable": bool(block.isWrite()), "initialized": bool(block.isInitialized())})

	strings = []
	defined_strings: dict[int, str] = {}
	item = listing.getDefinedData(True)
	while item.hasNext() and len(strings) < MAX_STRINGS:
		data = item.next()
		try:
			if not data.hasStringValue():
				continue
			value = str(data.getValue())
		except Exception:  # noqa: BLE001 - some defined data has no usable value
			continue
		address = data.getAddress()
		offset = int(address.getOffset())
		value = value[:MAX_STRING_LENGTH]
		strings.append({"address": offset, "section": block_name(address), "value": value,
			"length": int(data.getLength())})
		defined_strings[offset] = value

	symbols = []
	item = symbol_table.getAllSymbols(True)
	while item.hasNext():
		symbol = item.next()
		address = symbol.getAddress()
		if address is None:
			continue
		space = address.getAddressSpace()
		symbols.append({"address": int(address.getOffset()), "name": str(symbol.getName()),
			"type": str(symbol.getSymbolType()), "source": str(symbol.getSource()),
			"namespace": str(symbol.getParentNamespace().getName(True)),
			"section": None if str(space.getName()) == default_space else str(space.getName())})
	timings["symbols"] = time.time() - step

	step = time.time()
	if want_pseudocode:
		decompiler = DecompInterface()
		if not decompiler.openProgram(program):
			raise GhidraError("the Ghidra decompiler refused to open the program")
	else:
		decompiler = None

	pseudo_seconds = 0.0
	functions = []
	function_objects = []
	body_count = thunk_count = instruction_count = reference_count = 0
	external_count = 0
	for function in function_manager.getFunctions(True):
		if function.isExternal():
			external_count += 1
			continue
		entry = function.getEntryPoint()
		entry_offset = int(entry.getOffset())
		body = function.getBody()
		ranges = []
		data = b""
		# Ghidra also represents the imported symbols themselves, in its EXTERNAL block: no
		# bytes, nothing to decompile, but they are what a libc call resolves to.
		block = memory.getBlock(entry)
		block_label = str(block.getName()) if block is not None else None
		in_image = str(entry.getAddressSpace().getName()) == default_space and block_label != "EXTERNAL"
		if in_image:
			for address_range in body.getAddressRanges():
				start_address = address_range.getMinAddress()
				start = int(start_address.getOffset())
				end = int(address_range.getMaxAddress().getOffset()) + 1
				ranges.append([start, end])
				data += read_bytes(start_address, end - start)
		size = sum(end - start for start, end in ranges)
		is_thunk = bool(function.isThunk())
		# nothing in the image to look at: an imported symbol, not a body
		kind = "external" if (not in_image or not ranges) else ("thunk" if is_thunk else "function")
		if kind == "external":
			external_count += 1
		elif kind == "thunk":
			thunk_count += 1
		else:
			body_count += 1
		row = {
			"name": str(function.getName()),
			"namespace": str(function.getParentNamespace().getName(True)),
			"entry": entry_offset,
			"size": size,
			"section": block_name(entry),
			"kind": kind,
			"signature": str(function.getSignature()),
			"return_type": str(function.getReturnType().getName()),
			"params": parameter_rows(function),
			"tags": [str(tag) for tag in function.getTags()],
			"comment": plate_comment(entry),
			"bytes": data,
			"ranges": ranges,
			"instructions": [],
			"refs": [],
			"calls": [],
		}
		if kind == "thunk":
			thunked = function.getThunkedFunction(True)
			row["thunk_target"] = str(thunked.getName()) if thunked is not None else None

		instruction = listing.getInstructions(body, True)
		while instruction.hasNext():
			current = instruction.next()
			if not body.contains(current.getAddress()):
				continue
			address = current.getAddress()
			offset = int(address.getOffset())
			raw = jbytes(current.getBytes())
			mnemonic = str(current.getMnemonicString())
			decoded = normalize.decode(decoder, raw, offset) if decoder is not None else None
			if decoded is not None:
				text = normalize.format_instruction(decoded[0], decoded[1])
			else:
				text = normalize.format_instruction(mnemonic, ghidra_operands(current))
			row["instructions"].append({"address": offset, "length": int(current.getLength()),
				"mnemonic": mnemonic, "text": text, "bytes": raw,
				"comment": plate_comment(address)})
			instruction_count += 1
			for reference in current.getReferencesFrom():
				if not reference.isMemoryReference():
					continue
				target_address = reference.getToAddress()
				if target_address is None:
					continue
				reference_type = reference.getReferenceType()
				offset_target, name, target_kind, section = resolve_target(target_address)
				row["refs"].append({
					"address": offset, "to_address": offset_target, "to_name": name, "to_kind": target_kind,
					"section": section, "ref_type": str(reference_type),
					"source_type": str(reference.getSource()),
					"is_call": bool(reference_type.isCall()), "is_data": bool(reference_type.isData()),
					"operand_index": int(reference.getOperandIndex()),
				})
				reference_count += 1

		if decompiler is not None and kind == "function":
			pseudo_start = time.time()
			try:
				results = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, mon)
				decompiled = results.getDecompiledFunction()
				if decompiled is not None:
					row["pseudocode"] = str(decompiled.getC())
				else:
					row["decompile_error"] = str(results.getErrorMessage() or "the decompiler produced nothing")
			except Exception as exc:  # noqa: BLE001 - one bad function must not lose the run
				row["decompile_error"] = repr(exc)
			pseudo_seconds += time.time() - pseudo_start

		functions.append(row)
		function_objects.append(function)

	if decompiler is not None:
		decompiler.dispose()

	# Call graph. Ghidra's own caller/callee lists are both turned into directed edges
	# between row indices, then de-duplicated; `calls` on each row is the edges leaving it.
	by_entry = {row["entry"]: index for index, row in enumerate(functions)}
	edges: set[tuple[int, int]] = set()
	for index, function in enumerate(function_objects):
		for callee in function.getCalledFunctions(mon):
			other = by_entry.get(int(callee.getEntryPoint().getOffset()))
			if other is not None:
				edges.add((index, other))
		for caller in function.getCallingFunctions(mon):
			other = by_entry.get(int(caller.getEntryPoint().getOffset()))
			if other is not None:
				edges.add((other, index))
	rows_with_calls: list[list[dict]] = [[] for _ in functions]
	for caller, callee in sorted(edges):
		rows_with_calls[caller].append({"caller": caller, "callee": callee, "site": None})
	for row, calls in zip(functions, rows_with_calls):
		row["calls"] = calls

	timings["decompile"] = pseudo_seconds
	timings["export"] = time.time() - step

	def call(obj, name, default=None):
		"""Call an optional Ghidra getter; a missing one costs a metadata field, not the run."""
		method = getattr(obj, name, None)
		if method is None:
			return default
		try:
			value = method()
		except Exception:  # noqa: BLE001
			return default
		return default if value is None else value

	parts = language_id.split(":")
	compiler = call(language, "getCompiler")
	headline = {
		"language_id": language_id,
		"processor": str(call(language, "getProcessor", "?")),
		"endian": parts[1] if len(parts) > 1 else None,
		"pointer_size": call(language, "getPointerSize"),
		"compiler_id": str(call(compiler, "getId")) if compiler is not None else None,
		"image_base": int(program.getImageBase().getOffset()),
		# the executable entry point comes from the file headers (decomp.toolchain), and
		# Ghidra's own entry symbols are in the symbols table
		"program_format": str(call(program, "getExecutableFormat")),
	}

	analysis = {
		"meta": {
			"cache_version": cache.CACHE_VERSION,
			**headline,
			"function_count": len(functions),
			"body_count": body_count,
			"thunk_count": thunk_count,
			"external_function_count": external_count,
			"instruction_count": instruction_count,
			"reference_count": reference_count,
			"string_count": len(strings),
			"symbol_count": len(symbols),
			"ghidra_version": _ghidra_version(),
			"pyghidra_version": _pyghidra_version(),
			"decoder": "capstone" if decoder is not None else "ghidra-operands",
		},
		"sections": sections,
		"symbols": symbols,
		"strings": strings,
		"functions": functions,
	}
	if progress:
		progress("%d functions (%d bodies, %d thunks), %d instructions, %d references, %d strings"
			% (len(functions), body_count, thunk_count, instruction_count, reference_count, len(strings)))
	return analysis, timings


def parameter_rows(function) -> list[dict]:
	"""Parameter names and types as Ghidra recovered them - the starting point for the
	candidate's signature."""
	rows = []
	for parameter in function.getParameters():
		try:
			data_type = str(parameter.getDataType().getName())
		except Exception:  # noqa: BLE001 - never lose a function over its metadata
			data_type = "?"
		rows.append({"ordinal": int(parameter.getOrdinal()), "name": str(parameter.getName()),
			"type": data_type})
	return rows


def ghidra_operands(instruction) -> str:
	"""Fallback operand text straight from a Ghidra Instruction, used when no decoder exists
	for this architecture."""
	parts = []
	for index in range(instruction.getNumOperands()):
		rendered = []
		for value in instruction.getOpObjects(index):
			name = getattr(value, "getName", None)
			if callable(name):
				try:
					rendered.append(str(name()))
					continue
				except Exception:  # noqa: BLE001
					pass
			offset = getattr(value, "getOffset", None)
			if callable(offset):
				try:
					rendered.append("0x%x" % int(offset()))
					continue
				except Exception:  # noqa: BLE001
					pass
			rendered.append(str(value))
		parts.append(" ".join(rendered))
	return ", ".join(part for part in parts if part)


def _ghidra_version() -> str | None:
	"""The version of the Ghidra that is actually running (the CLI falls back to
	application.properties if this fails)."""
	try:
		from ghidra.util import version

		return str(version.getApplicationVersion())
	except Exception:  # noqa: BLE001
		return None


def _pyghidra_version() -> str | None:
	try:
		import importlib.metadata

		return importlib.metadata.version("pyghidra")
	except Exception:  # noqa: BLE001
		return None
