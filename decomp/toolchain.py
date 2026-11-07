"""Compiler detection, build configuration, and optimisation-level inference (Phase 3).

Three things live here:

* `build_note()` - what the file itself says about how it was built: the `.comment`
  section (ELF), the Rich header and CodeView record (PE), the object type, the dynamic
  section, and `.note.gnu.property`. Read straight from the bytes: no analysis, no Ghidra.
* `shape_profile()` / `probe_signatures()` / `infer_optimize()` - the flag-inference
  helper. It compiles reference snippets with the compilers that are installed here, at
  each `-O`, and describes the *shape* of the code each flag set produces on this machine
  (prologue/epilogue and stack-traffic patterns). The target's own code is described the
  same way, out of its `.text`, and the two are ranked against each other.
* `starter_config()` - a `project.toml` written from the facts above, with every guess
  labelled as a guess next to the line it produced.

Nothing here is stated as fact unless it came from the file. An optimisation level is
never a fact a stripped binary carries: it is a ranked guess, and the report says how far
apart the candidates are.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path


# --------------------------------------------------------------------------------------
# build flags (the [variants.*] table)


def msvc(compiler) -> bool:
	"""Is this an MSVC-style driver? Its argument form differs in every way that matters."""
	return str(compiler or "").lower() in ("cl", "cl.exe", "clang-cl", "msvc", "icx", "icx-cl")


def _std_year(std) -> str:
	text = str(std).replace("c++", "").replace("gnu++", "")
	return text if text.isdigit() else "17"


# MSVC's own spelling of each level. `cl` has no -O1/-O2 distinction of the GCC kind: /O1
# optimises for size and /O2 for speed, and both imply /Gy and (at /O2) inlining everything.
_MSVC_OPTIMIZE = {0: "/Od", 1: "/O1", 2: "/O2"}
# `cl` has no -O3: the nearest it has is inlining every call.
_MSVC_ABOVE_O2 = "/Ob2"


def build_flags(variant: dict) -> list[str]:
	"""Compile flags a variant implies, in the same shape Tests/eval.py uses.

	GCC/Clang by default; an MSVC (`cl`) variant gets its own set, since `cl` accepts
	neither `-std` nor `-O`. These are the flags the config stores; `driver_form()` turns
	them into the driver's own argument form.

	The MSVC flags come from the variant's own keys, because a target's flags are not a
	choice the tool makes: `crt` ("mt"/"md") is /MT vs /MD, `guard` False is /GS-, `ltcg` is
	/GL, `comdat` is /Gy, `inline` is /Ob0|/Ob1|/Ob2, `fp` is /fp:*. A key that is absent
	adds nothing, which is what leaves `cl`'s defaults alone for a variant that does not
	name them (Docs/MSVC-Plan.md MS-4: the flag set has to be able to say what the target's
	was, not collapse it to /Od or /O2).
	"""
	if msvc(variant.get("compiler", "g++")):
		level = int(variant.get("optimize", 0))
		flags = ["/std:c++%s" % _std_year(variant.get("std", "c++17")),
			_MSVC_OPTIMIZE.get(level, "/O2"), "/W3", "/EHsc", "/nologo"]
		if level >= 3:
			flags.append(_MSVC_ABOVE_O2)
		inline = str(variant.get("inline", "")).lower()
		if inline in ("0", "off", "none"):
			flags.append("/Ob0")
		elif inline in ("1", "on", "inline"):
			flags.append("/Ob1")
		elif inline in ("2", "any", "all"):
			flags.append("/Ob2")
		if variant.get("ltcg"):
			flags.append("/GL")
		if variant.get("comdat"):
			# /Gy is implied by /O1 and /O2, and is not by /Od: a candidate built at /Od
			# without it gets its extents from the next symbol in the section rather than from
			# its own COMDAT (MS-3), so naming it is a decision, never an implication.
			flags.append("/Gy")
		guard = variant.get("guard")
		if guard is False:
			flags.append("/GS-")
		elif guard:
			flags.append("/GS")
		crt = str(variant.get("crt", "")).lower()
		if crt in ("mt", "static"):
			flags.append("/MT")
		elif crt in ("md", "dynamic", "dll"):
			flags.append("/MD")
		if str(variant.get("fp", "")).lower() in ("fast", "strict"):
			flags.append("/fp:%s" % str(variant["fp"]).lower())
		arch = str(variant.get("arch", ""))
		if arch == "x86":
			flags.insert(0, "/arch:IA32")
		elif arch.upper() in ("AVX", "AVX2", "AVX512"):
			flags.append("/arch:%s" % arch.upper())
		return flags + list(variant.get("cppflags", []))
	flags = ["-std=%s" % variant.get("std", "c++17"), "-O%d" % int(variant.get("optimize", 0)),
		"-Wall", "-Wextra"]
	if variant.get("arch") == "x86":
		flags.append("-m32")
	return flags + list(variant.get("cppflags", []))


def link_flags(variant: dict) -> list[str]:
	"""The link flags a variant implies. /GL is only half of it: the link has to be told to
	regenenerate the code (`/LTCG`), which is what makes the image's units the linker's
	units rather than the compiland's (Docs/MSVC-Plan.md §6)."""
	flags = []
	if msvc(variant.get("compiler", "g++")) and variant.get("ltcg"):
		flags.append("/LTCG")
	return flags + list(variant.get("linkflags", []))


def driver_form(compiler: str, flags: list[str], sources: list[Path], object_path: Path,
	includes: list[Path] | None = None) -> list[str]:
	"""The command line for one build, in the form this driver accepts (`-c -o` vs `/c /Fo`)."""
	command = [compiler, *flags]
	msvc_driver = msvc(compiler)
	# Every source's own directory goes on the include path, so a candidate beside a generated
	# `types.h` builds with no extra flags (Design-Plan Phase 4) - but not for `cl`, which
	# searches the includer's directory for *quoted* includes already and would put this
	# project's `math.h` on the angle-bracket path, where the C runtime's own `<math.h>` is
	# what `<cmath>` asks for. Measured (Docs/MSVC-Plan.md MS-3): `#include <a.h>` in a file
	# next to `a.h` is "Cannot open include file" from `cl` with no /I for that directory.
	source_dirs = () if msvc_driver else (Path(source).parent for source in sources)
	for include in [*(includes or []), *source_dirs]:
		command += [("/I" if msvc_driver else "-I"), str(Path(include))]
	command += ["/c"] if msvc_driver else ["-c"]
	if msvc_driver:
		# `cl` reads a bare `/home/…/x.cpp` as an option, and the msvc-wine wrappers rewrite
		# `/x/…` into `z:/…` by stripping the switch, so the language has to be named: /Tc for
		# C, /Tp for C++ (which is also what lets a candidate with an odd suffix build).
		for source in sources:
			command.append(("/Tc" if Path(source).suffix == ".c" else "/Tp") + str(source))
	else:
		command += [str(source) for source in sources]
	command += ["/Fo%s" % object_path] if msvc_driver else ["-o", str(object_path)]
	return command


# --------------------------------------------------------------------------------------
# linking a program from candidate objects


def link_form(compiler: str, flags: list[str], objects: list[Path], linkflags: list[str],
		override: Path) -> list[str]:
	"""The command line that links objects into a program, in this driver's own form.

	The compile flags are repeated on the link line on purpose: they carry `-m32` and `-no-pie`,
	and a driver that compiles 32-bit code but links 64-bit produces a program that cannot be
	compared to anything. `linkflags` come from the target's own `[variants.*] linkflags` - the
	tool does not invent any (`config.link_flags`), because a link the tool chose is not the
	target's link.

	`cl` names its output with `/Fe:` and passes everything after `/link` straight to `link.exe`
	(Tests/eval.py's own `link_binary` does the same, which is what built the reference binary).
	"""
	if msvc(compiler):
		return [compiler, *flags, *[str(item) for item in objects], "/Fe:%s" % override, "/link",
			*(linkflags or [])]
	return [compiler, *flags, *[str(item) for item in objects], *(linkflags or []), "-o",
		str(override)]


# --------------------------------------------------------------------------------------
# what the file says about how it was built


def build_note(target: Path) -> dict:
	"""What the file itself says about how it was built. Best effort: a target LIEF cannot
	parse still analyses in Ghidra, it just gets no note."""
	note = {"path": str(target), "name": Path(target).name, "format": None, "arch": None,
		"bits": 0, "entrypoint": None, "file_type": None, "pie": None, "static": None,
		"needed": [], "interp": None, "sections": {}, "segments": [], "gnu_features": [],
		"gnu_hardening": [], "gnu_isa": [], "gnu_property": False, "reloc_kinds": {},
		"comment": [], "rich": [], "linker_version": None, "dynstr": "", "image_base": None,
		"guard_cf": None,
		"pdb": None, "pogo": None, "ltcg": False, "toolset": None, "crt": None,
		"decorated": [], "language_proof": None,
		"compiler": None, "compiler_id": None, "compiler_version": None, "linker": None,
		"abi": None, "language": None, "std_hints": [], "build_notes": [],
		"compiler_hint": None, "error": None}
	try:
		import lief
	except ImportError as exc:  # pragma: no cover - covered by `decomp check`
		note["error"] = "lief is not importable: %s" % exc
		return note
	try:
		binary = _lief_binary(target)
	except Exception as exc:  # noqa: BLE001 - any parser failure is a note, not a crash
		note["error"] = "lief could not parse %s: %s" % (Path(target).name, exc)
		return note
	if binary is None:
		note["error"] = "lief could not parse %s" % Path(target).name
		return note

	try:
		note["format"] = str(binary.format).rsplit(".", 1)[-1]
		if isinstance(binary, lief.ELF.Binary):
			_read_elf(binary, note)
		elif isinstance(binary, lief.PE.Binary):
			_read_pe(binary, note)
		elif isinstance(binary, lief.MachO.Binary):
			_read_macho(binary, note)
		else:
			note["error"] = "%s is not an ELF/PE/Mach-O this tool knows" % Path(target).name
			return note
	except Exception as exc:  # noqa: BLE001
		note["error"] = "while reading the headers of %s: %s" % (Path(target).name, exc)
		return note

	# The toolset is read after the Rich header, because it is read from both of them and the
	# two readings have to be compared (`toolset_identity`). Its compiland counts are recorded
	# as build notes too: they are the /GL and the language mix seen from the object side, and
	# unlike the POGO record they say how many compilands were involved.
	if note.get("linker_version") or note.get("rich"):
		toolset = note["toolset"] = toolset_identity(note)
		counts = (toolset or {}).get("rich", {}).get("compilands", {})
		if counts.get("ltcg-c") or counts.get("ltcg-cpp"):
			note["comment"].append("rich:%d compiland(s) through /GL codegen (the linker's own "
				"record of them, independent of the POGO directory)" % (counts.get("ltcg-c", 0)
					+ counts.get("ltcg-cpp", 0)))
		if counts.get("cpp"):
			note["comment"].append("rich:%d C++ compiland(s), %d C, %d asm (front-end records of "
				"the link)" % (counts["cpp"], counts.get("c", 0), counts.get("asm", 0)))
		if (toolset or {}).get("agree") is False:
			note["comment"].append("toolset-disagreement:%s" % toolset["detail"])
	note["build_notes"] = list(note["comment"]) + ["rich:id=%d:build=%d:%d" % (item["id"],
		item["build"], item["count"]) for item in note["rich"]]
	_read_build_strings(note)
	language_evidence(note)
	note["compiler_hint"] = {"gcc": "gcc", "clang": "clang", "msvc": "msvc"}.get(note["compiler"])
	return note


def _lief_binary(target: Path):
	"""Parse a file with LIEF, reusing the parse of a file already read this session.

	`build_note`, `target_shape`, `extract.TargetImage` and `relink` all read the same target, and
	a 40 MB PE takes a second per parse. Keyed on (path, mtime, size), so an edited or rebuilt
	binary is parsed again: a note for a file that changed is not a note about that file.
	"""
	import lief

	key = str(Path(target))
	try:
		stat = Path(target).stat()
		stamp = (int(stat.st_mtime_ns), int(stat.st_size))
	except OSError:
		return lief.parse(key)
	cached = _BINARY_CACHE.get(key)
	if cached and cached[0] == stamp:
		return cached[1]
	binary = lief.parse(key)
	if binary is not None:
		if len(_BINARY_CACHE) > 4:
			_BINARY_CACHE.clear()
		_BINARY_CACHE[key] = (stamp, binary)
	return binary


_BINARY_CACHE: dict[str, tuple] = {}


def _short(value) -> str:
	return str(value).rsplit(".", 1)[-1]


def _segments(binary):
	"""(type name, segment) for every segment, in one pass, with LIEF's warning about segment
	types it cannot name suppressed: architecture-specific PT_* values reach the enum as an
	unknown number."""
	import warnings

	with warnings.catch_warnings():
		warnings.simplefilter("ignore", RuntimeWarning)
		segments = list(binary.segments)
		return [(_short(segment.type), segment) for segment in segments]


def _segment_types(binary) -> list[str]:
	return [name for name, _segment in _segments(binary)]


def _read_elf(binary, note: dict) -> None:
	import warnings

	header = binary.header
	note["arch"] = _short(header.machine_type)
	note["bits"] = 64 if "64" in str(header.identity_class) else 32
	note["file_type"] = _short(header.file_type)          # DYN (PIE/shared), EXEC, REL (a .o)
	note["entrypoint"] = int(header.entrypoint)
	# Section addresses in the file's own terms: Ghidra may load the image somewhere else
	# (a PIE at 0x100000), and the two address domains have to be reconciled.
	note["sections"] = {str(section.name): int(section.virtual_address)
		for section in binary.sections if section.size}
	note["segments"] = _segment_types(binary)
	for section in binary.sections:
		name = str(section.name)
		if name == ".comment":
			for text in bytes(section.content).split(b"\x00"):
				if text.strip():
					note["comment"].append(text.decode("utf-8", "replace"))
		elif name == ".dynstr":
			# The dynamic string table survives stripping: it holds the names of everything
			# the program imports, which is what says which language and standard library it uses.
			note["dynstr"] = bytes(section.content)[:400000].decode("utf-8", "replace")
	for kind, segment in _segments(binary):
		if kind == "INTERP":
			note["interp"] = bytes(segment.content).split(b"\x00")[0].decode("utf-8", "replace")
	for entry in binary.dynamic_entries:
		if _short(entry.tag) == "NEEDED":
			note["needed"].append(str(entry.name))
	for note_item in binary.notes:
		if "PROPERTY" not in str(note_item.type):
			continue
		# Its presence is itself a fact: the record is written by a toolchain that knows about
		# these features, and a feature it does not list was not asked for.
		note["gnu_property"] = True
		# `.note.gnu.property` is the one place a stripped ELF still says what its code was built
		# to use. LIEF spells each record as an object holding (FLAG, NAME) pairs. The two kinds
		# answer different Phase 7 questions, so they are kept apart:
		#   FLAG.NONE  -> `x86 feature: IBT, SHSTK`, the CET record, which -fcf-protection writes
		#   FLAG.USED  -> `x86 feature used: XMM, YMM` and the x86-64-vN level, which -mavx,
		#                 -mfma and -march=x86-64-vN write. Those level names are the compiler's.
		for prop in getattr(note_item, "properties", []) or []:
			kind = type(prop).__name__.upper()  # LIEF spells them `X86Features` / `X86ISA`
			if "FEATURE" in kind:
				for feature in getattr(prop, "features", []) or []:
					flag, name = _property_pair(feature)
					if flag == "used":
						if name and name not in note["gnu_features"]:
							note["gnu_features"].append(name)
					elif name and name not in note["gnu_hardening"]:
						note["gnu_hardening"].append(name)
			elif "ISA" in kind:
				for value in getattr(prop, "values", []) or []:
					name = _isa_name(_property_pair(value)[1])
					if name and name not in note["gnu_isa"]:
						note["gnu_isa"].append(name)
	# The relocation tables survive stripping, and what they relocate says how the code was
	# compiled: GOT slots (GOTPCREL*, GLOB_DAT) and PLT slots (JUMP_SLOT) only exist in code
	# that was compiled position-independent.
	for source in ("dynamic_relocations", "object_relocations"):
		try:
			for entry in getattr(binary, source) or []:
				kind = _short(entry.type)
				note["reloc_kinds"][kind] = note["reloc_kinds"].get(kind, 0) + 1
		except Exception:  # noqa: BLE001 - a file may have neither table, which is an answer
			continue
	# Both are needed for a PIE (ET_DYN *and* a program interpreter), and no PT_DYNAMIC and
	# no DT_NEEDED means it was linked static. `-m32`/`-m64` come from the class exactly.
	note["pie"] = note["file_type"] == "DYN" and bool(note["interp"])
	note["static"] = "DYNAMIC" not in note["segments"] and not note["needed"]
	if note["static"]:
		note["link_flags"] = ["-static"]
	elif note["pie"] is False and note["file_type"] == "EXEC":
		note["link_flags"] = ["-no-pie"]
	else:
		note["link_flags"] = []


def _property_pair(item) -> tuple[str, str]:
	"""(flag, name) out of a LIEF `.note.gnu.property` pair, however that version spells it."""
	if isinstance(item, (tuple, list)) and len(item) == 2:
		return _short(item[0]).lower(), _short(item[1])
	return "", _short(item)


# The GNU property's ISA level names are the compiler's own -march= spellings.
_GNU_ISA = {"BASELINE": "x86-64-baseline", "V2": "x86-64-v2", "V3": "x86-64-v3",
	"V4": "x86-64-v4"}


def _isa_name(value) -> str:
	value = str(value or "").upper()
	return _GNU_ISA.get(value, value.lower() if value else "")


def _read_pe(binary, note: dict) -> None:
	header = binary.header
	optional = binary.optional_header
	note["arch"] = _short(header.machine)
	note["bits"] = 64 if "64" in note["arch"] else 32
	# A PE's own headers speak RVAs; the analysis, objdump and `decomp --range` speak
	# imagebase + RVA. The note is recorded in the second domain, the one the cache is keyed
	# by, so `cli._address_offset()` can answer "0, because the format says so" instead of
	# answering "unknown" (Docs/MSVC-Plan.md §8: forget that bias once and every address in
	# the tool is "no such function").
	image_base = int(getattr(binary, "imagebase", 0) or getattr(optional, "imagebase", 0) or 0)
	note["image_base"] = image_base
	# /guard:cf: the guard-function table and this bit only appear when the flag was on, and the
	# bit is the linker's own statement about it (Phase 7).
	note["guard_cf"] = bool(int(getattr(optional, "dll_characteristics", 0) or 0) & 0x4000)
	note["entrypoint"] = image_base + int(optional.addressof_entrypoint)
	note["file_type"] = "DLL" if int(header.characteristics) & 0x2000 else "EXE"  # IMAGE_FILE_DLL
	note["pie"] = bool(int(optional.dll_characteristics) & 0x0040)  # DYNAMIC_BASE (ASLR)
	note["sections"] = {str(section.name): image_base + int(section.virtual_address)
		for section in binary.sections if section.size}
	for library in binary.imports:
		# The import directory is the PE's DT_NEEDED: what it asks the loader for. PE stores
		# these names upper-cased, so they are kept as the file writes them and compared
		# case-insensitively where a name is evidence.
		note["needed"].append(str(library.name))
	# A PE has no `.dynstr`, but it carries the same kind of evidence in two other places: the
	# names it imports and the names it exports. They are collected under the same key, because
	# it is the same question - which names does a stripped file still carry - and
	# `language_evidence` reads that key. For an MSVC image this is where a decorated name
	# (`?EditProc@@YAH...`) is findable at all: there is no symbol table to look in.
	names = []
	for library in binary.imports:
		for entry in library.entries:
			try:
				if entry.name:
					names.append(str(entry.name))
			except Exception:  # noqa: BLE001 - an import by ordinal has no name, which is fine
				continue
	try:
		for entry in binary.exports:
			if entry.name:
				names.append(str(entry.name))
	except Exception:  # noqa: BLE001 - most executables export nothing
		pass
	note["dynstr"] = " ".join(names)[:400000]
	note["static"] = not note["needed"]
	note["linker_version"] = "%d.%d" % (optional.major_linker_version, optional.minor_linker_version)
	rich = getattr(binary, "rich_header", None)
	if rich is not None:
		# The Rich header's id -> product table is Microsoft-internal and undocumented, so the
		# build number is what is recorded: it identifies the toolset build that produced it.
		for entry in rich.entries:
			count = getattr(entry, "count", None)
			if count is None:  # LIEF < 1.0 spelled it `number`
				count = getattr(entry, "number", 0)
			note["rich"].append({"id": int(getattr(entry, "id", 0) or 0),
				"build": int(getattr(entry, "build_id", 0) or 0), "count": int(count or 0)})
	_read_pe_debug(binary, note)
	note["link_flags"] = []


SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def symbol_server_key(guid: str, age: int) -> str:
	"""The directory a PDB is served under: its GUID with no dashes, then the age.

	The age is written in hex (pefile builds the same string with `%X`, and that is what the
	server indexes), so an image the linker rewrote ten or more times is 404 if it is spelled
	in decimal.
	"""
	return "%s%s" % (str(guid).replace("-", "").upper(), format(int(age or 0), "X"))


def pdb_name(path_or_name: str) -> str:
	"""The bare file name of a PDB. A CodeView record can hold the path the link ran with
	(deadrising2.exe names `c:\\bcg\\deadrising\\build\\pc\\deadrising2.pdb`), and a symbol store
	keys on the file name alone. Every Windows binary checked here carries a bare name already.
	"""
	return str(path_or_name or "").replace("/", "\\").split("\\")[-1]


def symbol_server_url(name: str, guid: str, age: int) -> str:
	name = pdb_name(name)
	return "%s/%s/%s/%s" % (SYMBOL_SERVER, name, symbol_server_key(guid, age), name)


def _debug_records(binary) -> list:
	"""The debug directory of a PE: CodeView, POGO, REPRO, ... LIEF 1.0 calls this `debug`;
	`debug_info` is what older LIEF called it, and in 1.0 it is something else entirely (the
	abstract DebugInfo, and None in a LIEF built without it). Asking both by name, in the
	order that works, is the only portable way to read the CodeView record."""
	for attribute in ("debug", "debug_info"):
		try:
			items = list(getattr(binary, attribute) or [])
		except Exception:  # noqa: BLE001 - a format that has neither is not a PE worth arguing about
			continue
		if items:
			return items
	return []


def _read_pe_debug(binary, note: dict) -> None:
	"""The three debug records that say how an MSVC image was built.

	CodeView is the PDB's identity - and the address Microsoft serves the PDB of a shipped
	Windows binary from, which for a stripped proprietary target is an answer key
	(§4 of Docs/MSVC-Plan.md). POGO says whether the image went through link-time
	codegen, and that is what decides whether the byte gate can be promised at all (§6).
	"""
	for record in _debug_records(binary):
		kind = _short(record.type)
		if kind == "CODEVIEW":
			name = str(getattr(record, "filename", "") or "")
			guid = str(getattr(record, "guid", "") or "")
			age = int(getattr(record, "age", 0) or 0)
			entry = {"name": name, "guid": guid, "age": age,
				"signature": _short(getattr(record, "cv_signature", "") or "")}
			if name and guid:
				entry["symbols_url"] = symbol_server_url(name, guid, age)
			note["pdb"] = entry
			note["comment"].append("codeview:%s guid=%s age=%d" % (name or "?", guid or "?", age))
		elif kind == "POGO":
			signature = _short(getattr(record, "signature", "") or "")
			note["pogo"] = signature
			if signature == "LCTG":
				note["ltcg"] = True
				note["comment"].append("pogo:LCTG (/GL + /LTCG: the linker generated this code)")
			else:
				note["comment"].append("pogo:%s" % signature)
		elif kind == "REPRO":
			note["comment"].append("reproducible-build record (/REPRO)")


# link.exe's version says which toolset family produced the file - which is the decision the
# tool has to make before it compiles anything: a candidate only has a chance of matching when
# the compiler is of the same era (Docs/MSVC-Plan.md §6). The major and minor say the family;
# the exact Visual Studio update comes from the Rich build id, and Docs/MSVC-Plan.md MS-4 owns
# that table. Listed newest first, so the first match is the narrowest one.
_MSVC_TOOLSETS = (
	((14, 30), "v143 (Visual Studio 2022)"),
	((14, 20), "v142 (Visual Studio 2019)"),
	((14, 10), "v141 (Visual Studio 2017)"),
	((14, 0), "v140 (Visual Studio 2015)"),
	((13, 10), "v130 (Visual Studio 2003)"),
	((12, 0), "v120 (Visual Studio 2013)"),
	((11, 0), "v110 (Visual Studio 2012)"),
	((10, 0), "v100 (Visual Studio 2010)"),
)


def msvc_toolset(linker_version) -> dict | None:
	"""The toolset family a PE's linker version names, or None when there is no such version."""
	if not linker_version:
		return None
	parts = str(linker_version).split(".")
	try:
		major, minor = int(parts[0]), int(parts[1])
	except (IndexError, ValueError):
		return None
	for (want_major, want_minor), family in _MSVC_TOOLSETS:
		if major == want_major and minor >= want_minor:
			return {"family": family, "linker_version": str(linker_version)}
	return {"family": "MSVC link.exe %s (no toolset table entry)" % linker_version,
		"linker_version": str(linker_version)}


def rich_builds(note: dict) -> list[int]:
	"""The toolset build ids the Rich header names (0 is the padding entry).

	Every build number in the table, which is a *listing* and not an answer: id 1 and id 147
	carry numbers that identify no toolset (`rich_identity` says which records do).
	"""
	return sorted({int(item["build"]) for item in note.get("rich", []) if item.get("build")})


# The Rich header's product ids. Microsoft does not document them; this is the table the
# RichHeaderResearch project publishes (spoof_check.py / rich.py), which is the only public
# reading of it, and the parts that matter here are confirmed by measurement: this machine's
# link.exe 14.12.25835 writes **id 258 with build 25835** into every PE it links, so id 258
# ("Linker1400") is the record that names the linker, and its build number is the fourth
# component of that linker's version. The family is what the name says - "1400" is the 14.x
# family - and the *build* is what says which era. (Docs/MSVC-Plan.md MS-4.)
_RICH_TOOLS = {
	0: ("padding", "not-a-tool", "the padding record"),
	1: ("Import0", "not-a-tool", "a count related to the import table; present in almost every "
		"file, always at build 0 - it identifies no tool"),
	147: ("Implib900", "linker-subtool", "the import-library stubs of the 9.0 linker. Measured "
		"here: it carries build 30729 in a Windows OS binary of 2018 and in a file this "
		"machine linked today with 14.12.25835, so its build number is a constant of those "
		"stubs and not a toolset identity"),
	255: ("Cvtres1400", "cvtres", "cvtres.exe: compiled resources"),
	256: ("Export1400", "linker-subtool", "the linker's export-table writer"),
	257: ("Implib1400", "linker-subtool", "the linker's import-library writer"),
	258: ("Linker1400", "linker", "link.exe itself: the record whose build number is the "
		"linker's own build"),
	259: ("Masm1400", "asm", "the macro assembler: assembly compilands"),
	260: ("Utc1900_C", "c", "the C front-end: C compilands"),
	261: ("Utc1900_CPP", "cpp", "the C++ front-end: C++ compilands"),
	262: ("Utc1900_CVTCIL_C", "c-cvtcil", "C compilands converted to IL"),
	263: ("Utc1900_CVTCIL_CPP", "cpp-cvtcil", "C++ compilands converted to IL"),
	264: ("Utc1900_LTCG_C", "ltcg-c", "C compilands that went through /GL link-time codegen"),
	265: ("Utc1900_LTCG_CPP", "ltcg-cpp", "C++ compilands that went through /GL codegen"),
	266: ("Utc1900_LTCG_MSIL", "ltcg-msil", "managed IL from /GL"),
	267: ("Utc1900_POGO_I_C", "pogo-c", "/GL C compilands as seen by the PGO/instrumentation pass"),
	268: ("Utc1900_POGO_I_CPP", "pogo-cpp", "/GL C++ compilands, instrumentation pass"),
	269: ("Utc1900_POGO_O_C", "pogo-c", "/GL C compilands, optimisation pass"),
	270: ("Utc1900_POGO_O_CPP", "pogo-cpp", "/GL C++ compilands, optimisation pass"),
}

# Toolset build numbers, from the published Visual C++ / redistributable version tables: the
# build at which each toolset family first appears. The optional header's linker version is
# the fact about the family; this table corroborates it and names the exact build, which is
# what deciding between two updates of the same family needs. Newest first.
_MSVC_BUILDS = (
	(35418, "14.44"), (35112, "14.43"), (34829, "14.42"), (34211, "14.41"), (33808, "14.40"),
	(33519, "14.39"), (33130, "14.38"), (32822, "14.37"), (32532, "14.36"), (32215, "14.35"),
	(31918, "14.34"), (31628, "14.33"), (31328, "14.32"), (31103, "14.31"), (30704, "14.30"),
	(30037, "14.29"), (29326, "14.28"), (28801, "14.26"), (28614, "14.25"), (28314, "14.24"),
	(28018, "14.23"), (27905, "14.22"), (27702, "14.21"), (27508, "14.20"), (27011, "14.16"),
	(26723, "14.15"), (26428, "14.14"), (26128, "14.13"), (25711, "14.12"), (25325, "14.11"),
	(25017, "14.10"), (24210, "14.0"),
)


def msvc_build_version(build) -> str | None:
	"""The toolset family a Rich build number falls in, or None if it is below the table."""
	try:
		value = int(build)
	except (TypeError, ValueError):
		return None
	for low, family in _MSVC_BUILDS:
		if value >= low:
			return family
	return None


def rich_identity(note: dict) -> dict:
	"""What the Rich header says about the tools that made this file.

	Two readings, and they are kept apart because they answer different questions:

	* **The toolset.** Record 258 ("Linker1400") is link.exe's own, and its build number is
	  the fourth component of link.exe's version - measured with the toolchain of
	  Docs/Setup.md §6, which writes 25835 and prints 14.12.25835. So the Rich header is an
	  independent second reading of the optional header's linker version, and `agree` says
	  whether the two are the same answer. Records that are not a tool (id 1) or whose build
	  number is a constant of the linker's own stub objects (id 147) are excluded from this
	  reading rather than maxed in with the rest.
	* **What was compiled.** The counts are per compiland and per front-end: how many C, C++,
	  and assembly compilands the link had, and how many went through /GL. The /GL count is a
	  second, independent confirmation of the POGO record of §2, and it survives stripping.
	"""
	records = []
	for item in note.get("rich", []):
		name, role, meaning = _RICH_TOOLS.get(int(item["id"]), (None, None, None))
		records.append({"id": int(item["id"]), "build": int(item["build"]),
			"count": int(item["count"]), "name": name, "role": role, "meaning": meaning})
	out = {"records": sorted(records, key=lambda item: (-item["count"], item["id"])),
		"linker": None, "linker_version": None, "agree": None, "compilands": {}, "unnamed": []}
	linker = next((item for item in records if item["role"] == "linker" and item["build"]), None)
	if linker:
		family = msvc_build_version(linker["build"])
		out["linker"] = linker
		out["linker_version"] = family
		header = note.get("linker_version")
		if family and header:
			out["agree"] = family == header
	counts = {}
	for item in records:
		if item["role"] in ("c", "cpp", "asm", "ltcg-c", "ltcg-cpp", "pogo-c", "pogo-cpp"):
			counts[item["role"]] = counts.get(item["role"], 0) + item["count"]
		elif item["name"] is None:
			out["unnamed"].append(item["id"])
	out["compilands"] = counts
	return out


def toolset_identity(note: dict) -> dict | None:
	"""The toolset, read from the file twice and compared. None when the file says nothing."""
	from_header = msvc_toolset(note.get("linker_version"))
	identity = rich_identity(note)
	if not from_header and not identity["linker"]:
		return None
	toolset = dict(from_header or {"family": None, "linker_version": None})
	toolset["rich"] = identity
	toolset["rich_version"] = identity["linker_version"]
	toolset["agree"] = identity["agree"]
	if identity["linker"] and identity["linker_version"] and not from_header:
		toolset["family"] = msvc_toolset(identity["linker_version"])["family"]
	if from_header and identity["linker"]:
		if identity["agree"]:
			toolset["detail"] = ("the optional header says link.exe %s and the Rich header's own "
				"linker record says build %s, which is that version - the two readings agree"
				% (note.get("linker_version"), identity["linker"]["build"]))
		else:
			toolset["detail"] = ("the optional header says link.exe %s, the Rich header's linker "
				"record (id %d) says build %s = %s: they disagree, so one of these headers was "
				"rewritten after the link - trust neither for the era on its own"
				% (note.get("linker_version"), identity["linker"]["id"], identity["linker"]["build"],
					identity["linker_version"]))
	elif from_header:
		toolset["detail"] = ("no linker record in the Rich header: the toolset comes from the "
			"optional header's linker version alone, which records only major.minor")
	return toolset


def _read_macho(binary, note: dict) -> None:
	header = binary.header
	note["arch"] = _short(getattr(header, "cputype", getattr(header, "cpu_type", "?")))
	note["bits"] = 64 if "64" in str(note["arch"]) else 32
	note["file_type"] = _short(getattr(header, "filetype", getattr(header, "file_type", "?")))
	note["entrypoint"] = int(header.entrypoint)
	note["link_flags"] = []


_COMMENT_GCC = re.compile(r"GCC[:\s]*\(([^)]*)\)\s*([0-9][0-9.]*)?|\bGCC\s+([0-9][0-9.]*)", re.I)
_COMMENT_CLANG = re.compile(r"clang version (\S+)|LLVM version ([0-9.]+)", re.I)
_COMMENT_MASM = re.compile(r"Microsoft \(R\) (?:C/C\+\+|MacroAssembler)", re.I)
_LINKER = re.compile(r"link\.exe|LLD[: ]|GNU ld|ld\.exe|Microsoft \(R\) C/C\+\+", re.I)


def _read_build_strings(note: dict) -> None:
	"""Compiler and linker identity out of `.comment`, the Rich header and the PDB record."""
	text = " ".join(note["comment"])
	if text:
		match = _COMMENT_GCC.search(text)
		if match:
			note["compiler"], note["compiler_id"] = "gcc", ((match.group(1) or "").strip() or None)
			note["compiler_version"] = match.group(2) or match.group(3)
		match = _COMMENT_CLANG.search(text)
		if match:
			note["compiler"], note["compiler_version"] = "clang", (match.group(1) or match.group(2))
		elif _COMMENT_MASM.search(text):
			note["compiler"] = "msvc"
	if note["rich"]:
		# A Rich header is written by the Microsoft linker and by nothing else.
		note["compiler"] = note["compiler"] or "msvc"
	if note["compiler"] is None:
		match = re.search(r"\b(GCC|clang|Microsoft)", text, re.I)
		if match:
			note["compiler"] = match.group(1).lower().replace("microsoft", "msvc")
	if text:
		match = _LINKER.search(text)
		if match:
			note["linker"] = match.group(0).strip()


# Standard-library names that only exist from one language level upwards. The names are the
# mangled ones, because that is what a stripped binary carries; the matched text is kept as
# the evidence for the hint.
_STD_MARKERS = [
	("c++23", r"St7format|St8expected|St10format_args"),
	("c++20", r"St7jthread|St4spanI|St7barrier|St10stop_token|St13latch"),
	("c++17", r"basic_string_view|St10filesystem|St8optional|St7variant|St17bad_optional_"
		r"access|St10shared_ptr.*pmr"),
	("c++11", r"St6thread|St5mutex|St5atomic|__cxa_thread_atexit|throw_bad_array_new_length"),
]
_CPP_ABI = re.compile(r"__cxxabiv1|__cxa_|_ZTV|_ZTI|_ZTS|__gxx_personality")

# An MSVC decoration: `?_Xbad_alloc@std@@YAXXZ`, `?EditProc@@YAH...`, `??2@YAPAXI@Z`,
# `??_C@_0BJ@...`. A C name never contains `?`, so one of these in an import or export table
# proves C++ in the image, and names the entity - which is the only language evidence a
# stripped PE carries, and the reason MS-0 left `language` unset (Docs/MSVC-Plan.md MS-4).
_MSVC_DECORATED = re.compile(r"\?(?:\?[A-Za-z_~0-9][A-Za-z0-9_@?$]*|"
	r"[A-Za-z_~][A-Za-z0-9_@?$]*@@[Y?])[A-Za-z0-9_@?$.]*")

# The CRT/STL families an MSVC image can import, and what each one proves. The DLL name is the
# whole story here: a PE's imports survive stripping, and which runtime a program links is a
# decision of the compiler era and of /MT vs /MD - not of the source.
_MSVC_RUNTIMES = (
	("api-ms-win-crt-", "ucrt", "the UCRT (Universal CRT): the CRT of VS2015 and every toolset "
		"since, linked dynamically (/MD)"),
	("ucrtbase", "ucrt", "the UCRT itself, rather than its api-set shims"),
	("msvcp", "msvc-stl", "the Microsoft C++ standard library (MSVC STL): the program is C++ and "
		"links the STL dynamically"),
	("vccorlib", "winrt", "C++/WinRT or C++/CX support"),
	("vcruntime", "vcruntime", "the v14x C runtime DLL - /MD with a VC redist installed"),
	("vcr", "oldcrt", "the per-version CRT of an older toolset (msvcr80 = VS2005, 90 = 2008, "
		"100 = 2010, 110 = 2012, 120 = 2013)"),
	("msvcrt", "downlevel", "the downlevel CRT (msvcrt.dll): what msvcrt.lib links - a C runtime, "
		"so it says nothing about the language"),
)


def msvc_runtime(note: dict) -> dict:
	"""Which MSVC runtime this image links, from the DLLs it imports.

	Three things the tool needs and cannot get anywhere else on a stripped PE: whether the CRT
	is in the process (`/MD`) or in the file (`/MT` - no CRT DLL is imported), which runtime
	generation that means, and therefore which `/std:` levels the build could have used.
	"""
	out = {"dlls": {}, "static_crt": None, "cpp": False, "generation": None, "notes": []}
	lowered = {name.lower(): name for name in note.get("needed", [])}
	for key, kind, meaning in _MSVC_RUNTIMES:
		for name, original in lowered.items():
			# `msvcr` must not match `msvcrt.dll`: the first is the per-version CRT of one
			# toolset, the second is the downlevel CRT any toolset can link.
			if kind == "oldcrt":
				if not re.match(r"^(msvcr|vcr)\d", name):
					continue
			elif not (name.startswith(key) or key in name):
				continue
			out["dlls"].setdefault(kind, []).append(original)
			if kind == "msvc-stl":
				out["cpp"] = True
			out["notes"].append("%s: %s" % (original, meaning))
	if note.get("compiler") == "msvc":
		# A PE linked by Microsoft's linker that imports no CRT at all has the CRT in its own
		# bytes: that is /MT. (A binary with no imports at all is static everything, which the
		# `static` fact already says.)
		out["static_crt"] = bool(note["needed"]) and not out["dlls"] and not note.get("static")
	if any(kind in out["dlls"] for kind in ("ucrt", "vcruntime", "msvc-stl", "winrt")):
		out["generation"] = "v14x (VS2015 or newer)"
	elif "oldcrt" in out["dlls"]:
		for name in out["dlls"]["oldcrt"]:
			match = re.search(r"(\d\d)", name)
			if match:
				out["generation"] = {"80": "v80 (VS2005)", "90": "v90 (VS2008)",
					"100": "v100 (VS2010)", "110": "v110 (VS2012)",
					"120": "v120 (VS2013)"}.get(match.group(1))
	elif "downlevel" in out["dlls"]:
		out["generation"] = "the downlevel msvcrt.dll - any toolset can link it"
	return out


def msvc_std_evidence(note: dict) -> dict | None:
	"""What the standard level can honestly be said for an MSVC target.

	MSVC decoration carries no standard level: `?Foo@@YAHHH@Z` is the same string at every
	`/std:`. What the file *does* name is the toolset (linker version, Rich build) and the
	runtime it links, and those bound the level: the level the toolset defaults to, and the
	levels it has a switch for. That is what a config needs, and it is labelled as such rather
	than reported as if a name proved it.
	"""
	version = str((note.get("toolset") or {}).get("linker_version")
		or note.get("linker_version") or "")
	try:
		major, minor = (int(part) for part in version.split(".")[:2])
	except ValueError:
		return None
	if major != 14:
		return None
	# Every v14x toolset from 14.0 on defaults to its "C++14" mode; /std:c++17 exists from
	# 14.16 (VS2017 15.9) and /std:c++20 from 14.2x (VS2019 16.x).
	default, offered = "c++14", ["c++14"]
	if (minor or 0) >= 16:
		offered.append("c++17")
	if (minor or 0) >= 20:
		offered.append("c++20")
	runtime = msvc_runtime(note)
	named = sorted({name for names in runtime["dlls"].values() for name in names})
	evidence = ("the %s toolset defaults to %s and has switches for %s; it imports %s"
		% (version, default, ", ".join("/std:" + item for item in offered), ", ".join(named))
		if named else ("the %s toolset defaults to %s and has switches for %s; it imports no CRT "
		"DLL, so the CRT is in the file (/MT)" % (version, default,
			", ".join("/std:" + item for item in offered))))
	return {"std": default, "offered": offered, "evidence": evidence, "proof": "toolset, not name"}



def language_evidence(note: dict) -> None:
	"""ABI, language and the lowest `-std` the imports force, from names the file carries."""
	carrier = " ".join(note["needed"]) + " " + note["dynstr"] + " " + " ".join(note["comment"])
	abi, cpp_abi = None, False
	for name in note["needed"]:
		# A PE names its imports upper-cased (MSVCRT.dll), an ELF lower-cased, so the name is
		# compared case-insensitively and reported as the file writes it.
		library = name.lower()
		if "stdc++" in library:
			abi, cpp_abi = "libstdc++ (Itanium C++ ABI)", True
		elif library.startswith(("libc++", "c++.")):
			abi, cpp_abi = "libc++ (Itanium C++ ABI)", True
		elif library.startswith("msvcrt"):
			# The *downlevel* CRT: what `msvcrt.lib` links - not the UCRT, not the redistributable
			# vcruntime/MSVC++ DLLs. It is a C runtime, so it says nothing about the language.
			abi = "MSVC CRT (%s: the downlevel C runtime, not UCRT or the vcruntime DLLs)" % name
		elif library.startswith(("msvc", "vcruntime", "ucrt", "vccorlib")):
			abi, cpp_abi = "MSVC CRT (%s)" % name, library.startswith(("msvcp", "vccorlib"))
	if abi is None and note["rich"]:
		abi = "MSVC CRT (the Rich header is written by the Microsoft linker)"
	if abi is None:
		match = _CPP_ABI.search(note["dynstr"])
		if match:
			abi, cpp_abi = "C++ ABI runtime (the symbol %s)" % match.group(0), True
	# Which runtime a program imports is not the same question as what language it is written
	# in: msvcrt.dll is what a plain C program imports too. On an MSVC image the language comes
	# from decorated names in the import/export tables and the standard level from the toolset
	# and the runtime family - which is MS-4, and is what the paragraph below deferred.
	decorated = []
	if note.get("compiler") == "msvc" or note.get("rich"):
		decorated = [match.group(0) for match in _MSVC_DECORATED.finditer(note["dynstr"])]
		runtime = msvc_runtime(note)
		if decorated:
			# A decoration is a C++ name, and it is the entity the image calls, not a runtime it
			# links: `?terminate@@YAXXZ` in an import table says this image reaches C++ runtime
			# support. That is the language evidence the paragraph below deferred.
			cpp_abi = True
			note["language_proof"] = "decorated name(s) in its import/export names"
		elif (note.get("toolset") or {}).get("rich", {}).get("compilands", {}).get("cpp"):
			# With a static CRT there is no decorated import to read, and the link's own
			# front-end records are what remains: they say C++ was compiled into this image,
			# which is true but coarser - the count includes the runtime objects the link pulled
			# in, so it cannot say how much of the *program* is C++.
			cpp_abi = True
			note["language_proof"] = ("%d C++ front-end record(s) in the Rich header (includes the "
				"runtime objects the link pulled in)" % note["toolset"]["rich"]["compilands"]["cpp"])
		if runtime["cpp"]:
			cpp_abi = True
		if runtime["dlls"] or runtime["static_crt"]:
			detail = "; ".join(runtime["notes"][:3])
			if runtime["static_crt"]:
				detail = ("no CRT DLL is imported: the CRT is in the file (/MT)"
					+ ("; " + detail if detail else ""))
			if abi is None or abi.startswith("MSVC CRT"):
				abi = "MSVC CRT (%s)" % detail
			if runtime["generation"]:
				abi = "%s; runtime generation: %s" % (abi, runtime["generation"])
	note["crt"] = msvc_runtime(note)
	note["decorated"] = sorted(set(decorated))[:12]
	note["abi"] = abi
	note["language"] = "c++" if cpp_abi else None
	for std, pattern in _STD_MARKERS:
		match = re.search(pattern, carrier)
		if match:
			note["std_hints"].append({"std": std, "evidence": match.group(0),
				"proof": "imported name"})
	if not note["std_hints"] and note.get("compiler") == "msvc":
		# No Itanium marker means anything on a PE, and no MSVC name encodes a level. Say what
		# the toolset does bound, which is what a variant's /std: has to agree with.
		hint = msvc_std_evidence(note)
		if hint:
			note["std_hints"].append(hint)


def _isa_note(note: dict) -> str:
	"""The ISA facts of `.note.gnu.property` as one line: the level first, then what it names."""
	levels = " ".join(note.get("gnu_isa") or [])
	used = ", ".join(note.get("gnu_features") or [])
	if levels and used:
		return "%s (features: %s)" % (levels, used)
	return levels or used


def note_lines(note: dict, width: int = 12) -> list[str]:
	"""The build note as lines a reader can act on."""
	if note.get("error"):
		return ["  note: %s" % note["error"]]

	def line(key, value):
		return None if value in (None, [], {}, "") else "  %-*s %s" % (width, key, value)
	built = " ".join(part for part in (note.get("compiler"), note.get("compiler_version")) if part)
	toolset, pdb = note.get("toolset") or {}, note.get("pdb") or {}
	toolset_line = None
	if toolset:
		# The toolset era is the first thing a candidate build has to agree with: a 2022 `cl`
		# does not produce a 2017 image (Docs/MSVC-Plan.md §6). MS-4 reads it twice and says
		# whether the two readings agree, and names the exact build, which is what separating
		# two updates of one family needs.
		identity = toolset.get("rich") or {}
		linker = identity.get("linker") or {}
		toolset_line = "%s - link.exe %s" % (toolset.get("family"), note.get("linker_version")
			or "(not recorded)")
		if linker:
			toolset_line += ", Rich header linker record (id %d) build %d" % (linker["id"],
				linker["build"])
		if toolset.get("detail"):
			toolset_line += "\n%s%s" % (" " * (width + 2), toolset["detail"])
	elif note.get("rich"):
		builds = rich_builds(note)
		toolset_line = "MSVC tools, Rich header tool build %s" % "/".join(str(item)
			for item in builds)
	return [item for item in (
		line("file", "%s %s %s-bit" % (note.get("format"), note.get("arch"), note.get("bits"))),
		line("object", "%s%s" % (note.get("file_type"), " (PIE)" if note.get("pie") else "")),
		line("linked", "static" if note.get("static") else
			"dynamic" + (": " + ", ".join(note["needed"][:6]) if note.get("needed") else "")),
		line("built by", built),
		line("linker", note.get("linker") or ("MSVC link.exe %s" % note["linker_version"]
			if note.get("linker_version") else None)),
		# The toolset era line above; the compiland counts are what /GL and the language mix
		# look like from the object side, and they survive stripping.
		line("toolset", toolset_line),
		line("compilands", (", ".join("%d %s" % (count, role) for role, count in sorted(
			((toolset.get("rich") or {}).get("compilands") or {}).items()))
			+ " (the link's front-end records, per compiland - this includes the runtime objects "
			"the link pulled in)") or None),
		line("whole-program", "link-time code generation (/GL + /LTCG): the code in this image "
			"was regenerated by the linker, so no single-file compile of the same source "
			"reproduces its bytes - the byte gate cannot be promised here"
			if note.get("ltcg") else None),
		line("pdb", ("%s  guid %s age %s" % (pdb.get("name"), pdb.get("guid"), pdb.get("age"))
			+ ("\n%s%s" % (" " * (width + 2), pdb["symbols_url"]) if pdb.get("symbols_url") else ""))
			if pdb.get("guid") else None),
		line("build notes", "; ".join(note.get("build_notes", [])) or None),
		line("abi", note.get("abi")),
		line("language evidence", ("%s: %s" % (note.get("language_proof"),
			", ".join((note.get("decorated") or [])[:3])))
			if note.get("language_proof") else None),
		line("std at least", "; ".join("%s (%s)%s" % (hint["std"], hint["evidence"],
			" - proved by the toolset, not by a name" if hint.get("proof") == "toolset, not name"
			else "") for hint in note.get("std_hints", []))
			or "not determined from the imports"),
		line("hardening", ", ".join(filter(None, [
			", ".join(note.get("gnu_hardening", [])),
			"/guard:cf (the image declares Guard CF and carries a guard-function table)"
			if note.get("guard_cf") else None])) or None),
		# The instruction set the file's own property note names, in the compiler's own spelling.
		# This is the fact that says whether a candidate built for the baseline can match at all.
		line("isa used", _isa_note(note)),
	) if item]


# --------------------------------------------------------------------------------------
# writing a starting project.toml


def variant_name(note: dict, optimize: int | None) -> str:
	"""A variant name in the Tests/project.toml shape: gcc-o0, clang-o2, gcc-o2-x86."""
	parts = [note.get("compiler") or "gcc", "o%d" % (0 if optimize is None else int(optimize))]
	if note.get("bits") == 32:
		parts.append("x86")
	return "-".join(parts)


def shared_object(note: dict) -> bool:
	"""Is this file a shared object rather than a program? `ET_DYN` with no program interpreter -
	the loader is not going to start it, something else is going to dlopen it. Its code was
	compiled position-independent, which is what makes `-fPIC` a fact of the file and not a guess
	(Docs/byte-cleanup-plan.md Phase 7). A PIE *executable* is `DYN` with an interpreter, and the
	flag that produces its code is `-fPIE`; the codegen is the same, the link is not."""
	return (note.get("format") == "ELF" and note.get("file_type") == "DYN"
		and not note.get("interp"))


def starter_config(target: Path, note: dict, guess: dict | None = None,
		flags: dict | None = None) -> str:
	"""A `project.toml` for this target, facts and guesses separated.

	Anything inferred is written as a comment next to the value it produced, so the first
	thing a reader sees is which line they have to check.
	"""
	levels = sorted({hint["std"] for hint in note.get("std_hints", [])},
		key=lambda value: int(value[3:]))
	optimize = (guess or {}).get("optimize")
	cppflags: list[str] = []
	if note.get("pie") is False and note.get("format") == "ELF" and note.get("file_type") == "EXEC":
		cppflags.append("-no-pie")
	elif shared_object(note):
		# The one beyond-`-O` flag a shared object proves on its own: a `DYN` file no interpreter
		# loads only exists as position-independent code, and its GOT/PLT relocations are the same
		# statement from the other side. Written here because a candidate compiled without it cannot
		# match, whatever else the config gets right.
		cppflags.append("-fPIC")
	compiler = {"gcc": "g++", "clang": "clang++", "msvc": "cl"}.get(note.get("compiler"), "g++")
	lines = [
		"# Written by `decomp detect` for %s." % target,
		"# Read from the file: %s %s, %s-bit, %s%s, built by %s." % (
			note.get("format"), note.get("arch"), note.get("bits"),
			"static" if note.get("static") else "dynamic",
			" PIE" if note.get("pie") else "", built_of(note) or "unknown"),
	]
	if note.get("abi"):
		lines.append("# Its imports say: %s." % note["abi"])
	toolset = note.get("toolset") or {}
	if toolset.get("family"):
		# A candidate only has a chance of matching a target built by a compiler of the same era
		# (Docs/MSVC-Plan.md §6), so the toolset belongs next to the `compiler =` line it
		# constrains - with the two independent readings of it, and whether they agree.
		lines.append("# Its toolset: %s (link.exe %s). %s" % (toolset["family"],
			note.get("linker_version") or "?", toolset.get("detail") or ""))
		lines.append("# Build a candidate with a `cl` of that era: Docs/Setup.md §6 installs one")
		lines.append("# by version (this one is --major 15 --msvc-version 15.5).")
	if (note.get("crt") or {}).get("static_crt"):
		lines.append("# Its own bytes hold the CRT: no CRT DLL is imported, so it was linked /MT.")
	elif note.get("compiler") == "msvc" and (note.get("crt") or {}).get("dlls"):
		lines.append("# It imports its CRT%s (%s): the CRT is a DLL, so /MD." % (
			" and STL" if (note["crt"].get("dlls") or {}).get("msvc-stl") else "",
			", ".join(sorted({item for names in note["crt"]["dlls"].values()
				for item in names})[:4])))
	if note.get("ltcg"):
		# Docs/MSVC-Plan.md §6: the byte gate only applies to a target a variant can reproduce.
		lines.append("# This image went through link-time code generation (/GL + /LTCG): no"
			" single-file")
		lines.append("# compile of the same source reproduces its bytes, so a variant here can be"
			" scored on")
		lines.append("# shape and references, not byte-identity. Its toolset:%s"
			% (" %s" % note["toolset"]["family"] if note.get("toolset") else " (see `decomp detect`)"))
	if levels:
		lines.append("# The imports need at least -std=%s (%s)." % (levels[-1],
			", ".join(hint["evidence"] for hint in note["std_hints"][:3])))
	if shared_object(note):
		lines.append("# cppflags carries -fPIC: this is a shared object (%s with no program "
			"interpreter),\n# so its own bytes are position-independent code. Not a guess."
			% note.get("file_type"))
	for line in (flags or {}).get("config_comments", []):
		# What the rest of the flags look like, from the same file. These are findings, not facts
		# where the evidence is a pattern, and the comment says which is which.
		lines.append("# " + line)
	if guess:
		lines.append("# optimize=%s is the flag-inference helper's best match over %d sampled"
			" bodies (distance %.3f, next-best %.3f at -O%s): %s" % (
				optimize, guess.get("sampled", 0), guess.get("distance", 0.0),
				guess.get("runner_up", 0.0), guess.get("runner_up_optimize", "?"),
				guess.get("confidence", "see `decomp detect`")))
		if guess.get("sample_warning"):
			lines.append("# CHECK THIS: %s" % guess["sample_warning"])
	else:
		lines.append("# optimize=0 is a placeholder: `-O` was not inferred from this sample.")
	lines += [
		"",
		'std = "%s"' % (levels[-1] if levels else "c++17"),
		"threshold = 97.0",
		"cppflags = %r" % cppflags,
		"linkflags = %r" % list(note.get("link_flags") or []),
		"include_dirs = []",
		"",
		"[ghidra]",
		'install_dir = ""',
		'cache_dir = "cache/ghproj"',
		'language = ""',
		"",
		"[variants.%s]" % variant_name(note, optimize),
		'compiler = "%s"' % compiler,
		"optimize = %d" % (0 if optimize is None else int(optimize)),
		'arch = "%s"' % ("x86" if note.get("bits") == 32 else "x86-64"),
	]
	if compiler == "cl":
		# The MSVC flags the file itself proves, in the keys `build_flags` reads. An absent key
		# means the driver's default, which is what an unknown target is.
		if note.get("ltcg"):
			lines.append("ltcg = true")
		crt = note.get("crt") or {}
		if crt.get("static_crt"):
			lines.append('crt = "mt"')
		elif crt.get("dlls"):
			lines.append('crt = "md"')
		if (guess or {}).get("level_class"):
			lines.append("# optimize above is the nearer of %s: the shape cannot tell those two "
				"apart (Docs/MSVC-Plan.md MS-4). Try the other if this one's bytes do not match."
				% guess["level_class"])
	if note.get("compiler_version") or note.get("compiler_id"):
		lines.append("# detected: %s %s%s" % (note.get("compiler"), note.get("compiler_version") or "",
			" (%s)" % note["compiler_id"] if note.get("compiler_id") else ""))
	return "\n".join(lines) + "\n"


def built_of(note: dict) -> str:
	return " ".join(part for part in (note.get("compiler"), note.get("compiler_version")) if part)


# --------------------------------------------------------------------------------------
# flag inference: what each -O looks like here, and what the target looks like


PROBE_SOURCE = r'''
// The reference snippets for `decomp detect`. Plain, and deliberately varied: a leaf
// function, one with locals and a stack array (so a stack canary shows up or not), loops
// with known and unknown trip counts (vectorisation), a helper call (inlining), a branch
// ladder, and struct walking. Nothing external - no header, no libc - so the only thing
// that changes the shape of the code is the flags.
struct PPoint { int x; int y; };
int p_leaf(int a, int b) { return a + b; }
int p_frame(int a, int b) { int t = a * b; int u = a - b; return t + u * 2; }
int p_locals(int n) {
	int buf[8];
	for (int i = 0; i < 8; ++i) buf[i] = 0;
	for (int i = 0; i < n; ++i) buf[i & 7] = i * 3;
	int s = 0;
	for (int i = 0; i < 8; ++i) s += buf[i];
	return s;
}
int p_loop(int n) { int s = 0; for (int i = 0; i < n; ++i) s += i * i; return s; }
int p_call(int a, int b) { return p_leaf(a, b) * 2; }
float p_sum(const float* v, int n) { float s = 0.0f; for (int i = 0; i < n; ++i) s += v[i] * v[i]; return s; }
int p_branch(int x) { if (x < 0) return -x; if (x & 1) return x + 7; return x / 2; }
int p_swap(int* a, int* b) { int t = *a; *a = *b; *b = t; return t; }
int p_walk(const PPoint* p, int n) { int s = 0; for (int i = 0; i < n; ++i) s += p[i].x * 3 + p[i].y; return s; }
'''

# The shape features, all read from instruction text in AT&T form - which is what the
# analysis cache stores and what capstone prints, so the same code reads both sides.
_PUSHRBP = re.compile(r"^push(?:l|q|w)?\s+%(?:r|e)bp\b")
_FRAMESET = re.compile(r"^mov(?:l|q)\s+%(?:r|e)sp,\s*%(?:r|e)bp\b")
_ENDBR = re.compile(r"^endbr(64|32)\b")
_SUBRSP = re.compile(r"^sub(?:l|q|w)?\s+\$[0-9a-fx]+,\s*%(?:r|e)sp\b")
_CANARY = re.compile(r"%fs:|__stack_chk")
_LEAVE = re.compile(r"^leave\b")
_POPRBP = re.compile(r"^pop(?:l|q|w)?\s+%(?:r|e)bp\b")
_FRAME_MEM = re.compile(r"\(%(?:r|e)bp")
_ARG_STORE = re.compile(r"^mov[lqwb]?\s+%(?:[a-z0-9]+),\s*-?[0-9]+\(%(?:r|e)bp\)")
_XMM = re.compile(r"%(?:x|e)mm|movss|movsd|addss|mulss|cvtsi|punpck")
_CALL = re.compile(r"^call")
_RET = re.compile(r"^ret\b")

# Phase 7: the trace a vector flag leaves in the instruction stream. `%ymm`/`%zmm` are
# unambiguous; a mnemonic starting with `v` is a VEX encoding (no legacy x86 mnemonic starts
# with `v`), which is how -mavx shows up when the compiler still only used xmm registers.
# FMA and reciprocal forms are what -mfma and -ffast-math leave, with the caveat that the last
# one is a pattern and not a proof (a hand-written intrinsic produces the same lines).
_VEX = re.compile(r"^v[a-z]|%(?:y|z)mm\d", re.I)
_YMM = re.compile(r"%ymm\d")
_ZMM = re.compile(r"%zmm\d|%(?:kn)?k[1-7]\b")
_FMA = re.compile(r"^v?f(?:n?madd|msub)")
_RCP = re.compile(r"^v?r(?:cp|sqrt)")

# What an MSVC x64 body looks like, which is a different shape in the literal sense: `cl`
# never uses a frame pointer in a leaf-able x64 function, its locals are addressed off `%rsp`
# with the caller's 32-byte shadow space above them, it emits no `endbr`, and its /GS guard is
# a cookie loaded from `%rip` and xor-ed with `%rsp`, checked inline or by a call to
# `__security_check_cookie` - not the `%fs:` canary of a System V target. None of the Itanium
# features above carry any signal on a PE (all are 0 on both sides), so the MSVC family scores
# a different set. (Docs/MSVC-Plan.md MS-4; every pattern here was read off `cl` 14.12 output
# on this machine, at /Od, /O1 and /O2.)
_RSP_MEM = re.compile(r"\(%rsp[,)]")
# An inbound argument (`%ecx`/`%edx`/`%r8d`/`%r9d`, the Microsoft x64 order) stored to a stack
# slot near the top of the body: `cl` at /Od spills every parameter, and never does at /O1|/O2.
_ARG_STORE_MSVC = re.compile(r"^(mov|mov[a-z]+|lea|fstp)\s+%(ecx|edx|r8d|r9d|rcx|rdx|r8|r9),\s*"
	r"(?:qword|dword|byte|word|ptr)?\s*-?[0-9a-fx]*\(%rsp\)")
# The /GS guard: the cookie xor-ed with `%rsp`, or the call that checks it.
_GS_XOR = re.compile(r"^xor[a-z]*\s+%rsp,\s*%[a-z0-9]+|^xor[a-z]*\s+%[a-z0-9]+,\s*%rsp\b")
_GS_CALL = re.compile(r"security_check_cookie|__guard|@comp\.guard_check")

# Per-body features are shares over the sampled bodies (share of bodies, or share of
# instructions). `bodies` and `insmean` are reported but never scored: they describe the
# program, not the flags.
FEATURES = ("frame", "endbr", "subrsp", "canary", "leave", "poprbp", "spill", "framemem",
	"xmm", "calls")
# The ones scored for an MSVC target/probe. `subrsp`/`calls`/`xmm` mean the same thing on both
# ABIs and discriminate here too; the rest are the MSVC-only readings of the same flags.
FEATURES_MSVC = ("rspmem", "argstore", "gs", "calls", "xmm")
# Measured and reported, never scored against the -O probe: these say which *instruction set* the
# build used (Phase 7), not how hard it optimised. Putting them in the scored sets would change
# the -O ranking every measured number in Docs/byte-cleanup-plan.md rests on.
FEATURES_VECTOR = ("vex", "ymm", "zmm", "fma", "rcp")
ALL_FEATURES = (FEATURES + tuple(name for name in FEATURES_MSVC if name not in FEATURES)
	+ FEATURES_VECTOR)

# What a feature means where it is present, so the report names the reason and not just a
# distance. Only the ones that discriminate.
FEATURE_MEANING = {
	"frame": "a frame pointer is set up (push rbp; mov rbp,rsp) in this share of bodies",
	"spill": "arguments are stored to the stack at the top of the body: no register allocation",
	"framemem": "locals are read back through the frame pointer on every use",
	"leave": "leave in the epilogue (a frame is set up and torn down)",
	"poprbp": "the frame pointer is popped in the epilogue",
	"canary": "a stack canary is taken (-fstack-protector*)",
	"endbr": "endbr at the entry (-fcf-protection)",
	"xmm": "SSE/vector operations, including vectorised loops",
	"subrsp": "the stack is adjusted with sub rsp/esp",
	"calls": "calls per instruction (helpers are not inlined)",
	"rspmem": "locals and arguments are addressed off %rsp on every use: no register allocation "
		"(cl /Od); at /O1|/O2 they live in registers",
	"argstore": "the inbound argument registers are stored to stack slots at the top of the body "
		"(cl /Od writes every parameter to its home slot)",
	"gs": "/GS stack guard: the cookie xor-ed with %rsp, or the check of it",
	"vex": "VEX-encoded instructions (an AVX form), whatever register width they use",
	"ymm": "the body uses 256-bit %ymm registers: -mavx or higher built it",
	"zmm": "the body uses 512-bit %zmm registers or %k mask registers: -mavx512* built it",
	"fma": "fused multiply-add forms (-mfma; cl /fp:fast or /arch:AVX2)",
	"rcp": "reciprocal/square-root approximations, the shape -ffast-math leaves (a pattern, not "
		"a proof: intrinsics give the same lines)",
}


def shape_profile(bodies: list[list[str]]) -> dict:
	"""Describe the shape of a set of function bodies, each a list of instruction texts."""
	counts = dict.fromkeys(ALL_FEATURES, 0)
	bodies_counted = instructions = 0
	for body in bodies:
		text = [item for item in body if item]
		if not text:
			continue
		bodies_counted += 1
		head, tail, joined = text[:6], text[-4:], "\n".join(text)
		if any(_PUSHRBP.match(item) for item in head) and any(_FRAMESET.match(item) for item in head):
			counts["frame"] += 1
		if _ENDBR.match(text[0]):
			counts["endbr"] += 1
		if any(_SUBRSP.match(item) for item in head):
			counts["subrsp"] += 1
		if _CANARY.search(joined):
			counts["canary"] += 1
		if any(_LEAVE.match(item) for item in tail):
			counts["leave"] += 1
		if any(_POPRBP.match(item) for item in tail):
			counts["poprbp"] += 1
		if any(_ARG_STORE.match(item) for item in text[:10]):
			counts["spill"] += 1
		if any(_ARG_STORE_MSVC.match(item) for item in text[:8]):
			counts["argstore"] += 1
		if any(_GS_XOR.match(item) for item in text[:8]) or _GS_CALL.search(joined):
			counts["gs"] += 1
		counts["rspmem"] += sum(1 for item in text if _RSP_MEM.search(item))
		counts["framemem"] += sum(1 for item in text if _FRAME_MEM.search(item))
		counts["xmm"] += sum(1 for item in text if _XMM.search(item))
		counts["vex"] += sum(1 for item in text if _VEX.search(item))
		counts["fma"] += sum(1 for item in text if _FMA.search(item))
		counts["rcp"] += sum(1 for item in text if _RCP.search(item))
		if any(_YMM.search(item) for item in text):
			counts["ymm"] += 1
		if any(_ZMM.search(item) for item in text):
			counts["zmm"] += 1
		counts["calls"] += sum(1 for item in text if _CALL.match(item))
		instructions += len(text)
	profile = {name: counts[name] / max(1, bodies_counted) for name in
		("frame", "endbr", "subrsp", "canary", "leave", "poprbp", "spill", "argstore", "gs",
			"ymm", "zmm")}
	profile.update({name: counts[name] / max(1, instructions) for name in
		("framemem", "xmm", "calls", "rspmem", "vex", "fma", "rcp")})
	profile["bodies"] = bodies_counted
	profile["insmean"] = instructions / max(1, bodies_counted)
	return profile


def profile_lines(profile: dict, width: int = 9, features: tuple = FEATURES) -> list[str]:
	return ["  %-*s %s" % (width, name, "%.3f" % profile[name]) for name in features] \
		+ ["  %-*s %d bodies, mean %.1f instructions each"
			% (width, "sample", profile.get("bodies", 0), profile.get("insmean", 0.0))]


def probe_signatures(compiler: str, bits: int, std: str = "c++17",
	levels: tuple[int, ...] = (0, 1, 2, 3), work_dir: Path | None = None) -> tuple[list[dict], list[str]]:
	"""What each `-O<n>` looks like, measured with the compiler installed here.

	The answer is toolchain-specific on purpose: whether `-O2` vectorises, whether a frame
	pointer survives, and what an epilogue looks like are properties of *this* compiler, and
	a candidate is going to be built with this compiler. Returns (signatures, problems).
	"""
	from . import normalize  # local import: capstone is only needed on this path

	problems: list[str] = []
	handle = normalize.capstone_for("x86:LE:%d:default" % bits)
	if handle is None:
		return [], ["no decoder for %d-bit x86 - flag inference supports x86 only" % bits]
	keep = work_dir is not None
	directory = Path(work_dir or tempfile.mkdtemp(prefix="decomp-probe-"))
	source = directory / "decomp_probe.cpp"
	source.write_text(PROBE_SOURCE)
	import lief

	signatures = []
	for level in levels:
		object_path = directory / ("decomp_probe_o%d%s.o" % (level, "-m32" if bits == 32 else ""))
		if msvc(compiler):
			# cl's own flag spellings and driver_form's argument order; no 32-bit target from this
			# machine's MSVC (Docs/Setup.md §6.7). /Gy gives one `.text$…` COMDAT per function,
			# which is also what makes the bodies readable in a COFF object (below).
			if bits != 64:
				problems.append("%s: no 32-bit x86 target from this machine's MSVC (Docs/Setup.md §6.7)"
					% compiler)
				continue
			if level >= 3:
				# cl has no -O3. `/O2 /Ob2` is the nearest it has and it is the same shape as /O2,
				# so probing it separately would only add a duplicate row to the ranking.
				problems.append("%s: no -O3 to probe - /O2 is the top level this driver has "
					"(/Ob2 inlines more calls but does not change the shape of a body)" % compiler)
				continue
			flags = ["/std:%s" % std, "/Gy",
				"/Od" if level == 0 else ("/O1" if level == 1 else "/O2")]
			command = driver_form(compiler, flags, [source], object_path)
		else:
			command = [compiler, "-std=%s" % std] + (["-m32"] if bits == 32 else []) + [
				"-O%d" % level, "-c", str(source), "-o", str(object_path)]
		try:
			finished = subprocess.run(command, capture_output=True, text=True, timeout=180)
		except (OSError, subprocess.TimeoutExpired) as exc:
			problems.append("%s -O%d: %s" % (compiler, level, exc))
			continue
		if finished.returncode != 0:
			problems.append("%s -O%d: %s" % (compiler, level,
				(finished.stderr or finished.stdout).strip().splitlines()[:1] or "the compiler failed"))
			continue
		binary = lief.parse(str(object_path))
		if binary is None:
			problems.append("could not read %s" % object_path.name)
			continue
		bodies = []
		if not hasattr(binary, "format"):
			# A COFF object: its symbols carry no size and no function flag (MSVC-Plan §8), so a
			# section is a function - which is what /Gy above arranges. The sections are walked in
			# file order and *not* keyed by name: with /Gy every function is its own `.text$mn`,
			# and a name-keyed dict silently keeps one of them (MS-3: a COFF object may give
			# several sections the same name).
			for section in binary.sections:
				if not section.size or not str(section.name).startswith(".text"):
					continue
				bodies.append([normalize.format_instruction(item.mnemonic, item.op_str)
					for item in handle.disasm(bytes(section.content), 0)])
		else:
			contents = {str(section.name): bytes(section.content)
				for section in binary.sections if section.size}
			for symbol in binary.symbols:
				try:
					section = str(symbol.section.name) if symbol.section is not None else ""
					if not symbol.is_function or not symbol.size or section not in contents:
						continue
					data = contents[section][int(symbol.value):int(symbol.value) + int(symbol.size)]
				except Exception:  # noqa: BLE001 - a section-less symbol carries nothing
					continue
				bodies.append([normalize.format_instruction(item.mnemonic, item.op_str)
					for item in handle.disasm(data, int(symbol.value))])
		if not bodies:
			problems.append("%s -O%d produced no function symbols in %s" % (compiler, level,
				object_path.name))
			continue
		signatures.append({"optimize": level, "compiler": compiler, "bits": bits,
			"object": str(object_path), "profile": shape_profile(bodies)})
		if not keep:
			object_path.unlink(missing_ok=True)
	if not keep:
		source.unlink(missing_ok=True)
		try:
			directory.rmdir()
		except OSError:  # pragma: no cover - the caller asked for the objects
			pass
	return signatures, problems


# The sample both sides are measured over: bodies of this many instructions. Small enough
# that a body is one function, big enough to have a prologue and an epilogue; the same band
# is applied to the target and to the probe, so the two samples are of comparable things.
BAND = (4, 90)


def split_bodies(instructions: list[tuple[int, str]]) -> list[list[str]]:
	"""Cut a linear disassembly into bodies at every `ret`.

	Used when there is no analysis to take real boundaries from. It is an approximation and
	says so: a function ending in a tail call continues into the next one, and a `ret` inside
	a basic block splits one in two. What is being measured is the shape of the code, and the
	same cut is applied to the probe objects - where the real boundaries *are* known - only
	when the analysis is not there.
	"""
	bodies: list[list[str]] = []
	current: list[str] = []
	for _address, text in instructions:
		current.append(text)
		if text.startswith("ret"):
			bodies.append(current)
			current = []
	if current:
		bodies.append(current)
	return bodies


def target_shape(target: Path, rng: tuple[int, int] | None = None, band: tuple[int, int] = BAND,
	note: dict | None = None) -> tuple[dict, dict, list[str]]:
	"""The shape of a file's own code, with no analysis and no Ghidra.

	`rng` is a half-open range of **file** addresses (the ones nm and objdump print), which is
	how a sample is narrowed to the program proper in a statically linked target.
	Returns (profile, build note, problems).
	"""
	from . import extract, normalize

	note = note or build_note(target)
	problems: list[str] = []
	if note.get("error"):
		return {}, note, [note["error"]]
	handle = normalize.capstone_for("x86:LE:%d:default" % (note.get("bits") or 64))
	if handle is None:
		return {}, note, ["flag inference supports x86 (%d-bit) for now" % (note.get("bits") or 0)]
	try:
		import lief

		binary = lief.parse(str(target))
	except Exception as exc:  # noqa: BLE001
		return {}, note, ["could not re-read %s: %s" % (Path(target).name, exc)]
	bodies: list[list[str]] = []
	seen_sections: list[str] = []
	# A PE section header gives an RVA and the sample's addresses have to be in the domain the
	# caller is quoting (`--range` comes from objdump, which adds the image base). ELF and
	# Mach-O section headers already carry load addresses.
	base = extract.file_address_base(binary)
	code: list[tuple[int, bytes]] = []
	for section in binary.sections:
		name = str(section.name)
		if not section.size or not (name.startswith(".text") or name in ("__text", ".text.unlikely")):
			continue
		if not extract.section_capabilities(getattr(binary, "format", None), section)[2]:
			continue
		seen_sections.append(name)
		code.append((base + int(section.virtual_address), bytes(section.content)))
	if not seen_sections:
		problems.append("%s has no executable .text section to sample" % Path(target).name)
		return {}, note, problems

	def bytes_at(address: int, size: int) -> bytes:
		for start, data in code:
			if start <= address < start + len(data):
				return data[address - start:address - start + size]
		return b""

	# Sample the units, if the file names them. For an x64 PE that is `.pdata`, the compiler's
	# own table (MS-1): cutting `.text` at every `ret` was MS-1's known debt - it splits a
	# body that ends in a tail call, joins two bodies at a padding run, and puts an alignment
	# gap inside one, so the shape it measures is the disassembly's, not the build's.
	units = extract.pdata_records(binary)
	sampled = ""
	if units:
		for begin, end, _unwind in units:
			start, size = begin + base, int(end) - int(begin)
			if rng is not None and not rng[0] <= start < rng[1]:
				continue
			data = bytes_at(start, size)
			if not data:
				continue
			bodies.append([normalize.format_instruction(item.mnemonic, item.op_str)
				for item in handle.disasm(data, start)])
		sampled = ".pdata (%d function records)" % len(units)
	else:
		for start, data in code:
			stream = [(int(item.address), normalize.format_instruction(item.mnemonic, item.op_str))
				for item in handle.disasm(data, start)]
			if rng is not None:
				stream = [item for item in stream if rng[0] <= item[0] < rng[1]]
			bodies.extend(item for item in split_bodies(stream)
				if band[0] <= len(item) <= band[1])
		profile = shape_profile(bodies)
		profile["sample_source"] = "the executable sections, cut at every ret"
		if not profile["bodies"]:
			problems.append("no body of %d-%d instructions was found in %s%s - widen the sample"
				% (band[0], band[1], ", ".join(seen_sections),
					" inside the given --range" if rng else ""))
		return profile, note, problems
	profile = shape_profile([body for body in bodies if band[0] <= len(body) <= band[1]])
	profile["sample_source"] = "the file's own function table, %s" % sampled
	if not profile["bodies"]:
		problems.append("no body of %d-%d instructions was found in %s%s - widen the sample"
			% (band[0], band[1], ", ".join(seen_sections),
				" inside the given --range" if rng else ""))
	return profile, note, problems


def feature_family(compiler) -> tuple:
	"""Which features carry the answer for this side. An MSVC probe and an MSVC target are
	compared on the MSVC set; nothing else knows what a shadow space is."""
	return FEATURES_MSVC if msvc(compiler) else FEATURES


def msvc_shape_flags(profile: dict) -> list[str]:
	"""What the shape says about the MSVC flags that have no other trace in a stripped file.

	/GS is a compile flag, not a byte the file carries; the guard it leaves in every body that
	has a buffer is the only place it can still be seen. (The /GL half of the question is
	answered exactly by the POGO directory and the linker's own Rich records, in `note_lines`.)
	"""
	lines = []
	if not profile.get("bodies"):
		return lines
	share = profile.get("gs", 0.0)
	if share >= 0.02:
		lines.append("/GS: the stack guard appears in %d%% of the sampled bodies - this build "
			"has it on (cl's default)" % round(share * 100))
	elif share == 0.0:
		lines.append("/GS-: no sampled body checks a stack guard, which is what /GS- or a build "
			"of only leaf functions looks like")
	if profile.get("argstore", 0.0) >= 0.5:
		lines.append("the argument registers are stored to their home slots in most bodies: this "
			"is /Od code, and a candidate built at /O1|/O2 will not match it")
	return lines


def infer_optimize(target: dict, signatures: list[dict]) -> list[dict]:
	"""Rank the probe signatures against the shape of the target. Best match first.

	`confidence` is part of the result, not decoration: the -O0 class separates cleanly from
	everything else on every x86 toolchain measured here, while -O1/-O2/-O3 shade into each
	same shape and are reported as a class, not a level.
	"""
	ranked = []
	for item in signatures:
		profile, family = item["profile"], feature_family(item.get("compiler"))
		ranked.append({"optimize": item["optimize"], "compiler": item.get("compiler"),
			"bits": item.get("bits"), "features": list(family),
			"distance": round(sum(abs(profile[name] - target[name]) for name in family), 3),
			"profile": profile})
	ranked.sort(key=lambda item: item["distance"])
	for position, item in enumerate(ranked):
		item["margin"] = round(ranked[position + 1]["distance"] - item["distance"], 3) \
			if position + 1 < len(ranked) else 0.0
		if msvc(item.get("compiler")) and item["optimize"] in (1, 2) \
			and item.get("margin", 0.0) < 0.5 \
			and any(other["optimize"] in (1, 2) and other is not item for other in ranked):
			# /O1 and /O2 of the same toolchain, close together: that is a class, and the
			# `confidence` text says so. `optimize` still names the closest one, because a config
			# has to pick a flag.
			item["level_class"] = "/O1|/O2"
	if ranked:
		best = ranked[0]
		evidence = []
		for name in best["features"]:
			here, there = target[name], best["profile"][name]
			if abs(here - there) <= 0.15 and max(here, there) >= 0.15:
				evidence.append("%s: target %d%%, this probe %d%%" % (FEATURE_MEANING[name],
					round(here * 100), round(there * 100)))
		best["why"] = "; ".join(evidence[:4]) or "no single feature dominates - the match is weak"
		if len(ranked) > 1:
			best["runner_up"] = ranked[1]["distance"]
			best["runner_up_optimize"] = ranked[1]["optimize"]
		best["confidence"] = confidence(best, target)
	return ranked


def confidence(best: dict, target: dict) -> str:
	"""How much weight the answer carries, in the tool's own words."""
	if best.get("margin", 0.0) >= 0.5:
		return "strong: the shape of this code is not produced by the other levels"
	if msvc(best.get("compiler")):
		# `cl` has no -O3, and /O1 and /O2 trade size against speed rather than differing in the
		# shape of a body: whether /O2 vectorises depends on whether the program has a loop it
		# can vectorise. So two optimising levels close together are reported as the class they
		# are, and only /Od against the rest is claimed as an answer. (Docs/MSVC-Plan.md MS-4.)
		if best.get("level_class"):
			return ("a class, not a level: /O1 and /O2 are %.3f apart on these features and which "
				"one it is depends on what the program contains (cl /O2 vectorises loops, /O1 "
				"trades size for speed). What is established is that this is optimised cl code: "
				"%d%% of bodies address their locals off %%rsp and %d%% store their arguments to "
				"their home slots, against %d%% and %d%% at /Od") % (best.get("margin", 0.0),
					round(target.get("rspmem", 0) * 100), round(target.get("argstore", 0) * 100),
					round(best["profile"]["rspmem"] * 100), round(best["profile"]["argstore"] * 100))
		if best["optimize"] == 0:
			return ("probable as a class: this is /Od cl code - %d%% of the sampled bodies address "
				"their locals off %%rsp and %d%% store their arguments to their home slots" % (
					round(target.get("rspmem", 0) * 100), round(target.get("argstore", 0) * 100)))
		return ("weak as a level: /O1 and /O2 differ in how hard they optimise, not in the shape "
			"of a body. What is established is that this is not /Od code")
	if best.get("margin", 0.0) >= 0.15:
		return "probable: clearly closer than the next level, but the levels are adjacent"
	if best["optimize"] >= 1:
		return ("weak as a level: -O1/-O2/-O3 differ in ways a prologue does not show "
			"(inlining depth, unrolling). What is established is that this is optimised code: "
			"no frame pointer (%d%%) and no argument spilling (%d%%)") % (
				round(target.get("frame", 0.0) * 100), round(target.get("spill", 0.0) * 100))
	return "weak: the sample is too small or too mixed to rank the levels apart"


def sample_warning(profile: dict, note: dict | None = None, narrowed: bool = False) -> str:
	"""Why a single answer may not be safe for this sample, or '' when it is.

	The common case is not a mystery in the code but a fact about the file: a statically
	linked image is mostly somebody else's library code, built with somebody else's flags.
	That only needs saying when the caller has not already narrowed the sample themselves.
	"""
	warnings = []
	if note and note.get("static") and not narrowed and profile.get("bodies", 0) > 40:
		warnings.append("this image is linked static: most of the %d sampled bodies are "
			"library code built by someone else with someone else's flags, and they outvote "
			"the program itself" % profile["bodies"])
	frame = profile.get("frame", 0.0)
	if 0.15 < frame < 0.85 and profile.get("bodies", 0) >= 20:
		warnings.append("%d%% of the sampled bodies set up a frame pointer and %d%% do not, so the "
			"sample spans more than one build" % (round(frame * 100), round((1 - frame) * 100)))
	if not warnings:
		return ""
	return ("%s. Narrow the sample with --range <file addresses> (the span nm/objdump show for "
		"the program's own code) or --sample <name>, then read the answer again."
		% ". ".join(warnings))
