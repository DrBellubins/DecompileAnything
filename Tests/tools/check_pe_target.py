"""MS-0 + MS-1 acceptance (Docs/MSVC-Plan.md §7): does the tool read a PE *target*?

	run: .venv/bin/python Tests/tools/check_pe_target.py

The target is a shipped MSVC binary, `Tests/Proprietary/notepad.exe` (gitignored - §2 of the
plan says what it is and how to re-measure it). Nothing here needs a compiler: MS-0 is the
target side only, and every assertion is a fact that file carries. The expected values are the
ones §2/§3 of the plan measured on this machine on 2026-11-04, so a change in them means the
tool or the target changed, not that this script was rewritten to match.

Three groups:

1. **The build note** (`decomp detect` without a probe): the container, the imports, the
   toolset era, and the three debug records - CodeView (the PDB's identity, hence the answer
   key of §4), POGO/LCTG (which is what decides that the byte gate cannot be promised, §6)
   and REPRO. `static` must not be reported as true for a binary that imports 28 DLLs, and a
   C runtime import must not be reported as C++.
2. **The section and byte path**, which is what crashed: `section_capabilities` reading a
   PE's `characteristics`, and reading the bytes of a `.rdata` string the analysis named.
3. **`detect --range`**, which only works if the sample's addresses are in the domain the
   caller is quoting: imagebase + RVA for an x64 PE.
4. **`find` and `show` on the cached analysis**, run as the CLI runs them, plus the address
   question the PE can answer exactly: the analysis' domain is the file's own plus the image
   base, so the offset is 0 - said, not guessed.

4. **`find` and `show` on the cached analysis**, run as the CLI runs them, plus the address
   question the PE can answer exactly: the analysis' domain is the file's own plus the image
   base, so the offset is 0 - said, not guessed.
5. **MS-1: the file's own function table.** `.pdata` is read into the cache next to the Ghidra
   ranges, every unit's extent equals the record the file carries, and the disagreement between
   the two is *reported* with the exact numbers §3 item 5 measured by hand: 154 agree, 32 the
   analysis reports shorter, 0 longer, 0 units without an entry, 35 analysis entries the file's
   table does not name. Those functions are then labelled as not-in-`.pdata` rather than shown
   like real units, and `extract.original_function` compares the compiler's extent of a unit.
   A cache written before MS-1 (every ELF analysis on disk) must still work and must be
   unchanged - the ELF path has no unit table.

Exit: 0 everything passed, 1 a fact came out wrong, 2 the target (or its analysis) is missing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, extract, normalize, toolchain  # noqa: E402

TARGET = TESTS / "Proprietary" / "notepad.exe"

# The facts of Docs/MSVC-Plan.md §2 and §3, verbatim.
IMAGE_BASE = 0x140000000
PDB = {"name": "notepad.pdb", "guid": "5c1bb141-8276-e6c4-c297-fcbaec420f58", "age": 1}
IMPORTS = 28
TOOL_BUILD = 25711  # every MSVC tool at this build id, per the Rich header
STRING_ADDRESS = 0x1400205f0  # 'TextOutW' in .rdata, as the analysis names it
STRING_BYTES = b"TextOutW"

# The function table this file carries (MSVC-Plan §2/§4) and the disagreement MS-1 must now
# report instead of hiding (§3 item 5, measured by hand on 2026-11-04).
PDATA_UNITS = 186
PDATA_BYTES = 99778
AGREE, ANALYSIS_SHORTER, ANALYSIS_LONGER = 154, 32, 0
ANALYSIS_ONLY = 35  # entries Ghidra made up in the alignment gaps between units


def main() -> int:
	if not TARGET.is_file():
		print("%s: not here - it is gitignored; see Docs/MSVC-Plan.md §2 for what it is and "
			"how to re-measure it" % TARGET)
		return 2
	bad = []
	bad += check_note()
	bad += check_sections()
	bad += check_range()
	bad += check_cli()
	bad += check_units()
	bad += check_unchanged_path()
	print("check_pe_target: %s" % ("OK" if not bad else "%d check(s) failed" % len(bad)))
	return 0 if not bad else 1


def report(name: str, bad: list[str]) -> None:
	for line in bad:
		print("   FAIL %s" % line)
	print("%s: %s" % (name, "ok" if not bad else "%d wrong" % len(bad)))


# --------------------------------------------------------------------------------------
# 1. the build note


def check_note() -> list[str]:
	note = toolchain.build_note(TARGET)
	bad = []
	if note.get("error"):
		report("build note", [note["error"]])
		return ["note"]
	facts = {
		"format": (note.get("format"), "PE"),
		"arch": (note.get("arch"), "AMD64"),
		"bits": (note.get("bits"), 64),
		"file_type": (note.get("file_type"), "EXE"),
		"pie (ASLR)": (note.get("pie"), True),
		"compiler": (note.get("compiler"), "msvc"),
		"linker_version": (note.get("linker_version"), "14.12"),
		"imports": (len(note.get("needed") or []), IMPORTS),
		"static": (note.get("static"), False),
		"ltcg (/GL + /LTCG)": (note.get("ltcg"), True),
		"pogo": (note.get("pogo"), "LCTG"),
		# MS-0 left `language` unset on purpose: an msvcrt.dll import is what a plain C program
		# imports too, and there was nothing else to read. MS-4 has something else to read: this
		# file's import table names `?terminate@@YAXXZ`, a decorated C++ runtime function - a
		# C++ name, not a C runtime. The claim is made now, and `language_proof` says on what.
		"language (from a decorated name, not from a C runtime)": (note.get("language"), "c++"),
	}
	for name, (got, want) in facts.items():
		if got != want:
			bad.append("%s: %r, the file says %r" % (name, got, want))
	# The toolset era is what a candidate has to be built with (§6); the Rich build id is the
	# independent second reading of it (§2: linker 14.12 and build 25711 agree).
	toolset = note.get("toolset") or {}
	if "v141" not in str(toolset.get("family", "")):
		bad.append("toolset: %r, expected the v141 family that link.exe 14.12 names" % toolset)
	if TOOL_BUILD not in toolchain.rich_builds(note):
		bad.append("rich: tool build %d not recorded (%r)" % (TOOL_BUILD, note.get("rich")))
	# MS-4: the toolset is read from the linker's own Rich record as well as from the optional
	# header, and the two readings are *compared* rather than merged. On this file they agree,
	# which is a fact about the file and can be asserted.
	identity = toolset.get("rich") or {}
	if (identity.get("linker") or {}).get("build") != TOOL_BUILD:
		bad.append("rich linker record: %r, expected the linker record at build %d"
			% (identity.get("linker"), TOOL_BUILD))
	if identity.get("linker_version") != "14.12":
		bad.append("rich build -> toolset: %r, expected build %d to read as 14.12"
			% (identity.get("linker_version"), TOOL_BUILD))
	if toolset.get("agree") is not True:
		bad.append("toolset cross-check: %r, on this file the two readings agree"
			% toolset.get("agree"))
	if not any(item["count"] for item in note.get("rich", [])):
		bad.append("rich: every count read as 0 (LIEF 1.0 says `count`, not `number`)")
	pdb = note.get("pdb") or {}
	for key, want in PDB.items():
		if pdb.get(key) != want:
			bad.append("pdb.%s: %r, the CodeView record says %r" % (key, pdb.get(key), want))
	url = "https://msdl.microsoft.com/download/symbols/%s/%s%d/%s" % (
		PDB["name"], PDB["guid"].replace("-", "").upper(), PDB["age"], PDB["name"])
	if pdb.get("symbols_url") != url:
		bad.append("pdb.symbols_url: %r, expected %r" % (pdb.get("symbols_url"), url))
	if not str(note.get("abi", "")).lower().startswith("msvc crt"):
		bad.append("abi: %r, expected the MSVC CRT that msvcrt.dll imports" % note.get("abi"))
	for want in ("pogo:LCTG", "reproducible-build"):
		if not any(want in item for item in note.get("build_notes", [])):
			bad.append("build notes: %r not recorded (%s)" % (want, note.get("build_notes")))
	# §8 of the plan: forget the image-base bias once and every address is "no such function".
	if not note.get("image_base") or note["image_base"] != IMAGE_BASE:
		bad.append("image_base: %r, expected %s" % (note.get("image_base"), hex(IMAGE_BASE)))
	text = (note.get("sections") or {}).get(".text")
	if text != IMAGE_BASE + 0x1000:
		bad.append("sections[.text]: %r, expected %s (RVA + image base)"
			% (text, hex(IMAGE_BASE + 0x1000)))
	entry = note.get("entrypoint") or 0
	if not text <= entry < IMAGE_BASE + 0x20000:
		bad.append("entrypoint: %s, expected an address inside .text" % hex(entry))
	for line in toolchain.note_lines(note):
		print(line)
	report("build note", bad)
	return bad


# --------------------------------------------------------------------------------------
# 2. the section flags and the bytes behind them


def check_sections() -> list[str]:
	import lief

	bad = []
	binary = lief.parse(str(TARGET))
	want = {".text": (True, False, True), ".rdata": (True, False, False),
		".data": (True, True, False)}
	seen = {}
	for section in binary.sections:
		name = str(section.name)
		if name in want:
			seen[name] = extract.section_capabilities(binary.format, section)
	for name, expected in want.items():
		if seen.get(name) != expected:
			bad.append("section %s: %r, expected %r (allocated, writable, executable)"
				% (name, seen.get(name), expected))
	# The bytes behind a reference: `find`/`show`/`try` read them through TargetImage, keyed by
	# the analysis' addresses. `.rdata` is a PE's `.rodata`.
	image = extract.TargetImage(TARGET, 0)
	if image.error:
		bad.append("TargetImage: %s" % image.error)
	else:
		got = image.read(STRING_ADDRESS, len(STRING_BYTES))
		if got != STRING_BYTES:
			bad.append("read at %s: %r, expected %r" % (hex(STRING_ADDRESS), got, STRING_BYTES))
		found = {name for name, _address, _size in image.data_sections()}
		for name in (".rdata", ".data"):
			if name not in found:
				bad.append("data_sections: %s missing (%s)" % (name, sorted(found)))
	# A COFF object has no `binary.format` and no `identity_class`, which is what used to make
	# even opening one an error. The symbol semantics are MS-3; this only asks for no crash.
	bad += check_coff()
	report("sections and bytes", bad)
	return bad


def check_coff() -> list[str]:
	import shutil
	import tempfile

	# Either driver emits a real COFF object here; both are the same container MS-3 has to read.
	drivers = []
	if shutil.which("clang-cl"):
		drivers.append((["clang-cl", "/Od", "/Gy", "/c"], lambda where: ["/Fo%s" % where]))
	if shutil.which("clang"):
		drivers.append((["clang", "--target=x86_64-pc-windows-msvc", "-Od", "-function-sections",
			"-c"], lambda where: ["-o", where]))
	for command, out_form in drivers:
		with tempfile.TemporaryDirectory(prefix="decomp-coff-probe-") as directory:
			source = Path(directory) / "probe.c"
			source.write_text("int add2(int a, int b) { return a + b; }\n"
				"int use(int x) { return add2(x, 3) + 4; }\n")
			object_path = Path(directory) / "probe.obj"
			finished = subprocess.run(command + [str(source)] + out_form(str(object_path)),
				capture_output=True, text=True)
			if finished.returncode != 0 or not object_path.is_file():
				print("   note %s could not build a COFF object: %s"
					% (command[0], (finished.stderr or finished.stdout).strip().splitlines()[:1]))
				continue
			coff = extract.CandidateObject(object_path)
			bad = []
			if coff.error:
				bad.append("CandidateObject on a COFF object: %s" % coff.error)
			if coff.machine != "AMD64" or coff.bits != 64:
				bad.append("COFF header: machine=%r bits=%r, expected AMD64 64"
					% (coff.machine, coff.bits))
			print("   COFF object from %s: machine %s, %d bits, no error (its symbols are MS-3)"
				% (command[0], coff.machine, coff.bits))
			return bad
	print("   note no COFF-emitting compiler here (clang-cl or clang --target=...-msvc), so the"
		" COFF header path was not exercised")
	return []


# --------------------------------------------------------------------------------------
# 3. `detect --range`: the sample addresses must be the ones objdump prints


def check_range() -> list[str]:
	"""Narrowing the -O shape sample to a range of file addresses, which for an x64 PE means
	imagebase + RVA (the same domain `--bin`/`nm`/objdump and the cache use)."""
	profile, _note, problems = toolchain.target_shape(TARGET, rng=(0x140012000, 0x140018000))
	bad = []
	if problems or not profile.get("bodies"):
		bad.append("--range inside .text sampled nothing: %s" % (problems or "no bodies"))
	else:
		inside = profile["bodies"]
		_bad, _note, problems = toolchain.target_shape(TARGET, rng=(0x90000, 0x91000))
		if not any("--range" in item for item in problems):
			bad.append("a range outside the image sampled %r bodies instead of saying it found none"
				% _bad.get("bodies"))
		print("   sampled %d bodies of 0x140012000-0x140018000; a range outside the image is"
			" reported as empty" % inside)
	report("--range in the file's own addresses", bad)
	return bad


# --------------------------------------------------------------------------------------
# 4. the cached analysis: find and show, run as the CLI runs them


def check_cli() -> list[str]:
	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	status = store.status(cache.target_key(TARGET)["key"])
	if not status.get("complete"):
		print("%s: not analysed - run: decomp analyze %s" % (TARGET, TARGET))
		return ["no analysis"]
	conn = cache.open_readonly(Path(status["db"]))
	bad = []
	try:
		meta = cache.meta(conn)
		# An analysis made before MS-0 recorded the text "None" here; the one on disk was rewritten
		# by MS-1's re-analysis, so check the tolerant reader itself as well as the value.
		if cache.address_offset(meta) != 0 or cache.address_offset({"address_offset": "None"}) != 0:
			bad.append("address_offset: %r, expected 0 (and 'None' to read as 0)"
				% meta.get("address_offset"))
		sections = [dict(row) for row in conn.execute("SELECT name, start, end, executable,"
			" writable FROM sections")]
		offset, basis = cli._address_offset(sections, toolchain.build_note(TARGET)["sections"],
			int(meta["image_base"]))
		if (offset, basis) != (0, ".text"):
			bad.append("address offset: %r via %r, expected 0 via .text (Ghidra loads a PE at its"
				" own image base)" % (offset, basis))
		# the data path `show` runs: the cached bytes, the decoder, and the reference the
		# analysis recorded against the .rdata slot
		row = conn.execute("SELECT * FROM functions WHERE entry = 0x140012a88").fetchone()
		if row is None:
			bad.append("no cached function at 0x140012a88 (the caller of TextOutW)")
		else:
			function = extract.original_function(conn, meta, row)
			if not function.bytes or len(function.bytes) != int(row["size"]):
				bad.append("cached bytes: %r for a %s-byte function"
					% (len(function.bytes) if function.bytes else None, row["size"]))
			# `show` and `try` bind a reference to the operand that encodes it, through the same
			# decoder and tokeniser, on an x64 PE exactly as on an ELF.
			handle = normalize.capstone_for(meta.get("language_id") or "", detail=True)
			if handle is None:
				bad.append("no decoder for %r" % meta.get("language_id"))
				instructions = []
			else:
				instructions = normalize.decode_function(handle, function.address, function.bytes,
					function.boundaries)
			if len(instructions) < 10:
				bad.append("decoded %d instructions of a %s-byte body" % (len(instructions), row["size"]))
			bind, _used = extract.original_bindings(conn, meta, row,
				extract.TargetImage(TARGET, cache.address_offset(meta)))
			bound = [item for instruction in instructions for item in bind(instruction).values()]
			if not bound:
				bad.append("no reference bound to an operand, though the analysis recorded %d"
					% conn.execute("SELECT count(*) FROM refs WHERE fn = ?", (row["id"],)).fetchone()[0])
			else:
				named = [item for item in bound if item.name]
				print("   decoded %d instructions, bound %d references (%d named), e.g. %s in %s"
					% (len(instructions), len(bound), len(named), named[0].name, named[0].section))
	finally:
		conn.close()

	for argv in (["find", "TextOutW", "--bin", str(TARGET)],
			["show", "0x140012a88", "--bin", str(TARGET)]):
		finished = subprocess.run([sys.executable, "-m", "decomp", *argv], cwd=str(REPO),
			capture_output=True, text=True)
		if finished.returncode != 0 or "Traceback" in finished.stdout + finished.stderr:
			bad.append("decomp %s: exit %s\n%s" % (" ".join(argv), finished.returncode,
				(finished.stdout + finished.stderr).strip()[-600:]))
		else:
			lines = (finished.stdout or "").strip().splitlines()
			print("   decomp %s -> %d lines, exit 0" % (" ".join(argv), len(lines)))
	report("find and show on the PE", bad)
	return bad


# --------------------------------------------------------------------------------------
# 5. MS-1: the file's own function table, kept, preferred, and its disagreement reported


def pdata_units() -> list[dict]:
	"""`.pdata` read straight out of the file, independently of `decomp.extract`: the answer key.
	Its RVAs are relative to the image base, which is the bias every consumer has to apply."""
	import lief
	import struct

	binary = lief.PE.parse(str(TARGET))
	section = binary.get_section(".pdata")
	data = bytes(section.content)
	base = int(binary.imagebase)
	units = []
	for position in range(0, len(data) - len(data) % 12, 12):
		begin, end, unwind = struct.unpack_from("<III", data, position)
		if end <= begin:
			continue
		units.append({"entry": base + begin, "end": base + end, "size": end - begin,
			"unwind": base + unwind})
	return units


def unit_size(conn, entry: int) -> str:
	row = cache.unit_at(conn, entry)
	return str(int(row["size"])) if row is not None else "?"


def check_units() -> list[str]:
	bad = []
	answer = pdata_units()
	if len(answer) != PDATA_UNITS or sum(item["size"] for item in answer) != PDATA_BYTES:
		print("%s: .pdata now reads as %d units / %d bytes - re-measure §2 of the plan"
			% (TARGET, len(answer), sum(item["size"] for item in answer)))
		return [".pdata changed"]
	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	status = store.status(cache.target_key(TARGET)["key"])
	if not status.get("complete"):
		print("%s: not analysed - run: decomp analyze %s --force" % (TARGET, TARGET))
		return ["no analysis"]
	conn = cache.open_readonly(Path(status["db"]))
	try:
		if not cache.has_table(conn, "units"):
			report("the file's function table", ["the cached analysis holds no unit table - "
				"re-analyse: decomp analyze %s --force" % TARGET])
			return ["no units table"]
		rows = cache.unit_rows(conn)
		# (a) the cache holds the file's table, unchanged, in the analysis' addresses
		if len(rows) != PDATA_UNITS:
			bad.append("%d units cached, the file's .pdata names %d" % (len(rows), PDATA_UNITS))
		else:
			for row, want in zip(rows, answer):
				for key in ("entry", "end", "size", "unwind"):
					if int(row[key]) != want[key]:
						bad.append("unit %s: %s %s, the file says %s"
							% (hex(want["entry"]), key, hex(int(row[key])), hex(want[key])))
						break
				if row["source"] != ".pdata" or row["section"] != ".text":
					bad.append("unit %s: source %r section %r, expected .pdata in .text"
						% (hex(want["entry"]), row["source"], row["section"]))
		if bad:
			report("the file's function table", bad)
			return bad
		# (b) the disagreement is reported, with the numbers §3 item 5 measured by hand
		rec = cache.unit_reconciliation(conn)
		for name, got, want in (("units", rec["units"], PDATA_UNITS),
				("code bytes", rec["code_bytes"], PDATA_BYTES),
				("agree", rec["agree"], AGREE),
				("analysis reports shorter", rec["analysis_shorter"], ANALYSIS_SHORTER),
				("analysis reports longer", rec["analysis_longer"], ANALYSIS_LONGER),
				("units with no entry in the analysis", len(rec["not_in_analysis"]), 0),
				("analysis entries not in .pdata", len(rec["not_in_table"]), ANALYSIS_ONLY)):
			if got != want:
				bad.append("%s: %r, expected %r" % (name, got, want))
		if rec["source"] != ".pdata":
			bad.append("unit source: %r, expected .pdata" % rec["source"])
		for line in cache.unit_lines(rec):
			print(line)
		for line in rec["not_in_table"][:3]:
			print("   invented at %s: %s (%d bytes)" % (hex(line["entry"]), line["name"], line["size"]))
		# (c) preferred: a unit the analysis cut short is compared at the compiler's extent
		meta = cache.meta(conn)
		short, agree = [], []
		for row in conn.execute("SELECT entry, size FROM functions"):
			unit = cache.unit_at(conn, int(row["entry"]))
			if unit is None:
				continue
			(short if int(row["size"]) < int(unit["size"]) else
				agree if int(row["size"]) == int(unit["size"]) else []).append(
				(int(row["entry"]), int(row["size"])))
		if not short or not agree:
			bad.append("expected a short unit and an agreeing one to compare, found %d and %d"
				% (len(short), len(agree)))
		else:
			entry, cached = short[0]
			unit = cache.unit_at(conn, entry)
			row = cache.resolve_function(conn, hex(entry))[0]
			function = extract.original_function(conn, meta, row)
			if function.size != int(unit["size"]):
				bad.append("original_function at %s: %d bytes, %s says the unit is %d"
					% (hex(entry), function.size, unit["source"], unit["size"]))
			if len(function.bytes) != int(unit["size"]):
				bad.append("bytes at %s: %d read, expected the unit's %d"
					% (hex(entry), len(function.bytes), unit["size"]))
			if not any(".pdata" in item for item in function.warnings):
				bad.append("no disagreement reported at %s (%s)" % (hex(entry), row["name"]))
			# the bytes past the analysed body are the file's own, not invented
			tail = extract.TargetImage(TARGET, cache.address_offset(meta)).read(
				entry + cached, int(unit["size"]) - cached)
			if tail and function.bytes[cached:cached + len(tail)] != tail:
				bad.append("the %d bytes past the analysed body at %s are not the file's bytes"
					% (len(tail), hex(entry)))
			print("   %s (%s): the analysis' %d bytes, %d compared - %s" % (hex(entry), row["name"],
				cached, function.size,
				[item for item in function.warnings if ".pdata" in item][0][:70] + "..."))
			entry, cached = agree[0]
			function = extract.original_function(conn, meta, cache.resolve_function(conn, hex(entry))[0])
			if function.size != cached or function.warnings:
				bad.append("agreeing unit at %s: %d bytes and %d warning(s), expected %d and none"
					% (hex(entry), function.size, len(function.warnings), cached))
		# (c2) a body the analysis split into ranges with a gap in it: the unit is one contiguous
		# range, and its bytes come out of the file in one piece. This is the multi-range problem
		# Design-Plan Phase 5 has for -O2 hot/cold bodies, solved here for a PE.
		import json as _json

		split = []
		for row in conn.execute("SELECT entry, size, ranges FROM functions"):
			ranges = _json.loads(row["ranges"] or "[]")
			unit = cache.unit_at(conn, int(row["entry"]))
			if len(ranges) > 1 and unit is not None \
					and int(unit["end"]) - int(row["entry"]) > int(row["size"]):
				split.append((int(row["entry"]), int(row["size"]), ranges))
		if not split:
			bad.append("no multi-range body whose unit is longer, which this file is expected to have")
		else:
			entry, cached, ranges = split[0]
			extent = int(cache.unit_at(conn, entry)["size"])
			row = cache.resolve_function(conn, hex(entry))[0]
			function = extract.original_function(conn, meta, row)
			whole = extract.TargetImage(TARGET, cache.address_offset(meta)).read(entry, extent)
			if function.size != extent or function.bytes != whole:
				bad.append("the split body at %s was not read as the unit: %d bytes, expected the "
					"file's contiguous %d" % (hex(entry), len(function.bytes), extent))
			gaps = sum(int(ranges[k + 1][0]) - int(ranges[k][1]) for k in range(len(ranges) - 1))
			if not any(".pdata" in item for item in function.warnings):
				bad.append("the %d-byte gap inside the body at %s is not reported" % (gaps, hex(entry)))
			# and those bytes are decodable: comparing a unit means decoding its padding, which is
			# where a gap byte used to end the run (capstone's own object has `.size`, not `.length`)
			handle = normalize.capstone_for(meta.get("language_id") or "", detail=True)
			instructions = normalize.decode_function(handle, function.address, function.bytes,
				function.boundaries) if handle is not None else []
			inside = [item for item in instructions
				if int(ranges[0][1]) <= item.address < int(ranges[1][0])]
			if not instructions or not inside:
				bad.append("decoding the unit at %s gave %d instruction(s), %d of them in the "
					"%d-byte gap" % (hex(entry), len(instructions), len(inside), gaps))
			print("   %s: %d ranges with %d gap bytes, %d analysed -> the unit's %d bytes read "
				"contiguously from the file, %d instructions decoded (%d in the gap)"
				% (hex(entry), len(ranges), gaps, cached, extent, len(instructions), len(inside)))
		# (d) `find`/`show` say which of what they list the file's table knows
		cases = [(["show", hex(rec["not_in_table"][0]["entry"]), "--bin", str(TARGET)],
			["names no unit at", ".pdata"]),
			(["find", hex(rec["not_in_table"][0]["entry"]), "--bin", str(TARGET)],
			["not in .pdata"])]
		if short:
			cases.append((["show", hex(short[0][0]), "--bin", str(TARGET)],
				["the analysis' body is", unit_size(conn, short[0][0])]))
		for argv, wants in cases:
			finished = subprocess.run([sys.executable, "-m", "decomp", *argv], cwd=str(REPO),
				capture_output=True, text=True)
			text = finished.stdout + finished.stderr
			if finished.returncode != 0 or "Traceback" in text:
				bad.append("decomp %s: exit %s\n%s" % (" ".join(argv), finished.returncode,
					text.strip()[-400:]))
				continue
			missing = [item for item in wants if item not in text]
			if missing:
				bad.append("decomp %s does not report %r" % (" ".join(argv), missing))
			else:
				line = next((item for item in text.splitlines() if wants[-1] in item), "")
				print("   decomp %s -> %s" % (" ".join(argv), line.strip()[:150]))
	finally:
		conn.close()
	report("the file's own function table (MS-1)", bad)
	return bad


# --------------------------------------------------------------------------------------
# 6. the ELF path is untouched: a cache with no unit table still works and says nothing false


# --------------------------------------------------------------------------------------
# 6. the ELF path: an old cache with no unit table still works, and a unit has its own extent


def check_unchanged_path() -> list[str]:
	"""What a PE may not change: the ELF path, and what Phase 5 made it."""
	elf = TESTS / "build" / "gcc-o0" / "da_tests.stripped"
	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	status = store.status(cache.target_key(elf)["key"])
	if not status.get("complete"):
		print("   note %s is not analysed, so the ELF path was not re-checked" % elf)
		return []
	bad = []
	conn = None
	try:
		conn = cache.open_readonly(Path(status["db"]))
		units = cache.unit_rows(conn) if cache.has_table(conn, "units") else []
		if units:
			# Phase 5: an ELF analysis carries the file's own table too - `.eh_frame`, and
			# `st_size` where the file kept it. Any other source would be an invention.
			sources = {row["source"] for row in units}
			if not sources <= {".eh_frame", "symtab"}:
				bad.append("an ELF unit table with sources %s" % ", ".join(sorted(sources)))
			print("   ELF analysis carries %d units from %s"
				% (len(units), ", ".join(sorted(sources))))
		else:
			# a cache written before either table existed: read tolerantly, and say nothing false
			if cache.unit_at(conn, 0x1000) is not None \
					or cache.unit_covering(conn, 0x1000) is not None:
				bad.append("a unit lookup on an analysis without a table returned something")
			if cache.unit_reconciliation(conn).get("units"):
				bad.append("unit_reconciliation invented units for an analysis without a table")
		row = conn.execute("SELECT * FROM functions WHERE kind = 'function' AND size > 40"
			" ORDER BY entry LIMIT 5").fetchall()
		if not row:
			bad.append("no function in the ELF analysis to re-check")
		else:
			# A single-range body is compared exactly as it always was. A body the analysis
			# split at alignment padding is now read as the one block it is (Phase 5): the
			# bytes between the ranges are inside the unit, and the candidate's `.o` has them.
			single = [item for item in row if len(json.loads(item["ranges"] or "[]")) <= 1]
			split = [item for item in row if len(json.loads(item["ranges"] or "[]")) > 1]
			cases = []
			if single:
				cases.append((single[0], int(single[0]["size"])))
			for item in split[:1]:
				ranges = json.loads(item["ranges"])
				span = max(stop for _start, stop in ranges) - min(start for start, _stop in ranges)
				cases.append((item, span))
			for item, want in cases:
				function = extract.original_function(conn, cache.meta(conn), item)
				if function.size != want or any(".pdata" in claim for claim in function.warnings):
					bad.append("original_function on the ELF path at %s: %d bytes, want %d, %r"
						% (hex(item["entry"]), function.size, want, function.warnings))
				else:
					print("   ELF path: %s @ %s, %d bytes compared (%s)"
						% (item["name"], hex(item["entry"]), function.size,
							"one range" if len(json.loads(item["ranges"] or "[]")) <= 1
							else "one block across %d ranges" % len(json.loads(item["ranges"]))))
	finally:
		if conn is not None:
			conn.close()
	report("the ELF path (its own unit, never a PE one)", bad)
	return bad


if __name__ == "__main__":
	raise SystemExit(main())
