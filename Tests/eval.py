"""Build, describe and score the TestBinary benchmark.

This is the harness that judges the decompilation loop, so it deliberately does not depend on
the decomp tool for anything about scoring: the normalise/diff half is its own, and works with
binutils + stdlib only (see Docs/Design-Plan.md, Phase 2). The one thing it takes from the
tool is how to run an external command with a deadline that holds - `decomp.spawn` - because a
build that never returns is worse than a build that fails: `eval.py build --variant msvc-o0`
runs 89 sources through `cl` under Wine, and with no Windows prefix in the environment the
first one of them never comes back.

Commands
  build      compile the benchmark, strip a copy, write answer_key/task_list/goldens
  selfcheck  run the reference binary's own hand-checked expectations
  self       recompile the original source and score every unit against the reference
             (calibration: this is the ceiling any candidate is measured against)
  try        score one candidate function against one unit
  goldens    (re)dump the golden trace
  report     coverage summary: units per tag/level, size histogram

Outputs live in Tests/build/<variant>/ and are gitignored.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shlex
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from decomp import spawn  # noqa: E402  (the bounded runner only, see the docstring)

TESTS_DIR = Path(__file__).resolve().parent
SOURCE_DIR = TESTS_DIR / "TestBinary"
BUILD_DIR = TESTS_DIR / "build"
CONFIG_PATH = TESTS_DIR / "project.toml"

SOURCES = [
	"main.cpp",
	"SelfTest.cpp",
	"TestFunctions/math.cpp",
	"TestFunctions/strings.cpp",
	"TestFunctions/structs.cpp",
]

DEFAULT_VARIANTS = {
	"gcc-o0": {"compiler": "g++", "optimize": 0, "arch": "x86-64"},
	"gcc-o2": {"compiler": "g++", "optimize": 2, "arch": "x86-64"},
	"gcc-o0-x86": {"compiler": "g++", "optimize": 0, "arch": "x86"},
}

UNIT_MARKER = re.compile(
	r"//\s*DA-UNIT\s+(?P<id>[A-Z]+-\d+)\s+level:(?P<level>easy|medium|hard)"
	r"(?:\s+tags:(?P<tags>[\w,+.-]*))?(?:\s+sym:(?P<sym>\S+))?"
)
# A definition header: something::Name( or name( at the start of a line.
DEF_MEMBER = re.compile(r"^(?:[\w:<>,\*&\[\]\s]+?)?([A-Za-z_]\w*)::(~?[A-Za-z_]\w*)\s*\(")
DEF_FREE = re.compile(r"^(?:static\s+|inline\s+|template\s*<[^>]*>\s*)*[\w:<>,\*&\[\]]+[\s]+([A-Za-z_]\w*)\s*\(")


# A build or a link is bounded at BUILD_TIMEOUT; everything the harness asks a binutils tool or
# the target binary for is bounded at TOOL_TIMEOUT. Both are far above anything measured here;
# the number exists so that a tool which is never going to answer is reported instead of waited
# for. `subprocess.run(timeout=)` is not that bound - see decomp/spawn.py.
BUILD_TIMEOUT = 300
TOOL_TIMEOUT = 120


def sh(args, cwd=None, binary=False, timeout=TOOL_TIMEOUT):
	finished = spawn.run(args, cwd=cwd, timeout=timeout)
	out = finished.stdout if not binary else finished.stdout.encode()
	if finished.timed_out:
		raise RuntimeError("%s did not finish in %ds (its whole process group was stopped)%s" % (
			" ".join(map(str, args)), timeout,
			" - " + finished.note if finished.note else "; a compiler that never answers is usually "
			"Wine with no WINEPREFIX (Docs/Setup.md §6)"))
	if finished.returncode != 0:
		raise RuntimeError("command failed (%s): %s\n%s" % (finished.returncode,
			" ".join(map(str, args)), (finished.stderr or finished.stdout) or
			"the command produced no output"))
	return out


# --------------------------------------------------------------------------------------
# config


def load_config():
	config = {"variants": DEFAULT_VARIANTS, "threshold": 97.0, "std": "c++17"}
	if CONFIG_PATH.exists():
		try:
			import tomllib

			with CONFIG_PATH.open("rb") as handle:
				raw = tomllib.load(handle)
			for key in ("std", "threshold", "cppflags", "linkflags"):
				if key in raw:
					config[key] = raw[key]
			if "variants" in raw:
				merged = dict(DEFAULT_VARIANTS)
				merged.update(raw["variants"])
				config["variants"] = merged
		except Exception as exc:  # a broken config must not hide the benchmark
			print("warning: ignoring %s: %s" % (CONFIG_PATH, exc))
	return config


def variant_flags(config, name):
	variant = config["variants"][name]
	compiler = variant.get("compiler", "g++")
	extra = list(variant.get("cppflags", config.get("cppflags", [])))
	arch = ["-m32"] if variant.get("arch") == "x86" else []
	link = list(variant.get("linkflags", config.get("linkflags", [])))
	if is_msvc(compiler):
		# cl takes none of -std/-O/-Wall (Docs/MSVC-Plan.md §1); /nologo keeps the build log
		# readable. Same rule as decomp.toolchain.build_flags - the benchmark and the tool have
		# to build a candidate the same way.
		level = "/O2" if int(variant.get("optimize", 0)) >= 2 else "/Od"
		std = "/std:c++%s" % str(config["std"]).replace("c++", "").replace("gnu++", "") or "17"
		return compiler, [level, std, "/EHsc", "/W3", "/nologo", "/FS"] + extra, link
	return compiler, ["-std=%s" % config["std"], "-O%d" % variant.get("optimize", 0), "-Wall", "-Wextra"] + arch + extra, link


def is_msvc(compiler):
	"""An MSVC driver - a different argument form in everything that matters."""
	return str(compiler or "").lower() in ("cl", "cl.exe", "clang-cl", "msvc", "icx", "icx-cl")


def is_pe(path):
	"""PE/COFF rather than ELF - by its magic, because the answer key differs per format."""
	try:
		with open(path, "rb") as handle:
			return handle.read(2) == b"MZ"
	except OSError:
		return False


def wine_runner():
	"""A PE is built for Windows; Wine runs it. `wine64` first: a 32-bit wine launcher is not
	usable on this machine (Docs/Setup.md §1)."""
	import shutil

	return shutil.which("wine64") or shutil.which("wine")


def runner(path):
	return [wine_runner(), str(path)] if is_pe(path) else [str(path)]


# --------------------------------------------------------------------------------------
# symbol tables


def msvc_simple_name(decorated):
	"""`?AbsDiff@CMathTests@@SAHHH@Z` -> `CMathTests::AbsDiff`.

	`c++filt` cannot read an MSVC decoration (Docs/MSVC-Plan.md §8), and the decorated name is
	the comparison key anyway - this is only the display/matching form of the Itanium names the
	answer key already uses. Anything it does not understand comes back unchanged.
	"""
	if not decorated.startswith("?"):
		return decorated
	body = decorated[1:].split("@@")[0]
	parts = body.split("@")
	name = parts[0]
	owner = [p for p in parts[1:] if p and not p.startswith("?")]
	if "?" in name or not name:
		return decorated
	return "::".join(list(reversed(owner)) + [name]) if owner else name


def demangle(names):
	if not names:
		return []
	return spawn.run(["c++filt"], stdin="\n".join(names), timeout=30).stdout.splitlines()


def symbols(binary):
	"""Every symbol with a size: [{address,size,mangled,name,type}] in address order.

	ELF: `nm --print-size` gives names and sizes. A PE gives neither in general - a linked
	MSVC image has no COFF symbol table at all, and COFF symbols have no size field - so the
	extents come from the file's own function table (`.pdata`, MSVC-Plan §4) and the names
	from whatever the build left behind: COFF symbols (a MinGW PE) or the map file `link /MAP`
	writes. A unit the names do not cover is still a unit; it is just unnamed.
	"""
	if is_pe(binary):
		return pe_symbols(binary)
	out = sh(["nm", "--defined-only", "--print-size", str(binary)])
	entries = []
	for line in out.splitlines():
		parts = line.split(None, 3)
		if len(parts) < 4:
			continue
		address, size, kind, mangled = parts
		if kind not in "tTwWdDrRbB":
			continue
		try:
			entries.append({"address": int(address, 16), "size": int(size, 16), "mangled": mangled, "type": kind})
		except ValueError:
			continue
	names = demangle([e["mangled"] for e in entries])
	for entry, name in zip(entries, names):
		entry["name"] = name
	entries.sort(key=lambda e: e["address"])
	return entries


# --------------------------------------------------------------------------------------
# the PE side of the answer key (Docs/MSVC-Plan.md §4)


def pe_sections(path):
	"""(image base, {section name: {va, vsize, rawptr, rawsize}}), stdlib only.

	Section `va` is imagebase + RVA, i.e. in the domain objdump, Ghidra and the cache use -
	the one conversion that has to be made exactly once (MSVC-Plan §8).
	"""
	with open(path, "rb") as handle:
		data = handle.read()
	offset = struct.unpack_from("<I", data, 0x3C)[0]
	if data[offset:offset + 4] != b"PE\0\0":
		raise RuntimeError("%s is not a PE" % path)
	coff = offset + 4
	_, count, _, _, _, size_optional, _ = struct.unpack_from("<HHIIIHH", data, coff)
	optional = coff + 20
	magic = struct.unpack_from("<H", data, optional)[0]
	image_base = (struct.unpack_from("<Q", data, optional + 24)[0] if magic == 0x20B
		else struct.unpack_from("<I", data, optional + 28)[0])
	sections = {}
	for index in range(count):
		head = optional + size_optional + index * 40
		name = data[head:head + 8].split(b"\0")[0].decode("latin-1")
		vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", data, head + 8)
		characteristics = struct.unpack_from("<I", data, head + 36)[0]
		sections[name] = {"va": image_base + rva, "vsize": vsize, "rawptr": rawptr,
			"rawsize": rawsize,
			# IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE are alternatives, not both set (MSVC-Plan §8).
			"executable": bool(characteristics & 0x20000020)}
	return image_base, sections


def pe_units(path):
	"""`.pdata`, the x64 unwind directory: (begin, end) of every function the compiler emitted.

	Iterated by the bytes the file actually holds, not by the section's virtual size - the
	padding after the records is not in the file (MSVC-Plan §8).
	"""
	image_base, sections = pe_sections(path)
	table = sections.get(".pdata")
	if not table:
		return []
	with open(path, "rb") as handle:
		handle.seek(table["rawptr"])
		data = handle.read(table["rawsize"])
	units = []
	for index in range(len(data) // 12):
		begin, end, _unwind = struct.unpack_from("<III", data, index * 12)
		if end <= begin:
			continue
		units.append({"address": image_base + begin, "size": end - begin})
	return units


def pe_names(binary, units, image_base, sections):
	"""Names for those extents: COFF symbols if the file kept them, else the map file.

	A linked MSVC image has no COFF symbol table (`nm` says "no symbols"), which is why the
	MSVC build links with `/MAP`. A MinGW PE does keep symbols, and `nm` reads them - that is
	the form this machine can produce without a Windows SDK.
	"""
	try:
		out = sh(["nm", "--defined-only", str(binary)])
	except RuntimeError:
		out = ""
	names = {}
	for line in out.splitlines():
		parts = line.split(None, 2)
		if len(parts) != 3 or parts[1] not in "tTwWdDrRbB":
			continue
		try:
			names[int(parts[0], 16)] = parts[2]
		except ValueError:
			continue
	if names and not any(address in names for address in (u["address"] for u in units)):
		# nm quotes an address relative to the image base on some builds; the units are biased.
		shifted = {address + image_base: name for address, name in names.items()}
		if any(address in shifted for address in (u["address"] for u in units)):
			names = shifted
	if not names:
		names.update(msvc_map_names(binary, image_base, sections))
	return names


def msvc_map_names(binary, image_base, sections):
	"""Names from `link /MAP`, measured on a v141 map of this benchmark.

	The "Publics by Value" rows are
	` 0001:00000270  main  0000000140001270 f  main.o` - a `group:offset` pair, the symbol,
	then `Rva+Base`, then flags and the object file. Two things that are not obvious from the
	documentation and were wrong here until a real map was read:

	* there is no section-*name* column to anchor on. The `0001:` index numbers the table of
	  "Start Length Name Class" at the top of the file, which lists merge groups (here
	  `.text$mn`, `.text$mn$00` and `.text$x` are all group 0001), so it is not a section
	  name and cannot be looked up in the PE's own section table.
	* the `Rva+Base` column is the final address - image base included - so it needs no
	  arithmetic at all. Rows of section `0000` are `<absolute>`/`<linker-defined>` symbols
	  (0x0, 0x100, the image base itself), which is exactly why the address is also required
	  to land inside an executable section of the file.
	"""
	for path in (Path(str(binary) + ".map"), Path(binary).with_suffix(".map")):
		# `link /MAP` names the file after the output: da_tests -> da_tests.map, u.exe -> u.map
		# (removing the ".map" from the first candidate would ask for the binary itself).
		if path.is_file():
			break
	else:
		return {}
	text = path.read_text(errors="replace")
	if "Publics by Value" not in text:
		return {}
	range_of = [(info["va"], info["va"] + info["vsize"])
		for info in sections.values() if info.get("executable")]
	names = {}
	body = text.split("Publics by Value", 1)[1]
	for line in body.splitlines():
		match = re.match(r"^\s*([0-9a-f]{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})\b", line)
		if not match or match.group(1) == "0000":
			continue
		address = int(match.group(4), 16)
		if not any(start <= address < end for start, end in range_of):
			continue
		names.setdefault(address, match.group(3))
	return names

def pe_symbols(binary):
	"""The same entry shape `symbols()` returns for an ELF, built from `.pdata` + names.

	An MSVC-built x64 PE has one `.pdata` record per function, which is the exact answer key
	(MSVC-Plan §4) - with one exception measured here, on a v141 /Od build of this benchmark:
	**12 of the 89 units have no `.pdata` record at all**. The ones that are missing are the
	functions the compiler gave no prologue and no epilogue - they only write the caller's
	shadow space, never touch `rsp`, make no call and have a single `ret`, so there is nothing
	for unwind info to describe and `link` emits neither `$unwind$…` nor `$pdata$…` for them.
	(Confirmed on a four-function control: `int other(int a,int b){return a-b;}` has no record,
	`int leaf_no_frame(int a,int b){return a<b?a:b;}` - which spills to a frame - does.)
	So `.pdata` is the compiler's function table for the functions that need unwinding, which
	for an /O2 or /GL build is every function (notepad.exe: 186 of 186), and is not complete
	for an /Od one. Both sources are therefore used, and the count from each is printed.

	GCC splits a function into one record per block group, so on a MinGW-built PE most records
	name no symbol. When that happens the units are taken from the symbols instead - stated out
	loud, because it is a worse answer and any score built on it inherits that.
	"""
	image_base, sections = pe_sections(binary)
	units = pe_units(binary)
	if not units:
		raise RuntimeError("%s has no .pdata - the answer key of an x64 PE is its function table"
			% binary)
	names = pe_names(binary, units, image_base, sections)
	entries = []
	for unit in units:
		name = names.get(unit["address"], "")
		entries.append({"address": unit["address"], "size": unit["size"], "mangled": name,
			"name": simple_name(name) if name else "unnamed@0x%x" % unit["address"], "type": "t"})
	named = sum(1 for entry in entries if entry["mangled"])
	if named * 3 < len(entries):
		print("  note: only %d of %d .pdata records of %s carry a name - this PE was not built "
			"by MSVC (GCC splits one function across several unwind records), so the units below "
			"come from the symbol table with extents up to the next symbol" % (named, len(entries), binary))
		entries = symbol_units(names)
	else:
		# Functions the unwind table does not describe, named by the map: added with an extent
		# up to the next boundary, which is the same fallback the paragraph above describes.
		boundaries = sorted([entry["address"] for entry in entries] + list(names))
		covered = [(entry["address"], entry["address"] + entry["size"]) for entry in entries]
		missing = [(address, name) for address, name in sorted(names.items())
			if not any(start <= address < end for start, end in covered)]
		if missing:
			print("  note: %d named functions of %s have no .pdata record - MSVC emits none for a "
				"function with no prologue or epilogue; their extent comes from the next boundary"
				% (len(missing), Path(binary).name))
		for address, name in missing:
			nexts = [boundary for boundary in boundaries if boundary > address]
			end = nexts[0] if nexts else address
			entries.append({"address": address, "size": end - address, "mangled": name,
				"name": simple_name(name), "type": "t"})
	# A PE built by GCC still uses Itanium names; MSVC decorations are handled by simple_name.
	itanium = [entry["mangled"] for entry in entries if entry["mangled"].startswith("_Z")]
	if itanium:
		table = dict(zip(sorted(set(itanium)), demangle(sorted(set(itanium)))))
		for entry in entries:
			if entry["mangled"]:
				entry["name"] = simple_name(table.get(entry["mangled"], entry["mangled"]))
	entries.sort(key=lambda entry: entry["address"])
	return entries


def symbol_units(names):
	"""Named addresses -> units, each running to the next name. A merged `.rdata` pool or a
	tail-padded function makes this wrong at the edges; it is still the boundary the file
	names, and better than no boundary at all."""
	addresses = sorted(names)
	entries = []
	for index, address in enumerate(addresses):
		end = addresses[index + 1] if index + 1 < len(addresses) else address
		name = names[address]
		entries.append({"address": address, "size": max(0, end - address), "mangled": name,
			"name": name, "type": "t"})
	return [entry for entry in entries if entry["size"]]


def simple_name(demangled):
	"""`CMathTests::AbsDiff(int, int)` -> `CMathTests::AbsDiff`."""
	text = demangled
	if text.startswith("?"):
		return msvc_simple_name(text)
	text = re.sub(r"\s+(const|noexcept|volatile)\b.*$", "", text)
	paren = text.find("(")
	if paren > 0:
		text = text[:paren]
	return text.strip()


def name_index(entries):
	index = {}
	for entry in entries:
		index.setdefault(simple_name(entry["name"]), []).append(entry)
	return index


# --------------------------------------------------------------------------------------
# the answer key: unit markers in the source + symbols in the unstripped binary


def parse_units():
	"""Returns [{id, level, tags, symbol_hint, file, line, qualified}] for every DA-UNIT."""
	units = []
	for source in SOURCES:
		path = SOURCE_DIR / source
		lines = path.read_text().splitlines()
		for position, line in enumerate(lines):
			match = UNIT_MARKER.search(line)
			if not match:
				continue
			header = ""
			header_line = position + 2
			for follow in range(position + 1, min(position + 12, len(lines))):
				candidate = lines[follow].strip()
				if not candidate or candidate.startswith("//"):
					continue
				header = candidate
				header_line = follow + 1
				break
			qualified = None
			member = DEF_MEMBER.match(header)
			if member:
				qualified = "%s::%s" % (member.group(1), member.group(2))
			else:
				free = DEF_FREE.match(header)
				if free:
					qualified = free.group(1)
			units.append({
				"id": match.group("id"),
				"level": match.group("level"),
				"tags": [t for t in (match.group("tags") or "").split(",") if t],
				"symbol_hint": match.group("sym"),
				"file": source,
				"line": position + 1,
				"decl_line": header_line,
				"qualified": qualified,
				"header": header,
			})
	return units


def build_answer_key(variant, config):
	"""Matches every unit marker to a real symbol. Writes answer_key.json + task_list.json."""
	out_dir = BUILD_DIR / variant
	binary = out_dir / "da_tests"
	entries = symbols(binary)
	index = name_index(entries)
	units = parse_units()
	resolved, unresolved, ambiguous = [], [], []
	for unit in units:
		hint = unit["symbol_hint"]
		candidates = []
		if hint:
			candidates = [e for e in entries if e["mangled"] == hint or simple_name(e["name"]) == hint]
		else:
			qualified = unit["qualified"]
			if not qualified:
				unresolved.append((unit["id"], "no definition header found after the marker"))
				continue
			for key, found in index.items():
				if key == qualified or key.split("::")[-1] == qualified and "::" not in qualified:
					candidates = found
					break
		if len(candidates) == 0:
			unresolved.append((unit["id"], "no symbol for %s" % (unit["qualified"] or "?")))
			continue
		if len(candidates) > 1:
			ambiguous.append((unit["id"], [c["name"] for c in candidates]))
			continue
		entry = candidates[0]
		resolved.append({
			"id": unit["id"],
			"level": unit["level"],
			"tags": unit["tags"],
			"file": unit["file"],
			"line": unit["line"],
			"address": entry["address"],
			"size": entry["size"],
			"mangled": entry["mangled"],
			"name": entry["name"],
			"signature": unit["header"],
		})

	unit_addresses = {u["address"] for u in resolved}
	# Anything else defined by our sources is "harness" (drivers, helpers, entry point);
	# the rest is CRT/libstdc++ startup. Both stay in the task list - the model has to
	# tell them apart by itself - the answer key just records which is which.
	ours = set()
	for source in SOURCES:
		text = (SOURCE_DIR / source).read_text()
		ours.update(re.findall(r"\b(CMathTests|CStringTests|CStructTests|CSelfTest|CCaseScope)\b", text))
		for line in text.splitlines():
			member = DEF_MEMBER.match(line)
			if member:
				ours.add("%s::%s" % (member.group(1), member.group(2)))
				continue
			free = DEF_FREE.match(line)
			if free:
				ours.add(free.group(1))
	other = []
	for entry in entries:
		if entry["address"] in unit_addresses or entry["size"] == 0:
			continue
		simple = simple_name(entry["name"])
		kind = "harness" if (simple in ours or simple.split("::")[0] in ours) else "runtime"
		other.append({"address": entry["address"], "size": entry["size"], "name": entry["name"], "kind": kind})

	resolved.sort(key=lambda u: u["address"])
	answer = {
		"variant": variant,
		"binary": str(binary),
		"units": resolved,
		"other_symbols": other,
	}
	(out_dir / "answer_key.json").write_text(json.dumps(answer, indent=1) + "\n")

	# The task list is what the model gets: the same addresses, no names, no tags.
	task = [{"address": hex(u["address"]), "size": u["size"]} for u in resolved]
	(out_dir / "task_list.json").write_text(json.dumps(task, indent=1) + "\n")
	if unresolved or ambiguous or len(units) != len(resolved):
		print("unit matching problems:")
		for item in unresolved:
			print("  unresolved %s: %s" % item)
		for item in ambiguous:
			print("  ambiguous %s: %s" % item)
	print("answer key: %d units (%d markers in source), %d other symbols" % (len(resolved), len(units), len(other)))
	return answer


# --------------------------------------------------------------------------------------
# disassembly + normalisation


def disassemble(binary, address, size, section_hint=None):
	"""Instructions of one function. section_hint is the mangled name, needed when the
	object was built with -ffunction-sections and every function has its own section."""
	out = sh([
		"objdump", "-dr", "--no-show-raw-insn",
		"--start-address=0x%x" % address, "--stop-address=0x%x" % (address + size), str(binary),
	])
	return parse_objdump(out, section_hint)


def parse_objdump(text, section_hint=None):
	instructions = []
	wanted_section = True
	for line in text.splitlines():
		header = re.match(r"^Disassembly of section ([^:]+):", line)
		if header:
			name = header.group(1)
			# in a .o every section is addressed from 0, so a plain address range hits
			# several of them: keep only the one that holds the function
			if name == ".text":
				wanted_section = True
			elif section_hint and name in (".text." + section_hint, ".text.unlikely." + section_hint):
				wanted_section = True
			else:
				wanted_section = False
			continue
		if not wanted_section:
			continue
		# objdump -dr prints the relocation right after the instruction it applies to
		reloc = re.match(r"^\s+([0-9a-f]+):\s+(R_[A-Z0-9_]+)\s+(.*)$", line)
		if reloc and instructions:
			instructions[-1]["reloc"] = reloc.group(3).strip()
			continue
		match = re.match(r"^\s+([0-9a-f]+):\t(.*)$", line)
		if not match:
			continue
		address = int(match.group(1), 16)
		body = match.group(2).split("#")[0].strip()
		comment = match.group(2).split("#", 1)[1].strip() if "#" in match.group(2) else ""
		if not body:
			continue
		parts = body.split(None, 1)
		mnemonic = parts[0]
		operands = parts[1] if len(parts) > 1 else ""
		instructions.append({"address": address, "mnemonic": mnemonic, "operands": operands, "comment": comment, "reloc": ""})
	return instructions


RE_ABS = re.compile(r"0x[0-9a-f]{4,}\b")


class Reference:
	"""Name resolution for the original side: addresses from the unstriapped symbol table."""

	def __init__(self, entries):
		self.by_address = {e["address"]: e for e in entries}
		self.entries = entries

	def resolve(self, address):
		entry = self.by_address.get(address)
		if entry:
			return simple_name(entry["name"])
		best = None
		for candidate in self.entries:
			if candidate["address"] <= address and (best is None or candidate["address"] > best["address"]):
				best = candidate
		if best:
			return "%s+0x%x" % (simple_name(best["name"]), address - best["address"])
		return "abs:0x%x" % address


_demangle_cache = {}


def clean_symbol(text):
	"""`_ZN10CMathTests8AbsDiffEii+0x15` or `strlen@plt` -> `CMathTests::AbsDiff`."""
	name = re.sub(r"\+0x[0-9a-f]+$", "", text).strip()
	name = name.replace("@plt", "").replace("@PLT", "")
	if name.startswith("_Z"):
		if name not in _demangle_cache:
			_demangle_cache[name] = simple_name(demangle([name])[0] if demangle([name]) else name)
		return _demangle_cache[name]
	return name


def normalize(instructions, base, reference=None, register_abstract=False):
	"""One token per instruction: mnemonic + operands, addresses turned into names.

	Branch targets become function-relative labels and data references become DATA<n>
	tokens (the resolved names are reported separately), so a different link layout does
	not read as a code difference.
	"""
	tokens = []
	reg_map = {}
	data_tokens = {}
	data_names = []

	def data_token(name):
		if name not in data_tokens:
			data_tokens[name] = "DATA%d" % len(data_tokens)
			data_names.append(name)
		return data_tokens[name]

	for instruction in instructions:
		mnemonic = instruction["mnemonic"]
		operands = instruction["operands"]
		comment = instruction["comment"]

		# branches first: labels are relative, so a moved function does not look changed
		branch = re.match(r"^(j[a-z]*|loop[a-z]*)\s+([0-9a-f]+)\s*(<.*>)?$", mnemonic + " " + operands)
		if branch:
			target = branch.group(2)
			try:
				target = "L%x" % (int(branch.group(2), 16) - base)
			except ValueError:
				pass
			tokens.append("%s %s" % (branch.group(1), target))
			continue

		# calls: keep the callee name, whatever form the linker left it in
		call = re.match(r"^(call\w*|jmp)\s+(.*)$", mnemonic + " " + operands)
		if call:
			pick = None
			if instruction.get("reloc"):
				symbol = re.match(r"([A-Za-z_.$][\w.$]*)", instruction["reloc"])
				if symbol and not symbol.group(1).startswith("SECTION"):
					tokens.append("%s %s" % (call.group(1), clean_symbol(symbol.group(1))))
					continue
			pick = re.search(r"<([^>]+)>", comment) or re.search(r"<([^>]+)>", call.group(2))
			name = pick.group(1) if pick else None
			if name is None:
				pick = re.match(r"([A-Za-z_.$][\w.$]*)", call.group(2))
				name = pick.group(1) if pick else None
			if name is not None and re.fullmatch(r"[0-9a-f]+", name):
				name = reference.resolve(int(name, 16)) if reference else "0x" + name
			elif name is not None:
				name = clean_symbol(name)
			if name is not None:
				tokens.append("%s %s" % (call.group(1), name))
				continue

		# rip-relative data: objdump names the target in the comment
		rip = re.search(r"(?:([0-9a-f]+))\(%rip\)", operands)
		if rip:
			pick = re.search(r"<([^>]+)>", comment)
			if instruction.get("reloc"):
				symbol = re.match(r"([A-Za-z_.$][\w.$<>-]*)", instruction["reloc"])
				if symbol:
					name = clean_symbol(re.sub(r"-0x[0-9a-f]+$", "", symbol.group(1)))
				else:
					name = clean_symbol(pick.group(1)) if pick else ("abs:" + rip.group(1))
			else:
				name = clean_symbol(pick.group(1)) if pick else ("abs:" + rip.group(1))
			tokens.append(operands.replace(rip.group(0), data_token(name) + "(%rip)"))
			continue

		# non-RIP (32-bit style) data references: the relocation names the object
		reloc_name = instruction.get("reloc") or ""
		symbol = re.match(r"([A-Za-z_.$][\w.$]*)", reloc_name)
		if symbol and re.match(r"^(\.L|\.rodata|\.data|\.bss|_ZTV|_ZTI|_ZTS)", symbol.group(1)):
			name = clean_symbol(re.sub(r"[-+](0x)?[0-9a-f]+$", "", symbol.group(1)))
			operands = re.sub(r"(?<![\w$])\$?0x[0-9a-f]+", data_token(name), operands)

		# absolute data references in the original binary -> names from the answer key
		if reference:
			def replace(match):
				return data_token(reference.resolve(int(match.group(0), 16)))

			operands = re.sub(r"(?<!\$)\b0x[0-9a-f]{4,}\b", replace, operands)

		if register_abstract:
			def abstract(match):
				reg = match.group(0)
				if reg not in reg_map:
					reg_map[reg] = "R%d" % len(reg_map)
				return reg_map[reg]

			operands = re.sub(r"\b(e[a-d]x|[a-d][sl][pi]|r[abcd]x|r\d+[wdb]?|sip|dil|sil|bpl|spl|xmm\d+)\b", abstract, operands)
		tokens.append((mnemonic + " " + operands).strip())
	normalize.data_names = data_names
	return tokens


def score_tokens(original, candidate):
	matcher = difflib.SequenceMatcher(None, original, candidate, autojunk=False)
	match = sum(block.size for block in matcher.get_matching_blocks())
	denominator = max(len(original), len(candidate), 1)
	ratio = 100.0 * match / denominator
	diff = []
	categories = {"opcode": 0, "operand": 0, "missing": 0, "extra": 0}
	for tag, i1, i2, j1, j2 in matcher.get_opcodes():
		if tag == "equal":
			continue
		if tag == "replace":
			for a, b in zip(original[i1:i2], candidate[j1:j2]):
				op_a, _, rest_a = a.partition(" ")
				op_b, _, rest_b = b.partition(" ")
				if op_a == op_b:
					categories["operand"] += 1
				else:
					categories["opcode"] += 1
				diff.append({"kind": tag, "original": a, "candidate": b})
		elif tag == "delete":
			categories["missing"] += len(original[i1:i2])
			for a in original[i1:i2]:
				diff.append({"kind": tag, "original": a, "candidate": None})
		elif tag == "insert":
			categories["extra"] += len(candidate[j1:j2])
			for b in candidate[j1:j2]:
				diff.append({"kind": tag, "original": None, "candidate": b})
	return {
		"match_percent": round(ratio, 2),
		"original_instructions": len(original),
		"candidate_instructions": len(candidate),
		"size_delta_instructions": len(candidate) - len(original),
		"identical": original == candidate,
		"categories": categories,
		"diff": diff,
	}


# --------------------------------------------------------------------------------------
# commands


def compile_source(compiler, flags, source, output):
	if is_msvc(compiler):
		# A bare `/home/…/x.cpp` reads as an option to cl, so the language is named (the same
		# rule decomp.toolchain.driver_form follows).
		sh([compiler] + flags + ["/c",
			("/Tc" if str(source).endswith(".c") else "/Tp") + str(source), "/Fo%s" % output],
			timeout=BUILD_TIMEOUT)
		return
	sh([compiler] + flags + ["-c", str(source), "-o", str(output)], timeout=BUILD_TIMEOUT)


def include_flags(compiler, directories):
	"""The include-path arguments for this driver (`-I` vs `/I`; cl reads `-I` as an option
	too, but spelling it the driver's own way keeps the command line copy-pasteable)."""
	flag = "/I" if is_msvc(compiler) else "-I"
	return [x for directory in directories for x in (flag, str(directory))]


def link_binary(compiler, flags, objects, linkflags, binary):
	"""Link the benchmark. `cl` names the output with /Fe and passes the rest to the linker
	after /link; a gcc driver uses -o (Docs/MSVC-Plan.md §7, MS-2)."""
	if is_msvc(compiler):
		# /MAP is not in the config on purpose: the answer key needs the map next to the
		# binary it describes, and only this function knows where that is.
		sh([compiler] + ["/Fe:%s" % binary] + [str(o) for o in objects] +
			["/link", "/MAP:%s.map" % binary] + linkflags, timeout=BUILD_TIMEOUT)
		return
	sh([compiler] + flags + [str(o) for o in objects] + linkflags + ["-o", str(binary)],
		timeout=BUILD_TIMEOUT)


def cmd_build(config, variants, capture=True):
	for variant in variants:
		compiler, flags, linkflags = variant_flags(config, variant)
		out_dir = BUILD_DIR / variant
		out_dir.mkdir(parents=True, exist_ok=True)
		objects = []
		for source in SOURCES:
			object_path = out_dir / (Path(source).stem + ".o")
			print("  %s %s" % (variant, source))
			# Only the top source directory goes on the include path, even though the sources
			# under TestFunctions/ are named "math.h", "strings.h", "structs.h": every include
			# of a sibling is quoted and resolves next to the including file. Listing
			# TestFunctions/ too makes `cl` find TestFunctions/math.h for the C runtime's own
			# <math.h> - a driver that searches the -I directories for angle brackets, unlike
			# GCC, whose <cmath> escapes them with #include_next - and the CRT headers then
			# fail on their own using-declarations (cstdlib: "'fabs' is not a member of
			# '`global namespace``'").
			compile_source(compiler, flags + include_flags(compiler, [SOURCE_DIR]),
				SOURCE_DIR / source, object_path)
			objects.append(object_path)
		binary = out_dir / "da_tests"
		link_binary(compiler, flags, objects, linkflags, binary)
		if not binary.exists() and Path(str(binary) + ".exe").exists():
			# A Windows toolchain adds the .exe suffix to an extension-less output name (MinGW's
			# ld does; `cl /Fe:` does not). This harness names the reference binary one way.
			Path(str(binary) + ".exe").rename(binary)
		stripped = out_dir / "da_tests.stripped"
		if is_pe(binary):
			# A PE from `link` has no symbol table to strip and `strip` would only rewrite the
			# file, so the two names hold the same bytes by construction. The check below still
			# runs, because the answer key addresses have to stay valid either way.
			stripped.write_bytes(binary.read_bytes())
		else:
			sh(["strip", "--strip-all", str(binary), "-o", str(stripped)])
		# strip must not move anything: the answer key addresses have to stay valid
		original_text = sh(["objdump", "-s", "--section=.text", str(binary)], binary=False)
		stripped_text = sh(["objdump", "-s", "--section=.text", str(stripped)], binary=False)
		if original_text.split("\n", 2)[2:] != stripped_text.split("\n", 2)[2:]:
			raise RuntimeError("%s: .text differs after strip, addresses are not reusable" % variant)
		try:
			compiler_version = sh([compiler, "--version"] if not is_msvc(compiler) else [compiler, "/Bv", "/c"])
		except RuntimeError as exc:  # cl /Bv exits non-zero: it has no source file, and that is fine
			compiler_version = str(exc)
		build_info = {
			"variant": variant,
			"compiler": (compiler_version.strip().splitlines() or [""])[0],
			"flags": flags,
			"binary": str(binary),
			"stripped": str(stripped),
			"comment_section": (sh(["readelf", "-p", ".comment", str(binary)], binary=False).strip()
				if not is_pe(binary) else ""),
		}
		(out_dir / "build.json").write_text(json.dumps(build_info, indent=1) + "\n")
		build_answer_key(variant, config)
		if capture:
			try:
				cmd_goldens(variant, config)
			except (RuntimeError, FileNotFoundError) as exc:
				print("  warning: no goldens for %s (%s) - link it statically if you want them" % (variant, exc))
	print("built: %s" % ", ".join(variants))


def cmd_goldens(variant, config):
	out_dir = BUILD_DIR / variant
	binary = out_dir / "da_tests"
	text = sh(runner(binary) + ["--golden"])
	(out_dir / "goldens.jsonl").write_text(text)
	cases = len([line for line in text.splitlines() if line.strip()])
	print("goldens: %d cases -> %s" % (cases, out_dir / "goldens.jsonl"))


def cmd_selfcheck(variant, config):
	binary = BUILD_DIR / variant / "da_tests"
	out = sh(runner(binary))
	print(out.strip())
	return 0 if " 0 failures" in out else 1


def extract_candidate_function(object_path, wanted):
	entries = symbols(object_path)
	found = []
	for entry in entries:
		if entry["size"] == 0:
			continue
		simple = simple_name(entry["name"])
		if simple == wanted or simple.split("::")[-1] == wanted or entry["mangled"] == wanted:
			found.append(entry)
	if not found:
		raise RuntimeError("no symbol matching %r in %s; candidates: %s" % (wanted, object_path.name,
			", ".join(sorted({simple_name(e["name"]) for e in entries if e["size"]})[:40])))
	if len(found) > 1:
		raise RuntimeError("%r is ambiguous: %s" % (wanted, ", ".join(e["name"] for e in found)))
	return found[0]


def score_candidate(variant, unit_id, source, wanted, config, register_abstract=False, show=12):
	out_dir = BUILD_DIR / variant
	answer = json.loads((out_dir / "answer_key.json").read_text())
	unit = next((u for u in answer["units"] if u["id"] == unit_id), None)
	if unit is None:
		raise RuntimeError("unit %s is not in the answer key for %s" % (unit_id, variant))
	compiler, flags, _link = variant_flags(config, variant)
	candidate_object = out_dir / ("candidate_%s.o" % re.sub(r"\W", "_", wanted))
	compile_source(compiler, flags + ["-I", str(SOURCE_DIR), "-I", str(SOURCE_DIR / "TestFunctions"),
		"-I", str(source.parent)], source, candidate_object)
	entry = extract_candidate_function(candidate_object, wanted)

	reference = Reference(symbols(out_dir / "da_tests"))
	original_insns = disassemble(out_dir / "da_tests.stripped", unit["address"], unit["size"], unit["mangled"])
	candidate_insns = disassemble(candidate_object, entry["address"], entry["size"], entry["mangled"])
	original = normalize(original_insns, unit["address"], reference, register_abstract)
	candidate = normalize(candidate_insns, entry["address"], None, register_abstract)
	result = score_tokens(original, candidate)
	result["original_data_references"] = getattr(normalize, "data_names", [])
	result.update({
		"unit": unit_id,
		"unit_name": unit["name"],
		"candidate_name": entry["name"],
		"candidate_source": str(source),
		"variant": variant,
		"threshold": config["threshold"],
		"passed": result["match_percent"] >= config["threshold"] and result["categories"]["opcode"] == 0,
	})
	print("%s vs %s  %s" % (unit_id, unit["name"], variant))
	print("  match %.2f%% (threshold %.0f%%) %s" % (result["match_percent"], config["threshold"],
		"PASS" if result["passed"] else "FAIL"))
	print("  instructions: original %d, candidate %d (%+d)  categories: %s" % (
		result["original_instructions"], result["candidate_instructions"],
		result["size_delta_instructions"], result["categories"]))
	for item in result["diff"][:show]:
		print("    - %s" % item["original"])
		print("    + %s" % item["candidate"])
	if len(result["diff"]) > show:
		print("    ... %d more differing lines" % (len(result["diff"]) - show))
	return result


def cmd_crosscheck(config, variants):
	"""Behaviour must not depend on the flags/arch used to build the reference.

	A mismatch here means the benchmark has undefined or input-dependent behaviour in it,
	which would make every byte score downstream meaningless - so it is checked first.
	"""
	traces = {}
	for variant in variants:
		path = BUILD_DIR / variant / "goldens.jsonl"
		if not path.exists():
			print("%s: no goldens (build it)" % variant)
			continue
		records = {}
		for line in path.read_text().splitlines():
			if line.strip():
				record = json.loads(line)
				records[(record["id"], record["case"])] = record
		traces[variant] = records
	names = list(traces)
	if len(names) < 2:
		print("need at least two variants with goldens")
		return 1
	def arch_of(variant):
		info = BUILD_DIR / variant / "build.json"
		if not info.exists():
			return "?"
		return json.loads(info.read_text()).get("variant", variant).split("-x86")[-1] and (
			"x86" if variant.endswith("-x86") else "x86-64")

	base = names[0]
	differences = 0
	for other in names[1:]:
		same_arch = arch_of(base) == arch_of(other)
		print("%s vs %s (%s): %d cases" % (base, other, "same arch" if same_arch else "different arch", len(traces[base])))
		keys = sorted(set(traces[base]) | set(traces[other]))
		for key in keys:
			left, right = traces[base].get(key), traces[other].get(key)
			if left is None or right is None:
				print("  %s vs %s: %s #%d present in only one build" % (base, other, key[0], key[1]))
				differences += 1
			elif left["out"] != right["out"]:
				# float results legitimately differ between the x87 and SSE code paths,
				# so only a same-arch difference is a real problem (UB, or an
				# uninitialised padding byte inside a hashed struct).
				label = "MISMATCH" if same_arch else "cross-arch difference (expected)"
				print("  %s %s #%d: %s != %s" % (label, key[0], key[1], left["out"], right["out"]))
				if same_arch:
					differences += 1
	print("crosscheck: %d differing cases across %d variants" % (differences, len(names)))
	return 1 if differences else 0


def cmd_self(config, variants, register_abstract=False):
	"""Calibration: compile the untouched original source again and score it as a candidate."""
	for variant in variants:
		compiler, flags, linkflags = variant_flags(config, variant)
		out_dir = BUILD_DIR / variant
		answer = json.loads((out_dir / "answer_key.json").read_text())
		results = []
		for unit in answer["units"]:
			source = SOURCE_DIR / unit["file"]
			object_path = out_dir / ("self_%s.o" % unit["id"].lower())
			compile_source(compiler, flags + ["-I", str(SOURCE_DIR), "-I", str(SOURCE_DIR / "TestFunctions")],
				source, object_path)
			entry = extract_candidate_function(object_path, unit["mangled"])
			reference = Reference(symbols(out_dir / "da_tests"))
			original = normalize(disassemble(out_dir / "da_tests.stripped", unit["address"], unit["size"],
					unit["mangled"]), unit["address"], reference, register_abstract)
			original_data = list(getattr(normalize, "data_names", []))
			candidate = normalize(disassemble(object_path, entry["address"], entry["size"], entry["mangled"]),
				entry["address"], None, register_abstract)
			result_data = list(getattr(normalize, "data_names", []))
			result = score_tokens(original, candidate)
			result["unit"] = unit["id"]
			results.append(result)
		scores = [r["match_percent"] for r in results]
		perfect = sum(1 for r in results if r["identical"])
		passed = sum(1 for r in results if r["match_percent"] >= config["threshold"] and r["categories"]["opcode"] == 0)
		print("%s: %d units, mean %.1f%%, byte-identical after normalise %d, above threshold %d" % (
			variant, len(results), sum(scores) / max(1, len(scores)), perfect, passed))
		weak = sorted(results, key=lambda r: r["match_percent"])[:5]
		for item in weak:
			if item["match_percent"] < 100.0:
				print("  weakest %s %.1f%% %s" % (item["unit"], item["match_percent"], item["categories"]))
		(out_dir / "self_scores.json").write_text(json.dumps(results, indent=1) + "\n")


def cmd_report(config, variants):
	for variant in variants:
		answer = json.loads((BUILD_DIR / variant / "answer_key.json").read_text())
		units = answer["units"]
		by_tag, by_level = {}, {}
		for unit in units:
			by_level[unit["level"]] = by_level.get(unit["level"], 0) + 1
			for tag in unit["tags"]:
				by_tag[tag] = by_tag.get(tag, 0) + 1
		sizes = sorted(u["size"] for u in units)
		buckets = {"<32": 0, "32-63": 0, "64-127": 0, "128-255": 0, ">=256": 0}
		for size in sizes:
			if size < 32:
				buckets["<32"] += 1
			elif size < 64:
				buckets["32-63"] += 1
			elif size < 128:
				buckets["64-127"] += 1
			elif size < 256:
				buckets["128-255"] += 1
			else:
				buckets[">=256"] += 1
		print("%s: %d units, %d bytes of unit code" % (variant, len(units), sum(sizes)))
		print("  levels: %s" % by_level)
		print("  size buckets: %s  median %d" % (buckets, sizes[len(sizes) // 2]))
		print("  tags: " + ", ".join("%s:%d" % kv for kv in sorted(by_tag.items(), key=lambda kv: -kv[1])))


def main(argv=None):
	parser = argparse.ArgumentParser(prog="eval.py", description=__doc__.splitlines()[0])
	parser.add_argument("command", choices=["build", "selfcheck", "self", "try", "goldens", "report", "units", "crosscheck"])
	parser.add_argument("--variant", default="gcc-o0")
	parser.add_argument("--variants", default="", help="comma separated, for build/self/report")
	parser.add_argument("--unit", help="unit id from answer_key.json, e.g. MATH-01")
	parser.add_argument("--src", type=Path, help="candidate source file")
	parser.add_argument("--fn", help="candidate symbol or function name to score")
	parser.add_argument("--register-abstract", action="store_true")
	parser.add_argument("--show", type=int, default=12)
	args = parser.parse_args(argv)

	config = load_config()
	variants = [v.strip() for v in args.variants.split(",") if v.strip()] or [args.variant]

	if args.command == "build":
		cmd_build(config, variants if args.variants else [args.variant])
	elif args.command == "goldens":
		cmd_goldens(args.variant, config)
	elif args.command == "selfcheck":
		return cmd_selfcheck(args.variant, config)
	elif args.command == "self":
		cmd_self(config, variants)
	elif args.command == "crosscheck":
		return cmd_crosscheck(config, variants)
	elif args.command == "report":
		cmd_report(config, variants if args.variants else [args.variant])
	elif args.command == "units":
		answer = json.loads((BUILD_DIR / args.variant / "answer_key.json").read_text())
		for unit in answer["units"]:
			print("%-11s %-6s %5d  %s" % (unit["id"], unit["level"], unit["size"], unit["name"]))
	elif args.command == "try":
		if not (args.unit and args.src and args.fn):
			parser.error("try needs --unit, --src and --fn")
		score_candidate(args.variant, args.unit, args.src, args.fn, config,
			args.register_abstract, args.show)
	return 0


if __name__ == "__main__":
	sys.exit(main())
