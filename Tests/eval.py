"""Build, describe and score the TestBinary benchmark.

This is the harness that judges the decompilation loop, so it deliberately does not
depend on the decomp tool itself: everything here works with binutils + stdlib only.
The normalise/diff half is written to be lifted into decomp/normalize.py + decomp/diff.py
once those exist (see Docs/Design-Plan.md, Phase 2).

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
import subprocess
import sys
from pathlib import Path

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


def sh(args, cwd=None, binary=False):
	proc = subprocess.run(args, cwd=cwd, capture_output=True)
	out = proc.stdout.decode("utf-8", "replace") if binary else proc.stdout.decode(errors="replace")
	err = proc.stderr.decode(errors="replace")
	if proc.returncode != 0:
		raise RuntimeError("command failed (%d): %s\n%s" % (proc.returncode, " ".join(map(str, args)), err or out))
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
	return compiler, ["-std=%s" % config["std"], "-O%d" % variant.get("optimize", 0), "-Wall", "-Wextra"] + arch + extra, link


# --------------------------------------------------------------------------------------
# symbol tables


def demangle(names):
	if not names:
		return []
	proc = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True)
	return proc.stdout.splitlines()


def symbols(binary):
	"""Every symbol with a size: [{address,size,mangled,name,type}] in address order."""
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


def simple_name(demangled):
	"""`CMathTests::AbsDiff(int, int)` -> `CMathTests::AbsDiff`."""
	text = demangled
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
	sh([compiler] + flags + ["-c", str(source), "-o", str(output)])


def cmd_build(config, variants, capture=True):
	for variant in variants:
		compiler, flags, linkflags = variant_flags(config, variant)
		out_dir = BUILD_DIR / variant
		out_dir.mkdir(parents=True, exist_ok=True)
		objects = []
		for source in SOURCES:
			object_path = out_dir / (Path(source).stem + ".o")
			print("  %s %s" % (variant, source))
			compile_source(compiler, flags + ["-I", str(SOURCE_DIR), "-I", str(SOURCE_DIR / "TestFunctions")],
				SOURCE_DIR / source, object_path)
			objects.append(object_path)
		binary = out_dir / "da_tests"
		sh([compiler] + flags + [str(o) for o in objects] + linkflags + ["-o", str(binary)])
		stripped = out_dir / "da_tests.stripped"
		sh(["strip", "--strip-all", str(binary), "-o", str(stripped)])
		# strip must not move anything: the answer key addresses have to stay valid
		original_text = sh(["objdump", "-s", "--section=.text", str(binary)], binary=False)
		stripped_text = sh(["objdump", "-s", "--section=.text", str(stripped)], binary=False)
		if original_text.split("\n", 2)[2:] != stripped_text.split("\n", 2)[2:]:
			raise RuntimeError("%s: .text differs after strip, addresses are not reusable" % variant)
		build_info = {
			"variant": variant,
			"compiler": sh([compiler, "--version"]).splitlines()[0],
			"flags": flags,
			"binary": str(binary),
			"stripped": str(stripped),
			"comment_section": sh(["readelf", "-p", ".comment", str(binary)], binary=False).strip(),
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
	text = sh([str(binary), "--golden"])
	(out_dir / "goldens.jsonl").write_text(text)
	cases = len([line for line in text.splitlines() if line.strip()])
	print("goldens: %d cases -> %s" % (cases, out_dir / "goldens.jsonl"))


def cmd_selfcheck(variant, config):
	binary = BUILD_DIR / variant / "da_tests"
	out = sh([str(binary)])
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
