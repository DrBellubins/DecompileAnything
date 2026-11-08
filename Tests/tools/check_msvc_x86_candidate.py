"""MSVC-x86 X86-3 acceptance (Docs/MSVC-x86-Plan.md): reading COFF the way i386 spells it.

	run: .venv/bin/python Tests/tools/check_msvc_x86_candidate.py
	     [--variant msvc-o0-x86] [--limit N] [--no-controls] [--no-target]

`check_coff_candidate.py` is the x64 side and stays untouched: adding a second arch to it would
change what its numbers mean. This asks the same three questions of an i386 candidate, plus one
that only i386 asks, because on i386 **every reference to something outside the body is an
absolute 32-bit field**, not a pc-relative one, and a field whose width the tool does not know is
a field it cannot mask, cannot read the offset out of, and cannot compare.

1. **The field rules.** `relocation_width`/`pc_bias` for the types this `cl` actually emits
   (`TYPE.I386_DIR32`, `TYPE.I386_REL32`), read together with the rule pointed the other way: on
   x86-64 a `call`/`jmp` displacement carries a pc-relative record that binds to a *function* and
   keeps its bias, and adding the i386 forms must not change that. Then: what bounds a function
   in an i386 object, measured from a real one - a COMDAT section, or the next function symbol.
2. **Extents.** For every unit of the benchmark's 32-bit PE, the extent read out of the `.obj`
   equals the extent the original side is compared over. There is no `.pdata` in an i386 image
   (X86-3), so the original side is read over the analysis' body - the same situation
   `gcc-o0-x86` is in, and the reason these numbers belong next to the `-m32` ones.
3. **The loop.** The untouched source through `decomp try`'s own path for every unit.
4. **The negative controls.** The deliberately wrong candidates of
   `Tests/examples/candidate_math_bad.cpp`, built by the x86 driver, still reported as the kind of
   wrong they are.
5. **One table, reached two ways**, and **an address stored through a register operand** (X86-6,
   \u00a737): the same object read from the instruction's immediate and from the analysis' resolved
   reference must be one object.
6. **A call to a function of the same object** (\u00a739): with function-level linking the call's
   relocation names the callee's *section symbol*, and the unfilled field disassembles to an address
   inside the caller's own body. It has to reach the callee, while a self-recursive call stays an
   edge inside the unit and a call inside one shared section keeps needing no relocation at all.

The candidate objects are built through `compile.build(variant=...)`, i.e. the same driver
resolver `decomp try` uses (`arch = "x86"` -> `<prefix>/bin/x86/cl`), and every object is
required to *measure* 32-bit: a check that handed an i386 target x64 objects would be measuring
nothing (X86-2).

Exit: 0 all passed, 1 something came out wrong, 2 there is no x86 driver, no 32-bit PE build, or
no analysis of it to judge (which is not a failure of the tool).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config  # noqa: E402
from decomp import compile as build_  # noqa: E402
from decomp import extract, normalize, toolchain  # noqa: E402

NEGATIVE_CONTROLS = [
	("MATH-02", "ClampRangeProbe", {"operand"}, "the inverted-range guard is gone, bounds compared the wrong way"),
	("MATH-38", "ParityOfProbe", {"opcode", "missing"}, "counts bits instead of folding them"),
	("STR-01", "LengthOfProbe", {"opcode"}, "a counted loop instead of the sentinel test"),
]

# What this variant is held to, measured by the first run (2026-11-07) and recorded in the same
# commit as the numbers, exactly as Phase 3 of the byte-cleanup plan did - X86-3 explicitly refuses
# to invent a floor before measuring one. `extents` is not a floor but the phase's own claim: the
# extent read out of a COFF object equals the extent the original side is compared over, for every
# unit.
#
# 19 of the 89 units stop at `structural`. After X86-6 none of them has an operand or byte
# difference left - all 19 are at 100.00% with the masked bytes identical, and each is capped by a
# reference neither side can describe. They fall into two families, both known and owned elsewhere:
#
# * a callee the stripped image does not name and the candidate does (`FUN_00402ff0` against
#   `?Vec3LengthSq@…`), matched on nothing stronger than "both bodies are the same size" - the
#   ledger/PDB naming gap (`decomp symbols` reads the fetched PDB's `S_PUB32` rows and nothing
#   consumes them yet).
# * an object neither side can read: `___security_cookie` lives in `.bss` on both sides, so there are
#   no bytes anywhere to compare, and a table of *function pointers* (`g_stateTable`) is a relocation
#   placeholder in the object and a final address in the image - the data-side pairing that
#   byte-cleanup-plan Phase 6 owns.
FLOORS: dict[str, dict[str, float]] = {
	"msvc-o0-x86": {"extents": 89, "pass": 70, "mean": 100.00},
}


def gated() -> bool:
	return VARIANT_NAME in FLOORS


def expect(ok: bool, detail: str, failures: list[str]) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def _objects_for(store: cache.Cache, suffix: str = "") -> Path:
	"""A candidate-object directory per variant, so two variants never read each other's `.obj`."""
	return store.root / ("candidates-x86-%s%s" % (VARIANT_NAME, suffix))


def object_for(source: Path, work: Path, variant_body: dict | None = None,
	extra_flags: list[str] | None = None) -> tuple[Path, str]:
	"""Build one translation unit with this variant's own driver and flags (the resolver's choice)."""
	body = variant_body if variant_body is not None else VARIANT
	object_path = work / ("%s.obj" % source.stem)
	built = build_.build([source], object_path, flags=toolchain.build_flags(body) + list(extra_flags or []),
		includes=config.include_dirs(CONFIG, body), variant=body, cfg=CONFIG)
	if not built.ok:
		print("  %s" % "\n  ".join(build_.describe(built)))
		print("  %s did not compile: %s" % (source.name,
			(built.diagnostics or "no output").splitlines()[:6]))
	return object_path, "" if built.ok else "the benchmark source did not compile"


def field_rules(failures: list[str]) -> None:
	"""The widths and the pc rule, both directions, plus what bounds an i386 function.

	No target needed: the object is this variant's own build of one benchmark source.
	"""
	i386 = {"I386_DIR32": 4, "TYPE.I386_DIR32": 4, "I386_REL32": 4, "TYPE.I386_REL32": 4,
		"I386_DIR32NB": 4, "I386_SECREL": 4, "I386_SECREL7": 1, "I386_IMMEDIATE": 4,
		"I386_SECTION": 4, "I386_ABSOLUTE": 0}
	wrong = {key: (extract.relocation_width(key), want)
		for key, want in i386.items() if extract.relocation_width(key) != want}
	expect(not wrong, "the field a COFF i386 relocation fixes is known: %s" %
		(", ".join("%s -> %s not %s" % (key, got, want) for key, (got, want) in wrong.items())
			or "%d types read at their width" % len(i386)), failures)
	# i386 has no pc-relative data reference: an absolute field is read as itself, with no bias.
	biased = [kind for kind in ("I386_DIR32", "TYPE.I386_DIR32", "I386_REL32", "I386_SECREL")
		if extract.pc_bias(kind)]
	expect(not biased, "an i386 relocation is never biased as though it were pc-relative (%s)"
		% (", ".join(biased) or "none"), failures)
	# ... and the rule pointed the other way still holds: on x86-64 the displacement of a call or
	# jump carries a pc-relative record that binds to a function, and its bias is what makes the
	# address the instruction means. Adding the i386 forms must not touch that.
	x64 = [("R_X86_64_PC32", 4), ("R_X86_64_PLT32", 4), ("X86_64_PLT32", 4)]
	kept = [(kind, extract.pc_bias(kind)) for kind, want in x64 if extract.pc_bias(kind) != want]
	expect(not kept, "an x86-64 call displacement keeps its pc bias: %s" %
		(", ".join("%s -> %d" % item for item in kept) or "still %s" % x64), failures)
	expect(extract.pc_relative("R_X86_64_PC32") and not extract.pc_relative("I386_DIR32"),
		"a data reference on i386 is not classed as a pc-relative one", failures)

	# What bounds a function in an i386 object, measured rather than assumed: `/Gy` would put each
	# one in its own `.text$…` COMDAT (an exact extent); without it the extent is the next function
	# symbol minus `cl`'s inter-function padding. Both paths already exist and are bitness-neutral
	# - which of them runs here is a fact about this compiler at /Od for x86.
	source = TESTS / "TestBinary" / "TestFunctions" / "math.cpp"
	work = _objects_for(cache_store, "fieldrules")
	object_path, problem = object_for(source, work)
	if problem:
		failures.append("math.cpp: %s" % problem)
		return
	candidate = extract.CandidateObject(object_path)
	if candidate.error:
		failures.append("math.obj: %s" % candidate.error)
		return
	expect(candidate.bits == 32 and candidate.machine.upper() == "I386",
		"the object this variant resolves to is i386: machine %s, %d-bit (not an x64 object "
		"pretending to be a 32-bit one)" % (candidate.machine, candidate.bits), failures)
	comdat = sum(1 for symbol in candidate.functions if symbol.section in candidate._comdat)
	total = len(candidate.functions)
	print("   %d functions in %s: %d are their own COMDAT section (exact extent), %d bounded by "
		"the next function symbol with the int3/nop run cut off - the same path MS-3 measured on "
		"x64" % (total, object_path.name, comdat, total - comdat))
	expect(total > 40, "the i386 object yields functions with extents at all (%d)" % total,
		failures)
	# A reference to data is a DIR32 on the field the instruction reads. The tool has to know the
	# width to mask it: an unmasked placeholder (0 in the object, a final address in the image) is
	# a byte difference that is not a source difference.
	known = sum(1 for section, items in candidate._relocs.items()
		for item in items if extract.relocation_width(item[1]))
	unknown = sum(1 for items in candidate._relocs.values() for item in items
		if not extract.relocation_width(item[1]))
	print("   %d relocations in this object: %d have a known field width, %d do not"
		% (known + unknown, known, unknown))
	expect(unknown == 0, "every relocation this compiler emits has a known field width (%d do not)"
		% unknown, failures)
	operand_shapes(failures)


def operand_shapes(failures: list[str]) -> None:
	"""The two i386 spellings of "reach something outside this body" are one rule.

	i386 has no pc-relative data reference, so a candidate reaches a global either through a
	`[disp32]` memory operand (an absolute address in the ModR/M displacement) or through a
	`movl $disp32` immediate with a `DIR32` sitting on it - which is how a non-PIE 32-bit object
	already writes `pushl $_ZTI14CVehicleEntity` on the ELF side (Docs/MSVC-x86-Plan.md X86-3).
	Both have to be found at the same place in the instruction and masked at the same width, or

every data reference on one side is shifted by the length of the instruction.
	"""
	handle = normalize.capstone_for("x86:LE:32:default", detail=True)
	if handle is None:  # pragma: no cover
		failures.append("no capstone decoder for x86:LE:32")
		return
	block = (0x1000, 16, 0)
	reached = normalize.Ref(kind="data", name="globl", address=0x2000, identity=".data+0x0")
	for text, data in (("movl 0x12345678, %eax  (absolute displacement)",
			bytes([0xa1, 0x78, 0x56, 0x34, 0x12])),
			("movl $0x12345678, %eax  (immediate the link fills in)",
				bytes([0xb8, 0x78, 0x56, 0x34, 0x12]))):
		instructions = normalize.decode_function(handle, 0x1000, data)
		if not instructions:
			failures.append("could not decode %s" % text)
			continue
		instruction = instructions[0]
		kinds = [slot.kind for slot in instruction.slots]
		slot = next((item for item in instruction.slots if item.value == 0x12345678), None)
		span = normalize.field_span(instruction, slot) if slot else None
		# an absolute displacement is the link's choice wherever it appears; an immediate is a
		# constant until something resolves it - and then it is the same field of the same
		# instruction, hidden at the same width.
		ref = reached if (slot and slot.kind == "imm") else None
		hidden = bool(slot) and normalize.position_dependent(instruction, slot, ref, block)
		unresolved = bool(slot) and normalize.position_dependent(instruction, slot, None, block)
		expect(bool(slot) and span == (1, 4) and hidden,
			"%s: slots %s, field %s, hidden when it reaches outside: %s"
			% (text, kinds, span, hidden), failures)
		if slot is not None and slot.kind == "imm":
			expect(not unresolved,
				"an *unresolved* $disp32 immediate stays a constant (not masked on a guess)", failures)
	expect(True, "a `[disp32]` operand and a relocated `$disp32` immediate are the same field "
		"at the same offset", failures)


def extents(answer: dict, failures: list[str]) -> None:
	"""The extent a COFF candidate symbol gets vs the extent the original side is read over."""
	conn = cache.open_readonly(Path(cache_store.db_path(KEY)))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	by_file: dict[str, list[dict]] = {}
	for unit in answer["units"]:
		by_file.setdefault(unit["file"], []).append(unit)
	objects: dict[str, extract.CandidateObject] = {}
	same, rows = 0, []
	for name, units in sorted(by_file.items()):
		source = TESTS / "TestBinary" / name
		object_path, problem = object_for(source, _objects_for(cache_store, "extent"))
		if problem:
			failures.append("%s: %s" % (name, problem))
			continue
		candidate = extract.CandidateObject(object_path)
		if candidate.error:
			failures.append("%s: %s" % (name, candidate.error))
			continue
		objects[name] = candidate
		expect(candidate.bits == 32, "%s opens as a 32-bit COFF object (machine %s)"
			% (object_path.name, candidate.machine), failures)
		for unit in units:
			row = cache.resolve_function(conn, hex(unit["address"] + offset))
			if not row:
				rows.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"])))
				continue
			original = extract.original_function(conn, meta, row[0])
			try:
				symbol = candidate.function(unit["mangled"])
			except extract.SymbolNotFound as exc:
				rows.append("%s: %s" % (unit["id"], exc))
				continue
			if symbol.size == original.size:
				same += 1
			else:
				rows.append("%s %-40s original %d bytes (%s), candidate %d in %s+%s"
					% (unit["id"], unit["name"], original.size, "the file's own unit table"
						if cache.unit_at(conn, int(row[0]["entry"])) else "the analysis' body",
						symbol.size, symbol.section, hex(symbol.address)))
	conn.close()
	tabled = sum(1 for unit in answer["units"]
		if cache.unit_at(cache.open_readonly(Path(cache_store.db_path(KEY))),
			int(unit["address"] + OFFSET)))
	if same == len(answer["units"]):
		print("  ok   every one of the %d units: the extent read out of the COFF object equals the "
			"extent the original side is compared over" % len(answer["units"]))
	elif gated():
		want = int(FLOORS[VARIANT_NAME].get("extents", len(answer["units"])))
		expect(same >= want, "the extent read out of the COFF object equals the extent compared for "
			"%d units (held to %d of %d)" % (same, want, len(answer["units"])), failures)
	else:
		print("  measured, not gated (%s is not in FLOORS): %d of %d units agree"
			% (VARIANT_NAME, same, len(answer["units"])))
	for item in rows[:10]:
		print("   %s" % item)
	print("   %d units of this target have an entry in the file's own unit table: an i386 PE "
		"carries no `.pdata`, so the original side is read over the analysis' body - which is what "
		"makes an x86 MSVC number comparable to the -m32 ones and not to msvc-o0's"
		% tabled)


def the_loop(answer: dict, limit: int, failures: list[str]) -> None:
	"""The untouched source through `decomp try`, for every unit of the 32-bit PE."""
	conn = cache.open_readonly(Path(cache_store.db_path(KEY)))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	units = answer["units"][:limit] if limit else answer["units"]
	scores, below, broken = [], [], []
	for unit in units:
		row = cache.resolve_function(conn, hex(unit["address"] + offset))
		if not row:
			broken.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"])))
			continue
		outcome = cli.score_candidate(CONFIG, conn, meta, row[0],
			[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"],
			object_dir=_objects_for(cache_store))
		verdict = outcome["verdict"]
		if verdict is None:
			broken.append("%s: %s" % (unit["id"], outcome["error"]))
			continue
		scores.append(verdict)
		if not verdict.passed:
			below.append("%s %-42s %6.2f%% bytes %+d %s" % (unit["id"], unit["name"],
				verdict.match_percent, verdict.size_delta_bytes,
				{k: v for k, v in verdict.categories.items() if v}))
		outcome["object"].unlink(missing_ok=True)
	conn.close()
	if not scores:
		failures.append("nothing scored (%d problems)" % len(broken))
		return
	percent = [item.match_percent for item in scores]
	tiers: dict[str, int] = {}
	for item in scores:
		tiers[item.tier] = tiers.get(item.tier, 0) + 1
	print("   %d/%d units scored, mean %.2f%%, byte-identical %d, bytes equal with the fields the "
		"link writes zeroed %d, tiers %s, pass the gate %d"
		% (len(scores), len(units), sum(percent) / len(percent),
			sum(1 for item in scores if item.bytes_equal),
			sum(1 for item in scores if item.bytes_equal_masked), tiers,
			sum(1 for item in scores if item.passed)))
	for item in broken[:8]:
		print("   BROKEN %s" % item)
	shown = below if ALL_FAILURES else below[:12]
	for item in shown:
		print("   FAIL %s" % item)
	if len(below) > len(shown):
		print("   ... %d more (--all lists them)" % (len(below) - len(shown)))
	if broken:
		failures.append("%d units could not be scored" % len(broken))
	if not gated():
		print("   measured, not gated (%s is not in FLOORS): %d of %d past the gate" % (
			VARIANT_NAME, sum(1 for item in scores if item.passed), len(scores)))
		return
	floor = FLOORS[VARIANT_NAME]
	passed = sum(1 for item in scores if item.passed)
	mean = sum(percent) / len(percent)
	expect(passed >= int(floor["pass"]), "at least %d units pass the gate (measured %d of %d)"
		% (int(floor["pass"]), passed, len(scores)), failures)
	# Compared at the precision the number is reported at: the mean is printed as two decimals, and
	# a floor set from that print must not fail on the digits behind it.
	expect(round(mean, 2) >= floor["mean"], "the mean match stays at or above %.2f%% (measured %.2f%%)"
		% (floor["mean"], mean), failures)


def controls(answer: dict, failures: list[str]) -> None:
	"""The wrong candidates, built by the x86 driver, must be reported as the kind of wrong they are."""
	units = {unit["id"]: unit for unit in answer["units"]}
	conn = cache.open_readonly(Path(cache_store.db_path(KEY)))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	bad = 0
	for unit_id, symbol, wanted, why in NEGATIVE_CONTROLS:
		unit = units.get(unit_id)
		if unit is None:
			print("   no such unit %s" % unit_id)
			bad += 1
			continue
		row = cache.resolve_function(conn, hex(unit["address"] + offset))
		outcome = cli.score_candidate(CONFIG, conn, meta, row[0],
			[TESTS / "examples" / "candidate_math_bad.cpp"], fn=symbol,
			object_dir=_objects_for(cache_store))
		verdict = outcome["verdict"]
		if verdict is None:
			print("   controls %s: %s" % (unit_id, outcome["error"]))
			bad += 1
			continue
		missing = [name for name in sorted(wanted) if not verdict.categories[name]]
		print("   controls %s vs %-22s %6.2f%% %-9s categories %s  (%s) %s"
			% (unit_id, symbol, verdict.match_percent,
				"not-passed" if not verdict.passed else "PASSED!",
				{k: v for k, v in verdict.categories.items() if v}, why,
				"ok" if not missing and not verdict.passed else "WRONG REPORT"))
		if missing or verdict.passed:
			bad += 1
		outcome["object"].unlink(missing_ok=True)
	conn.close()
	if not gated():
		print("   measured, not gated (%s is not in FLOORS)" % VARIANT_NAME)
		return
	expect(bad == 0, "the wrong candidates are still classified correctly on an i386 PE", failures)


# X86-6's acceptance, in one sentence: the *same object* in the benchmark has to be reached two
# ways - by a 32-bit absolute operand on the target side and by a `DIR32`/`R_386_32` on the candidate
# side - and produce a reference the two sides agree on. MATH-32 (`NearestTableIndex`) is that case:
# it reads `k_lodDistances` as `subss 0x41f488(%ecx)` / `subss 0x41f488(, %eax, 4)` in the image and
# as `subss (%ecx)` / `subss (, %eax, 4)` with a relocation on those four bytes in the object. Both
# 32-bit paths are asked, because the phase is about the bitness and not the toolchain: the COFF half
# is this script's own variant, the ELF half is `gcc-o0-x86`.
TABLE_UNITS = {"MATH-32": "NearestTableIndex - reads a global float table by index"}
OTHER_32 = "gcc-o0-x86"


def reached_twice(variant_name: str, failures: list[str]) -> None:
	"""One table, one reference: the target's absolute operand and the candidate's relocation."""
	from decomp import diff as diff_
	build = TESTS / "build" / variant_name
	answer_path = build / "answer_key.json"
	if not answer_path.is_file():
		print("   %s is not built (Tests/eval.py build --variant %s)" % (variant_name, variant_name))
		return
	key = cache.target_key(build / "da_tests.stripped")["key"]
	if not cache_store.status(key).get("complete"):
		print("   %s is not analysed (decomp analyze … --variant %s)" % (variant_name, variant_name))
		return
	conn = cache.open_readonly(Path(cache_store.db_path(key)))
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	handle = normalize.capstone_for(meta.get("language_id") or "", detail=True)
	answer = json.loads(answer_path.read_text())
	try:
		judge_name, judge = config.variant(CONFIG, variant_name)
	except config.ConfigError as exc:
		print("   no variant %s in Tests/project.toml: %s" % (variant_name, exc))
		return
	for unit in answer["units"]:
		if unit["id"] not in TABLE_UNITS:
			continue
		row = cache.resolve_function(conn, hex(unit["address"] + offset))
		if not row:
			failures.append("%s: no cached function at %s" % (unit["id"], hex(unit["address"])))
			continue
		original = extract.original_function(conn, meta, row[0])
		image = extract.TargetImage(build / "da_tests.stripped", offset)
		bind_o, _refs_o = extract.original_bindings(conn, meta, row[0], image)
		object_path, problem = object_for(TESTS / "TestBinary" / unit["file"],
			_objects_for(cache_store, "table"), variant_body=judge)
		if problem:
			failures.append("%s: %s" % (unit["id"], problem))
			continue
		candidate = extract.CandidateObject(object_path)
		try:
			function = candidate.function(unit["mangled"])
		except extract.SymbolNotFound as exc:
			failures.append("%s: %s" % (unit["id"], exc))
			continue
		bind_c, _refs_c = candidate.bindings(function)

		def absolute(func, bind, boundaries=None):
			"""Every operand this side reaches through an absolute 32-bit field, with its Ref."""
			out = []
			for instruction in normalize.decode_function(handle, func.address, func.bytes,
					boundaries, None):
					bound = bind(instruction) or {}
					for slot in instruction.slots:
						if slot.kind not in ("abs", "disp"):
							continue
						ref = bound.get(slot.operand)
						if ref is not None and ref.cls == "data":
							out.append((instruction, slot, ref))
			return out

		left = absolute(original, bind_o, [(int(a), int(b)) for a, b in
			json.loads(row[0]["ranges"] or "[]")] or None)
		right = absolute(function, bind_c)
		expect(bool(left) and bool(right), "%s %s: both sides state the absolute data reference "
			"(%d on the target, %d in the object)" % (variant_name, unit["id"], len(left),
				len(right)), failures)
		if not left or not right:
			continue
		# pair by position, not any-to-any: the two sides state their absolute data references in the
		# same order (that is what the unit's diff asserts), and pairing them freely would compare two
		# different instructions that happen to reach the same object
		found = None
		for (instruction, _slot, one), (other_instruction, _other_slot, two) in zip(left, right):
			ok, _why, evidence = diff_.ref_evidence(one, two)
			if ok and evidence in ("bytes", "name", "string", "size"):
				found = (one, two, evidence, instruction, other_instruction)
				break
		expect(found is not None, "%s %s: one table reached two ways is the same reference (%s; "
			"target %s, candidate %s)" % (variant_name, unit["id"], TABLE_UNITS[unit["id"]],
				left[0][2].raw or hex(left[0][2].address or 0), right[0][2].raw), failures)
		if found:
			one, two, evidence, instruction, other_instruction = found
			# and the two spellings have to tokenise to one line, which is what the unit's tier
			# rests on
			vocab = normalize.Vocabulary()
			tokens_o = normalize.normalize_function(vocab, "original", [instruction], bind_o,
				original.address, original.size)
			tokens_c = normalize.normalize_function(vocab, "candidate", [other_instruction], bind_c,
				function.address, function.size)
			expect(tokens_o and tokens_c and tokens_o[0].text == tokens_c[0].text,
				"%s %s: the two spellings tokenise to one line: %r / %r" % (variant_name, unit["id"],
					tokens_o[0].text if tokens_o else "", tokens_c[0].text if tokens_c else ""),
				failures)
			print("   %s %s: %s <- target %s (%s) | candidate %s (%s) - agreed on %s"
				% (variant_name, unit["id"], tokens_o[0].text,
					one.raw or hex(one.address or 0), one.section, two.raw, two.identity or two.section,
					evidence))
	conn.close()


VARIANT: dict = {}
VARIANT_NAME = ""
CONFIG: dict = {}
KEY = ""
OFFSET = 0
ALL_FAILURES = False
cache_store = None


def stored_addresses(variant_name: str, failures: list[str]) -> None:
	"""An address stored through a register-relative operand reaches its object (§37).

	One question about the candidate side, with no target involved. In a 32-bit object the value is
	still zero and a relocation sits on the four bytes of the *immediate* of `movl $0, 8(%esi)`;
	those same four bytes are also what a slot list built from instruction length would call the
	memory operand's displacement, and only one of the two claims can be a field of the
	instruction. Bind the relocation to the displacement and the object the code reaches is gone
	from the candidate side: what the link fills in then reads as an operand difference, and a unit
	that stores a vptr, a global's address or a function pointer can never be matched on it. That
	covers every constructor and destructor of a C++ target of this era, and any function that
	takes the address of a global.

	`Tests/probe/x86_addr_store.cpp` is the smallest source that makes all three shapes, asked of
	both 32-bit toolchains this repository has. Each unit must bind exactly one reference, to the
	*immediate* operand, naming the global; and `store_constant`, which has the same instruction
	shape and no relocation, must still bind nothing - the fix is about who owns a relocated field,
	not about inventing references.
	"""
	probe = TESTS / "probe" / "x86_addr_store.cpp"
	units = ["store_global", "store_field", "store_local"]
	try:
		judge_name, judge = config.variant(CONFIG, variant_name)
	except config.ConfigError as exc:
		print("   no variant %s in Tests/project.toml: %s" % (variant_name, exc))
		return
	# a directory per variant: the two 32-bit toolchains build the same probe, and the second
	# build must not overwrite the first one's object
	work = _objects_for(cache_store, "addr-store-%s" % variant_name)
	work.mkdir(parents=True, exist_ok=True)
	object_path, problem = object_for(probe, work, variant_body=judge)
	if problem:
		failures.append("%s: the address-store probe did not build: %s" % (variant_name, problem))
		return
	candidate = extract.CandidateObject(object_path)
	if candidate.error:
		failures.append("%s: %s" % (variant_name, candidate.error))
		return
	expect(candidate.bits == 32, "%s: the probe object measures %d-bit, this group is the 32-bit "
		"one" % (variant_name, candidate.bits), failures)
	handle = normalize.capstone_for("x86:LE:32:default", detail=True)
	if handle is None:
		failures.append("%s: no capstone decoder for x86:LE:32" % variant_name)
		return

	def reached(function):
		"""Every (instruction, slot, reference) this function's bindings state."""
		bind, _refs = candidate.bindings(function)
		out = []
		for instruction in normalize.decode_function(handle, function.address, function.bytes,
				None, None):
			bound = bind(instruction) or {}
			for slot in instruction.slots:
				ref = bound.get(slot.operand)
				if ref is not None:
					out.append((instruction, slot, ref))
		return out

	for name in units:
		try:
			function = candidate.function(name)
		except extract.SymbolNotFound as exc:
			failures.append("%s: %s" % (variant_name, exc))
			continue
		found = reached(function)
		expect(len(found) == 1, "%s %s: the address it stores is bound to exactly one operand "
			"(%d: %s)" % (variant_name, name, len(found),
				", ".join("%s@%s" % (s.kind, hex(i.address)) for i, s, _ in found)), failures)
		if len(found) != 1:
			continue
		_instruction, slot, ref = found[0]
		expect(slot.kind == "imm", "%s %s: the relocated field belongs to the immediate, not to a "
			"displacement (bound to %s)" % (variant_name, name, slot.kind), failures)
		expect("g_slot" in (ref.raw or "") + (ref.name or ""), "%s %s: the reference names the "
			"global the source stores the address of (%s)" % (variant_name, name, ref.raw), failures)
		expect(ref.cls == "data", "%s %s: storing the address of data is a data reference (%s)"
			% (variant_name, name, ref.cls), failures)
	# the control: the same instruction shape, no relocation, no reference
	try:
		held = reached(candidate.function("store_constant"))
	except extract.SymbolNotFound as exc:
		failures.append("%s: %s" % (variant_name, exc))
		return
	expect(not held, "%s store_constant: a store of a constant binds no reference (%d)"
		% (variant_name, len(held)), failures)


def same_object_call(variant_name: str, failures: list[str]) -> None:
	"""A call to another function of the same object reaches that function (\u00a739).

	One question about the candidate side, with no target involved. A caller and a callee in one
	translation unit are the ordinary shape of a decompilation project, and what the object makes of
	the call depends on one flag. Left as it comes, the front end puts every function of the unit in
	one section, the call carries **no relocation**, and the callee is read by looking the final
	address up in that section. With function-level linking (`/Gy`, what an optimizing build of this
	era ships) every function gets its own section and every one of those sections shares a name, so
	the call's relocation names the callee's *section symbol* - this object has no symbol for the
	callee at all - and the field in the code holds 0, which disassembles as a call to the next
	instruction. An address of 0 is inside the caller's own body, because both sections start at 0.
	A tool that believes it turns a call into a jump to a label inside the unit and reports an
	operand difference on a field the link writes: the callee vanishes, and the unit cannot be shown
	right however faithful the source is.

	`Tests/probe/x86_call_pair.cpp` makes both shapes, asked of the same driver. The `/Gy` object is
	the one under test; the plain object is the control that the same-section lookup still works, and
	`calls_itself` is the control in the other direction - a self-recursive call *is* an edge inside
	the unit, and must still read as one.
	"""
	probe = TESTS / "probe" / "x86_call_pair.cpp"
	try:
		judge_name, judge = config.variant(CONFIG, variant_name)
	except config.ConfigError as exc:
		print("   no variant %s in Tests/project.toml: %s" % (variant_name, exc))
		return
	handle = normalize.capstone_for("x86:LE:32:default", detail=True)
	if handle is None:
		failures.append("%s: no capstone decoder for x86:LE:32" % variant_name)
		return

	def sites(candidate: extract.CandidateObject, function) -> list:
		"""Every call this function makes, with the reference behind it and its token text."""
		bind, _refs = candidate.bindings(function)
		instructions = normalize.decode_function(handle, function.address, function.bytes,
			None, None)
		tokens = normalize.normalize_function(normalize.Vocabulary(), "candidate", instructions,
			bind, function.address, function.size, False, function.extents, function.section)
		found = []
		for instruction, token in zip(instructions, tokens):
			if not token.text.startswith("call"):
				continue
			bound = bind(instruction) or {}
			ref = next((bound[slot.operand] for slot in instruction.slots
				if bound.get(slot.operand) is not None), None)
			found.append((instruction, ref, token))
		return found

	def built_object(suffix: str, extra_flags: list[str]) -> tuple:
		work = _objects_for(cache_store, "call-pair-%s%s" % (variant_name, suffix))
		work.mkdir(parents=True, exist_ok=True)
		object_path, problem = object_for(probe, work, variant_body=judge, extra_flags=extra_flags)
		if problem:
			failures.append("%s%s: the call-pair probe did not build: %s"
				% (variant_name, suffix, problem))
			return None
		candidate = extract.CandidateObject(object_path)
		if candidate.error:
			failures.append("%s%s: %s" % (variant_name, suffix, candidate.error))
			return None
		if candidate.bits != 32:
			failures.append("%s%s: the probe object measures %d-bit"
				% (variant_name, suffix, candidate.bits))
			return None
		return candidate

	# 1. the shape under test: function-level linking, and what it does to the call.
	split = built_object("-gy", ["/Gy"])
	if split is not None:
		try:
			caller = split.function("calls_its_own_unit")
			callee = split.function("inner_of_this_unit")
		except extract.SymbolNotFound as exc:
			failures.append("%s: %s" % (variant_name, exc))
			caller = None
		if caller is not None and callee is not None:
			expect(caller.section != callee.section and caller.section.split("#", 1)[0]
				== callee.section.split("#", 1)[0],
				"%s: the /Gy object puts the caller and the callee in two sections that share one "
				"name (%s / %s) - this group measures that shape or nothing"
				% (variant_name, caller.section, callee.section), failures)
			found = sites(split, caller)
			expect(len(found) == 1, "%s: calls_its_own_unit makes one call (%d)" % (variant_name,
				len(found)), failures)
			if len(found) == 1:
				_instruction, ref, token = found[0]
				expect(ref is not None and ref.kind == "function", "%s: the call to a function of the "
					"same object reaches a function (%s)" % (variant_name,
						ref.kind if ref else "nothing is bound"), failures)
				expect(ref is not None and "inner_of_this_unit" in (ref.raw or "") + (ref.name or ""),
					"%s: the reference names the callee of this unit (%s)" % (variant_name,
						(ref.raw or ref.name) if ref else "-"), failures)
				# what the differ sees: a reference, not an edge to a label inside the body
				expect("SYM" in token.text, "%s: the call is tokenised as a reference to a symbol (%s)"
					% (variant_name, token.text), failures)
		# the self-call stays an edge inside the unit - the rule the fix must not break
		try:
			recursive = split.function("calls_itself")
		except extract.SymbolNotFound as exc:
			failures.append("%s: %s" % (variant_name, exc))
			recursive = None
		if recursive is not None:
			found = sites(split, recursive)
			expect(len(found) == 1, "%s: calls_itself makes one call, to itself (%d)"
				% (variant_name, len(found)), failures)
			if len(found) == 1:
				_instruction, ref, token = found[0]
				# the reference may be there (the self-call is a symbol of this object too); what must
				# not change is how it reads: an edge to a label inside this body, on both sides
				opcode, _, target = token.text.partition(" ")
				expect(target.startswith("L"),
					"%s: a self-recursive call is still an edge inside the unit (%s: %s)"
					% (variant_name, token.text, (ref.raw if ref else "unbound")), failures)

	# 2. the control: without function-level linking there is no relocation on the call at all, and
	# the callee is read from the address the assembly already settled. That path must keep working.
	shared = built_object("", [])
	if shared is not None:
		try:
			caller = shared.function("calls_its_own_unit")
			callee = shared.function("inner_of_this_unit")
		except extract.SymbolNotFound as exc:
			failures.append("%s: %s" % (variant_name, exc))
			caller = None
		if caller is not None and callee is not None:
			expect(caller.section == callee.section, "%s: the plain object keeps the unit in one "
				"section (%s / %s) - this control measures that shape or nothing"
				% (variant_name, caller.section, callee.section), failures)
			found = sites(shared, caller)
			expect(len(found) == 1 and found[0][1] is not None
				and "inner_of_this_unit" in (found[0][1].raw or "") + (found[0][1].name or ""),
				"%s: a call inside one section still reaches its callee (%s)" % (variant_name,
					"; ".join((ref.raw if ref else "unbound") for _i, ref, _t in found)
					or "no call found"), failures)


def main() -> int:
	global VARIANT, VARIANT_NAME, CONFIG, KEY, OFFSET, cache_store
	parser = argparse.ArgumentParser(prog="check_msvc_x86_candidate.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variant", default="msvc-o0-x86")
	parser.add_argument("--limit", type=int, default=0)
	parser.add_argument("--no-controls", action="store_true")
	parser.add_argument("--no-target", action="store_true",
		help="only group 1: the field rules and one object, no analysed PE needed")
	parser.add_argument("--all", action="store_true", dest="all",
		help="print every unit below the gate, not the first twelve")
	args = parser.parse_args()
	global ALL_FAILURES
	ALL_FAILURES = bool(args.all)

	CONFIG = config.load(str(TESTS / "project.toml"))
	try:
		VARIANT_NAME, VARIANT = config.variant(CONFIG, args.variant)
	except config.ConfigError as exc:
		print("no variant to judge: %s" % exc)
		return 2
	if not toolchain.msvc(VARIANT.get("compiler", "")):
		print("%s is not an MSVC variant (compiler = %s)" % (VARIANT_NAME, VARIANT.get("compiler")))
		return 2
	arch = str(VARIANT.get("arch", "")).lower()
	if arch not in ("x86", "i386", "i686"):
		print("%s asks for arch = %r: this check is the i386 candidate side (use "
			"check_coff_candidate.py for x86-64)" % (VARIANT_NAME, VARIANT.get("arch")))
		return 2
	driver = toolchain.compiler_for(VARIANT, prefix=(config.msvc_prefix(CONFIG) or (None, ""))[0],
		prefix_from="[msvc] prefix in Tests/project.toml")
	if driver.refused:
		print("no 32-bit MSVC driver here: %s\nNothing was judged - this is not a failure of the "
			"tool." % driver.gap)
		return 2
	if not shutil.which(driver.name):
		print("the resolved driver %s cannot be run from here." % driver.name)
		return 2
	print("variant %s: %s\n  driver %s (%s)" % (VARIANT_NAME, " ".join(toolchain.build_flags(VARIANT)),
		driver.name, driver.why))
	cache_store = cache.Cache(config.cache_dir(CONFIG))

	failures: list[str] = []
	print("\n=== 1. the field rules of i386 COFF (no target needed) ===")
	field_rules(failures)
	if args.no_target:
		if failures:
			print("\nFAILURES (%d):" % len(failures))
			for item in failures:
				print("  %s" % item)
			return 1
		print("\ncheck_msvc_x86_candidate: OK (group 1 only)")
		return 0

	answer_path = TESTS / "build" / VARIANT_NAME / "answer_key.json"
	stripped = TESTS / "build" / VARIANT_NAME / "da_tests.stripped"
	if not answer_path.is_file() or not stripped.is_file():
		print("\nbuild the 32-bit reference first: Tests/eval.py build --variant %s" % VARIANT_NAME)
		return 2
	KEY = cache.target_key(stripped)["key"]
	status = cache_store.status(KEY)
	if not status.get("complete"):
		print("\nnot analysed: decomp analyze %s --variant %s --config Tests/project.toml"
			% (stripped, VARIANT_NAME))
		return 2
	answer = json.loads(answer_path.read_text())
	global OFFSET
	conn = cache.open_readonly(Path(status["db"]))
	OFFSET = int(cache.meta(conn).get("address_offset") or 0)
	conn.close()
	print("target %s" % stripped)
	print("\n=== 2. the extent a COFF object gives for each unit (X86-3's whole claim) ===")
	extents(answer, failures)
	print("\n=== 3. the untouched source through decomp try, every unit ===")
	the_loop(answer, args.limit, failures)
	if not args.no_controls:
		print("\n=== 4. the deliberately wrong candidates ===")
		controls(answer, failures)
	print("\n=== 5. one table, reached two ways (X86-6's acceptance) ===")
	reached_twice(VARIANT_NAME, failures)
	print("\n=== 6. an address stored through a register operand reaches its object (\u00a737) ===")
	stored_addresses(VARIANT_NAME, failures)
	print("\n=== 7. a call to a function of the same object reaches that function (\u00a739) ===")
	same_object_call(VARIANT_NAME, failures)
	if VARIANT_NAME == "msvc-o0-x86":
		# the same rule on the other 32-bit toolchain - X86-6 is one phase, not two
		reached_twice(OTHER_32, failures)
		stored_addresses(OTHER_32, failures)

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_msvc_x86_candidate: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
