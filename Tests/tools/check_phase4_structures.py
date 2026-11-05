"""Phase 4 acceptance: does the tool recover the C++ structure the source has?

	run: .venv/bin/python Tests/tools/check_phase4_structures.py

The benchmark's `structs.cpp` hierarchy is the ground truth, and it is deliberately a
stripped binary: nothing here may use a symbol name. What is checked, against
`Tests/build/<variant>/answer_key.json` (the addresses and names of the class's own
constructors, destructors and virtual methods) and against the field offsets in
`Tests/TestBinary/TestFunctions/structs.h`:

1. **the classes exist and are named**: from the type_info name string in `.rodata`, not from
   `_ZTV`/`_ZTI` symbols - so this fails the moment the recovery falls back to names;
2. **the hierarchy**: which class is whose base, and that the abstract one has a pure slot;
3. **the vtables**: one per class, the right number of slots, and the slots point at that
   class's real `GetHealth`/`Classify` (answer-key addresses);
4. **constructors and destructors**: every address the tool calls a constructor or destructor
   must be one the compiler built (no invented member), and the real ones must be found where
   the file makes them findable;
5. **the field layout**: every member offset the source has must be recovered (through `this`
   in the class's own code), and no recovered offset may lie outside the object;
6. **the shared header**: `decomp types --write` output must compile as C++ on its own, and
   the `static_assert` in it must hold for the real class - so a wrong layout fails the
   candidate's build rather than the tool's opinion;
7. **the loop**: the `dynamic_cast` unit (STRUCT-24), which was the named gap Phase 4 exists
   to close, passes `try` - both sides have to name the same type_info for that to happen.

A PE built by MSVC (Tests/Proprietary/notepad.exe) is checked for the opposite: it must
report no classes, because its RTTI is not this format, and must not crash doing so.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, extract, structures  # noqa: E402

VARIANTS = ["gcc-o0", "gcc-o0-x86"]
NAMED_BINARY = TESTS / "build" / "gcc-o0" / "da_tests"

# Ground truth: the classes in Tests/TestBinary/TestFunctions/structs.h. `members` is the
# source's own declaration order; a polymorphic class starts with its vptr (one pointer), so
# the first member sits after that. Offsets are what `structs.h` implies and what the code
# has to agree with; `size` is the whole object, used to reject an invented offset.
CLASSES = {
	"CEntityBase": {"base": None,
		"members": [("m_health", "int"), ("m_tag", "int")],
		"virtual": ["GetHealth", "Classify"], "pure": ["GetHealth"]},
	"CVehicleEntity": {"base": "CEntityBase",
		"members": [("m_armour", "int"), ("m_speed", "float")],
		"virtual": ["GetHealth", "Classify"], "pure": []},
	"CCharacterEntity": {"base": "CEntityBase",
		"members": [("m_stamina", "int")],
		"virtual": ["GetHealth", "Classify"], "pure": []},
}
# The unit that `dynamic_cast`s: the one whose every reference is a type_info.
RTTI_UNIT = "STRUCT-24"


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_phase4_structures.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variants", default=",".join(VARIANTS))
	args = parser.parse_args(argv)

	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	failures = 0
	for variant in [item.strip() for item in args.variants.split(",") if item.strip()]:
		failures += check_variant(cfg, store, variant, stripped=True)
	failures += check_variant(cfg, store, "gcc-o0", stripped=False)
	failures += check_header_compiles(cfg, store, "gcc-o0")
	failures += check_no_structure_on_pe(cfg)
	print("check_phase4_structures: %s" % ("OK" if failures == 0 else "%d group(s) failed"
		% failures))
	return 0 if failures == 0 else 1


def expected_layout(name: str, bits: int) -> dict:
	"""{member: offset} for one class in this target's ABI, from the source's own order."""
	spec = CLASSES[name]
	ptr = bits // 8
	offset = ptr if spec["base"] is not None or True else 0   # every class here is polymorphic
	if spec["base"]:
		offset = expected_total(CLASSES[spec["base"]]["members"], bits)
	sizes = {"int": 4, "float": 4, "char": 1}
	layout = {}
	for member, kind in spec["members"]:
		width = sizes[kind]
		offset = -(-offset // width) * width          # the alignment the ABI gives it
		layout[member] = offset
		offset += width
	return {"members": layout, "size": offset}


def expected_total(members: list, bits: int) -> int:
	sizes = {"int": 4, "float": 4, "char": 1}
	offset = bits // 8
	for _member, kind in members:
		width = sizes[kind]
		offset = -(-offset // width) * width
		offset += width
	return offset


def open_cached(store: cache.Cache, path: Path):
	identity = cache.target_key(path)
	status = store.status(identity["key"])
	if not status.get("complete"):
		print("%s: not analysed - run: decomp analyze %s" % (path.name, path))
		return None, {}
	return cache.open_readonly(Path(status["db"])), status


# --------------------------------------------------------------------------------------
# the recovered structure, against the source


def check_variant(cfg: dict, store: cache.Cache, variant: str, stripped: bool) -> int:
	path = TESTS / "build" / variant / ("da_tests.stripped" if stripped else "da_tests")
	label = "%s %s" % (variant, "stripped" if stripped else "with symbols")
	conn, _status = open_cached(store, path)
	if conn is None:
		return 1
	meta = cache.meta(conn)
	bits = 32 if ":32:" in (meta.get("language_id") or "") else 64
	answer = json.loads((TESTS / "build" / variant / "answer_key.json").read_text())
	units = {item["id"]: item for item in answer["units"]}
	# every symbol the compiler emitted that is not a scored unit: the class's own ctors,
	# dtors and virtual methods are all here, named, with their addresses
	built = {}
	for item in answer.get("other_symbols", []):
		built.setdefault(item["name"], []).append(int(item["address"]) + cache.address_offset(meta))
	bad: list[str] = []
	try:
		recovered = structures.Recovery(conn, meta).build()
		summary = recovered.summary()
		print("%s: %d classes, %d vtables, %d type_info in %.3fs (%d addresses probed)"
			% (label, summary["classes"], summary["vtables"], summary["typeinfos"],
				summary["seconds"], summary["probed"]))
		for note in recovered.notes:
			print("   note %s" % note)
		for name, spec in CLASSES.items():
			klass = recovered.classes.get(name)
			if klass is None:
				bad.append("%s: %s was not recovered at all (its RTTI is in the file)"
					% (label, name))
				continue
			# 1/2. identity and hierarchy, from RTTI alone
			if klass.typeinfo is None:
				bad.append("%s: %s has no type_info address" % (label, name))
			if bool(klass.bases) != bool(spec["base"]) or (spec["base"] and klass.bases != [spec["base"]]):
				bad.append("%s: %s claims bases %s, the source says %s"
					% (label, name, klass.bases, [spec["base"]] if spec["base"] else []))
			# 3. the vtable: one per class; where the file fills the slots in they must be
			#    that class's real methods, and where it leaves them null the tool has to say
			#    so rather than invent something
			if klass.vtable is None:
				bad.append("%s: %s has a type_info but no vtable was found" % (label, name))
			else:
				filled = [method for method in klass.methods if method.address]
				if not filled:
					if not any("null" in note for note in klass.notes):
						bad.append("%s: %s's vtable reads as all-null slots and the tool does "
							"not say so" % (label, name))
					print("   %s: the file leaves %s's %d vtable slot(s) null - its methods are "
						"only reachable through the derived classes' vtables"
						% (label, name, len(klass.methods)))
					continue
				if len(klass.methods) != 4:
					bad.append("%s: %s's vtable has %d slots, the class declares 4 (dtor pair, "
						"GetHealth, Classify)" % (label, name, len(klass.methods)))
				slot_addresses = {method.address for method in filled}
				for method in spec["virtual"]:
					want = _addresses(built, "%s::%s" % (name, method))
					if want and not any(address in slot_addresses for address in want):
						bad.append("%s: no vtable slot of %s points at its real %s (%s)"
							% (label, name, method, ", ".join(hex(a) for a in want)))
				if spec["pure"] and not klass.pure_count:
					bad.append("%s: %s is abstract in the source but no slot resolved to "
						"__cxa_pure_virtual" % (label, name))
			# 4. constructors and destructors: none invented, and the real ones found
			invented = [entry for entry in klass.constructors + klass.destructors
				if not _is_member_of(built, name, entry, meta)]
			if invented:
				bad.append("%s: %s - the tool calls %s a constructor/destructor, and the "
					"compiler built no member of that class there"
					% (label, name, ", ".join(hex(entry) for entry in invented)))
			ctor_addresses = _addresses(built, "%s::%s" % (name, name))
			if ctor_addresses and not (set(klass.constructors) & set(ctor_addresses)):
				bad.append("%s: %s - its real constructor (%s) was not identified"
					% (label, name, ", ".join(hex(a) for a in ctor_addresses)))
			dtor_addresses = _addresses(built, "%s::~%s" % (name, name))
			if dtor_addresses and not (set(klass.destructors) & set(dtor_addresses)):
				bad.append("%s: %s - its real destructor (%s) was not identified"
					% (label, name, ", ".join(hex(a) for a in dtor_addresses)))
			# 5. the field layout
			layout = expected_layout(name, bits)
			missing = {member: offset for member, offset in layout["members"].items()
				if offset not in klass.fields}
			if missing:
				bad.append("%s: %s - the code reads/writes these member offsets and they were "
					"not recovered: %s" % (label, name,
						", ".join("%s=+%#x" % (member, offset) for member, offset
							in missing.items())))
			outside = [offset for offset in klass.fields if offset >= layout["size"]]
			if outside:
				bad.append("%s: %s - offsets %s are outside the object (the source says %d bytes)"
					% (label, name, ", ".join(hex(offset) for offset in outside), layout["size"]))
			widths = [(offset, klass.fields[offset].size) for offset in layout["members"].values()
				if offset in klass.fields and klass.fields[offset].size
				and klass.fields[offset].size != 4]
			if widths:
				bad.append("%s: %s - every member is an int or a float (4 bytes), but these were "
					"measured differently: %s" % (label, name,
						", ".join("+%#x=%d" % (offset, size) for offset, size in widths)))
			print("   %s: vtable %s, %d slots, %d ctor(s), %d dtor(s), fields %s (source: %s)"
				% (name, hex(klass.vtable) if klass.vtable else "-", len(klass.methods),
					len(klass.constructors), len(klass.destructors),
					sorted(hex(offset) for offset in klass.fields),
					sorted(hex(offset) for offset in layout["members"].values())))
		# 7. the loop: the dynamic_cast unit has to pass, which needs both sides to agree
		#    on which type_info each of its references reaches
		unit = units.get(RTTI_UNIT)
		if unit is None:
			bad.append("%s: the answer key has no %s" % (label, RTTI_UNIT))
		else:
			at = cache.function_at(conn, int(unit["address"]) + cache.address_offset(meta))
			row = cache.function_row(conn, at["id"]) if at else None
			if row is None:
				bad.append("%s: %s is not in the analysis" % (label, RTTI_UNIT))
			else:
				outcome = cli.score_candidate(cfg, conn, meta, row,
					[TESTS / "TestBinary" / "TestFunctions" / "structs.cpp"],
					fn=unit["name"].split("(")[0].split("::")[-1],
					object_dir=store.root / "candidates-check")
				verdict = outcome["verdict"]
				if verdict is None:
					bad.append("%s: %s could not be scored: %s" % (label, RTTI_UNIT,
						outcome["error"]))
				elif not verdict.passed:
					bad.append("%s: %s (dynamic_cast) scores %.2f%% with %d relocation "
						"difference(s) - both sides must name the same type_info"
						% (label, RTTI_UNIT, verdict.match_percent,
							verdict.categories["relocation"]))
				else:
					names = {item["original"]["name"] for item in verdict.symbols
						if item["ok"] and item["original"]["kind"] != "function"}
					print("   %s: %s passes at %.2f%%, and both sides name %s"
						% (label, RTTI_UNIT, verdict.match_percent, ", ".join(sorted(names))))
	finally:
		conn.close()
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


def _addresses(built: dict, qualified: str) -> list[int]:
	"""Every address the compiler built for `Class::method` (a ctor/dtor has several forms)."""
	out: list[int] = []
	for name, addresses in built.items():
		if name.replace(" const", "").startswith(qualified + "("):
			out.extend(addresses)
	return sorted(set(out))


def _is_member_of(built: dict, klass: str, entry: int, meta: dict) -> bool:
	"""Did the compiler really build a member of this class at this address?"""
	for name, addresses in built.items():
		if not name.startswith(klass + "::"):
			continue
		if entry in addresses:
			return True
	return False


# --------------------------------------------------------------------------------------
# the shared header has to be a header


def check_header_compiles(cfg: dict, store: cache.Cache, variant: str) -> int:
	path = TESTS / "build" / variant / "da_tests.stripped"
	conn, _status = open_cached(store, path)
	if conn is None:
		return 1
	bad = []
	try:
		recovered = structures.Recovery(conn, cache.meta(conn)).build()
		header = recovered.header()
		with tempfile.TemporaryDirectory() as directory:
			header_path = Path(directory) / "types.h"
			header_path.write_text(header)
			user = Path(directory) / "use.cpp"
			# the point of the header: a candidate can name the class and its offsets. The
			# field names are the tool's, so this file uses those - and the static_asserts
			# inside the header are what fail if a layout is wrong.
			user.write_text('#include "types.h"\n'
				"int probe(CCharacterEntity *entity) { return entity->f0x8; }\n")
			compiler = config.variant(cfg, "gcc-o0")[1].get("compiler", "g++")
			proc = subprocess.run([compiler, "-std=c++17", "-I", directory, "-fsyntax-only",
				str(user)], capture_output=True, text=True)
			print("header: %d lines, %d classes; %s -fsyntax-only -> %s"
				% (len(header.splitlines()), recovered.summary()["classes"], compiler,
					"ok" if proc.returncode == 0 else "failed"))
			if proc.returncode != 0:
				bad.append("the generated types.h does not compile: %s"
					% proc.stderr.strip().splitlines()[:4])
			if "vptr_" not in header or "static_assert" not in header:
				bad.append("the generated types.h is missing the vptr member or the size asserts")
			for klass in sorted(recovered.classes):
				if ("class %s" % klass) not in header:
					bad.append("the generated types.h has no definition for %s" % klass)
			for line in header.splitlines()[:3]:
				print("   %s" % line)
	finally:
		conn.close()
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


def check_no_structure_on_pe(cfg: dict) -> int:
	"""An MSVC PE must report no classes: its RTTI is a different format (MS-5)."""
	path = TESTS / "Proprietary" / "notepad.exe"
	store = cache.Cache(config.cache_dir(cfg))
	conn, _status = open_cached(store, path)
	if conn is None:
		return 1
	bad = []
	try:
		recovered = structures.Recovery(conn, cache.meta(conn)).build()
		summary = recovered.summary()
		print("notepad.exe: %d classes, %d vtables in %.3fs" % (summary["classes"],
			summary["vtables"], summary["seconds"]))
		if summary["classes"]:
			bad.append("notepad.exe: %d classes claimed - an MSVC binary's RTTI is not the "
				"Itanium form, so any claim here is a false positive" % summary["classes"])
	except Exception as exc:  # noqa: BLE001 - the whole point: it must not raise
		bad.append("notepad.exe: recovering structure raised %s: %s" % (type(exc).__name__, exc))
		conn.close()
		for line in bad:
			print("   FAIL %s" % line)
		return 1
	conn.close()
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


if __name__ == "__main__":
	sys.exit(main())
