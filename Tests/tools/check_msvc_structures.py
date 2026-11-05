"""MS-5 acceptance (Docs/MSVC-Plan.md §7): the MSVC C++ structure model.

	run: .venv/bin/python Tests/tools/check_msvc_structures.py [--skip-cl]

`check_phase4_structures.py` is the Itanium model; this is the parallel one for a target built
by Microsoft's compiler, where the type system is a graph of RTTI records rather than a vtable
with a header, and nothing in a PE is named. What is checked:

1. **the records are read, and read as what they are.** For the benchmark's own `cl` build: the
   `.?AV…` type descriptors, the RTTICompleteObjectLocator that names each one, the class
   hierarchy descriptor that names its bases, and the vftable whose slot before the methods
   points at that locator. The class names come from the type-name strings, never from a symbol
   - a PE has none.
2. **the structure is right.** Bases, one vftable per class, its slots pointing at the class's
   real methods (answer-key addresses from the map file), its constructor and destructor, and
   the member offsets the code reaches through `this` (in the Microsoft x64 ABI that is `%rcx`,
   spilled to `8(%rsp)` at `/Od`). MSVC's vtable has no offset-to-top and one destructor slot,
   so the slot count this model must report is 3, not the Itanium 4.
3. **one object, named the same way on both sides.** `object_at` gives a type descriptor the
   words `typeinfo for CVehicleEntity`; `normalize.clean_symbol` gives those same words for the
   `.obj`'s `??_R0?AVCVehicleEntity@@@8`, and the unit that `dynamic_cast`s (STRUCT-24) passes
   `try`. That is the unit MS-3 left as its one gap.
4. **a real shipped MSVC binary**, 32-bit, where every RTTI reference is an absolute address
   instead of an RVA: `Tests/Proprietary/deadrising2.exe` (770 type descriptors). No answer key
   exists for it, so what is asserted is that the model reads the same format at that scale,
   that a base relation the game really has comes out, that a nested name
   (`.?AUSimpleMapping@hkaSkeletonMapper@@`) is decoded to the scope form, and that the
   generated header still builds.
5. **the opposite, still.** `Tests/Proprietary/notepad.exe` carries no MSVC RTTI at all (it is
   C and asm): it must report no classes *and say why*, not stay silent.
6. **a PE is not an MSVC target.** `Tests/build/mingw-o0` is a PE built by MinGW, so its RTTI is
   the Itanium one: the model is chosen from the compiler, never from the container.

Exit: 0 all passed, 1 something came out wrong, 2 a target or a toolchain needed for a group is
absent - which is not a failure of the tool.
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

from decomp import cache, cli, config, normalize, structures  # noqa: E402

# The benchmark's own MSVC build: analysed by `decomp analyze`, with the answer key `eval.py`
# wrote from the map file (a PE has no symbol table, so the names come from `/MAP`).
MSVC_BUILD = TESTS / "build" / "msvc-o0" / "da_tests.stripped"
# A shipped 32-bit MSVC binary: the format at real size, with absolute RTTI references.
REAL_TARGET = TESTS / "Proprietary" / "deadrising2.exe"
# A PE built by MinGW: still a PE, but its RTTI is the Itanium one. Docs/MSVC-Plan.md §1 names
# this as the trap, and §9 keeps it out of scope as "an MSVC target".
MINGW_TARGET = TESTS / "build" / "mingw-o0" / "da_tests.stripped"
# A PE with no C++ type system in it at all.
NO_RTTI = TESTS / "Proprietary" / "notepad.exe"

# Ground truth: Tests/TestBinary/TestFunctions/structs.h. Offsets are what the Microsoft x64
# ABI gives this declaration order - one vptr at +0, then the base's members, then the
# derived class's - and every claim the tool makes has to agree with them.
CLASSES = {
	"CEntityBase": {"base": None, "members": {"m_health": 0x8, "m_tag": 0xc}, "size": 0x10,
		"methods": {"GetHealth": None, "Classify": "CEntityBase::Classify"},
		"ctor": "??0CEntityBase@@", "dtor": "??1CEntityBase@@"},
	"CVehicleEntity": {"base": "CEntityBase", "members": {"m_armour": 0x10, "m_speed": 0x14},
		"size": 0x18, "methods": {"GetHealth": "CVehicleEntity::GetHealth",
			"Classify": "CVehicleEntity::Classify"},
		"ctor": "??0CVehicleEntity@@", "dtor": "??1CVehicleEntity@@"},
	"CCharacterEntity": {"base": "CEntityBase", "members": {"m_stamina": 0x10}, "size": 0x18,
		"methods": {"GetHealth": "CCharacterEntity::GetHealth",
			"Classify": "CCharacterEntity::Classify"},
		"ctor": None, "dtor": None},
}
# MSVC's vtable for these classes: the deleting destructor, then the two virtual functions.
# (The Itanium form has four slots, because it stores the D1/D2 destructor pair.)
SLOTS = 3
RTTI_UNIT = "STRUCT-24"


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_msvc_structures.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--skip-cl", action="store_true",
		help="skip the group that compiles a candidate (group 3)")
	parser.add_argument("--no-real", action="store_true", help="skip the shipped-binary group")
	args = parser.parse_args(argv)

	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	failures = 0
	recovered = open_recovery(store, MSVC_BUILD)
	if recovered is None:
		failures += 1
	else:
		failures += check_model(recovered)
		failures += check_names(recovered)
		failures += check_header(recovered)
		if not args.skip_cl:
			failures += check_the_loop(cfg, store, recovered)
		recovered.conn.close()
	if not args.no_real:
		failures += check_real_target(store)
	failures += check_mingw_is_not_msvc(store)
	failures += check_no_rtti(cfg)
	print("check_msvc_structures: %s" % ("OK" if failures == 0 else "%d group(s) failed"
		% failures))
	return 0 if failures == 0 else 1


def open_recovery(store: cache.Cache, path: Path):
	"""A built `structures.Recovery` for an analysed target, or None (and a reason)."""
	if not path.is_file():
		print("%s: not present - this group measures nothing" % path)
		return None
	identity = cache.target_key(path)
	status = store.status(identity["key"])
	if not status.get("complete"):
		print("%s: not analysed - run: decomp analyze %s" % (path, path))
		return None
	conn = cache.open_readonly(Path(status["db"]))
	recovered = structures.Recovery(conn, cache.meta(conn)).build()
	recovered.conn = conn
	summary = recovered.summary()
	print("%s: abi=%s %d classes, %d vftables, %d type descriptors in %.2fs"
		% (path.name, summary["abi"], summary["classes"], summary["vtables"],
			summary["typeinfos"], summary["seconds"]))
	for note in summary["notes"]:
		print("   note %s" % note)
	return recovered


# --------------------------------------------------------------------------------------
# 1 and 2. the records, and the structure they describe


def check_model(recovered: structures.Recovery) -> int:
	bad: list[str] = []
	answer = json.loads((MSVC_BUILD.parent / "answer_key.json").read_text())
	built: dict[str, list[int]] = {}
	for item in answer["other_symbols"] + answer["units"]:
		built.setdefault(item["name"], []).append(int(item["address"]))
	if recovered.abi != "msvc":
		bad.append("the model chosen for a `cl` binary is %r, not 'msvc'" % recovered.abi)
	# the RTTI graph was walked, not guessed: every class names a locator and a CHD
	for name, klass in sorted(recovered.classes.items()):
		info = recovered.typeinfos.get(klass.typeinfo or 0, {})
		if not info.get("msvc"):
			bad.append("%s: its type descriptor was not read by the MSVC model" % name)
		if klass.vtable is not None and not info.get("claims"):
			bad.append("%s: a vftable with no RTTICompleteObjectLocator claiming it" % name)
		if klass.vtable is not None:
			table = recovered.vtables[klass.vtable]
			if not table.get("col"):
				bad.append("%s: its vftable records no locator" % name)
	for name, spec in CLASSES.items():
		klass = recovered.classes.get(name)
		if klass is None:
			bad.append("%s was not recovered at all (its `.?AV…` descriptor is in the file)"
				% name)
			continue
		folded = any("folded" in note or "shared" in note for note in klass.notes)
		if bool(klass.bases) != bool(spec["base"]) or (spec["base"] and klass.bases
				!= [spec["base"]]):
			bad.append("%s claims bases %s, the source says %s"
				% (name, klass.bases, [spec["base"]] if spec["base"] else []))
		if klass.vtable is None:
			bad.append("%s has a type descriptor but no vftable was found" % name)
		else:
			filled = [item for item in klass.methods if item.address]
			if len(klass.methods) != SLOTS:
				bad.append("%s's vftable has %d slots; MSVC gives this class %d (deleting "
					"destructor, GetHealth, Classify) - the Itanium count is 4"
					% (name, len(klass.methods), SLOTS))
			for method, display in spec["methods"].items():
				if display is None:
					continue      # a pure virtual: MSVC's slot is `_purecall`, unnamed here
				want = built.get(display, [])
				if not any(item.address in want for item in klass.methods):
					bad.append("no vftable slot of %s points at its real %s (%s)"
						% (name, method, ", ".join(hex(a) for a in want)))
		# constructors and destructors: nothing invented, and the ones the file proves found
		invented = [entry for entry in klass.constructors + klass.destructors
			if not any(entry in addresses for symbol, addresses in built.items()
				if name in symbol)]
		if invented:
			bad.append("%s - called %s a constructor/destructor; the compiler built no member "
				"of that class there" % (name, ", ".join(hex(x) for x in invented)))
		for prefix, found in ((spec["ctor"], klass.constructors),
				(spec["dtor"], klass.destructors)):
			if not prefix:
				continue
			want = [address for symbol, addresses in built.items() if symbol.startswith(prefix)
				for address in addresses]
			if want and not (set(found) & set(want)) and not folded:
				bad.append("%s - its real %s (%s) was not identified"
					% (name, prefix, ", ".join(hex(a) for a in want)))
		# the field layout, through `this` in the Microsoft x64 ABI
		missing = {member: offset for member, offset in spec["members"].items()
			if offset not in klass.fields}
		if missing:
			bad.append("%s - these member offsets were not recovered: %s" % (name,
				", ".join("%s=+%#x" % item for item in missing.items())))
		outside = [offset for offset in klass.fields if offset >= spec["size"]]
		if outside:
			bad.append("%s - offsets %s are outside the object (the source says %d bytes)"
				% (name, ", ".join(hex(o) for o in outside), spec["size"]))
		wrong = [(offset, klass.fields[offset].size) for offset in spec["members"].values()
			if offset in klass.fields and klass.fields[offset].size not in (0, 4)]
		if wrong:
			bad.append("%s - every member is 4 bytes, measured as: %s" % (name, wrong))
		# a pure slot: either claimed, or the limit is stated - never silently mislabelled
		pure = [item for item in klass.methods if item.kind == "pure"]
		if name == "CEntityBase" and not pure and not any(
				"pure" in note.lower() for note in klass.notes + klass.evidence):
			bad.append("CEntityBase::GetHealth is pure and the tool neither says so nor says "
				"it cannot tell")
		print("   %s: vftable %s %d slots, %d ctor(s), %d dtor(s), fields %s (source: %s)"
			% (name, hex(klass.vtable) if klass.vtable else "-", len(klass.methods),
				len(klass.constructors), len(klass.destructors),
				sorted(hex(offset) for offset in klass.fields),
				sorted(hex(offset) for offset in spec["members"].values())))
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


# --------------------------------------------------------------------------------------
# 3. one object, one name


def check_header(recovered: structures.Recovery) -> int:
	"""`decomp types --write` on a PE: the header has to be a real header."""
	bad: list[str] = []
	header = recovered.header()
	with tempfile.TemporaryDirectory() as directory:
		path = Path(directory) / "types.h"
		path.write_text(header)
		user = Path(directory) / "use.cpp"
		user.write_text('#include "types.h"\nint probe(CVehicleEntity *e) { return 0; }\n')
		proc = subprocess.run(["g++", "-std=c++17", "-I", directory, "-fsyntax-only",
			str(user)], capture_output=True, text=True)
		for name in ("CEntityBase", "CVehicleEntity", "CCharacterEntity"):
			if "class %s" % name not in header:
				bad.append("types.h has no `class %s`" % name)
		if "//   slot 0" not in header:
			bad.append("the header does not show the vtable in slot order, which is the one part "
				"of it a reader can check against the file")
		if "m_speed" in header or "m_health" in header:
			bad.append("the header names a member this model never recovers: only offsets are "
				"recovered, and they belong in comments, not as fields")
		print("   header: %d lines, %d classes; g++ -fsyntax-only -> %s"
			% (len(header.splitlines()),
				sum(1 for line in header.splitlines() if line.startswith("class ")),
				"ok" if proc.returncode == 0 else "failed"))
		if proc.returncode != 0:
			bad.append("the generated types.h does not compile: %s"
				% (proc.stderr.strip().splitlines()[:4] if proc.stderr.strip() else "no output"))
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


def check_names(recovered: structures.Recovery) -> int:
	"""`object_at` on the target side and `clean_symbol` on the candidate side have to agree."""
	bad: list[str] = []
	for name in ("CEntityBase", "CVehicleEntity", "CCharacterEntity"):
		klass = recovered.classes.get(name)
		if klass is None or klass.typeinfo is None:
			continue
		object_ = recovered.object_at(klass.typeinfo)
		if not object_ or object_["role"] != "typeinfo" or object_["name"] != (
				"typeinfo for %s" % name):
			bad.append("object_at(%s) for %s gave %r" % (hex(klass.typeinfo), name, object_))
			continue
		symbol = object_["mangled"]
		if not symbol.startswith("??_R0"):
			bad.append("%s: its type descriptor's decorated name was derived as %r"
				% (name, symbol))
		if normalize.canonical_name(symbol) != normalize.canonical_name(object_["name"]):
			bad.append("the decorated name %r and the RTTI name %r do not read the same"
				% (symbol, object_["name"]))
		if klass.vtable is not None:
			table = recovered.object_at(klass.vtable)
			if not table or table["role"] != "vtable" or table["name"] != ("vtable for %s"
					% name):
				bad.append("object_at(%s) for %s's vftable gave %r"
					% (hex(klass.vtable), name, table))
	# what a `.obj` really relocates against, read the same way
	for symbol, words in (
			("??_R0?AVCVehicleEntity@@@8", "typeinfo for CVehicleEntity"),
			("??_R1A@?0A@EA@CVehicleEntity@@8", "complete object locator for CVehicleEntity"),
			("??_7CVehicleEntity@@6B@", "vtable for CVehicleEntity"),
			("??_R3?AVCEntityBase@@8", "class hierarchy descriptor for CEntityBase")):
		got = normalize.clean_symbol(symbol)
		if normalize.canonical_name(got) != normalize.canonical_name(words):
			bad.append("clean_symbol(%r) = %r, expected %r" % (symbol, got, words))
	# an ordinary decorated function name is not an object and stays what it is
	if normalize.clean_symbol("?ClassifyEntity@CStructTests@@SAHPEAVCEntityBase@@@Z").startswith(
			("typeinfo", "vtable")):
		bad.append("a decorated function name was rewritten as an object name")
	print("   both sides name one descriptor: %s" % ", ".join(sorted({
		"%s / %s" % (normalize.msvc_type_symbol("typeinfo", info["mangled"]),
			"typeinfo for " + info["name"]) for info in recovered.typeinfos.values()
		if info.get("msvc") and info["name"] in CLASSES})))
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


def check_the_loop(cfg: dict, store: cache.Cache, recovered: structures.Recovery) -> int:
	"""The `dynamic_cast` unit, through `decomp try`. This is the unit MS-3 could not pass."""
	bad: list[str] = []
	units = {item["id"]: item for item in json.loads(
		(MSVC_BUILD.parent / "answer_key.json").read_text())["units"]}
	unit = units.get(RTTI_UNIT)
	if unit is None:
		print("   the answer key has no %s" % RTTI_UNIT)
		return 1
	meta = cache.meta(recovered.conn)
	row = cache.resolve_function(recovered.conn, hex(int(unit["address"])
		+ cache.address_offset(meta)))
	if not row:
		print("   %s is not in the analysis" % RTTI_UNIT)
		return 1
	outcome = cli.score_candidate(cfg, recovered.conn, meta, row[0],
		[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"],
		object_dir=store.root / "candidates-ms5")
	verdict = outcome["verdict"]
	outcome["object"].unlink(missing_ok=True)
	if verdict is None:
		bad.append("%s could not be scored: %s" % (RTTI_UNIT, outcome["error"]))
	elif not verdict.passed:
		bad.append("%s scores %.2f%% with %d relocation difference(s): both sides must name the "
			"same type descriptor" % (RTTI_UNIT, verdict.match_percent,
				verdict.categories["relocation"]))
	else:
		named = sorted({item["original"]["name"] for item in verdict.symbols if item["ok"]
			and item["original"]["kind"] != "function"})
		print("   %s: %s passes at %.2f%%, and both sides name %s"
			% (RTTI_UNIT, unit["name"], verdict.match_percent, ", ".join(named)))
		if not any(name.startswith("typeinfo for ") for name in named):
			bad.append("%s passes without naming a type descriptor on either side" % RTTI_UNIT)
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


# --------------------------------------------------------------------------------------
# 4. the same model at the size of a shipped 32-bit game


def check_real_target(store: cache.Cache) -> int:
	recovered = open_recovery(store, REAL_TARGET)
	if recovered is None:
		return 2       # not analysed here: measuring nothing, not a failure of the tool
	bad: list[str] = []
	summary = recovered.summary()
	if summary["abi"] != "msvc":
		bad.append("a shipped MSVC binary was read with the %s model" % summary["abi"])
	if summary["classes"] < 100:
		bad.append("only %d classes in a binary whose .data carries 770 type-name strings"
			% summary["classes"])
	nested = [name for name in summary["names"] if "::" in name]
	if not nested:
		bad.append("no nested name was decoded: MSVC writes `.?AUX@Y@@` innermost-first, and "
			"the scope form is what a reader can use")
	# a base relation the game really has (Havok's own root of its reference-counted objects)
	klass = recovered.classes.get("hkReferencedObject")
	if klass is None or "hkBaseObject" not in klass.bases:
		bad.append("hkReferencedObject: its base hkBaseObject was not recovered (%s)"
			% (klass.bases if klass else "no such class"))
	if klass is not None and klass.vtable is None:
		bad.append("hkReferencedObject has a type descriptor and no vftable")
	# 32-bit MSVC RTTI references itself by absolute address: check that the model says so
	if not any("absolute" in note for note in summary["notes"]):
		bad.append("the tool does not report that this binary's RTTI records are "
			"absolute-address referenced")
	templated = [name for name in summary["names"] if "$" in name]
	header = recovered.header()
	with tempfile.TemporaryDirectory() as directory:
		path = Path(directory) / "types.h"
		path.write_text(header)
		user = Path(directory) / "use.cpp"
		user.write_text('#include "types.h"\nint probe(hkReferencedObject *o) { return 0; }\n')
		proc = subprocess.run(["g++", "-std=c++17", "-I", directory, "-fsyntax-only",
			str(user)], capture_output=True, text=True)
		print("   %d classes, %d vftables; %d nested names (e.g. %s); %d template names kept as "
			"written; header %d lines, g++ -fsyntax-only -> %s"
			% (summary["classes"], summary["vtables"], len(nested),
				nested[0] if nested else "-", len(templated), len(header.splitlines()),
				"ok" if proc.returncode == 0 else "failed"))
		if proc.returncode != 0:
			bad.append("the generated types.h does not compile: %s"
				% proc.stderr.strip().splitlines()[:4])
	for line in bad:
		print("   FAIL %s" % line)
	recovered.conn.close()
	return 1 if bad else 0


def check_mingw_is_not_msvc(store: cache.Cache) -> int:
	"""A PE is not an MSVC target: what decides it is the compiler, not the container."""
	recovered = open_recovery(store, MINGW_TARGET)
	if recovered is None:
		return 2
	bad: list[str] = []
	summary = recovered.summary()
	if summary["abi"] != "itanium":
		bad.append("a MinGW-built PE was read with the %s model - it emits the Itanium type "
			"system, and Docs/MSVC-Plan.md §1 says not to call it MSVC" % summary["abi"])
	if not recovered.classes:
		bad.append("the Itanium model found nothing in a PE that has its RTTI in it")
	for name in ("CEntityBase", "CVehicleEntity", "CCharacterEntity"):
		klass = recovered.classes.get(name)
		if klass is None:
			bad.append("%s was not recovered from the MinGW build either" % name)
		elif name != "CEntityBase" and klass.bases != ["CEntityBase"]:
			bad.append("%s claims bases %s" % (name, klass.bases))
	print("   a PE built by %s: abi=%s, %d classes named the Itanium way"
		% (recovered.meta.get("variant_compiler"), summary["abi"], summary["classes"]))
	recovered.conn.close()
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


# --------------------------------------------------------------------------------------
# 5. and the opposite: a PE with no C++ type system in it


def check_no_rtti(cfg: dict) -> int:
	store = cache.Cache(config.cache_dir(cfg))
	recovered = open_recovery(store, NO_RTTI)
	if recovered is None:
		return 2
	bad: list[str] = []
	summary = recovered.summary()
	if summary["classes"]:
		bad.append("%d classes claimed for a binary that carries no `.?AV` type descriptor: any "
			"claim there would be invented" % summary["classes"])
	if not any("no MSVC RTTI" in note or "no `.?AV" in note for note in summary["notes"]):
		bad.append("the tool reports nothing at all instead of saying the file carries no RTTI")
	print("   notepad.exe: %d classes, and the reason is in the notes" % summary["classes"])
	recovered.conn.close()
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


if __name__ == "__main__":
	sys.exit(main())
