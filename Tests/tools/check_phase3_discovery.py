"""Phase 3 acceptance: does the tool find things, and does it know how the binary was built?

	run: .venv/bin/python Tests/tools/check_phase3_discovery.py

Two halves, both judged by the benchmark's own ground truth (Tests/build/<variant>/
answer_key.json and the source's own names), not by this tool's opinion.

1. **Detection** (`decomp detect`): the compiler, the object type, and the optimisation level.
   The first two are facts, so they are required exactly. The third is a ranked inference,
   so what is required is what the evidence can actually carry: at -O0 the answer must be
   exact and strongly separated, at -O2 the answer must at least be "not -O0" (measured:
   -O1/-O2/-O3 differ in ways a prologue does not show). The generated `project.toml` must
   parse and must not contradict the flags the variant was really built with.
2. **Discovery** (`decomp find`): string search reaches the unit that reads the string;
   `--family` from a name brings back the units of that family; a vtable's slots resolve to
   that class's own methods. A query that matches nothing must report nothing.

The sample for the -O inference is narrowed with the answer key's own address span: in the
statically linked -m32 build most of the image is glibc, built with someone else's flags.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import cache, cli, config, discover, extract, normalize, toolchain  # noqa: E402

VARIANTS = ["gcc-o0", "gcc-o2", "gcc-o0-x86"]
READERS: dict[str, set] = {}  # what reads the probe string, per build, for the cross-check below
# The unstripped build is analysed too, so the name/vtable half has ground truth to check
# against (a stripped binary has no names to find).
NAMED_BINARY = TESTS / "build" / "gcc-o0" / "da_tests"


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="check_phase3_discovery.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variants", default=",".join(VARIANTS))
	args = parser.parse_args(argv)

	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	failures = 0
	for variant in [item.strip() for item in args.variants.split(",") if item.strip()]:
		failures += check_detection(cfg, store, variant)
	READERS.clear()
	failures += check_search(store, "gcc-o0", stripped=True)
	failures += check_search(store, "gcc-o0", stripped=False)
	# the same query has to reach the same code in both builds of the same source: names are
	# what stripping takes away, reachability is not
	found = dict(READERS)
	for stripped in (True, False):
		found[stripped] = READERS.copy().get(stripped, set())
	if not found[True] or not found[False]:
		print("   FAIL a string query found no reader to cross-check")
		failures += 1
	elif found[True] != found[False]:
		print("   FAIL the stripped and named builds reached different code for the same string: %s"
			% sorted(map(hex, found[True] ^ found[False])))
		failures += 1
	else:
		print("cross-check: %r reaches the same %d function(s) in both builds: %s"
			% ("hello", len(found[True]), ", ".join(hex(a) for a in sorted(found[True]))))
	print("check_phase3_discovery: %s" % ("OK" if failures == 0 else "%d group(s) failed" % failures))
	return 0 if failures == 0 else 1


def open_cached(store: cache.Cache, path: Path, what: str):
	identity = cache.target_key(path)
	status = store.status(identity["key"])
	if not status.get("complete"):
		print("%s: not analysed - run: decomp analyze %s" % (what, path))
		return None
	return cache.open_readonly(Path(status["db"]))


# --------------------------------------------------------------------------------------
# 1. detection


def check_detection(cfg: dict, store: cache.Cache, variant: str) -> int:
	stripped = TESTS / "build" / variant / "da_tests.stripped"
	answer_path = TESTS / "build" / variant / "answer_key.json"
	build_path = TESTS / "build" / variant / "build.json"
	if not (stripped.is_file() and answer_path.is_file() and build_path.is_file()):
		print("%s: build it first (Tests/eval.py build --variant %s)" % (variant, variant))
		return 1
	answer = json.loads(answer_path.read_text())
	built = json.loads(build_path.read_text())
	units = answer["units"]
	# the program's own code, by the answer key: what the -O sample must be narrowed to
	low = min(int(item["address"]) for item in units)
	high = max(int(item["address"]) + int(item["size"]) for item in units)

	bad = []
	outcome = cli.detect_target(stripped, range_text="0x%x-0x%x" % (low, high))
	note, guess = outcome["note"], outcome["guess"]
	want_bits = 32 if variant.endswith("-x86") else 64
	want_compiler = "gcc"
	facts = {
		"compiler": (note.get("compiler"), want_compiler),
		"bits": (note.get("bits"), want_bits),
		"static": (bool(note.get("static")), variant.endswith("-x86")),
		"pie": (bool(note.get("pie")), not variant.endswith("-x86")),
	}
	for name, (got, want) in facts.items():
		if got != want:
			bad.append("%s: detected %s=%r, the build says %r" % (variant, name, got, want))

	std = [flag for flag in built["flags"] if flag.startswith("-std=")]
	flags = [std[0] if std else "-std=c++17", "-O%d" % _flag_level(built["flags"])]
	if want_bits == 32:
		flags.append("-m32")
	written = toolchain.starter_config(stripped, note, guess)
	import tomllib

	try:
		parsed = tomllib.loads(written)
		table = parsed["variants"][toolchain.variant_name(note, guess["optimize"] if guess else 0)]
		produced = toolchain.build_flags(dict(table, std=parsed["std"]))
	except Exception as exc:  # noqa: BLE001 - the config not loading is the failure
		bad.append("%s: the config `detect` wrote does not work: %s" % (variant, exc))
		produced = []
	missing = [flag for flag in flags if flag not in produced]
	if missing:
		bad.append("%s: the config it wrote would build with %s, missing %s (the variant used %s)"
			% (variant, produced, missing, built["flags"]))

	got_level = guess["optimize"] if guess else None
	exact = _flag_level(built["flags"])
	print("%s: detected %s %s-bit %s%s built by %s %s; variant %s -> %s"
		% (variant, note.get("format"), note.get("bits"),
			"static" if note.get("static") else "dynamic",
			" PIE" if note.get("pie") else "", note.get("compiler"),
			note.get("compiler_version"), toolchain.variant_name(note, got_level), produced))
	if guess is None:
		bad.append("%s: no -O guess at all (%s)" % (variant, outcome["problems"]))
	elif exact == 0:
		# at -O0 the answer has to be exact: an -O0 body is unmistakable
		if got_level != 0:
			bad.append("%s: built -O0, the inference said -O%s" % (variant, got_level))
		if guess.get("margin", 0.0) < 0.5:
			bad.append("%s: the -O0 answer is not separated from the next candidate (margin %.3f)"
				% (variant, guess.get("margin", 0.0)))
	else:
		# what the evidence carries: "this is optimised code", and never -O0
		profile = outcome["profile"]
		worst = max(outcome["ranked"], key=lambda item: item["distance"])
		if got_level == 0:
			bad.append("%s: built -O%d, the inference said -O0" % (variant, exact))
		if worst["optimize"] != 0:
			bad.append("%s: an -O%d build did not rank -O0 (the frame-pointer shape) last: it "
				"ranked -O%d worst" % (variant, exact, worst["optimize"]))
		if profile.get("frame", 0.0) > 0.2 or profile.get("spill", 0.0) > 0.2:
			bad.append("%s: an optimised build profiled with a %d%% frame-pointer share"
				% (variant, round(profile.get("frame", 0.0) * 100)))
	for line in outcome["problems"]:
		print("   note %s" % line)
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


def _flag_level(flags: list[str]) -> int:
	for flag in flags:
		if flag.startswith("-O") and flag[2:].isdigit():
			return int(flag[2:])
	return 0


# --------------------------------------------------------------------------------------
# 2. discovery


def check_search(store: cache.Cache, variant: str, stripped: bool) -> int:
	"""Name/string/xref/vtable queries, judged by the answer key and the source's own names.

	A stripped binary has no names to find, so the name-based half is only required of the
	build that has symbols; what IS required of both is that the same query reaches the same
	address in each - the name is what stripping takes away, not the reachability.
	"""
	path = (TESTS / "build" / variant / ("da_tests.stripped" if stripped else "da_tests"))
	label = "%s %s" % (variant, "stripped" if stripped else "with symbols")
	conn = open_cached(store, path, label)
	if conn is None:
		return 1
	answer = json.loads((TESTS / "build" / variant / "answer_key.json").read_text())
	meta = cache.meta(conn)
	offset = int(meta.get("address_offset") or 0)
	units = {int(item["address"]) + offset: item for item in answer["units"]}
	bits = 32 if ":32:" in (meta.get("language_id") or "") else 64
	bad = []
	try:
		# (a) a string search reaches the code that reads it, in the same place either way
		hits = discover.search(conn, meta, "hello", 20)
		readers = {}
		for address in discover.addresses_named(conn, hits):
			for group in discover.xrefs(conn, [address], 20):
				readers[group["entry"]] = group["name"]
		named = [name for address, name in readers.items() if not normalize.is_synthetic(name)]
		print("%s: string \"hello\" -> %d string hits, read by %s"
			% (label, len(hits["strings"]),
				", ".join("%s @ %s" % (name, hex(entry - offset))
					for entry, name in sorted(readers.items())) or "nobody"))
		if not readers:
			bad.append("%s: searching a string the program contains reached no function" % label)
		if stripped and named:
			bad.append("%s: a stripped target reported real names (%s)" % (label, named))
		if not stripped and not named:
			bad.append("%s: a target with symbols reached only names Ghidra invented" % label)
		READERS[stripped] = {entry - offset for entry in readers}

		# (b) a family query brings back the units of that family (needs names to seed it)
		if not stripped:
			wanted = {item["name"].split("(")[0].split("::")[-1]
				for item in answer["units"] if "Vehicle" in item["name"]}
			hits = discover.search(conn, meta, "Vehicle", 200)
			seeds = [int(row["id"]) for row in hits["functions"]]
			group = discover.family(conn, seeds, hops=2, limit=120)
			got = {row["name"].split("(")[0].split("::")[-1] for row in group["members"]}
			found = {name for name in wanted if name in got}
			print("%s: family \"Vehicle\" -> %d seeded, %d members; found %d/%d vehicle units: %s"
				% (label, len(seeds), len(group["members"]), len(found), len(wanted),
					", ".join(sorted(found)) or "none"))
			if wanted - found:
				bad.append("%s: --family missed the units %s" % (label, ", ".join(sorted(wanted - found))))
			if not group["shared"]:
				bad.append("%s: the vehicle group reported no shared object (its vtables are shared)"
					% label)
		else:
			# no names to seed with: seed from what the string search reached
			group = discover.family(conn, [row["id"] for row in
				cache.resolve_function(conn, hex(max(readers))) if readers], hops=1, limit=20)
			print("%s: family from the string's reader -> %d members" % (label, len(group["members"])))
			if readers and not group["members"]:
				bad.append("%s: --family from a real seed returned nothing" % label)

		# (c) a vtable: its slots resolve to that class's own methods, and its methods to it
		image = extract.TargetImage(path, offset)
		candidates = [row for row in cache.symbol_rows(conn, "_ZTV", [], 40)
			if not image.error and int(row["address"]) >= int(meta["image_base"])]
		# the class with the most methods: an abstract base has pure-virtual slots the file
		# leaves empty, and that is a property of the class, not of the query
		tried = []
		for row in candidates[:12]:
			found = discover.table(conn, image, int(row["address"]), bits=bits)
			methods = [slot["target"] for slot in found["slots"]
				if slot["target"]["kind"] == "function"]
			tried.append((len(methods), found, row, _class_of(row["name"])))
		tried.sort(key=lambda item: -item[0])
		table, cls, row_used = (tried[0][1], tried[0][3], tried[0][2]) if tried and tried[0][0] else \
			(None, "", None)
		if table is None and tried:
			table, cls, row_used = None, "", None
		if table is None:
			print("%s: no vtable with method slots (%d _ZTV symbols%s)"
				% (label, len(candidates), ", image: " + image.error if image.error else ""))
			if not stripped:
				bad.append("%s: an analysis of a binary with vtables found no slots in any of them"
					% label)
		else:
			methods = [slot["target"] for slot in table["slots"] if slot["target"]["kind"] == "function"]
			if len(methods) < 2:
				bad.append("%s: the richest vtable (%s) yielded only %d method slot(s)"
					% (label, row_used["name"], len(methods)))
			print("%s: vtable %s at %s -> %d slots: %s"
				% (label, row_used["name"], hex(int(row_used["address"])), table["count"],
					", ".join(item["name"] for item in methods[:4]) or "none"))
			# a slot may hold an inherited method (the base's implementation, when the class
			# does not override it), but the table must contain its own class's methods
			own = [item["name"] for item in methods if cls in item["name"]]
			if not own:
				bad.append("%s: the slots of %s name none of its own methods: %s"
					% (label, row_used["name"], [item["name"] for item in methods]))
			first = cache.function_at(conn, int(methods[0]["address"])) if methods else None
			peers = discover.members_of(conn, image, int(first["id"]), int(first["entry"]),
				bits=bits) if first else []
			if methods:
				print("%s: the same vtable as %s also holds %d other methods"
					% (label, methods[0]["name"], len(peers)))
				if len(peers) + 1 < len(methods):
					bad.append("%s: found %d of the %d methods of %s through their vtable"
						% (label, len(peers) + 1, len(methods), cls))

		# (d) nothing must be reported as nothing
		empty = discover.search(conn, meta, "zz-not-a-name-at-all", 10)
		if any(empty[key] for key in ("functions", "strings", "symbols")):
			bad.append("%s: a query that matches nothing reported something" % label)
	finally:
		conn.close()
	for line in bad:
		print("   FAIL %s" % line)
	return 1 if bad else 0


def _class_of(vtable_symbol: str) -> str:
	"""`_ZTV16CCharacterEntity` -> `CCharacterEntity` (the mangled length prefix)."""
	name = vtable_symbol[len("_ZTV"):]
	digits = ""
	for char in name:
		if not char.isdigit():
			break
		digits += char
	return name[len(digits):len(digits) + int(digits)] if digits else name


if __name__ == "__main__":
	sys.exit(main())
