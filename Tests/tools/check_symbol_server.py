"""`decomp symbols` acceptance: the symbol-server key, and reading a PDB's own identity.

	run: .venv/bin/python Tests/tools/check_symbol_server.py [--offline]

No group here needs the network except the last one, and that one runs on the copy already in
the store. What is checked:

1. **the key is spelled the way the server indexes it.** GUID upper case with no dashes, the age
   in *hex* (age 10 must come out `…A`, not `…10`), and the bare PDB file name for images whose
   CodeView record carries the path the link ran with.
2. **the identity is the one `detect` printed.** `symbols.codeview()` reads the same debug
   directory as `toolchain.build_note()`, so the URL fetched cannot drift from the URL reported.
3. **a file that asks for nothing says so.** An ELF, and a PE with no CodeView record, are named
   answers, not tracebacks.
4. **the PDB is checked from its own bytes.** Its stream 1 carries the GUID and the link
   timestamp that has to equal the image's `TimeDateStamp`; the stream directory is found even
   though this file's directory is one block below the address its superblock gives; and the age
   difference is reported as a note, never as a mismatch.

Exit: 0 all passed, 1 something came out wrong, 2 a target this needs is absent - which is not a
failure of the tool.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from decomp import symbols, toolchain  # noqa: E402

TARGET = ROOT / "Tests/Proprietary/notepad.exe"

failures: list[str] = []
notes: list[str] = []


def check(label: str, got, want) -> None:
	if got != want:
		failures.append("%s: got %r, want %r" % (label, got, want))
	else:
		print("  ok   %s = %r" % (label, got))


def note(label: str, value) -> None:
	notes.append("%s: %s" % (label, value))
	print("  note %s: %s" % (label, value))


def key_spelling() -> None:
	print("1. the key the server indexes")
	guid = "5c1bb141-8276-e6c4-c297-fcbaec420f58"
	check("age 1", toolchain.symbol_server_key(guid, 1), "5C1BB1418276E6C4C297FCBAEC420F581")
	check("age 10 is hex", toolchain.symbol_server_key(guid, 10)[-1], "A")
	check("bare name", toolchain.pdb_name("c:\\bcg\\deadrising\\build\\pc\\deadrising2.pdb"),
		"deadrising2.pdb")
	check("url uses the bare name",
		toolchain.symbol_server_url("c:\\a\\b\\x.pdb", guid, 1),
		"https://msdl.microsoft.com/download/symbols/x.pdb/%s/x.pdb"
		% toolchain.symbol_server_key(guid, 1))
	where = symbols.stored_at("cache/symbols", {"name": "c:\\a\\b\\x.pdb", "guid": guid, "age": 1})
	check("store path", str(where).replace("\\", "/"),
		"cache/symbols/x.pdb/%s/x.pdb" % toolchain.symbol_server_key(guid, 1))


def identity_matches_detect() -> None:
	print("2. the identity `detect` reports and the identity fetched are one record")
	record = symbols.codeview(TARGET)
	note_from_build = toolchain.build_note(TARGET)["pdb"]
	for field in ("name", "guid", "age", "symbols_url"):
		check("codeview.%s == detect's pdb.%s" % (field, field), record[field],
			note_from_build[field])
	check("image timestamp", record["image_timestamp"], 2638686146)


def files_that_ask_for_nothing() -> None:
	print("3. no CodeView record is an answer, not a traceback")
	for target in sorted(Path("/bin").glob("ls")):
		try:
			symbols.codeview(target)
			failures.append("%s: expected SymbolError" % target)
		except symbols.SymbolError as exc:
			check("%s refused" % target.name, "not a PE" in str(exc), True)
	for candidate in ("Tests/build/mingw-o0", "Tests/build/msvc-o0"):
		directory = ROOT / candidate
		if not directory.is_dir():
			continue
		for binary in sorted(directory.glob("*.stripped"))[:1]:
			try:
				record = symbols.codeview(binary)
				note("%s has a CodeView record" % binary.name, record["name"])
			except symbols.SymbolError as exc:
				note("%s: %s" % (binary.name, exc), "no symbols to ask for")


def pdb_identity_is_read_from_the_file() -> None:
	print("4. the PDB's own identity, out of its own bytes")
	record = symbols.codeview(TARGET)
	stored = symbols.stored_at(ROOT / symbols.DEFAULT_STORE, record)
	if not stored.is_file():
		print("  skip %s is not in the store (run: decomp symbols %s)" % (stored, TARGET))
		return
	identity = symbols.pdb_identity(stored)
	check("guid", symbols._flat(identity["guid"]), symbols._flat(record["guid"]))
	check("link timestamp == the image's TimeDateStamp", identity["link_timestamp"],
		record["image_timestamp"])
	check("MSF format version", identity["format_version"], 20000404)
	match = symbols.check(record, identity)
	check("match.guid", match["guid"], True)
	check("match.link_timestamp", match["link_timestamp"], True)
	# A shipped PDB is rewritten after the link, so its header age is larger than the key's.
	# That must not read as a mismatch, and the printed answer must not claim one.
	printed = "\n".join(symbols.lines({"target": str(TARGET), "pdb": record,
		"path": str(stored), "url": record["symbols_url"], "bytes": identity["bytes"],
		"source": "already in the store", "identity": identity, "match": match}))
	check("the age difference is a note, not a mismatch",
		("not a mismatch" in printed, "does NOT" in printed), (True, False))
	if identity["age"] != record["age"]:
		note("header age vs the key's age", "%d vs %d" % (identity["age"], record["age"]))


def fetched_once() -> None:
	print("5. one request, then the store answers it")
	if "--offline" in sys.argv:
		print("  skip --offline")
		return
	result = symbols.fetch(TARGET, ROOT / symbols.DEFAULT_STORE)
	check("source", result["source"] in ("fetched", "already in the store"), True)
	check("bytes", result["bytes"], 249856)
	check("match", result["match"]["guid"] and result["match"]["link_timestamp"], True)
	again = symbols.fetch(TARGET, ROOT / symbols.DEFAULT_STORE)
	check("second call reads the store", again["source"], "already in the store")
	check("and gets the same identity", again["identity"]["guid"], result["identity"]["guid"])
	# A target Microsoft has no symbols for is a miss named with the URL, not a crash.
	other = ROOT / "Tests/Proprietary/deadrising2.exe"
	if other.is_file():
		try:
			symbols.fetch(other, ROOT / symbols.DEFAULT_STORE)
			note("deadrising2.pdb", "served after all")
		except symbols.SymbolError as exc:
			check("a miss names the URL", "msdl.microsoft.com" in str(exc), True)


def main() -> int:
	if not TARGET.is_file():
		print("no such target: %s" % TARGET)
		return 2
	for group in (key_spelling, identity_matches_detect, files_that_ask_for_nothing,
			pdb_identity_is_read_from_the_file, fetched_once):
		group()
	print()
	for line in notes:
		print("  %s" % line)
	if failures:
		print("\n%d FAILED:" % len(failures))
		for line in failures:
			print("  %s" % line)
		return 1
	print("all groups passed")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
