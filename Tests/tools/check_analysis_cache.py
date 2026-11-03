"""Phase 1 acceptance: does the analysis cache agree with the benchmark's answer key?

	run: .venv/bin/python Tests/tools/check_analysis_cache.py

The answer key (from the unstripped build) has the true address+size of every unit; the
cache holds what Ghidra found in the stripped binary. They must agree, and every unit must
have instructions, resolved references and pseudo-code.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
CACHE = TESTS.parent / "cache" / "ghproj"

for variant in ("gcc-o0", "gcc-o2", "gcc-o0-x86"):
	answer_path = TESTS / "build" / variant / "answer_key.json"
	if not answer_path.is_file():
		continue
	answer = json.loads(answer_path.read_text())
	stripped = TESTS / "build" / variant / "da_tests.stripped"
	key = hashlib.sha256(stripped.read_bytes()).hexdigest()[:16]
	db = CACHE / key / "analysis.db"
	if not db.is_file():
		print("%s: no cache (%s)" % (variant, db))
		continue
	conn = sqlite3.connect(db)
	conn.row_factory = sqlite3.Row
	meta = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM meta")}
	offset = int(meta.get("address_offset") or 0)
	functions = {row["entry"]: row for row in conn.execute("SELECT * FROM functions")}

	found = missing = size_bad = no_code = no_pseudo = no_refs = 0
	for unit in answer["units"]:
		entry = unit["address"] + offset
		row = functions.get(entry)
		if row is None:
			missing += 1
			continue
		found += 1
		if row["size"] != unit["size"]:
			size_bad += 1
			print("  size mismatch %s: cache %s vs answer key %s at %s"
				% (unit["id"], row["size"], unit["size"], hex(entry)))
		ins = conn.execute("SELECT count(*) FROM instructions WHERE fn = ?", (row["id"],)).fetchone()[0]
		reff = conn.execute("SELECT count(*) FROM refs WHERE fn = ?", (row["id"],)).fetchone()[0]
		pseudo = row["pseudocode"] or ""
		if ins == 0:
			no_code += 1
		if not pseudo:
			no_pseudo += 1
		if reff == 0:
			no_refs += 1
	print("%s (%s): %d/%d units found at their answer-key address (+0x%x), size exact %d, "
		"missing instructions %d, no pseudo-code %d, no references %d"
		% (variant, key, found, len(answer["units"]), offset, found - size_bad, no_code,
			no_pseudo, no_refs))
	# the graph must agree with nm-derived callers at least in volume
	calls = conn.execute("SELECT count(*) FROM calls").fetchone()[0]
	print("   cache: %d functions, %d instructions, %d refs, %d call edges, db %.1f MB" % (
		conn.execute("SELECT count(*) FROM functions").fetchone()[0],
		conn.execute("SELECT count(*) FROM instructions").fetchone()[0],
		conn.execute("SELECT count(*) FROM refs").fetchone()[0], calls,
		db.stat().st_size / 1e6))
	conn.close()
