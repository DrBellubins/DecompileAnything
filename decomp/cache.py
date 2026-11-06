"""The analysis cache: one SQLite file per analysed binary.

	<cache_dir>/<key>/analysis.db    the facts every command except `analyze` reads
	<cache_dir>/<key>/target.gpr     the Ghidra project, so a re-export never re-analyses

`key` is a content hash of the target, so the cache follows the binary and not the file
name. Writing is one transaction whose last statement records `complete`, which makes a
half-written cache impossible to mistake for a usable one. This is what keeps the CLI
stateless and fast: `show`/`find` open the db, they never start a JVM.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import time
from pathlib import Path

from .config import ConfigError

# Bump when the schema or the exported fields change: an old cache is then rebuilt instead
# of silently read (it is recorded in every analysis.db).
CACHE_VERSION = 2

DB_NAME = "analysis.db"
PROJECT_NAME = "target"
PROGRAM_NAME = "program"

SCHEMA_TABLES = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE sections (
	name TEXT, start INTEGER, end INTEGER, executable INTEGER, writable INTEGER, initialized INTEGER);

CREATE TABLE symbols (
	address INTEGER, name TEXT, type TEXT, source TEXT, namespace TEXT, section TEXT);

CREATE TABLE strings (
	address INTEGER, section TEXT, value TEXT, length INTEGER);

CREATE TABLE functions (
	id INTEGER PRIMARY KEY,
	name TEXT, namespace TEXT, entry INTEGER, size INTEGER, section TEXT,
	kind TEXT,                       -- function | thunk
	thunk_target TEXT, signature TEXT, return_type TEXT, params TEXT,
	tags TEXT, comment TEXT,
	bytes BLOB, ranges TEXT,         -- ranges: JSON [[start, end), ...] for multi-range bodies
	pseudocode TEXT, decompile_error TEXT);

CREATE TABLE instructions (
	fn INTEGER REFERENCES functions(id) ON DELETE CASCADE,
	address INTEGER, length INTEGER, mnemonic TEXT, text TEXT, bytes BLOB, comment TEXT);

CREATE TABLE refs (
	fn INTEGER REFERENCES functions(id) ON DELETE CASCADE,
	address INTEGER,                 -- instruction the reference comes from
	to_address INTEGER, to_name TEXT, to_kind TEXT, section TEXT,
	ref_type TEXT, source_type TEXT, is_call INTEGER, is_data INTEGER, operand_index INTEGER);

CREATE TABLE calls (
	caller INTEGER REFERENCES functions(id) ON DELETE CASCADE,
	callee INTEGER REFERENCES functions(id) ON DELETE CASCADE,
	site INTEGER);

-- The function table the *file* carries, in the analysis' addresses: for an x64 PE this is
-- `.pdata`, the unwind table, which names every unit's begin/end with no symbols and after
-- stripping (Docs/MSVC-Plan.md §4). It is kept beside the Ghidra ranges rather than replacing
-- them so the two can be compared; where they differ the table wins for a unit's extent
-- (`extract.original_function`) and the disagreement is reported.
CREATE TABLE units (
	source TEXT,                    -- '.pdata' today; an ELF symbol table would be another
	entry INTEGER, end INTEGER, size INTEGER,
	unwind INTEGER,                 -- the unwind record, where the format gives one
	section TEXT);
"""

# The match ledger (Docs/byte-cleanup-plan.md, Phase 5): the pairs the tool has already been
# *shown*, by a unit that passed the gate. One row per (variant, entity, candidate symbol):
# the entity at `entry` in the original's addresses is reproduced by `candidate` in a candidate
# object built with `variant`'s flags.
#
# It is what lets a later unit be scored against something the loop already identified: a call to
# an anonymous helper in a stripped binary is the same call in every candidate that reaches it, so
# once one unit has proven which symbol it is, the next one is not free to call it something else.
#
# A separate statement rather than part of `SCHEMA`'s body because caches written before Phase 5 do
# not have it and are still usable: read paths check `has_table`, the write path adds it
# (`ensure_matches`) - the same way the `units` table was added without rebuilding every analysis.
MATCHES_DDL = """
CREATE TABLE IF NOT EXISTS matches (
	variant TEXT,
	entry INTEGER,                   -- the entity's address in the original
	kind TEXT,                       -- function | external | data
	candidate TEXT,                  -- the symbol name in the candidate object
	evidence TEXT,                   -- what proved the pair (name | string | bytes | object | ledger)
	tier TEXT,                       -- the tier of the unit that proved it
	unit TEXT,                       -- that unit's name
	unit_entry INTEGER,              -- ... and its address
	at TEXT,                         -- the date it was recorded
	PRIMARY KEY (variant, entry, candidate));
"""
MATCHES_INDEX = "CREATE INDEX IF NOT EXISTS i_matches_entry ON matches(entry);"

SCHEMA_INDEXES = """
CREATE INDEX i_functions_entry ON functions(entry);
CREATE INDEX i_functions_name ON functions(name);
CREATE INDEX i_instructions_fn ON instructions(fn);
CREATE INDEX i_refs_fn ON refs(fn);
CREATE INDEX i_refs_to ON refs(to_address);
CREATE INDEX i_calls_caller ON calls(caller);
CREATE INDEX i_calls_callee ON calls(callee);
CREATE INDEX i_symbols_address ON symbols(address);
CREATE INDEX i_units_entry ON units(entry);
CREATE INDEX i_strings_address ON strings(address);
"""

SCHEMA = SCHEMA_TABLES + MATCHES_DDL + MATCHES_INDEX + SCHEMA_INDEXES


def target_key(path: Path) -> dict:
	"""Content identity of a target: {key, sha256, size}. The whole file is hashed - on the
	sizes this tool sees (a few MB) it costs milliseconds and it is exact."""
	digest = hashlib.sha256()
	size = 0
	try:
		with path.open("rb") as handle:
			for chunk in iter(lambda: handle.read(1024 * 1024), b""):
				digest.update(chunk)
				size += len(chunk)
	except OSError as exc:
		raise ConfigError("cannot read %s: %s" % (path, exc)) from exc
	sha = digest.hexdigest()
	return {"key": sha[:16], "sha256": sha, "size": size}


class Cache:
	def __init__(self, root: Path) -> None:
		self.root = Path(root)

	def entry(self, key: str) -> Path:
		return self.root / key

	def has_project(self, key: str) -> bool:
		return (self.entry(key) / (PROJECT_NAME + ".gpr")).is_file()

	def db_path(self, key: str) -> Path:
		return self.entry(key) / DB_NAME

	def status(self, key: str) -> dict:
		"""What is cached for this key, or {"complete": 0} when there is nothing usable."""
		path = self.db_path(key)
		if not path.is_file():
			return {"complete": 0, "db": str(path)}
		try:
			conn = open_readonly(path)
		except sqlite3.Error:
			return {"complete": 0, "db": str(path)}
		try:
			try:
				values = meta(conn)
			except sqlite3.Error:
				# not every directory under the cache root is an analysis: `try` writes candidate
				# objects (and a scratch database) into candidates/, and a directory holding one is
				# not a target. Report it as unusable rather than raising through `targets()`.
				return {"complete": 0, "db": str(path), "reason": "not an analysis database"}
			if values.get("cache_version") != str(CACHE_VERSION):
				return {"complete": 0, "db": str(path), "reason": "written by an older cache version"}
			values["complete"] = int(values.get("complete") == "1")
			values["db"] = str(path)
			return values
		finally:
			conn.close()

	def reset(self, key: str) -> Path:
		"""Throw away everything cached for a key (`analyze --force`)."""
		entry = self.entry(key)
		if entry.exists():
			shutil.rmtree(entry)
		entry.mkdir(parents=True, exist_ok=True)
		return entry

	def targets(self) -> list[dict]:
		"""Every complete cached target, newest first."""
		found = []
		if not self.root.is_dir():
			return found
		for directory in sorted(self.root.iterdir()):
			if not directory.is_dir():
				continue
			values = self.status(directory.name)
			if values.get("complete"):
				found.append(values)
		found.sort(key=lambda v: v.get("analyzed_at_epoch", "0"), reverse=True)
		return found

	def resolve(self, target: Path | None, key: str | None) -> dict:
		"""Pick which cached analysis to read. Explicit key, explicit target, or the only one."""
		if key:
			values = self.status(key)
			if not values.get("complete"):
				raise ConfigError("no complete analysis cached for key %r - run: decomp analyze <bin>" % key)
			return values
		if target is not None:
			values = self.status(target_key(target)["key"])
			if not values.get("complete"):
				raise ConfigError(
					"%s (%s) is not analysed yet - run: decomp analyze %s"
					% (target, values.get("size", "?"), target))
			return values
		found = self.targets()
		if not found:
			raise ConfigError("no analysis cached in %s - run: decomp analyze <bin>" % self.root)
		if len(found) > 1:
			raise ConfigError("more than one target is cached, pass --bin <file> or --key <key>:\n  "
				+ "\n  ".join("%s  %s (variant %s)" % (values.get("target_key", "?"),
					values.get("target_path", "?"), values.get("variant", "?")) for values in found))
		return found[0]


def open_readonly(path: Path) -> sqlite3.Connection:
	conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
	conn.row_factory = sqlite3.Row
	return conn


def create(path: Path) -> sqlite3.Connection:
	conn = sqlite3.connect(path)
	conn.row_factory = sqlite3.Row
	conn.execute("PRAGMA foreign_keys = ON")
	conn.executescript(SCHEMA)
	return conn


def write(conn: sqlite3.Connection, analysis: dict) -> None:
	"""Store one exported analysis. `analysis` is what decomp.ghidra.export() returns."""
	with conn:
		for section in analysis.get("sections", []):
			conn.execute("INSERT INTO sections VALUES (?,?,?,?,?,?)", (
				section["name"], section["start"], section["end"],
				int(section["executable"]), int(section["writable"]), int(section["initialized"])))
		for symbol in analysis.get("symbols", []):
			conn.execute("INSERT INTO symbols VALUES (?,?,?,?,?,?)", (
				symbol["address"], symbol["name"], symbol["type"], symbol["source"],
				symbol["namespace"], symbol["section"]))
		for string in analysis.get("strings", []):
			conn.execute("INSERT INTO strings VALUES (?,?,?,?)", (
				string["address"], string["section"], string["value"], string["length"]))
		ids = []
		for function in analysis["functions"]:
			cursor = conn.execute(
				"INSERT INTO functions (name, namespace, entry, size, section, kind, thunk_target, signature,"
				" return_type, params, tags, comment, bytes, ranges, pseudocode, decompile_error)"
				" VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
					function["name"], function.get("namespace", ""), function["entry"], function["size"],
					function.get("section", ""), function.get("kind", "function"), function.get("thunk_target"),
					function.get("signature"), function.get("return_type"),
					json.dumps(function.get("params", [])), " ".join(function.get("tags", [])),
					function.get("comment"), function.get("bytes", b""), json.dumps(function.get("ranges", [])),
					function.get("pseudocode"), function.get("decompile_error")))
			ids.append(cursor.lastrowid)
		for index, function in enumerate(analysis["functions"]):
			fn = ids[index]
			for instruction in function.get("instructions", []):
				conn.execute("INSERT INTO instructions VALUES (?,?,?,?,?,?,?)", (
					fn, instruction["address"], instruction["length"], instruction["mnemonic"],
					instruction["text"], instruction.get("bytes", b""), instruction.get("comment")))
			for ref in function.get("refs", []):
				conn.execute("INSERT INTO refs VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
					fn, ref["address"], ref["to_address"], ref["to_name"], ref["to_kind"], ref.get("section"),
					ref["ref_type"], ref.get("source_type"), int(ref.get("is_call", 0)),
					int(ref.get("is_data", 0)), ref.get("operand_index", 0)))
			for call in function.get("calls", []):
				conn.execute("INSERT INTO calls VALUES (?,?,?)", (
					ids[call["caller"]], ids[call["callee"]], call.get("site")))
		for unit in analysis.get("units", []):
			conn.execute("INSERT INTO units VALUES (?,?,?,?,?,?)", (
				unit["source"], unit["entry"], unit["end"], unit["size"],
				unit.get("unwind") or 0, unit.get("section", "")))
		for key, value in analysis.get("meta", {}).items():
			conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))
		# last, so a cache is either complete or absent
		conn.execute("INSERT OR REPLACE INTO meta VALUES ('complete','1')")
		conn.execute("INSERT OR REPLACE INTO meta VALUES ('analyzed_at_epoch',?)", (str(int(time.time())),))


# --------------------------------------------------------------------------------------
# reading


def meta(conn: sqlite3.Connection) -> dict:
	return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}


def address_offset(meta: dict) -> int:
	"""The Ghidra-to-file address offset an analysis recorded, 0 when it did not record one.

	`meta` values come back as strings (`write` stores `str(value)`), so an analysis made
	before a format could answer the question holds the text "None" and `int()` of it raises in
	the middle of an otherwise working command. A PE always resolves to 0 - Ghidra loads the
	image at its own image base - and that is an answer, not a missing one.
	"""
	try:
		return int(meta.get("address_offset"))
	except (TypeError, ValueError):
		return 0


def has_table(conn: sqlite3.Connection, name: str) -> bool:
	"""Does this cache have a table at all? Caches written before a field was added do not, and
	saying so beats raising: the analyses already on disk predate MS-1."""
	return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)) \
		.fetchone() is not None


def counts(conn: sqlite3.Connection) -> dict:
	tables = ["functions", "instructions", "refs", "symbols", "strings", "sections", "calls"]
	if has_table(conn, "units"):
		tables.append("units")
	out = {name: conn.execute("SELECT count(*) FROM %s" % name).fetchone()[0] for name in tables}
	if has_table(conn, "matches"):
		out["matches"] = conn.execute("SELECT count(*) FROM matches").fetchone()[0]
	out["bodies"] = conn.execute("SELECT count(*) FROM functions WHERE kind='function'").fetchone()[0]
	out["thunks"] = conn.execute("SELECT count(*) FROM functions WHERE kind='thunk'").fetchone()[0]
	out["with_pseudocode"] = conn.execute(
		"SELECT count(*) FROM functions WHERE pseudocode IS NOT NULL AND pseudocode <> ''").fetchone()[0]
	out["code_bytes"] = conn.execute("SELECT ifnull(sum(size),0) FROM functions").fetchone()[0]
	return out


def find(conn: sqlite3.Connection, query: str, limit: int = 40, alt: list[int] | None = None) -> dict:
	"""Name, address and string search over the cached analysis.

	`alt` holds the same address in other address domains (see the address offset in meta).
	(`decomp find` grows xref and vtable queries in Phase 3; this is the part of it that is
	a plain cache lookup.)
	"""
	numeric = None
	text = query.strip()
	if text.lower().startswith("0x"):
		try:
			numeric = int(text, 16)
		except ValueError:
			pass
	pattern = "%" + text + "%"
	addresses = [a for a in ([numeric] if numeric is not None else []) + list(alt or []) if a is not None]
	columns = "SELECT id, name, entry, size, kind, section FROM functions"
	if addresses:
		marks = ",".join("?" * len(addresses))
		functions = conn.execute(
			"%s WHERE name LIKE ? OR entry IN (%s) ORDER BY entry LIMIT ?" % (columns, marks),
			[pattern] + addresses + [limit]).fetchall()
		strings = conn.execute(
			"SELECT address, section, value FROM strings WHERE value LIKE ? OR address IN (%s)"
			" ORDER BY address LIMIT ?" % marks, [pattern] + addresses + [limit]).fetchall()
		touching = conn.execute(
			"SELECT DISTINCT f.id, f.name, f.entry, r.to_name, r.to_address FROM refs r"
			" JOIN functions f ON f.id = r.fn WHERE r.to_name LIKE ? OR r.to_address IN (%s)"
			" ORDER BY f.entry LIMIT ?" % marks, [pattern] + addresses + [limit]).fetchall()
	else:
		functions = conn.execute("%s WHERE name LIKE ? ORDER BY entry LIMIT ?" % columns,
			(pattern, limit)).fetchall()
		strings = conn.execute("SELECT address, section, value FROM strings WHERE value LIKE ?"
			" ORDER BY address LIMIT ?", (pattern, limit)).fetchall()
		touching = conn.execute(
			"SELECT DISTINCT f.id, f.name, f.entry, r.to_name, r.to_address FROM refs r"
			" JOIN functions f ON f.id = r.fn WHERE r.to_name LIKE ? ORDER BY f.entry LIMIT ?",
			(pattern, limit)).fetchall()
	return {"functions": [dict(row) for row in functions],
		"strings": [dict(row) for row in strings],
		"touching": [dict(row) for row in touching]}


def resolve_function(conn: sqlite3.Connection, ident: str, alt: list[int] | None = None) -> list[sqlite3.Row]:
	"""Find functions by exact name, address, or substring (in that order). `alt` is the same
	address in another address domain (file vs Ghidra), so either one finds the function."""
	numeric = None
	text = ident.strip()
	if re.fullmatch(r"(0x)?[0-9a-fA-F]+", text):
		numeric = int(text, 16) if text.lower().startswith("0x") else int(text)
	addresses = [a for a in ([numeric] if numeric is not None else []) + list(alt or []) if a is not None]
	if addresses:
		rows = conn.execute(
			"SELECT * FROM functions WHERE entry IN (%s) OR name = ?"
			% ",".join("?" * len(addresses)), addresses + [text]).fetchall()
	else:
		rows = conn.execute("SELECT * FROM functions WHERE name = ?", (text,)).fetchall()
	if len(rows) > 1:
		# an imported symbol and its PLT stub can share a name; the code in the image wins
		preferred = [row for row in rows if row["kind"] != "external"]
		if preferred:
			rows = preferred
	if not rows:
		rows = conn.execute(
			"SELECT * FROM functions WHERE name LIKE ? ORDER BY length(name), entry LIMIT 20",
			("%" + text + "%",)).fetchall()
	return rows


def function_row(conn: sqlite3.Connection, fn_id: int) -> sqlite3.Row | None:
	return conn.execute("SELECT * FROM functions WHERE id = ?", (fn_id,)).fetchone()


def instructions(conn: sqlite3.Connection, fn_id: int) -> list[sqlite3.Row]:
	return conn.execute("SELECT * FROM instructions WHERE fn = ? ORDER BY address", (fn_id,)).fetchall()


def refs(conn: sqlite3.Connection, fn_id: int) -> list[sqlite3.Row]:
	return conn.execute(
		"SELECT * FROM refs WHERE fn = ? ORDER BY address, operand_index", (fn_id,)).fetchall()


def ref_summary(conn: sqlite3.Connection, fn_id: int) -> list[dict]:
	"""The data and symbols this function touches, grouped by target."""
	rows = conn.execute(
		"SELECT to_name, to_kind, to_address, section, count(*) AS sites, is_call, is_data"
		" FROM refs WHERE fn = ? GROUP BY to_name, to_kind, to_address"
		" ORDER BY is_call DESC, to_kind, to_address", (fn_id,)).fetchall()
	return [dict(row) for row in rows]


def callers(conn: sqlite3.Connection, fn_id: int) -> list[dict]:
	return [dict(row) for row in conn.execute(
		"SELECT f.id, f.name, f.entry, c.site FROM calls c JOIN functions f ON f.id = c.caller"
		" WHERE c.callee = ? ORDER BY f.entry", (fn_id,)).fetchall()]


def callees(conn: sqlite3.Connection, fn_id: int) -> list[dict]:
	return [dict(row) for row in conn.execute(
		"SELECT f.id, f.name, f.entry, f.kind, c.site FROM calls c JOIN functions f ON f.id = c.callee"
		" WHERE c.caller = ? ORDER BY f.entry", (fn_id,)).fetchall()]


def strings_at(conn: sqlite3.Connection, addresses: list[int]) -> dict[int, str]:
	if not addresses:
		return {}
	marks = ",".join("?" * len(addresses))
	rows = conn.execute("SELECT address, value FROM strings WHERE address IN (%s)" % marks, addresses)
	return {row["address"]: row["value"] for row in rows}


def section_of(conn: sqlite3.Connection, address: int) -> str | None:
	row = conn.execute("SELECT name FROM sections WHERE start <= ? AND end >= ? ORDER BY start DESC LIMIT 1",
		(address, address)).fetchone()
	return row["name"] if row else None


# --------------------------------------------------------------------------------------
# the file's own function table (Docs/MSVC-Plan.md MS-1)

_UNIT_SELECT = "SELECT source, entry, end, size, unwind, section FROM units"


def unit_rows(conn: sqlite3.Connection, limit: int = 0) -> list[sqlite3.Row]:
	"""Every unit the file's own table names, in address order ([] when it has none)."""
	if not has_table(conn, "units"):
		return []
	sql = "SELECT source, entry, end, size, unwind, section FROM units ORDER BY entry"
	return conn.execute(sql + (" LIMIT ?" if limit else ""), ([limit] if limit else [])).fetchall()


def unit_at(conn: sqlite3.Connection, entry: int) -> sqlite3.Row | None:
	"""The unit the file's table says *starts* here."""
	if not has_table(conn, "units"):
		return None
	return conn.execute(_UNIT_SELECT + " WHERE entry = ?", (entry,)).fetchone()


def unit_covering(conn: sqlite3.Connection, address: int) -> sqlite3.Row | None:
	"""The unit the file's table says this address is inside - a function the analysis placed in
	the middle of a unit the compiler had already bounded."""
	if not has_table(conn, "units"):
		return None
	return conn.execute(_UNIT_SELECT + " WHERE entry <= ? AND end > ? ORDER BY entry DESC LIMIT 1",
		(address, address)).fetchone()


def unit_neighbours(conn: sqlite3.Connection, address: int) -> tuple[sqlite3.Row | None, sqlite3.Row | None]:
	"""The units just below and just above an address the table does not name: the gap an
	analysis-only function sits in."""
	if not has_table(conn, "units"):
		return None, None
	before = conn.execute(_UNIT_SELECT + " WHERE end <= ? ORDER BY end DESC LIMIT 1", (address,)) \
		.fetchone()
	after = conn.execute(_UNIT_SELECT + " WHERE entry > ? ORDER BY entry LIMIT 1", (address,)) \
		.fetchone()
	return before, after


def unit_sizes(conn: sqlite3.Connection, entries: list[int]) -> dict[int, dict]:
	"""{entry: {source, size}} for the units starting at these addresses - what `find` annotates
	an entry that is not in the table, or is a different size in it, with."""
	if not entries or not has_table(conn, "units"):
		return {}
	marks = ",".join("?" * len(entries))
	return {int(row["entry"]): {"source": row["source"], "size": int(row["size"])}
		for row in conn.execute("SELECT entry, size, source FROM units WHERE entry IN (%s)" % marks,
			entries)}


def unit_reconciliation(conn: sqlite3.Connection) -> dict:
	"""The file's own function table against the analysis' bodies.

	Not a verdict about which side is right: a count of where they agree and of every place they

do not, which is what `decomp analyze` prints, what `show` repeats for one function, and what
	the MS-1 check asserts (Docs/MSVC-Plan.md §3 item 5 is the baseline it must improve on).
	"""
	units = unit_rows(conn)
	if not units:
		return {"source": None, "units": 0}
	by_entry = {int(row["entry"]): row for row in units}
	out = {"source": units[0]["source"], "units": len(units),
		"code_bytes": sum(int(row["size"]) for row in units), "sections": {},
		"agree": 0, "analysis_shorter": 0, "analysis_longer": 0,
		"not_in_analysis": [], "not_in_table": [], "sizes": {}}
	for row in units:
		name = row["section"] or "?"
		out["sections"][name] = out["sections"].get(name, 0) + int(row["size"])
	for row in conn.execute("SELECT name, entry, size, kind FROM functions"):
		unit = by_entry.get(int(row["entry"]))
		if unit is None:
			if row["kind"] == "function":
				out["not_in_table"].append({"name": row["name"], "entry": int(row["entry"]),
					"size": int(row["size"])})
			continue
		if int(row["size"]) == int(unit["size"]):
			out["agree"] += 1
			continue
		if int(row["size"]) < int(unit["size"]):
			out["analysis_shorter"] += 1
		else:
			out["analysis_longer"] += 1
		out["sizes"][hex(int(row["entry"]))] = [int(row["size"]), int(unit["size"])]
	known = {int(row["entry"]) for row in conn.execute("SELECT entry FROM functions")}
	out["not_in_analysis"] = [{"entry": int(row["entry"]), "size": int(row["size"]),
		"section": row["section"]} for row in units if int(row["entry"]) not in known]
	return out


def unit_lines(rec: dict, width: int = 12) -> list[str]:
	"""Print the reconciliation: the table first, then the disagreement in both directions."""
	if not rec.get("units"):
		return ["  %-*s none: this file carries no function table" % (width, "unit table")]
	sections = ", ".join("%s %d" % (name, size) for name, size in sorted(rec["sections"].items()))
	lines = ["  %-*s %s: %d units, %d bytes - the file's own boundaries (%s)" % (
		width, "unit table", rec["source"], rec["units"], rec["code_bytes"], sections)]
	lines.append("  %-*s %d agree with the analysis, %d the analysis reports shorter, %d longer, "
		"%d of its units are not a function entry in the analysis" % (
			width, "", rec["agree"], rec["analysis_shorter"], rec["analysis_longer"],
			len(rec["not_in_analysis"])))
	lines.append("  %-*s %d analysis function entries are not in %s - the analysis made those up, "
		"usually in an alignment gap between units" % (
			width, "", len(rec["not_in_table"]), rec["source"]))
	return lines


# --------------------------------------------------------------------------------------
# discovery (Phase 3): what the analysis knows about data, and what touches what


def symbol_rows(conn: sqlite3.Connection, pattern: str = "", addresses: list[int] | None = None,
	limit: int = 40) -> list[sqlite3.Row]:
	"""Symbols of the image: globals, vtables, labels, PLT stubs, imports.

	This is the half of the analysis a name-and-function search misses: the question "which
	functions touch this global/vtable" starts by finding the object, which is never a
	function.
	"""
	clauses, values = [], []
	if pattern:
		clauses.append("name LIKE ?")
		values.append("%" + pattern + "%")
	if addresses:
		clauses.append("address IN (%s)" % ",".join("?" * len(addresses)))
		values.extend(addresses)
	if not clauses:
		return []
	values.append(limit)
	return conn.execute("SELECT address, name, type, source, namespace, section FROM symbols"
		" WHERE %s ORDER BY length(name), address LIMIT ?" % " OR ".join(clauses), values).fetchall()


def xrefs_to(conn: sqlite3.Connection, addresses: list[int], limit: int = 60) -> list[sqlite3.Row]:
	"""Every recorded reference reaching one of these addresses, with the function it is in."""
	if not addresses:
		return []
	marks = ",".join("?" * len(addresses))
	return conn.execute(
		"SELECT r.address, r.to_address, r.to_name, r.to_kind, r.ref_type, r.is_call,"
		" f.id AS fn, f.name, f.entry, f.size, f.kind, i.text"
		" FROM refs r JOIN functions f ON f.id = r.fn"
		" LEFT JOIN instructions i ON i.fn = r.fn AND i.address = r.address"
		" WHERE r.to_address IN (%s) ORDER BY f.entry, r.address LIMIT ?" % marks,
		addresses + [limit]).fetchall()


def referrer_counts(conn: sqlite3.Connection, addresses: list[int]) -> dict[int, int]:
	"""How many reference sites each address has, per function ({fn id: sites})."""
	if not addresses:
		return {}
	marks = ",".join("?" * len(addresses))
	return {row["fn"]: row["sites"] for row in conn.execute(
		"SELECT fn, count(*) AS sites FROM refs WHERE to_address IN (%s) GROUP BY fn" % marks,
		addresses)}


def nearest_symbol(conn: sqlite3.Connection, address: int) -> tuple[str, int] | None:
	"""The symbol containing an address, as (name, its address) - what an offset is inside of.

	A vtable header, a `.rodata` table and a string all get named this way: the interesting
	part of a pointer slot is which object its address falls inside. A name that came from the
	file's own symbol table beats a label Ghidra invented at the same address.
	"""
	row = conn.execute("SELECT address, name FROM symbols WHERE address <= ?"
		" ORDER BY (source IN ('IMPORTED','EXTERNAL')) DESC, address DESC LIMIT 1",
		(address,)).fetchone()
	return (row["name"], row["address"]) if row else None


def next_own_symbol(conn: sqlite3.Connection, address: int) -> int | None:
	"""The next symbol the *file* names above an address - where an object ends.

	Labels Ghidra created (source DEFAULT/ANALYSIS) sit inside objects, so they cannot bound
	one; in a stripped binary there is nothing to bound by and the caller's other rule applies.
	"""
	row = conn.execute("SELECT min(address) AS next FROM symbols WHERE address > ?"
		" AND source IN ('IMPORTED','EXTERNAL')", (address,)).fetchone()
	return row["next"] if row and row["next"] else None


def function_at(conn: sqlite3.Connection, address: int) -> sqlite3.Row | None:
	if not fits_rowid (address):
		return None
	return conn.execute("SELECT id, name, namespace, entry, size, kind, section FROM functions"
		" WHERE entry = ?", (address,)).fetchone()


def targets_of(conn: sqlite3.Connection, fn_id: int) -> list[dict]:
	"""What one function reaches: (address, name, kind). The input to 'what else touches the
	same things' queries."""
	return [{"address": row["to_address"], "name": row["to_name"], "kind": row["to_kind"],
			"is_call": bool(row["is_call"])}
		for row in conn.execute("SELECT DISTINCT to_address, to_name, to_kind, is_call FROM refs"
			" WHERE fn = ? AND to_address IS NOT NULL", (fn_id,)).fetchall()]


def fits_rowid (address) -> bool:
	"""Can this address be handed to SQLite at all? A data slot read as unsigned can hold
	0xffff... - a value that is not an INTEGER to SQLite and raises OverflowError. It is
	never a code address, so every caller of the two lookups below wants 'no'."""
	return isinstance (address, int) and 0 <= address < 1 << 63


def inside_function (conn: sqlite3.Connection, address: int) -> bool:
	"""Is an address inside a function body? Then it is a code label, not an object."""
	if not fits_rowid (address):
		return False
	return conn.execute ("SELECT 1 FROM functions WHERE entry <= ? AND entry + size > ? LIMIT 1",
		(address, address)).fetchone() is not None


# --------------------------------------------------------------------------------------
# the match ledger


def ensure_matches(conn: sqlite3.Connection) -> None:
	"""Add the ledger to a cache written before Phase 5. Only ever called on a writable
	connection: a read-only one raises instead of creating it, which is why the readers below
	answer 'nothing' when the table is absent."""
	conn.executescript(MATCHES_DDL)
	conn.execute(MATCHES_INDEX)


def match_rows(conn: sqlite3.Connection, variant: str = "", entry: int | None = None,
	limit: int = 0) -> list[dict]:
	"""Ledger rows, in the order the pairs were proven: what the tool already knows reproduces what.

	`variant` narrows it to the candidate build being compared now - a symbol name proved under `-O0`
	is not a promise about what `-O2` calls it. `entry` narrows it to one entity."""
	if not has_table(conn, "matches"):
		return []
	sql = ("SELECT variant, entry, kind, candidate, evidence, tier, unit, unit_entry, at"
		" FROM matches")
	values: list = []
	if variant:
		sql += " WHERE variant = ?"
		values.append(variant)
	if entry is not None:
		sql += "%s entry = ?" % (" WHERE" if not values else " AND")
		values.append(entry)
	# rowid is the order they were written in, which is the order they were proven in - and the
	# tokens the ledger seeds are numbered in that order, so they do not move between runs
	sql += " ORDER BY rowid"
	if limit:
		sql += " LIMIT %d" % int(limit)
	return [dict(row) for row in conn.execute(sql, values).fetchall()]


def record_matches(conn: sqlite3.Connection, entries: list[dict]) -> int:
	"""Record what a unit that passed the gate proved.

	An entity is reproduced by a different symbol under a different variant, and by two symbols in
	one build (a function split into a hot body and a cold one), so the key is the triple and not
	the entity: every claim stays visible, and a re-run of the same unit updates its row."""
	ensure_matches(conn)
	count = 0
	with conn:
		for item in entries:
			if item.get("entry") is None or not item.get("candidate"):
				continue
			conn.execute(
				"INSERT OR REPLACE INTO matches (variant, entry, kind, candidate, evidence, tier,"
				" unit, unit_entry, at) VALUES (?,?,?,?,?,?,?,?,?)", (
					item.get("variant", ""), int(item["entry"]), item.get("kind", ""),
					item["candidate"], item.get("evidence", ""), item.get("tier", ""),
					item.get("unit", ""), item.get("unit_entry"), item.get("at", "")))
			count += 1
	return count


def match_index(conn: sqlite3.Connection, variant: str = "") -> dict[int, list[dict]]:
	"""The ledger as a lookup for one comparison: {entity address: [rows]}."""
	out: dict[int, list[dict]] = {}
	for row in match_rows(conn, variant=variant):
		out.setdefault(int(row["entry"]), []).append(row)
	return out


def matched_entries(conn: sqlite3.Connection, variant: str = "") -> set[int]:
	"""Which entities the ledger already names. An empty `variant` means any of them."""
	if not has_table(conn, "matches"):
		return set()
	sql = "SELECT DISTINCT entry FROM matches"
	values: list = []
	if variant:
		sql += " WHERE variant = ?"
		values.append(variant)
	return {int(row[0]) for row in conn.execute(sql, values)}


def callees_of(conn: sqlite3.Connection, among: set[int] | None, exclude: set[int],
	limit: int = 40) -> list[dict]:
	"""What the ledger still has to learn, by how many functions call it.

	`among` restricts the callers to that set of function entries; with `among` = the entities
	already in the ledger this is the frontier - the helpers a reproduced unit reaches that the
	ledger has no name for. `exclude` is what the ledger does know.

	This judges no candidate. It is a query about the original, and it is what turns the next
	decompilation from a guess into a decision: the callee with the most callers is the one whose
	name pays off in the most units at once.
	"""
	if not has_table(conn, "refs") or not has_table(conn, "functions"):
		return []
	sql = ("SELECT f.entry, f.name, f.size, f.kind, f.section,"
		" count(DISTINCT r.fn) AS callers, count(*) AS sites"
		" FROM refs r JOIN functions f ON f.entry = r.to_address"
		" WHERE (r.is_call = 1 OR r.to_kind IN ('function', 'external'))")
	values: list = []
	if among is not None:
		if not among:
			return []
		# the callers are restricted to the ledger's entities; the callees are excluded by `exclude`
		# below. Restricting the callers by `entry NOT IN among` as well asked for a function that
		# is and is not in the ledger, which made the frontier empty whenever the ledger was not.
		marks = ",".join("?" * len(among))
		sql += " AND r.fn IN (SELECT id FROM functions WHERE entry IN (%s))" % marks
		values.extend(sorted(among))
	if exclude:
		marks = ",".join("?" * len(exclude))
		sql += " AND f.entry NOT IN (%s)" % marks
		values.extend(sorted(exclude))
	sql += " GROUP BY f.entry, f.name, f.size, f.kind, f.section"
	sql += " ORDER BY callers DESC, sites DESC, f.size DESC LIMIT %d" % max(1, int(limit))
	return [dict(row) for row in conn.execute(sql, values).fetchall()]


def function_bodies(conn: sqlite3.Connection, sample: str = "",
	band: tuple[int, int] = (4, 90)) -> list[list[str]]:
	"""Instruction text of every function body in the cache, for shape profiling.

	`sample` narrows it to functions whose name matches, which is how the shape of one part
	of a binary is measured without measuring a statically linked library at the same time.
	The band is the same one `decomp.toolchain` applies to its own probe objects.
	"""
	sql = ("SELECT i.fn AS fn, f.entry AS entry, i.address AS address, i.text AS text"
		" FROM instructions i JOIN functions f ON f.id = i.fn WHERE f.kind = 'function'")
	values: list = []
	if sample:
		sql += " AND f.name LIKE ?"
		values.append("%" + sample + "%")
	groups: dict[int, list[str]] = {}
	order: dict[int, int] = {}
	for row in conn.execute(sql + " ORDER BY f.entry, i.address", values):
		groups.setdefault(row["fn"], []).append(row["text"] or "")
		order[row["fn"]] = row["entry"]
	return [text for text in groups.values() if band[0] <= len(text) <= band[1]]

