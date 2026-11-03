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

SCHEMA = """
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

CREATE INDEX i_functions_entry ON functions(entry);
CREATE INDEX i_functions_name ON functions(name);
CREATE INDEX i_instructions_fn ON instructions(fn);
CREATE INDEX i_refs_fn ON refs(fn);
CREATE INDEX i_refs_to ON refs(to_address);
CREATE INDEX i_calls_caller ON calls(caller);
CREATE INDEX i_calls_callee ON calls(callee);
CREATE INDEX i_symbols_address ON symbols(address);
CREATE INDEX i_strings_address ON strings(address);
"""


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
			values = meta(conn)
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
		for key, value in analysis.get("meta", {}).items():
			conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))
		# last, so a cache is either complete or absent
		conn.execute("INSERT OR REPLACE INTO meta VALUES ('complete','1')")
		conn.execute("INSERT OR REPLACE INTO meta VALUES ('analyzed_at_epoch',?)", (str(int(time.time())),))


# --------------------------------------------------------------------------------------
# reading


def meta(conn: sqlite3.Connection) -> dict:
	return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}


def counts(conn: sqlite3.Connection) -> dict:
	tables = ("functions", "instructions", "refs", "symbols", "strings", "sections", "calls")
	out = {name: conn.execute("SELECT count(*) FROM %s" % name).fetchone()[0] for name in tables}
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
