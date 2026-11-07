"""The `decomp` command line (Docs/Design-Plan.md, CLI Surface).

Stateless by design: `analyze` is the only command that starts Ghidra, everything else
reads the analysis cache. The tool never edits source - it reports facts and scores.

Exit codes: 0 ok, 1 a check or the work itself failed, 2 bad usage/config,
3 nothing found (or a command of a later phase).
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Optional

import typer

from . import (__version__, cache, check, compile, config, discover, diff, extract,
	fidelity, ghidra, normalize, relink, structures, symbols, toolchain)

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_NOT_FOUND = 0, 1, 2, 3

app = typer.Typer(
	help="Iteratively decompile functions out of a compiled binary into source that recompiles "
	"to the same bytes.",
	add_completion=False,
	no_args_is_help=True,
	invoke_without_command=True,
)


@app.callback()
def cli(
	version: bool = typer.Option(False, "--version", help="print the tool version and exit"),
) -> None:
	if version:
		echo("decomp %s" % __version__)
		raise typer.Exit(EXIT_OK)


# --------------------------------------------------------------------------------------
# shared plumbing


class Stop(Exception):
	"""Raised to leave a command with a specific exit code after printing what to do."""

	def __init__(self, code: int, *lines: str) -> None:
		super().__init__(lines[0] if lines else "")
		self.code = code
		self.lines = list(lines)


def echo(text: str = "", err: bool = False) -> None:
	typer.echo(text, err=err)


def load_config(config_path: Optional[str] = None, target: Optional[Path] = None) -> dict:
	try:
		return config.load(config_path, target)
	except config.ConfigError as exc:
		raise Stop(EXIT_USAGE, "config: %s" % exc)


def open_analysis(store: cache.Cache, target: Optional[Path], key: Optional[str]):
	try:
		values = store.resolve(target, key)
	except config.ConfigError as exc:
		raise Stop(EXIT_USAGE, "%s" % exc)
	try:
		return cache.open_readonly(Path(values["db"])), values
	except (OSError, sqlite3.Error) as exc:  # pragma: no cover
		raise Stop(EXIT_FAIL, "cannot read %s: %s" % (values.get("db"), exc))


# --------------------------------------------------------------------------------------
# check


@app.command("check")
def check_cmd(
	config_file: Optional[str] = typer.Option(None, "--config", "-C", help="target project.toml"),
) -> None:
	"""Run the startup checks: Ghidra install and matching pyghidra, JDK, Python, cache
	path, and the configured compilers."""
	cfg = load_config(config_file)
	report = check.check_all(cfg, want_compilers=True)
	echo("config: %s (%s)" % (cfg["path"], cfg["raw"].get("_found", "loaded")))
	echo("root:   %s" % cfg["root"])
	for line in report.lines():
		echo(line)
	echo("%s" % ("all checks passed" if not report.failed else "checks failed - fix the FAIL lines"))
	raise typer.Exit(EXIT_OK if not report.failed else EXIT_FAIL)


# --------------------------------------------------------------------------------------
# analyze


@app.command()
def analyze(
	binary: Path = typer.Argument(..., help="the target binary to analyse"),
	variant: Optional[str] = typer.Option(None, "--variant", "-v", help="which [variants.*] built it"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	force: bool = typer.Option(False, "--force", "-f", help="re-analyse and replace the cached analysis"),
	pseudocode: bool = typer.Option(True, "--pseudocode/--no-pseudocode",
		help="decompile every function (on for Phase 1; pass --no-pseudocode for a huge target)"),
) -> None:
	"""Run Ghidra once over a binary and cache everything later commands need."""
	target = Path(binary).expanduser()
	if not target.is_file():
		raise Stop(EXIT_USAGE, "no such file: %s" % target)
	target = target.resolve()

	cfg = load_config(config_file, target)
	report = check.check_all(cfg, want_compilers=False)
	failures = [item for item in report.items if item.level == check.FAIL]
	if failures:
		for line in report.lines():
			echo(line)
		raise Stop(EXIT_FAIL, "startup checks failed - run `decomp check` for the fixes")

	try:
		name, body = config.variant(cfg, variant)
	except config.ConfigError as exc:
		raise Stop(EXIT_USAGE, "%s" % exc)
	try:
		flags = toolchain.build_flags(body)
	except NotImplementedError as exc:
		raise Stop(EXIT_USAGE, "[variants.%s]: %s" % (name, exc))

	identity = cache.target_key(target)
	store = cache.Cache(config.cache_dir(cfg))
	existing = store.status(identity["key"])
	if existing.get("complete") and not force:
		echo("already analysed: %s" % target)
		echo("  key %s  db %s" % (identity["key"], existing["db"]))
		echo("  %s functions, %s instructions, %s pseudo-code  (Ghidra %s, %s)" % (
			existing.get("body_count", "?"), existing.get("instruction_count", "?"),
			existing.get("decompiled_count", "?"), existing.get("ghidra_version", "?"),
			existing.get("language_id", "?")))
		echo("  re-analyse with: decomp analyze %s --force" % binary)
		raise typer.Exit(EXIT_OK)

	install_dir, _tried = config.ghidra_install_dir(cfg)
	if install_dir is None:  # already reported by the checks
		raise Stop(EXIT_FAIL, "no Ghidra installation found")
	# Reaching this point means there is nothing complete to reuse, so start the entry clean:
	# a half-created Ghidra project or half-written db must not be mistaken for a cache.
	entry = store.reset(identity["key"])
	echo("analysing %s" % target, err=True)
	echo("  cache %s" % entry, err=True)
	try:
		ghidra.start(install_dir)
		analysis, timings = ghidra.analyze_target(cfg, target, entry, want_pseudocode=pseudocode,
			progress=lambda message: echo("  " + message, err=True))
	except ghidra.GhidraError as exc:
		raise Stop(EXIT_FAIL, "ghidra: %s" % exc)
	except KeyboardInterrupt:  # pragma: no cover
		raise Stop(EXIT_FAIL, "interrupted - nothing was cached")

	note = toolchain.build_note(target)
	offset, basis = _address_offset(analysis["sections"], note.get("sections") or {},
		int(analysis["meta"]["image_base"]))
	# The function table the file carries itself (MS-1: a PE's `.pdata`) is kept in the cache next
	# to the analysis' ranges, biased into the analysis' addresses. It is the only source of unit
	# boundaries a shipped, stripped binary gives, and it is the compiler's rather than a
	# recovery, so `extract.original_function` prefers it and reports where the two disagree.
	image = extract.TargetImage(target, offset)
	analysis["units"] = image.analysis_units()
	analysis["meta"].update({
		"unit_source": image.unit_source or None,
		"unit_count": len(analysis["units"]),
		"unit_note": image.unit_note or None,
	})
	analysis["meta"].update({
		"ghidra_version": analysis["meta"].get("ghidra_version")
			or config.application_properties(install_dir).get("application.version"),
		"address_offset": offset,
		"address_offset_basis": basis,
		"target_path": str(target),
		"target_name": target.name,
		"target_sha256": identity["sha256"],
		"target_size": identity["size"],
		"target_key": identity["key"],
		"target_format": note.get("format"),
		"target_arch": note.get("arch"),
		"target_bits": note.get("bits"),
		"target_entry_point": note.get("entrypoint"),
		"build_notes": " | ".join(note.get("build_notes", [])) or None,
		"compiler_hint": note.get("compiler_hint"),
		"build_error": note.get("error"),
		"variant": name,
		"variant_compiler": body.get("compiler"),
		"variant_arch": body.get("arch"),
		"variant_optimize": body.get("optimize"),
		"variant_flags": " ".join(flags),
		"config_path": str(cfg["path"]),
		"analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
		"seconds_import": round(timings.get("import", 0.0), 2),
		"seconds_analyze": round(timings.get("analyze", 0.0), 2),
		"seconds_decompile": round(timings.get("decompile", 0.0), 2),
		"seconds_export": round(timings.get("export", 0.0), 2),
		"seconds_total": round(timings.get("total", 0.0), 2),
		"pseudocode": int(bool(pseudocode)),
		"decompiled_count": sum(1 for f in analysis["functions"] if f.get("pseudocode")),
	})

	db_path = store.db_path(identity["key"])
	if db_path.exists():
		db_path.unlink()
	conn = cache.create(db_path)
	try:
		cache.write(conn, analysis)
		reconciled = cache.unit_reconciliation(conn)
	finally:
		conn.close()

	meta = analysis["meta"]
	echo()
	echo("analysed %s (%s, %s bytes)" % (target, meta.get("target_format") or meta["language_id"],
		meta["target_size"]))
	echo("  key       %s" % identity["key"])
	echo("  language  %s  image base %s%s" % (meta["language_id"], _hex(meta["image_base"]),
		"  entry %s" % _hex(meta["target_entry_point"]) if meta.get("target_entry_point") else ""))
	if offset:
		echo("  addresses Ghidra %s = file %s (via %s) - `nm`/objdump speak the file's" % (
			_hex(meta["image_base"]), _hex(meta["image_base"] - offset), basis or "the section map"))
	elif basis:
		echo("  addresses Ghidra = the file's own: a %s image is loaded at its image base, so no"
			" offset is needed (matched on %s)" % (meta.get("target_format") or "ELF", basis))
	if meta.get("build_notes"):
		echo("  built by  %s" % meta["build_notes"])
	elif meta.get("build_error"):
		echo("  build note: %s" % meta["build_error"])
	echo("  variant   %s (%s -O%s)" % (name, body.get("compiler"), body.get("optimize")))
	echo("  functions %s bodies, %s thunks, %s external" % (meta["body_count"], meta["thunk_count"],
		meta["external_function_count"]))
	echo("  exported  %s instructions, %s references, %s strings, %s pseudo-code" % (
		meta["instruction_count"], meta["reference_count"], meta["string_count"], meta["decompiled_count"]))
	for line in cache.unit_lines(reconciled):
		echo(line)
	if meta.get("unit_note"):
		echo("  %-*s %s" % (12, "unit note", meta["unit_note"]))
	if reconciled.get("not_in_table"):
		examples = ", ".join("%s (%d)" % (_hex(row["entry"]), row["size"])
			for row in reconciled["not_in_table"][:6])
		echo("  %-*s e.g. %s" % (12, "", examples))
	echo("  timing    import %.1fs, analysis %.1fs, decompile %.1fs, export %.1fs (total %.1fs)" % (
		timings.get("import", 0), timings.get("analyze", 0), timings.get("decompile", 0),
		timings.get("export", 0), timings.get("total", 0)))
	echo("  cache     %s" % db_path)
	echo()
	echo("next: decomp find <name>   |   decomp show <function>")


# --------------------------------------------------------------------------------------
# status


@app.command()
def status(
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""List the analysed targets in the cache."""
	cfg = load_config()
	store = cache.Cache(config.cache_dir(cfg))
	targets = store.targets()
	if as_json:
		echo(json.dumps({"cache": str(store.root), "targets": targets}, indent=1))
		raise typer.Exit(EXIT_OK if targets else EXIT_NOT_FOUND)
	echo("config: %s" % cfg["path"])
	echo("cache:  %s" % store.root)
	if not targets:
		echo("  nothing cached yet - run: decomp analyze <bin>")
		raise typer.Exit(EXIT_NOT_FOUND)
	for values in targets:
		echo("%s  %s" % (values.get("target_key", "?"), values.get("target_path", "?")))
		echo("  %s  %s  %s bytes  variant %s" % (values.get("language_id", "?"),
			values.get("target_format") or "?", values.get("target_size", "?"), values.get("variant", "?")))
		echo("  %s bodies + %s thunks, %s instructions, %s references, %s pseudo-code  analysed %s" % (
			values.get("body_count", "?"), values.get("thunk_count", "?"), values.get("instruction_count", "?"),
			values.get("reference_count", "?"), values.get("decompiled_count", "?"), values.get("analyzed_at", "?")))
		if values.get("unit_count"):
			echo("  function table: %s, %s units (the file's own boundaries)" % (
				values.get("unit_source", "?"), values.get("unit_count", "?")))
		echo("  ghidra %s / pyghidra %s  db %s" % (values.get("ghidra_version", "?"),
			values.get("pyghidra_version", "?"), values.get("db")))
		echo("  ghidra project: %s" % ("present" if store.has_project(values.get("target_key", "")) else "missing"))
	raise typer.Exit(EXIT_OK)


# --------------------------------------------------------------------------------------
# show


@app.command()
def show(
	function: str = typer.Argument(..., help="name, substring, or entry address (0x...)"),
	binary: Optional[Path] = typer.Option(None, "--bin", help="cached analysis of this binary"),
	key: Optional[str] = typer.Option(None, "--key", help="cache key from `decomp status`"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	code: bool = typer.Option(True, "--code/--no-code", help="Ghidra pseudo-code"),
	asm: bool = typer.Option(True, "--asm/--no-asm", help="the original instruction stream"),
	refs: bool = typer.Option(True, "--refs/--no-refs", help="symbols and data this function touches"),
	structure: bool = typer.Option(True, "--structure/--no-structure",
		help="what this function is to its class: a vtable slot, a constructor, a destructor"),
	calls: bool = typer.Option(True, "--calls/--no-calls", help="callers and callees"),
	max_lines: int = typer.Option(120, "--max-lines", help="0 prints everything"),
	as_json: bool = typer.Option(False, "--json", help="the whole record, no caps"),
) -> None:
	"""Everything known about one function: pseudo-code, instructions, references, callers."""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	try:
		meta = cache.meta(conn)
		offset = cache.address_offset(meta)
		rows = cache.resolve_function(conn, function, _other_addresses(function, offset))
		if not rows:
			raise Stop(EXIT_NOT_FOUND,
				"no function matches %r in the analysis of %s" % (function, values.get("target_path")),
				"see what is there with: decomp find %s" % function)
		if len(rows) > 1:
			lines = ["%r matches %d functions:" % (function, len(rows))]
			lines += ["  %s  %s" % (_hex(row["entry"]), row["name"]) for row in rows]
			raise Stop(EXIT_USAGE, *lines)
		row = rows[0]
		row = dict(row)
		for json_field in ("params", "ranges"):
			try:
				row[json_field] = json.loads(row.get(json_field) or "[]")
			except json.JSONDecodeError:  # pragma: no cover - written by us
				row[json_field] = []
		fn_id = row["id"]
		unit = _unit_note(conn, int(row["entry"]), int(row["size"]))
		if as_json:
			payload = dict(row)
			payload["bytes"] = row["bytes"].hex() if row["bytes"] else ""
			payload["instructions"] = [dict(item) for item in cache.instructions(conn, fn_id)]
			for item in payload["instructions"]:
				item["bytes"] = (item["bytes"] or b"").hex()
			payload["refs"] = [dict(item) for item in cache.refs(conn, fn_id)]
			payload["callers"] = cache.callers(conn, fn_id)
			payload["callees"] = cache.callees(conn, fn_id)
			payload["meta"] = meta
			payload["unit"] = unit
			echo(json.dumps(payload, indent=1))
			raise typer.Exit(EXIT_OK)

		echo("; %s" % row["name"])
		echo("; entry %s%s  size %s  section %s  kind %s" % (_hex(row["entry"]),
			" (file %s)" % _hex(row["entry"] - offset) if offset else "", row["size"],
			row["section"], row["kind"]))
		if row["namespace"]:
			echo("; namespace %s" % row["namespace"])
		if row["thunk_target"]:
			echo("; thunk for %s" % row["thunk_target"])
		prototype = _prototype(row)
		if prototype:
			echo("; prototype %s" % prototype)
		if row["params"]:
			echo("; ghidra parameters %s" % ", ".join("%s %s" % (p["type"], p["name"])
				for p in row["params"]))
		if row["tags"]:
			echo("; tags %s" % row["tags"])
		if row["comment"]:
			echo("; comment %s" % row["comment"])
		for line in unit["lines"]:
			echo("; %s" % line)
		echo("; source bytes: %s" % _hex_bytes(row["bytes"]))
		echo("; analysis: %s  %s  (key %s, variant %s)" % (meta.get("language_id"),
			meta.get("ghidra_version"), meta.get("target_key"), meta.get("variant")))

		if calls:
			_print_callers_callees(conn, fn_id, max_lines)
		if structure:
			recovered = structures.Recovery(conn, meta).build()
			for line in recovered.show_lines(int(row["entry"])):
				echo("structure: %s" % line)
			for note in recovered.notes:
				echo("structure note: %s" % note)
		if refs:
			_print_refs(conn, fn_id, max_lines)
		if code:
			_print_pseudocode(row, max_lines)
		if asm:
			_print_asm(conn, fn_id, max_lines)
	finally:
		conn.close()


def _mark_units(conn, rows: list[dict]) -> None:
	"""Annotate found entries with what the file's own function table says about them (MS-1): a
	different size there, or no unit at all. `find` is where a decompiler picks its next target, so
	it must not present an invented function and a real one identically.
	"""
	if not rows or not cache.has_table(conn, "units"):
		return
	table = cache.unit_rows(conn, 1)
	if not table:
		return
	units = cache.unit_sizes(conn, [int(row["entry"]) for row in rows])
	for row in rows:
		unit = units.get(int(row["entry"]))
		if unit is None:
			if row.get("kind") == "function":
				row["not_in_table"] = True
				row["unit_source"] = table[0]["source"]
		elif int(unit["size"]) != int(row["size"]):
			row["unit_size"] = int(unit["size"])
			row["unit_source"] = unit["source"]


def _unit_note(conn, entry: int, size: int) -> dict:
	"""What the file's own function table (MS-1) says about one analysed function.

	Both answers are printed: the unit boundary the compiler recorded and the body the analysis
	recovered. Where they differ the difference is the interesting fact - it says the analysis cut
	a unit short, or invented one in a gap the compiler emitted no function for - and saying it is
	what `Docs/MSVC-Plan.md` MS-1 asks for instead of silently taking one side.
	"""
	out = {"unit": None, "covers": None, "gap": None, "lines": []}
	if not cache.has_table(conn, "units"):
		return out
	found = cache.unit_at(conn, entry)
	if found is not None:
		record = {"source": found["source"], "entry": int(found["entry"]), "end": int(found["end"]),
			"size": int(found["size"]), "section": found["section"]}
		out["unit"] = record
		if record["size"] == size:
			out["lines"].append("%s %s-%s (%d bytes): the file's own function table and the analysis "
				"agree on this unit" % (record["source"], _hex(record["entry"]),
					_hex(record["end"]), record["size"]))
		else:
			out["lines"].append(
				"%s %s-%s (%d bytes): the file's own function table, the analysis' body is %d - "
				"`decomp try` compares the unit and says so" % (record["source"], _hex(record["entry"]),
					_hex(record["end"]), record["size"], size))
		return out
	covering = cache.unit_covering(conn, entry)
	if covering is not None:
		record = {"source": covering["source"], "entry": int(covering["entry"]),
			"end": int(covering["end"]), "size": int(covering["size"]),
			"section": covering["section"]}
		out["covers"] = record
		out["lines"].append(
			"%s has no unit at %s, but its unit %s-%s (%d bytes) covers this address: the analysis "
			"split one unit the compiler bounded as one" % (record["source"], _hex(entry),
				_hex(record["entry"]), _hex(record["end"]), record["size"]))
		return out
	before, after = cache.unit_neighbours(conn, entry)
	out["gap"] = {"units_end_at": int(before["end"]) if before is not None else None,
		"units_start_again_at": int(after["entry"]) if after is not None else None}
	where = ""
	if before is not None and after is not None:
		where = "its units end at %s and start again at %s, a %d-byte gap" % (
			_hex(int(before["end"])), _hex(int(after["entry"])),
			int(after["entry"]) - int(before["end"]))
	elif before is not None:
		where = "its last unit below ends at %s" % _hex(int(before["end"]))
	elif after is not None:
		where = "its first unit above starts at %s" % _hex(int(after["entry"]))
	source = (cache.unit_rows(conn, 1) or [None])[0]
	name = source["source"] if source is not None else "the function table"
	out["lines"].append("%s names no unit at %s: this function is the analysis' own%s"
		% (name, _hex(entry), (" - " + where) if where else ""))
	return out


def _limit(lines: list[str], max_lines: int, label: str) -> list[str]:
	if max_lines and len(lines) > max_lines:
		hidden = len(lines) - max_lines
		lines = lines[:max_lines] + ["; ... %d more %s (raise --max-lines)" % (hidden, label)]
	return lines


def _print_callers_callees(conn, fn_id: int, max_lines: int) -> None:
	callers = cache.callers(conn, fn_id)
	callees = cache.callees(conn, fn_id)
	echo()
	echo("callers (%d):" % len(callers))
	lines = ["  %s  %s" % (_hex(row["entry"]), row["name"]) for row in callers] or ["  none"]
	echo("\n".join(_limit(lines, max_lines, "callers")))
	echo("callees (%d):" % len(callees))
	lines = ["  %s  %s" % (_hex(row["entry"]), row["name"]) for row in callees] or ["  none"]
	echo("\n".join(_limit(lines, max_lines, "callees")))


def _print_refs(conn, fn_id: int, max_lines: int) -> None:
	summary = cache.ref_summary(conn, fn_id)
	known = cache.strings_at(conn, [row["to_address"] for row in summary if row["to_kind"] != "function"])
	echo()
	echo("references (%d targets):" % len(summary))
	lines = []
	for row in summary:
		kind = row["to_kind"]
		if kind == "function":
			lines.append("  call    %s  %s  (%d site%s)" % (_hex(row["to_address"]), row["to_name"],
				row["sites"], "" if row["sites"] == 1 else "s"))
		else:
			note = ""
			if row["to_address"] in known:
				note = "  = %r" % known[row["to_address"]]
			lines.append("  %-7s %s  %s%s  [%s]" % (kind if kind != "external" else "extern",
				_hex(row["to_address"]), row["to_name"], note, row["section"] or "?"))
	echo("\n".join(_limit(lines or ["  none"], max_lines, "references")))


def _print_pseudocode(row, max_lines: int) -> None:
	echo()
	if not row["pseudocode"]:
		echo("pseudo-code: none (%s)" % (row["decompile_error"] or "not decompiled"))
		return
	echo("pseudo-code (%s lines):" % len(row["pseudocode"].splitlines()))
	echo("\n".join(_limit(row["pseudocode"].splitlines(), max_lines, "lines")))


def _print_asm(conn, fn_id: int, max_lines: int) -> None:
	instructions = cache.instructions(conn, fn_id)
	by_address: dict[int, list] = {}
	for ref in cache.refs(conn, fn_id):
		by_address.setdefault(ref["address"], []).append(ref)
	lines = []
	for instruction in instructions:
		text = instruction["text"] or instruction["mnemonic"]
		suffix = ""
		here = by_address.get(instruction["address"], [])
		if here:
			wanted = [r for r in here if r["is_call"] or r["is_data"] or r["to_kind"] != "function"]
			if wanted:
				suffix = "   ; -> " + ", ".join("%s %s" % (r["ref_type"], r["to_name"]) for r in wanted)
		lines.append("  %s  %s  %s%s" % (_hex(instruction["address"]),
			(instruction["bytes"] or b"").hex().ljust(20), text, suffix))
	echo()
	echo("instructions (%d):" % len(instructions))
	echo("\n".join(_limit(lines, max_lines, "instructions")))


# --------------------------------------------------------------------------------------
# detect: the compiler, the object, and the -O it was built with (Phase 3)


def _parse_range(text: str) -> tuple[int, int] | None:
	"""`0x804c866-0x8053606` or `0x804c866+0x6da0`, in file addresses."""
	value = (text or "").strip()
	if not value:
		return None
	for separator in ("-", "+", ":"):
		body = value[2:] if value.lower().startswith("0x") else value
		if separator not in body:
			continue
		left, _, right = value.partition(separator)
		try:
			start, other = int(left.strip(), 16), int(right.strip(), 16)
		except ValueError:
			raise Stop(EXIT_USAGE, "--range wants 0xLO-0xHI or 0xSTART+0xLEN, got %r" % text)
		return (start, start + other) if separator == "+" else (start, other)
	raise Stop(EXIT_USAGE, "--range wants 0xLO-0xHI or 0xSTART+0xLEN, got %r" % text)


def detect_target(target: Path, *, range_text: str = "", sample: str = "", conn=None,
	levels: tuple[int, ...] = (0, 1, 2, 3), probe: bool = True) -> dict:
	"""Everything `decomp detect` reports, in one call (the benchmark check uses it too).

	No Ghidra: the facts come from the file's own headers, and the optimisation level comes
	from comparing the shape of the target's code against what the compilers installed here
	produce at each `-O`.
	"""
	out = {"target": str(target), "note": {}, "profile": {}, "signatures": [], "guess": None,
		"ranked": [], "problems": [], "sample": {}}
	note = toolchain.build_note(target)
	out["note"] = note
	if note.get("error"):
		out["problems"].append(note["error"])
		return out
	rng = _parse_range(range_text)
	if sample and conn is not None:
		bodies = cache.function_bodies(conn, sample=sample, band=toolchain.BAND)
		profile = toolchain.shape_profile(bodies)
		out["sample"] = {"source": "the cached analysis, functions whose name contains %r" % sample}
	else:
		profile, _note, problems = toolchain.target_shape(target, rng=rng, note=note)
		out["problems"].extend(problems)
		out["sample"] = {"source": "%s, bodies of %d-%d instructions%s" % (
			profile.get("sample_source")
			or "the executable sections of the file (cut at every ret)", *toolchain.BAND,
			" in --range" if rng else "")}
		out["sample"]["range"] = [hex(rng[0]), hex(rng[1])] if rng else None
	out["profile"] = profile
	if not probe:
		return out
	if not profile.get("bodies"):
		return out
	import shutil

	family = note.get("compiler")
	candidates = {"gcc": ["g++"], "clang": ["clang++"], "msvc": ["cl"]}.get(family, [])
	if not candidates:
		candidates = [compiler for compiler in ("g++", "clang++") if shutil.which(compiler)]
		out["problems"].append("the compiler is not named in the file: ranking the toolchains "
			"that are installed here by shape instead")
	out["compilers"] = candidates
	bits = note.get("bits") or 64
	for compiler in candidates:
		if not shutil.which(compiler):
			out["problems"].append("%s is not installed here - no probe for it, so no -O inference"
				% compiler)
			continue
		signatures, problems = toolchain.probe_signatures(compiler, bits, levels=levels)
		out["signatures"] += signatures
		out["problems"].extend(problems)
	if out["signatures"]:
		out["ranked"] = toolchain.infer_optimize(profile, out["signatures"])
		out["guess"] = out["ranked"][0] if out["ranked"] else None
	if out["guess"]:
		out["guess"]["sampled"] = profile.get("bodies", 0)
	out["sample_warning"] = toolchain.sample_warning(profile, note,
		narrowed=bool(range_text or sample))
	return out


@app.command()
def detect(
	binary: Path = typer.Argument(..., help="the target binary to describe"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	write: Optional[Path] = typer.Option(None, "--write",
		help="write a starting project.toml here (use with --force to replace one)"),
	force: bool = typer.Option(False, "--force", help="replace an existing file"),
	sample_range: str = typer.Option("", "--range",
		help="sample only this range of file addresses: 0xLO-0xHI or 0xSTART+0xLEN"),
	sample: str = typer.Option("", "--sample",
		help="sample only functions whose name matches, from the cached analysis"),
	levels: str = typer.Option("0,1,2,3", "--levels", help="which -O levels to probe"),
	probe: bool = typer.Option(True, "--probe/--no-probe", help="infer the optimisation level"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""Detect the compiler and the flags from the file itself, and write a starting config.

	Reads the `.comment` section (ELF), the Rich header and CodeView record (PE), the object
	type and the dynamic section. The optimisation level is not a fact a stripped binary
	carries, so it is a ranked guess: reference snippets are compiled with the installed
	toolchain at each `-O`, and the shape of the target's code is matched against them.
	"""
	target = Path(binary).expanduser()
	if not target.is_file():
		raise Stop(EXIT_USAGE, "no such file: %s" % target)
	target = target.resolve()
	wanted = tuple(int(item) for item in levels.split(",") if item.strip() != "")
	cfg = load_config(config_file, target)
	conn = None
	try:
		store = cache.Cache(config.cache_dir(cfg))
		status = store.status(cache.target_key(target)["key"])
		if status.get("complete"):
			conn = cache.open_readonly(Path(status["db"]))
	except config.ConfigError:
		conn = None
	try:
		outcome = detect_target(target, range_text=sample_range, sample=sample, conn=conn,
			levels=wanted, probe=probe)
	finally:
		if conn is not None:
			conn.close()

	note, profile, ranked = outcome["note"], outcome["profile"], outcome["ranked"]
	guess = outcome["guess"]
	# Phase 7: the flags beyond `-O` that the file itself names, and whether the compiler here is
	# the compiler that made it. Both come from the file's own records, not from the code's shape.
	fid = fidelity.for_target(note, profile, outcome.get("compilers") or [])
	outcome["fidelity"] = {"versions": [{"state": item["state"], "hard": item["hard"],
		"detail": item["detail"], "built": item["built"], "installed": item["installed"]}
		for item in fid["versions"]],
		"flags": [{"flag": item["flag"], "state": item["state"],
			"certainty": item["certainty"], "add": item["add"], "why": item["why"]}
			for item in fid["flags"]["findings"]],
		"suggest": fid["flags"]["suggest"]}
	if as_json:
		payload = {key: value for key, value in outcome.items() if key != "signatures"}
		payload["probes"] = [{"optimize": item["optimize"], "compiler": item.get("compiler"),
			"profile": item["profile"]} for item in outcome["signatures"]]
		echo(json.dumps(payload, indent=1, default=str))
		if write is not None:
			_path = _write_config(target, Path(write), note, guess, force, fid["flags"])
		raise typer.Exit(EXIT_OK if not note.get("error") else EXIT_FAIL)

	echo("target %s" % target)
	for line in toolchain.note_lines(note):
		echo(line)
	if note.get("error"):
		raise typer.Exit(EXIT_FAIL)

	echo()
	echo("code shape (%s):" % outcome["sample"].get("source", "the target"))
	if profile:
		for line in toolchain.profile_lines(profile,
				features=toolchain.feature_family((note.get("compiler") or ""))):
				echo(line)
	else:
		for problem in outcome["problems"]:
			echo("  %s" % problem)
	warning = outcome.get("sample_warning") or ""
	if warning:
		echo("  caution: %s" % warning)
	if toolchain.msvc(note.get("compiler")):
		for line in toolchain.msvc_shape_flags(profile):
			echo("  %s" % line)

	echo()
	echo("build fidelity (the file's own records, and this machine's toolchain):")
	for line in fidelity.detect_lines(fid):
		echo("  %s" % line)

	if probe and ranked:
		echo()
		echo("measured with the toolchains installed here (a candidate is built with these):")
		for item in ranked[:8]:
			echo("  %-10s -O%d  distance %.3f  next %.3f" % (item.get("compiler"), item["optimize"],
				item["distance"], item.get("runner_up", item["distance"])))
		echo()
		echo("optimize = %s  (%s)" % (guess["optimize"], guess.get("confidence")))
		if guess.get("level_class"):
			echo("  as a flag this is %s: the config picks the nearer one, %s" % (
				guess["level_class"], toolchain._MSVC_OPTIMIZE.get(int(guess["optimize"]), "?")))
		echo("  why: %s" % guess.get("why"))
		if warning:
			echo("  caution: the sample warning above applies to this answer")
	elif probe and not outcome["problems"]:
		echo("no -O inference: nothing was sampled")
	for problem in outcome["problems"]:
		echo("  note: %s" % problem)

	if write is not None:
		path = _write_config(target, Path(write), note, guess, force, fid["flags"])
		echo()
		echo("wrote %s" % path)
		echo("next: decomp analyze %s --variant %s -C %s" % (binary,
			toolchain.variant_name(note, guess["optimize"] if guess else None), path))
	raise typer.Exit(EXIT_OK)


def _write_config(target: Path, path: Path, note: dict, guess: dict | None, force: bool,
		flags: dict | None = None) -> Path:
	if path.is_dir():
		path = path / config.CONFIG_NAME
	if path.is_file() and not force:
		raise Stop(EXIT_USAGE, "%s already exists - pass --force to replace it (or edit it: "
		"`decomp detect` writes a starting point, not an answer)" % path)
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(toolchain.starter_config(target, note, guess, flags))
	return path


# --------------------------------------------------------------------------------------
# symbols


@app.command("symbols")
def symbols_cmd(
	binary: Path = typer.Argument(..., help="a PE whose debug directory names a PDB"),
	store: str = typer.Option(symbols.DEFAULT_STORE, "--store",
		help="local symbol store to keep the PDB in, laid out like a symbol server cache"),
	url_only: bool = typer.Option(False, "--url",
		help="print where the PDB is served from and stop (no request)"),
	refresh: bool = typer.Option(False, "--refresh", help="re-download even if the store has it"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""Fetch the debug symbols this binary asks for from Microsoft's public symbol server.

	A CodeView record is the address of the debug info, not the debug info: the PDB name, GUID
	and age in it are the key `msdl.microsoft.com` serves the real file under. LIEF and pefile
	both stop at spelling that key out, so this makes the request, checks that what came back
	carries this image's GUID and TimeDateStamp, and keeps it in the store layout a
	`_NT_SYMBOL_PATH` client would look in. For a target without its own symbols (a stripped
	image, an ELF, a Mach-O) this says so instead of guessing.
	"""
	target = Path(binary).expanduser()
	if not target.is_file():
		raise Stop(EXIT_USAGE, "no such file: %s" % target)
	target = target.resolve()
	try:
		record = symbols.codeview(target)
	except symbols.SymbolError as exc:
		echo(str(exc), err=True)
		raise typer.Exit(EXIT_NOT_FOUND)
	if url_only:
		echo(record["symbols_url"])
		raise typer.Exit(EXIT_OK)
	try:
		result = symbols.fetch(target, store, refresh=refresh)
	except symbols.SymbolError as exc:
		echo(str(exc), err=True)
		raise typer.Exit(EXIT_FAIL)
	if as_json:
		echo(json.dumps(result, indent=1, default=str))
	else:
		echo("target %s" % target)
		for line in symbols.lines(result):
			echo(line)
		echo()
		echo("what is in it (llvm-pdbutil, Docs/Setup.md): "
			"llvm-pdbutil dump --summary --modules --publics --section-contribs %s" % result["path"])
		echo("a store any symsrv client understands: _NT_SYMBOL_PATH=srv*%s*%s"
			% (store, symbols.SYMBOL_SERVER))
	if not result["match"]["guid"]:
		raise typer.Exit(EXIT_FAIL)


# --------------------------------------------------------------------------------------
# find


@app.command()
def ledger(
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	variant: Optional[str] = typer.Option(None, "--variant", "-v",
		help="default: the variant the analysis was run with"),
	limit: int = typer.Option(20, "--limit", help="how many frontier entries to show"),
	frontier: bool = typer.Option(True, "--frontier/--no-frontier",
		help="what the ledger has no name for yet, by how many functions call it"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""What the loop already knows about this target: which candidate symbol reproduces which
	entity in the original's addresses, and - more usefully - the callees it has not named yet.

	The ledger is written by `decomp try` when a unit reaches the gate (Docs/byte-cleanup-plan.md
	Phase 5): the pairs a scored unit was *shown*, not guesses. It is the memory of the loop. A
	helper proven in one function is a name every later unit has to use, and the frontier is the
	answer to "what should I decompile next": the callee the already-reproduced units reach most
	often, whose name would pay off in the most places at once.
	"""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	try:
		meta = cache.meta(conn)
		name = variant or str(meta.get("variant") or "")
		rows = cache.match_rows(conn, variant=name)
		known = cache.matched_entries(conn, variant=name)
		others: dict[str, int] = {}
		for row in cache.match_rows(conn):
			if row["variant"] != name:
				others[row["variant"]] = others.get(row["variant"], 0) + 1
		# with an empty ledger there is no frontier yet, so the honest thing to show is the seed:
		# the callees with the most callers anywhere in the analysis
		seeds = cache.callees_of(conn, among=known if known else None, exclude=known, limit=limit)
	finally:
		conn.close()

	by_entry: dict[int, list[dict]] = {}
	for row in rows:
		by_entry.setdefault(int(row["entry"]), []).append(row)
	if as_json:
		echo(json.dumps({"target": values.get("target_path"), "key": values.get("target_key"),
			"variant": name, "pairs": len(rows), "entities": len(by_entry),
			"other_variants": others, "matched": rows,
			"frontier": seeds if frontier else []}, indent=1, default=str))
		raise typer.Exit(EXIT_OK)

	echo("; %s (key %s)  ledger for variant %s" % (values.get("target_path"),
		values.get("target_key"), name or "(none recorded)"))
	if others:
		echo("; other variants: %s" % ", ".join("%s (%d pairs)" % item for item in
			sorted(others.items())))
	if not rows:
		echo("nothing yet: a unit that reaches the gate writes what it proved here - `decomp try`")
	else:
		echo("matched (%d entities, %d claims):" % (len(by_entry), len(rows)))
		for entry, group in sorted(by_entry.items()):
			newest = max(group, key=lambda item: str(item.get("at") or ""))
			names = ", ".join(sorted({str(item["candidate"]) for item in group}))
			echo("  %s  %-9s %s%s" % (_hex(entry), newest.get("kind") or "?", names,
				"  (%d claims)" % len(group) if len(group) > 1 else ""))
			echo("             %s at %s, shown by %s%s" % (newest.get("evidence") or "?",
				newest.get("tier") or "?", newest.get("unit") or "?",
				" @ %s" % _hex(newest["unit_entry"]) if newest.get("unit_entry") else ""))
	if frontier:
		echo("")
		echo("the frontier (%d):" % len(seeds) if known else
			"nothing has reached the gate yet, so this is every callee in the analysis, most-called "
			"first (%d):" % len(seeds))
		for row in seeds:
			echo("  %s  %-9s %6s  called by %-3d functions, %d sites  %s"
				% (_hex(row["entry"]), row.get("kind") or "?", row.get("size"), row["callers"],
					row["sites"], row.get("name") or ""))
		if seeds:
			first = seeds[0]
			echo("")
			echo("next: %s is reached by %d of the functions already reproduced - `decomp find %s`, "
				"then `decomp try %s <source>`; its name joins the ledger and the units that call it "
				"are scored against it" % (first.get("name") or _hex(first["entry"]), first["callers"],
					_hex(first["entry"]), _hex(first["entry"])))
	raise typer.Exit(EXIT_OK)


@app.command()
def find(
	query: str = typer.Argument(..., help="name, substring, 0x address, or string content"),
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	limit: int = typer.Option(40, "--limit"),
	xrefs: bool = typer.Option(True, "--xref/--no-xref",
		help="what references what was found, with the instruction at each site"),
	table: bool = typer.Option(True, "--table/--no-table",
		help="for a data object found: the pointers it holds (a vtable's methods, a table)"),
	members: bool = typer.Option(True, "--members/--no-members",
		help="for a function found: the other functions that share its vtable"),
	family: int = typer.Option(0, "--family",
		help="also list the functions related to what matched, grown N call edges out "
		"(the answer to \"decompile the coin system\")"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""Search a cached analysis: by name, address, string, global or vtable - and what in
	the binary is related to what was found.
	"""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	bits = 64 if ":64:" in (cache.meta(conn).get("language_id") or "") else 32
	try:
		meta = cache.meta(conn)
		offset = cache.address_offset(meta)
		hits = discover.search(conn, meta, query, limit, _other_addresses(query, offset))
		_mark_units(conn, hits["functions"])
		addresses = discover.addresses_named(conn, hits)
		report = {"target": values.get("target_path"), "target_key": values.get("target_key"),
			"address_offset": offset, "query": query, **hits, "addresses": addresses}
		if xrefs and addresses:
			report["xref_groups"] = discover.xrefs(conn, addresses, limit)
		image = None
		if (table or members) and addresses:
			image = extract.TargetImage(Path(meta.get("target_path") or ""), offset)
			if image.error:
				report["image_note"] = image.error
		if table and image is not None:
			report["tables"] = []
			for row in hits["symbols"][:8]:
				found = discover.table(conn, image, int(row["address"]), bits=bits, limit=limit)
				if found["count"]:
					report["tables"].append(dict(found, name=row["name"]))
		if members and image is not None:
			report["vtable_members"] = []
			for row in hits["functions"][:8]:
				rows = discover.members_of(conn, image, int(row["id"]), int(row["entry"]), bits=bits)
				if rows:
					report["vtable_members"].append({"function": row["name"], "entry": row["entry"],
						"members": rows[:limit]})
		if family:
			report["family"] = discover.family(conn, [int(row["id"]) for row in hits["functions"]],
				hops=family, limit=limit)
	finally:
		conn.close()

	found_any = any(hits[key] for key in ("functions", "strings", "symbols", "touching"))
	if as_json:
		echo(json.dumps(report, indent=1, default=str))
		raise typer.Exit(EXIT_OK if found_any else EXIT_NOT_FOUND)

	echo("; %s (key %s)%s" % (values.get("target_path"), values.get("target_key"),
		"  addresses: Ghidra = file + 0x%x" % offset if offset else ""))
	echo("functions (%d):" % len(hits["functions"]))
	for row in hits["functions"]:
		mark = ""
		if row.get("unit_size"):
			mark = "  <- %s says %s" % (row["unit_source"], row["unit_size"])
		elif row.get("not_in_table"):
			mark = "  <- not in %s" % row["unit_source"]
		echo("  %s  %-6s %6s  %s%s" % (_hex(row["entry"]), row["kind"], row["size"], row["name"], mark))
	if hits["symbols"]:
		echo("symbols and data (%d):" % len(hits["symbols"]))
		for row in hits["symbols"]:
			echo("  %s  %-9s %s%s" % (_hex(row["address"]), row["type"], row["name"],
				"  [%s]" % row["section"] if row["section"] else ""))
	echo("strings (%d):" % len(hits["strings"]))
	for row in hits["strings"]:
		echo("  %s  [%s]  %r" % (_hex(row["address"]), row["section"], row["value"]))
	if hits["touching"]:
		echo("functions referencing it (%d):" % len(hits["touching"]))
		for row in hits["touching"]:
			echo("  %s  %s  -> %s" % (_hex(row["entry"]), row["name"], row["to_name"]))
	for group in report.get("xref_groups", []):
		echo()
		echo("references from %s (%s bytes, %d sites):" % (group["name"], group["size"],
			len(group["sites"])))
		for site in group["sites"][:limit]:
			echo("    %s  %-28s -> %s %s" % (_hex(site["address"]), (site["text"] or "?")[:28],
				site["ref_type"], site["to_name"]))
	for entry in report.get("tables", []):
		echo()
		echo("what %s at %s points at (%d slots, %d bytes read):" % (entry["name"],
			_hex(entry["address"]), entry["count"], entry["bytes"]))
		for slot in entry["slots"]:
			target = slot["target"]
			extra = " (%s bytes)" % target["size"] if target["kind"] == "function" else ""
			echo("    %s +0x%-2x -> %-8s %s%s" % (_hex(slot["slot"]), slot["offset"],
				target["kind"], target["name"], extra))
	for entry in report.get("vtable_members", []):
		echo()
		echo("in the same vtable as %s (%s):" % (entry["function"], _hex(entry["entry"])))
		for row in entry["members"][:limit]:
			echo("    %s  %6s  %s  (slot %s of %s)" % (_hex(row["entry"]), row["size"], row["name"],
				_hex(row["slot"]), row["vtable"]))
	group = report.get("family")
	if group:
		echo()
		echo("related to what matched (%d functions, %d hops):" % (len(group["members"]), family))
		for row in group["members"]:
			echo("  %s  %-6s %6s  %-40s  %s" % (_hex(row["entry"]), row["kind"], row["size"],
				row["name"], "; ".join(row["why"])))
		if group["shared"]:
			echo("  objects this group shares:")
			for row in group["shared"][:limit]:
				echo("    %s  %-9s %s" % (_hex(row["address"]) if row["address"] else "-",
					row["kind"], row["name"]))
				echo("      referenced by %d of the matched functions" % row["seeds"])
	if not found_any:
		echo("nothing matched %r" % query)
		echo("  (a name search only finds names that survive: in a stripped binary, try a string, "
		"an address from `decomp status`/objdump, or `--family` from something that did match)")
	raise typer.Exit(EXIT_OK if found_any else EXIT_NOT_FOUND)


# --------------------------------------------------------------------------------------
# try: the loop (Phase 2)


def score_candidate(cfg: dict, conn, meta: dict, row, sources: list[Path], *,
	fn: str | None = None, variant: str | None = None, includes: list[str] | None = None,
	size: int = 0, register_abstract: bool = False, object_dir: Path | None = None,
	gate: str | None = None, waive: list[str] | None = None) -> dict:
	"""Compile a candidate and score it against one cached function.

	Everything `decomp try` does, in one call, so the benchmark check in
	`Tests/tools/check_phase2_try.py` exercises this same path.

	The gate is the tier in `[gate] require` (`--gate` overrides it). `register_abstract` is
	accepted and ignored: folding registers is no longer a mode, it is one of the two
	comparisons every verdict is scored by (`decomp/diff.py`).
	"""
	name, body = config.variant(cfg, variant or meta.get("variant"))
	flags = toolchain.build_flags(body)
	object_path = (object_dir or (config.cache_dir(cfg) / "candidates")) / compile.object_name(sources)
	result = compile.build(sources, object_path, compiler=body.get("compiler", "g++"),
		flags=flags, includes=[*config.include_dirs(cfg, body),
			*[Path(item) for item in (includes or [])]])
	if gate and gate not in diff.GATE_MODES:
		raise config.ConfigError("--gate %s: not a gate - use one of %s"
			% (gate, ", ".join(diff.GATE_MODES)))
	require, gate_from = (gate, "--gate") if gate else config.gate(cfg, body)
	if waive is None:
		waiver, waiver_from = config.gate_waivers(cfg, body)
	else:
		waiver, waiver_from = [str(item) for item in waive], "--waive"
	unknown = [item for item in waiver if item not in diff.WAIVABLE]
	if unknown:
		raise config.ConfigError("--waive %s: not something this gate can wave aside - the options "
		"are %s" % (", ".join(unknown), ", ".join(diff.WAIVABLE)))
	outcome = {"variant": name, "flags": flags, "build": result, "object": object_path,
		"warnings": [], "error": None, "error_code": EXIT_FAIL, "verdict": None,
		"gate": require, "gate_from": gate_from, "waive": waiver, "waive_from": waiver_from,
		"original": None, "candidate": None}
	if result.failed:
		outcome["error"] = "the candidate did not compile"
		return outcome

	language = meta.get("language_id") or ""
	handle = normalize.capstone_for(language, detail=True)
	if handle is None:
		outcome["error"] = ("no decoder for %s - the diff supports x86 (x86:LE:32/64) for now"
			% language)
		return outcome

	original = extract.original_function(conn, meta, row, size or None)
	outcome["original"] = original
	outcome["warnings"] += original.warnings
	if row["kind"] == "thunk" and cache.unit_at(conn, int(row["entry"])) is None:
		outcome["warnings"].append("the analysis classifies this function as a thunk: at -O2 its "
			"body may be a jump into another function, so the cached range may be shorter than "
			"the compiler's - the file's own function table (.eh_frame, .pdata, st_size) is what "
			"bounds a unit now, and --size overrides it")
	if not original.bytes:
		outcome["error"] = "nothing to compare: the cache holds no bytes for this function"
		return outcome

	image = extract.TargetImage(Path(meta.get("target_path") or ""), cache.address_offset(meta))
	# What the recovered C++ structure says about this unit, if anything: it is what names a
	# vtable or type_info reference on the original side, the same object the candidate
	# reaches by symbol (Docs/Design-Plan.md Phase 4).
	recovered = structures.Recovery(conn, meta, image).build()
	bound = _structures_for(recovered, row)
	outcome["structures"] = bound
	bind_original, _ = extract.original_bindings(conn, meta, row, image, structures=recovered)

	object_file = extract.CandidateObject(object_path)
	if object_file.error:
		outcome["error"] = object_file.error
		outcome["error_code"] = EXIT_NOT_FOUND
		return outcome
	bits = 64 if (language.split(":") + ["", ""])[2] == "64" else 32
	if object_file.bits and object_file.bits != bits:
		outcome["error"] = ("the candidate object is %d-bit (%s) but the analysis of this target "
			"is %s - compile it with the variant's arch (see [variants.%s] in %s)"
			% (object_file.bits, object_file.path.name, language, name, cfg["path"]))
		outcome["error_code"] = EXIT_USAGE
		return outcome
	try:
		candidate = object_file.function(fn, original.size)
	except extract.SymbolNotFound as exc:
		outcome["error"] = str(exc)
		outcome["error_code"] = EXIT_NOT_FOUND
		return outcome
	outcome["candidate"] = candidate
	outcome["warnings"] += candidate.warnings

	instructions_original = normalize.decode_function(handle, original.address, original.bytes,
		original.boundaries, original.extents)
	instructions_candidate = normalize.decode_function(handle, candidate.address, candidate.bytes,
		extents=candidate.extents)
	if not instructions_candidate:
		outcome["error"] = ("no instructions could be decoded at %s in %s"
			% (_hex(candidate.address), object_path.name))
		outcome["error_code"] = EXIT_FAIL
		return outcome

	# What the loop has already been shown about this target (Docs/byte-cleanup-plan.md, Phase 5):
	# which symbol in a candidate built this way reproduces which entity in the original's addresses.
	# Two things follow from having that written down. The positional token for an entity the ledger
	# knows comes from the ledger, so one helper is one thing across a target instead of a different
	# thing per body; and a reference that reaches it is a claim about how the candidate names it,
	# which the ledger confirms or contradicts. Both are scoped to the variant being compared: a name
	# proven at -O0 says nothing about what -O2 calls a static helper.
	ledger_rows = cache.match_rows(conn, variant=name)
	ledger = cache.match_index(conn, variant=name)
	outcome["ledger"] = len(ledger)
	vocabulary = normalize.Vocabulary()
	vocabulary.seed_ledger(ledger_rows)
	bind_candidate = object_file.bindings(candidate)[0]
	tokens_original = normalize.normalize_function(vocabulary, "original", instructions_original,
		bind_original, original.address, original.size, False, original.extents)
	tokens_candidate = normalize.normalize_function(vocabulary, "candidate", instructions_candidate,
		bind_candidate, candidate.address, candidate.size, False, candidate.extents)
	# The byte comparison of Phase 3 needs the fields of each body that the link writes. The
	# candidate's come from its own relocation table - authoritative, and the widths come from the
	# relocation type. The original's come from the address-carrying operands of its instructions,
	# because a linked file has no relocations left in it; for the candidate the decoder's view is
	# added second and only where there is no record, which is what covers a call to a helper in the same section (no relocation in a `.o`, the link
	# fills the displacement in anyway). Offsets are per extent, in the order the blocks are compared.
	blocks_original = normalize.body_blocks(original.extents, original.address, original.size)
	blocks_candidate = normalize.body_blocks(candidate.extents, candidate.address, candidate.size)
	fields_original = normalize.merge_fields(
		normalize.address_fields(blocks_original, instructions_original, bind_original))
	fields_candidate = normalize.merge_fields(
		object_file.relocation_fields(candidate),
		normalize.address_fields(blocks_candidate, instructions_candidate, bind_candidate))
	outcome["masked_fields"] = {"original": fields_original, "candidate": fields_candidate}
	outcome["verdict"] = diff.compare(tokens_original, tokens_candidate, vocabulary,
		threshold=config.threshold(cfg), original_bytes=original.bytes, candidate_bytes=candidate.bytes,
		original_fields=fields_original, candidate_fields=fields_candidate,
		original_at=normalize.body_index(blocks_original, instructions_original, tokens_original),
		candidate_at=normalize.body_index(blocks_candidate, instructions_candidate, tokens_candidate),
		require=require, waive=tuple(waiver), ledger=ledger)
	# Phase 7: the toolchain reading, and the flags the file names beyond `-O`. A compiler mismatch
	# is the one difference the loop cannot iterate towards, so it goes where the loop reads it
	# (`verdict.gaps`) as well as in the notes; the flags are offered as a build to try, never
	# applied on their own.
	target_path = Path(str(meta.get("target_path") or ""))
	agreement = fidelity.cached_agreement(meta, str(body.get("compiler", "g++")))
	if agreement["state"] not in ("same", "unknown"):
		outcome["warnings"].append(agreement["detail"])
		outcome["verdict"].build_mismatch = agreement["detail"]
	if require == "exact" and not outcome["verdict"].bytes_equal_masked and target_path.is_file():
		note = toolchain.build_note(target_path)
		if not note.get("error"):
			texts = [str(item.get("text") if isinstance(item, dict) else getattr(item, "text", "")
				or "") for item in instructions_original]
			found = fidelity.flag_findings(note,
				fidelity.evidence(texts=[item for item in texts if item]))
			outcome["flags_this_file_names"] = found["findings"]
			outcome["flag_advice"] = fidelity.finding_lines(found)
	return outcome


def _learn(db: Path, row, variant: str, verdict, candidate, sources: list = ()) -> dict:
	"""Write down what a unit that reached the gate proved about the target (Phase 5).

	Two things a scored unit proves, and they are different things.

	**The unit itself.** The candidate symbol that assembled to the bytes at this address *is* the
	name of whatever lives there - and in a stripped binary nothing else says. That is the pair every
	later unit is scored against: a call to `FUN_00102e1e` stops being a guess the moment the
	function at that address has been reproduced, and named.

	**What it reaches.** Only where the original side is anonymous: where the original has a name
	(`strcmp`, a symbol of an unstripped target) the name comparison in `diff.ref_evidence` already
	refuses a candidate that reaches something else, so there is nothing new to record. Where the
	original is a global with no symbol in it, the candidate's name for it is new, and every other
	unit that reaches it has to answer to it.

	Nothing is recorded on the strength of equal size (`diff.PROVEN_EVIDENCE`), and nothing is
	recorded for a unit that did not reach the gate: the ledger is a set of claims there is evidence
	for, and a name made up in here would make the next unit fail for the wrong reason. The write is
	a separate connection on purpose - scoring reads the analysis, learning is the one thing it does
	to it.
	"""
	entries = []
	if candidate is not None and normalize.is_synthetic(row["name"] or ""):
		# `raw_name`, not `display`: a later candidate's call is disassembled with the symbol the
		# object carries, which is this spelling - mangled and all
		entries.append({"variant": variant, "entry": row["entry"], "kind": row["kind"] or "function",
			"candidate": candidate.raw_name, "evidence": "unit", "tier": verdict.tier,
			"unit": row["name"], "unit_entry": row["entry"],
			# which file this came from, so `decomp link` (Phase 6) can put the whole program back
			# together out of what passed without being told the sources again
			"source": str(sources[0]) if sources else "", "at": time.strftime("%Y-%m-%d")})
	for item in verdict.symbols:
		original, candidate = item.get("original") or {}, item.get("candidate") or {}
		if not item.get("ok") or item.get("evidence") not in diff.PROVEN_EVIDENCE:
			continue
		if original.get("named") or not original.get("address"):
			continue
		name = candidate.get("name") or ""
		if not name or name == "?":
			continue
		entries.append({"variant": variant, "entry": original["address"],
			"kind": original.get("kind") or "", "candidate": name,
			"evidence": item["evidence"], "tier": verdict.tier, "unit": row["name"],
			"unit_entry": row["entry"], "at": time.strftime("%Y-%m-%d")})
	with sqlite3.connect(db) as conn:
		written = cache.record_matches(conn, entries)
	return {"written": written, "pairs": entries}


@app.command("try")
def try_cmd(
	function: str = typer.Argument(..., help="the function to score (name, substring, 0x address)"),
	source: list[Path] = typer.Argument(..., help="candidate source file(s)"),
	fn: Optional[str] = typer.Option(None, "--fn",
		help="which symbol in the candidate to compare (default: the only function it defines)"),
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	variant: Optional[str] = typer.Option(None, "--variant", "-v",
		help="default: the variant the analysis was run with"),
	include: list[str] = typer.Option([], "--include", help="-I for the candidate build"),
	size: int = typer.Option(0, "--size", help="compare only N bytes of the original "
		"(use the compiler's symbol size where the analysis' own range differs, e.g. at -O2; a "
		"PE's own .pdata unit is already used without this)"),
	register_abstract: bool = typer.Option(False, "--register-abstract",
		help="accepted for compatibility and ignored: the register-folded comparison now runs on "
			"every try and is part of the tier (decomp/diff.py)"),
	learn: bool = typer.Option(True, "--learn/--no-learn",
		help="a unit that reaches the gate writes what it proved into the match ledger (Phase 5): "
		"its own symbol at this address, and its names for anonymous entities it reaches. Later "
		"units are scored against that - `decomp ledger` shows it, --no-learn leaves it alone"),
	gate: str = typer.Option("", "--gate",
		help="override the tier this unit has to reach: %s (default: [gate] require in the "
			"target config, else semantic)" % ", ".join(diff.GATE_MODES)),
	waive: str = typer.Option("", "--waive",
		help="wave aside something the tier would otherwise insist on (%s); default: [gate] waive "
		"in the target config" % ", ".join(diff.WAIVABLE)),
	max_diff: int = typer.Option(16, "--max-diff"),
	max_symbols: int = typer.Option(12, "--max-symbols"),
	as_json: bool = typer.Option(False, "--json"),
	keep: bool = typer.Option(True, "--keep/--no-keep", help="keep the candidate object file"),
) -> None:
	"""Compile a candidate and diff it against the original: the tier it reaches, the match %
	as a progress indicator, and only the differing instructions, categorised.

	The candidate is built with the target's own variant flags, so it is compared at the same
	-O and the same arch. The tool never edits source - it reports. The exit code is the tier:
	0 when the unit reaches the tier `[gate] require` asks for, non-zero when it does not.
	"""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	try:
		meta = cache.meta(conn)
		# A candidate has to be built the way the analysed binary was built, so the config that
		# produced this analysis is the right default when the caller did not name one.
		recorded = str(meta.get("config_path") or "")
		if not config_file and recorded and Path(recorded).is_file() and Path(recorded) != cfg["path"]:
			cfg = load_config(recorded)
			echo("config: %s (the one this analysis was run with)" % cfg["path"])
		rows = cache.resolve_function(conn, function, _other_addresses(function,
			cache.address_offset(meta)))
		if not rows:
			raise Stop(EXIT_NOT_FOUND, "no function matches %r in the analysis of %s" % (function,
				values.get("target_path")), "see what is there with: decomp find %s" % function)
		if len(rows) > 1:
			raise Stop(EXIT_USAGE, "%r matches %d functions:" % (function, len(rows)),
				*["  %s  %s" % (_hex(row["entry"]), row["name"]) for row in rows])
		row = rows[0]
		missing = [str(item) for item in source if not Path(item).is_file()]
		if missing:
			raise Stop(EXIT_USAGE, "no such source file: %s" % ", ".join(missing))
		try:
			outcome = score_candidate(cfg, conn, meta, row, [Path(item) for item in source], fn=fn,
				variant=variant, includes=list(include), size=size,
				register_abstract=register_abstract, object_dir=store.root / "candidates", gate=gate,
				waive=([item.strip() for item in waive.replace(",", " ").split() if item.strip()]
					if waive.strip() else None))
			verdict = outcome["verdict"]
			if learn and verdict is not None and verdict.passed:
				outcome["learned"] = _learn(Path(values["db"]), row, outcome["variant"], verdict,
					outcome["candidate"], [Path(item) for item in source])
		except config.ConfigError as exc:
			raise Stop(EXIT_USAGE, "%s" % exc)
		except NotImplementedError as exc:
			raise Stop(EXIT_USAGE, "%s" % exc)
	finally:
		conn.close()

	build: "compile.Build" = outcome["build"]
	if not keep and build.object_path.exists():
		build.object_path.unlink()

	verdict = outcome["verdict"]
	if as_json:
		payload = {
			"target": values.get("target_path"), "function": row["name"],
			"entry": _hex(row["entry"]), "size": row["size"], "kind": row["kind"],
			"variant": outcome["variant"], "flags": outcome["flags"],
			"gate": outcome["gate"], "gate_from": outcome["gate_from"],
			"waive": outcome.get("waive", []), "waive_from": outcome.get("waive_from", ""),
			"object": str(build.object_path), "build_ok": build.ok,
			"diagnostics": build.diagnostics, "warnings": outcome["warnings"],
			"error": outcome["error"],
			"original": None if outcome["original"] is None else {
				"name": outcome["original"].display, "address": _hex(outcome["original"].address),
				"size": outcome["original"].size, "section": outcome["original"].section},
			"candidate": None if outcome["candidate"] is None else {
				"name": outcome["candidate"].display, "section": outcome["candidate"].section,
				"size": outcome["candidate"].size},
			"result": None if verdict is None else {
				"tier": verdict.tier, "require": verdict.require, "passed": verdict.passed,
				"gaps_to_gate": verdict.gaps(verdict.require),
				"abstract_categories": verdict.abstract_categories,
				"threshold": verdict.threshold,
				"match_percent": verdict.match_percent, "categories": verdict.categories,
				"identical": verdict.identical, "bytes_equal": verdict.bytes_equal,
				"bytes_equal_masked": verdict.bytes_equal_masked,
				"bytes_masked": verdict.bytes_masked,
				"masked_byte_fields": verdict.masked_byte_fields,
				"masked_first_difference": verdict.masked_first_difference,
				"masked_offsets": outcome.get("masked_fields", {}),
				"original_instructions": verdict.original_instructions,
				"candidate_instructions": verdict.candidate_instructions,
				"original_bytes": verdict.original_bytes, "candidate_bytes": verdict.candidate_bytes,
				"diff": verdict.diff, "symbols": verdict.symbols,
				"unverified": verdict.unverified, "unverified_refs": verdict.unverified_refs,
				"ledger_known": outcome.get("ledger", 0), "learned": outcome.get("learned", {}),
				"waived": verdict.waive},
		}
		echo(json.dumps(payload, indent=1))
		if verdict is not None and verdict.passed:
			raise typer.Exit(EXIT_OK)
		raise typer.Exit(EXIT_NOT_FOUND if verdict is None and outcome["error_code"] == EXIT_NOT_FOUND
			else EXIT_FAIL)

	echo("target %s  (key %s, variant %s: %s)" % (values.get("target_path"),
		values.get("target_key"), outcome["variant"], " ".join(outcome["flags"])))
	echo("gate: %s (%s)" % (outcome["gate"], outcome["gate_from"]))
	if outcome.get("waive"):
		echo("waived: %s (%s)" % (", ".join(outcome["waive"]), outcome.get("waive_from", "")))
	for line in compile.describe(build):
		echo(line)
	for warning in outcome["warnings"]:
		echo("  note: %s" % warning)
	if verdict is None:
		echo("%s" % outcome["error"])
		raise typer.Exit(outcome["error_code"])
	echo()
	for line in diff.report_lines(verdict, "%s @ %s" % (outcome["original"].display,
		_hex(outcome["original"].address)), "%s (%s)" % (outcome["candidate"].display,
		outcome["candidate"].section), max_diff=max_diff, max_symbols=max_symbols):
		echo(line)
	if outcome.get("flag_advice"):
		# The exact tier is a claim about the build as much as about the source.
		echo()
		echo("the build this file names (its own records, not a guess about the source):")
		for line in outcome["flag_advice"]:
			echo("  %s" % line)
	learned = outcome.get("learned") or {}
	if learned.get("written"):
		echo("learned: %d pair%s added to the match ledger - what a later unit has to name the same "
			"way; see them with: decomp ledger" % (learned["written"],
				"s" if learned["written"] != 1 else ""))
	raise typer.Exit(EXIT_OK if verdict.passed else EXIT_FAIL)


# --------------------------------------------------------------------------------------
# link: the whole program (Docs/byte-cleanup-plan.md, Phase 6)


def _link_sources(conn, variant: str, explicit: list[Path]) -> tuple[list[Path], str]:
	"""Where the candidate sources come from.

	What the caller names, or what the match ledger says reproduced something: the ledger has the
	source every passing unit was compiled from (Phase 5 added the column), which is what makes
	"relink what the loop has actually reproduced" work without the caller re-listing files. A
	ledger written before that column is honest about it and asks for the paths.
	"""
	if explicit:
		return [Path(item).expanduser() for item in explicit], "named on the command line"
	paths: list[Path] = []
	blind = 0
	for row in cache.match_rows(conn, variant=variant):
		value = str(dict(row).get("source") or "")
		if not value:
			blind += 1
			continue
		path = Path(value)
		if path.is_file() and path not in paths:
			paths.append(path)
	why = ("the match ledger for variant %s: the source every unit that reached the gate was built "
		"from" % variant)
	if blind:
		why += " (%d pairs were recorded before the source was kept, and cannot name a file)" % blind
	return paths, why


@app.command("link")
def link_cmd(
	source: list[Path] = typer.Argument(None,
		help="candidate source file(s); default: the ones the match ledger says reproduced something"),
	object_: list[Path] = typer.Option([], "--object",
		help="link these object files instead of compiling sources"),
	output: Optional[Path] = typer.Option(None, "--output",
		help="where to write the linked program (default: under the tool's cache)"),
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	variant: Optional[str] = typer.Option(None, "--variant", "-v",
		help="default: the variant the analysis was run with"),
	section: list[str] = typer.Option([], "--section",
		help="compare only these sections (repeatable); default: every section the program is made of"),
	include: list[str] = typer.Option([], "--include", "-I",
		help="an extra include directory for the candidate sources (the variant's are always used)"),
	link_flag: list[str] = typer.Option([], "--link-flag",
		help="an extra link flag, for a target whose own link flags were never recorded - it is reported, never assumed"),
	partial: bool = typer.Option(False, "--partial",
		help="the sources do not cover the whole program: link anyway, with unresolved symbols allowed"),
	max_units: int = typer.Option(12, "--max-units", help="how many differing functions to name"),
	max_rows: int = typer.Option(8, "--max-rows", help="how many differing rows per section to name"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""Rebuild the program from what the loop reproduced, and compare it to the target whole.

	`decomp try` proves one function against the bytes at one address. That is enough to work on,
	and not enough to claim: a program can be made of functions that each match and still not be
	the program - a function that was never reproduced, a helper inlined one way and not the
	other, a data object placed differently, a link flag nobody recorded. This compiles the
	candidate sources with the target's own variant flags, links them with the target's own
	`linkflags`, and compares the result section by section at the addresses the link gave them,
	then names the first place they part.

	Read it by the first difference. Everything in the report after it that differs *only in what
	the link wrote* (an operand address, a displacement) is a consequence of that one place, not a
	new problem: the bytes of that body are the same, they are just sitting somewhere else. A body
	that differs in an instruction is the next thing to work on.

	ELF/static for now; a PE or Mach-O target says so rather than being compared with the wrong
	assumptions. Sources come from the match ledger unless named.
"""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	try:
		meta = cache.meta(conn)
		recorded = str(meta.get("config_path") or "")
		if not config_file and recorded and Path(recorded).is_file() and Path(recorded) != cfg["path"]:
			cfg = load_config(recorded)
		name, body = config.variant(cfg, variant or str(meta.get("variant") or ""))
		flags = toolchain.build_flags(body)
		linkflags, flags_from = config.link_flags(cfg, body)
		sources, sources_from = _link_sources(conn, name, [Path(item) for item in (source or [])])
		units = [dict(row) for row in conn.execute(
			"SELECT entry, name, size, section, kind FROM functions ORDER BY entry")]
		anchors = {}
		for row in cache.match_rows(conn, variant=name):
			anchors[int(row["entry"])] = row["candidate"]
	finally:
		conn.close()

	target_path = Path(str(meta.get("target_path") or ""))
	offset = int(str(meta.get("address_offset") or "0") or 0)
	language = str(meta.get("language_id") or "")
	compiler = body.get("compiler") or "g++"
	if not object_ and not sources:
		raise Stop(EXIT_USAGE, "nothing to link",
			"pass the candidate sources: decomp link <file.cpp> ... --bin %s" % target_path,
			"or reproduce functions first: `decomp try` records which source proved what, and "
			"`decomp link` reads that back (%s)" % sources_from)
	missing = [str(item) for item in [*sources, *object_] if not Path(item).is_file()]
	if missing:
		raise Stop(EXIT_USAGE, "no such file: %s" % ", ".join(missing))

	out_dir = Path(output).parent if output else (config.cache_dir(cfg) / "links"
		/ ("%s-%s" % (values.get("target_key"), name)))
	out_path = Path(output) if output else out_dir / str(Path(str(meta.get("target_path") or
		"program")).name)
	objects = [Path(item) for item in object_]
	built: list = []
	if sources:
		for item in sources:
			result = compile.build([Path(item)], (out_dir / "objects"
				/ compile.object_name([Path(item)])), compiler=compiler, flags=flags,
				includes=[*[Path(part) for part in config.include_dirs(cfg, body)],
					*[Path(part) for part in (include or [])]])
			built.append(result)
			if result.failed:
				break
			objects.append(result.object_path)
		bad = [item for item in built if item.failed]
		if bad:
			for line in compile.describe(bad[0]):
				echo(line)
			raise Stop(EXIT_FAIL, "%d of %d candidate sources did not compile: the program cannot "
				"be linked from them" % (len(bad), len(sources)))

	link = compile.link(objects, out_path, compiler=compiler, flags=flags, linkflags=linkflags,
		extra=[*(link_flag or ()), *(["-Wl,--unresolved-symbols=ignore-all"] if partial else [])])
	for line in compile.describe(link):
		echo(line)
	if link.failed:
		echo("the link is: %s" % " ".join(link.command))
		echo("  a program that is only partly reproduced needs `--partial`; an undefined symbol can "
			"also mean a function the loop has not reproduced yet (`decomp ledger` names the ones "
			"it has)")
		raise typer.Exit(EXIT_FAIL)

	echo("target   %s (key %s)" % (target_path, values.get("target_key")))
	echo("built by %s: %s" % (name, " ".join(flags)))
	echo("linked by %s" % " ".join(link.command))
	echo("link flags from %s" % flags_from)
	echo("sources from %s" % (sources_from if sources else
		"not used: --object named the files to link"))
	target = relink.Program(target_path, bias=offset)
	candidate = relink.Program(out_path)
	if target.error:
		raise Stop(EXIT_USAGE, target.error)
	if candidate.error:
		raise Stop(EXIT_USAGE, candidate.error)
	named = [{"address": item.address, "size": item.size, "name": item.name,
		"section": target._section_of(item.address)} for item in target.symbols
		if item.kind == "object" and item.size]
	warnings = []
	if not named:
		warnings.append("no data object is named on the target side (a stripped ELF carries no "
			"object symbols), so data is compared as whole sections and through the runtime "
			"relocations, not object by object")
	if not anchors:
		warnings.append("the match ledger names no candidate symbol for this variant, so functions "
			"are paired by layout and length, which cannot prove identity - the pairing says so "
			"wherever it applies (`decomp ledger` shows what has been proven)")
	if units:
		warnings.append("%d functions of the target are being paired; the candidate program's own "
			"symbol table is what they are matched against" % len(units))
	result = relink.compare_program(target, candidate, units=units, anchors=anchors,
		language=language, objects=named, only=[item for item in section if item])
	result["warnings"] = warnings + list(result.get("warnings", []))
	result["link"] = {"command": link.command, "output": str(out_path),
		"linkflags_from": flags_from, "sources_from": sources_from,
		"objects": [str(item) for item in objects]}
	if as_json:
		echo(json.dumps(result, indent=1, default=str))
		raise typer.Exit(EXIT_OK if result["identical"] else EXIT_FAIL)
	for line in relink.report_lines(result, max_units=max_units, max_rows=max_rows):
		echo(line)
	raise typer.Exit(EXIT_OK if result["identical"] else EXIT_FAIL)


def _structures_for(recovered, row) -> dict:
	"""What the recovered structure says about one function - for the report, not for the score."""
	bound = {"classes": [], "roles": []}
	for entry in recovered.role_of(int(row["entry"])):
		bound["roles"].append(entry)
		if entry["class"] not in bound["classes"]:
			bound["classes"].append(entry["class"])
	if bound["classes"]:
		reached = set()
		for item in cache.ref_summary(recovered.conn, int(row["id"])):
			address = item.get("to_address")
			if not address:
				continue
			object_ = recovered.object_at(int(address))
			if object_ and object_.get("class"):
				reached.add(object_["class"])
		for name in sorted(reached):
			if name not in bound["classes"]:
				bound["classes"].append(name)
	return bound


def _type_lines(recovered, only: str = "", limit: int = 40) -> list[str]:
	"""What was recovered, and how it knows - the text form of `decomp types`."""
	lines = ["note: %s" % note for note in recovered.notes]
	for name, klass in sorted(recovered.classes.items())[:limit]:
		lines.append("%s%s" % (name, "  : public " + ", public ".join(klass.bases)
			if klass.bases else ""))
		lines.append("  %s %s, %s %s%s" % (recovered.words["table"],
			_hex(klass.vtable) if klass.vtable else "not found in this file",
			recovered.words["type"], _hex(klass.typeinfo),
			", abstract (%d pure slots)" % klass.pure_count if klass.pure_count else ""))
		for line in klass.evidence:
			lines.append("    - %s" % line)
		for line in klass.notes:
			lines.append("    ! %s" % line)
		if klass.methods:
			lines.append("  vtable slots:")
			for method in klass.methods:
				lines.append("    slot %-2d +%-#4x  %-8s %s%s" % (method.index, method.offset,
					method.kind, method.name or ("0x%x" % method.address if method.address
						else "-"), "  [calls operator delete]" if method.deleting else ""))
		if klass.fields:
			lines.append("  fields (offsets the class's own code uses through `this`):")
			for offset, item in klass.fields.items():
				lines.append("    +%-#4x %-2d bytes  read %-2d written %-2d  %s" % (offset,
					item.size, item.reads, item.writes, ", ".join(item.sites[:3])
					+ ("" if len(item.sites) <= 3 else ", +%d more" % (len(item.sites) - 3))))
		else:
			lines.append("  fields: none attributable (no member function could be identified)")
		lines.append("  size: at least %d bytes (the highest offset the code reaches)"
			% klass.lower_bound)
	return lines


@app.command("types")
def types_cmd(
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	write: Optional[Path] = typer.Option(None, "--write",
		help="write the shared header here (a directory gets types.h inside it)"),
	show_class: Optional[str] = typer.Option(None, "--class", help="one class in full"),
	limit: int = typer.Option(40, "--limit"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""The C++ structure the target itself proves: vtables, RTTI, constructors, destructors,
	and the field offsets - and the shared header a candidate can include (Phase 4, MS-5).

	Nothing here needs Ghidra or symbols. A C++ program leaves its own type system in the file,
	and which one it is follows from the compiler: a GCC or Clang target emits a `type_info`
	object naming its type, with the vtable pointing at it; a target built by Microsoft's
	compiler emits a `.?AV<name>@@` type descriptor, an RTTICompleteObjectLocator that names it,
	and a vftable whose slot before the methods points at that locator. Either way the class
	name, its bases, its method slots and the offsets its code uses through `this` are in the
	data, and the model is chosen from the target's build note, not guessed.
	"""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	try:
		meta = cache.meta(conn)
		recovered = structures.Recovery(conn, meta).build()
		summary = recovered.summary()
		if write is not None:
			target = Path(write)
			if target.is_dir() or str(write).endswith("/"):
				target = target / "types.h"
			target.parent.mkdir(parents=True, exist_ok=True)
			target.write_text(recovered.header())
			on_path = [str(path) for path in config.include_dirs(cfg) if path.is_dir()]
			echo("wrote %s (%d classes)" % (target, summary["classes"]))
			echo("  a candidate in that directory can include types.h directly: `decomp try` "
				"puts the source's own directory on the include path already%s"
				% ("" if str(target.parent) in on_path else
					" - add -I%s with --include, or put it in [include_dirs]" % target.parent))
		if as_json:
			echo(json.dumps(dict(summary, detail=recovered.as_json()["detail"]), indent=1,
				default=str))
			raise typer.Exit(EXIT_OK if summary["classes"] else EXIT_NOT_FOUND)
		echo("; %s (key %s) %d-bit" % (values.get("target_path"), values.get("target_key"),
			summary["bits"]))
		echo("recovered in %.3fs: %d classes, %d %s, %d %s (%d candidate addresses probed)"
			% (summary["seconds"], summary["classes"], summary["vtables"],
				"vftables" if summary["abi"] == "msvc" else "vtables",
				summary["typeinfos"], "MSVC type descriptors" if summary["abi"] == "msvc"
					else "type_info objects", summary["probed"]))
		for line in _type_lines(recovered, show_class or "", limit):
			echo(line)
		if not summary["classes"]:
			echo("nothing recovered: this file carries no C++ type system at all - no MSVC type "
				"descriptor (`.?AV…`), and no Itanium `type_info` and vtable pair. It is a C "
				"binary, or C++ built with RTTI off (`/GR-`, `-fno-rtti`).")
	finally:
		conn.close()
	raise typer.Exit(EXIT_OK if summary["classes"] else EXIT_NOT_FOUND)


# --------------------------------------------------------------------------------------


def _address_offset(sections: list[dict], file_sections: dict, image_base: int) -> tuple[int | None, str | None]:
	"""The gap between Ghidra's addresses and the file's own ones.

	Ghidra loads a PIE at 0x100000, while `nm`, objdump and LIEF all speak the file's
	addresses. Phase 2 compares candidate bytes extracted from a `.o` with original bytes
	extracted from this file, so the two domains have to be reconciled once, here.
	"""
	for name in (".text", ".init", ".plt", "__text"):
		file_start = file_sections.get(name)
		ghidra_start = next((row["start"] for row in sections if row["name"] == name), None)
		if file_start is not None and ghidra_start is not None:
			return ghidra_start - file_start, name
	for row in sections:
		if row["executable"] and row["name"] in file_sections:
			return row["start"] - file_sections[row["name"]], row["name"]
	return None, None


def _other_addresses(ident: str, offset: int) -> list[int]:
	"""The same address in the other domain: a user pastes file addresses from nm/objdump,
	the analysis is keyed by Ghidra's."""
	text = ident.strip()
	if not offset or not re.fullmatch(r"(0x)?[0-9a-fA-F]+", text):
		return []
	value = int(text, 16) if text.lower().startswith("0x") else int(text)
	return [value - offset, value + offset]


def _prototype(row) -> str:
	"""The best signature there is: the decompiler's own header for the function, which knows
	the parameters; Ghidra's stored signature only when there is no pseudo-code."""
	if row["pseudocode"]:
		head = []
		for line in row["pseudocode"].splitlines():
			if not line.strip():
				continue
			if line.strip().startswith("{") or line.strip().endswith("{"):
				break
			head.append(line.strip())
		if head:
			return " ".join(head)
	return row["signature"] or ""


def _hex(value) -> str:
	try:
		return "0x%x" % int(value)
	except (TypeError, ValueError):
		return str(value)


def _hex_bytes(data) -> str:
	if not data:
		return "none"
	return "%d bytes, first %s" % (len(data), data[:8].hex())


def main(argv: list[str] | None = None) -> None:
	"""Entry point. Typer prints usage errors and turns `typer.Exit` into the exit code; the
	only thing handled here is `Stop`, the tool's own "here is what to do next" error."""
	try:
		app(args=argv, prog_name="decomp")
	except Stop as stop:
		for line in stop.lines:
			echo(line)
		raise SystemExit(stop.code)


if __name__ == "__main__":
	sys.exit(main())
