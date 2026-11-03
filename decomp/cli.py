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

from . import __version__, cache, check, config, ghidra, toolchain

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
	if meta.get("build_notes"):
		echo("  built by  %s" % meta["build_notes"])
	elif meta.get("build_error"):
		echo("  build note: %s" % meta["build_error"])
	echo("  variant   %s (%s -O%s)" % (name, body.get("compiler"), body.get("optimize")))
	echo("  functions %s bodies, %s thunks, %s external" % (meta["body_count"], meta["thunk_count"],
		meta["external_function_count"]))
	echo("  exported  %s instructions, %s references, %s strings, %s pseudo-code" % (
		meta["instruction_count"], meta["reference_count"], meta["string_count"], meta["decompiled_count"]))
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
		offset = int(meta.get("address_offset") or 0)
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
		echo("; source bytes: %s" % _hex_bytes(row["bytes"]))
		echo("; analysis: %s  %s  (key %s, variant %s)" % (meta.get("language_id"),
			meta.get("ghidra_version"), meta.get("target_key"), meta.get("variant")))

		if calls:
			_print_callers_callees(conn, fn_id, max_lines)
		if refs:
			_print_refs(conn, fn_id, max_lines)
		if code:
			_print_pseudocode(row, max_lines)
		if asm:
			_print_asm(conn, fn_id, max_lines)
	finally:
		conn.close()


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
# find


@app.command()
def find(
	query: str = typer.Argument(..., help="name, substring, 0x address, or string content"),
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	limit: int = typer.Option(40, "--limit"),
	as_json: bool = typer.Option(False, "--json"),
) -> None:
	"""Search a cached analysis by name, address, or the strings a function reads.

	(xref/vtable queries and flag inference come with Phase 3.)
	"""
	cfg = load_config(config_file)
	store = cache.Cache(config.cache_dir(cfg))
	conn, values = open_analysis(store, binary, key)
	try:
		offset = int(cache.meta(conn).get("address_offset") or 0)
		hits = cache.find(conn, query, limit, _other_addresses(query, offset))
	finally:
		conn.close()
	if as_json:
		echo(json.dumps({"target": values.get("target_path"), **hits}, indent=1))
		raise typer.Exit(EXIT_OK if any(hits.values()) else EXIT_NOT_FOUND)
	echo("; %s (key %s)" % (values.get("target_path"), values.get("target_key")))
	echo("functions (%d):" % len(hits["functions"]))
	for row in hits["functions"]:
		echo("  %s  %-6s %6s  %s" % (_hex(row["entry"]), row["kind"], row["size"], row["name"]))
	echo("strings (%d):" % len(hits["strings"]))
	for row in hits["strings"]:
		echo("  %s  [%s]  %r" % (_hex(row["address"]), row["section"], row["value"]))
	echo("functions referencing it (%d):" % len(hits["touching"]))
	for row in hits["touching"]:
		echo("  %s  %s  -> %s" % (_hex(row["entry"]), row["name"], row["to_name"]))
	if not any(hits.values()):
		echo("nothing matched %r" % query)
	raise typer.Exit(EXIT_OK if any(hits.values()) else EXIT_NOT_FOUND)


# --------------------------------------------------------------------------------------
# later phases


@app.command("try")
def try_cmd(
	function: str = typer.Argument(..., help="the function to score"),
	source: Path = typer.Argument(..., help="candidate source file"),
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
	variant: Optional[str] = typer.Option(None, "--variant", "-v"),
) -> None:
	"""Compile a candidate and diff it against the original. Not implemented until Phase 2."""
	echo("`decomp try` is Phase 2 (Docs/Design-Plan.md): compile -> extract -> normalise -> diff.")
	echo("Implemented so far: check, analyze, status, show, find.")
	raise typer.Exit(EXIT_NOT_FOUND)


@app.command("types")
def types_cmd(
	binary: Optional[Path] = typer.Option(None, "--bin"),
	key: Optional[str] = typer.Option(None, "--key"),
	config_file: Optional[str] = typer.Option(None, "--config", "-C"),
) -> None:
	"""The shared struct/class definitions recovered so far. Not implemented until Phase 4."""
	echo("`decomp types` is Phase 4 (Docs/Design-Plan.md): vtables, RTTI and the shared header.")
	raise typer.Exit(EXIT_NOT_FOUND)


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
