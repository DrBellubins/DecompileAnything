"""Per-target configuration: project.toml discovery, Ghidra install resolution, cache paths.

Same file shape as Tests/project.toml (which Tests/eval.py reads) plus the analysis side,
per Docs/Setup.md §3:

	[ghidra]
	install_dir = "/opt/ghidra"
	cache_dir   = "cache/ghproj"
	language    = ""
"""

from __future__ import annotations

import os
import shutil
import tomllib
from pathlib import Path

CONFIG_NAME = "project.toml"
FALLBACK_GHIDRA_DIRS = ("/opt/ghidra",)
DEFAULT_JAVA_MIN = 21


class ConfigError(Exception):
	"""A configuration or path problem worth naming to the caller before any work."""


def find_config(explicit: str | None = None, target: Path | None = None) -> tuple[Path, str]:
	"""Return (path, how_it_was_found). Never returns a missing file."""
	if explicit:
		path = Path(explicit).expanduser()
		if not path.is_file():
			raise ConfigError("--config %s: no such file" % path)
		return path.resolve(), "--config"

	candidates: list[tuple[Path, str]] = []
	if target is not None:
		candidates.append((target.parent / CONFIG_NAME, "next to the target binary"))
	here = Path.cwd()
	for directory in [here, *here.parents]:
		candidates.append((directory / CONFIG_NAME, "in a parent directory of the cwd"))
	# the package's own defaults; cache_dir there is written relative to the package,
	# i.e. <repo>/cache/ghproj
	candidates.append((Path(__file__).resolve().parent / CONFIG_NAME, "the packaged default"))
	for path, how in candidates:
		if path.is_file():
			return path.resolve(), how
	raise ConfigError("no %s found (looked next to the target, in the cwd and its parents, and in %s)"
		% (CONFIG_NAME, Path(__file__).resolve().parent))


def load(explicit: str | None = None, target: Path | None = None) -> dict:
	"""Read a target config and return {path, root, raw}. Raises ConfigError on a bad file."""
	path, how = find_config(explicit, target)
	try:
		with path.open("rb") as handle:
			raw = tomllib.load(handle)
	except (OSError, tomllib.TOMLDecodeError) as exc:
		raise ConfigError("%s: %s" % (path, exc)) from exc
	if not isinstance(raw, dict):
		raise ConfigError("%s: top level must be a table" % path)
	raw["_found"] = how
	return {"path": path, "root": path.parent, "raw": raw}


def cache_dir(config: dict) -> Path:
	"""Absolute analysis cache directory, validated against Ghidra's ProjectLocator rules."""
	raw = config["raw"].get("ghidra", {}).get("cache_dir")
	if raw:
		path = Path(os.path.expandvars(os.path.expanduser(str(raw))))
		path = path if path.is_absolute() else (config["root"] / path)
	else:
		path = config["root"] / "cache" / "ghproj"
	path = Path(os.path.realpath(path))
	problem = cache_path_problem(path)
	if problem:
		raise ConfigError("[ghidra] cache_dir %s: %s (Docs/Setup.md §3)" % (path, problem))
	return path


def cache_path_problem(path: Path) -> str | None:
	"""Why Ghidra would reject this project path, or None if it would accept it.

	Both rules raise unhelpful Java exceptions, so they are checked before starting the JVM:
	ProjectLocator wants an absolute path and no path element starting with '.'.
	"""
	if not path.is_absolute():
		return "not an absolute path (Absolute path required)"
	for element in path.parts:
		if element.startswith("."):
			return "path element %r starts with '.' (Path element starting with '.' is not permitted)" % element
	return None


def ghidra_install_dir(config: dict | None = None) -> tuple[Path | None, list[str]]:
	"""Resolve the Ghidra install directory. Returns (path_or_None, tried).

	Order (Docs/Setup.md §3): GHIDRA_INSTALL_DIR, [ghidra] install_dir, /opt/ghidra,
	then `ghidra` on PATH resolved through its symlinks.
	"""
	tried: list[str] = []

	def check(value: str, source: str) -> Path | None:
		path = Path(os.path.expandvars(os.path.expanduser(value)))
		if not path.is_absolute():
			if config is not None:
				path = config["root"] / path
			else:
				path = Path.cwd() / path
		path = Path(os.path.realpath(path))
		tried.append("%s -> %s" % (source, path))
		return path if (path / "Ghidra" / "application.properties").is_file() else None

	sources: list[tuple[str, str]] = []
	env = os.environ.get("GHIDRA_INSTALL_DIR")
	if env:
		sources.append((env, "env GHIDRA_INSTALL_DIR"))
	if config is not None:
		installed = config["raw"].get("ghidra", {}).get("install_dir")
		if installed:
			sources.append((str(installed), "[ghidra] install_dir in %s" % config["path"]))
	for fallback in FALLBACK_GHIDRA_DIRS:
		sources.append((fallback, "fallback path"))
	for launcher in ("ghidra", "ghidra-analyzeHeadless"):
		found = shutil.which(launcher)
		if found:
			sources.extend((str(parent), "`%s` on PATH" % launcher) for parent in
				[Path(found).resolve(), *Path(found).resolve().parents])

	for value, source in sources:
		path = check(value, source)
		if path is not None:
			return path, tried
	return None, tried


def application_properties(install_dir: Path) -> dict:
	"""Parse <install>/Ghidra/application.properties (version, java min, python support)."""
	path = install_dir / "Ghidra" / "application.properties"
	properties: dict[str, str] = {}
	try:
		for line in path.read_text(errors="replace").splitlines():
			line = line.strip()
			if not line or line.startswith("#") or "=" not in line:
				continue
			key, value = line.split("=", 1)
			properties[key.strip()] = value.strip()
	except OSError:
		pass
	properties["_path"] = str(path)
	return properties


def language(config: dict) -> str:
	"""Empty means: let Ghidra auto-select the language."""
	return str(config["raw"].get("ghidra", {}).get("language") or "")


def variants(config: dict) -> dict:
	raw = config["raw"].get("variants") or {}
	if not raw:
		raise ConfigError("%s: no [variants.<name>] table - the tool must know how the target was built"
		% config["path"])
	return raw


def variant(config: dict, name: str | None) -> tuple[str, dict]:
	table = variants(config)
	if name is None:
		if len(table) != 1:
			raise ConfigError("%s: --variant is required, more than one is configured (%s)"
				% (config["path"], ", ".join(sorted(table))))
		name = next(iter(table))
	if name not in table:
		raise ConfigError("%s: no [variants.%s] (configured: %s)"
			% (config["path"], name, ", ".join(sorted(table))))
	body = dict(table[name])
	body.setdefault("compiler", "g++")
	body.setdefault("optimize", 0)
	body.setdefault("arch", "x86-64")
	body.setdefault("std", config["raw"].get("std", "c++17"))
	body["cppflags"] = list(body.get("cppflags", config["raw"].get("cppflags", [])))
	body["linkflags"] = list(body.get("linkflags", config["raw"].get("linkflags", [])))
	return name, body


def threshold(config: dict) -> float:
	return float(config["raw"].get("threshold", 97.0))


def gate(config: dict, variant: dict | None = None) -> tuple[str, str]:
	"""The tier a unit has to reach: `[gate] require` in the target config, or a `gate` key in
	the `[variants.*]` table, else `semantic` (Docs/byte-cleanup-plan.md, Phase 2).

	Returns (require, where_it_came_from). One target relaxes it where no tier can honestly be
	claimed - an LTCG MSVC image, a toolchain this machine cannot reproduce - and says so in the
	file rather than in the tool. `percent` is the pre-Phase-2 rule (threshold, no opcode or
	relocation differences); `none` turns the gate off.
	"""
	from .diff import GATE_DEFAULT, GATE_MODES  # local: keep this module import-light
	table = config["raw"].get("gate") or {}
	value, where = None, ""
	if isinstance(table, dict) and table.get("require"):
		value, where = str(table["require"]), "[gate] require in %s" % config["path"]
	if variant and variant.get("gate"):
		value, where = str(variant["gate"]), "the variant's gate key in %s" % config["path"]
	if value is None:
		return GATE_DEFAULT, "the default (no [gate] require in %s)" % config["path"]
	if value not in GATE_MODES:
		raise ConfigError("%s: %s is not a gate - use one of %s"
			% (config["path"], value, ", ".join(GATE_MODES)))
	return value, where


def gate_waivers(config: dict, variant: dict | None = None) -> tuple[list[str], str]:
	"""What the gate is allowed to wave aside: `[gate] waive` in the target config, or a `waive`
	key in a `[variants.*]` table (Docs/byte-cleanup-plan.md, Phase 4).

	The one waiver today is `unverified`: references both sides reach but neither can name, bound
	or read. They stop a unit claiming `semantic`, because "same operations, operands and targets"
	is only true of a unit whose references are known. A target where no source can do better - a
	stripped binary whose data has no symbols, where every `.rodata` object is anonymous - says so
	here, in the file, rather than having the tool hand out a tier it cannot prove.
	"""
	from .diff import WAIVABLE  # local: keep this module import-light

	def values(table) -> list[str]:
		if not isinstance(table, dict):
			return []
		value = table.get("waive")
		if isinstance(value, str):
			value = value.replace(",", " ").split()
		return [str(item).strip() for item in (value or []) if str(item).strip()]

	out, where = values(config["raw"].get("gate")), ""
	if out:
		where = "[gate] waive in %s" % config["path"]
	if variant and values(variant):
		out, where = values(variant), "the variant's waive key in %s" % config["path"]
	unknown = [item for item in out if item not in WAIVABLE]
	if unknown:
		raise ConfigError("%s: waive %s is not something this gate can wave aside - the options "
		"are %s" % (config["path"], ", ".join(unknown), ", ".join(WAIVABLE)))
	return out, where


def link_flags(config: dict, variant: dict | None = None) -> tuple[list[str], str]:
	"""The link flags the target's own build used: a `linkflags` key in the `[variants.*]` table,
	or the top-level `[linkflags]`, else nothing. Returns (flags, where_from).

	`decomp link` (Docs/byte-cleanup-plan.md, Phase 6) has to link the way the target was linked,
	or its section layout means nothing. The tool adds no flags of its own: a link it chose is not
	the target's link. Where none were recorded it says so, because that is a real limit on the
	claim - `-static`, a version script, `-Wl,--build-id=none` or `/ORDER` all move bytes around.
	"""
	variant_values = [str(item) for item in ((variant or {}).get("linkflags") or [])]
	top = [str(item) for item in (config["raw"].get("linkflags") or [])]
	if variant_values:
		return variant_values, "the variant's linkflags in %s" % config["path"]
	if top:
		return top, "[linkflags] in %s" % config["path"]
	return [], ("nothing - no linkflags are recorded in %s, so the link is the compiler's "
		"default" % config["path"])


def include_dirs(config: dict, variant: dict | None = None) -> list[Path]:
	"""Directories the candidate may include from - `[include_dirs]` in the target config, or
	the same key inside a `[variants.*]` table. Relative paths are relative to the config
	file, like `cache_dir` is. Phase 4's shared `types.h` header lives in one of these."""
	values = list(config["raw"].get("include_dirs") or [])
	if variant:
		values += list(variant.get("include_dirs") or [])
	out: list[Path] = []
	for value in values:
		path = Path(os.path.expandvars(os.path.expanduser(str(value))))
		out.append(path if path.is_absolute() else (config["root"] / path))
	return out
