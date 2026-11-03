"""Startup checks: Ghidra install, JDK, Python, the analysis cache path, the compilers.

Every check names what it looked for and what to do about it, because the Java exceptions
these correspond to are unreadable from a shell (Docs/Setup.md §1, §3).
"""

from __future__ import annotations

import importlib
import importlib.metadata
import glob
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import config

OK, FAIL, WARN = "ok", "fail", "warn"


@dataclass
class Item:
	name: str
	level: str
	detail: str
	fix: str = ""


class Report:
	def __init__(self) -> None:
		self.items: list[Item] = []

	def add(self, name: str, ok: bool, detail: str, fix: str = "", fatal: bool = True) -> None:
		self.items.append(Item(name, OK if ok else (FAIL if fatal else WARN), detail, fix))

	@property
	def failed(self) -> bool:
		return any(item.level == FAIL for item in self.items)

	def lines(self) -> list[str]:
		width = max(len(item.name) for item in self.items) if self.items else 0
		out = []
		for item in self.items:
			mark = {"ok": "ok  ", "fail": "FAIL", "warn": "warn"}[item.level]
			out.append("%-*s  %-4s  %s" % (width, item.name, mark, item.detail))
			if item.fix and item.level != OK:
				out.append("%-*s      -> %s" % (width, "", item.fix))
		return out


def module_version(distribution: str, import_name: str) -> str | None:
	"""Version of an installed dependency, or None when it is missing."""
	try:
		importlib.import_module(import_name)
		return importlib.metadata.version(distribution)
	except (ImportError, importlib.metadata.PackageNotFoundError):
		return None


def java_binary() -> str | None:
	home = os.environ.get("JAVA_HOME")
	if home:
		candidate = Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")
		if candidate.is_file():
			return str(candidate)
	return shutil.which("java")


def java_major(java_path: str) -> int | None:
	try:
		proc = subprocess.run([java_path, "-version"], capture_output=True, text=True, timeout=60)
	except OSError:
		return None
	text = (proc.stderr or "") + (proc.stdout or "")
	match = re.search(r'version "(\d+)(?:\.(\d+))?', text)
	if not match:
		return None
	return int(match.group(1))


def bundled_pyghidra_version(install_dir: Path) -> str | None:
	"""Version of the pyghidra wheel that ships inside this Ghidra.

	PyGhidra has its own version number (Ghidra 12.1.2 ships pyghidra 3.1.0), so the pairing
	is checked against the bundled wheel rather than against Ghidra's version.
	"""
	pattern = str(install_dir / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist" / "pyghidra-*.whl")
	for name in sorted(glob.glob(pattern)):
		match = re.search(r"pyghidra-([^-]+)-", os.path.basename(name))
		if match:
			return match.group(1)
	return None


def check_all(cfg: dict, want_compilers: bool = True) -> Report:
	"""Run every startup check. `want_compilers=False` downgrades missing compilers to a
	warning, which is what `analyze` does (analysis needs no compiler; `try` will)."""
	report = Report()

	install_dir, tried = config.ghidra_install_dir(cfg)
	if install_dir is None:
		report.add("ghidra install", False,
			"no Ghidra installation found; tried: %s" % "; ".join(tried),
			"install Ghidra system-wide and set GHIDRA_INSTALL_DIR, or set [ghidra] install_dir "
			"in %s" % cfg["path"])
	else:
		properties = config.application_properties(install_dir)
		version = properties.get("application.version", "?")
		report.add("ghidra install", True, "%s (version %s)" % (install_dir, version))

		pyghidra = module_version("pyghidra", "pyghidra")
		bundled = bundled_pyghidra_version(install_dir)
		if pyghidra is None:
			report.add("pyghidra module", False,
				"the importable pyghidra module is not installed in this interpreter",
				'pip install "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist/'
				'pyghidra-*.whl" (Docs/Setup.md §2 - never the PyPI one)')
		elif bundled is None:
			report.add("pyghidra module", False,
				"pyghidra %s is installed but %s ships no wheel to compare it with"
				% (pyghidra, install_dir),
				"Ghidra/Features/PyGhidra/pypkg/dist/ must contain pyghidra-*.whl - a partial "
				"Ghidra install cannot drive PyGhidra", fatal=False)
		elif pyghidra != bundled:
			report.add("pyghidra module", False,
				"pyghidra %s is not the pyghidra %s bundled with Ghidra %s"
				% (pyghidra, bundled, version),
				"pip install %s/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-%s-py3-none-any.whl"
				% (install_dir, bundled))
		else:
			report.add("pyghidra module", True, "pyghidra %s = the wheel bundled with Ghidra %s"
				% (pyghidra, version))

		min_java = int(properties.get("application.java.min") or config.DEFAULT_JAVA_MIN)
		java_path = java_binary()
		if java_path is None:
			report.add("java", False, "no java on PATH and JAVA_HOME is unset",
				"install a JDK %d+ (Ghidra %s requires it)" % (min_java, version))
		else:
			major = java_major(java_path)
			if major is None:
				report.add("java", False, "could not read the version of %s" % java_path, "check the JDK install")
			else:
				report.add("java", major >= min_java, "%s -> java %d (Ghidra needs %d+)"
					% (java_path, major, min_java), "install a JDK %d+" % min_java)

		supported = [p.strip() for p in (properties.get("application.python.supported") or "").split(",") if p.strip()]
		running = "%d.%d" % sys.version_info[:2]
		if supported:
			report.add("python", running in supported,
				"CPython %s %s in application.python.supported (%s)"
				% (running, "is" if running in supported else "is not", ", ".join(supported)),
				"use one of the supported Pythons for this Ghidra (Docs/Setup.md §1)")

	jpype = module_version("jpype1", "jpype")
	report.add("jpype1", jpype is not None, "jpype1 %s" % (jpype or "missing"),
		"it comes as a dependency of the bundled pyghidra wheel")
	capstone = module_version("capstone", "capstone")
	report.add("capstone", capstone is not None, "capstone %s" % (capstone or "missing"),
		"pip install capstone (used to disassemble both sides)")
	lief = module_version("lief", "lief")
	report.add("lief", lief is not None, "lief %s" % (lief or "missing"),
		"pip install lief (used for the build note and, from Phase 2, the candidate .o)",
		fatal=False)

	try:
		cache_root = config.cache_dir(cfg)
	except config.ConfigError as exc:
		report.add("analysis cache", False, str(exc), "fix [ghidra] cache_dir in %s" % cfg["path"])
	else:
		usable = cache_root.is_dir() or _try_mkdir(cache_root)
		report.add("analysis cache", usable, "%s%s" % (cache_root, "" if cache_root.is_dir() else " (created)"),
			"the directory must be writable and outside dot-prefixed path elements")
		if str(cache_root).startswith(("/tmp", "/run", "/dev/shm")):
			report.items.append(Item("analysis cache", WARN,
				"%s is not durable - every new session re-runs the analysis" % cache_root))

	try:
		names = config.variants(cfg)
	except config.ConfigError as exc:
		report.add("compilers", False, str(exc), "add a [variants.<name>] table")
	else:
		for name, body in sorted(names.items()):
			compiler = body.get("compiler", "g++")
			problems = _compiler_problem(compiler)
			message = "%s: %s" % (name, problems or "%s -> %s" % (compiler, shutil.which(compiler) or compiler))
			if problems:
				report.add("compiler %s" % name, False, message,
					"install %s, or point [variants.%s] compiler at one that exists" % (compiler, name),
					fatal=want_compilers)
			else:
				report.add("compiler %s" % name, True, message)
	return report


def _try_mkdir(path: Path) -> bool:
	try:
		path.mkdir(parents=True, exist_ok=True)
		return True
	except OSError:
		return False


def _compiler_problem(compiler: str) -> str:
	"""Empty when `<compiler> --version` answers, otherwise the reason it does not."""
	path = shutil.which(compiler)
	if path is None:
		return "not found on PATH"
	try:
		proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60)
	except OSError as exc:
		return "cannot run: %s" % exc
	if proc.returncode != 0:
		return "--version failed (%d)" % proc.returncode
	first = (proc.stdout or proc.stderr).strip().splitlines()
	return "" if first else "--version printed nothing"
