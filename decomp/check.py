"""Startup checks: Ghidra install, JDK, Python, the analysis cache path, the compilers.

Every check names what it looked for and what to do about it, because the Java exceptions
these correspond to are unreadable from a shell (Docs/Setup.md §1, §3).

The MSVC half (Docs/MSVC-Plan.md MS-2) has a requirement the gcc half does not: `cl` is only
useful together with `link`, `lib` and `dumpbin` of the *same era*, and a tool found by name
may not be the tool it claims to be - `/usr/bin/link` on Linux is binutils' `link`, which
shares nothing with Microsoft's `link.exe`. So every MSVC tool here is identified by its
banner, and the reported version is the toolset family, not a bare version string.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import glob
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import config
from . import spawn
from . import toolchain

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
	proc = spawn.run([java_path, "-version"], timeout=60)
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
		prefix, prefix_from = config.msvc_prefix(cfg)
		for name, body in sorted(names.items()):
			compiler = body.get("compiler", "g++")
			# X86-2: a variant's `arch` picks the driver, and `decomp try` asks the resolver. So `check`
			# reports the driver `try` would actually run - a pinned or installed toolchain's wrapper,
			# named by path - rather than only what a shell PATH happens to hold. Otherwise the two
			# disagree about whether a variant can be built, which is the disagreement this whole
			# phase exists to remove.
			driver = toolchain.compiler_for(body, prefix=prefix, prefix_from=prefix_from)
			problems = _compiler_problem(driver.name or compiler)
			off_path = bool(driver.name) and shutil.which(compiler) is None
			message = "%s: %s" % (name, problems or "%s -> %s%s" % (compiler,
				shutil.which(driver.name or compiler) or driver.name or compiler,
				" (not on PATH; the driver is named by path)" if off_path else ""))
			if problems:
				report.add("compiler %s" % name, False, message,
					"install %s, or point [variants.%s] compiler at one that exists; for an MSVC "
					"variant the driver also comes from [msvc] prefix or the toolchain under "
					"toolchains/ (Docs/Setup.md §6.2)" % (compiler, name),
					fatal=want_compilers)
			else:
				report.add("compiler %s" % name, True, message)
			# X86-0: does this variant's target arch exist here at all? Asked per variant, before
			# anything is compiled, so a 32-bit request is not answered with a 64-bit object.
			gap = variant_arch_gap(body)
			if gap:
				report.add("arch %s" % name, False,
					"variant %s: %s" % (name, gap),
					"see the `msvc target <arch>` lines below, or Docs/Setup.md §6.7 / "
					"Docs/MSVC-x86-Plan.md X86-1 for what would add it", fatal=want_compilers)
		msvc_report(report, [body.get("compiler", "g++") for body in names.values()], want_compilers)
		build_agreement(report, cfg, names)
	return report


def build_agreement(report: "Report", cfg: dict, variants: dict) -> None:
	"""Phase 7: was each analysed target built by the compiler its variant would use here?

	This is the check that tells an operator why `exact` is out of reach before a loop starts: a
	file whose own `.comment` names another release, or a PE built by MSVC whose variant names
	`g++`, cannot be byte-matched by the toolchain in front of them. It reads what `decomp analyze`
	recorded about each file rather than re-reading the binaries, and a file that names nothing is
	left alone: not knowing is not a mismatch. Warnings, never failures - an existing analysis is
	still worth working with, and the report says which way to go about it.
	"""
	from . import cache  # local: the analysis store is not needed by any other check
	from . import fidelity

	try:
		targets = cache.Cache(config.cache_dir(cfg)).targets()
	except config.ConfigError:
		return  # `check_all` already reported the cache path when it is unusable
	seen: set[tuple] = set()
	for values in targets:
		target = Path(str(values.get("target_path") or ""))
		for name, body in sorted(variants.items()):
			compiler = str(body.get("compiler", "g++"))
			agreement = fidelity.cached_agreement(values, compiler)
			if agreement["state"] in ("same", "unknown"):
				continue
			key = (target.name, agreement["detail"])
			if key in seen:
				continue
			seen.add(key)
			report.items.append(Item("built by %s" % target.name, WARN,
				"variant %s: %s" % (name, agreement["detail"]),
				"use a variant whose compiler matches the file, or install the release the file names "
				"(Docs/Setup.md §6); the exact tier is not available across the gap"))


# ---------------------------------------------------------------------------------------
# the MSVC toolchain (Docs/MSVC-Plan.md MS-2)

# The tools a candidate build needs, in the order they are worth reporting. `cl` compiles,
# `link` links, `lib` builds .lib stubs, `dumpbin` is how a COFF candidate is read by eye,
# `undname` turns a decorated name into something a human can read (display only - the
# decorated name stays the comparison key).
MSVC_TOOLS = ("cl", "link", "lib", "dumpbin", "undname")

# How to make each tool print its banner. `cl /?` prints only the option list - the banner
# comes with /Bv (which then fails for want of a source file, which is fine here). The
# others print it with /?. `--version` is tried last: it answers for binutils and clang-cl,
# which is how the impostors get named.
def _banner_arguments(name: str) -> list[list[str]]:
	if name == "cl":
		return [["/Bv", "/c"], ["--version"], ["/?"]]
	return [["--version"], ["/?"]]

# "Microsoft (R) Incremental Linker Version 14.12.25835", "Microsoft (R) C/C++ Optimizing
# Compiler Version 19.12.25835 for x64", "Microsoft (R) COFF/PE Dumper Version ...".
_MSVC_BANNER = re.compile(r"Microsoft \(R\)(?P<what>[^\n]*?)(?:Version|for x\d+)\s+(?P<version>\d+\.\d+[\d.]*)")
# What a non-MSVC tool of that name answers with. On this machine /usr/bin/link is GNU
# coreutils' `link` (the link() syscall wrapper); binutils' linker is `ld`. Both are
# impostors for an MSVC build, so the match is on "GNU", not on one package name.
_IMPOSTOR_BANNER = re.compile(r"\bGNU\b|binutils|coreutils", re.I)

# Path + arguments -> the run that produced its banner. See `_run`.
_BANNER_CACHE: dict[tuple[str, tuple[str, ...]], spawn.Result] = {}


def banner_note() -> str:
	"""Anything the tool probes had to add to the environment to get an answer (Wine prefix)."""
	for result in _BANNER_CACHE.values():
		if result.note:
			return result.note
	return ""


class Tool:
	"""One MSVC-family tool as found on this machine, identified rather than assumed."""

	def __init__(self, name: str, path: str | None = None) -> None:
		self.name = name
		self.path = path or shutil.which(name)
		self.text = ""
		self.what = ""       # the tool's own description, from its banner
		self.version = ""    # the version the banner prints, e.g. 19.12.25835
		self.vendor = "none"  # msvc | clang | gnu | unknown | none
		if self.path:
			self._identify()

	@property
	def found(self) -> bool:
		return bool(self.path)

	def _identify(self) -> None:
		# Two spellings, because the drivers disagree: /? and /Bv are MSVC's, --version answers
		# for binutils/coreutils and for clang-cl.
		texts = []
		for arguments in _banner_arguments(self.name):
			texts.append(_run(self.path, arguments))
			if any(_MSVC_BANNER.search(t or "") for t in texts):
				break
			if any(_IMPOSTOR_BANNER.search(t or "") for t in texts):
				break
		self.text = "\n".join(t for t in texts if t).strip()
		match = _MSVC_BANNER.search(self.text)
		if match:
			self.vendor = "msvc"
			self.what = match.group("what").strip()
			self.version = match.group("version")
			return
		if _IMPOSTOR_BANNER.search(self.text):
			self.vendor = "gnu"
			self.what = _first_line(self.text)
			return
		if "clang" in self.text.lower():
			self.vendor = "clang"
			self.what = _first_line(self.text)
			self.version = self.what.split()[-1] if self.what else ""
			return
		self.vendor = "unknown"
		self.what = _first_line(self.text) or (self.path + " printed nothing")

	def toolset(self) -> dict | None:
		"""The toolset family this tool belongs to.

		`cl` reports its own version (19.12), which is the same minor as the toolset the
		linker reports (14.12) for every toolset from VS2015 on; `link`/`lib`/`dumpbin`
		report the linker version directly, which is what `msvc_toolset` reads.
		"""
		if not self.version:
			return None
		parts = self.version.split(".")
		try:
			major, minor = int(parts[0]), int(parts[1])
		except (IndexError, ValueError):
			return None
		if self.name == "cl" or major >= 19:
			if major < 16:
				return None
			# cl and link share the minor; the major only differs from VS2017 on, where the
			# compiler stayed at 19.x while the toolset numbering went 14.10, 14.20, 14.30...
			return toolchain.msvc_toolset("%d.%d" % (14 if major >= 19 else major - 6, minor))
		return toolchain.msvc_toolset("%d.%d" % (major, minor))

	def describe(self) -> str:
		if not self.found:
			return "no %s on PATH" % self.name
		family = (self.toolset() or {}).get("family")
		if self.vendor == "msvc":
			return "%s -> %s %s%s" % (self.path, self.what, self.version,
				" = toolset %s" % family if family else "")
		if self.vendor == "clang":
			return "%s -> %s (COFF output, but not Microsoft codegen - never an MSVC variant)" % (self.path, self.what)
		if self.vendor == "gnu":
			return "%s -> %s: not Microsoft's %s.exe, it only shares the name" % (self.path, self.what, self.name)
		return "%s -> %s" % (self.path, self.what)

	def wine_wrapper(self) -> bool:
		"""True when this is a shell wrapper that starts the real tool through Wine."""
		try:
			text = Path(self.path).read_text(errors="replace")
		except (OSError, ValueError):
			return False
		return text.startswith("#!") and "wine" in text.lower()


def _first_line(text: str) -> str:
	lines = [line.strip() for line in text.splitlines() if line.strip()]
	return lines[0] if lines else ""


def _run(path: str, arguments: list[str]) -> str:
	"""One banner. Bounded, and asked once per tool path per process.

	The bound matters more here than anywhere else in the tool: a banner probe is the first thing
	`decomp check` and every MSVC acceptance script do, there are up to fourteen of them, and a
	Wine wrapper with no prefix configured never answers at all. `spawn.BANNER_TIMEOUT` is the
	budget for one; the cache is what stops a script that asks about the same tool three times
	from waiting out that budget three times.
	"""
	key = (path, tuple(arguments))
	if key not in _BANNER_CACHE:
		_BANNER_CACHE[key] = spawn.run([path, *arguments], timeout=spawn.BANNER_TIMEOUT)
	result = _BANNER_CACHE[key]
	return ((result.stdout or "") + (result.stderr or "")).strip()


def msvc_tools() -> dict[str, Tool]:
	"""Every MSVC tool that can be named on this PATH, identified by its banner."""
	return {name: Tool(name) for name in MSVC_TOOLS}


# ---------------------------------------------------------------------------------------
# what an installed toolchain can target, per *target* arch (Docs/MSVC-x86-Plan.md X86-0)

# The target bitnesses worth asking about. `arm`/`arm64` appear in a real install and are
# reported when this prefix happens to have them, but nothing in this tool builds for them
# (Docs/MSVC-x86-Plan.md §9), so only these two are probed and only these two can make a
# configured variant unbuildable.
MSVC_TARGET_ARCHES = ("x64", "x86")

# The toolset's own import libraries for a target arch: what `cl /MT` auto-links. They live in
# `VC/Tools/MSVC/<v>/lib/<arch>/`, and for the libraries the desktop CRT payload leaves out in
# `lib/onecore/<arch>/` (install_msvc.fill_missing_libs, Docs/Setup.md §6.10). Their absence is
# a package the installer never asked for - a different answer, and a different fix, from a
# missing compiler.
MSVC_CRT_LIBS = ("libcmt.lib", "libvcruntime.lib", "libcpmt.lib")

# The SDK side of a target arch. `Include/` is arch-independent, so the SDK half of a target
# arch is only ever about these two libraries (the measured package-naming trap is on `msvc_sdk`).
MSVC_SDK_LIBS = (("ucrt", "libucrt.lib"), ("um", "kernel32.lib"))


def _dir_named(parent: Path, name: str) -> Path | None:
	"""`VC` or `vc`, `Windows Kits` or `windows kits`: the payloads and msvc-wine's install.sh

do not agree on case, and the second adds lowercase aliases of the first."""
	if not parent.is_dir():
		return None
	wanted = name.lower()
	try:
		entries = sorted(parent.iterdir())
	except OSError:
		return None
	for entry in entries:
		if entry.name.lower() == wanted and entry.is_dir():
			return entry
	return None


def toolset_dirs(prefix: Path) -> list[Path]:
	"""`<prefix>/VC/Tools/MSVC/<version>` for every toolset under an installed prefix."""
	vc = _dir_named(prefix, "VC")
	if vc is None:
		return []
	found, seen, unique = [], set(), []
	for spelling in ("Tools/MSVC", "tools/msvc"):
		root = vc / spelling
		if not root.is_dir():
			continue
		found += [p for p in sorted(root.iterdir()) if p.is_dir() and re.match(r"^\d+\.\d+", p.name)]
	for path in found:
		key = os.path.realpath(path)
		if key not in seen:
			seen.add(key)
			unique.append(path)
	return unique


def _kits_dir(prefix: Path) -> Path | None:
	"""`<prefix>/Windows Kits/10`, the SDK root, or None."""
	kits = _dir_named(prefix, "Windows Kits")
	return _dir_named(kits, "10") if kits is not None else None


def _looks_like_prefix(path: Path) -> bool:
	return bool(toolset_dirs(path)) or _kits_dir(path) is not None


def _installed_prefixes() -> list[Path]:
	"""Toolchain directories this repo's installer writes (Docs/Setup.md §6.1, §6.5).

	`toolchains/` is gitignored and machine-local, so this is a probe, not an assumption: an
	empty list just means the machine has no MSVC toolchain sitting in the repo.
	"""
	repo = Path(__file__).resolve().parents[1]
	tools = repo / "toolchains"
	if not tools.is_dir():
		return []
	candidates = [tools / "msvc"]
	candidates += sorted(p for p in tools.iterdir() if p.is_dir())
	for msvc in (tools / "msvc",):
		if msvc.is_dir():
			candidates += sorted(p for p in msvc.iterdir() if p.is_dir())
	out, seen = [], set()
	for candidate in candidates:
		key = os.path.realpath(candidate)
		if key in seen or not _looks_like_prefix(candidate):
			continue
		seen.add(key)
		out.append(candidate)
	return out


def msvc_prefix(cl_path: str | None = None) -> tuple[Path | None, str]:
	"""The root of an installed MSVC toolchain (`<prefix>/bin/<arch>/cl`, `<prefix>/VC`,
	`<prefix>/Windows Kits`), or None with the reason there is none.

	Two ways to find one, because they mean different things. An msvc-wine wrapper is
	`<prefix>/bin/<arch>/cl`, so a `cl` on PATH has the prefix as an ancestor. When nothing is
	on PATH, the directory `toolchains/install_msvc.py` installs into is still a fact about this
	machine, and the two gaps it can show are different gaps: an installed toolchain that is not
	on PATH needs one shell line, while a toolset with no 32-bit target needs a download
	(Docs/MSVC-x86-Plan.md X86-0). Reporting only the first case is what made `decomp check`
	say "no `cl` on PATH" about a toolchain that is in fact installed at `toolchains/msvc`.
	"""
	cl = cl_path or shutil.which("cl")
	if cl:
		resolved = Path(cl).resolve()
		root = next((p for p in resolved.parents
			if (p / "Windows Kits").is_dir() or (p / "VC").is_dir()), None)
		if root is not None:
			return root, "found from the cl on PATH (%s)" % resolved
		reason = "the cl on PATH (%s) has no Windows Kits or VC directory above it" % resolved
	else:
		reason = "no cl on PATH"
	for candidate in _installed_prefixes():
		if candidate.is_dir():
			return candidate, "%s is installed but not on PATH" % candidate
	return None, reason + " - no toolchain under toolchains/ either"


def _arch_sdk(prefix: Path, arch: str) -> dict:
	"""The Windows SDK libraries for one target arch, as files on disk."""
	out = {"root": None, "version": None, "present": [], "missing": []}
	kits = _kits_dir(prefix)
	if kits is None:
		out["detail"] = "no Windows Kits/10 under %s" % prefix
		return out
	versions = sorted((kits / "Include").glob("10.*")) if (kits / "Include").is_dir() else []
	versions += sorted((kits / "include").glob("10.*")) if (kits / "include").is_dir() else []
	if not versions:
		out["detail"] = "Windows Kits/10 has no Include/10.* - the SDK payload MSIs were never extracted"
		return out
	version = versions[-1]
	libs = None
	for spelling in ("Lib", "lib"):
		candidate = kits / spelling / version.name
		if candidate.is_dir():
			libs = candidate
			break
	out["version"] = version.name
	if libs is None:
		out["detail"] = "Windows Kits/10/Lib/%s is missing" % version.name
		return out
	for part, name in MSVC_SDK_LIBS:
		path = libs / part / arch / name
		(out["present"] if path.is_file() else out["missing"]).append(str(path))
	out["detail"] = ("all of them are there" if not out["missing"]
		else "missing " + ", ".join(os.path.relpath(p, prefix) for p in out["missing"]))
	return out


def _arch_crt(prefix: Path, arch: str) -> dict:
	"""The toolset's own CRT/STL import libraries for one target arch.

	Both spellings are looked at: `lib/<arch>` is what `cl` searches, and `lib/onecore/<arch>` is
	where the sibling CRT payload puts the libraries the desktop package does not ship -
	`install_msvc.fill_missing_libs` symlinks those into `lib/<arch>`, but a toolchain installed
	some other way has only the OneCore copy (Docs/Setup.md §6.10).
	"""
	out = {"dirs": [], "present": [], "missing": list(MSVC_CRT_LIBS)}
	for toolset in toolset_dirs(prefix):
		for directory in (toolset / "lib" / arch, toolset / "lib" / "onecore" / arch):
			if not directory.is_dir():
				continue
			out["dirs"].append(str(directory))
			lower = {p.name.lower(): p for p in directory.iterdir() if p.is_file()}
			for name in MSVC_CRT_LIBS:
				if name in lower and name in out["missing"]:
					out["present"].append(str(lower[name]))
					out["missing"] = [m for m in out["missing"] if m != name]
	found = ", ".join(os.path.relpath(d, prefix) for d in out["dirs"])
	out["detail"] = ("present in " + found if not out["missing"] else
		"no " + ", ".join(out["missing"]) +
		(" under " + found if found else " - this toolset has no lib/%s directory at all" % arch))
	return out


def msvc_target_arches(prefix: Path | None = None) -> dict[str, dict]:
	"""What an installed MSVC toolchain can produce, per target arch.

	A 32-bit or 64-bit MSVC build needs four things to line up for that target arch, and none
	of them implies the next:

	  * `VC/Tools/MSVC/<v>/bin/Host<h>/<arch>/cl.exe` - the target bitness is the *directory*
	    the compiler lives in, never a flag (`/arch:IA32` disables SSE, it does not emit 32-bit
	    code - Docs/MSVC-x86-Plan.md §8, Setup.md §6.2);
	  * `VC/Tools/MSVC/<v>/lib/<arch>/` - the toolset's own CRT/STL import libraries;
	  * `Windows Kits/10/Lib/<v>/{ucrt,um}/<arch>/` - the SDK's;
	  * `<prefix>/bin/<arch>/cl`, the wrapper that runs it through Wine, and whether that
	    directory is on PATH.

	The halves are independent in practice, and that is the whole point of this function: on
	this machine (v141, measured 2026-11-07) the SDK payload ships `ucrt/x86` and `um/x86`
	libraries, while the toolset has `Hostx64/x64` only and no `lib/x86`. A probe that looks at
	x64 paths alone - which is what `msvc_sdk` did until X86-0 - calls that toolchain complete.
	"""
	if prefix is None:
		prefix, _ = msvc_prefix()
	if prefix is None:
		return {}
	arches = list(MSVC_TARGET_ARCHES)
	for other in _present_arches(prefix):
		if other not in arches:
			arches.append(other)
	out: dict[str, dict] = {}
	for arch in arches:
		entry = {"arch": arch, "prefix": str(prefix), "compilers": [], "crt": _arch_crt(prefix, arch),
			"sdk": _arch_sdk(prefix, arch), "wrapper": None, "on_path": False}
		for toolset in toolset_dirs(prefix):
			binroot = toolset / "bin"
			if not binroot.is_dir():
				continue
			for host in sorted(p for p in binroot.iterdir() if p.is_dir()):
				if not host.name.lower().startswith("host"):
					continue		# `bin/` also holds the native-helper directories
				cl = host / arch / "cl.exe"
				if cl.is_file():
					entry["compilers"].append({"path": str(cl), "host": host.name,
						"toolset": toolset.name})
		for wrapper in (prefix / "bin" / arch / "cl", prefix / "bin" / arch / "cl.exe"):
			if wrapper.is_file():
				entry["wrapper"] = str(wrapper)
				break
		entry["can_build"] = bool(entry["compilers"]) and not entry["crt"]["missing"] \
			and not entry["sdk"]["missing"]
		entry["on_path"] = _on_path(arch)
		entry["summary"], entry["detail"], entry["fix"] = _arch_sentence(prefix, entry, out.get("x64"))
		out[arch] = entry
	return out


def _present_arches(prefix: Path) -> list[str]:
	"""Target arches this prefix can *compile for*, beyond the two asked about.

	Deliberately the toolset's own directories only: a Windows SDK ships import libraries for
	every arch Microsoft sells, so counting those would list arm/arm64 on every machine and say
	nothing.
	"""
	found = set()
	for toolset in toolset_dirs(prefix):
		binroot = toolset / "bin"
		if binroot.is_dir():
			for host in binroot.iterdir():
				if host.name.lower().startswith("host") and host.is_dir():
					found |= {p.name for p in host.iterdir()
						if (p / "cl.exe").is_file()}
		lib = toolset / "lib"
		if lib.is_dir():
			found |= {p.name for p in lib.iterdir() if p.name.lower() != "onecore" and p.is_dir()}
	return sorted(found)


def arch_on_path() -> str | None:
	"""Which target arch the `cl` on PATH would produce, or None when there is no `cl` there.

	Judged by the wrapper directory, because that is what carries the bitness: an msvc-wine
	install is `<prefix>/bin/<arch>/cl`, and the target arch is the directory the real `cl.exe`
	lives in (`Hostx64/x86`), never a flag (Docs/Setup.md §6.2). A driver reached through a
	symlink resolves out of its real directory, which is why this resolves first.
	"""
	cl = shutil.which("cl")
	if cl is None:
		return None
	resolved = Path(cl).resolve()
	if resolved.parent.parent.name.lower() != "bin":
		return None
	return resolved.parent.name.lower()


def _on_path(arch: str) -> bool:
	"""Is a driver for this target arch reachable through PATH?"""
	return arch_on_path() == arch


def _arch_sentence(prefix: Path, entry: dict, x64: dict | None) -> tuple[str, str, str]:
	"""The one line a human needs about one target arch, and the command that would change it.

	Paths inside the prefix are printed relative to it: `decomp check` names the prefix in the
	line above, and the parts that matter here are `bin/Hostx64/x86` versus `bin/Hostx64/x64`
	and `lib/x86` versus `lib/x64`, which a shared absolute prefix only buries.
	"""
	arch = entry["arch"]

	def shown(path):
		return os.path.relpath(path, prefix) if str(path).startswith(str(prefix) + os.sep) else str(path)

	hosts = sorted({c["host"] for c in entry["compilers"]})
	parts = []
	if entry["compilers"]:
		parts.append("cl for %s targets: %s (host %s, toolset %s)" % (arch,
			shown(entry["compilers"][0]["path"]), "/".join(hosts),
			", ".join(sorted({c["toolset"] for c in entry["compilers"]}))))
	elif arch == "x86" and x64 and x64["compilers"]:
		parts.append("x64 only: no 32-bit target from this toolchain - it has %s, not a Host*/x86"
			% "/".join(sorted({os.path.dirname(shown(c["path"])) for c in x64["compilers"]})))
	else:
		parts.append("no cl.exe for %s targets under %s" % (arch, " or ".join(
			str(t / "bin") for t in toolset_dirs(prefix)) or str(prefix)))
	parts.append("toolset CRT libraries for %s: %s" % (arch, entry["crt"]["detail"]))
	parts.append("Windows SDK libraries for %s: %s" % (arch, entry["sdk"]["detail"]))
	if entry["wrapper"]:
		parts.append("wrapper %s%s" % (shown(entry["wrapper"]),
			" (on PATH)" if entry["on_path"] else " (not on PATH)"))
	else:
		parts.append("no wrapper at %s/bin/%s/cl - re-run toolchains/msvc-wine/install.sh for this prefix"
			% (prefix, arch))
	wrapper_dir = os.path.join(str(prefix), "bin", arch)
	if entry["can_build"] and not entry["on_path"] and entry["wrapper"]:
		fix = ("put %s on PATH - the target arch is the wrapper directory, not a flag "
			"(Docs/Setup.md §6.2)" % wrapper_dir)
	elif entry["can_build"] and not entry["on_path"]:
		fix = ("this prefix has the toolset and the libraries for %s but no wrapper: re-run "
			"sh toolchains/msvc-wine/install.sh %s, which generates %s/cl" % (arch, prefix, wrapper_dir))
	elif entry["compilers"]:
		fix = ("the toolset has this target but not everything it needs: fetch the missing "
			"packages named above (the toolset CRT libraries are a Microsoft.VisualC.…CRT.<arch>… "
			"payload, the SDK ones are a Windows SDK payload) and re-run "
			"sh toolchains/msvc-wine/install.sh %s" % prefix)
	elif arch == "x86":
		fix = ("add the 32-bit target of this toolset: re-run the install for it with "
			"`--architecture x86 x64 --host-arch x64` (Docs/Setup.md §6.3), then re-run "
			"sh toolchains/msvc-wine/install.sh %s, which generates %s/cl. A 32-bit target needs no "
			"32-bit Wine - an x64-host cl emits i386 code; only *running* a 32-bit PE does "
			"(Docs/Setup.md §6.7)" % (prefix, wrapper_dir))
	else:
		fix = "install a toolset that targets %s (Docs/Setup.md §6)" % arch
	return ("can build %s candidates" % arch if entry["can_build"]
		else "cannot build %s candidates" % arch), "; ".join(parts), fix


def arch_bitness(value) -> str | None:
	"""Which target *bitness* a variant's `arch` asks for, or None when it asks for something else.

	`arch` in a [variants.*] table is doing two jobs today (Docs/MSVC-x86-Plan.md §4.2): it names
	a bitness (`"x86"`, `"x86-64"`), and for `cl` it can name an ISA level that `build_flags`
	turns into `/arch:AVX2`, which is not a bitness at all. Empty means "whatever the driver
	defaults to", which is the bitness of whichever driver gets chosen - so neither of those has
	an answer here, and neither is contradicted by this check.
	"""
	# The table lives in `toolchain` from X86-2 on: the same spelling rule decides the flags
	# (`-m32`) and the driver, and a check reading a second table could disagree with the build.
	return toolchain.arch_bitness(value)


def gcc_multilib(compiler: str, arch: str) -> tuple[bool, str]:
	"""Can this GCC-family driver really emit this target arch? Asked, not assumed.

	For GCC, `arch = "x86"` is a `-m32` flag, and the flag is only half of it: without the 32-bit
	multilib the driver fails on headers or `crt1.o`. One empty translation unit decides it in
	~0.1 s, which is cheap enough to ask on every `decomp check`.
	"""
	flag = {"x86": "-m32", "x64": "-m64"}.get(arch)
	if flag is None or not shutil.which(compiler):
		return True, "not asked"
	try:
		with tempfile.TemporaryDirectory(prefix="decomp-multilib-") as directory:
			proc = spawn.run([compiler, flag, "-x", "c", "-c", "-o",
				str(Path(directory) / "probe.o"), "-"], stdin="", timeout=120)
	except OSError as exc:
		return False, "%s could not be run (%s)" % (compiler, exc)
	if proc.timed_out:
		return False, "%s did not answer the %s probe in %ds" % (compiler, flag, 120)
	if proc.returncode == 0:
		return True, "%s accepts %s" % (compiler, flag)
	detail = " ".join((proc.stderr or proc.stdout or "").split())[:200]
	return False, "%s does not have a %s multilib: %s" % (compiler, arch, detail)


def variant_arch_gap(variant: dict) -> str:
	"""Why this variant's `arch` cannot be served by the toolchains here, or "" for nothing to say.

	This is the same principle as `build_agreement` (byte-cleanup-plan Phase 7): name the gap
	before any bytes are spent. A 32-bit request that reaches a compiler learns the gap as an
	environment error or, worse, as a 64-bit object refused afterwards; here it is a sentence
	about which half is missing - no such driver, or the wrong one installed (the operator's
	question in Docs/MSVC-x86-Plan.md §1).
	"""
	arch = arch_bitness(variant.get("arch"))
	if arch is None:
		return ""
	if toolchain.msvc(variant.get("compiler", "g++")):
		# From X86-2 on this is the resolver's own answer, because it is the same sentence
		# `compile.build` refuses with: `check` and `try` cannot disagree about whether a variant can
		# be built, and there is one place that knows what "cannot" means here. Two cases that used to
		# be gaps are not:
		#   * "buildable here but not on PATH" - the resolver names that driver by path and says so,
		#     which is what the `chosen` line of a build report prints;
		#   * a variant that names its driver by path - honoured, and a disagreement with `arch` is a
		#     warning about the object that comes back, not a refusal to try.
		driver = toolchain.compiler_for(variant)
		if driver.gap:
			return driver.gap
		return driver.conflict
	ok, detail = gcc_multilib(str(variant.get("compiler", "g++")), arch)
	return "" if ok else ("its arch = \"%s\" asks for that target and the compiler cannot do it: %s"
		% (arch, detail))


def i386_guest() -> dict:
	"""Can a **32-bit PE be run** here? A different question from building one (Docs/Setup.md §6.7).

	Nothing in this tool is required to execute a target, so this row is never fatal. What it gates is
	the behavioural half: the benchmark's goldens and `Tests/eval.py selfcheck` for a 32-bit variant,
	and the same question for a shipped 32-bit target. It is reported here because of the plan's trap
	that a report blurs "this toolchain can build x86" with "this machine can run an x86 program":
	the first is a fact about `bin/x86/cl` (the `msvc target x86` row above), the second about Wine
	or wibo (§6.7).
	"""
	wibo = toolchain.wibo_path()
	wine_i386 = sorted(str(directory) for directory in
		(Path("/usr/lib/wine"), Path("/usr/lib32/wine"), Path("/usr/lib/i386-linux-gnu/wine"),
			Path("/opt/wine/lib/wine")) if (directory / "i386-windows").is_dir())
	interpreter = next((str(path) for path in ("/lib/ld-linux.so.2", "/usr/lib/ld-linux.so.2")
		if Path(path).exists()), None)
	if wibo:
		return {"ok": True, "detail": "wibo at %s starts a 32-bit image (§6.7 Option B); wine64 "
			"still starts the 64-bit ones" % wibo,
			"fix": "a 32-bit *target* needed none of this - only *running* one does"}
	if wine_i386:
		return {"ok": True, "detail": "this Wine carries an i386 guest (%s)" % ", ".join(wine_i386),
			"fix": "a fresh prefix may be needed (WINEARCH=win32): an existing prefix does not gain "
			"32-bit support in place (§6.7 Option A)"}
	how = ("this Wine has no i386 guest build (no i386-windows under its wine library directory)"
		+ ("; the host's 32-bit ELF interpreter is %s" % interpreter if interpreter else
			"; /lib/ld-linux.so.2 is missing, so /usr/bin/wine cannot exec either"))
	return {"ok": False, "detail": "no way to run a 32-bit PE here: %s" % how,
		"fix": ".venv/bin/python toolchains/install_wibo.py (no root, §6.7 Option B), or Wine's "
		"i386 build plus a fresh prefix (§6.7 Option A, needs root). Building 32-bit code never "
		"needed either of them."}


def msvc_arch_report(report: "Report", prefix: Path | None) -> None:
	"""Print the per-target-arch table (Docs/MSVC-x86-Plan.md X86-0).

	Nothing here is a failure on its own: a toolchain that can only do x64 is a fact, not a
	fault, and a variant that asks for x86 is reported against it by `check_all`. Warn rather
	than fail so that `decomp check` stays a report of the machine.
	"""
	if prefix is None:
		return
	targets = msvc_target_arches(prefix)
	for arch in MSVC_TARGET_ARCHES:
		entry = targets.get(arch)
		if entry is None:
			continue
		report.add("msvc target %s" % arch, entry["can_build"], "%s - %s" % (entry["summary"], entry["detail"]),
			entry["fix"], fatal=False)
	extra = [a for a in targets if a not in MSVC_TARGET_ARCHES]
	if extra:
		report.add("msvc other targets", True,
			"this prefix also has %s; nothing in this tool builds for them" % ", ".join(sorted(extra)),
			fatal=False)
	# The row that stops the two facts being read as one: "can build x86" says something about
	# bin/x86/cl, "can run an x86 program" says something about Wine or wibo (§6.7). Printed next to
	# the arch rows so they cannot be quoted separately (Docs/MSVC-x86-Plan.md §8, X86-4).
	guest = i386_guest()
	report.add("run 32-bit PE", guest["ok"], guest["detail"], guest["fix"], fatal=False)


def msvc_report(report: "Report", variant_compilers: list[str], fatal: bool) -> None:
	"""Add the MSVC toolchain items.

	Runs when a variant asks for the MSVC family (`cli.py` maps it to `cl`), and also when
	`cl` is simply installed, so `decomp check` answers "is there a compiler of the target's
	era here?" for a PE target without needing a PE variant configured.
	"""
	tools = msvc_tools()
	asked = any(toolchain.msvc(name) for name in variant_compilers)
	prefix, why = msvc_prefix(tools["cl"].path)
	if not asked and not tools["cl"].found and prefix is None:
		return
	fix = ("install a toolset of the target's era with msvc-wine into toolchains/msvc and put "
		"its bin/<arch> on PATH (Docs/Setup.md §6, Docs/MSVC-Plan.md §5)")
	cl = tools["cl"]
	if not cl.found:
		if prefix is not None:
			# A different gap, and a much cheaper one: the toolchain is here, its wrappers are
			# not on PATH. Say which PATH line fixes it, then still print what it can target.
			# Since X86-2 a variant does not need this on PATH: `toolchain.compiler_for` names the
			# wrapper by path from the variant's arch. This stays a report row because a shell that
			# runs `cl` itself, or a tool outside this project, still needs the PATH line.
			report.add("msvc toolchain", True, "no `cl` on PATH, but %s is installed and usable: a "
				"variant that asks for MSVC is resolved to its driver under that prefix by path"
				% prefix,
				"put a wrapper directory on PATH only for tools outside this one: "
				"PATH=%s/bin/<arch>:$PATH (Docs/Setup.md §6.3); this toolchain's targets are below"
				% prefix, fatal=False)
			msvc_arch_report(report, prefix)
			return
		report.add("msvc toolchain", False, "no `cl` on PATH - a PE target cannot be matched by a candidate",
			fix, fatal=fatal)
		return
	family = (cl.toolset() or {}).get("family", "unknown toolset")
	report.add("msvc cl", cl.vendor == "msvc", cl.describe(), fix, fatal=fatal)
	if cl.vendor != "msvc":
		return
	report.add("msvc toolset", True, "candidate builds would use toolset %s; the target's own "
		"toolset is what `decomp detect` reports" % family)
	for name in ("link", "lib", "dumpbin"):
		tool = tools[name]
		if not tool.found:
			report.add("msvc %s" % name, False, "not found on PATH", fix, fatal=name in ("link",))
			continue
		same = tool.toolset() and cl.toolset() and tool.toolset().get("family") == cl.toolset().get("family")
		detail = tool.describe()
		if not same:
			detail += " - a different era than cl, which is what breaks a candidate build"
		report.add("msvc %s" % name, tool.vendor == "msvc" and bool(same), detail, fix,
			fatal=name in ("link",))
	if cl.wine_wrapper():
		wine = shutil.which("wine64") or shutil.which("wine")
		report.add("wine", bool(wine), "%s (the cl wrapper shells out to it)" % (wine or "no wine/wine64 on PATH"),
			"a 32-bit wine launcher is not enough - the wrappers use wine64 (Docs/Setup.md §1)",
			fatal=fatal)
		# A Windows tool with no Windows prefix is not slow, it is stuck: `wine` falls back to
		# the desktop prefix, which is not one a build tool works in (Docs/Setup.md §6). This is
		# the first thing to name when a `cl` call never comes back.
		env_prefix = os.environ.get("WINEPREFIX", "")
		if env_prefix:
			report.add("wine prefix", (Path(env_prefix).expanduser() / "drive_c").is_dir(),
				"WINEPREFIX=%s from the environment" % env_prefix,
				"that prefix does not look initialised - wineboot it, or point it at one that is "
				"(Docs/Setup.md §6.4)", fatal=False)
			
		else:
			project = spawn.project_wine_prefix()
			report.add("wine prefix", bool(project),
				("WINEPREFIX is not set, so this tool uses its own prefix %s" % project) if project else
				"WINEPREFIX is not set and there is no project prefix here: Wine falls back to "
				"~/.wine, where a compiler call can hang forever", "export WINEPREFIX=$PWD/.wine "
				"(Docs/Setup.md §6), or the tool will use its own prefix when one is initialised there",
				fatal=False)
	undname = tools["undname"]
	if undname.found and undname.vendor == "msvc":
		report.add("msvc undname", True, undname.describe() + " (display only - decorated names stay the key)")
	msvc_arch_report(report, prefix)
	sdk = msvc_sdk(cl.path)
	report.add("windows sdk", bool(sdk.get("complete")),
		"%s%s (%s)" % (sdk.get("root"), "" if not sdk.get("version") else " SDK " + sdk["version"],
				 sdk.get("detail")),
		"the toolset's own headers and libraries compile, but a program needs the Windows SDK's "
		"UCRT and import libraries - extract its payload MSIs (Docs/Setup.md §6.2)",
		fatal=fatal)


def msvc_sdk(cl_path: str | None = None, arch: str = "x64") -> dict:
	"""The Windows SDK that goes with an msvc-wine style toolchain prefix, for one target arch.

	`cl` finds its headers through the wrapper's environment, so the honest question is not
	"is there a directory" but "is there a C runtime and a Win32 import library to link
	against": `<version>/um/windows.h`, `<version>/ucrt/<arch>/libucrt.lib` and
	`<version>/um/<arch>/kernel32.lib`. A toolchain prefix with an empty placeholder (which is
	what a machine that cannot extract the SDK payload MSIs ends up with) answers no.

	`arch` is a parameter because these libraries are per target arch, and hardcoding x64 is the
	reporting bug X86-0 exists to fix: it let `decomp check` call an SDK complete while saying
	nothing about a 32-bit target. Measured here (v141 + SDK 10.0.19041, 2026-11-07): the SDK
	half of the 32-bit gap is *already* satisfied - `ucrt/x86/libucrt.lib` and `um/x86/kernel32.lib`
	are both present - so a missing 32-bit build is the toolset's, not the SDK's.

	Measured on SDK 10.0.19041 as served by the VS2017 channel: `um/windows.h` and
	`kernel32.lib` are NOT in the payload MSIs named "Windows SDK Desktop Headers/Libs x64"
	(their File tables hold 3 and 346 entries, none of them these) - they come from the
	payloads named "Windows SDK for Windows Store Apps Headers/Libs", which install into the
	same Windows Kits trees. `oldnames.lib`, which an earlier version of this probe asked for,
	is a VC toolset library and is not in the SDK at all (Docs/Setup.md §6.11).
	"""
	out = {"arch": arch, "root": None, "version": None,
		"detail": "no cl on PATH and no installed toolchain - cannot locate a toolchain prefix"}
	root, why = msvc_prefix(cl_path)
	if root is None:
		out["detail"] = why
		return out
	out["root"] = str(root)
	probe = _arch_sdk(root, arch)
	out["version"] = probe.get("version")
	if not probe.get("present") and not probe.get("missing"):
		out["complete"] = False
		out["detail"] = probe.get("detail", "the SDK of this prefix cannot be read")
		return out
	include = _kits_dir(root)
	headertests = []
	if include is not None and out["version"]:
		for spelling in ("Include", "include"):
			candidate = include / spelling / out["version"] / "um/windows.h"
			if candidate.is_file():
				headertests.append(candidate)
				break
	no_headers = not headertests
	missing = [Path(p).name for p in probe["missing"]]
	out["complete"] = not missing and not no_headers
	out["detail"] = ("ucrt/um libraries for %s present" % arch if out["complete"] else
		("headers for %s are there but %s are not - this is a placeholder, not a usable SDK"
			% (out["version"], ", ".join(missing)) if missing else
			"the ucrt/um libraries for %s are there but %s/um/windows.h is not" % (arch, out["version"])))
	return out


def _try_mkdir(path: Path) -> bool:
	try:
		path.mkdir(parents=True, exist_ok=True)
		return True
	except OSError:
		return False


def _compiler_problem(compiler: str) -> str:
	"""Empty when the compiler answers and is what its name claims, otherwise the reason it
	is not. An MSVC-family name is checked by banner: `cl` must answer as Microsoft's cl, and
	`clang-cl` is a different codegen (Docs/MSVC-Plan.md §1) even though it builds COFF."""
	path = shutil.which(compiler)
	if path is None:
		return "not found on PATH"
	if toolchain.msvc(compiler):
		tool = Tool(compiler)
		if tool.vendor == "msvc":
			return ""
		if tool.vendor == "clang":
			return ("%s is clang's driver, not MSVC's - it emits COFF but with clang codegen, so it "
				"cannot be used to match an MSVC target" % path)
		return "%s is not Microsoft's %s: %s" % (path, compiler, tool.describe())
	try:
		proc = spawn.run([path, "--version"], timeout=60)
	except OSError as exc:
		return "cannot run: %s" % exc
	if proc.timed_out:
		return "%s did not answer --version in 60s%s" % (path, ": " + proc.note if proc.note else "")
	if proc.returncode != 0:
		return "--version failed (%d)" % proc.returncode
	first = (proc.stdout or proc.stderr).strip().splitlines()
	return "" if first else "--version printed nothing"
