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
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import config
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
		msvc_report(report, [body.get("compiler", "g++") for body in names.values()], want_compilers)
	return report


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
	try:
		proc = subprocess.run([path, *arguments], capture_output=True, text=True, timeout=120)
	except (OSError, subprocess.SubprocessError):
		return ""
	return ((proc.stdout or "") + (proc.stderr or "")).strip()


def msvc_tools() -> dict[str, Tool]:
	"""Every MSVC tool that can be named on this PATH, identified by its banner."""
	return {name: Tool(name) for name in MSVC_TOOLS}


def msvc_report(report: "Report", variant_compilers: list[str], fatal: bool) -> None:
	"""Add the MSVC toolchain items.

	Runs when a variant asks for the MSVC family (`cli.py` maps it to `cl`), and also when
	`cl` is simply installed, so `decomp check` answers "is there a compiler of the target's
	era here?" for a PE target without needing a PE variant configured.
	"""
	tools = msvc_tools()
	asked = any(toolchain.msvc(name) for name in variant_compilers)
	if not asked and not tools["cl"].found:
		return
	fix = ("install a toolset of the target's era with msvc-wine into toolchains/msvc and put "
		"its bin/<arch> on PATH (Docs/Setup.md §6, Docs/MSVC-Plan.md §5)")
	cl = tools["cl"]
	if not cl.found:
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
	undname = tools["undname"]
	if undname.found and undname.vendor == "msvc":
		report.add("msvc undname", True, undname.describe() + " (display only - decorated names stay the key)")
	sdk = msvc_sdk()
	report.add("windows sdk", bool(sdk.get("complete")),
		"%s%s (%s)" % (sdk.get("root"), "" if not sdk.get("version") else " SDK " + sdk["version"],
				 sdk.get("detail")),
		"the toolset's own headers and libraries compile, but a program needs the Windows SDK's "
		"UCRT and import libraries - extract its payload MSIs (Docs/Setup.md §6.2)",
		fatal=fatal)


def msvc_sdk(cl_path: str | None = None) -> dict:
	"""The Windows SDK that goes with an msvc-wine style toolchain prefix.

	`cl` finds its headers through the wrapper's environment, so the honest question is not
	"is there a directory" but "is there a UCRT to link against": `libucrt.lib` for this
	target arch, plus the CRT/Win32 import libraries. A toolchain prefix with an empty
	placeholder (which is what a machine that cannot extract the SDK payload MSIs ends up
	with) answers no.
	"""
	path = cl_path or shutil.which("cl")
	out = {"root": None, "version": None, "detail": "no cl on PATH - cannot locate a toolchain prefix"}
	if not path:
		return out
	resolved = Path(path).resolve()
	# An msvc-wine wrapper is <prefix>/bin/<arch>/cl, so the prefix is an ancestor.
	root = next((p for p in resolved.parents
		if (p / "Windows Kits").is_dir() or (p / "VC").is_dir()), None)
	if root is None:
		out["detail"] = "no Windows Kits directory above %s" % resolved
		return out
	out["root"] = str(root)
	kits = root / "Windows Kits" / "10"
	versions = sorted(p.name for p in kits.glob("Lib") if p.is_dir()) if kits.is_dir() else []
	include_versions = sorted(p.name for p in (kits / "Include").glob("10.*")) if (kits / "Include").is_dir() else []
	if not include_versions:
		out["detail"] = "Windows Kits/10 has no Include/10.* - the SDK payload MSIs were never extracted"
		out["complete"] = False
		return out
	version = include_versions[-1]
	libs = kits / "Lib" / version
	wanted = [str(libs / "ucrt/x64/libucrt.lib"), str(libs / "um/x64/kernel32.lib"),
		str(libs / "um/x64/oldnames.lib")]
	missing = [w for w in wanted if not Path(w).is_file()]
	out["version"] = version
	out["complete"] = not missing
	out["detail"] = ("ucrt/um libraries present" if not missing
		else "headers for %s are there but %s are not - this is a placeholder, not a usable SDK"
		% (version, ", ".join(Path(m).name for m in missing)))
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
		proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60)
	except OSError as exc:
		return "cannot run: %s" % exc
	if proc.returncode != 0:
		return "--version failed (%d)" % proc.returncode
	first = (proc.stdout or proc.stderr).strip().splitlines()
	return "" if first else "--version printed nothing"
