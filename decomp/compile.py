"""Build a candidate source file into a relocatable object.

The flags come from the target's own `project.toml` variant, the same table `analyze`
recorded, so a candidate is compiled the way the original was built: same compiler, same
`-O`, same `-m32`/`-std`. Comparing across optimisation levels is meaningless here, so the
tool does not offer to do it.

Nothing is hidden from the model: the compiler's own diagnostics are returned verbatim
(capped), and the object path is kept, so `objdump -dr` on it is one command away.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from . import spawn

# Suffixes the compiler picks the language from itself. Anything else is compiled as C++
# (a candidate written to notes.txt or candidate.iii should still build).
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".C", ".m", ".mm"}
_MAX_DIAGNOSTICS = 600


@dataclass
class Build:
	ok: bool
	command: list[str]
	object_path: Path
	diagnostics: str = ""
	seconds: float = 0.0
	stderr_lines: int = 0
	warnings: list[str] = field(default_factory=list)
	# Which driver ran and what bitness it emits - the answer of `toolchain.compiler_for`, kept so the
	# reader can see it (Docs/MSVC-x86-Plan.md X86-2). `refused` is the case where that resolver knew
	# there is no driver for the variant's `arch`: no compiler was run, and `diagnostics` is why.
	driver: str = ""
	arch: str = ""
	why: str = ""
	refused: bool = False
	# Set when the driver was aborted by the loader that runs it and the compile was retried once
	# (see `loader_aborted`). Anyone reading a build that succeeded is entitled to know it ran twice.
	retried: str = ""

	@property
	def failed(self) -> bool:
		return not self.ok


def object_name(sources: list[Path], stem: str = "candidate") -> str:
	"""A stable object file name for a set of candidate sources."""
	if len(sources) == 1:
		return "%s_%s.o" % (stem, "".join(c for c in sources[0].stem if c.isalnum() or c == "_")[:40])
	return "%s.o" % stem


def resolve(variant: dict | None, cfg: dict | None):
	"""The driver this variant runs, chosen by the one resolver (`toolchain.compiler_for`).

	`cfg` is consulted only for an `[msvc] prefix` the project pins; with no such pin the resolver
	falls back to whatever is on PATH and then to the toolchain `decomp check` reports finding. Used
	by `build`/`link`, and by anything that wants to print the choice before a compiler runs.
	"""
	from . import config, toolchain

	prefix, prefix_from = (None, "")
	if cfg:
		prefix, prefix_from = config.msvc_prefix(cfg)
	return toolchain.compiler_for(variant or {}, prefix=prefix, prefix_from=prefix_from)


_LOADER_ABORT = ("reached missing import", "cannot load", "image is not valid", "unimplemented")


def loader_aborted(returncode, stderr: str = "", stdout: str = "") -> bool:
	"""Did the *loader* give up on the compiler, rather than the compiler reject the source?

	On this box an MSVC driver is a Windows PE run through a loader (there is no i386 Wine guest,
	Docs/x86-32bit-issues.md §4), and that loader sometimes reaches an import it never bound and
	aborts: the only output is its own line (e.g. `wibo: call reached missing import lstrcatW from
	kernel32`), the process dies by signal or with a shell-level status >= 128, and no object is
	produced (§38). It is intermittent, and it says nothing about the candidate source - a tool that
	reported it as "the candidate did not compile" would be stating a false fact about the program.
	A real compile error exits 1 or 2 with the compiler's own diagnostics, which is the common case
	this must not mistake for an abort.
	"""
	if returncode is not None and 0 <= returncode < 128:
		return False                     # the driver judged the source and said why
	text = "%s\n%s" % (stderr or "", stdout or "")
	if any(marker in text for marker in _LOADER_ABORT):
		return True
	# died without a compiler's verdict: killed by a signal (a negative status, or no status at
	# all), or exited through a shell trap (>= 128). Neither is a statement about the source.
	return returncode is None or returncode < 0 or returncode >= 128


def build(sources: list[Path], object_path: Path, *, compiler: str | None = None,
		flags: list[str], includes: list[Path] | None = None, timeout: int = 120,
		variant: dict | None = None, cfg: dict | None = None) -> Build:
	"""Compile one or more candidate sources to one object file. Never raises.

	Give it a `compiler`, or give it the `variant` (plus the `cfg` that may hold an `[msvc] prefix`)
	and `toolchain.compiler_for` picks the driver. The second is the only way a variant's `arch`
	reaches a compiler that emits that bitness, and the only way a variant that cannot be built here
	is named *before* any compiler runs, instead of as a missing executable or a refused 64-bit
	object (Docs/MSVC-x86-Plan.md X86-2). `Build.driver`/`.arch`/`.why` carry what was chosen.
	"""
	from . import toolchain

	sources = [Path(source).expanduser() for source in sources]
	object_path = Path(object_path)
	driver = resolve(variant, cfg) if compiler is None else None
	if compiler is None:
		if driver.refused:
			return Build(ok=False, command=[], object_path=object_path, refused=True,
				diagnostics=driver.gap, arch=driver.arch, why=driver.why)
		compiler = driver.name
	if not compiler:
		return Build(ok=False, command=[], object_path=object_path, refused=True,
			diagnostics="no compiler is named for this variant and none could be resolved here")
	missing = [str(source) for source in sources if not source.is_file()]
	if missing:
		return Build(ok=False, command=[compiler, *flags], object_path=object_path,
			diagnostics="no such source file: %s" % ", ".join(missing))
	command = toolchain.driver_form(compiler, flags, sources, object_path, includes)
	for source in sources:
		if source.suffix not in _SOURCE_SUFFIXES and not toolchain.msvc(compiler):
			command[-3:-3] = ["-x", "c++"]  # before -c: tell the driver it is C++
			break

	object_path.parent.mkdir(parents=True, exist_ok=True)
	started = time.time()
	retried = ""
	for attempt in (0, 1):
		finished = spawn.run(command, timeout=timeout)
		if (attempt == 0 and not finished.timed_out
				and loader_aborted(finished.returncode, finished.stderr, finished.stdout)):
			retried = ("the driver was aborted before it reported anything (its loader, not the "
				"source); ran it once more")
			continue
		break
	if finished.returncode is None and not finished.timed_out:
		return Build(ok=False, command=command, object_path=object_path,
			diagnostics=("compiler %r not found - set [variants.*] compiler in project.toml" % compiler
				if "No such file" in (finished.stderr or "") else
				"cannot run %s: %s" % (compiler, finished.stderr or finished.note)))
	if finished.timed_out:
		return Build(ok=False, command=command, object_path=object_path,
			diagnostics="the compiler did not finish in %ds (%s)%s" % (timeout,
				" ".join(command[:2]),
				" - " + finished.note if finished.note else ""))
	process = finished
	diagnostics = "\n".join(part for part in (process.stderr, process.stdout) if part).strip()
	lines = diagnostics.splitlines()
	if len(lines) > _MAX_DIAGNOSTICS:
		hidden = len(lines) - _MAX_DIAGNOSTICS
		lines = lines[:_MAX_DIAGNOSTICS] + ["... %d more lines from the compiler" % hidden]
	return Build(ok=process.returncode == 0, command=command, object_path=object_path,
		diagnostics="\n".join(lines), seconds=round(time.time() - started, 2),
		stderr_lines=len(lines), driver=compiler, retried=retried,
		warnings=([retried] if retried else []),
		arch=(driver.arch if driver is not None else toolchain.driver_bitness(compiler)[0]),
		why=driver.why if driver is not None else "named by the caller")


@dataclass
class Link:
	"""A link, in the same shape as a `Build`, because the two failures are the same kind of
	information: the command, whether it worked, and what the linker said."""

	ok: bool
	command: list[str]
	output_path: Path
	diagnostics: str = ""
	seconds: float = 0.0
	# As on a `Build`: the driver that ran, what it targets, and why it was picked.
	driver: str = ""
	arch: str = ""
	why: str = ""
	refused: bool = False

	@property
	def failed(self) -> bool:
		return not self.ok


def link(objects: list[Path], output_path: Path, *, compiler: str | None = None,
		flags: list[str], linkflags: list[str] | None = None, extra: list[str] | None = None,
		timeout: int = 180, variant: dict | None = None, cfg: dict | None = None) -> Link:
	"""Link objects into a program (Docs/byte-cleanup-plan.md, Phase 6). Never raises.

	The objects are the loop's own; `flags` are the variant's build flags, which carry the arch, and
	`linkflags` are the target's own (`config.link_flags`). `extra` is for the one thing only the
	caller knows it needs - `--unresolved-symbols=ignore-all`, say, when a program is only
	partially reproduced - and it is reported, never assumed.
	"""
	from . import toolchain

	objects = [Path(item).expanduser() for item in objects]
	output_path = Path(output_path)
	driver = resolve(variant, cfg) if compiler is None else None
	if compiler is None:
		if driver.refused:
			return Link(ok=False, command=[], output_path=output_path, refused=True,
				diagnostics=driver.gap, arch=driver.arch, why=driver.why)
		compiler = driver.name
	if not compiler:
		return Link(ok=False, command=[], output_path=output_path, refused=True,
			diagnostics="no linker driver is named for this variant and none could be resolved here")
	missing = [str(item) for item in objects if not item.is_file()]
	if missing:
		return Link(ok=False, command=[compiler], output_path=output_path,
			diagnostics="no such object file: %s" % ", ".join(missing))
	command = toolchain.link_form(compiler, flags, objects, [*(linkflags or []), *(extra or [])],
		output_path)
	output_path.parent.mkdir(parents=True, exist_ok=True)
	started = time.time()
	process = spawn.run(command, timeout=timeout)
	if process.returncode is None and not process.timed_out:
		return Link(ok=False, command=command, output_path=output_path,
			diagnostics=("linker driver %r not found - set [variants.*] compiler in project.toml"
				% command[0] if "No such file" in (process.stderr or "") else
				"cannot run %s: %s" % (command[0], process.stderr or process.note)))
	if process.timed_out:
		return Link(ok=False, command=command, output_path=output_path,
			diagnostics="the linker did not finish in %ds (%s)%s" % (timeout,
				" ".join(command[:2]), " - " + process.note if process.note else ""))
	diagnostics = "\n".join(part for part in (process.stderr, process.stdout) if part).strip()
	lines = diagnostics.splitlines()
	if len(lines) > _MAX_DIAGNOSTICS:
		lines = lines[:_MAX_DIAGNOSTICS] + [
			"... %d more lines from the linker" % (len(lines) - _MAX_DIAGNOSTICS)]
	return Link(ok=process.returncode == 0, command=command, output_path=output_path,
		diagnostics="\n".join(lines), seconds=round(time.time() - started, 2),
		driver=compiler, arch=driver.arch if driver is not None else "",
		why=driver.why if driver is not None else "named by the caller")


def _driver_lines(result) -> list[str]:
	"""Which compiler or linker driver ran, what it targets, and why it was picked.

	First, because on this machine the same variant can be built by two different drivers and the
	difference is the answer (Docs/MSVC-x86-Plan.md X86-2).
	"""
	if getattr(result, "refused", False):
		return ["driver    none: %s" % result.diagnostics]
	driver = getattr(result, "driver", "")
	if not driver:
		return []
	return ["driver    %s - %s%s" % (driver, "targets %s, " % result.arch if result.arch else "",
		getattr(result, "why", "") or "named by the caller")]


def describe(result) -> list[str]:
	"""A build or a link result as lines a reader can act on. Which driver ran comes first."""
	if getattr(result, "refused", False):
		return _driver_lines(result)
	head = _driver_lines(result)
	if isinstance(result, Link):
		if result.ok:
			lines = ["link: ok (%.2fs) -> %s" % (result.seconds, result.output_path)]
			if result.diagnostics:
				lines.append("  linker said:")
				lines += ["    " + line for line in result.diagnostics.splitlines()[:20]]
			return head + lines
		lines = ["link: FAILED (%s)" % result.command[0]]
		lines += ["  " + line for line in result.diagnostics.splitlines()[:40]] or [
			"  the linker produced no output"]
		return head + lines
	if result.ok:
		return head + ["build: ok (%.2fs) -> %s" % (result.seconds, result.object_path)] + (
			["  note: %s" % result.retried] if getattr(result, "retried", "") else []) + (
			["  compiler said:%s" % ("\n" + "\n".join("  " + line for line in
				result.diagnostics.splitlines()[:20]))] if result.diagnostics else [])
	lines = ["build: FAILED (%s)" % result.command[0]]
	if getattr(result, "retried", ""):
		lines.append("  note: %s" % result.retried)
	if result.diagnostics:
		lines += ["  " + line for line in result.diagnostics.splitlines()[:40]]
	else:
		lines.append("  the compiler produced no output")
	return head + lines
