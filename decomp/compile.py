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

	@property
	def failed(self) -> bool:
		return not self.ok


def object_name(sources: list[Path], stem: str = "candidate") -> str:
	"""A stable object file name for a set of candidate sources."""
	if len(sources) == 1:
		return "%s_%s.o" % (stem, "".join(c for c in sources[0].stem if c.isalnum() or c == "_")[:40])
	return "%s.o" % stem


def build(sources: list[Path], object_path: Path, *, compiler: str, flags: list[str],
	includes: list[Path] | None = None, timeout: int = 120) -> Build:
	"""Compile one or more candidate sources to one object file. Never raises."""
	from . import toolchain

	sources = [Path(source).expanduser() for source in sources]
	object_path = Path(object_path)
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
	finished = spawn.run(command, timeout=timeout)
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
		stderr_lines=len(lines))


@dataclass
class Link:
	"""A link, in the same shape as a `Build`, because the two failures are the same kind of
	information: the command, whether it worked, and what the linker said."""

	ok: bool
	command: list[str]
	output_path: Path
	diagnostics: str = ""
	seconds: float = 0.0

	@property
	def failed(self) -> bool:
		return not self.ok


def link(objects: list[Path], output_path: Path, *, compiler: str, flags: list[str],
		linkflags: list[str] | None = None, extra: list[str] | None = None,
		timeout: int = 180) -> Link:
	"""Link objects into a program (Docs/byte-cleanup-plan.md, Phase 6). Never raises.

	The objects are the loop's own; `flags` are the variant's build flags, which carry the arch, and
	`linkflags` are the target's own (`config.link_flags`). `extra` is for the one thing only the
	caller knows it needs - `--unresolved-symbols=ignore-all`, say, when a program is only
	partially reproduced - and it is reported, never assumed.
	"""
	from . import toolchain

	objects = [Path(item).expanduser() for item in objects]
	output_path = Path(output_path)
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
		diagnostics="\n".join(lines), seconds=round(time.time() - started, 2))


def describe(result) -> list[str]:
	"""A build or a link result as lines a reader can act on."""
	if isinstance(result, Link):
		if result.ok:
			lines = ["link: ok (%.2fs) -> %s" % (result.seconds, result.output_path)]
			if result.diagnostics:
				lines.append("  linker said:")
				lines += ["    " + line for line in result.diagnostics.splitlines()[:20]]
			return lines
		lines = ["link: FAILED (%s)" % result.command[0]]
		lines += ["  " + line for line in result.diagnostics.splitlines()[:40]] or [
			"  the linker produced no output"]
		return lines
	if result.ok:
		return ["build: ok (%.2fs) -> %s" % (result.seconds, result.object_path)] + (
			["  compiler said:%s" % ("\n" + "\n".join("  " + line for line in
				result.diagnostics.splitlines()[:20]))] if result.diagnostics else [])
	lines = ["build: FAILED (%s)" % result.command[0]]
	if result.diagnostics:
		lines += ["  " + line for line in result.diagnostics.splitlines()[:40]]
	else:
		lines.append("  the compiler produced no output")
	return lines
