"""Build a candidate source file into a relocatable object.

The flags come from the target's own `project.toml` variant, the same table `analyze`
recorded, so a candidate is compiled the way the original was built: same compiler, same
`-O`, same `-m32`/`-std`. Comparing across optimisation levels is meaningless here, so the
tool does not offer to do it.

Nothing is hidden from the model: the compiler's own diagnostics are returned verbatim
(capped), and the object path is kept, so `objdump -dr` on it is one command away.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

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
	sources = [Path(source).expanduser() for source in sources]
	object_path = Path(object_path)
	command = [compiler, *flags]
	missing = [str(source) for source in sources if not source.is_file()]
	if missing:
		return Build(ok=False, command=command, object_path=object_path,
			diagnostics="no such source file: %s" % ", ".join(missing))
	for source in sources:
		if source.suffix not in _SOURCE_SUFFIXES:
			command += ["-x", "c++"]
			break
	for include in [*(includes or []), *(source.parent for source in sources)]:
		command += ["-I", str(Path(include))]
	command += ["-c"] + [str(source) for source in sources] + ["-o", str(object_path)]

	object_path.parent.mkdir(parents=True, exist_ok=True)
	started = time.time()
	try:
		process = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
	except FileNotFoundError:
		return Build(ok=False, command=command, object_path=object_path,
			diagnostics="compiler %r not found - set [variants.*] compiler in project.toml" % compiler)
	except subprocess.TimeoutExpired:
		return Build(ok=False, command=command, object_path=object_path,
			diagnostics="the compiler did not finish in %ds" % timeout)
	except OSError as exc:  # pragma: no cover
		return Build(ok=False, command=command, object_path=object_path,
			diagnostics="cannot run %s: %s" % (compiler, exc))
	diagnostics = "\n".join(part for part in (process.stderr, process.stdout) if part).strip()
	lines = diagnostics.splitlines()
	if len(lines) > _MAX_DIAGNOSTICS:
		hidden = len(lines) - _MAX_DIAGNOSTICS
		lines = lines[:_MAX_DIAGNOSTICS] + ["... %d more lines from the compiler" % hidden]
	return Build(ok=process.returncode == 0, command=command, object_path=object_path,
		diagnostics="\n".join(lines), seconds=round(time.time() - started, 2),
		stderr_lines=len(lines))


def describe(build: Build) -> list[str]:
	"""The build result as lines a reader can act on."""
	if build.ok:
		return ["build: ok (%.2fs) -> %s" % (build.seconds, build.object_path)] + (
			["  compiler said:%s" % ("\n" + "\n".join("  " + line for line in
				build.diagnostics.splitlines()[:20]))] if build.diagnostics else [])
	lines = ["build: FAILED (%s)" % build.command[0]]
	if build.diagnostics:
		lines += ["  " + line for line in build.diagnostics.splitlines()[:40]]
	else:
		lines.append("  the compiler produced no output")
	return lines
