"""Run an external command with a deadline that actually holds.

Every compiler, linker, banner probe and Wine wrapper this tool talks to is a subprocess, and
two things about subprocesses are measured here rather than assumed:

* **`subprocess.run(..., timeout=n)` is not a bound.** When it fires, CPython kills the *direct*
  child and then calls `communicate()` again *with no deadline*. The direct child of an MSVC
  build is a shell wrapper (`toolchains/msvc/bin/x64/cl`), which forks `wine-msvc.sh`, which
  forks `wine64` and leaves `sed` jobs and a `wineserver` behind it. Anything in that tree that
  inherited the capture pipe keeps it open, so the second `communicate()` never sees EOF and the
  call never returns. Measured on this machine: a 100 s probe of `cl /?` produced no output and no
  exit, and the calls left running by the checks of 2026-11-07 never printed a status at all.
* **A tool that never answers is a normal outcome, not an exceptional one.** `cl` through Wine
  with no Windows prefix configured waits in Wine's first-run path forever. The caller has to
  learn that as one line - the deadline used, and why the tool is probably waiting - instead of
  watching a terminal that produces nothing.

So `run()` below:

* puts the child in its own process group and kills that *group* when the deadline fires, which
  is what reaps the wrapper, its `sed`s and the `wine64` under it (a detached `wineserver`
  starts its own session and is deliberately left alone);
* reads both pipes in threads, so a full pipe can never deadlock and the child's exit is noticed
  even when a grandchild still holds the pipe open - that drain is bounded and whatever arrived
  is kept and labelled `partial`;
* therefore never waits more than `timeout + DRAIN_GRACE` for any call, and says so.

It also supplies the one piece of environment a Microsoft toolchain here cannot work without:
see `wine_environment`.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

# How long to keep reading after the child itself is gone (or has been killed). Long enough for
# a well-behaved tool's last few kilobytes to arrive; short enough that a Wine daemon holding the
# pipe open cannot add more than this to a call that is already over.
DRAIN_GRACE = 3.0
# How long a killed process group gets to die before its exit is reported as unknown.
KILL_GRACE = 5.0

# A tool's version banner is a string write, not a build: it answers in well under a second.
# This is generous, and it is not 120 - `check_msvc_toolchain.py` asks up to fourteen tools, so
# a per-banner budget of two minutes is a half hour of waiting before any real work starts.
BANNER_TIMEOUT = 20


@dataclass
class Result:
	"""What a bounded run produced. Never raises; check `returncode`/`timed_out`."""

	command: list[str]
	returncode: int | None          # None = it could not be run, or it never died
	stdout: str
	stderr: str
	seconds: float
	timed_out: bool = False         # the deadline fired and the group was killed
	partial: bool = False           # the pipes never reached EOF; output may be truncated
	note: str = ""                  # e.g. which Wine prefix was used, and why

	@property
	def ok(self) -> bool:
		return self.returncode == 0

	@property
	def output(self) -> str:
		"""Both streams in the order a user reads them. The msvc-wine wrappers put the banner
		on stderr and the diagnostics on stdout, so a caller that shows one must show both."""
		return "\n".join(part for part in (self.stderr, self.stdout) if part).strip()


def run(command, *, timeout: float, cwd: str | Path | None = None,
		stdin: str | None = None, env: dict[str, str] | None = None) -> Result:
	"""Run `command`, and return within `timeout + DRAIN_GRACE`. Never raises.

	`stdin` is written and closed (so a filter like `c++filt` is never left waiting for input);
	with no `stdin` the child gets `/dev/null` for the same reason.
	"""
	command = [str(item) for item in command]
	started = time.time()
	environment, note = wine_environment(command[0], env)
	try:
		process = subprocess.Popen(command,
			cwd=str(cwd) if cwd else None, env=environment,
			stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE,
			start_new_session=True)
	except OSError as exc:
		return Result(command=command, returncode=None, stdout="", stderr=str(exc),
			seconds=round(time.time() - started, 2), timed_out=False,
			note=note or "cannot run %s: %s" % (command[0], exc))
	if stdin is not None:
		try:
			process.stdin.write(stdin.encode())
			process.stdin.close()
		except OSError:  # the child died before reading it - its exit says the rest
			pass

	chunks: list[list] = [[], []]
	workers = []
	for stream, into in zip((process.stdout, process.stderr), chunks):
		worker = threading.Thread(target=_pump, args=(stream, into), daemon=True)
		worker.start()
		workers.append(worker)

	timed_out = False
	returncode: int | None
	try:
		returncode = process.wait(timeout=timeout)
	except subprocess.TimeoutExpired:
		timed_out = True
		_kill_group(process)
		try:
			returncode = process.wait(timeout=KILL_GRACE)
		except subprocess.TimeoutExpired:
			returncode = None

	# The child is gone; anything still reading is a pipe a surviving daemon holds open. Give it
	# the grace, then keep what arrived and say that it may not be all of it.
	for worker in workers:
		worker.join(timeout=DRAIN_GRACE)
	decoded = [b"".join(item).decode("utf-8", "replace") for item in chunks]
	return Result(command=command, returncode=returncode, stdout=decoded[0],
		stderr=decoded[1], seconds=round(time.time() - started, 2), timed_out=timed_out,
		note=note, partial=timed_out or any(worker.is_alive() for worker in workers))


def _pump(stream, into: list) -> None:
	"""Read one pipe to EOF, then close it. A daemon thread, so a pipe some Wine daemon still
	holds open can never keep the interpreter alive on its way out."""
	try:
		while True:
			data = stream.read(65536)
			if not data:
				break
			into.append(data)
	except (OSError, ValueError):
		pass
	finally:
		try:
			stream.close()
		except OSError:
			pass


def _kill_group(process: subprocess.Popen) -> None:
	"""Kill the child *and everything it started*, which is the only way a Wine wrapper's
	`sed` jobs and `wine64` stop running when the deadline fires."""
	try:
		os.killpg(os.getpgid(process.pid), signal.SIGKILL)
	except (OSError, ProcessLookupError):
		try:
			process.kill()
		except OSError:
			pass


# ---------------------------------------------------------------------------------------
# the environment a Microsoft toolchain here needs


def wine_environment(program: str, env: dict[str, str] | None = None) -> tuple[dict | None, str]:
	"""The environment to run `program` with, and what had to be added to it ("" for nothing).

	A Windows tool driven through Wine is only usable with a Windows prefix. Docs/Setup.md §6 says
	to run everything with `WINEPREFIX=$PWD/.wine`, but nothing enforced it: without it, `wine`
	falls back to the desktop prefix in `~/.wine`, which on this machine is a live gaming prefix
	(yabridge hosts, a `winedbg --auto` left over from a crash) - and a `cl /?` there has never
	returned at all, while the same call in the project's own prefix answers in well under a second. So a command
	that goes through Wine - a wrapper script, or `wine`/`wine64` invoked directly, which is how a
	built PE is *run* - gets the project's own prefix when the caller set none, and says that it
	did. An explicit `WINEPREFIX` always wins; nothing is set for commands that do not involve Wine.
	"""
	note = ""
	base = env if env is not None else dict(os.environ)
	if "WINEPREFIX" in base:
		return (env if env is not None else None), ""
	if not goes_through_wine(program):
		return (env if env is not None else None), ""
	prefix = project_wine_prefix()
	if prefix is None:
		return (env if env is not None else None), (
			"WINEPREFIX is not set and there is no project Wine prefix (%s); Wine falls back to "
			"~/.wine, which is usually not a prefix a build tool works in - see Docs/Setup.md §6"
			% (Path(__file__).resolve().parents[1] / ".wine"))
	environment = dict(base)
	environment["WINEPREFIX"] = str(prefix)
	note = ("WINEPREFIX was not set, so the project's own Wine prefix %s was used "
		"(Docs/Setup.md §6); export WINEPREFIX to choose another" % prefix)
	return environment, note


def wine_wrapper(program: str) -> bool:
	"""True when `program` is a script that starts its real work through Wine."""
	path = _resolved(program)
	if not path:
		return False
	try:
		text = Path(path).read_text(errors="replace")[:8000]
	except (OSError, ValueError):
		return False
	return text.startswith("#!") and "wine" in text.lower()


# A wine launcher named on the command line rather than wrapped in a script: how a built PE gets
# run (Tests/eval.py runs the reference binary, and `decomp` runs a candidate program the same way).
_WINE_LAUNCHERS = {"wine", "wine64", "wine-stable", "wine-development", "wine-preloader",
	"winepath", "wineserver", "winetricks"}


def goes_through_wine(program: str) -> bool:
	"""Will running `program` start Wine? Either because it is a Wine launcher, or because it is a
	script that shells out to one."""
	if _name(program) in _WINE_LAUNCHERS:
		return True
	resolved = _resolved(program)
	if resolved and _name(resolved) in _WINE_LAUNCHERS:
		return True
	return wine_wrapper(program)


def _name(program: str) -> str:
	return str(program).replace("\\\\", "/").rsplit("/", 1)[-1].lower()


def _resolved(program: str) -> str:
	return program if os.path.isabs(program) else (shutil.which(program) or "")


def project_wine_prefix() -> Path | None:
	"""The repository's own Wine prefix, if it looks like one."""
	candidate = Path(__file__).resolve().parents[1] / ".wine"
	if (candidate / "drive_c").is_dir() or (candidate / "system.reg").is_file():
		return candidate
	return None
