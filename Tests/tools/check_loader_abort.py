"""§38 acceptance: a driver killed by its loader is retried once; a compile error is not.

	run: .venv/bin/python Tests/tools/check_loader_abort.py

`Docs/x86-32bit-issues.md` §38 records an MSVC driver dying as

	wibo: call reached missing import lstrcatW from kernel32
	Aborted (core dumped)

with no object and no word about the source. That is the PE loader running the compiler, not the
compiler judging the candidate, and it is intermittent. Left alone it becomes a false claim in the
loop ("your candidate does not compile"), so `compile.build` classifies it and retries once.

This check does not need that loader, and does not depend on it misbehaving on demand: it drives
`build()` with a stub driver whose behaviour is decided here, and counts how many times the stub
ran. Two things have to hold at once, and they are the two halves of the claim:

* an aborted driver is run twice, and the second attempt is what the result reports (with the note
  that it was a retry, in the result and in `describe`'s lines);
* a driver that answers with a compile error is run **once** - the retry must not become a habit
  that hides a real error, doubles the wall time of every failed candidate, or re-runs a compiler
  that is writing into the same object file.

Exit: 0 all passed, 1 something came out wrong, 2 the stub driver could not be run here.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import compile as build_  # noqa: E402

LOADER_LINE = "wibo: call reached missing import lstrcatW from kernel32"
COMPILE_ERROR = "probe.cpp(7) : error C2143: syntax error : missing '{' before '__stdcall'"

_COUNTER = 0


def expect(ok: bool, detail: str, failures: list[str]) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def stub_driver(work: Path, mode: str) -> tuple[Path, Path]:
	"""A driver that behaves as §38 describes, and counts its own invocations."""
	global _COUNTER
	_COUNTER += 1
	counter = work / ("count-%d" % _COUNTER)
	# The scratch directory outlives the run, and the count is what the check asserts: a second run
	# on a leftover counter would read the first run's total and report that the driver ran twice as
	# often as it did.
	counter.unlink(missing_ok=True)
	script = work / ("driver-%d.sh" % _COUNTER)
	body = """#!/bin/sh
n=$(cat "%s" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "%s"
%s
""" % (counter, counter, {
		"abort-then-ok": ('if [ "$n" = 1 ]; then\n  echo "%s" >&2\n  exit 134\nfi\nexit 0'
			% LOADER_LINE),
		"always-aborts": ('echo "%s" >&2\nexit 134' % LOADER_LINE),
		"compile-error": ('echo "%s" >&2\nexit 1' % COMPILE_ERROR),
		"killed-silent": ('if [ "$n" = 1 ]; then\n  kill -9 $$\nfi\nexit 0'),
	}[mode])
	script.write_text(body)
	script.chmod(0o755)
	return script, counter


def main() -> int:
	failures: list[str] = []
	print("\n=== 1. what counts as a loader abort ===")
	# the signature of §38, and the things it must not catch: a compiler's own diagnostics, and a
	# clean build. The false-positive half matters more than the true-positive one - retrying a real
	# compile error twice would hide it and double the time of every failed candidate.
	expect(build_.loader_aborted(134, LOADER_LINE), "the loader's own line is an abort", failures)
	expect(build_.loader_aborted(134, ""), "killed by a signal with nothing to say is an abort",
		failures)
	expect(build_.loader_aborted(None, ""), "a run that never reported a status is an abort",
		failures)
	expect(not build_.loader_aborted(1, COMPILE_ERROR), "a compile error is not an abort", failures)
	expect(not build_.loader_aborted(2, "gcc: fatal error: no input files"),
		"a driver's own fatal error is not an abort", failures)
	expect(not build_.loader_aborted(0, ""), "a clean build is not an abort", failures)
	expect(not build_.loader_aborted(0, LOADER_LINE),
		"a driver that succeeded did not abort whatever it printed", failures)

	print("\n=== 2. build() retries the abort, once, and says so ===")
	work = TESTS / "build" / "loader-abort"
	work.mkdir(parents=True, exist_ok=True)
	source = work / "probe.cpp"
	source.write_text("int probe() { return 1; }\n")
	for mode, want_ok, want_count in (("abort-then-ok", True, 2), ("always-aborts", False, 2),
			("compile-error", False, 1), ("killed-silent", True, 2)):
		driver, counter = stub_driver(work, mode)
		object_path = work / ("probe-%s.o" % mode)
		if object_path.exists():
			object_path.unlink()
		result = build_.build([source], object_path, compiler=str(driver), flags=["-c"],
			timeout=30)
		ran = int(counter.read_text().strip()) if counter.is_file() else 0
		expect(ran == want_count, "%s: the driver ran %d time(s) as expected (ran %d)"
			% (mode, want_count, ran), failures)
		expect(result.ok is want_ok, "%s: reported ok=%s as expected (ok=%s: %s)"
			% (mode, want_ok, result.ok, (result.diagnostics or "").splitlines()[:1]), failures)
		retried = bool(getattr(result, "retried", ""))
		expect(retried == (want_count == 2), "%s: the result %s the retry"
			% (mode, "names" if want_count == 2 else "does not invent"), failures)
		lines = "\n".join(build_.describe(result))
		expect(("note:" in lines) == (want_count == 2), "%s: what a reader is shown %s the retry"
			% (mode, "names" if want_count == 2 else "does not invent"), failures)
		if mode == "always-aborts":
			expect(LOADER_LINE in result.diagnostics,
				"always-aborts: the loader's line is what the failure reports, not a silent no",
				failures)
		if mode == "compile-error":
			expect(COMPILE_ERROR in result.diagnostics,
				"compile-error: the compiler's own words reach the reader unchanged", failures)

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_loader_abort: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
