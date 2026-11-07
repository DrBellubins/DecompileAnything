#!/usr/bin/env python3
"""X86-2 through the real command line: what `decomp try` / `decomp link` print.

`check_msvc_x86_toolchain.py` proves the resolver's rules through the API. This drives the commands a
person or an LLM actually runs, because the user-facing half of that phase is what the tool *says*:

  * `try` names the driver it resolved (and where it came from) before it compiles, and `--json`
    records `driver` / `driver_arch` / `driver_from` next to `flags`;
  * a variant whose `arch` no toolchain here can serve exits as a usage error, with the missing
    target named, and no compiler command anywhere in the output;
  * `link` refuses the same variant before linking;
  * a variant that names a driver contradicting its own `arch` reaches the object-level bitness
    refusal — the safety net, now with the driver named as the cause.

Needs the cached benchmark targets (`Tests/build/msvc-o0`, `Tests/build/gcc-o0-x86`) and an installed
MSVC toolchain; the CLI is run as a subprocess so argv and exit codes are the real ones.

	.venv/bin/python Tests/tools/check_driver_resolution_cli.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
PY = str(REPO / ".venv/bin/python")
bad = 0


def run(args, cwd=None):
	proc = subprocess.run([PY, "-m", "decomp.cli"] + args, capture_output=True, text=True,
		cwd=str(cwd or REPO), timeout=300)
	return proc.returncode, proc.stdout + proc.stderr


def expect(ok, what):
	global bad
	print("  %s %s" % ("ok  " if ok else "FAIL", what))
	if not ok:
		bad += 1


# --- A. a real MSVC candidate: the driver it chose is said, and --json says it too
key = json.loads((REPO / "Tests/build/msvc-o0/answer_key.json").read_text())
unit = next(u for u in key["units"] if u["id"].startswith("MATH"))
source = REPO / "Tests/TestBinary" / unit["file"]
base = [hex(unit["address"]), str(source), "--fn", unit["mangled"], "--bin",
	str(REPO / "Tests/build/msvc-o0/da_tests.stripped"), "--config",
	str(REPO / "Tests/project.toml"), "--variant", "msvc-o0"]
x86key = json.loads((REPO / "Tests/build/gcc-o0-x86/answer_key.json").read_text())
x86unit = next(u for u in x86key["units"] if u["id"].startswith("MATH"))
where = hex(x86unit["address"])
code, out = run(["try"] + base)
expect("driver" in out and "toolchains/msvc/bin" in out,
	"`try` names the driver it used: %s" % [l for l in out.splitlines() if "driver" in l][:2])
expect("x86-64" in out or "x64" in out, "…and the bitness that driver targets")
code, out = run(["try"] + base + ["--json"])
body, exc = {}, None
try:
	body = json.loads(out)
except Exception as error:
	body, exc = {}, error
expect(bool(body), "the json parses (%s)" % (exc,))
expect(isinstance(body.get("driver"), str) and "bin/x64/cl" in body["driver"],
		"--json carries the driver: %s" % body.get("driver"))
expect(body.get("driver_arch") == "x64" and bool(body.get("driver_from")),
		"...its bitness, and where it came from: %s / %s" % (body.get("driver_arch"),
		str(body.get("driver_from"))[:80]))

# --- B. a variant with no driver here: refused, and nothing compiled
with tempfile.TemporaryDirectory(prefix="x86cli-") as directory:
	here = Path(directory)
	pinned = here / "no-x86"
	(pinned / "bin" / "x64").mkdir(parents=True)
	(pinned / "bin" / "x64" / "cl").write_text("#!/bin/sh\nexit 1\n")
	(here / "project.toml").write_text(
		'[gate]\nrequire = "none"\n\n[ghidra]\ncache_dir = %r\n\n[msvc]\nprefix = %r\n\n'
		'[variants.msvc-x86]\ncompiler = "cl"\noptimize = 0\narch = "x86"\n'
		% (str(REPO / "cache/ghproj"), str(pinned)))
	source = here / "probe.cpp"
	source.write_text("int da_probe(int a, int b) { return a + b; }\n")
	target = str(REPO / "Tests/build/gcc-o0-x86/da_tests.stripped")
	code, out = run(["try", where, str(source), "--bin", target,
		"--config", str(here / "project.toml"), "--variant", "msvc-x86"])
	lines = [line for line in out.splitlines() if "cannot be built" in line or "driver" in line]
	expect(code == 2, "exit is a usage error, not a build failure: %s" % code)
	expect(any("arch = \"x86\"" in line or "cannot be built" in line for line in lines),
		"the refusal names the target this toolchain lacks: %s" % lines[:2])
	expect(not any("cl " in line and "/Tp" in line for line in out.splitlines()),
		"no compiler command was printed or run: %s" % out.splitlines()[-3:])
	code, out = run(["link", str(source), "--config", str(here / "project.toml"),
		"--variant", "msvc-x86", "--bin", target])
	expect(code == 2 and ("cannot be linked here" in out or "cannot be built" in out),
		"`link` refuses the same variant before linking anything: %s" % out.splitlines()[-3:])

	print("  --- C. a driver that contradicts the variant reaches the object check ---")
	(here / "project.toml").write_text(
		'[gate]\nrequire = "none"\n\n[ghidra]\ncache_dir = %r\n\n[variants.wrong-driver]\n'
		'compiler = %r\noptimize = 0\narch = "x86"\n'
		% (str(REPO / "cache/ghproj"), str(REPO / "toolchains/msvc/bin/x64/cl")))
	code, out = run(["try", where, str(source), "--bin", target,
		"--config", str(here / "project.toml"), "--variant", "wrong-driver"])
	expect("64-bit" in out and "bin/x64/cl" in out and 'arch = "x86"' in out,
		"the safety net names the driver as the cause: %s"
		% [l for l in out.splitlines() if "64-bit" in l][:1])

print("check_driver_resolution_cli: %s" % ("OK" if not bad else "%d group(s) failed" % bad))
sys.exit(1 if bad else 0)
