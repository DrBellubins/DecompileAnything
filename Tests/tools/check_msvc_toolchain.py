"""MS-2 acceptance (Docs/MSVC-Plan.md §7): is there a real MSVC toolchain on this machine?

	run: .venv/bin/python Tests/tools/check_msvc_toolchain.py [--variant msvc-o0]

This is the compiler side of the PE story - `check_pe_target.py` is the target side and needs
no compiler at all. Four groups, each one a question the tool has to answer correctly before
any candidate on a PE target means anything:

1. **Identity.** `cl`, `link`, `lib`, `dumpbin` must answer as Microsoft's tools, and all of
   them as the *same* toolset era - a v141 `cl` with a v143 `link` is not a toolchain. A
   tool found by name is not the tool: `/usr/bin/link` is GNU coreutils' `link`, and the
   check asserts it is refused, not used. A `clang-cl` on PATH must be reported as clang.
2. **One probe compile at each level.** Built through the tool's own `compile.build()` with
   the variant's own flags, so what is tested is the path `decomp try` takes, not a hand
   written `cl` command line. The `.obj` is then read back with `extract.CandidateObject`
   (the COFF half of MS-0) and the two levels must differ in bytes - which proves the
   `/Od` and `/O2` flags reached the driver, and shows MS-3's premise: one `.text$…` COMDAT
   per function, which is where a COFF candidate's exact function extents come from.
3. **One probe link at each level**, and run it. This needs the Windows SDK's UCRT and
   import libraries, so it doubles as the check of the installed prefix (Docs/Setup.md §6).
4. **The benchmark itself**: `Tests/eval.py build` + `selfcheck` for the PE variant, i.e.
   the test binary built by `cl` runs and reports no failures.

Exit: 0 all passed, 1 something came out wrong, 2 there is no MSVC toolchain here to judge
(or it has no Windows SDK, for the groups that need one).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import check, compile as build_, config, extract, toolchain  # noqa: E402

PROBE = """
int probe_abs(int a, int b) { int d = a - b; if (d < 0) d = -d; return d; }
int probe_sum(const int *p, int n) { int s = 0; for (int i = 0; i < n; ++i) s += p[i]; return s; }
"""

MAIN = """
int probe_abs(int, int);
int main() { return probe_abs(3, 9) == 6 ? 0 : 1; }
"""

failures: list[str] = []


def expect(ok: bool, detail: str) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def tools() -> dict[str, check.Tool]:
	found = check.msvc_tools()
	family = (found["cl"].toolset() or {}).get("family")
	expect(found["cl"].found and found["cl"].vendor == "msvc", found["cl"].describe())
	for name in ("link", "lib", "dumpbin"):
		tool = found[name]
		expect(tool.found and tool.vendor == "msvc", tool.describe())
		if tool.found and tool.vendor == "msvc":
			expect((tool.toolset() or {}).get("family") == family,
				"%s is the same toolset as cl (%s)" % (name, family))
	expect(bool(family), "the toolset family of this toolchain: %s" % (family or "unknown"))
	# The impostor the plan names. On this machine /usr/bin/link is GNU coreutils' `link`.
	# The impostor the plan names: /usr/bin/link. Asked about by path, so that a real link.exe
	# being on PATH first does not hide it.
	for impostor in ("/usr/bin/link", "/bin/link"):
		if Path(impostor).is_file():
			pretender = check.Tool("link", impostor)
			expect(pretender.vendor != "msvc", "%s is refused as MSVC: %s" % (impostor, pretender.describe()))
			break
	clang_cl = check.Tool("clang-cl")
	if clang_cl.found:
		expect(clang_cl.vendor != "msvc", "clang-cl is named as what it is: %s" % clang_cl.describe())
	return found


def probe_compile(variant: dict, work: Path) -> dict[int, Path]:
	"""The probe source at every optimisation level this variant names, via the tool's own builder."""
	objects = {}
	for level in ([0, 2] if variant.get("optimize", 0) == 0 else [int(variant["optimize"])]):
		body = dict(variant, optimize=level)
		source = work / "probe.cpp"
		source.write_text(PROBE)
		object_path = work / ("probe_O%d.obj" % level)
		built = build_.build([source], object_path, compiler=body["compiler"],
			flags=toolchain.build_flags(body), includes=[])
		expect(built.ok, "cl %s compiles (%s)" % ("/O2" if level >= 2 else "/Od", " ".join(built.command[-3:])))
		if not built.ok:
			print("      " + "\n      ".join(built.diagnostics.splitlines()[:10]))
			continue
		objects[level] = object_path
		# The COFF half of MS-0: the tool must be able to open what the compiler produced.
		candidate = extract.CandidateObject(object_path)
		expect(candidate.error == "", "extract.CandidateObject opens it (%s, %d-bit, no error)"
			% (candidate.machine, candidate.bits))
		sections = [name for name in candidate._sections if name.startswith(".text")]
		expect(any(name.startswith(".text$") for name in sections),
			"one COMDAT per function (/Gy): %s" % ", ".join(sorted(sections)[:4]))
	if len(objects) == 2:
		left, right = (objects[0].read_bytes(), objects[2].read_bytes())
		expect(left != right, "/Od and /O2 produced different objects (%d vs %d bytes)"
			% (len(left), len(right)))
	return objects


def probe_link(variant: dict, work: Path, objects: dict[int, Path]) -> None:
	sdk = check.msvc_sdk()
	if not sdk.get("complete"):
		print("  skip link: the Windows SDK of this prefix is not usable - %s" % sdk.get("detail"))
		failures.append("the installed MSVC prefix has no usable Windows SDK (%s)" % sdk.get("detail"))
		return
	for level, obj in sorted(objects.items()):
		exe = work / ("probe_O%d.exe" % level)
		command = [variant["compiler"], "/Fe:%s" % exe, "/link", *toolchain.link_flags(variant)] + [str(obj)]
		proc = subprocess.run(command, capture_output=True, text=True, timeout=300)
		expect(proc.returncode == 0, "cl links /O%d -> PE (%s)" % (level, Path(exe).name))
		if proc.returncode:
			print("      " + "\n      ".join((proc.stderr or proc.stdout).splitlines()[:10]))
			continue
		note = toolchain.build_note(exe)
		expect(note.get("format") == "PE" and note.get("arch"), "the linked file is a PE: %s %s"
			% (note.get("format"), note.get("arch")))
		wine = shutil.which("wine64") or shutil.which("wine")
		if not wine:
			print("      no wine to run it with")
			continue
		run = subprocess.run([wine, str(exe)], capture_output=True, text=True, timeout=120)
		expect(run.returncode == 0, "and it runs under Wine (exit %d)" % run.returncode)


def benchmark(variant_name: str) -> None:
	sdk = check.msvc_sdk()
	if not sdk.get("complete"):
		print("  skipped: the benchmark needs the Windows SDK headers and libraries")
		return
	for command in (["build", "--variant", variant_name], ["selfcheck", "--variant", variant_name]):
		proc = subprocess.run([sys.executable, str(TESTS / "eval.py"), *command],
			capture_output=True, text=True, timeout=1800)
		expect(proc.returncode == 0, "eval.py %s" % " ".join(command))
		tail = (proc.stdout or proc.stderr).strip().splitlines()[-4:]
		for line in tail:
			print("      " + line)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("--variant", default="msvc-o0", help="the [variants.*] table to exercise")
	args = parser.parse_args()

	cfg = config.load(str(TESTS / "project.toml"))
	try:
		name, variant = config.variant(cfg, args.variant)
	except config.ConfigError as exc:
		print("no variant to exercise: %s" % exc)
		return 2
	if not toolchain.msvc(variant.get("compiler", "")):
		print("%s is not an MSVC variant (compiler = %s) - Docs/MSVC-Plan.md §1"
			% (name, variant.get("compiler")))
		return 2
	if not check.msvc_tools()["cl"].found:
		print("no `cl` on PATH: install a toolset of the target's era (Docs/Setup.md §6), then\n"
			"  PATH=<prefix>/bin/x64:$PATH again\nNothing was judged - this is not a failure of the tool.")
		return 2

	print("=== 1. identity (Docs/MSVC-Plan.md §1: a tool found by name is not the tool) ===")
	tools()
	with tempfile.TemporaryDirectory(prefix="msvcprobe-") as directory:
		work = Path(directory)
		print("\n=== 2. probe compile, through decomp.compile, at each level ===")
		objects = probe_compile(variant, work)
		print("\n=== 3. probe link and run ===")
		probe_link(variant, work, objects)
	print("\n=== 4. the benchmark built by cl (Tests/eval.py) ===")
	benchmark(name)

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		sdk = check.msvc_sdk()
		if not sdk.get("complete") and all("Windows SDK" in item for item in failures):
			print("\nNothing above this line failed: the toolset works, the Windows SDK of this prefix "
				"does not.\nExtract its payload MSIs (Docs/Setup.md §6.2) and re-run this check.")
			return 2
		return 1
	print("\ncheck_msvc_toolchain: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
