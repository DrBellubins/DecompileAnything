"""X86-1 acceptance (Docs/MSVC-x86-Plan.md §6 X86-1): is there a 32-bit *target* compiler here,
and does the tool read what it emits?

	run: .venv/bin/python Tests/tools/check_msvc_x86_install.py

This is the machine side of the 32-bit MSVC track: `check_msvc_x86_toolchain.py` is the report
side (X86-0) and `check_msvc_toolchain.py` is the x64 compiler side (MS-2). X86-1 claims one
thing only - a `cl` that can be asked exists - so this script asks it the §6.8 probe of
Docs/Setup.md, at x86, and reads the answer back. It deliberately does **not** go through
`decomp compile`/`try`: resolving `arch = "x86"` to this driver is X86-2, and claiming that
here would be claiming X86-2's work. Nothing is asserted about what i386 `cl` emits beyond the
bitness of its own object file.

Groups:

1. **Both target halves are in the tree.** Per arch: the `Host*/<arch>/cl.exe`, the toolset's
   `lib/<arch>` CRT import libraries, and the `<prefix>/bin/<arch>/cl` wrapper.
2. **Ask the compiler, not the directory** (§6.8). `bin/x86/cl` and `bin/x64/cl` must answer
   with the *same* `cl` version, which must match the toolset directory. One toolset, two
   targets: that is the whole point, and a `Hostx64/x86` tree whose banner said 14.16 would be
   a different toolchain than the one `detect` pins.
3. **§6.8 step 2 at x86.** `#include <vector>` compiles (the STL + SDK include path), and a
   `/MT` console program **links**. No bitness flag is passed: the flags are the tool's own MSVC
   set for a variant that names no `arch`, so the only thing that decides the target is which
   `cl.exe` ran.
4. **The object is read back as 32-bit.** `extract.CandidateObject` on the `.obj` must report
   `machine` I386 / `bits` 32 with no error, while the same source through `bin/x64/cl` reads
   64. The linked `.exe` is reported as a 32-bit PE and **not run** - a 32-bit *guest* is a
   different question than a 32-bit *target* (Docs/Setup.md §6.7), and this machine cannot do it.

Exit: 0 all passed, 1 something came out wrong, 2 no MSVC toolchain, or no x86 target in it.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import check, extract, toolchain  # noqa: E402

# Docs/Setup.md §6.8's probe: <vector> is what catches a headers-without-compiler setup.
PROBE = """
#include <vector>
#include <cstdio>
int probe_abs(int a, int b) { int d = a - b; if (d < 0) d = -d; return d; }
int main() {
	std::vector<int> v;
	v.push_back(probe_abs(3, 9));
	printf("_MSC_VER=%d\\n", _MSC_VER);
	return (int) v[0] != 6;
}
"""

failures: list[str] = []


def expect(ok: bool, detail: str) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
	return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=180)


def banner(wrapper: Path) -> tuple:
	"""What the compiler itself says it is: (version, target word). §6.8: never record a
	toolchain's identity from its directory name - and note that `cl`'s own banner names the
	target it was invoked as, which is the fact `arch = "x86"` has to end up selecting."""
	with tempfile.TemporaryDirectory() as tmp:
		work = Path(tmp)
		(work / "v.cpp").write_text("int v_marker;\n")
		out = run([str(wrapper), "/c", "v.cpp"], cwd=work)   # no /nologo: that is what hides the banner
	text = (out.stdout or "") + (out.stderr or "")
	version = re.search(r"Version (\d+\.\d+)", text)
	target = re.search(r"\bfor (x64|x86)\b", text)
	return (version.group(1) if version else "", target.group(1) if target else "")


def tree_cl(prefix: Path, arch: str) -> list[str]:
	return sorted(glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "bin" / "Host*"
		/ arch / "cl.exe")))


def both_targets(prefix: Path) -> "dict[str, dict]":
	targets = check.msvc_target_arches(prefix)
	for arch in check.MSVC_TARGET_ARCHES:
		entry = targets.get(arch) or {}
		cl = tree_cl(prefix, arch)
		expect(bool(entry.get("compilers")) == bool(cl),
			"%s: the tool finds %s, the tree has %s" % (arch,
				", ".join(c["path"] for c in entry.get("compilers", [])) or "no cl.exe",
				", ".join(cl) or "no cl.exe"))
		expect(bool(entry.get("wrapper")), "%s: %s exists" % (arch, entry.get("wrapper") or "no wrapper"))
		expect(entry.get("can_build"), "%s: cl + toolset CRT + SDK all present" % arch)
	return targets


def read_back(obj: Path, want_bits: int, arch: str) -> None:
	candidate = extract.CandidateObject(obj)
	expect(not candidate.error, "%s: the .obj is read without error (%s)"
		% (arch, candidate.error or "clean"))
	expect(candidate.bits == want_bits,
		"%s: extract.CandidateObject reports bits=%d, wanted %d" % (arch, candidate.bits, want_bits))
	name = str(candidate.machine)
	expect(("I386" if want_bits == 32 else "AMD64") in name or ("386" if want_bits == 32 else "64") in name,
		"%s: the machine is named as %s" % (arch, name or "unknown"))


def compile_link(wrapper: Path, arch: str, work: Path, flags: "list[str]") -> "Path | None":
	source = work / ("probe_%s.cpp" % arch)
	source.write_text(PROBE)
	obj = work / ("probe_%s.obj" % arch)
	exe = work / ("probe_%s.exe" % arch)
	# /Z7 (C7 codeview), never /Zi: /Zi starts mspdbsrv.exe (Docs/Setup.md §6.1).
	step = run([str(wrapper), *flags, "/Z7", "/c", "/Fo:%s" % obj.name, source.name], cwd=work)
	ok = step.returncode == 0 and obj.is_file()
	expect(ok, "%s: `#include <vector>` compiles with the tool's own MSVC flags" % arch)
	if not ok:
		print("      " + ((step.stdout or "") + (step.stderr or "")).strip().replace("\n", "\n      ")[:600])
		return None
	out = run([str(wrapper), *flags, "/Z7", obj.name, "/Fe:%s" % exe.name], cwd=work)
	expect(out.returncode == 0 and exe.is_file(),
		"%s: a /MT console program links (%s)" % (arch, exe.name if exe.is_file() else "no image"))
	if out.returncode != 0:
		print("      " + ((out.stdout or "") + (out.stderr or "")).strip().replace("\n", "\n      ")[:600])
	read_back(obj, 32 if arch == "x86" else 64, arch)
	if exe.is_file():
		image = extract.CandidateObject(exe)
		expect(image.bits == (32 if arch == "x86" else 64),
			"%s: the linked image is a %d-bit PE (not run - a 32-bit guest is Setup.md §6.7)"
			% (arch, image.bits))
	return obj


def main() -> int:
	if not os.environ.get("WINEPREFIX") and (REPO / ".wine").is_dir():
		os.environ["WINEPREFIX"] = str(REPO / ".wine")
	prefix, why = check.msvc_prefix()
	if prefix is None:
		print("no MSVC toolchain installed here (%s) - nothing to judge" % why)
		return 2
	print("toolchain prefix: %s (%s)" % (prefix, why))
	targets = both_targets(prefix)
	if not targets.get("x86", {}).get("can_build"):
		print("\nthis toolchain has no x86 target half - X86-1 has not run here:")
		print("  %s" % targets.get("x86", {}).get("detail", ""))
		print("  fix: .venv/bin/python toolchains/install_msvc.py --architecture x86 x64")
		return 2

	print("\n=== 2. ask both compilers who they are (Setup.md §6.8) ===")
	banners = {}
	for arch in check.MSVC_TARGET_ARCHES:
		wrapper = Path(targets[arch]["wrapper"])
		banners[arch] = banner(wrapper)
		expect(bool(banners[arch][0]), "%s: %s prints a compiler version: %s"
			% (arch, wrapper, banners[arch][0] or "nothing matched"))
		expect(banners[arch][1] == arch,
			"%s: the compiler's own banner names its target as %s: %s"
			% (arch, arch, banners[arch][1] or "no target word"))
	if all(b[0] for b in banners.values()):
		versions = {arch: b[0] for arch, b in banners.items()}
		toolsets = {str(d.name) for d in (prefix / "VC/Tools/MSVC").glob("*")}
		expect(len(set(versions.values())) == 1,
			"both wrappers answer as one toolset: %s" % versions)
		version = versions["x86"]
		# `cl` reports 19.xx where the toolset directory says 14.xx (Docs/Setup.md §6.3's table:
		# toolset 14.12 -> _MSC_VER 1912). The minor number is the toolset; the major is offset
		# by 5. Asserting the pair is what makes "same toolset as the x64 one" a real claim.
		def as_toolset(text: str) -> str:
			major, _, minor = text.partition(".")
			return "%d.%s" % (int(major) - 5, minor)
		expect(any(t.startswith(as_toolset(version) + ".") for t in toolsets),
			"the banner (%s = toolset %s) matches the toolset directory: %s"
			% (version, as_toolset(version), ", ".join(sorted(toolsets))))
	else:
		expect(False, "every wrapper answers with a version")

	print("\n=== 3/4. the §6.8 probe at x86, and its object read back ===")
	# The tool's own flag set for an MSVC variant that names no `arch`: no /arch, no -m32. The
	# only thing that decides the target is which cl.exe runs. (`arch = "x86"` is X86-2's.)
	flags = toolchain.build_flags({"compiler": "cl", "optimize": 0, "crt": "mt"})
	expect(not any(f in ("/arch:IA32", "-m32") for f in flags),
		"no bitness flag is passed to either compiler: %s" % " ".join(flags))
	with tempfile.TemporaryDirectory() as tmp:
		work = Path(tmp)
		for arch in ("x86", "x64"):
			compile_link(Path(targets[arch]["wrapper"]), arch, work, flags)

	print("\n=== what is NOT claimed ===")
	print("  The i386 .exe above is not run: this Wine has no 32-bit guest (Setup.md §1/§6.7),")
	print("  and nothing in this plan is gated on running a 32-bit PE.")
	print("  Nothing is claimed about i386 codegen, -O, or what a candidate scores:")
	print("  that is X86-3 (reading COFF i386), X86-4 (a reference build) and X86-5 (shape).")
	print("  Resolving `arch = \"x86\"` to this driver is X86-2; today `decomp try` would still")
	print("  pick a bare `cl` off PATH, which is why this probe calls the wrappers directly.")

	print("\ncheck_msvc_x86_install: %s" % ("OK" if not failures else "%d FAILED" % len(failures)))
	for f in failures:
		print("  - " + f)
	return 1 if failures else 0


if __name__ == "__main__":
	sys.exit(main())
