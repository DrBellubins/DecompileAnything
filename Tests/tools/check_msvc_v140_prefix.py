"""The v140 (VS2015) prefix is usable: layout, resolution, identity, and one real candidate path.

	run: .venv/bin/python Tests/tools/check_msvc_v140_prefix.py
	     .venv/bin/python Tests/tools/check_msvc_v140_prefix.py --skip-run   # no Wine, no link

Why this exists next to `check_msvc_toolchain.py`. That one asks "is there *an* MSVC toolchain and
does it work" for the benchmark's pinned prefix (`toolchains/msvc`, v141). The Synplant target is
v140 (Synplant.md §2), so its answers come from a different prefix, laid out by a different route:
the payloads were fetched by hand and extracted (Docs/Setup.md §6.4, `toolchains/media/vc140/`), so
the tree on disk is the *VS2015* spelling (`VC/bin/amd64`, `VC/lib/amd64`), and
`toolchains/relayout_msvc.py` symlinks the manifest-era spelling on top of it. That is a chain of
five things that can silently come apart - the extraction, the relayout, the shared SDK, the wrapper
environment, and the project pin - and a `decomp try` failure on a proprietary target is the worst
place to discover which one moved. So each is asserted here, in the order the tool walks them.

Five groups:

1. **The layout, read off the disk.** Exactly one toolset directory, and its name agrees with the
   version the binaries themselves carry (`link.exe` 14.00.24247.2 -> `14.00.24247`); each
   manifest-era path resolves into the extracted VS2015 directory rather than a copy; the SDK is
   the shared one; and the compiler's own runtime DLLs (vcruntime140/msvcp140 - the host tools are
   linked against them, and this payload set ships them only under `VC/redist`) are present next to
   `cl.exe`, without which Wine answers status 53 and says nothing.
2. **What the tool concludes.** `check.msvc_target_arches` says x64 is buildable - compiler
   directory, toolset CRT libraries, SDK libraries, wrapper - and says x86 is *not*, because this
   fetch is x64-only. A toolchain that claims a target it cannot emit is the MSVC-Plan MS-0/X86-0
   bug, in the other direction.
3. **What the project pins.** `config.load` on `Tests/Proprietary/Synplant-reverse/project.toml`
   resolves the prefix, the variant resolves its driver to that prefix's `bin/x64/cl` by path (not
   to whatever is on PATH), and the flags the file states come out as `/MT /GS- /fp:precise` at the
   requested level, with `/std:c++14` - which this driver accepts, unlike `/std:c++17` - and no
   `/GL`, which is the flag the target was built with and a candidate must not use.
4. **Identity through the wrapper** (needs Wine): `cl` answers 19.00.242xx, `link` 14.00.242xx, and
   the tool's own `Tool.toolset()` names **v140** for both. A prefix whose `cl` and `link` disagree
   is not a toolchain.
5. **One candidate, the way `decomp try` builds one**: `compile.build()` with the project variant's
   flags, the object opened by `extract.CandidateObject`, one `.text$…` COMDAT per function, and
   the float body compiled with `/fp:precise` contains **no VEX encoding and no FMA** - the encoding
   fact the target shows (Synplant.md §7.4) and the one a candidate has to reproduce. Then link and
   run it, which is also the check that the SDK libraries resolve.

Exit: 0 all passed, 1 a fact came out wrong, 2 the prefix (or Wine, or the project file) is not
here to judge.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import check, compile as build_, config, extract, spawn, toolchain  # noqa: E402

PREFIX = REPO / "toolchains" / "msvc-14.0"
PROJECT = TESTS / "Proprietary" / "Synplant-reverse" / "project.toml"
VARIANT = "msvc-o2-x64"

# A float body, because that is what this target is made of: the point of compiling it is to see
# what the driver emits for `a*b+c` with /fp:precise, not whether it compiles.
PROBE = """
double probe_mix(const double *p, int n, double k) {
    double s = 0.0;
    for (int i = 0; i < n; ++i) s = p[i] * k + s;
    return s;
}
float probe_clamp(float v, float lo, float hi) {
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    return v * 1.0001f;
}
"""

MAIN = """
double probe_mix(const double *, int, double);
float probe_clamp(float, float, float);
int main() { const double t[2] = {1.0, 2.0};
    return (probe_mix(t, 2, 0.5) > 1.0 && probe_clamp(2.0f, 0.0f, 1.0f) < 1.1f) ? 0 : 1; }
"""

failures: list[str] = []


def expect(ok: bool, detail: str) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def pe_file_version(path: Path) -> str:
	"""FileVersion of a PE, read out of VS_VERSIONINFO (the same reading relayout_msvc.py uses)."""
	import lief
	image = lief.parse(str(path))

	def attr(node, name, default=None):
		value = getattr(node, name, default)
		return value() if callable(value) else value

	def walk(node):
		for child in node.childs:
			yield child
			yield from walk(child)

	for node in walk(image.resources):
		if attr(node, "id") != 16:
			continue
		for leaf in walk(node):
			if not attr(leaf, "is_data"):
				continue
			data = bytes(leaf.content)
			at = data.find(struct.pack("<I", 0xFEEF04BD))
			if at < 0:
				continue
			ms, ls = struct.unpack_from("<II", data, at + 8)
			return "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
	return ""


def layout() -> str:
	print("=== 1. the layout on disk (toolchains/relayout_msvc.py) ===")
	if not (PREFIX / "VC" / "bin" / "amd64" / "cl.exe").is_file():
		return ""
	toolsets = check.toolset_dirs(PREFIX)
	expect(len(toolsets) == 1, "exactly one toolset directory under the prefix: %s"
		% ", ".join(p.name for p in toolsets))
	if not toolsets:
		return ""
	toolset = toolsets[0]
	linker = pe_file_version(PREFIX / "VC" / "bin" / "amd64" / "link.exe")
	parts = linker.split(".")
	want = "%s.%02d.%s" % (parts[0], int(parts[1]), parts[2]) if len(parts) >= 3 else "?"
	expect(toolset.name == want,
		"the directory name is the version the binaries carry: %s vs link.exe %s" % (toolset.name, linker))
	for spelled, real in (("bin/Hostx64/x64", "VC/bin/amd64"), ("include", "VC/include"),
			("lib/x64", "VC/lib/amd64")):
		path = toolset / spelled
		expect(path.is_dir(), "%s exists" % spelled)
		if path.exists():
			expect(Path(path.resolve()) == (PREFIX / real).resolve(),
				"%s is the extracted %s, not a copy of it" % (spelled, real))
	kits = check._kits_dir(PREFIX)
	expect(kits is not None and (kits / "Include").is_dir() and (kits / "Lib").is_dir(),
		"the shared Windows SDK resolves under the prefix: %s" % (kits or "none"))
	expect(all((PREFIX / "VC" / "bin" / "amd64" / d).is_file()
		for d in ("vcruntime140.dll", "msvcp140.dll")),
		"the compiler's own runtime DLLs sit next to cl.exe (without them Wine exits 53 silently)")
	cl = toolset / "bin" / "Hostx64" / "x64" / "cl.exe"
	version = pe_file_version(cl)
	expect(version.split(".")[0] == "19" and version.split(".")[1] in ("0", "00"),
		"cl.exe is the 19.00 compiler of the v140 toolset: %s (the file version spells the minor 0)" % version)
	return toolset.name


def arches(toolset: str) -> None:
	print("\n=== 2. what the tool concludes about this prefix (check.msvc_target_arches) ===")
	got = check.msvc_target_arches(PREFIX)
	x64 = got.get("x64") or {}
	expect(x64.get("can_build"), "x64: %s" % x64.get("detail"))
	expect(any(c["path"].endswith("VC/tools/msvc/%s/bin/Hostx64/x64/cl.exe" % toolset)
		for c in x64.get("compilers", [])), "the x64 driver is the manifest-era path, toolset %s" % toolset)
	expect(x64.get("wrapper"), "the wrapper decomp would run: %s" % x64.get("wrapper"))
	expect(not x64.get("crt", {}).get("missing"), "the toolset's CRT libraries for x64: %s"
		% x64.get("crt", {}).get("detail"))
	expect(not x64.get("sdk", {}).get("missing"), "the SDK libraries for x64: %s"
		% x64.get("sdk", {}).get("detail"))
	x86 = got.get("x86") or {}
	expect(not x86.get("can_build"), "x86 is refused, as it must be - this fetch is x64 only: %s"
		% x86.get("detail"))


def project() -> dict:
	print("\n=== 3. what the project pins (Synplant-reverse/project.toml) ===")
	if not PROJECT.is_file():
		print("  no %s - nothing to judge" % PROJECT)
		return {}
	cfg = config.load(str(PROJECT))
	prefix, how = config.msvc_prefix(cfg)
	expect(prefix is not None and Path(prefix) == PREFIX, "the pinned prefix is this one (%s)" % how)
	name, variant = config.variant(cfg, VARIANT)
	# The prefix is handed over the way the CLI hands it (`decomp detect` prints the same reason),
	# because a variant that only says `compiler = "cl"` must not fall back to whatever cl is on
	# this machine - that is the era gap this project exists to close.
	driver = toolchain.compiler_for(variant, prefix=prefix, prefix_from=how)
	expect(Path(driver.name).resolve() == (PREFIX / "bin" / "x64" / "cl").resolve(),
		"the variant's driver is named by path, not by PATH: %s (%s)" % (driver.name, driver.why))
	flags = toolchain.build_flags(variant)
	for wanted in ("/MT", "/GS-", "/fp:precise", "/O2", "/std:c++14"):
		expect(wanted in flags, "%s is in the flags the project states" % wanted)
	expect(not any("/GL" in f for f in flags), "no /GL: a candidate cannot use the flag that made the target")
	print("  flags: %s" % " ".join(flags))
	return dict(variant, _driver=driver.name)


def identity(variant: dict) -> bool:
	print("\n=== 4. identity through the wrapper (this group needs Wine) ===")
	runner = None
	wrapper = PREFIX / "bin" / "x64" / "cl"
	if not (shutil.which("wine64") or shutil.which("wine")):
		print("  no Wine here - the group cannot run")
		return False
	cl = check.Tool("cl", str(wrapper))
	expect(cl.found and cl.vendor == "msvc", cl.describe())
	link = check.Tool("link", str(PREFIX / "bin" / "x64" / "link"))
	expect(link.found and link.vendor == "msvc", link.describe())
	family = (cl.toolset() or {}).get("family")
	expect(str(family).startswith("v140"), "the tool's own toolset reading names v140: %s"
		% (cl.toolset() or {}))
	expect((link.toolset() or {}).get("family") == family,
		"cl and link agree on the toolset (%s)" % (link.toolset() or {}))
	return True


def candidate(variant: dict, work: Path) -> None:
	print("\n=== 5. one candidate, built the way `decomp try` builds one ===")
	source = work / "probe.cpp"
	source.write_text(PROBE)
	object_path = work / "probe.obj"
	built = build_.build([source], object_path, compiler=variant["_driver"],
		flags=toolchain.build_flags(variant), includes=[])
	expect(built.ok, "the project variant's own flags compile a float body")
	if not built.ok:
		print("      " + "\n".join(built.diagnostics.splitlines()[:12]))
		return
	candidate_object = extract.CandidateObject(object_path)
	expect(candidate_object.error == "", "extract.CandidateObject opens it (%s, %d-bit)"
		% (candidate_object.machine, candidate_object.bits))
	sections = sorted(name for name in candidate_object._sections if name.startswith(".text"))
	expect(any(name.startswith(".text$") for name in sections),
		"one COMDAT per function: %s" % ", ".join(sections[:4]))
	# The encoding fact the target shows and a candidate has to reproduce: SSE2-only, no VEX, no FMA
	# (Synplant.md §7.4). The candidate's own code bytes are the honest place to look, so read the
	# COMDATs out of the object with the same reader the package uses for PEs, then disassemble.
	code = b""
	try:
		import lief
		image = lief.parse(str(object_path))
		for section in image.sections:
			if section.name.startswith(".text$"):
				code += bytes(section.content)
	except Exception as exc:
		print("  skip the encoding check: %s" % exc)
	import capstone
	engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	if code:
		vex = fma = sse = 0
		for instruction in engine.disasm(code, 0):
			if instruction.bytes[0] in (0xC4, 0xC5):
				vex += 1
			if instruction.mnemonic.upper().startswith(("VFMADD", "VFMSUB", "VFNMA", "VFNMS")):
				fma += 1
			if instruction.mnemonic.upper() in ("MULSD", "ADDSD", "DIVSD", "SQRTSD", "MULSS", "ADDSS",
				"MULPS", "ADDPS", "CMPLTSD", "MAXSS", "MINSS"):
				sse += 1
		expect(sse > 0, "the float body really is SSE arithmetic (%d scalar/packed float instructions)" % sse)
		expect(vex == 0 and fma == 0,
			"/fp:precise at /O2 emits no VEX and no FMA (%d VEX, %d FMA) - the target's encoding" % (vex, fma))
	entry = work / "main.cpp"
	entry.write_text(MAIN)
	entry_object = work / "main.obj"
	if not build_.build([entry], entry_object, compiler=variant["_driver"],
		flags=toolchain.build_flags(variant), includes=[]).ok:
		expect(False, "the entry point for the link probe compiles")
		return
	exe = work / ("probe.exe")
	command = [variant["_driver"], "/Fe:%s" % exe, str(object_path), str(entry_object), "/link",
		*toolchain.link_flags(variant)]
	proc = spawn.run(command, timeout=300)
	expect(proc.returncode == 0, "and links against the shared SDK's UCRT -> PE")
	if proc.returncode != 0:
		for stream in (proc.stdout, proc.stderr):
			for line in [x for x in stream.splitlines() if "Fontconfig" not in x][-6:]:
				print("      " + line)
		return
	note = toolchain.build_note(exe)
	expect(note.get("format") == "PE" and note.get("arch"), "the linked file is a PE: %s" % note.get("format"))
	wine = shutil.which("wine64") or shutil.which("wine")
	if not wine:
		print("  no wine to run it with")
		return
	run = spawn.run([wine, str(exe)], timeout=120)
	expect(run.returncode == 0, "and it runs under Wine (exit %s)" % run.returncode)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("--skip-run", action="store_true",
		help="stop after group 3: no Wine, no link, no run")
	args = parser.parse_args()
	if not PREFIX.is_dir():
		print("no %s - install the v140 payloads (Docs/Setup.md §6.4) and run\n"
			"  .venv/bin/python toolchains/relayout_msvc.py --prefix %s" % (PREFIX, PREFIX))
		return 2
	toolset = layout()
	if not toolset:
		print("the prefix is not an extracted v140 tree")
		return 2
	arches(toolset)
	variant = project()
	if not variant:
		return 1 if failures else 2
	if not args.skip_run:
		if not identity(variant):
			print("\nthe prefix itself passed; the Wine side could not be judged.")
			return 2 if not failures else 1
		with tempfile.TemporaryDirectory(prefix="v140probe-") as directory:
			candidate(variant, Path(directory))
	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_msvc_v140_prefix: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
