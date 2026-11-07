"""X86-0 acceptance (Docs/MSVC-x86-Plan.md §6 X86-0): does the tool describe this machine's
MSVC toolchain honestly, per *target* arch?

	run: .venv/bin/python Tests/tools/check_msvc_x86_toolchain.py

This is a report check, not a compiler check. It compiles nothing, and it is written to pass
**both before and after X86-1**: for every target arch it measures the tree itself and asserts
that what `decomp check` says agrees with it, so the claim under test is the report, not the
machine. Before X86-1 this machine's v141 tree says "x64 only"; after X86-1 it must say
"can build x86 candidates" and the same assertions still hold, read off the new tree.

Groups:

1. **The prefix is found, and how it was found is stated.** A toolchain installed at
   `toolchains/msvc` with its wrappers off PATH is a different gap from a toolchain that is not
   installed, and reporting the second when the first is true is what made `decomp check` say
   "no `cl` on PATH" about a compiler that is sitting in the repo.
2. **Per-target-arch facts match the tree.** For x64 and x86: `VC/Tools/MSVC/<v>/bin/Host*/
   <arch>/cl.exe`, the toolset's `lib/<arch>` CRT import libraries, the SDK's
   `Windows Kits/10/Lib/<v>/{ucrt,um}/<arch>`, and the `<prefix>/bin/<arch>/cl` wrapper are each
   looked for twice - once by the tool, once here - and the answers must be the same.
   `can_build` only when the first three hold.
3. **The sentences.** A toolchain that can only do x64 has to say "no 32-bit target from this
   toolchain" and name the command that would add it; one that can do the arch has to name the
   compiler's own `Host<h>/<arch>` directory, because that - not a flag - is the bitness.
4. **`msvc_sdk(arch=…)` per arch.** The SDK half is its own question: on this machine the x86
   import libraries *are* installed, so "no 32-bit MSVC here" is a toolset gap, not an SDK gap.
   A call with no arch still means x64 (the pre-X86-0 behaviour the other scripts rely on).
5. **What `decomp check` prints for a variant.** A `[variants.*] arch = "x86"` MSVC variant is
   named before any work starts; `arch = "x86-64"` and an ISA-level `arch = "AVX2"` are not; a
   `-m32` GCC variant is named only when the driver really cannot do that target.

Exit: 0 all passed, 1 something came out wrong, 2 there is no MSVC toolchain here to judge.

X86-2 (one `arch` -> driver resolver) extends this file with its `build_flags`/resolver assertions,
as Docs/MSVC-x86-Plan.md §6 says; nothing here pre-judges what a 32-bit `cl` emits.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import check, config  # noqa: E402

failures: list[str] = []


def expect(ok: bool, detail: str) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def tree_cl(prefix: Path, arch: str) -> list[str]:
	"""An independent read of the same question: which `cl.exe` targets this arch?"""
	return sorted(glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "bin" / "Host*"
		/ arch / "cl.exe")))


def tree_crt(prefix: Path, arch: str) -> bool:
	"""Does the toolset have the CRT import libraries for this target arch?"""
	dirs = (glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "lib" / arch))
		+ glob.glob(str(prefix / "VC" / "Tools" / "MSVC" / "*" / "lib" / "onecore" / arch)))
	return all(any((Path(d) / name).is_file() for d in dirs) for name in check.MSVC_CRT_LIBS)


def tree_sdk(prefix: Path, arch: str) -> bool:
	"""Does the Windows SDK have its import libraries for this target arch?"""
	return all(bool(glob.glob(str(prefix / "Windows Kits" / "10" / "Lib" / "*" / part
		/ arch / name))) for part, name in check.MSVC_SDK_LIBS)


def wrapper_dir(prefix: Path, arch: str) -> list[str]:
	return sorted(glob.glob(str(prefix / "bin" / arch / "cl")))


def prefix_found() -> "Path | None":
	prefix, why = check.msvc_prefix()
	on_path = check.Tool("cl").found
	expect(prefix is not None, "a toolchain prefix is found: %s (%s)" % (prefix, why))
	if prefix is None:
		return None
	expect((prefix / "VC").is_dir() or (prefix / "Windows Kits").is_dir(),
		"the prefix named is a real toolchain root: %s" % prefix)
	if on_path:
		expect("from the cl on PATH" in why, "found from PATH, and says so: %s" % why)
	else:
		expect("not on PATH" in why,
			"an installed toolchain that is off PATH is reported as that, not as absent: %s" % why)
	return prefix


def per_arch(prefix: Path) -> None:
	targets = check.msvc_target_arches(prefix)
	for arch in check.MSVC_TARGET_ARCHES:
		entry = targets.get(arch)
		expect(entry is not None, "%s is answered for at all" % arch)
		if entry is None:
			continue
		cl, crt, sdk = tree_cl(prefix, arch), tree_crt(prefix, arch), tree_sdk(prefix, arch)
		expect(sorted(c["path"] for c in entry["compilers"]) == cl,
			"%s: the tool finds %s, the tree has %s" % (arch,
				", ".join(c["path"] for c in entry["compilers"]) or "no cl.exe",
				", ".join(cl) or "no cl.exe"))
		expect((not entry["crt"]["missing"]) == crt,
			"%s: toolset CRT libraries - tool says %s, the tree says %s"
			% (arch, "complete" if not entry["crt"]["missing"] else "missing",
			"complete" if crt else "missing"))
		expect((not entry["sdk"]["missing"]) == sdk,
			"%s: Windows SDK libraries - tool says %s, the tree says %s"
			% (arch, "complete" if not entry["sdk"]["missing"] else "missing",
			"missing" if not sdk else "complete"))
		expect(entry["can_build"] == (bool(cl) and crt and sdk),
			"%s: can_build=%s agrees with those three facts" % (arch, entry["can_build"]))
		expect(entry["on_path"] == (check.arch_on_path() == arch),
			"%s: on_path=%s is judged by the wrapper directory on PATH (%s)"
			% (arch, entry["on_path"], check.arch_on_path() or "no cl on PATH"))
		expect(bool(entry["wrapper"]) == bool(wrapper_dir(prefix, arch)),
			"%s: the wrapper is reported as %s, the tree has %s" % (arch,
				entry["wrapper"] or "none", ", ".join(wrapper_dir(prefix, arch)) or "none"))
		if entry["compilers"]:
			# The bitness is the directory the compiler lives in, so the report has to name it.
			expect(any("host" in c and c["host"].lower().startswith("host") for c in entry["compilers"]),
				"%s names the host directory of its cl.exe: %s"
				% (arch, ", ".join(c["host"] for c in entry["compilers"])))
			expect("cl for %s targets" % arch in entry["detail"],
				"%s: the line says which cl it found" % arch)
		else:
			expect("no cl.exe" in entry["detail"] or "no 32-bit target" in entry["detail"],
				"%s: the line names the missing compiler rather than a symptom" % arch)
			expect(bool(entry["fix"]), "%s: a missing target comes with the command to add it" % arch)
			if arch == "x86" and targets.get("x64", {}).get("compilers"):
				expect("x64 only: no 32-bit target from this toolchain" in entry["detail"],
					"x86 is called what it is: x64 only, not \"complete\"")
				expect("--architecture" in entry["fix"] and "install.sh" in entry["fix"],
					"the fix names the install that would add the target: %s" % entry["fix"][:160])
		# Which half is missing has to be separable: the SDK libraries for x86 are installed on
		# this machine, so an x86 gap here is the toolset's and the report must not blur them.
		if sdk != crt:
			expect(("Windows SDK libraries for %s: all of them are there" % arch in entry["detail"])
				== sdk, "%s: the SDK half is reported separately from the toolset half" % arch)


def sdk_per_arch(prefix: Path) -> None:
	x64 = check.msvc_sdk()
	expect(x64.get("arch") == "x64", "msvc_sdk() with no arch still answers about x64")
	expect(bool(x64.get("complete")) == tree_sdk(prefix, "x64"),
		"msvc_sdk() (x64) still agrees with the tree: %s" % x64.get("detail"))
	for arch in check.MSVC_TARGET_ARCHES:
		sdk = check.msvc_sdk(arch=arch)
		expect(sdk.get("arch") == arch and bool(sdk.get("complete")) == tree_sdk(prefix, arch),
			"msvc_sdk(arch=%s) = %s (%s)" % (arch, sdk.get("complete"), sdk.get("detail")))
		if not sdk.get("complete"):
			expect(arch in sdk.get("detail", "") or "placeholder" in sdk.get("detail", ""),
				"a negative SDK answer names what is missing for %s" % arch)


def report_for(variants: dict) -> list:
	"""Run the real startup check over a synthetic config; nothing here compiles anything."""
	with tempfile.TemporaryDirectory(prefix="x86check-") as directory:
		path = Path(directory) / "project.toml"
		body = ["[gate]\nrequire = \"none\"\n"]
		for name, values in variants.items():
			body.append("[variants.%s]\n" % name)
			body += ["%s = %r\n" % (key, value) for key, value in values.items()]
		path.write_text("".join(body))
		cfg = config.load(str(path))
		report = check.check_all(cfg, want_compilers=False)
	return [(item.name, item.level, item.detail) for item in report.items]


def variants_asked(prefix: Path) -> None:
	"""A variant whose arch no installed driver can serve is named before any work starts."""
	x64_ok = check.msvc_target_arches(prefix).get("x64", {}).get("can_build")
	x86 = check.msvc_target_arches(prefix).get("x86", {})
	items = report_for({
		"msvc-x86": {"compiler": "cl", "optimize": 0, "arch": "x86", "crt": "mt"},
		"msvc-x64": {"compiler": "cl", "optimize": 0, "arch": "x86-64"},
		"msvc-isa": {"compiler": "cl", "optimize": 2, "arch": "AVX2"},
		"gcc-m32": {"compiler": "g++", "optimize": 0, "arch": "x86"},
	})
	named = {name[len("arch "):]: (level, detail)
		for name, level, detail in items if name.startswith("arch ")}
	target_lines = {name: (level, detail) for name, level, detail in items
		if name.startswith("msvc target ")}
	expect(set(target_lines) == {"msvc target x64", "msvc target x86"},
		"`decomp check` prints the per-target-arch table: %s" % sorted(target_lines))
	expect(target_lines.get("msvc target x86", ("?",))[0] in ("warn", "ok"),
		"a toolchain that cannot do x86 is a fact, not a fault: %s"
		% target_lines.get("msvc target x86", ("absent",))[0])
	if not x86.get("can_build"):
		expect("msvc-x86" in named, "an arch the toolchain cannot serve is named per variant")
		level, detail = named.get("msvc-x86", ("?", ""))
		expect(level == "warn", "…as a warning, so reading a 32-bit target still works: %s" % level)
		expect("cannot be built here" in detail or "only half installed" in detail,
			"…saying which half is missing, not a symptom: %s" % detail[:200])
		if not tree_cl(prefix, "x86"):
			expect("no 32-bit target" in detail,
				"…and calling an x64-only toolchain that: %s" % detail[:200])
		known = {os.path.relpath(os.path.dirname(p), prefix) for p in tree_cl(prefix, "x64")}
		expect(any(where in detail for where in known) or "not on PATH" in detail,
			"…naming what this toolchain does have, so the gap is locatable: %s" % detail[:200])
	else:
		print("      (x86 is buildable here; the variant is only named if it is unreachable)")
	expect("msvc-x64" not in named or x64_ok is False
		or "not on PATH" in named["msvc-x64"][1],
		"an x64 MSVC variant is never told it cannot be built here when this toolchain serves "
		"x64: %s" % named.get("msvc-x64", ("not named", ""))[1][:200])
	expect("msvc-isa" not in named,
		"arch = \"AVX2\" is an ISA level, not a bitness, and is not contradicted (%s)"
		% sorted(named))
	multilib = subprocess.run(["g++", "-m32", "-x", "c", "-c", "-o", "/dev/null", "-"],
		input="", capture_output=True, text=True, timeout=120).returncode == 0
	expect(("gcc-m32" in named) != multilib,
		"a -m32 GCC variant is named only if the driver really cannot do it (multilib here: %s)"
		% multilib)


def main() -> int:
	print("=== 1. the prefix, and how it was found ===")
	prefix = prefix_found()
	if prefix is None:
		print("\nNo MSVC toolchain installed here (nothing on PATH, nothing under toolchains/).\n"
			"Nothing was judged - install one (Docs/Setup.md §6) and re-run this check.")
		return 2
	print("\n=== 2. per-target-arch facts (the tree is measured twice) ===")
	per_arch(prefix)
	print("\n=== 3. the sentences ===")
	targets = check.msvc_target_arches(prefix)
	for arch in check.MSVC_TARGET_ARCHES:
		print("  %s: %s" % (arch, targets[arch]["summary"]))
		print("      %s" % targets[arch]["detail"])
	print("\n=== 4. the Windows SDK, per target arch ===")
	sdk_per_arch(prefix)
	print("\n=== 5. what a variant is told before any work starts ===")
	variants_asked(prefix)

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_msvc_x86_toolchain: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
