"""MSVC-x86 X86-4 acceptance (Docs/MSVC-x86-Plan.md): the 32-bit MSVC reference build and its answer key.

	run: .venv/bin/python Tests/tools/check_msvc_x86_reference.py
	     [--variant msvc-o0-x86] [--no-run]

X86-3 made an i386 candidate *readable*; this is the asset it is read against. The phase asks for
three things and refuses to claim a fourth, and the groups follow that order:

1. **No bitness flag, and the image proves it.** The variant's own `build_flags`/`link_flags` name
   no `-m32`, no `/arch:IA32`, no `/MACHINE:X86` — and the linked program *measures* PE32 (i386).
   The flags are read as the tool builds them, the bitness from the optional header: `/MACHINE:`
   would only be needed if a link had to be told what the objects already say (X86-Plan §8).
2. **One directory, one program.** Every MSVC build directory holds one reference binary (no `da_tests`
   beside a newer `da_tests.exe`), the `link /MAP` beside it is stamped with that image's own
   TimeDateStamp, and every answer-key unit address lands inside an executable section of *that*
   image. Before this phase all three MSVC directories held a fresh map next to an older link, so
   the answer key and the bytes it scores were two different programs — and the `.text`-after-strip
   check could not see it, because a PE is not stripped.
3. **The answer key says where its extents came from.** An i386 PE has no function table, so its key
   is the map file with extents taken to the next name, and that has to be *printed*, next to the
   unit count, not buried above it. The x64 MSVC key still says `.pdata` first: the i386 path must
   not become the answer for a file that carries a table (Docs/MSVC-x86-Plan.md X86-3).
4. **Running it, or refusing with a reason.** A 32-bit *target* needed nothing from this machine; a
   32-bit *guest* needs Docs/Setup.md §6.7. With a guest available, `selfcheck` reports the
   reference program's own expectations passing and `crosscheck` compares behaviour across every
   built variant, including a 32-bit MSVC one. Without one, `selfcheck` exits 2 and says which
   option would fix it — never a silent zero, never a failed score.

Exit: 0 all passed, 1 something came out wrong, 2 the variant is not built (or not an MSVC x86
variant), which is not a failure of the tool.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import check, config, toolchain  # noqa: E402

EVAL = TESTS / "eval.py"


def expect(ok: bool, detail: str, failures: list[str]) -> None:
	print("  %s %s" % ("ok  " if ok else "FAIL", detail))
	if not ok:
		failures.append(detail)


def run_eval(*args: str) -> tuple[int, str]:
	"""Ask the harness itself, so this script cannot disagree with what it runs."""
	finished = subprocess.run([sys.executable, str(EVAL)] + list(args),
		capture_output=True, text=True, timeout=600)
	return finished.returncode, (finished.stdout or "") + (finished.stderr or "")


def pe_image(path: Path) -> dict:
	"""{machine, bits, timestamp, sections} read from the file, never from the build flags."""
	data = path.read_bytes()
	offset = struct.unpack_from("<I", data, 0x3C)[0]
	if data[offset:offset + 4] != b"PE\0\0":
		raise RuntimeError("%s is not a PE" % path)
	coff = offset + 4
	machine, _, _, _, _, size_optional, _ = struct.unpack_from("<HHIIIHH", data, coff)
	optional = coff + 20
	magic = struct.unpack_from("<H", data, optional)[0]
	bits = 64 if magic == 0x20B else 32
	base = (struct.unpack_from("<Q", data, optional + 24)[0] if magic == 0x20B
		else struct.unpack_from("<I", data, optional + 28)[0])
	sections = []
	for index in range(struct.unpack_from("<H", data, coff + 2)[0]):
		head = optional + size_optional + index * 40
		name = data[head:head + 8].split(b"\0")[0].decode("latin-1")
		vsize, rva = struct.unpack_from("<II", data, head + 8)
		# IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE are alternatives, not both set
		# (Docs/MSVC-Plan.md §8) - and they live at +36, not behind the four size fields.
		characteristics = struct.unpack_from("<I", data, head + 36)[0]
		sections.append({"name": name, "va": base + rva, "size": vsize,
			"code": bool(characteristics & 0x20000020)})
	return {"machine": machine, "bits": bits, "base": base,
		"timestamp": struct.unpack_from("<I", data, coff + 4)[0], "sections": sections}


def variant_and_flags(name: str) -> tuple[dict, list[str], list[str]]:
	cfg = config.load(str(TESTS / "project.toml"))
	variant_name, variant = config.variant(cfg, name)
	if not toolchain.msvc(variant.get("compiler", "")):
		raise SystemExit("%s is not an MSVC variant (compiler = %s)"
			% (variant_name, variant.get("compiler")))
	if str(variant.get("arch", "")).lower() not in ("x86", "i386", "i686"):
		raise SystemExit("%s asks for arch = %r; this check is the 32-bit reference build "
			"(check_coff_candidate.py / check_msvc_toolchain.py judge x86-64)"
			% (variant_name, variant.get("arch")))
	# The config-wide linkflags/cppflags are what eval.py merges into a variant; take the same
	# merge here, or "no /MACHINE: anywhere" would be a claim about half the command line.
	for key in ("cppflags", "linkflags"):
		if key not in variant and cfg.get(key):
			variant[key] = list(cfg[key])
	variant.setdefault("std", cfg.get("std", "c++17"))
	return variant, toolchain.build_flags(variant), toolchain.link_flags(variant)


def no_bitness_flag(variant: dict, flags: list[str], link: list[str], failures: list[str]) -> None:
	print("=== 1. the link is not told the bitness, and the image says what it is ===")
	print("   build %s" % " ".join(flags))
	print("   link  %s" % " ".join(link))
	bitness = [flag for flag in flags + link
		if flag in ("-m32", "/arch:IA32") or flag.upper().startswith("/MACHINE")]
	expect(not bitness, "no bitness flag in either list (%s)"
		% (", ".join(bitness) or "-m32 / /arch:IA32 / /MACHINE: all absent"), failures)
	expect(variant.get("arch") in ("x86", "i386", "i686"),
		"the variant asks for arch = %r, and that is what selects the driver (X86-2), not a flag"
		% variant.get("arch"), failures)


def one_program(build_dir: Path, answer: dict, failures: list[str]) -> None:
	print("=== 2. one directory, one program ===")
	left = [path.name for path in build_dir.glob("da_tests.exe")]
	expect(not left, "no second reference binary in %s (%s)"
		% (build_dir.name, ", ".join(left) or "da_tests only"), failures)
	image = build_dir / "da_tests"
	stripped = build_dir / "da_tests.stripped"
	if not image.is_file() or not stripped.is_file():
		failures.append("no reference binary in %s" % build_dir)
		return
	info = pe_image(image)
	expect(info["machine"] == 0x14C and info["bits"] == 32,
		"the linked program is a 32-bit PE: machine 0x%x, optional header PE32 (%d-bit)"
		% (info["machine"], info["bits"]), failures)
	# A PE from `link` has no symbol table to strip, so the two names hold the same bytes - and
	# every answer-key address has to stay valid in both. Asserted, because it is the reason the
	# analysis of `da_tests.stripped` is the analysis of the program the answer key describes.
	expect(image.read_bytes() == stripped.read_bytes(),
		"da_tests and da_tests.stripped are the same bytes (a PE is not stripped)", failures)
	map_path = Path(str(image) + ".map")
	if map_path.is_file():
		stamp = re.search(r"Timestamp is ([0-9a-fA-F]{8})", map_path.read_text(errors="replace"))
		expect(bool(stamp) and int(stamp.group(1), 16) == info["timestamp"],
			"the map file belongs to this link: the image is stamped %s and %s says %s"
			% (hex(info["timestamp"]), map_path.name,
				stamp.group(1) if stamp else "nothing"), failures)
	# The check the pre-X86-4 directories would have failed: an extent taken from one link and an
	# address range read out of another land outside the code.
	code = [section for section in info["sections"] if section["code"]]
	outside = [unit["id"] for unit in answer["units"]
		if not any(section["va"] <= unit["address"] < section["va"] + section["size"]
			for section in code)]
	expect(not outside, "every one of the %d answer-key units lies in an executable section of "
		"this image (%s outside: %s)" % (len(answer["units"]), len(outside),
			", ".join(outside[:6])), failures)


def answer_key_says_its_basis(build_dir: Path, answer: dict, failures: list[str]) -> None:
	print("=== 3. the answer key names where its extents came from ===")
	build = json.loads((build_dir / "build.json").read_text())
	tally = build.get("answer_key_extents") or {}
	print("   build.json answer_key_extents: %s" % (tally or "absent"))
	expect(bool(tally) and sum(tally.values()) == len(answer["units"]),
		"the recorded provenance accounts for every unit (%d recorded, %d units)"
		% (sum(tally.values()), len(answer["units"])), failures)
	tabled = {source: count for source, count in tally.items() if "pdata" in source}
	expect(not tabled, "no unit of a 32-bit PE is claimed to come from a function table (%s)"
		% (tabled or "none"), failures)
	spaced = {source: count for source, count in tally.items() if "MAP" in source or "/MAP" in source}
	expect(sum(spaced.values()) == len(answer["units"]),
		"all %d units are recorded as map names bounded by the next name - the weaker key, and it "
		"is printed as one (eval.py: 'carries no .pdata')" % len(answer["units"]), failures)


def x64_key_not_moved(failures: list[str]) -> None:
	"""The i386 path must not answer for a file that does carry a table."""
	for name in ("msvc-o0", "msvc-o2"):
		build_dir = TESTS / "build" / name
		if not (build_dir / "answer_key.json").is_file():
			continue
		answer = json.loads((build_dir / "answer_key.json").read_text())
		tally = json.loads((build_dir / "build.json").read_text()).get("answer_key_extents") or {}
		tabled = {source: count for source, count in tally.items() if "pdata" in source}
		info = pe_image(build_dir / "da_tests")
		expect(info["bits"] == 64 and sum(tally.values()) == len(answer["units"]) and tabled,
			"%s still answers from its own function table: %d-bit image, %d units, %s"
			% (name, info["bits"], len(answer["units"]), tally or "no provenance recorded"),
			failures)


def running_it(failures: list[str], variant_name: str, skip: bool) -> None:
	print("=== 4. running the 32-bit reference program, or refusing with a reason ===")
	guest = check.i386_guest()
	print("   decomp check would say: %s | %s" % ("ok" if guest["ok"] else "warn", guest["detail"]))
	expect(guest["ok"] == bool(toolchain.wibo_path() or _wine_i386()),
		"the report's answer agrees with what is installed here (wibo at %s)"
		% (toolchain.wibo_path() or "not installed"), failures)
	expect(not guest["ok"] or "target" in guest["fix"],
		"the row keeps a 32-bit *target* out of it: %s" % guest["fix"], failures)
	if skip:
		print("   --no-run: selfcheck/crosscheck not asked (the run group is still reported above)")
		return
	code, out = run_eval("selfcheck", "--variant", variant_name)
	summary = [line for line in out.splitlines() if "failures" in line or "not run" in line]
	if guest["ok"]:
		expect(code == 0 and any(line.strip().endswith("0 failures") for line in summary),
			"eval.py selfcheck --variant %s runs the reference program and it passes (%d): %s"
			% (variant_name, code, " | ".join(summary)), failures)
		built = TESTS / "build" / variant_name / "goldens.jsonl"
		cases = len([line for line in built.read_text().splitlines() if line.strip()]) if built.is_file() else 0
		expect(cases == len(json.loads((TESTS / "build" / variant_name / "answer_key.json")
			.read_text())["units"]),
			"goldens were captured for it: %d cases" % cases, failures)
	else:
		expect(code == 2 and any("§6.7" in line or "32-bit" in line for line in summary),
			"without a 32-bit guest selfcheck exits 2 and names the option (exit %d): %s"
			% (code, " | ".join(summary)), failures)
		return
	# Behaviour must not depend on which compiler or bitness built the reference. This is the first
	# time the benchmark can ask that question of a 32-bit MSVC program at all.
	traces = [name for name in ("gcc-o0", "gcc-o0-x86", "mingw-o0", "msvc-o0", variant_name)
		if (TESTS / "build" / name / "goldens.jsonl").is_file()]
	code, out = run_eval("crosscheck", "--variants", ",".join(traces))
	tail = [line for line in out.splitlines() if line.startswith("crosscheck:")]
	expect(code == 0 and bool(tail), "crosscheck over %s (%s): %s"
		% (", ".join(traces), "exit %d" % code, " | ".join(tail)), failures)


def _wine_i386() -> bool:
	return any((path / "i386-windows").is_dir() for path in
		(Path("/usr/lib/wine"), Path("/usr/lib32/wine"), Path("/usr/lib/i386-linux-gnu/wine")))


def main() -> int:
	parser = argparse.ArgumentParser(prog="check_msvc_x86_reference.py",
		description=__doc__.splitlines()[0])
	parser.add_argument("--variant", default="msvc-o0-x86")
	parser.add_argument("--no-run", action="store_true",
		help="skip the selfcheck/crosscheck group (only the asset is being checked)")
	args = parser.parse_args()

	try:
		variant, flags, link = variant_and_flags(args.variant)
	except config.ConfigError as exc:
		print("no variant to judge: %s" % exc)
		return 2
	name = args.variant
	build_dir = TESTS / "build" / name
	answer_path = build_dir / "answer_key.json"
	if not answer_path.is_file() or not (build_dir / "build.json").is_file():
		print("build the reference first: Tests/eval.py build --variant %s" % name)
		return 2
	answer = json.loads(answer_path.read_text())
	print("variant %s: %d units in %s" % (name, len(answer["units"]), build_dir))

	failures: list[str] = []
	no_bitness_flag(variant, flags, link, failures)
	one_program(build_dir, answer, failures)
	answer_key_says_its_basis(build_dir, answer, failures)
	x64_key_not_moved(failures)
	running_it(failures, name, args.no_run)

	if failures:
		print("\nFAILURES (%d):" % len(failures))
		for item in failures:
			print("  %s" % item)
		return 1
	print("\ncheck_msvc_x86_reference: OK")
	return 0


if __name__ == "__main__":
	sys.exit(main())
