"""Compiler detection and build configuration.

Phase 1 needs two things from it: the target's own build note (the `.comment` section on
ELF, the Rich header on PE) so an analysis records how the binary was built, and the flags
a variant implies. Full flag inference - compiling reference snippets and comparing
prologues - is Phase 3 (Docs/Design-Plan.md).
"""

from __future__ import annotations

from pathlib import Path


def build_flags(variant: dict) -> list[str]:
	"""Compile flags a variant implies, in the same shape Tests/eval.py uses.

	GCC/Clang only for now; an MSVC (`cl`) target needs its own set, which comes with the
	Phase 3 toolchain work.
	"""
	compiler = variant.get("compiler", "g++")
	if compiler in ("cl", "cl.exe", "msvc"):
		raise NotImplementedError("MSVC flags are Phase 3 (Docs/Design-Plan.md); use a gcc/clang variant")
	flags = ["-std=%s" % variant.get("std", "c++17"), "-O%d" % int(variant.get("optimize", 0)),
		"-Wall", "-Wextra"]
	if variant.get("arch") == "x86":
		flags.append("-m32")
	flags += list(variant.get("cppflags", []))
	return flags


def link_flags(variant: dict) -> list[str]:
	return list(variant.get("linkflags", []))


def build_note(target: Path) -> dict:
	"""What the file itself says about how it was built. Best effort: a target that LIEF
	cannot parse still analyses in Ghidra, it just gets no note."""
	note = {"format": None, "arch": None, "bits": None, "entrypoint": None,
		"file_type": None, "build_notes": [], "sections": {}, "compiler_hint": None, "error": None}
	try:
		import lief
	except ImportError as exc:  # pragma: no cover - covered by `decomp check`
		note["error"] = "lief is not importable: %s" % exc
		return note
	try:
		binary = lief.parse(str(target))
	except Exception as exc:  # noqa: BLE001 - any parser failure is a note, not a crash
		note["error"] = "lief could not parse %s: %s" % (target.name, exc)
		return note
	if binary is None:
		note["error"] = "lief could not parse %s" % target.name
		return note

	try:
		note["format"] = str(binary.format).rsplit(".", 1)[-1]
		if isinstance(binary, lief.ELF.Binary):
			header = binary.header
			note["arch"] = str(header.machine_type).rsplit(".", 1)[-1]
			note["bits"] = 64 if "64" in str(header.identity_class) else 32
			note["file_type"] = str(header.file_type).rsplit(".", 1)[-1]
			note["entrypoint"] = header.entrypoint
			# Section addresses in the file's own terms: Ghidra may load the image somewhere
			# else (a PIE at 0x100000), and the two address domains have to be reconciled.
			note["sections"] = {str(section.name): int(section.virtual_address)
				for section in binary.sections if section.size}
			section = binary.get_section(".comment")
			if section is not None:
				for text in bytes(section.content).split(b"\x00"):
					if text.strip():
						note["build_notes"].append(text.decode("utf-8", "replace"))
		elif isinstance(binary, lief.PE.Binary):
			note["arch"] = str(binary.header.machine).rsplit(".", 1)[-1]
			note["bits"] = 64 if "64" in note["arch"] else 32
			note["entrypoint"] = binary.header.address_of_entry_point
			rich = getattr(binary, "rich_header", None)
			if rich is not None:
				for entry in rich.entries:
					note["build_notes"].append("rich:%s:%d" % (getattr(entry, "key", "?"),
						getattr(entry, "number", 0)))
			for version in getattr(binary, "version_resources", []) or []:
				note["build_notes"].append("version:%s" % version)
		elif isinstance(binary, lief.MachO.Binary):
			note["arch"] = str(binary.header.file_type).rsplit(".", 1)[-1]
			note["entrypoint"] = binary.header.entrypoint
			note["file_type"] = str(binary.header.file_type).rsplit(".", 1)[-1]
	except Exception as exc:  # noqa: BLE001
		note["error"] = "while reading the headers of %s: %s" % (target.name, exc)
		return note

	joined = " ".join(note["build_notes"]).lower()
	if "gcc" in joined or "g++" in joined:
		note["compiler_hint"] = "gcc"
	elif "clang" in joined or "llvm" in joined:
		note["compiler_hint"] = "clang"
	elif note["build_notes"] and all(str(n).startswith("rich:") for n in note["build_notes"]):
		note["compiler_hint"] = "msvc"
	return note
