"""Compiler detection, build configuration, and optimisation-level inference (Phase 3).

Three things live here:

* `build_note()` - what the file itself says about how it was built: the `.comment`
  section (ELF), the Rich header and CodeView record (PE), the object type, the dynamic
  section, and `.note.gnu.property`. Read straight from the bytes: no analysis, no Ghidra.
* `shape_profile()` / `probe_signatures()` / `infer_optimize()` - the flag-inference
  helper. It compiles reference snippets with the compilers that are installed here, at
  each `-O`, and describes the *shape* of the code each flag set produces on this machine
  (prologue/epilogue and stack-traffic patterns). The target's own code is described the
  same way, out of its `.text`, and the two are ranked against each other.
* `starter_config()` - a `project.toml` written from the facts above, with every guess
  labelled as a guess next to the line it produced.

Nothing here is stated as fact unless it came from the file. An optimisation level is
never a fact a stripped binary carries: it is a ranked guess, and the report says how far
apart the candidates are.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path


# --------------------------------------------------------------------------------------
# build flags (the [variants.*] table)


def msvc(compiler) -> bool:
	"""Is this an MSVC-style driver? Its argument form differs in every way that matters."""
	return str(compiler or "").lower() in ("cl", "cl.exe", "clang-cl", "msvc", "icx", "icx-cl")


def _std_year(std) -> str:
	text = str(std).replace("c++", "").replace("gnu++", "")
	return text if text.isdigit() else "17"


def build_flags(variant: dict) -> list[str]:
	"""Compile flags a variant implies, in the same shape Tests/eval.py uses.

	GCC/Clang by default; an MSVC (`cl`) variant gets its own set, since `cl` accepts
	neither `-std` nor `-O`. These are the flags the config stores; `driver_form()` turns
	them into the driver's own argument form.
	"""
	if msvc(variant.get("compiler", "g++")):
		flags = ["/std:c++%s" % _std_year(variant.get("std", "c++17")),
			"/O2" if int(variant.get("optimize", 0)) >= 2 else "/Od", "/W3", "/EHsc", "/nologo"]
		if variant.get("arch") == "x86":
			flags.insert(0, "/arch:IA32")
		return flags + list(variant.get("cppflags", []))
	flags = ["-std=%s" % variant.get("std", "c++17"), "-O%d" % int(variant.get("optimize", 0)),
		"-Wall", "-Wextra"]
	if variant.get("arch") == "x86":
		flags.append("-m32")
	return flags + list(variant.get("cppflags", []))


def link_flags(variant: dict) -> list[str]:
	return list(variant.get("linkflags", []))


def driver_form(compiler: str, flags: list[str], sources: list[Path], object_path: Path,
	includes: list[Path] | None = None) -> list[str]:
	"""The command line for one build, in the form this driver accepts (`-c -o` vs `/c /Fo`)."""
	command = [compiler, *flags]
	msvc_driver = msvc(compiler)
	for include in [*(includes or []), *(Path(source).parent for source in sources)]:
		command += [("/I" if msvc_driver else "-I"), str(Path(include))]
	command += ["/c"] if msvc_driver else ["-c"]
	command += [str(source) for source in sources]
	command += ["/Fo%s" % object_path] if msvc_driver else ["-o", str(object_path)]
	return command


# --------------------------------------------------------------------------------------
# what the file says about how it was built


def build_note(target: Path) -> dict:
	"""What the file itself says about how it was built. Best effort: a target LIEF cannot
	parse still analyses in Ghidra, it just gets no note."""
	note = {"path": str(target), "name": Path(target).name, "format": None, "arch": None,
		"bits": 0, "entrypoint": None, "file_type": None, "pie": None, "static": None,
		"needed": [], "interp": None, "sections": {}, "segments": [], "gnu_features": [],
		"comment": [], "rich": [], "linker_version": None, "dynstr": "",
		"compiler": None, "compiler_id": None, "compiler_version": None, "linker": None,
		"abi": None, "language": None, "std_hints": [], "build_notes": [],
		"compiler_hint": None, "error": None}
	try:
		import lief
	except ImportError as exc:  # pragma: no cover - covered by `decomp check`
		note["error"] = "lief is not importable: %s" % exc
		return note
	try:
		binary = lief.parse(str(target))
	except Exception as exc:  # noqa: BLE001 - any parser failure is a note, not a crash
		note["error"] = "lief could not parse %s: %s" % (Path(target).name, exc)
		return note
	if binary is None:
		note["error"] = "lief could not parse %s" % Path(target).name
		return note

	try:
		note["format"] = str(binary.format).rsplit(".", 1)[-1]
		if isinstance(binary, lief.ELF.Binary):
			_read_elf(binary, note)
		elif isinstance(binary, lief.PE.Binary):
			_read_pe(binary, note)
		elif isinstance(binary, lief.MachO.Binary):
			_read_macho(binary, note)
		else:
			note["error"] = "%s is not an ELF/PE/Mach-O this tool knows" % Path(target).name
			return note
	except Exception as exc:  # noqa: BLE001
		note["error"] = "while reading the headers of %s: %s" % (Path(target).name, exc)
		return note

	note["build_notes"] = list(note["comment"]) + ["rich:id=%d:build=%d:%d" % (item["id"],
		item["build"], item["count"]) for item in note["rich"]]
	_read_build_strings(note)
	language_evidence(note)
	note["compiler_hint"] = {"gcc": "gcc", "clang": "clang", "msvc": "msvc"}.get(note["compiler"])
	return note


def _short(value) -> str:
	return str(value).rsplit(".", 1)[-1]


def _segments(binary):
	"""(type name, segment) for every segment, in one pass, with LIEF's warning about segment
	types it cannot name suppressed: architecture-specific PT_* values reach the enum as an
	unknown number."""
	import warnings

	with warnings.catch_warnings():
		warnings.simplefilter("ignore", RuntimeWarning)
		segments = list(binary.segments)
		return [(_short(segment.type), segment) for segment in segments]


def _segment_types(binary) -> list[str]:
	return [name for name, _segment in _segments(binary)]


def _read_elf(binary, note: dict) -> None:
	import warnings

	header = binary.header
	note["arch"] = _short(header.machine_type)
	note["bits"] = 64 if "64" in str(header.identity_class) else 32
	note["file_type"] = _short(header.file_type)          # DYN (PIE/shared), EXEC, REL (a .o)
	note["entrypoint"] = int(header.entrypoint)
	# Section addresses in the file's own terms: Ghidra may load the image somewhere else
	# (a PIE at 0x100000), and the two address domains have to be reconciled.
	note["sections"] = {str(section.name): int(section.virtual_address)
		for section in binary.sections if section.size}
	note["segments"] = _segment_types(binary)
	for section in binary.sections:
		name = str(section.name)
		if name == ".comment":
			for text in bytes(section.content).split(b"\x00"):
				if text.strip():
					note["comment"].append(text.decode("utf-8", "replace"))
		elif name == ".dynstr":
			# The dynamic string table survives stripping: it holds the names of everything
			# the program imports, which is what says which language and standard library it uses.
			note["dynstr"] = bytes(section.content)[:400000].decode("utf-8", "replace")
	for kind, segment in _segments(binary):
		if kind == "INTERP":
			note["interp"] = bytes(segment.content).split(b"\x00")[0].decode("utf-8", "replace")
	for entry in binary.dynamic_entries:
		if _short(entry.tag) == "NEEDED":
			note["needed"].append(str(entry.name))
	for note_item in binary.notes:
		if "PROPERTY" not in str(note_item.type):
			continue
		for prop in getattr(note_item, "properties", []) or []:
			if "FEATURE" not in type(prop).__name__:
				continue
			for feature in getattr(prop, "features", []) or []:
				note["gnu_features"].append(_short(feature))
	# Both are needed for a PIE (ET_DYN *and* a program interpreter), and no PT_DYNAMIC and
	# no DT_NEEDED means it was linked static. `-m32`/`-m64` come from the class exactly.
	note["pie"] = note["file_type"] == "DYN" and bool(note["interp"])
	note["static"] = "DYNAMIC" not in note["segments"] and not note["needed"]
	if note["static"]:
		note["link_flags"] = ["-static"]
	elif note["pie"] is False and note["file_type"] == "EXEC":
		note["link_flags"] = ["-no-pie"]
	else:
		note["link_flags"] = []


def _read_pe(binary, note: dict) -> None:
	header = binary.header
	note["arch"] = _short(header.machine)
	note["bits"] = 64 if "64" in note["arch"] else 32
	note["entrypoint"] = int(binary.optional_header.addressof_entrypoint)
	note["file_type"] = "DLL" if int(header.characteristics) & 0x2000 else "EXE"  # IMAGE_FILE_DLL
	note["pie"] = bool(int(binary.optional_header.dll_characteristics) & 0x0040)  # DYNAMIC_BASE
	note["static"] = not note["needed"]
	note["linker_version"] = "%d.%d" % (binary.optional_header.major_linker_version,
		binary.optional_header.minor_linker_version)
	rich = getattr(binary, "rich_header", None)
	if rich is not None:
		# The Rich header's id -> product table is Microsoft-internal and undocumented, so the
		# build number is what is recorded: it identifies the toolset build that produced it.
		for entry in rich.entries:
			note["rich"].append({"id": int(getattr(entry, "id", 0) or 0),
				"build": int(getattr(entry, "build_id", 0) or 0),
				"count": int(getattr(entry, "number", 0) or 0)})
	for info in getattr(binary, "debug_info", []) or []:
		if _short(info.type) == "CODEVIEW":
			note["comment"].append("codeview:%s" % getattr(info, "info", ""))
	note["link_flags"] = []


def _read_macho(binary, note: dict) -> None:
	header = binary.header
	note["arch"] = _short(getattr(header, "cputype", getattr(header, "cpu_type", "?")))
	note["bits"] = 64 if "64" in str(note["arch"]) else 32
	note["file_type"] = _short(getattr(header, "filetype", getattr(header, "file_type", "?")))
	note["entrypoint"] = int(header.entrypoint)
	note["link_flags"] = []


_COMMENT_GCC = re.compile(r"GCC[:\s]*\(([^)]*)\)\s*([0-9][0-9.]*)?|\bGCC\s+([0-9][0-9.]*)", re.I)
_COMMENT_CLANG = re.compile(r"clang version (\S+)|LLVM version ([0-9.]+)", re.I)
_COMMENT_MASM = re.compile(r"Microsoft \(R\) (?:C/C\+\+|MacroAssembler)", re.I)
_LINKER = re.compile(r"link\.exe|LLD[: ]|GNU ld|ld\.exe|Microsoft \(R\) C/C\+\+", re.I)


def _read_build_strings(note: dict) -> None:
	"""Compiler and linker identity out of `.comment`, the Rich header and the PDB record."""
	text = " ".join(note["comment"])
	if text:
		match = _COMMENT_GCC.search(text)
		if match:
			note["compiler"], note["compiler_id"] = "gcc", ((match.group(1) or "").strip() or None)
			note["compiler_version"] = match.group(2) or match.group(3)
		match = _COMMENT_CLANG.search(text)
		if match:
			note["compiler"], note["compiler_version"] = "clang", (match.group(1) or match.group(2))
		elif _COMMENT_MASM.search(text):
			note["compiler"] = "msvc"
	if note["rich"]:
		# A Rich header is written by the Microsoft linker and by nothing else.
		note["compiler"] = note["compiler"] or "msvc"
	if note["compiler"] is None:
		match = re.search(r"\b(GCC|clang|Microsoft)", text, re.I)
		if match:
			note["compiler"] = match.group(1).lower().replace("microsoft", "msvc")
	if text:
		match = _LINKER.search(text)
		if match:
			note["linker"] = match.group(0).strip()


# Standard-library names that only exist from one language level upwards. The names are the
# mangled ones, because that is what a stripped binary carries; the matched text is kept as
# the evidence for the hint.
_STD_MARKERS = [
	("c++23", r"St7format|St8expected|St10format_args"),
	("c++20", r"St7jthread|St4spanI|St7barrier|St10stop_token|St13latch"),
	("c++17", r"basic_string_view|St10filesystem|St8optional|St7variant|St17bad_optional_"
		r"access|St10shared_ptr.*pmr"),
	("c++11", r"St6thread|St5mutex|St5atomic|__cxa_thread_atexit|throw_bad_array_new_length"),
]
_CPP_ABI = re.compile(r"__cxxabiv1|__cxa_|_ZTV|_ZTI|_ZTS|__gxx_personality")


def language_evidence(note: dict) -> None:
	"""ABI, language and the lowest `-std` the imports force, from names the file carries."""
	carrier = " ".join(note["needed"]) + " " + note["dynstr"] + " " + " ".join(note["comment"])
	abi = None
	for name in note["needed"]:
		if "stdc++" in name:
			abi = "libstdc++ (Itanium C++ ABI)"
		elif name.startswith(("libc++", "c++.")):
			abi = "libc++ (Itanium C++ ABI)"
		elif name.startswith(("msvc", "vcruntime", "ucrt")):
			abi = "MSVC CRT"
	if abi is None and note["rich"]:
		abi = "MSVC CRT (the Rich header is written by the Microsoft linker)"
	if abi is None:
		match = _CPP_ABI.search(note["dynstr"])
		if match:
			abi = "C++ ABI runtime (the symbol %s)" % match.group(0)
	note["abi"] = abi
	note["language"] = "c++" if abi else None
	for std, pattern in _STD_MARKERS:
		match = re.search(pattern, carrier)
		if match:
			note["std_hints"].append({"std": std, "evidence": match.group(0)})


def note_lines(note: dict, width: int = 12) -> list[str]:
	"""The build note as lines a reader can act on."""
	if note.get("error"):
		return ["  note: %s" % note["error"]]

	def line(key, value):
		return None if value in (None, [], {}, "") else "  %-*s %s" % (width, key, value)
	built = " ".join(part for part in (note.get("compiler"), note.get("compiler_version")) if part)
	return [item for item in (
		line("file", "%s %s %s-bit" % (note.get("format"), note.get("arch"), note.get("bits"))),
		line("object", "%s%s" % (note.get("file_type"), " (PIE)" if note.get("pie") else "")),
		line("linked", "static" if note.get("static") else
			"dynamic" + (": " + ", ".join(note["needed"][:6]) if note.get("needed") else "")),
		line("built by", built),
		line("linker", note.get("linker") or ("MSVC link.exe %s" % note["linker_version"]
			if note.get("linker_version") else None)),
		line("build notes", "; ".join(note.get("build_notes", [])) or None),
		line("abi", note.get("abi")),
		line("std at least", "; ".join("%s (%s)" % (hint["std"], hint["evidence"])
			for hint in note.get("std_hints", [])) or "not determined from the imports"),
		line("hardening", ", ".join(note.get("gnu_features", [])) or None),
	) if item]


# --------------------------------------------------------------------------------------
# writing a starting project.toml


def variant_name(note: dict, optimize: int | None) -> str:
	"""A variant name in the Tests/project.toml shape: gcc-o0, clang-o2, gcc-o2-x86."""
	parts = [note.get("compiler") or "gcc", "o%d" % (0 if optimize is None else int(optimize))]
	if note.get("bits") == 32:
		parts.append("x86")
	return "-".join(parts)


def starter_config(target: Path, note: dict, guess: dict | None = None) -> str:
	"""A `project.toml` for this target, facts and guesses separated.

	Anything inferred is written as a comment next to the value it produced, so the first
	thing a reader sees is which line they have to check.
	"""
	levels = sorted({hint["std"] for hint in note.get("std_hints", [])},
		key=lambda value: int(value[3:]))
	optimize = (guess or {}).get("optimize")
	cppflags: list[str] = []
	if note.get("pie") is False and note.get("format") == "ELF" and note.get("file_type") == "EXEC":
		cppflags.append("-no-pie")
	compiler = {"gcc": "g++", "clang": "clang++", "msvc": "cl"}.get(note.get("compiler"), "g++")
	lines = [
		"# Written by `decomp detect` for %s." % target,
		"# Read from the file: %s %s, %s-bit, %s%s, built by %s." % (
			note.get("format"), note.get("arch"), note.get("bits"),
			"static" if note.get("static") else "dynamic",
			" PIE" if note.get("pie") else "", built_of(note) or "unknown"),
	]
	if note.get("abi"):
		lines.append("# Its imports say: %s." % note["abi"])
	if levels:
		lines.append("# The imports need at least -std=%s (%s)." % (levels[-1],
			", ".join(hint["evidence"] for hint in note["std_hints"][:3])))
	if guess:
		lines.append("# optimize=%s is the flag-inference helper's best match over %d sampled"
			" bodies (distance %.3f, next-best %.3f at -O%s): %s" % (
				optimize, guess.get("sampled", 0), guess.get("distance", 0.0),
				guess.get("runner_up", 0.0), guess.get("runner_up_optimize", "?"),
				guess.get("confidence", "see `decomp detect`")))
		if guess.get("sample_warning"):
			lines.append("# CHECK THIS: %s" % guess["sample_warning"])
	else:
		lines.append("# optimize=0 is a placeholder: `-O` was not inferred from this sample.")
	lines += [
		"",
		'std = "%s"' % (levels[-1] if levels else "c++17"),
		"threshold = 97.0",
		"cppflags = %r" % cppflags,
		"linkflags = %r" % list(note.get("link_flags") or []),
		"include_dirs = []",
		"",
		"[ghidra]",
		'install_dir = ""',
		'cache_dir = "cache/ghproj"',
		'language = ""',
		"",
		"[variants.%s]" % variant_name(note, optimize),
		'compiler = "%s"' % compiler,
		"optimize = %d" % (0 if optimize is None else int(optimize)),
		'arch = "%s"' % ("x86" if note.get("bits") == 32 else "x86-64"),
	]
	if note.get("compiler_version") or note.get("compiler_id"):
		lines.append("# detected: %s %s%s" % (note.get("compiler"), note.get("compiler_version") or "",
			" (%s)" % note["compiler_id"] if note.get("compiler_id") else ""))
	return "\n".join(lines) + "\n"


def built_of(note: dict) -> str:
	return " ".join(part for part in (note.get("compiler"), note.get("compiler_version")) if part)


# --------------------------------------------------------------------------------------
# flag inference: what each -O looks like here, and what the target looks like


PROBE_SOURCE = r'''
// The reference snippets for `decomp detect`. Plain, and deliberately varied: a leaf
// function, one with locals and a stack array (so a stack canary shows up or not), loops
// with known and unknown trip counts (vectorisation), a helper call (inlining), a branch
// ladder, and struct walking. Nothing external - no header, no libc - so the only thing
// that changes the shape of the code is the flags.
struct PPoint { int x; int y; };
int p_leaf(int a, int b) { return a + b; }
int p_frame(int a, int b) { int t = a * b; int u = a - b; return t + u * 2; }
int p_locals(int n) {
	int buf[8];
	for (int i = 0; i < 8; ++i) buf[i] = 0;
	for (int i = 0; i < n; ++i) buf[i & 7] = i * 3;
	int s = 0;
	for (int i = 0; i < 8; ++i) s += buf[i];
	return s;
}
int p_loop(int n) { int s = 0; for (int i = 0; i < n; ++i) s += i * i; return s; }
int p_call(int a, int b) { return p_leaf(a, b) * 2; }
float p_sum(const float* v, int n) { float s = 0.0f; for (int i = 0; i < n; ++i) s += v[i] * v[i]; return s; }
int p_branch(int x) { if (x < 0) return -x; if (x & 1) return x + 7; return x / 2; }
int p_swap(int* a, int* b) { int t = *a; *a = *b; *b = t; return t; }
int p_walk(const PPoint* p, int n) { int s = 0; for (int i = 0; i < n; ++i) s += p[i].x * 3 + p[i].y; return s; }
'''

# The shape features, all read from instruction text in AT&T form - which is what the
# analysis cache stores and what capstone prints, so the same code reads both sides.
_PUSHRBP = re.compile(r"^push(?:l|q|w)?\s+%(?:r|e)bp\b")
_FRAMESET = re.compile(r"^mov(?:l|q)\s+%(?:r|e)sp,\s*%(?:r|e)bp\b")
_ENDBR = re.compile(r"^endbr(64|32)\b")
_SUBRSP = re.compile(r"^sub(?:l|q|w)?\s+\$[0-9a-fx]+,\s*%(?:r|e)sp\b")
_CANARY = re.compile(r"%fs:|__stack_chk")
_LEAVE = re.compile(r"^leave\b")
_POPRBP = re.compile(r"^pop(?:l|q|w)?\s+%(?:r|e)bp\b")
_FRAME_MEM = re.compile(r"\(%(?:r|e)bp")
_ARG_STORE = re.compile(r"^mov[lqwb]?\s+%(?:[a-z0-9]+),\s*-?[0-9]+\(%(?:r|e)bp\)")
_XMM = re.compile(r"%(?:x|e)mm|movss|movsd|addss|mulss|cvtsi|punpck")
_CALL = re.compile(r"^call")
_RET = re.compile(r"^ret\b")

# Per-body features are shares over the sampled bodies (share of bodies, or share of
# instructions). `bodies` and `insmean` are reported but never scored: they describe the
# program, not the flags.
FEATURES = ("frame", "endbr", "subrsp", "canary", "leave", "poprbp", "spill", "framemem",
	"xmm", "calls")

# What a feature means where it is present, so the report names the reason and not just a
# distance. Only the ones that discriminate.
FEATURE_MEANING = {
	"frame": "a frame pointer is set up (push rbp; mov rbp,rsp) in this share of bodies",
	"spill": "arguments are stored to the stack at the top of the body: no register allocation",
	"framemem": "locals are read back through the frame pointer on every use",
	"leave": "leave in the epilogue (a frame is set up and torn down)",
	"poprbp": "the frame pointer is popped in the epilogue",
	"canary": "a stack canary is taken (-fstack-protector*)",
	"endbr": "endbr at the entry (-fcf-protection)",
	"xmm": "SSE/vector operations, including vectorised loops",
	"subrsp": "the stack is adjusted with sub rsp/esp",
	"calls": "calls per instruction (helpers are not inlined)",
}


def shape_profile(bodies: list[list[str]]) -> dict:
	"""Describe the shape of a set of function bodies, each a list of instruction texts."""
	counts = dict.fromkeys(FEATURES, 0)
	bodies_counted = instructions = 0
	for body in bodies:
		text = [item for item in body if item]
		if not text:
			continue
		bodies_counted += 1
		head, tail, joined = text[:6], text[-4:], "\n".join(text)
		if any(_PUSHRBP.match(item) for item in head) and any(_FRAMESET.match(item) for item in head):
			counts["frame"] += 1
		if _ENDBR.match(text[0]):
			counts["endbr"] += 1
		if any(_SUBRSP.match(item) for item in head):
			counts["subrsp"] += 1
		if _CANARY.search(joined):
			counts["canary"] += 1
		if any(_LEAVE.match(item) for item in tail):
			counts["leave"] += 1
		if any(_POPRBP.match(item) for item in tail):
			counts["poprbp"] += 1
		if any(_ARG_STORE.match(item) for item in text[:10]):
			counts["spill"] += 1
		counts["framemem"] += sum(1 for item in text if _FRAME_MEM.search(item))
		counts["xmm"] += sum(1 for item in text if _XMM.search(item))
		counts["calls"] += sum(1 for item in text if _CALL.match(item))
		instructions += len(text)
	profile = {name: counts[name] / max(1, bodies_counted) for name in
		("frame", "endbr", "subrsp", "canary", "leave", "poprbp", "spill")}
	profile.update({name: counts[name] / max(1, instructions) for name in ("framemem", "xmm", "calls")})
	profile["bodies"] = bodies_counted
	profile["insmean"] = instructions / max(1, bodies_counted)
	return profile


def profile_lines(profile: dict, width: int = 9) -> list[str]:
	return ["  %-*s %s" % (width, name, "%.3f" % profile[name]) for name in FEATURES] \
		+ ["  %-*s %d bodies, mean %.1f instructions each"
			% (width, "sample", profile.get("bodies", 0), profile.get("insmean", 0.0))]


def probe_signatures(compiler: str, bits: int, std: str = "c++17",
	levels: tuple[int, ...] = (0, 1, 2, 3), work_dir: Path | None = None) -> tuple[list[dict], list[str]]:
	"""What each `-O<n>` looks like, measured with the compiler installed here.

	The answer is toolchain-specific on purpose: whether `-O2` vectorises, whether a frame
	pointer survives, and what an epilogue looks like are properties of *this* compiler, and
	a candidate is going to be built with this compiler. Returns (signatures, problems).
	"""
	from . import normalize  # local import: capstone is only needed on this path

	problems: list[str] = []
	handle = normalize.capstone_for("x86:LE:%d:default" % bits)
	if handle is None:
		return [], ["no decoder for %d-bit x86 - flag inference supports x86 only" % bits]
	keep = work_dir is not None
	directory = Path(work_dir or tempfile.mkdtemp(prefix="decomp-probe-"))
	source = directory / "decomp_probe.cpp"
	source.write_text(PROBE_SOURCE)
	import lief

	signatures = []
	for level in levels:
		object_path = directory / ("decomp_probe_o%d%s.o" % (level, "-m32" if bits == 32 else ""))
		command = [compiler, "-std=%s" % std] + (["-m32"] if bits == 32 else []) + [
			"-O%d" % level, "-c", str(source), "-o", str(object_path)]
		try:
			finished = subprocess.run(command, capture_output=True, text=True, timeout=180)
		except (OSError, subprocess.TimeoutExpired) as exc:
			problems.append("%s -O%d: %s" % (compiler, level, exc))
			continue
		if finished.returncode != 0:
			problems.append("%s -O%d: %s" % (compiler, level,
				(finished.stderr or finished.stdout).strip().splitlines()[:1] or "the compiler failed"))
			continue
		binary = lief.parse(str(object_path))
		if binary is None:
			problems.append("could not read %s" % object_path.name)
			continue
		contents = {str(section.name): bytes(section.content)
			for section in binary.sections if section.size}
		bodies = []
		for symbol in binary.symbols:
			try:
				section = str(symbol.section.name) if symbol.section is not None else ""
				if not symbol.is_function or not symbol.size or section not in contents:
					continue
				data = contents[section][int(symbol.value):int(symbol.value) + int(symbol.size)]
			except Exception:  # noqa: BLE001 - a section-less symbol carries nothing
				continue
			bodies.append([normalize.format_instruction(item.mnemonic, item.op_str)
				for item in handle.disasm(data, int(symbol.value))])
		if not bodies:
			problems.append("%s -O%d produced no function symbols in %s" % (compiler, level,
				object_path.name))
			continue
		signatures.append({"optimize": level, "compiler": compiler, "bits": bits,
			"object": str(object_path), "profile": shape_profile(bodies)})
		if not keep:
			object_path.unlink(missing_ok=True)
	if not keep:
		source.unlink(missing_ok=True)
		try:
			directory.rmdir()
		except OSError:  # pragma: no cover - the caller asked for the objects
			pass
	return signatures, problems


# The sample both sides are measured over: bodies of this many instructions. Small enough
# that a body is one function, big enough to have a prologue and an epilogue; the same band
# is applied to the target and to the probe, so the two samples are of comparable things.
BAND = (4, 90)


def split_bodies(instructions: list[tuple[int, str]]) -> list[list[str]]:
	"""Cut a linear disassembly into bodies at every `ret`.

	Used when there is no analysis to take real boundaries from. It is an approximation and
	says so: a function ending in a tail call continues into the next one, and a `ret` inside
	a basic block splits one in two. What is being measured is the shape of the code, and the
	same cut is applied to the probe objects - where the real boundaries *are* known - only
	when the analysis is not there.
	"""
	bodies: list[list[str]] = []
	current: list[str] = []
	for _address, text in instructions:
		current.append(text)
		if text.startswith("ret"):
			bodies.append(current)
			current = []
	if current:
		bodies.append(current)
	return bodies


def target_shape(target: Path, rng: tuple[int, int] | None = None, band: tuple[int, int] = BAND,
	note: dict | None = None) -> tuple[dict, dict, list[str]]:
	"""The shape of a file's own code, with no analysis and no Ghidra.

	`rng` is a half-open range of **file** addresses (the ones nm and objdump print), which is
	how a sample is narrowed to the program proper in a statically linked target.
	Returns (profile, build note, problems).
	"""
	from . import extract, normalize

	note = note or build_note(target)
	problems: list[str] = []
	if note.get("error"):
		return {}, note, [note["error"]]
	handle = normalize.capstone_for("x86:LE:%d:default" % (note.get("bits") or 64))
	if handle is None:
		return {}, note, ["flag inference supports x86 (%d-bit) for now" % (note.get("bits") or 0)]
	try:
		import lief

		binary = lief.parse(str(target))
	except Exception as exc:  # noqa: BLE001
		return {}, note, ["could not re-read %s: %s" % (Path(target).name, exc)]
	bodies: list[list[str]] = []
	seen_sections: list[str] = []
	for section in binary.sections:
		name = str(section.name)
		if not section.size or not (name.startswith(".text") or name in ("__text", ".text.unlikely")):
			continue
		if not extract.section_capabilities(binary.format, section)[2]:
			continue
		seen_sections.append(name)
		start = int(section.virtual_address)
		data = bytes(section.content)
		stream = [(int(item.address), normalize.format_instruction(item.mnemonic, item.op_str))
			for item in handle.disasm(data, start)]
		if rng is not None:
			stream = [item for item in stream if rng[0] <= item[0] < rng[1]]
		bodies.extend(item for item in split_bodies(stream) if band[0] <= len(item) <= band[1])
	if not seen_sections:
		problems.append("%s has no executable .text section to sample" % Path(target).name)
		return {}, note, problems
	profile = shape_profile(bodies)
	if not profile["bodies"]:
		problems.append("no body of %d-%d instructions was found in %s%s - widen the sample"
			% (band[0], band[1], ", ".join(seen_sections),
				" inside the given --range" if rng else ""))
	return profile, note, problems


def infer_optimize(target: dict, signatures: list[dict]) -> list[dict]:
	"""Rank the probe signatures against the shape of the target. Best match first.

	`confidence` is part of the result, not decoration: the -O0 class separates cleanly from
	everything else on every x86 toolchain measured here, while -O1/-O2/-O3 shade into each
	same shape and are reported as a class, not a level.
	"""
	ranked = []
	for item in signatures:
		profile = item["profile"]
		ranked.append({"optimize": item["optimize"], "compiler": item.get("compiler"),
			"bits": item.get("bits"), "distance": round(sum(abs(profile[name] - target[name])
				for name in FEATURES), 3), "profile": profile})
	ranked.sort(key=lambda item: item["distance"])
	for position, item in enumerate(ranked):
		item["margin"] = round(ranked[position + 1]["distance"] - item["distance"], 3) \
			if position + 1 < len(ranked) else 0.0
	if ranked:
		best = ranked[0]
		evidence = []
		for name in FEATURES:
			here, there = target[name], best["profile"][name]
			if abs(here - there) <= 0.15 and max(here, there) >= 0.15:
				evidence.append("%s: target %d%%, this probe %d%%" % (FEATURE_MEANING[name],
					round(here * 100), round(there * 100)))
		best["why"] = "; ".join(evidence[:4]) or "no single feature dominates - the match is weak"
		if len(ranked) > 1:
			best["runner_up"] = ranked[1]["distance"]
			best["runner_up_optimize"] = ranked[1]["optimize"]
		best["confidence"] = confidence(best, target)
	return ranked


def confidence(best: dict, target: dict) -> str:
	"""How much weight the answer carries, in the tool's own words."""
	if best.get("margin", 0.0) >= 0.5:
		return "strong: the shape of this code is not produced by the other levels"
	if best.get("margin", 0.0) >= 0.15:
		return "probable: clearly closer than the next level, but the levels are adjacent"
	if best["optimize"] >= 1:
		return ("weak as a level: -O1/-O2/-O3 differ in ways a prologue does not show "
			"(inlining depth, unrolling). What is established is that this is optimised code: "
			"no frame pointer (%d%%) and no argument spilling (%d%%)") % (
				round(target.get("frame", 0.0) * 100), round(target.get("spill", 0.0) * 100))
	return "weak: the sample is too small or too mixed to rank the levels apart"


def sample_warning(profile: dict, note: dict | None = None, narrowed: bool = False) -> str:
	"""Why a single answer may not be safe for this sample, or '' when it is.

	The common case is not a mystery in the code but a fact about the file: a statically
	linked image is mostly somebody else's library code, built with somebody else's flags.
	That only needs saying when the caller has not already narrowed the sample themselves.
	"""
	warnings = []
	if note and note.get("static") and not narrowed and profile.get("bodies", 0) > 40:
		warnings.append("this image is linked static: most of the %d sampled bodies are "
			"library code built by someone else with someone else's flags, and they outvote "
			"the program itself" % profile["bodies"])
	frame = profile.get("frame", 0.0)
	if 0.15 < frame < 0.85 and profile.get("bodies", 0) >= 20:
		warnings.append("%d%% of the sampled bodies set up a frame pointer and %d%% do not, so the "
			"sample spans more than one build" % (round(frame * 100), round((1 - frame) * 100)))
	if not warnings:
		return ""
	return ("%s. Narrow the sample with --range <file addresses> (the span nm/objdump show for "
		"the program's own code) or --sample <name>, then read the answer again."
		% ". ".join(warnings))
