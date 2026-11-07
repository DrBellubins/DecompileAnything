"""Phase 7: build fidelity (Docs/byte-cleanup-plan.md).

Two questions the `-O` inference does not answer, and both of them decide whether the byte
gate can be reached at all:

* **Is the compiler here the compiler that made this file?** (`note_identity`,
  `installed_identity`, `version_agreement`). A `.comment` section that says `GCC: (GNU)
  16.1.1` against a `g++ 16.2.1` on this machine is not a note to shrug at: a different
  compiler version regenerates different prologues, different jump tables and different
  constants, and a loop that chases those bytes is wasting its time. Reported as a warning
  everywhere, and treated as a hard failure of the `exact` tier (`decomp/diff.py`): the tier
  says "the candidate assembles to the original bytes", and that claim is not available across
  a toolchain gap - it would be an accident of this particular pair of builds.
* **Which flags beyond `-O` does the file itself name?** (`flag_findings`). Some of these are
  facts of the file and are labelled as such: `ET_DYN` with no program interpreter *is*
  position-independent code, `.note.gnu.property` names CET (IBT/SHSTK) and the x86-64-vN ISA
  level in the compiler's own spelling, a PE's Guard CF bit is the linker's own statement about
  `/guard:cf`. Some are readings of the code and are labelled as readings: a stack canary in
  most bodies says some `-fstack-protector*` level was on but not which one, `%ymm` registers say
  an AVX level without naming it, and a reciprocal pattern is a hint about `-ffast-math` and
  nothing more. Every finding says which kind it is, and the ones that are actionable are
  printed as a "try these" list rather than quietly added to a build.

Nothing here invents a flag: a finding is either the file's own record, or a shape the code
shows, and the wording names which.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import spawn
from . import toolchain

# --------------------------------------------------------------------------------------
# what the file says its compiler was


def note_identity(note: dict) -> dict:
	"""What a build note says about the compiler that produced the file.

	A COFF file's linker version is not a compiler version, and a linker version with no toolset
	table entry (a binutils `link`, an MSVC link older than the table) names no toolset either.
	Such a file may still name its toolchain - a Rich header, a CodeView record - and the reader
	below says the difference between "MSVC built this" and "this is MSVC 14.12".
	"""
	toolset = note.get("toolset") or {}
	family = str(toolset.get("family") or "")
	if "no toolset table entry" in family:
		family = ""
	version = str(note.get("compiler_version") or "")
	if not version and family and note.get("compiler") == "msvc":
		version = str(toolset.get("linker_version") or "")
	return {"vendor": note.get("compiler") or "", "version": version,
		"toolset": family if note.get("compiler") == "msvc" else "",
		"path": note.get("compiler_id") or "",
		"source": ("the file's own version record" if note.get("compiler_version")
			else ("the linker version and Rich header" if family else "")),
		"named": bool(version or family or note.get("compiler"))}


# The same identity out of the `build_notes` string `decomp analyze` recorded, so `decomp
# check` can answer the question about a cached target without re-reading a 40 MB binary.
# The cached build notes name the toolchain in whatever records survived: a `.comment`, a Rich
# header, a CodeView record, a POGO record. Each is a fact about the tools that made the file.
_RICH_LINKER = re.compile(r"rich:id=258:build=(\d+)")
_RICH_ANY = re.compile(r"rich:id=|codeview:|pogo:|\.pdb")


def text_identity(build_notes: str) -> dict:
	"""What the analysis cached about the compiler that made the target.

	`decomp check` answers the question about a cached target from this string instead of
	re-reading a 40 MB binary. Records that name only the toolchain (a Rich header, a CodeView or
	POGO record, which MSVC writes and nothing else does) are enough to say what built the file;
	they are not enough to say which release, and the wording keeps those apart.
	"""
	text = str(build_notes or "")
	identity = {"vendor": "", "version": "", "toolset": "", "path": "", "source":
		"the build notes cached with the analysis", "named": False}
	match = toolchain._COMMENT_GCC.search(text)
	if match:
		identity["vendor"], identity["version"] = "gcc", (match.group(2) or match.group(3) or "")
	if not identity["version"]:
		match = toolchain._COMMENT_CLANG.search(text)
		if match:
			identity["vendor"], identity["version"] = "clang", (match.group(1) or match.group(2)
				or "")
	linker = _RICH_LINKER.search(text)
	if linker:
		# link.exe's own record: its build number is the fourth component of its version, which is
		# how `toolchain.rich_identity` reads the toolset (Docs/MSVC-Plan.md MS-2).
		identity["vendor"] = "msvc"
		build = toolchain.msvc_build_version(linker.group(1))
		if build:
			# Spelled the same way `check.Tool.toolset()` spells it, so the two are comparable.
			identity["version"] = build
			identity["toolset"] = (toolchain.msvc_toolset(build) or {}).get("family", "")
	elif _RICH_ANY.search(text):
		identity["vendor"] = identity["vendor"] or "msvc"
	identity["named"] = bool(identity["version"] or identity["toolset"] or identity["vendor"])
	return identity


# --------------------------------------------------------------------------------------
# what this machine's compiler says it is


_GCC_BANNER = re.compile(r"\b(?:GCC|g\+\+|gcc)\b[^\d]*?(\d+\.\d+(?:\.\d+)?)", re.I)
_CLANG_BANNER = re.compile(r"clang version (\d+\.\d+(?:\.\d+)?)", re.I)


_INSTALLED: dict[str, dict] = {}


def installed_identity(compiler: str) -> dict:
	"""The compiler a variant names, as identified on this machine.

	Cached per process: `try` scores many functions, and a compiler does not change its version
	between them.

	The same banner reading `decomp check` uses for MSVC (`check.Tool`), because `cl` does not
	answer `--version` the way gcc does and `/usr/bin/link` is not Microsoft's linker.
	"""
	name = str(compiler or "g++")
	if name in _INSTALLED:
		return _INSTALLED[name]
	_INSTALLED[name] = out = _identify(name)
	return out


def _identify(name: str) -> dict:
	out = {"compiler": name, "path": "", "vendor": "", "version": "", "toolset": "",
		"line": "", "named": False}
	if toolchain.msvc(name):
		from . import check  # local: check imports toolchain

		tool = check.Tool(name)
		out["path"] = tool.path or ""
		out["vendor"] = "msvc" if tool.vendor == "msvc" else tool.vendor
		out["version"] = tool.version
		out["toolset"] = (tool.toolset() or {}).get("family", "") if tool.vendor == "msvc" else ""
		out["line"] = tool.describe()
		out["named"] = bool(out["toolset"] or out["version"])
		return out
	import shutil

	path = shutil.which(name)
	out["path"] = path or ""
	if not path:
		out["line"] = "%s is not on PATH" % name
		return out
	finished = spawn.run([path, "--version"], timeout=spawn.BANNER_TIMEOUT)
	if finished.timed_out or finished.returncode is None:
		out["line"] = "%s did not answer --version in %ds%s" % (name, spawn.BANNER_TIMEOUT,
			": " + (finished.note or finished.stderr) if (finished.note or finished.stderr) else "")
		return out
	first = ((finished.stdout or "") + (finished.stderr or "")).strip().splitlines()
	out["line"] = first[0] if first else "%s printed nothing" % path
	match = _CLANG_BANNER.search("\n".join(first))
	if match:
		out["vendor"], out["version"] = "clang", match.group(1)
	else:
		match = _GCC_BANNER.search("\n".join(first[:2]))
		if match:
			out["vendor"], out["version"] = "gcc", match.group(1)
	out["named"] = bool(out["version"])
	return out


# --------------------------------------------------------------------------------------
# compare them


def version_parts(version) -> tuple[int, ...]:
	parts = []
	for piece in str(version or "").split(".")[:3]:
		digits = re.match(r"\d+", piece)
		parts.append(int(digits.group(0)) if digits else -1)
	while parts and parts[-1] == -1:
		parts.pop()
	return tuple(parts or [-1])


def version_agreement(built: dict, installed: dict) -> dict:
	"""Do the file's compiler and this machine's compiler agree closely enough to byte-match?

	`state` is `same`, `close` (one toolchain, a different release), `different` (another
	toolchain) or `unknown` (the file does not say). Anything but `same` and `unknown` is
	`hard`: the `exact` tier is not available for it.
	"""
	out = {"state": "unknown", "hard": False, "built": built, "installed": installed,
		"detail": "", "what": ""}
	if not built.get("named"):
		out["detail"] = ("the file does not name the compiler that made it (no .comment, no Rich "
			"header): nothing can be said about the compiler here, and no tier is capped for it")
		return out
	if not installed.get("named"):
		out["detail"] = "%s: its version could not be read here" % (installed.get("line")
			or installed.get("compiler") or "the variant's compiler")
		return out
	built_vendor, machine = str(built.get("vendor") or ""), str(installed.get("vendor") or "")
	if built_vendor and machine and built_vendor != machine:
		out["state"], out["hard"] = "different", True
		out["what"] = "different toolchain"
		out["detail"] = ("the file was built by %s%s, the variant's compiler is %s: they are "
			"different code generators, so byte-identity is not on the table - pick the variant "
			"whose compiler matches the file, or expect the `semantic` tier" % (
				built_vendor, " %s" % built["version"] if built.get("version")
				else " (its release is not named)",
				installed.get("line") or machine))
		return out
	if built_vendor == "msvc" or machine == "msvc" or built.get("toolset"):
		want, have = str(built.get("toolset") or ""), str(installed.get("toolset") or "")
		if want and have:
			if want == have:
				out["state"] = "same"
				out["detail"] = ("the toolset matches: the file is %s and %s is that toolset"
					% (want, installed.get("compiler")))
			else:
				out["state"], out["hard"], out["what"] = "different", True, "toolset"
				out["detail"] = ("the file is %s and the compiler here is %s (%s): a candidate "
					"only has a chance of matching bytes with a compiler of the same era - see "
					"Docs/Setup.md §6 for installing one by version" % (
						want, installed.get("line"), installed.get("toolset")))
		else:
			out["detail"] = ("the file says %s and %s answered %s: one of the two is not named "
				"exactly, so no comparison is made" % (
					want or built.get("version") or "an MSVC toolchain",
					installed.get("compiler"), have or "no toolset"))
		return out
	if not built.get("version") or not installed.get("version"):
		out["detail"] = ("the toolchain matches (%s), but %s does not name its release: nothing is "
			"claimed about versions here, and no tier is capped for it" % (built_vendor or machine,
				"the file" if not built.get("version") else "this machine's compiler"))
		return out
	want, have = version_parts(built.get("version")), version_parts(installed.get("version"))
	if want == have:
		out["state"] = "same"
		out["detail"] = ("%s %s built this file and %s is the compiler here: versions agree, so a "
			"byte-level match is reachable" % (built_vendor or machine, built.get("version"),
				installed.get("compiler") or installed.get("line")))
		return out
	if want[:1] == have[:1] and want[0] > 0:
		out["state"], out["hard"], out["what"] = "close", True, "compiler release"
	else:
		out["state"], out["hard"], out["what"] = "different", True, "compiler release"
	out["detail"] = ("the file says it was built by %s %s (%s); the compiler here is %s. %s: a "
		"different release regenerates different prologues, constants and jump tables, so the "
		"`exact` tier is not claimed here - expect to stop at `semantic` on functions whose "
		"bytes depend on the release, and install the one the file names if the bytes matter"
		% (built.get("vendor") or machine, built.get("version"), built.get("source"),
			installed.get("line") or installed.get("version"),
			"Same major version, a different minor" if out["what"] == "compiler release"
			and want[:1] == have[:1] else "A different major version"))
	return out


def version_check(target: Path, compiler: str) -> dict:
	"""The build note of a file against the compiler a variant would use here."""
	return version_agreement(note_identity(toolchain.build_note(target)),
		installed_identity(compiler))


def cached_agreement(meta: dict, compiler: str) -> dict:
	"""The same reading for a cached analysis (`decomp try`, `decomp check`).

	`decomp analyze` recorded the file's build notes, so the comparison does not need the binary.
	Only when those notes name nothing (a fully stripped target) is the file re-read, which is the
	case where the answer is worth a second parse.
	"""
	built = text_identity(meta.get("build_notes") or "")
	path = Path(str(meta.get("target_path") or ""))
	if not built["named"] and path.is_file():
		found = note_identity(toolchain.build_note(path))
		if found["named"]:
			built = found
			built["source"] = built["source"] or "the file itself, re-read"
	return version_agreement(built, installed_identity(compiler))


# --------------------------------------------------------------------------------------
# what the file says about flags beyond -O


def evidence(profile: dict | None = None, texts: list[str] | None = None) -> dict:
	"""The shares a set of findings is allowed to cite.

	`profile` is a whole-sample shape (`toolchain.shape_profile`); `texts` is one function body,
	which is what `try` has. One body can say "this function reads a stack canary", and it cannot
	say "this build had -fstack-protector on", so `single` is carried through and the wording of
	every finding follows it.
	"""
	from . import toolchain as _t

	names = ("canary", "endbr", "vex", "ymm", "zmm", "fma", "rcp", "gs")
	if profile:
		out = {name: float(profile.get(name, 0.0)) for name in names}
		out["bodies"] = int(profile.get("bodies", 0))
		out["single"] = False
		return out
	out = dict.fromkeys(names, 0.0)
	body = [item for item in (texts or []) if item]
	out["bodies"] = 1 if body else 0
	out["single"] = True
	if not body:
		return out
	joined = "\n".join(body)
	if _t._CANARY.search(joined):
		out["canary"] = 1.0
	if any(_t._ENDBR.match(item) for item in body):
		out["endbr"] = 1.0
	if any(_t._GS_XOR.search(item) or _t._GS_CALL.search(item) for item in body):
		out["gs"] = 1.0
	for name in ("vex", "ymm", "zmm", "fma", "rcp"):
		pattern = getattr(_t, "_" + name.upper())
		out[name] = 1.0 if any(pattern.search(item) for item in body) else 0.0
	return out


# How sure a finding is, and what that costs the caller. `file` means the file carries a record
# of it; `shape` means the code shows it; `hint` means it is a lead, not a claim.
CERTAINTY = ("file", "shape", "hint")


def _finding(out: dict, flag: str, state: str, certainty: str, why: str, add: str = "") -> None:
	out["findings"].append({"flag": flag, "state": state, "certainty": certainty, "why": why,
		"add": add or (flag if state == "on" else "")})
	if state == "on" and add:
		out["suggest"].append(add)
	if state != "unknown" and certainty in ("file", "shape"):
		out["config_comments"].append("%s: %s" % (add or flag, why))


def flag_findings(note: dict, ev: dict | None = None, profile: dict | None = None) -> dict:
	"""What this file says about the flags that are not `-O`.

	Returns `{"findings": [...], "suggest": [flags to add], "config_comments": [...],
	"lines": [...]}`. `suggest` is a *try these* list: it is what a variant's `cppflags` would
	need, printed for a human or a loop to act on - except for `-fPIC` of a shared object, which
	is the file's own fact and goes into a generated config directly (`toolchain.starter_config`).
	"""
	ev = ev if ev is not None else evidence(profile)
	is_msvc = toolchain.msvc(note.get("compiler")) or note.get("format") == "PE"
	out: dict = {"findings": [], "suggest": [], "config_comments": [], "lines": [],
		"msvc": is_msvc, "bodies": ev["bodies"]}
	relocs = note.get("reloc_kinds") or {}
	got_relocs = sum(count for kind, count in relocs.items() if "GOT" in kind or "GLOB_DAT" in kind
		or "JUMP_SLOT" in kind)
	single = ev.get("single")

	# --- position independence -------------------------------------------------------
	if not is_msvc and note.get("format") == "ELF":
		if toolchain.shared_object(note):
			_finding(out, "-fPIC", "on", "file",
				"this is a shared object: ET_DYN with no program interpreter is position-independent "
				"code by definition%s - a candidate built without it cannot match these bytes"
				% (", and its relocation table has %d GOT/PLT slot(s) in it" % got_relocs
					if got_relocs else ""), add="-fPIC")
		elif note.get("pie"):
			_finding(out, "-fPIC", "on", "file",
				"this is a PIE executable (ET_DYN *with* a program interpreter%s): its code is "
				"position-independent, so the candidate must not be built -fno-pic. The flag that "
				"produced it is -fPIE; the code it generates is the same as -fPIC and the link "
				"differs, which is why either one compiles the same bytes"
				% (", reached through %d GOT/PLT slot(s)" % got_relocs if got_relocs else ""),
				add="-fPIE")
		elif note.get("file_type") == "EXEC":
			_finding(out, "-fPIC", "off", "file",
				"the file is ET_EXEC with no interpreter%s: its code is not position-independent, "
				"so a candidate wants -fno-pie -fno-pic and -fPIC would break the match"
				% ("" if not got_relocs else " (and still reaches %d GOT slot(s): the link is "
					"non-PIE while some objects were compiled PIC)" % got_relocs))
	# --- control-flow protection / CET --------------------------------------------------
	hardening = [str(item).upper() for item in (note.get("gnu_hardening") or [])]
	if not is_msvc and note.get("format") == "ELF":
		if "IBT" in hardening or "SHSTK" in hardening:
			level = "full" if ("IBT" in hardening and "SHSTK" in hardening) else "branch"
			_finding(out, "-fcf-protection", "on", "file",
				"the file's own `.note.gnu.property` declares %s, which is what "
				"-fcf-protection=%s writes; endbr appears in %d%% of the sampled bodies"
				% (", ".join(hardening), level, round(ev["endbr"] * 100)),
				add="-fcf-protection=%s" % level)
		elif ev["endbr"] >= (0.5 if not single else 1.0):
			_finding(out, "-fcf-protection", "on", "shape",
				"endbr appears at the entry of %d%% of the sampled bodies but the file carries no CET "
				"property record, which is what an older toolchain with -fcf-protection looks like"
				% round(ev["endbr"] * 100), add="-fcf-protection=full")
		elif note.get("gnu_property"):
			# The record is written by a toolchain that knows about these features; one it does not
			# list was not asked for. That is the file talking, whatever the sample shows.
			_finding(out, "-fcf-protection", "off", "file",
				"the file's own `.note.gnu.property` is present and lists no CET feature%s: this "
				"build has -fcf-protection off"
				% ("" if not ev["endbr"] else ", and no sampled body begins with endbr"))
		elif ev["endbr"] == 0.0 and not single:
			_finding(out, "-fcf-protection", "off", "shape",
				"no sampled body begins with endbr (%d bodies) and the file carries no property record "
				"naming CET: this build has -fcf-protection off" % ev["bodies"])
	if is_msvc:
		if note.get("guard_cf") is True:
			_finding(out, "/guard:cf", "on", "file",
				"the image declares Guard CF in its optional header, which `link` only writes for "
				"/guard:cf; the guard-check call shape appears in %d%% of the sampled bodies"
				% round(ev["gs"] * 100), add="/guard:cf")
		elif note.get("guard_cf") is False and int(note.get("bits") or 64) == 64:
			_finding(out, "/guard:cf", "off", "file",
				"the image does not declare Guard CF: this build was linked with /guard:cf off, and "
				"a candidate that has it on carries an extra guard check in every body")
		elif is_msvc:
			_finding(out, "/guard:cf", "unknown", "shape",
				"/guard:cf is x64-only: nothing is claimed about it for a 32-bit image")
	# --- stack protection --------------------------------------------------------------
	if ev["canary"] >= 0.95 and not single:
		_finding(out, "-fstack-protector", "on", "shape",
			"every one of the %d sampled bodies reads a stack canary: that is "
			"-fstack-protector-all, which is the only level that guards every function"
			% ev["bodies"], add="-fstack-protector-all")
	elif ev["canary"] > 0.0:
		_finding(out, "-fstack-protector", "on", "shape",
			("this body reads a stack canary: the build has some -fstack-protector level on, and "
				"one body cannot say which" if single else
				"%d%% of the sampled bodies read a stack canary: some -fstack-protector level is "
				"on. Which level is not separable from the code (-strong guards functions with "
				"arrays and address-of locals, -all guards every function), so try -strong first"
				% round(ev["canary"] * 100)),
			add="-fstack-protector-all" if ev["canary"] >= 0.95 else "-fstack-protector-strong")
	elif not single and ev["bodies"] >= 10:
		_finding(out, "-fstack-protector", "off", "shape",
			"none of the %d sampled bodies reads a canary: this build has -fstack-protector off, "
			"or is a build of functions none of that flag protects" % ev["bodies"])
	# --- instruction set ---------------------------------------------------------------
	levels = [str(item) for item in (note.get("gnu_isa") or [])]
	used = [str(item).upper() for item in (note.get("gnu_features") or [])]
	exact = next((item for item in reversed(levels) if item.startswith("x86-64-v")), "")
	if not is_msvc and exact:
		# The ISA level the file's own record names, in GCC's own spelling. This is the strongest
		# evidence there is for a vector flag, and it is a fact rather than a reading.
		_finding(out, "-march=%s" % exact, "on", "file",
			"the file's own `.note.gnu.property` names the ISA level %s%s, which is the compiler's "
			"spelling of the level it was built for. A candidate built for the baseline cannot match "
			"code this level vectorised" % (exact,
				" (features used: %s)" % ", ".join(used) if used else ""),
			add="-march=%s" % exact)
	elif ev["zmm"] > 0.0:
		_finding(out, "-mavx512f", "on", "shape",
			"%d%% of the sampled bodies use 512-bit %%zmm registers or %%k mask registers%s"
			% (round(ev["zmm"] * (100 if not single else 1)),
				"" if not single else " (this one body)"),
			add="/arch:AVX512" if is_msvc else "-mavx512f")
	elif ev["ymm"] > 0.0:
		_finding(out, "/arch:AVX2" if is_msvc else "-mavx2", "on", "shape",
			"%d%% of the sampled bodies use 256-bit %%ymm registers%s: an AVX level is on. Which "
			"one is not separable from the registers alone -mavx, -mavx2 and -march=native all "
			"produce them - and the file's own ISA property record, when it carries one, names it "
			"exactly%s"
			% (round(ev["ymm"] * (100 if not single else 1)), "" if not single else " (this one "
				"body)", ", see the isa used line" if levels else ""),
			add="/arch:AVX2" if is_msvc else "-mavx2")
	elif ev["vex"] > 0.0:
		_finding(out, "-mavx", "on", "shape",
			"%d%% of the instructions are VEX-encoded forms%s while no wider register appears: the "
			"build has -mavx (or higher) on and the codegen stayed at 128-bit"
			% (round(ev["vex"] * 100), "" if not single else " (in this body)"),
			add="/arch:AVX" if is_msvc else "-mavx")
	elif "x86-64-baseline" in levels and not single:
		_finding(out, "-march=x86-64-baseline", "off", "file",
			"the file's property record names x86-64-baseline as its highest ISA level and no VEX "
			"form appears in the sample: build the candidate for the baseline. Note this machine's "
			"default may be a higher level, which would not match")
	if ev["fma"] > 0.0:
		_finding(out, "-mfma", "on", "shape",
			"%d%% of the instructions are fused multiply-add forms%s. -mfma is how gcc is asked for "
			"them; -march=%s already includes them, and an intrinsic written in the source is the "
			"other way they appear"
			% (round(ev["fma"] * 100), "" if not single else " (in this body)", exact or "x86-64-v3"),
			add="-mfma")
	if ev["rcp"] > 0.0:
		_finding(out, "-ffast-math", "unknown", "hint",
			"%d%% of the instructions are reciprocal or rsqrt approximations%s. That is what "
			"-ffast-math leaves behind, but it is also what hand-written intrinsics leave, and no "
			"flag is claimed from it: try it if the bytes at those lines do not match"
			% (round(ev["rcp"] * 100), "" if not single else " (in this body)"), add="-ffast-math"
			if not is_msvc else "/fp:fast")
	elif is_msvc:
		_finding(out, "/fp:", "unknown", "hint",
			"no reciprocal approximation or FMA pattern appears in the sample, which is consistent "
			"with /fp:precise: nothing is claimed, as /fp only shows up in what the codegen chose "
			"to emit")
	return out


def default_compiler(note: dict) -> str:
	"""The compiler a variant for this file would use here, by the vendor the file names."""
	return {"gcc": "g++", "clang": "clang++", "msvc": "cl"}.get(str(note.get("compiler")), "g++")


def for_target(note: dict, profile: dict | None = None,
		compilers: list[str] | None = None) -> dict:
	"""Everything Phase 7 reports about one file: the flags it names, and whether the compilers
	a variant would use here are the compiler that made it."""
	return {"flags": flag_findings(note, evidence(profile=profile)),
		"versions": [version_agreement(note_identity(note), installed_identity(compiler))
			for compiler in (compilers or [default_compiler(note)])]}


def detect_lines(result: dict) -> list[str]:
	"""The `decomp detect` section: the version reading first, then the flags."""
	lines = []
	for agreement in result["versions"]:
		mark = {"same": "ok", "close": "warn", "different": "warn"}.get(agreement["state"], "n/a")
		lines.append("[%s] %s" % (mark, agreement["detail"]))
	lines.append("the flags this file names (beyond -O):")
	lines.extend(finding_lines(result["flags"]))
	return lines


def finding_lines(result: dict) -> list[str]:
	"""The findings, in the order a reader acts on them: what to add, then what is ruled out."""
	lines = []
	for item in result["findings"]:
		mark = {"on": "+", "off": "-", "unknown": "?"}[item["state"]]
		lines.append("  %s %-22s %s" % (mark, item["flag"], item["why"]))
	if result["suggest"]:
		seen: list[str] = []
		for flag in result["suggest"]:
			if flag not in seen:
				seen.append(flag)
		lines.append("  try these: %s" % " ".join(seen))
	if not result["findings"]:
		lines.append("  the file names no flag beyond -O: nothing is claimed here")
	return lines
