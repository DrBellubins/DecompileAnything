#!/usr/bin/env python3
"""Phase 7 (Docs/byte-cleanup-plan.md): build fidelity.

Two things decide whether the byte gate is reachable, and neither is `-O`: whether the compiler
installed here is the compiler that made the file, and which other flags the build used. This
suite checks that the tool says both, and that it keeps the two kinds of answer apart.

**A file names its compiler, and a mismatch is not a note to shrug at.** `.comment` (ELF) and
the Rich header (PE) are read by `decomp analyze`; the comparison is made against the compiler
the variant would actually run. A different release is a warning everywhere and takes the `exact`
tier away, because byte-identity across two releases is not something a loop can iterate to. A
file that names nothing is left alone: not knowing is not a mismatch, and nothing is capped.

**Flags are either the file's record or a shape the code shows, and the wording says which.**
`ET_DYN` with no program interpreter *is* position-independent code; `.note.gnu.property` names
CET and the x86-64-vN ISA level in the compiler's own spelling; a PE's Guard CF bit is the
linker's own statement about `/guard:cf`. A canary in some bodies says some `-fstack-protector`
level was on but not which; `%ymm` says an AVX level without naming it; a reciprocal pattern is
a lead. One function body can never say what the build's flags were, and the findings say so.

Built here, in a scratch directory, with flags known: a plain shared plugin, the same plugin with
`-mavx2 -mfma`, and one with `-fcf-protection=full -fstack-protector-all`. Then measured on real
targets: `Tests/Proprietary/Dr Up-down gate.so`, which names a GCC release this machine does not
have, and `Tests/Proprietary/notepad.exe`, which names MSVC and declares Guard CF.

Run:
  .venv/bin/python Tests/tools/check_phase7_fidelity.py            # everything
  .venv/bin/python Tests/tools/check_phase7_fidelity.py --quick     # synthetic cases only
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
REPO = TESTS.parent
sys.path.insert(0, str(REPO))

from decomp import config, diff, fidelity, toolchain  # noqa: E402

PLUGIN = '''
struct Widget { int a; double scale; virtual int probe() const; };
int plugin_run(Widget *w, int n) {
	int total = 0;
	double acc = 0.0;
	for (int i = 0; i < n; ++i) { total += w->probe() + i; acc += w->scale * i; }
	return total + (int) acc;
}
int plugin_scale(Widget *a, Widget *b, double k) {
	return (int) (a->scale * k + b->scale * k);
}
'''

FAILURES: list[str] = []
OK = 0


def ok(what: str, got, want) -> bool:
	global OK
	if got == want:
		OK += 1
		print("  ok   %s = %r" % (what, got))
		return True
	FAILURES.append("%s: got %r, want %r" % (what, got, want))
	print("  FAIL %s: got %r, want %r" % (what, got, want))
	return False


def truth(what: str, got) -> bool:
	global OK
	if got:
		OK += 1
		print("  ok   %s" % what)
		return True
	FAILURES.append("%s: got %r" % (what, got))
	print("  FAIL %s: got %r" % (what, got))
	return False


def note_(what: str, detail: str) -> None:
	print("  note %s: %s" % (what, detail))


def find(result: dict, flag: str) -> dict:
	for item in result["findings"]:
		if item["flag"] == flag:
			return item
	return {}


# --------------------------------------------------------------------------------------
# the version reading


def check_versions() -> None:
	print("\nthe file's compiler against this machine's:")
	gcc = fidelity.text_identity("GCC: (GNU) 16.1.1 20260430")
	ok("identity from a .comment", (gcc["vendor"], gcc["version"], gcc["named"]),
		("gcc", "16.1.1", True))
	rich = fidelity.text_identity("pogo:ZERO | rich:id=258:build=25835:1 | other")
	ok("identity from a Rich header", (rich["vendor"], rich["version"], rich["toolset"]),
		("msvc", "14.12", "v141 (Visual Studio 2017)"))
	ok("identity from nothing", fidelity.text_identity("")["named"], False)
	# A CodeView or POGO record names MSVC and nothing else; a release it does not name.
	cv = fidelity.text_identity("codeview:foo.pdb guid=1 age=1")
	ok("a CodeView record names the toolchain only",
		(cv["vendor"], cv["toolset"], cv["named"]), ("msvc", "", True))

	built = {"vendor": "gcc", "version": "16.1.1", "named": True, "source": "x"}
	same = fidelity.version_agreement(built, {"vendor": "gcc", "version": "16.1.1",
		"named": True, "compiler": "g++", "line": "g++ (GCC) 16.1.1"})
	ok("same release", (same["state"], same["hard"]), ("same", False))
	minor = fidelity.version_agreement(built, {"vendor": "gcc", "version": "16.2.1",
		"named": True, "compiler": "g++", "line": "g++ (GCC) 16.2.1"})
	ok("a different minor caps exact", (minor["state"], minor["hard"]), ("close", True))
	major = fidelity.version_agreement(built, {"vendor": "gcc", "version": "15.2.0",
		"named": True, "compiler": "g++"})
	ok("a different major", (major["state"], major["hard"]), ("different", True))
	other = fidelity.version_agreement(built, {"vendor": "clang", "version": "18.1.0",
		"named": True, "compiler": "clang++", "line": "clang version 18.1.0"})
	ok("another toolchain", (other["state"], other["hard"]), ("different", True))
	blind = fidelity.version_agreement({"named": False}, {"vendor": "gcc", "version": "16.1.1",
		"named": True})
	ok("the file does not name its compiler", (blind["state"], blind["hard"]), ("unknown", False))
	quiet = fidelity.version_agreement({"vendor": "gcc", "named": True, "version": ""},
		{"vendor": "gcc", "version": "16.1.1", "named": True})
	ok("the toolchain matches but no release is named", (quiet["state"], quiet["hard"]),
		("unknown", False))
	msvc = fidelity.version_agreement({"vendor": "msvc", "toolset": "v141 (Visual Studio 2017)",
		"version": "14.12", "named": True}, {"vendor": "msvc", "toolset": "", "named": False,
		"compiler": "cl", "line": "cl is not on PATH"})
	ok("an MSVC target with no cl here is not compared", msvc["state"], "unknown")

	# What the `exact` tier does with the answer: a byte-identical body still claims exact (the
	# bytes are the proof), a body whose bytes differ says what stands in the way.
	gaps = diff.tier_gaps({name: 0 for name in diff.CATEGORIES}, {}, False, "exact",
		byte_gap="the bytes are not equal",
		build_mismatch="the file says gcc 16.1.1, this is 16.2.1")
	truth("the toolchain gap is named before the byte gap",
		gaps[0].startswith("the compiler here is not the one that made this file"))
	truth("and the byte gap is still reported", any("bytes are not equal" in line for line in gaps))
	ok("no mismatch, no such line", "the compiler here" in
		" ".join(diff.tier_gaps({name: 0 for name in diff.CATEGORIES}, {}, False, "exact")), False)


# --------------------------------------------------------------------------------------
# the flags the file names


def build_plugin(directory: Path, name: str, flags: list[str]) -> Path:
	source = directory / (name + ".cpp")
	source.write_text(PLUGIN)
	out = directory / (name + ".so")
	command = ["g++", "-x", "c++", *flags, "-shared", "-fPIC", "-o", str(out), str(source)]
	if subprocess.run(command, capture_output=True, text=True, timeout=600).returncode:
		raise RuntimeError("could not build %s: %s" % (name, " ".join(command)))
	return out


def check_plugin_flags() -> None:
	print("\nflags read back out of files built with known flags:")
	with tempfile.TemporaryDirectory() as raw:
		directory = Path(raw)
		plain = build_plugin(directory, "plain", ["-O1"])
		avx = build_plugin(directory, "avx", ["-O2", "-mavx2", "-mfma"])
		hardened = build_plugin(directory, "hardened",
			["-O1", "-fcf-protection=full", "-fstack-protector-all"])
		for path, want in ((plain, "plain"), (avx, "avx"), (hardened, "hardened")):
			note = toolchain.build_note(path)
			ok("%s: read as a shared object" % want,
				(note.get("format"), note.get("file_type"), note.get("interp")),
				("ELF", "DYN", None))
			profile, _, problems = toolchain.target_shape(path, note=note)
			truth("%s: bodies sampled" % want, bool(profile.get("bodies")))
			result = fidelity.flag_findings(note, fidelity.evidence(profile=profile))
			# Position independence is the file's fact, not an inference, on every one of them.
			pic = find(result, "-fPIC")
			ok("%s: -fPIC is claimed as the file's own record" % want,
				(pic.get("state"), pic.get("certainty"), pic.get("add")),
				("on", "file", "-fPIC"))
			note_(" %s suggests" % want, " ".join(result["suggest"]) or "(nothing)")
			if want == "avx":
				ok("the ISA level the file names is read out of its property note",
					note.get("gnu_isa"), ["x86-64-baseline", "x86-64-v3"])
				truth("and used as the exact flag spelling",
					"-march=x86-64-v3" in result["suggest"])
				ok("the level is claimed as the file's record, not a shape reading",
					find(result, "-march=x86-64-v3").get("certainty"), "file")
			if want == "hardened":
				ok("CET is read out of the property note", note.get("gnu_hardening"),
					["IBT", "SHSTK"])
				ok("and named as the flag that writes it",
					[find(result, "-fcf-protection").get(key)
						for key in ("state", "certainty", "add")],
					["on", "file", "-fcf-protection=full"])
			if want == "plain":
				# No property record names a vector level and no VEX form appears: the tool says
				# to build for the baseline rather than guessing at this machine's -march.
				truth("a baseline file is told to stay on the baseline",
					any(item["flag"] == "-march=x86-64-baseline" and item["state"] == "off"
						for item in result["findings"]))
				ok("nothing vector is suggested for it",
					[flag for flag in result["suggest"] if "march" in flag or "avx" in flag], [])


def check_generated_config() -> None:
	print("\nwhat a generated project.toml carries:")
	with tempfile.TemporaryDirectory() as raw:
		directory = Path(raw)
		path = build_plugin(directory, "cfg", ["-O1", "-fcf-protection=full"])
		note = toolchain.build_note(path)
		profile, _, _ = toolchain.target_shape(path, note=note)
		found = fidelity.flag_findings(note, fidelity.evidence(profile=profile))
		text = toolchain.starter_config(path, note, {"optimize": 1, "compiler": "g++"}, found)
		truth("the provable flag is written into cppflags",
			any("cppflags" in line and "-fPIC" in line for line in text.splitlines()))
		truth("the reason is written next to it", "position-independent" in text)
		truth("a flag the file records is carried as a comment",
			"-fcf-protection=full" in text.split("cppflags")[1])
		note_("cppflags and the flag comments", " ".join(
			line for line in text.splitlines() if "cppflags" in line or line.startswith("# -")))


# --------------------------------------------------------------------------------------
# measured on the real targets


def check_targets() -> None:
	print("\nmeasured on the targets in Tests/Proprietary:")
	plugin = REPO / "Tests/Proprietary/Dr Up-down gate.so"
	if plugin.is_file():
		note = toolchain.build_note(plugin)
		built = fidelity.note_identity(note)
		truth("the plugin names the release that built it",
			(built["vendor"], built["version"]) == ("gcc", "16.1.1") or built["version"])
		installed = fidelity.installed_identity("g++")
		agreement = fidelity.version_agreement(built, installed)
		note_("this machine's g++", installed.get("line") or "not installed")
		if installed["named"]:
			truth("the mismatch is reported before any try", agreement["state"] != "same")
			truth("and it is a hard one for the exact tier", agreement["hard"])
			note_("what it says", agreement["detail"])
		result = fidelity.flag_findings(note, fidelity.evidence(profile={
			"bodies": 2805, "canary": 0.164, "endbr": 0.0}))
		truth("-fPIC is suggested for the plugin", "-fPIC" in result["suggest"])
		ok("and CET is ruled out from the file, not the sample",
			[find(result, "-fcf-protection").get(key) for key in ("state", "certainty")],
			["off", "file"])
		ok("the plugin's own ISA level is named",
			find(result, "-march=x86-64-baseline").get("certainty"), "file")
	else:
		note_("plugin", "%s is not here" % plugin)

	notepad = REPO / "Tests/Proprietary/notepad.exe"
	if notepad.is_file():
		note = toolchain.build_note(notepad)
		ok("notepad.exe declares Guard CF", note.get("guard_cf"), True)
		result = fidelity.flag_findings(note, fidelity.evidence(profile={"bodies": 40, "gs": 0.0}))
		ok("/guard:cf is read from the image, as the file's own record",
			[find(result, "/guard:cf").get(key) for key in ("state", "certainty", "add")],
			["on", "file", "/guard:cf"])
		agreement = fidelity.version_check(notepad, "g++")
		ok("a g++ variant against an MSVC-built target is a toolchain gap",
			(agreement["state"], agreement["hard"]), ("different", True))
	else:
		note_("notepad", "%s is not here" % notepad)

	# `decomp try` reads the same facts from the cached analysis, without re-reading the file.
	from decomp import cache

	try:
		targets = cache.Cache(REPO / "cache/ghproj").targets()
	except config.ConfigError as exc:
		note_("cached analyses", str(exc))
		targets = []
	for values in targets:
		name = Path(str(values.get("target_path") or "")).name
		agreement = fidelity.cached_agreement(values, "g++")
		note_(name, "%s: %s" % (agreement["state"], agreement["detail"][:150]))
	mismatches = [values for values in targets
		if fidelity.cached_agreement(values, "g++")["state"] not in ("same", "unknown")]
	truth("at least one cached target disagrees with the compiler here", bool(mismatches))

	# The command the user runs: `decomp detect` must show all of it, in JSON and as text.
	if plugin.is_file():
		from typer.testing import CliRunner

		runner = CliRunner()
		result = runner.invoke(cli_app(), ["detect", str(plugin), "--json", "--no-probe"])
		ok("decomp detect exits cleanly", result.exit_code, 0)
		payload = json.loads(result.output)
		facts = payload.get("fidelity") or {}
		truth("it carries the version agreement with the compiler here",
			[facts["versions"][0]["state"], facts["versions"][0]["hard"]] == ["close", True]
			if facts.get("versions") else False)
		truth("and the flags this file names", "-fPIC" in facts.get("suggest", []))
		truth("every flag finding says where it came from",
			bool(facts.get("flags")) and all(item["certainty"] in ("file", "shape", "hint")
				for item in facts["flags"]))
		truth("and a reading of the ISA level the file names", any(
			item["flag"].startswith("-march=x86-64") and item["certainty"] == "file"
			for item in facts.get("flags", [])))
		words = runner.invoke(cli_app(), ["detect", str(plugin), "--no-probe"])
		truth("the text report says the same",
			all(part in words.output for part in ("build fidelity",
				"[warn] the file says it was built by gcc", "+ -fPIC", "try these:")))
		for line in words.output.splitlines():
			if "warn]" in line or "+ -fPIC" in line:
				note_("detect says", line.strip()[:170])


def check_try_path() -> None:
	"""The Phase 7 facts where the loop reads them: inside a scored candidate (`decomp try`).

	Two directions are checked. A candidate scored against the benchmark, whose own `.comment`
	names the compiler installed here, must get no toolchain warning and no cap: the tool is not
	allowed to cry wolf about a build that matches. A candidate scored against the plugin, which
	names a GCC release this machine does not have, must be told the gap in the same place the
	report puts what stands in the way of `exact`, and be offered the flags that file names.
	"""
	from decomp import cache, cli

	cfg = config.load(str(TESTS / "project.toml"))
	store = cache.Cache(config.cache_dir(cfg))
	key_path = TESTS / "build" / "gcc-o0" / "answer_key.json"
	if not key_path.is_file():
		note_("try path", "%s is not built - skipped" % key_path)
		return
	answer = json.loads(key_path.read_text())
	units = answer["units"] if isinstance(answer, dict) else answer
	unit = sorted(units, key=lambda item: item["size"])[0]

	def score(target: Path, address: int) -> dict:
		values = store.status(cache.target_key(target)["key"])
		if not values.get("complete"):
				return {"error": "%s is not analysed in this cache" % target.name}
		conn = cache.open_readonly(Path(values["db"]))
		try:
			# `address` is an analysis address: the caller adds the section bias when the
			# address it holds came from a link map rather than from this cache.
			found = cache.resolve_function(conn, hex(address))
			if not found:
				return {"error": "nothing at %s in the analysis of %s" % (hex(address), target.name)}
			return cli.score_candidate(cfg, conn, dict(values), found[0],
				[TESTS / "TestBinary" / unit["file"]], fn=unit["mangled"], variant="gcc-o0",
				gate="exact", object_dir=store.root / "candidates-check")
		finally:
			conn.close()

	# The answer key gives link addresses; the cache is keyed by analysis addresses.
	benchmark = TESTS / "build" / "gcc-o0" / "da_tests.stripped"
	bmeta = store.status(cache.target_key(benchmark)["key"])
	at = int(unit["address"]) + (cache.address_offset(bmeta) if bmeta.get("complete") else 0)
	own = score(benchmark, at)
	if own.get("verdict") is None:
		note_("try path (the benchmark)", own.get("error") or "no verdict")
	else:
		ok("a build that matches the file is not questioned", own["verdict"].build_mismatch, "")
		if own["verdict"].bytes_equal_masked:
			ok("no flags are pushed at a body whose bytes already match",
				bool(own.get("flag_advice")), False)
		truth("the toolchain gap is not in its way",
			"the compiler here" not in " ".join(own["verdict"].gaps("exact")))

	plugin = REPO / "Tests/Proprietary/Dr Up-down gate.so"
	other = None
	if plugin.is_file():
		values = store.status(cache.target_key(plugin)["key"])
		if values.get("complete"):
			conn = cache.open_readonly(Path(values["db"]))
			try:
				# Any real unit of a reasonable size: what is being checked is what the tool says
				# about the build, not which function it is said about.
				cands = [row for row in cache.unit_rows(conn) if 40 <= int(row["size"] or 0) <= 200]
				other = int(cands[0]["entry"]) if cands else None
			finally:
				conn.close()
	rather = score(plugin, other) if other else {"error": "no usable unit in the plugin"}
	if rather.get("verdict") is None:
		note_("try path (the plugin)", rather.get("error") or "no verdict")
		return
	verdict = rather["verdict"]
	truth("a target built by another release is named in the score itself",
		bool(verdict.build_mismatch) and "16.1.1" in verdict.build_mismatch)
	gaps = verdict.gaps("exact")
	at = [index for index, line in enumerate(gaps)
		if line.startswith("the compiler here is not the one")]
	truth("and it is named immediately before the byte differences a loop would chase",
		len(at) == 1 and at[0] == len(gaps) - 2 and "byte" in gaps[at[0] + 1])
	truth("the candidate is offered the flags that file names",
		bool(rather.get("flag_advice")))
	truth("-fPIC among them, because the file says so",
		any("-fPIC" in line for line in rather.get("flag_advice", [])))
	for line in rather.get("flag_advice", [])[:6]:
		note_("try says", line)


def cli_app():
	from decomp.cli import app

	return app


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--quick", action="store_true", help="skip the real targets")
	args = parser.parse_args()
	if not shutil.which("g++"):
		print("g++ is not installed: the synthetic cases cannot be built")
		return 2
	check_versions()
	check_plugin_flags()
	check_generated_config()
	if not args.quick:
		check_targets()
		check_try_path()
	print("\n%d checks passed, %d failed" % (OK, len(FAILURES)))
	for failure in FAILURES:
		print("  FAIL %s" % failure)
	return 1 if FAILURES else 0


if __name__ == "__main__":
	sys.exit(main())
