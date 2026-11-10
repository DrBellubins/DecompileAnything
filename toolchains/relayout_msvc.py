#!/usr/bin/env python3
"""Lay an extracted pre-manifest MSVC tree out the way the manifest route lays its trees out.

Why this exists. A toolset fetched through the VS installer channel lands in
`VC/Tools/MSVC/<version>/{bin/Host<host>/<arch>,lib/<arch>,include}` and
`Windows Kits/10/{Include,Lib}/<sdk>` - the shape `toolchains/msvc-wine/install.sh` writes, the
shape `decomp check` (`decomp/check.py:msvc_target_arches`) probes, and the shape
`decomp.toolchain.msvc_wrapper` expects for `<prefix>/bin/<arch>/cl`. A toolset taken out of an
MSI by hand instead lands the way its own era laid it on disk, and for VS2015 (v140) that is:

	VC/bin/amd64		x64-host, x64-target cl/c1/c2/link/lib/ml + the C1/RTE DLLs
	VC/bin/amd64_x86	x64-host, x86-target cross tools (only if that arch was fetched)
	VC/include		CRT + STL headers
	VC/lib/amd64		libcmt / libvcruntime / libcpmt and friends
	VC/lib/onecore/amd64	oldnames.lib, msvcrt.lib, legacy_stdio_definitions.lib - the
				`CRT.x64.OneCore.Desktop` payload, which the desktop payload lacks

Nothing in that tree is wrong; it is only spelled the older way, so `decomp check` answers "no
Windows Kits/10 under …" and `decomp try` finds no driver. This script adds the manifest-era
*spelling* on top of the extracted tree - symlinks, no moves, no copies of the toolset - and writes
the msvc-wine wrapper set for the prefix. No tool code changes.

What it writes (for `--prefix toolchains/msvc-14.0`):

	VC/tools/msvc/<toolset>/bin/Hostx64/x64	-> ../../../bin/amd64
	VC/tools/msvc/<toolset>/bin/Hostx64/x86	-> ../../../bin/amd64_x86	(if present)
	VC/tools/msvc/<toolset>/include		-> ../../../../include
	VC/tools/msvc/<toolset>/lib/<arch>		-> ../../../lib/<dir>
	VC/tools/msvc/<toolset>/lib/onecore/<arch>	-> ../../../lib/onecore/<dir>
	Windows Kits/10				-> the shared SDK under --sdk-prefix
	kits						-> Windows Kits
	bin/<arch>/{cl,link,lib,dumpbin,…}		(the upstream wrappers, from --wrapper-prefix)
	bin/<arch>/msvcenv.sh			(generated; see write_msvcenv)

It is idempotent: a link that is already right is reported `ok`, one that points elsewhere is
left alone unless `--force`, and `--dry-run` shows the whole plan first.

The toolset version is derived, and the derivation is printed: the *family* comes from the
`Microsoft.VC140.*` redist directory names (`VC140` -> toolset `14.00`), the *build* from the file
version of `VC/bin/<hostdir>/cl.exe`. Pass `--toolset-version` to state it instead.

Usage:
  .venv/bin/python toolchains/relayout_msvc.py --prefix toolchains/msvc-14.0 --dry-run
  .venv/bin/python toolchains/relayout_msvc.py --prefix toolchains/msvc-14.0
  .venv/bin/decomp check -C Tests/Proprietary/Synplant-reverse/project.toml	# then verify
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (the VC/bin directory, its manifest-era host directory, its target arch, the arch name `decomp`
# and msvc-wine use). The directory *is* the calling convention of this era: host first, then
# target, and a bare `amd64` means "the host's own bitness" (Docs/Setup.md §6.2, §6.4).
LAYOUT = [
	("amd64", "Hostx64", "x64", "x64"),
	("amd64_x86", "Hostx64", "x86", "x86"),
	("x86_amd64", "Hostx86", "x64", "x64"),
	("x86", "Hostx86", "x86", "x86"),
]
# Same mapping for VC/lib: `VC/lib/amd64` is the x64-target CRT.
LIB_DIRS = {"x64": "amd64", "x86": "x86"}

# The wrappers a `decomp` run may reach for. `cl` is the driver `decomp.toolchain.msvc_wrapper`
# asks for; the others are what a candidate link and an inspection use. Only the ones the toolset
# actually ships are written.
WRAPPERS = ("cl", "link", "lib", "dumpbin", "ml64", "nmake", "cvtres", "editbin", "cmd", "findstr")
PLUMBING = ("wine-msvc.sh", "msvctricks.exe")

# Libraries only the OneCore desktop payload ships, which cl auto-links anyway. The v141 fetch has
# the same gap and `install_msvc.py:fill_missing_libs` fills it; here both lib directories simply
# go on LIB, which is what a real VS2015 developer command prompt does.
ONECORE_ONLY = ("oldnames.lib", "msvcrt.lib", "legacy_stdio_definitions.lib")

# The Windows SDK of an extracted tree is case-exact on Linux (`Include`, `Lib`), while the
# generated environment uses it case-insensitively through Wine. Keep one spelling: the real one.
SDK_CASE = {"include": "Include", "lib": "Lib"}


def file_version(path: Path) -> str:
	"""The FileVersion of a PE as `major.minor.build.patch`, or "" if it has no version resource.

	Read out of the VS_VERSIONINFO fixed block (signature `0xFEEF04BD`) instead of trusted from a
	directory name. lief is already a dependency of the package; its resource-tree API differs
	between releases (`childs` in 1.0, `id` an attribute rather than a method), so this walks
	defensively and answers "" for any shape it does not understand instead of raising.
	"""
	try:
		import lief  # type: ignore
		image = lief.parse(str(path))

		def attr(node, name, default=None):
			value = getattr(node, name, default)
			return value() if callable(value) else value

		def walk(node):
			for child in node.childs:
				yield child
				yield from walk(child)

		for node in walk(image.resources):
			if attr(node, "id") != 16:			# RT_VERSION
				continue
			for leaf in walk(node):
				if not attr(leaf, "is_data"):
					continue
				data = bytes(leaf.content)
				signature = data.find(struct.pack("<I", 0xFEEF04BD))
				if signature < 0:
					continue
				file_ms, file_ls = struct.unpack_from("<II", data, signature + 8)
				return "%d.%d.%d.%d" % (file_ms >> 16, file_ms & 0xFFFF, file_ls >> 16, file_ls & 0xFFFF)
	except Exception as exc:					# any unexpected lief shape: say so, do not crash
		print("  (reading %s: %s)" % (path.name, exc), file=sys.stderr)
	return ""


def derive_toolset(prefix: Path, log: list) -> "str | None":
	"""Name the toolset directory from the binaries: `link.exe` 14.0.24247.2 -> `14.00.24247`.

	A toolset directory is named for the toolset, and every tool in it carries the linker's version
	(here `cl.exe` says 19.00.24247.2 while `link.exe`/`lib.exe`/`ml64.exe` say 14.00.24247.2),
	which is also the package version the fetch recorded in `toolchains/media/vc140/README.md`. A
	manifest install names the directory after its *package* id, which can sit a servicing build
	behind the files it installed - the v141 tree on this machine is `14.12.25827` while its
	link.exe is 14.12.25835. Nothing reads that number except this script and the wrapper it writes,
	so the measured value is used and the derivation printed. Pass `--toolset-version` to match a
	package id you know. The `Microsoft.VC140.*` redist names are kept as a cross-check only.
	"""
	family = None
	for redist in sorted((prefix / "VC" / "redist").glob("*/x64/Microsoft.VC*")):
		match = re.match(r"^Microsoft\.VC(\d{3})", redist.name)
		if match:
			family = "%s.%s" % (match.group(1)[:2], match.group(1)[2:])
			log.append("redist package %s says toolset family %s" % (redist.name, family))
			break
	for directory, _, _, _ in LAYOUT:
		tools = prefix / "VC" / "bin" / directory
		if not (tools / "cl.exe").is_file():
			continue
		compiler = file_version(tools / "cl.exe")
		linker = file_version(tools / "link.exe")
		match = re.match(r"^(\d+)\.(\d+)\.(\d+)", linker or "")
		if not match:
			log.append("%s/link.exe: no readable version (%r) - pass --toolset-version" % (tools, linker))
			return None
		toolset = "%s.%02d.%s" % (match.group(1), int(match.group(2)), match.group(3))
		log.append("cl.exe %s, link.exe %s -> toolset directory %s" % (compiler or "?", linker, toolset))
		if family and not linker.startswith(family):
			log.append("WARNING: link.exe says %s, the redist packages say %s" % (linker, family))
		return toolset
	log.append("no cl.exe under VC/bin")
	return None


def link(log: list, do: bool, force: bool, target: Path, dest: Path, planned=()) -> None:
	"""Point `dest` at `target` with a relative symlink; never overwrite a real file.

	`planned` are the links this run has already decided to make, which do not exist yet in a dry
	run - a chain like `kits -> Windows Kits -> <the shared SDK>` still has to be printable.
	"""
	if not target.exists() and target not in planned:
		return
	want = os.path.relpath(target, dest.parent)
	if dest.is_symlink():
		if os.path.realpath(dest) == os.path.realpath(target):
			log.append("ok   %s -> %s" % (dest.relative_to(dest.parent.parent), os.readlink(dest)))
			return
		if not force:
			log.append("left alone %s: -> %s, but this run wants -> %s (--force to replace)"
				% (dest, os.readlink(dest), want))
			return
		dest.unlink()
	elif dest.exists():
		log.append("REFUSING %s: a real %s is in the way" % (dest, "directory" if dest.is_dir() else "file"))
		return
	if not do:
		log.append("would link %s -> %s" % (dest, want))
		return
	dest.parent.mkdir(parents=True, exist_ok=True)
	dest.symlink_to(want)
	log.append("link %s -> %s" % (dest, want))


def supply_host_runtime(log: list, do: bool, prefix: Path, vcbin: str) -> None:
	"""Put the VC runtime DLLs the *compiler itself* needs next to the host tools.

	`cl.exe`/`c1.dll`/`c2.dll`/`link.exe` are built against vcruntime140.dll/msvcp140.dll, and
	msvc-wine's environment asks Wine for the Windows build of them
	(`WINEDLLOVERRIDES="vcruntime140=n,..."`). A real VS2015 install has those DLLs in
	`VC/bin/amd64`; this payload set does not - they only ship in the CRT *redist* package - so
	without this step `cl` dies with Wine status 53 and no message at all. Copies, not links: they
	are loaded by the host tools, and one more symlink next to a directory of real DLLs adds
	nothing.
	"""
	target = prefix / "VC" / "bin" / vcbin
	for name in ("vcruntime140.dll", "msvcp140.dll", "vccorlib140.dll"):
		if (target / name).is_file():
			continue
		found = sorted((prefix / "VC" / "redist").glob("*/x64/Microsoft.VC*.CRT/" + name))
		if not found:
			log.append("%s is not in this payload set and not under VC/redist - the host tools may "
				"not start (see the docstring)" % name)
			continue
		if not do:
			log.append("would copy %s -> %s/%s" % (found[0].relative_to(prefix), target.relative_to(prefix), name))
			continue
		shutil.copy2(found[0], target / name)
		log.append("copy %s -> %s (the compiler's own runtime)"
			% (found[0].relative_to(prefix), target.relative_to(prefix)))


def make_executable(log: list, do: bool, root: Path) -> None:
	"""`msiextract` writes .exe files 0644 and Wine cannot exec one (Docs/Setup.md §6.3)."""
	fixed = [p for p in sorted(root.rglob("*.exe"))
		if p.is_file() and not p.is_symlink() and not (p.stat().st_mode & 0o111)]
	if not fixed:
		return
	if do:
		for p in fixed:
			p.chmod(p.stat().st_mode | 0o755)
	log.append("%s %d .exe files under %s" % ("chmod +x" if do else "would chmod +x", len(fixed), root))


MSVCENV = '''#!/usr/bin/env bash
# Written by toolchains/relayout_msvc.py for the %(toolset)s toolset at this prefix.
# The same shape as the upstream msvc-wine msvcenv.sh (which see for what each variable is for),
# with three era facts changed: this payload has no atlmfc, its desktop and OneCore CRT libraries
# live in two directories, and WINEPREFIX is found by walking up to the repository's .wine.
SDK=kits\\\\10
SDK_UNIX=kits/10
BASE_UNIX=$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)
BASE=z:${BASE_UNIX//\\//\\\\}
MSVCVER=%(toolset)s
SDKVER=%(sdk)s
ARCH=%(arch)s
MSVCBASE="$BASE\\\\VC"
SDKBASE="$BASE\\\\$SDK"
MSVCDIR="$MSVCBASE\\\\tools\\\\msvc\\\\$MSVCVER"
SDKINCLUDE="$SDKBASE\\\\%(include)s\\\\$SDKVER"
SDKLIB="$SDKBASE\\\\%(lib)s\\\\$SDKVER"
BINDIR=$BASE_UNIX/VC/tools/msvc/$MSVCVER/bin/%(hostdir)s/$ARCH
SDKBINDIR=$BASE_UNIX/$SDK_UNIX/bin/$SDKVER/x64
# No atlmfc entry: that payload was never fetched here, and naming it would claim an MFC install
# this prefix does not have (Docs/Setup.md §6.4).
export INCLUDE="$MSVCDIR\\\\include;$SDKINCLUDE\\\\shared;$SDKINCLUDE\\\\ucrt;$SDKINCLUDE\\\\um;$SDKINCLUDE\\\\winrt;$SDKINCLUDE\\\\km"
export LIB="$MSVCDIR\\\\lib\\\\$ARCH;$SDKLIB\\\\ucrt\\\\$ARCH;$SDKLIB\\\\um\\\\$ARCH;$SDKLIB\\\\km\\\\$ARCH%(extra_lib)s"
export LIBPATH="$LIB"
# The host bin directory is on PATH for c1.dll/c2.dll/mspdb*.dll, which cl and link load as DLLs.
export WINEPATH="${BINDIR//\\//\\\\};${SDKBINDIR//\\//\\\\};$MSVCDIR\\\\bin\\\\%(hostdir)s\\\\$ARCH"
export WINEDLLOVERRIDES="vcruntime140=n,vcruntime140_1=n"
# The repository's shared Wine prefix, not ~/.wine: walking up finds it wherever this prefix sits
# (decomp/spawn.py uses the same one; a fresh prefix costs 165 MB and a stall).
_wine=$(cd "$BASE_UNIX" && pwd)
while [ "$_wine" != "/" ]; do
    if [ -d "$_wine/.wine" ]; then export WINEPREFIX="$_wine/.wine"; break; fi
    _wine=$(cd "$_wine/.." && pwd)
done
unset _wine
export WINEDEBUG=-all
'''


def real_case(parent: Path, guess: str) -> str:
	"""The spelling `parent` actually uses for `guess`. Linux is case-exact, Wine is not, and the
	generated environment has to name the directory that exists (Docs/Setup.md §6.6 casing trap)."""
	for entry in sorted(parent.iterdir()):
		if entry.name.lower() == guess.lower() and entry.is_dir():
			return entry.name
	return guess


def write_msvcenv(log: list, do: bool, prefix: Path, toolset: str, sdk: Path, arch: str,
	hostdir: str) -> None:
	"""`bin/<arch>/msvcenv.sh`, the environment the wrappers source."""
	# The SDK's version directories live under Include/ (and Lib/), not at the SDK root - the same
	# probe decomp/check.py:msvc_target_arches makes.
	inc = sdk / real_case(sdk, "Include")
	lib = sdk / real_case(sdk, "Lib")
	version = next((p.name for p in sorted(inc.iterdir()) if p.name.startswith("10.")), None) \
		if inc.is_dir() else None
	if version is None or not (lib / version).is_dir():
		log.append("no Include/10.* + Lib/10.* pair under %s - the SDK payload is not extracted" % sdk)
		return
	body = MSVCENV % {"toolset": toolset, "sdk": version, "arch": arch,
		"hostdir": hostdir,
		"include": inc.name, "lib": lib.name,
		"extra_lib": ";z:%s" % str(prefix / "VC" / "lib" / "onecore" / LIB_DIRS[arch]).replace("/", "\\")
			if (prefix / "VC" / "lib" / "onecore" / LIB_DIRS[arch]).is_dir() else ""}
	path = prefix / "bin" / arch / "msvcenv.sh"
	if path.exists():
		if path.read_text() == body:
			log.append("ok   %s" % path)
			return
		log.append("%s %s (MSVCVER=%s SDKVER=%s)"
			% ("would rewrite" if not do else "rewrote", path, toolset, version))
	if not do:
		return
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(body)
	path.chmod(0o755)
	log.append("write %s (MSVCVER=%s SDKVER=%s)" % (path, toolset, version))


def write_wrappers(log: list, do: bool, prefix: Path, template: Path, arch: str) -> None:
	"""Copy the upstream msvc-wine wrappers for the tools this toolset actually ships."""
	bindir = prefix / "bin" / arch
	# The tools this toolset ships, read out of the directories that were extracted (rglob does not
	# walk the symlinks this script has just made).
	have = set()
	for directory, _, _, _ in LAYOUT:
		source = prefix / "VC" / "bin" / directory
		if source.is_dir():
			have |= {p.name[:-4] for p in source.glob("*.exe")}
	for name in WRAPPERS:
		dest = bindir / name
		if name not in have:
			log.append("skip wrapper %s: this toolset has no %s.exe" % (name, name))
			continue
		from_ = template / "bin" / arch / name
		if dest.is_file():
			log.append("ok   wrapper %s" % dest)
			continue
		if not from_.is_file():
			log.append("skip wrapper %s: no template at %s" % (name, from_))
			continue
		if not do:
			log.append("would write %s (from %s)" % (dest, from_))
			continue
		bindir.mkdir(parents=True, exist_ok=True)
		shutil.copy2(from_, dest)
		dest.chmod(0o755)
		log.append("wrapper %s (from %s)" % (dest, from_))
	for name in PLUMBING:
		source, dest = template / "bin" / arch / name, bindir / name
		if source.is_file() and not dest.exists():
			if do:
				bindir.mkdir(parents=True, exist_ok=True)
				shutil.copy2(source, dest)
				dest.chmod(0o755)
				log.append("copy %s" % dest)
			else:
				log.append("would copy %s" % dest)


def main() -> int:
	ap = argparse.ArgumentParser()
	ap.add_argument("--prefix", required=True, help="the extracted toolset, e.g. toolchains/msvc-14.0")
	ap.add_argument("--toolset-version", default=None,
		help="the version directory to create (default: derive it, and print the derivation)")
	ap.add_argument("--sdk-prefix", default=str(HERE / "msvc"),
		help="a prefix that already has a usable Windows Kits/10 to share (default toolchains/msvc)")
	ap.add_argument("--wrapper-prefix", default=str(HERE / "msvc"),
		help="a prefix whose msvc-wine wrappers to copy (default toolchains/msvc)")
	ap.add_argument("--architectures", default="x64", help="target architectures to write wrappers for")
	ap.add_argument("--dry-run", action="store_true")
	ap.add_argument("--force", action="store_true", help="replace a symlink that points elsewhere")
	a = ap.parse_args()

	prefix = Path(a.prefix).resolve()
	if not (prefix / "VC").is_dir():
		print("%s: no VC directory - not an extracted MSVC tree" % prefix, file=sys.stderr)
		return 2
	do, force, log = not a.dry_run, a.force, []

	possible = [row for row in LAYOUT if (prefix / "VC" / "bin" / row[0] / "cl.exe").is_file()]
	if not possible:
		print("%s: no cl.exe under any of VC/bin/{%s}" % (prefix, ",".join(r[0] for r in LAYOUT)),
			file=sys.stderr)
		return 2
	arches = set(a.architectures.split())
	rows = [row for row in possible if row[3] in arches]
	if not rows:
		print("%s: this tree emits %s, but --architectures asked for %s" % (prefix,
			sorted({r[3] for r in possible}), sorted(arches)), file=sys.stderr)
		return 2
	print("%s: %s" % (prefix, "; ".join("VC/bin/%s -> bin/%s/%s" % (r[0], r[1], r[2]) for r in rows)))

	toolset = a.toolset_version or derive_toolset(prefix, log)
	if not toolset:
		print("\n".join(log), file=sys.stderr)
		return 2
	print("toolset directory VC/tools/msvc/%s" % toolset)

	sdk = Path(a.sdk_prefix).resolve() / "Windows Kits" / "10"
	if not sdk.is_dir():
		print("%s: no Windows Kits/10 to share" % sdk, file=sys.stderr)
		return 2
	print("shared SDK %s" % sdk)

	make_executable(log, do, prefix / "VC")
	supply_host_runtime(log, do, prefix, next(r[0] for r in rows if r[3] == "x64")
		if any(r[3] == "x64" for r in rows) else rows[0][0])
	root = prefix / "VC" / "tools" / "msvc" / toolset
	planned = set()

	def plan(target: Path, dest: Path) -> None:
		link(log, do, force, target, dest, planned)
		planned.add(dest)

	for directory, hostdir, target, arch in rows:
		plan(prefix / "VC" / "bin" / directory, root / "bin" / hostdir / target)
	plan(prefix / "VC" / "include", root / "include")
	for arch in sorted({r[3] for r in rows}):
		for source, dest in ((prefix / "VC" / "lib" / LIB_DIRS[arch], root / "lib" / arch),
				(prefix / "VC" / "lib" / "onecore" / LIB_DIRS[arch], root / "lib" / "onecore" / arch)):
			plan(source, dest)
	planned.add(prefix / "Windows Kits")	# created by the line below, and the target of the one after
	plan(sdk, prefix / "Windows Kits" / "10")
	plan(prefix / "Windows Kits", prefix / "kits")
	for directory, hostdir, target, arch in rows:
		onecore = prefix / "VC" / "lib" / "onecore" / LIB_DIRS[arch]
		if onecore.is_dir():
			missing = [n for n in ONECORE_ONLY if (onecore / n).is_file()
				and not (prefix / "VC" / "lib" / LIB_DIRS[arch] / n).is_file()]
			if missing:
				log.append("%s holds %s, which VC/lib/%s does not - both go on LIB"
					% (onecore.relative_to(prefix), ", ".join(missing), LIB_DIRS[arch]))
		write_msvcenv(log, do, prefix, toolset, sdk, arch, hostdir)
		write_wrappers(log, do, prefix, Path(a.wrapper_prefix).resolve(), arch)

	print()
	print("\n".join(log))
	if a.dry_run:
		print("\ndry run: nothing written. Re-run without --dry-run, then `decomp check`.")
	elif rows:
		print("\nnext: PATH=%s/bin/%s:$PATH and `decomp check`; a project pins this prefix with "
			"[msvc] prefix = ..." % (prefix, rows[0][3]))
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
