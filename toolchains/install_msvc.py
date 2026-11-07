#!/usr/bin/env python3
"""Install one MSVC toolset of a chosen era into ./toolchains/msvc (Docs/Setup.md §6).

This is the MS-2 step "put a compiler on the machine" (Docs/MSVC-Plan.md §7): a real
`cl.exe`/`link.exe`, of the era the target was built with, driven through msvc-wine's
wrappers. It exists because the plain upstream command does not finish on this machine:

  toolchains/msvc-wine/vsdownload.py --accept-license --major 15 --msvc-version 15.5 \
      --dest toolchains/msvc

* The VS2017-era (major 15) manifest drags the whole IDE shell in behind
  `Component.VC.Tools.14.12` - 363 packages, 7.7 GB. `keep_pattern` keeps the toolset, its
  CRT headers and the import libraries of the target arches asked for, and the Windows SDK.
* `--msvc-version 15.5` pins the SDK to 10.0.16299, which the 15.9 channel no longer
  serves (only 10.0.19041 here), so `--sdk-version` has to be passed.
* Its Windows SDK extraction calls `msiextract` (msitools) - use that when installed; it
  reads the MSI file table and expands the SDK's external cabinets. `toolchains/msiextract.py`
  stands in for machines without it, by running `wine msiexec /a` - which does NOT work for
  the Windows SDK's WiX MSIs on this Wine (Docs/Setup.md §6.10).
* Extracting every SDK MSI is ~4 GB of files, most of them ARM/WinRT/App-Certification
  parts we never use; `SDK_KEEP` keeps the desktop x64 + UCRT ones. Note that the desktop
  C/C++ headers and the base import libraries (kernel32, user32, uuid, WindowsApp) are NOT
  in the payloads named "Desktop Headers/Libs" - see the comment on SDK_KEEP.
* The desktop CRT package does not ship every library cl auto-links; see `fill_missing_libs`.

Nothing here is committed except this file and msiextract.py - `toolchains/` and `.wine/`
are gitignored (the toolset is under a non-redistributable licence).

Target bitness (X86-1, Docs/MSVC-x86-Plan.md §6): the fetch used to be hard-wired to
`--architecture x64`, and `vsdownload.matchPackageTargetArch` then drops every x86 package,
so the tree had `VC/Tools/MSVC/<v>/bin/Hostx64/x64` and `lib/x64` only - an x64-only
compiler, which is what `decomp check` reports (X86-0). `--architecture x86 x64` fetches
`Microsoft.VisualC.<v>.Tools.HostX64.TargetX86` and the x86 CRT import libraries, and
`install.sh` then writes a wrapper per target arch: `bin/x86/cl` -> `bin/Hostx64/x86/cl.exe`.
That is an x64-host process emitting i386 code, so **compiling 32-bit needs no 32-bit Wine**
(only running a 32-bit PE does - Docs/Setup.md §6.7 item 1).

Usage:
  .venv/bin/python toolchains/install_msvc.py                        # v141, x64 target only
  .venv/bin/python toolchains/install_msvc.py --print                # only show the selection
  .venv/bin/python toolchains/install_msvc.py --architecture x86 x64 # both target bitnesses
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
CLONE = HERE / "msvc-wine"
DEST = HERE / "msvc"
CACHE = Path("/tmp/msvc-cache")          # the download cache; /tmp keeps it off the toolchain fs
WINEPREFIX = REPO / ".wine"             # gitignored; shared with the wrappers and checks

# The target bitnesses this driver offers. Everything in decomp reads x86 or x64; ARM/ARM64X
# are fetchable upstream and deliberately not offered here (Docs/MSVC-x86-Plan.md §9).
ARCHES = ("x86", "x64")
DEFAULT_ARCHES = ("x64",)                # what the install did before X86-1, kept as the default

# The upstream default for a VS2017-era channel is the whole product. These are the packages a
# compiler needs: the pinned toolset, its own CRT headers, the CRT import libraries for the
# target arches asked for (not the versionless 14.16 ones, which would put a second, newer VC
# under VC/tools/msvc and make install.sh pick that one), and the Windows SDK. The
# `crt.<arch>.onecore.desktop` package is not optional in practice - the desktop one leaves out
# msvcrt.lib/oldnames.lib and the rest, see fill_missing_libs.
#
# The CRT clause is built from the requested arches, so that asking for x86 does not fetch
# `Microsoft.VisualC.14.12.CRT.x86.Desktop` with vsdownload and then drop it here. The tools
# clause needs no per-arch name: `Tools.HostX64.TargetX86` is a `.tools.` id and already
# matches. An arch that was not requested never reaches this regex at all - vsdownload filters
# the selection by target arch first - so a x64-only run keeps selecting exactly what it did.
def keep_pattern(arches: "tuple[str, ...] | list[str]") -> re.Pattern:
	crt = "|".join("%s\\.(desktop|onecore\\.desktop)" % re.escape(a) for a in arches)
	return re.compile(
		r"^("
		r"microsoft\.visualstudio\.component\.vc\.tools\.[\d.]+"		# the pinned toolset component
		r"|microsoft\.visualc\.\d+\.\d+\.tools(\.|$)"			# cl/c1/c2/link/lib/ml, every host
		r"|microsoft\.visualc\.\d+\.\d+\.crt\.(headers|source|" + crt + r")"	# STL+CRT headers, import libs
		r"|win1[01]sdk"								# the Windows SDK
		")", re.I)

# Which Windows SDK payloads to unpack. Every .cab stays: the MSIs name their own external
# cabinet, and an admin install fails when the cabinet is not next to the MSI.
#
# The "…Desktop Headers/Libs x64" payloads are NOT what their names suggest: their File
# tables hold 3 and 346 entries, and none of them is windows.h or kernel32.lib. In the SDK
# as served through the VS channel, the desktop C/C++ headers (Include/*/um, most of the
# shared/ set) and the base import libraries (kernel32.Lib, User32.Lib, Uuid.Lib,
# WindowsApp.lib, OneCoreUAP*.Lib) ship in the payloads named "…for Windows Store Apps…",
# which install into the same Windows Kits/10/Include/<v>/um and Lib/<v>/um/<arch> trees.
# Keeping only the "Desktop" ones gives an SDK with no <windows.h> and no kernel32.lib.
#
# No per-arch clause is needed here: the payloads that hold `Lib/<v>/um/x86` and
# `Lib/<v>/ucrt/x86` are the same payloads that hold the x64 ones (measured - the x86 SDK
# import libraries were already present in the x64-only install, which is exactly the state
# Docs/MSVC-x86-Plan.md §4.1 and X86-0 report: the missing half is the VC toolset, not the SDK).
SDK_KEEP = re.compile(
	r"^("
	r"Windows SDK$|Windows SDK EULA|Kits Configuration Installer"
	r"|Windows SDK Desktop (Headers|Libs) x64"
	r"|Windows SDK for Windows Store Apps (Headers|Libs|Contracts)"
	r"|Universal CRT Headers Libraries and Sources"
	r"|Universal CRT Tools x64"
	r"|Windows SDK Signing Tools"
	r")", re.I)

# 14.12 = the era of Tests/Proprietary/notepad.exe; its pinned SDK 10.0.16299 is no longer
# served by that channel, so the SDK version has to be named (10.0.19041 is what 15.9 has).
# Nothing here needs a 32-bit Wine host: these toolsets ship an x64-hosted cl for both target
# bitnesses (Docs/Setup.md §6.2/§6.7). A 32-bit *guest* - running the i386 .exe it links - is
# a different question and is not solved by anything in this file.
MAJOR, MSVC_VERSION, SDK_VERSION = "15", "15.5", "10.0.19041"
TRIM = ["--with-workload", "no", "--with-asan", "no", "--with-atl", "no",
	"--with-dia", "no", "--with-msbuild", "no", "--with-devcmd", "no"]


def prune_dangling_links(dest: str) -> int:
	"""Remove symlinks whose target is gone, so msvc-wine's install.sh can be re-run.

	install.sh creates the case-insensitive aliases a build expects (`msvcrt.lib` ->
	`MSVCRT.lib`) with `ln_s() { if [ ! -e "$2" ]; then ln -s "$1" "$2"; fi; }`. `-e` follows
	the link, so a *dangling* alias from an earlier, partial run passes the test and `ln -s`
	then fails with "File exists" - which, under `set -e`, aborts the whole install. The v141
	toolset payload really has no msvcrt.lib/msvcrtd.lib/oldnames.lib (they live in the CRT
	redist packages), so those three aliases are always dangling here.
	"""
	removed = []
	for dirpath, dirnames, filenames in os.walk(dest):
		for name in dirnames + filenames:
			path = os.path.join(dirpath, name)
			if os.path.islink(path) and not os.path.exists(path):
				os.unlink(path)
				removed.append(path)
	if removed:
		print("removed %d dangling symlink(s) left by an earlier partial install:" % len(removed))
		for path in removed:
			print("  " + os.path.relpath(path, dest))
	return len(removed)


def fill_missing_libs(dest: str, arches: "tuple[str, ...]" = ARCHES) -> int:
	"""Point each arch's desktop lib directory at the library that arch's desktop CRT package does not ship.

	Measured on the 15.9 channel: `Microsoft.VisualC.14.12.CRT.x64.Desktop` ships 30 files
	under `VC/Tools/MSVC/<ver>/lib/x64` - the static CRT (libcmt/libcpmt/libvcruntime),
	the concrt variants and msvcmrt - and nothing else. `msvcrt.lib`, `msvcrtd.lib`,
	`oldnames.lib`, `msvcprt.lib`, `legacy_stdio_definitions.lib`, `vccorlib.lib`,
	`vcomp.lib` and the PGO/DIA support libs are only in the sibling package
	`…CRT.x64.OneCore.Desktop`, under `lib/onecore/x64`. cl auto-links oldnames.lib, so
	every link, including msvc-wine's own msvctricks.cpp, stops at
	`LNK1104: cannot open file 'OLDNAMES.lib'` without it.

	For every file name the desktop directory lacks, symlink the OneCore copy next to it and
	print it. Nothing already there is touched, so the CRT flavour the build uses is unchanged.
	This is per target arch, because the packages are: `lib/x86` and `lib/onecore/x86` are
	separate payloads with the same relationship (X86-1).
	"""
	added = 0
	for toolset in sorted((Path(dest) / "VC/Tools/MSVC").glob("*")):
		for arch in arches:
			onecore, desktop = toolset / ("lib/onecore/" + arch), toolset / ("lib/" + arch)
			if not onecore.is_dir() or not desktop.is_dir():
				continue
			for source in sorted(onecore.iterdir()):
				target = desktop / source.name
				if target.exists():
					continue
				target.symlink_to(os.path.relpath(source, desktop))
				added += 1
				print("  %-32s %s (from %s/lib/onecore/%s)"
					% (source.name, arch, toolset.name, arch))
	if added:
		print("linked %d library/libraries the desktop CRT packages do not ship" % added)
	return added


def msiextract_shim() -> "Path | None":
	"""A PATH entry providing `msiextract` for vsdownload's SDK extraction step, or None.

	None means the machine has msitools' own `msiextract`, which is the one to use: it reads
	the MSI file table itself and expands the SDK's external cabinets (measured: the 284 MB
	`Universal CRT Headers Libraries and Sources` payload in 0.85 s, into the same
	`Program Files/Windows Kits/10/...` layout moveVCSDK expects). The shim below is for
	machines without msitools; it runs `wine msiexec /a`, which stops on the Windows SDK's
	WiX MSIs at `InstallAdminPackage` with 1627 (Docs/Setup.md §6.10).
	"""
	found = shutil.which("msiextract")
	if found:
		print("msiextract: using %s" % found)
		return None
	bin_dir = HERE / "bin"
	bin_dir.mkdir(parents=True, exist_ok=True)
	shim = bin_dir / "msiextract"
	shim.write_text('#!/bin/sh\nexec "%s" "%s/msiextract.py" "$@"\n' % (sys.executable, HERE))
	shim.chmod(0o755)
	print("msiextract: not on PATH - using the wine shim, toolchains/msiextract.py")
	return bin_dir


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("--print", action="store_true", help="print the package selection and stop")
	parser.add_argument("--dest", default=str(DEST))
	parser.add_argument("--cache", default=str(CACHE))
	parser.add_argument("--major", default=MAJOR)
	parser.add_argument("--msvc-version", default=MSVC_VERSION)
	parser.add_argument("--sdk-version", default=SDK_VERSION)
	parser.add_argument("--architecture", nargs="+", choices=list(ARCHES), default=list(DEFAULT_ARCHES),
		help="target bitnesses to install (default: x64). Each one adds that target's cl - the "
			"Hostx64/<arch> cross compiler - and its CRT import libraries, and install.sh writes a "
			"bin/<arch>/cl wrapper for it. No 32-bit Wine is involved (Docs/Setup.md §6.7).")
	parser.add_argument("--manifest", help="a saved installer manifest (skips the network)")
	parser.add_argument("--full-sdk", action="store_true", help="unpack every Windows SDK payload")
	parser.add_argument("--no-sdk", action="store_true",
		help="skip the Windows SDK: the toolset alone, for a machine that cannot extract its MSIs")
	parser.add_argument("--no-install-sh", action="store_true", help="skip the wrapper step")
	args = parser.parse_args()

	if not (CLONE / "vsdownload.py").is_file():
		print("no msvc-wine clone in %s:\n  git clone https://github.com/mstorsjo/msvc-wine %s"
			"\n  git -C %s checkout 514f8ea   (Docs/Setup.md §6.1)" % (CLONE, CLONE, CLONE))
		return 2

	sys.path.insert(0, str(CLONE))
	import vsdownload as vsd  # noqa: E402

	arches = list(dict.fromkeys(args.architecture))		# de-duplicate, keep the order asked for
	command = ["--accept-license", "--major", args.major, "--msvc-version", args.msvc_version,
		"--sdk-version", args.sdk_version, "--host-arch", "x64", "--architecture", *arches, *TRIM]
	if args.no_sdk:
		command += ["--with-sdk", "no"]
	if args.manifest:
		command += ["--manifest", args.manifest]
	opts = vsd.getArgsParser().parse_args(command)
	if opts.host_arch is None:
		opts.host_arch = "x64"
	if not opts.architecture:
		opts.architecture = list(arches)

	KEEP = keep_pattern(arches)
	manifest = vsd.getManifest(opts)
	# vsdownload.prioritizePackage reads the module-level `args` that its own main() would
	# have set, so it has to be in place before getPackages.
	vsd.args = opts
	packages = vsd.getPackages(manifest, opts.host_arch)
	vsd.setPackageSelection(opts, packages)
	vsd.lowercaseIgnores(opts)

	def select():
		return vsd.getSelectedPackages(packages, opts)

	selected = select()
	print("upstream selection: %d packages, %s to download"
		% (len(selected), vsd.formatSize(vsd.sumDownloadSize(selected))))
	opts.ignore += [p["id"].lower() for p in selected if not KEEP.match(p["id"])]
	selected = select()
	print("pruned selection:   %d packages, %s to download"
		% (len(selected), vsd.formatSize(vsd.sumDownloadSize(selected))))
	print("target architectures: %s" % " ".join(arches))
	for p in sorted(selected, key=lambda p: p["id"]):
		print("  %-55s %s" % (p["id"], vsd.formatSize(sum(pl.get("size", 0) for pl in p.get("payloads", [])))))
	if args.print:
		return 0

	if not args.full_sdk:
		for p in selected:
			if not p["id"].startswith(("Win10SDK", "Win11SDK")):
				continue
			keep = [pl for pl in p["payloads"]
				if pl["fileName"].lower().endswith(".cab")
				or SDK_KEEP.match(vsd.getPayloadName(pl).split("-")[0])]
			print("Windows SDK payloads: keeping %d of %d" % (len(keep), len(p["payloads"])))
			p["payloads"] = keep

	cache = os.path.abspath(args.cache)
	dest = os.path.abspath(args.dest)
	vsd.downloadPackages(selected, cache, allowHashMismatch=False)

	unpack = os.path.join(dest, "unpack")
	vsd.makedirs(unpack)
	# The SDK MSIs resolve [ProgramFilesFolder]; vsdownload symlinks "Program Files" to the
	# unpack root so moveVCSDK finds Windows Kits. Wine's 32-bit msiexec says "Program Files".
	for name in ("Program Files", "Program Files (x86)"):
		if not os.access(os.path.join(unpack, name), os.F_OK):
			os.symlink(".", os.path.join(unpack, name), target_is_directory=True)

	shim_dir = msiextract_shim()
	if shim_dir is not None:
		os.environ["PATH"] = "%s%s%s" % (shim_dir, os.pathsep, os.environ.get("PATH", ""))
	os.environ.setdefault("WINEPREFIX", str(WINEPREFIX))
	WINEPREFIX.mkdir(parents=True, exist_ok=True)
	vsd.extractPackages(selected, cache, unpack)
	vsd.moveVCSDK(unpack, dest)
	shutil.rmtree(unpack)

	if not args.no_install_sh:
		if not args.no_sdk:
			print("\n=== libraries the desktop CRT package does not ship ===")
		fill_missing_libs(dest, tuple(arches))
		prune_dangling_links(dest)
		if not args.no_sdk:
			print("\n=== msvc-wine install.sh (wrappers) ===")
			subprocess.run(["sh", str(CLONE / "install.sh"), dest], check=True)
		else:
			# install.sh refuses to make the wrappers without a Windows Kits directory - it
			# reads the SDK version out of Windows Kits/10/include/10.*. Put an empty one in
			# place so the toolset gets its wrappers, and say plainly that it is empty: with
			# it, cl runs and compiles freestanding code, but there is no CRT header or
			# import library to build or link a real program against.
			for version in (SDK_VERSION + ".0",):
				(Path(dest) / "Windows Kits/10/Include" / version / "ucrt").mkdir(parents=True, exist_ok=True)
				for arch in arches:
					(Path(dest) / "Windows Kits/10/Lib" / version / "ucrt" / arch).mkdir(parents=True, exist_ok=True)
			print("\n=== msvc-wine install.sh (wrappers, empty Windows SDK placeholder) ===")
			subprocess.run(["sh", str(CLONE / "install.sh"), dest], check=True)
			print("\nWARNING: Windows Kits/10 is an empty placeholder - the Windows SDK payload MSIs were")
			print("         not extracted, so this toolset can compile but not build a real program.")
			print("         It needs `msiextract` (msitools) or a Wine whose msiexec extracts them;")
			print("         this machine's Wine 9.21 stops at InstallAdminPackage with 1627.")
		print("\nNow: PATH=%s  WINEPREFIX=%s"
			% (" ".join("%s/bin/%s:$PATH" % (dest, a) for a in arches), WINEPREFIX))
		print("     each bin/<arch>/cl is that arch's target compiler; use one at a time, the")
		print("     bitness comes from which cl.exe runs, never from a flag (Docs/Setup.md §6.2).")
		return 0

	print("\nNow: PATH=%s" % " ".join("%s/bin/%s:$PATH" % (dest, a) for a in arches))
	return 0


if __name__ == "__main__":
	sys.exit(main())
