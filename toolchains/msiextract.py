#!/usr/bin/env python3
"""`msiextract -C DEST SRC.msi` for machines without msitools.

vsdownload.py extracts the Windows SDK payloads with `msiextract` on every non-Windows
system (msvc-wine/vsdownload.py:787-801) and with `msiexec /a` on Windows. msitools is not
installable on this machine (no root, Docs/Setup.md §6.7), while Wine is - so this is the
Windows branch, run through wine64, with the same command line as msitools'.

Difference worth knowing: msitools reads the MSI file table itself, while an admin install
(`msiexec /a`) resolves the MSI *directory table*, which is what produces the
`Program Files/Windows Kits/10/...` layout that vsdownload's moveVCSDK expects. That is the
layout we want; `pymsi`-style extraction gives directory-table *ids* (`ProgramFilesFolder`)
and is not drop-in.

Usage: msiextract [-C DEST] [-l] package.msi
Prints the files it added, like msiextract, because vsdownload tees that into a listing file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def wine_launcher() -> str:
	"""wine64 first: this machine's /usr/bin/wine is a 32-bit ELF whose interpreter
	/lib/ld-linux.so.2 is missing, so it cannot exec at all (Docs/Setup.md §1)."""
	for name in ("wine64", "wine"):
		found = shutil.which(name)
		if found:
			return found
	raise SystemExit("msiextract: no wine or wine64 on PATH - the MSVC SDK payloads can be "
		"extracted with msitools (msiextract) or with Wine; neither is installed")


def snapshot(root: Path) -> set[str]:
	out = set()
	for dirpath, dirnames, filenames in os.walk(root):
		for name in filenames:
			out.add(str(Path(dirpath, name).relative_to(root)))
	return out


def main(argv: list[str]) -> int:
	dest = None
	args = []
	i = 0
	while i < len(argv):
		arg = argv[i]
		if arg in ("-C", "--directory"):
			dest = argv[i + 1]
			i += 2
		elif arg in ("-l", "--list"):
			i += 1  # msitools' --list; we always print what appeared
		elif arg.startswith("-"):
			# Any other msitools switch (--unpackpath, -x ...) is accepted and ignored:
			# an admin install has no equivalents for them.
			i += 1
		else:
			args.append(arg)
			i += 1
	if dest is None or not args:
		print(__doc__.strip().splitlines()[-1], file=sys.stderr)
		return 2

	dest = Path(dest).resolve()
	dest.mkdir(parents=True, exist_ok=True)
	# Wine's own msiexec needs TARGETDIR as a DOS path; z: is the host root.
	target = "z:%s" % str(dest).replace("\\", "/")
	wine = wine_launcher()
	env = dict(os.environ)
	env.setdefault("WINEDEBUG", "-all,err+all")
	env.setdefault("WINEPREFIX", str(Path(__file__).resolve().parents[1] / ".wine"))
	Path(env["WINEPREFIX"]).mkdir(parents=True, exist_ok=True)
	if not (Path(env["WINEPREFIX"]) / "system.reg").is_file():
		print("msiextract: initialising Wine prefix %s" % env["WINEPREFIX"], file=sys.stderr)

	before = snapshot(dest)
	for msi in args:
		cmd = [wine, "msiexec", "/a", os.path.abspath(msi), "/qn", "TARGETDIR=%s" % target]
		for attempt in range(2):  # Wine's msiexec sometimes needs a second pass for external cabs
			process = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)
			if process.returncode == 0:
				break
			time.sleep(2)
		else:
			sys.stderr.write("msiextract: %s failed (%d)\n%s\n" % (msi, process.returncode,
				"\n".join((process.stderr or process.stdout).splitlines()[-15:])))
			return process.returncode

	after = snapshot(dest)
	for name in sorted(after - before):
		print(name)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
