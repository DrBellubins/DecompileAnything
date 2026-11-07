#!/usr/bin/env python3
"""Install wibo, the PE loader that runs a **32-bit** program here (Docs/Setup.md §6.7 Option B).

Why this exists (Docs/MSVC-x86-Plan.md X86-4)
--------------------------------------------
A 32-bit *target* and a 32-bit *guest* are two different problems, and only the second one needs
anything installed. Building i386 code needs nothing: `VC/Tools/MSVC/<v>/bin/Hostx64/x86/cl.exe`
is an x64 process that emits i386 (§6.7 item 1, and X86-1 installed it). **Running** the program
that comes out is a separate question, and this machine cannot answer it with Wine:

    wine64 Tests/build/msvc-o0-x86/da_tests   ->   /lib/ld-linux.so.2: could not open

measured again 2026-11-07: the host now has a 32-bit ELF interpreter (`/lib/ld-linux.so.2`
resolves), but this Wine ships no i386 guest - `/usr/lib/wine` contains `x86_64-unix` and
`x86_64-windows` only. §6.7's Option A fixes that with root (`[multilib]` + `wine mesa`, plus a
fresh prefix). Option B needs no root and no prefix: **wibo** is a static single-binary PE loader,
which is what the decomp.me crowd compiles and runs 32-bit code with.

What it buys
------------
`Tests/eval.py`'s `runner()` prefers it for an image whose optional header says PE32 (32-bit), and
uses `wine64` for PE32+ as before. Without it, `eval.py selfcheck --variant msvc-o0-x86` and its
goldens are *not judgeable* (exit 2, with this reason). With it, the 32-bit reference program runs
and the benchmark's own self-test is checked on it. Nothing is gated on having it installed.

Usage
-----
    .venv/bin/python toolchains/install_wibo.py              # download, verify, install
    .venv/bin/python toolchains/install_wibo.py --print      # say what would be done
    .venv/bin/python toolchains/install_wibo.py --verify     # only re-run the checks below

Installed at `toolchains/wibo/wibo` (gitignored, like the rest of `toolchains/`). It is found in
the order the tool finds everything else: `$DECOMP_WIBO`, then PATH, then that path.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import stat
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEST = HERE / "wibo" / "wibo"

# wibo 1.2.0 (current release, 2026-07) - the Linux x86-64 build. The 64-bit guest line is still
# the experimental `winoah64`, so this is for 32-bit images; a PE32+ image stays on Wine, which
# runs it fine today.
RELEASE = "1.2.0"
ASSET = "wibo-x86_64"
URL = "https://github.com/decompals/wibo/releases/download/%s/%s" % (RELEASE, ASSET)
# Measured on the file this machine downloaded, 2026-11-07. Pinned so a re-download is checked
# against the thing that was actually tested here rather than whatever the URL serves today.
SHA256 = "13f86a2d618f0dbe67179d349625345eabf9b46450295cb4c904e49f6aff85af"

PROBE = r'''
#include <stdio.h>
int main(){printf("hello32\n");return 3;}
'''

# The two checks, in order of what they prove. Both are the §6.7 probe, which is the call that
# cost this discovery the first time.
def probe_source() -> str:
	return PROBE


def checksum(path: Path) -> str:
	return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(prog="install_wibo.py", description=__doc__.splitlines()[0])
	parser.add_argument("--print", action="store_true", dest="show",
		help="say what would be downloaded and where, then stop")
	parser.add_argument("--verify", action="store_true",
		help="do not download: check the installed binary and run the probe")
	parser.add_argument("--force", action="store_true", help="re-download over an installed copy")
	args = parser.parse_args(argv)

	if args.show:
		print("would download %s" % URL)
		print("to %s, then check it against sha256 %s" % (DEST, SHA256))
		print("found by Tests/eval.py's runner() for any image whose optional header is PE32")
		return 0

	if DEST.is_file() and not args.force:
		print("%s is already installed (%s)" % (DEST, checksum(DEST)[:16]))
	elif args.verify:
		print("no %s to verify - run this without --verify first" % DEST)
		return 1
	else:
		print("downloading %s" % URL)
		try:
			with urllib.request.urlopen(URL, timeout=120) as response:
				payload = response.read()
		except OSError as exc:
			print("download failed: %s" % exc)
			print("Option A (§6.7) is the other way: a Wine with an i386 guest, which needs root.")
			return 1
		DEST.parent.mkdir(parents=True, exist_ok=True)
		DEST.write_bytes(payload)
		DEST.chmod(DEST.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
		print("wrote %s (%d bytes)" % (DEST, len(payload)))

	digest = checksum(DEST)
	if digest != SHA256:
		print("warning: sha256 is %s, not the pinned %s - the file at that URL changed, so the "
			"behaviour measured here is not the behaviour being verified" % (digest, SHA256))
		return 1
	print("ok  sha256 %s (the pinned %s build)" % (digest[:16] + "...", RELEASE))

	# The §6.7 probe: an i386 PE that exits 3 and prints. Static, because a shared libgcc is a
	# DLL the guest has to be given separately (measured: `wibo` on a non-static MinGW i386 build
	# aborts with `missing import __register_frame_info from libgcc_s_dw2-1.dll`).
	compiler = shutil.which("i686-w64-mingw32-g++")
	if not compiler:
		print("skip probe: no i686-w64-mingw32-g++ to build the 32-bit probe with. Install mingw, "
			"or verify against a real target: Tests/eval.py selfcheck --variant msvc-o0-x86")
		return 0
	scratch = DEST.parent / "hello32.exe"
	import subprocess

	build = subprocess.run([compiler, "-static", "-o", str(scratch), "-x", "c++", "-"],
		input=probe_source(), text=True, capture_output=True, timeout=120)
	if build.returncode != 0:
		print("probe did not build: %s" % (build.stderr or "").strip()[:400])
		return 1
	run = subprocess.run([str(DEST), str(scratch)], text=True, capture_output=True, timeout=60)
	print("probe: wibo hello32.exe -> exit %d, stdout %r" % (run.returncode, run.stdout.strip()))
	if run.returncode != 3 or "hello32" not in run.stdout:
		print("FAIL: the probe did not run as documented (expected exit 3 and 'hello32').\n%s"
			% (run.stderr or "").strip()[:400])
		return 1
	scratch.unlink(missing_ok=True)
	print("ok  a 32-bit PE runs. Tests/eval.py build/selfcheck --variant msvc-o0-x86 can now "
		"capture goldens and run the reference program's own self-test.")
	print("    A 32-bit target still needed none of this: only running one does (§6.7).")
	return 0


if __name__ == "__main__":
	sys.exit(main())
