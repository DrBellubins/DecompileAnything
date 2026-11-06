"""Fetch the PDB that a shipped PE asks for, from Microsoft's public symbol server.

A CodeView record is not debug information, it is the *address* of debug information: the PDB
name plus a GUID and an age is the key Microsoft serves the real file under, and
`decomp detect` already prints that URL (`decomp detect notepad.exe` -> the `pdb` line).
Nothing in LIEF or pefile makes the request - pefile goes exactly as far as spelling the key
out (`entry.Signature_String`) and LIEF as far as handing over the GUID and age - so fetching
is one HTTPS GET. What is worth code is the part after it: proving that what came back is the
file this image links against, and keeping it somewhere a symbol-server client would look.

The store is laid out the way a symbol server cache is laid out,
`<store>/<pdb name>/<GUID+age>/<pdb name>`, so
`_NT_SYMBOL_PATH=srv*</store>*https://msdl.microsoft.com/download/symbols` - and any other
tool - finds the same file.
"""

from __future__ import annotations

import math
import os
import struct
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .toolchain import (SYMBOL_SERVER, _read_pe_debug, pdb_name, symbol_server_key,
	symbol_server_url)

DEFAULT_STORE = "cache/symbols"
MSF_SIGNATURE = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


class SymbolError(Exception):
	"""No CodeView record, no symbol server hit, or not a PDB - named instead of traced."""


def codeview(target: Path) -> dict:
	"""{name, guid, age, symbols_url} of a PE, plus the timestamp its PDB has to carry.

	Same debug-directory reading as `detect` (toolchain._read_pe_debug), so the identity this
	fetch uses cannot drift from the one `detect` printed.
	"""
	import lief
	try:
		binary = lief.parse(str(target))
	except Exception as exc:  # noqa: BLE001 - any parser failure is an answer, not a crash
		raise SymbolError("lief could not parse %s: %s" % (target.name, exc)) from exc
	if binary is None or not isinstance(binary, lief.PE.Binary):
		raise SymbolError("%s is not a PE: only PE/COFF images carry a CodeView record" % target.name)
	note = {"comment": [], "pdb": None, "pogo": None, "ltcg": False}
	_read_pe_debug(binary, note)
	record = note["pdb"] or {}
	if not record.get("guid") or not record.get("name"):
		raise SymbolError(
			"%s has no CodeView (RSDS) record - it was linked without /Zi, or the debug "
			"directory was stripped, so there is no key to ask the symbol server with"
			% target.name)
	record["image_timestamp"] = int(getattr(binary.header, "time_date_stamps", 0) or 0)
	record.setdefault("symbols_url", symbol_server_url(record["name"], record["guid"],
		record["age"]))
	return record


def stored_at(store: Path | str, record: dict) -> Path:
	"""Where a symbol server keeps it: <store>/<pdb>/<GUID+age>/<pdb>, by bare file name."""
	name = pdb_name(record["name"])
	return Path(store) / name / symbol_server_key(record["guid"], record["age"]) / name


def _stream_directory(data: bytes) -> dict:
	"""The MSF 7.0 stream directory: sizes of every stream, then the blocks of each.

	SuperBlock.BlockMapAddr names the block it starts at, but writers disagree about that field:
	notepad.pdb's own directory is one block below the address its superblock gives. A candidate
	is only accepted when it accounts for exactly NumDirectoryBytes, which is what rules out the
	free-block map sitting next to it, and the blocks are scanned otherwise.
	"""
	if not data.startswith(MSF_SIGNATURE):
		raise SymbolError("not an MSF 7.0 container (no %r header)" % MSF_SIGNATURE[:24])
	block, _free, blocks, dir_bytes, _zero, block_map = struct.unpack_from("<IIIIII", data, 32)
	if block == 0 or blocks == 0:
		raise SymbolError("MSF superblock of %s is nonsense" % block)

	def read(start):
		raw = b"".join(data[(start + i) * block:(start + i + 1) * block]
			for i in range(math.ceil(dir_bytes / block)))[:dir_bytes]
		count = struct.unpack_from("<I", raw, 0)[0]
		if not 0 < count < 8192:
			return None
		sizes = struct.unpack_from("<%dI" % count, raw, 4)
		if any(size > len(data) for size in sizes):
			return None
		pages = sum(math.ceil(size / block) if size else 0 for size in sizes)
		if 4 + 4 * count + 4 * pages != dir_bytes:
			return None
		offset, listed = 4 + 4 * count, []
		for size in sizes:
			need = math.ceil(size / block) if size else 0
			found = struct.unpack_from("<%dI" % need, raw, offset)
			offset += 4 * need
			if any(page >= blocks for page in found):
				return None
			listed.append(found)
		return {"block": block, "sizes": sizes, "pages": listed, "at": start}

	for start in [block_map, block_map - 1, *range(blocks)]:
		if 0 <= start < blocks:
			found = read(start)
			if found:
				return found
	raise SymbolError("no stream directory accounted for in this MSF container")


def _stream(data: bytes, directory: dict, index: int) -> bytes:
	if index >= len(directory["sizes"]):
		raise SymbolError("MSF container has no stream %d" % index)
	raw = b"".join(data[page * directory["block"]:(page + 1) * directory["block"]]
		for page in directory["pages"][index])
	return raw[:directory["sizes"][index]]


def pdb_identity(path: Path | str) -> dict:
	"""What a PDB says about itself, out of stream 1 (the PDB stream).

	Measured on the Windows notepad.pdb: a u32 format version (20000404), a u32 signature that
	is the TimeDateStamp of the image it was built with, a u32 age, then the 16-byte GUID. The
	image's CodeView record asks for age 1 while this header says 3, because a shipped PDB is
	rewritten after linking (indexed, signed); the CodeView age is part of the key, so that is
	not a mismatch. Stream 0 is the pre-7.0 directory kept for compatibility, not the directory.
	"""
	data = Path(path).read_bytes()
	info = _stream(data, _stream_directory(data), 1)
	if len(info) < 28:
		raise SymbolError("%s: its PDB stream is %d bytes, too short to carry an identity"
			% (path, len(info)))
	version, signature, age = struct.unpack_from("<III", info, 0)
	return {"path": str(path), "bytes": len(data), "format_version": version,
		"link_timestamp": signature, "age": age,
		"guid": str(uuid.UUID(bytes_le=info[12:28])).lower()}


def _flat(value) -> str:
	return str(value or "").replace("-", "").lower()


def check(record: dict, identity: dict) -> dict:
	"""Is this the PDB the image links against? The GUID has to agree; the timestamp is the
	corroborating fact (a PDB carries the TimeDateStamp of the link it describes)."""
	return {
		"guid": _flat(identity["guid"]) == _flat(record["guid"]),
		"link_timestamp": identity["link_timestamp"] == int(record.get("image_timestamp") or -1),
		"pdb_age": identity["age"], "asked_age": int(record.get("age") or 0),
	}


def fetch(target: Path | str, store: Path | str = DEFAULT_STORE, *, refresh: bool = False,
		timeout: float = 60.0) -> dict:
	"""Get the PDB this image asks for into <store>, and verify it. Cached files are verified
	as they are read, not assumed."""
	target = Path(target)
	record = codeview(target)
	dest = stored_at(store, record)
	result = {"target": str(target), "pdb": record, "path": str(dest), "url": record["symbols_url"]}
	if dest.is_file() and not refresh:
		result["source"] = "already in the store"
	else:
		dest.parent.mkdir(parents=True, exist_ok=True)
		try:
			with urllib.request.urlopen(record["symbols_url"], timeout=timeout) as response:
				body = response.read()
		except urllib.error.HTTPError as exc:
			raise SymbolError(
				"%s %s: the symbol server has no %r under that key (Microsoft only publishes "
				"symbols for some shipped binaries, and the key is exact)"
				% (exc.code, record["symbols_url"], record["name"])) from exc
		except (urllib.error.URLError, TimeoutError) as exc:
			raise SymbolError("%s is not reachable: %s" % (SYMBOL_SERVER, exc)) from exc
		if not body:
			raise SymbolError("%s returned 0 bytes" % record["symbols_url"])
		# .part + rename: a half-written PDB must not pass as a cached one tomorrow.
		part = dest.with_name(dest.name + ".part")
		part.write_bytes(body)
		os.replace(part, dest)
		result["source"] = "fetched"
		result["bytes"] = len(body)
	result["identity"] = pdb_identity(dest)
	result["match"] = check(record, result["identity"])
	result.setdefault("bytes", dest.stat().st_size)
	return result


def lines(result: dict) -> list[str]:
	"""What `decomp symbols` prints."""
	pdb, identity, match = result["pdb"], result["identity"], result["match"]
	out = [
		"  pdb         %s  guid %s age %s" % (pdb["name"], pdb["guid"], pdb["age"]),
		"  served at   %s" % result["url"],
		"  stored      %s  (%d bytes, %s)" % (result["path"], result["bytes"], result["source"]),
		"  identity    guid %s  link timestamp %d  age %d  %s" % (
			identity["guid"], identity["link_timestamp"], identity["age"],
			"MSF format version %d" % identity["format_version"]),
		"  match       %s" % ("the PDB the image asks for: its GUID is the one in the CodeView "
			"record, and it carries this image's TimeDateStamp (%d)" % pdb.get("image_timestamp", 0)
			if match["guid"] and match["link_timestamp"] else
			"%s" % ("GUID " + ("ok" if match["guid"] else "does NOT match the CodeView record")
				+ ", link timestamp " + ("ok" if match["link_timestamp"]
				else "does NOT match the image's TimeDateStamp"))),
	]
	if match["pdb_age"] != match["asked_age"]:
		out.append("  note        the PDB header says age %d but the image asks for %d: the key the "
			"server indexes is the one in the CodeView record, and a shipped PDB is rewritten "
			"after the link, so this is not a mismatch" % (match["pdb_age"], match["asked_age"]))
	return out
