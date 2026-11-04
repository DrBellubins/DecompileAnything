"""Discovery: what a question in words names, and what in the binary is related to it.

Phase 3 of Docs/Design-Plan.md. `decomp find` used to answer "which functions have this
name" and "which functions read this string"; this module adds the two things that makes a
request like "decompile the coin system" answerable:

* **xrefs to anything** - a global, a vtable, a table, an address - not only to functions,
  and with the instruction each reference sits on;
* **the shape of an object** - what a data address points at (a vtable's methods, a jump
  table, a GOT slot) and, the other way round, which objects hold a pointer to a function.

A stripped binary names almost nothing, so both directions are driven by *addresses* and by
what the link wrote there (`extract.TargetImage.pointers`), with the names that do exist
used when they exist.

`family()` answers the second half of the request: the functions that belong together,
grown along the call graph from whatever the query named, and ranked by how strongly they
are connected to it and to each other.
"""

from __future__ import annotations

import sqlite3

from . import cache, extract
from .normalize import demangle, simple_name


def demangled(name: str) -> str:
	"""An import's name as a reader would read it (mangled names are kept in the raw form)."""
	table = demangle([name])
	return simple_name(table.get(name, name)) if name.startswith("_Z") else name

# How far to read into an object when looking for pointer slots. A vtable of a class with
# more methods than this is rare; a table longer than this is not a vtable.
MAX_TABLE_BYTES = 0x600
MAX_HOLDER_SCAN = 4_000_000


def search(conn: sqlite3.Connection, meta: dict, query: str, limit: int = 40,
	alt: list[int] | None = None) -> dict:
	"""Everything the query names: functions, symbols (globals, vtables, imports), strings."""
	hits = cache.find(conn, query, limit, alt)
	# A "string" defined inside a symbol table is a name, not data the program reads.
	hits["strings"] = [item for item in hits["strings"]
		if not (item["section"] or "").startswith((".strtab", ".dynstr", ".shstrtab", ".note"))]
	addresses = list(dict.fromkeys(
		[int(item["address"]) for item in hits["strings"]]
		+ [int(item["to_address"]) for item in hits["touching"] if item.get("to_address")]))
	# fetched wide, trimmed after filtering: the names that are *not* already functions are the
	# interesting ones and they sort last
	symbols = cache.symbol_rows(conn, "" if _is_address(query) else query, addresses, limit * 4)
	known = {int(row["entry"]) for row in hits["functions"]}
	hits["symbols"] = [dict(row) for row in symbols
		if int(row["address"]) not in known or row["type"] != "Function"][:limit]
	return hits


def _is_address(text: str) -> bool:
	value = (text or "").strip().lower()
	return value.startswith("0x") and len(value) > 2 and all(
		char in "0123456789abcdef" for char in value[2:])


def addresses_named(conn: sqlite3.Connection, hits: dict) -> list[int]:
	"""Every address a query resolved to, in the analysis' domain."""
	found: list[int] = []
	for row in hits.get("functions", []):
		found.append(int(row["entry"]))
	for row in hits.get("symbols", []):
		found.append(int(row["address"]))
	for row in hits.get("strings", []):
		found.append(int(row["address"]))
	return list(dict.fromkeys(found))


def xrefs(conn: sqlite3.Connection, addresses: list[int], limit: int = 60) -> list[dict]:
	"""The functions that reference these addresses, grouped, with the site of each one."""
	grouped: dict[int, dict] = {}
	order: list[int] = []
	for row in cache.xrefs_to(conn, addresses, limit * 4):
		entry = grouped.get(row["fn"])
		if entry is None:
			entry = grouped[row["fn"]] = {"id": row["fn"], "name": row["name"],
				"entry": row["entry"], "size": row["size"], "kind": row["kind"], "sites": []}
			order.append(row["fn"])
		entry["sites"].append({"address": row["address"], "to_address": row["to_address"],
			"to_name": row["to_name"], "to_kind": row["to_kind"], "ref_type": row["ref_type"],
			"text": row["text"] or ""})
	return [grouped[key] for key in order[:limit]]


# --------------------------------------------------------------------------------------
# the shape of an object: pointer tables in both directions


def _resolve(conn: sqlite3.Connection, image: extract.TargetImage, address: int) -> dict:
	"""What an address is: a function, a string, a symbol, or just an address."""
	row = cache.function_at(conn, address)
	if row is not None:
		namespace = row["namespace"] or ""
		qualified = row["name"] if namespace in ("", "Global", "<root>") else \
			"%s::%s" % (namespace.replace("::", "."), row["name"])
		return {"kind": "function", "name": qualified, "address": address,
			"size": row["size"], "section": row["section"]}
	strings = cache.strings_at(conn, [address])
	if address in strings:
		return {"kind": "string", "name": strings[address], "address": address}
	symbol = cache.nearest_symbol(conn, address)
	if symbol is not None:
		return {"kind": "object", "name": symbol[0], "address": symbol[1],
			"offset": address - symbol[1]}
	return {"kind": "address", "name": "0x%x" % address, "address": address}


def _meaningful(conn: sqlite3.Connection, image: extract.TargetImage, address: int) -> bool:
	"""Is a word a plausible pointer into this image - a function, an object, a string?"""
	if address <= 0:
		return False
	if cache.function_at(conn, address) is not None:
		return True
	if cache.strings_at(conn, [address]).get(address) is not None:
		return True
	symbol = cache.nearest_symbol(conn, address)
	return bool(symbol) and address - symbol[1] < 0x40


def table(conn: sqlite3.Connection, image: extract.TargetImage, address: int,
	bits: int = 64, length: int | None = None, limit: int = 32) -> dict:
	"""What the pointer slots of a data object point at - a vtable's methods, a jump table.

	Which source holds a pointer depends on how the file was linked: in a PIE the file bytes
	of .data.rel.ro are zeros and the value is the relocation's addend, in a non-PIE the value
	is written in the bytes. So: if anything in the range is relocated, those are the pointers
	(a range with no relocation in it holds no pointers); only where there are none are the
	bytes read as pointers. The object ends at the next symbol, or at the first gap in the
	pointer slots, whichever comes first.
	"""
	size = bits // 8
	next_symbol = cache.next_own_symbol(conn, address)
	bound = address + MAX_TABLE_BYTES if length is None else address + min(int(length), MAX_TABLE_BYTES)
	if next_symbol:
		bound = min(bound, int(next_symbol))
	slot_addresses = {key: value for key, value in image.pointers.items()
		if address <= key < bound and (key - address) % size == 0}
	named = {key: name for key, name in getattr(image, "named_pointers", {}).items()
		if address <= key < bound and (key - address) % size == 0}
	slot_addresses.update({key: None for key in named})
	byte_slots: set = set()
	if cache.strings_at(conn, [address]).get(address) is None:
		# The bytes are the other place a pointer can live (a non-PIE writes absolute addresses
		# with no relocation). Only keep a word that actually lands somewhere meaningful in
		# this image, and never read a defined string as if it were a table.
		raw = image.read_data(address, bound - address) or b""
		for offset in range(0, len(raw) - size + 1, size):
			value = int.from_bytes(raw[offset:offset + size], "little")
			slot = address + offset
			if slot in slot_addresses or not value:
				continue
			if _meaningful(conn, image, value):
				byte_slots.add(slot)
			slot_addresses.update({slot: None for slot in byte_slots if slot not in slot_addresses})
		if raw:
			bound = min(bound, address + len(raw))
	# stop at the first gap: an object's pointer slots are contiguous
	ordered = sorted(slot_addresses)
	if ordered:
		keep = [ordered[0]]
		for slot in ordered[1:]:
			if slot != keep[-1] + size:
				break
			keep.append(slot)
		slot_addresses = {slot: slot_addresses[slot] for slot in keep}
		bound = max(bound, keep[-1] + size) if keep else bound
	slots = []
	for slot in sorted(slot_addresses):
		if slot in named:
			target = {"kind": "import", "name": demangled(named[slot]), "address": None}
		elif slot in byte_slots:
			target = _resolve(conn, image, int.from_bytes(
				(image.read_data(slot, bits // 8) or b""), "little"))
		else:
			target = _resolve(conn, image, slot_addresses[slot])
		near = cache.nearest_symbol(conn, slot)
		slots.append({"slot": slot, "inside": near[0] if near else "",
			"offset": slot - (near[1] if near else slot), "target": target})
	return {"address": address, "bytes": bound - address, "slots": slots[:limit],
		"count": len(slots)}


def holders(conn: sqlite3.Connection, image: extract.TargetImage, address: int,
	limit: int = 20) -> list[dict]:
	"""The objects that hold a pointer to `address` - which vtables a method belongs to."""
	found: list[dict] = []
	for slot, target in image.pointers.items():
		if target != address:
			continue
		near = cache.nearest_symbol(conn, slot)
		found.append({"slot": slot, "inside": near[0] if near else "",
			"offset": slot - (near[1] if near else slot)})
		if len(found) >= limit:
			break
	return found


def members_of(conn: sqlite3.Connection, image: extract.TargetImage, fn_id: int,
	entry: int, bits: int = 64, limit: int = 24) -> list[dict]:
	"""The other functions that share a vtable with this one, via the objects pointing at it."""
	members: list[dict] = []
	for holder in holders(conn, image, entry, limit=4):
		owner = holder["inside"]
		if not owner:
			continue
		start = holder["slot"] - holder["offset"]
		for slot in table(conn, image, start, bits=bits, limit=limit)["slots"]:
			target = slot["target"]
			if target["kind"] == "function" and target["address"] != entry:
				row = cache.function_at(conn, target["address"])
				if row is not None:
					members.append({"vtable": owner, "id": row["id"], "name": target["name"],
						"entry": row["entry"], "size": row["size"], "slot": slot["slot"]})
	return members


# --------------------------------------------------------------------------------------
# the group a query is asking about


def _neighbours(conn: sqlite3.Connection, ids: list[int]) -> list[tuple[int, int]]:
	"""(other, from) for every call edge touching these functions, in both directions."""
	if not ids:
		return []
	marks = ",".join("?" * len(ids))
	rows = conn.execute(
		"SELECT c.caller AS other, c.callee AS from_fn FROM calls c WHERE c.callee IN (%s)"
		" UNION SELECT c.callee, c.caller FROM calls c WHERE c.caller IN (%s)" % (marks, marks),
		ids + ids)
	return [(int(row["other"]), int(row["from_fn"])) for row in rows]


def family(conn: sqlite3.Connection, seeds: list[int], hops: int = 1, limit: int = 40) -> dict:
	"""Grow a set of functions along the call graph and rank what comes back.

	`seeds` are function ids - whatever the query named. Everything within `hops` call edges
	is collected, then scored: an edge to a seed counts most, then reaching the same globals,
	vtables and strings the seeds reach, then edges into the group. The result is ordered the
	way an LLM should work through it: most connected first, smallest body first.
	"""
	seed_ids = [int(item) for item in seeds]
	if not seed_ids:
		return {"members": [], "shared": [], "seeds": []}
	marks = ",".join("?" * len(seed_ids))
	seed_rows = {row["id"]: row for row in conn.execute(
		"SELECT id, name, entry, size, kind FROM functions WHERE id IN (%s)" % marks, seed_ids)}

	# What the seeds reach: the data half of "related", shared by everything in the group.
	shared: dict[tuple, dict] = {}
	for fn_id in seed_rows:
		for target in cache.targets_of(conn, fn_id):
			# only objects count as shared: a call is a call, and a label inside a body is a
			# jump target, not something two functions have in common
			if target["is_call"] or target["kind"] == "function" or (target["address"]
					and cache.inside_function(conn, target["address"])):
				continue
			key = (target["kind"], target["address"] or target["name"])
			if key in shared:
				shared[key]["seeds"] += 1
			else:
				shared[key] = dict(target, seeds=1)

	members: dict[int, dict] = {}
	frontier, seen = list(seed_rows), set(seed_rows)
	for hop in range(max(0, int(hops))):
		next_frontier = []
		for other, source in _neighbours(conn, frontier):
			if other in seen:
				continue
			seen.add(other)
			next_frontier.append(other)
			members[other] = {"hop": hop + 1, "via": source}
		frontier = next_frontier

	group = set(members)
	ranked: list[dict] = []
	for fn_id, info in seed_rows.items():
		ranked.append({"id": fn_id, "name": info["name"], "entry": info["entry"],
			"size": info["size"], "kind": info["kind"], "hop": 0, "score": 1000,
			"why": ["named by the query"]})
	for fn_id, info in members.items():
		row = cache.function_row(conn, fn_id)
		if row is None:
			continue
		seed_marks = ",".join("?" * len(seed_rows))
		edges = conn.execute(
			"SELECT count(*) FROM calls WHERE (caller = ? AND callee IN (%s))"
			" OR (callee = ? AND caller IN (%s))" % (seed_marks, seed_marks),
			[fn_id] + list(seed_rows) + [fn_id] + list(seed_rows)).fetchone()[0]
		reaches = [target for target in cache.targets_of(conn, fn_id)
			if (target["kind"], target["address"] or target["name"]) in shared]
		inside = 0
		if group:
			group_marks = ",".join("?" * len(group))
			inside = conn.execute(
				"SELECT count(*) FROM calls WHERE (caller = ? AND callee IN (%s))"
				" OR (callee = ? AND caller IN (%s))" % (group_marks, group_marks),
				[fn_id] + list(group) + [fn_id] + list(group)).fetchone()[0]
		score = edges * 6 + len(reaches) * 3 + inside
		if not score:
			continue
		why = []
		if edges:
			why.append("%d call edge%s to what the query named"
				% (edges, "" if edges == 1 else "s"))
		if reaches:
			why.append("reaches %d of the same objects: %s" % (len(reaches),
				", ".join(sorted({str(item["name"]) for item in reaches})[:4])))
		if inside:
			why.append("%d call edge%s inside the group" % (inside, "" if inside == 1 else "s"))
		ranked.append({"id": fn_id, "name": row["name"], "entry": row["entry"],
			"size": row["size"], "kind": row["kind"], "hop": info["hop"], "score": score,
			"why": why})
	ranked.sort(key=lambda item: (-item["score"], item["size"], item["entry"]))
	shared_rows = sorted((dict(item) for item in shared.values() if item["kind"] != "function"),
		key=lambda item: -item["seeds"])
	return {"members": ranked[:limit], "shared": shared_rows[:limit],
		"seeds": [{"id": row["id"], "name": row["name"], "entry": row["entry"]}
			for row in seed_rows.values()]}
