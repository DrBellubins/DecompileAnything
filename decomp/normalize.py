"""Instruction text from bytes - the one representation both sides of a diff share.

Phase 1 uses this to store the original function's instruction stream in the analysis cache
alongside Ghidra's own instruction boundaries (Ghidra decides where instructions start, the
decoder here decides how they read). Phase 2 decodes the candidate `.o` with the same
decoder and then adds name normalisation and the categorised diff on top.

x86 is decoded in AT&T syntax, which is what `objdump -d` prints, so a candidate read from
a `.o` with objdump and one read from a `.o` here line up token for token.
"""

from __future__ import annotations

from capstone import CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64, CS_OPT_SYNTAX_ATT, Cs

# Ghidra language ids look like x86:LE:64:default.
_MODES = {"16": CS_MODE_16, "32": CS_MODE_32, "64": CS_MODE_64}


def capstone_for(language_id: str) -> Cs | None:
	"""A decoder for a Ghidra language id, or None when this arch is not supported yet."""
	parts = (language_id or "").split(":")
	if len(parts) < 3 or parts[0] != "x86":
		return None
	mode = _MODES.get(parts[2])
	if mode is None:
		return None
	if parts[1] != "LE":
		return None
	handle = Cs(CS_ARCH_X86, mode)
	handle.syntax = CS_OPT_SYNTAX_ATT
	handle.detail = False
	return handle


def decode(handle: Cs, data: bytes, address: int) -> tuple[str, str, int] | None:
	"""Decode exactly one instruction at `address`: (mnemonic, operand text, length)."""
	for instruction in handle.disasm(data, address, count=1):
		return instruction.mnemonic, instruction.op_str, instruction.size
	return None


def format_instruction(mnemonic: str, operands: str) -> str:
	return ("%s %s" % (mnemonic, operands)).strip()
