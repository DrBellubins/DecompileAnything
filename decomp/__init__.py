"""decomp - a stateless CLI that lets an LLM iterate a decompilation until the bytes match.

The tool never edits source: it reports facts about the original binary (from a cached
Ghidra analysis) and scores a candidate the caller compiled. See Docs/Design-Plan.md.
"""

from __future__ import annotations

__version__ = "0.1.0"
