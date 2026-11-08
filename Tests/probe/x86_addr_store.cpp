// Tests/probe/x86_addr_store.cpp - the smallest source that makes a 32-bit object store an
// address through a register-relative operand.
//
// Why this is a probe and not a benchmark unit: it isolates one question about the *candidate
// side* of the differ, with no target involved. In a 32-bit object the value is still zero and a
// relocation (IMAGE_REL_I386_DIR32 / R_386_32) sits on the four bytes of the instruction's
// immediate. The same instruction also has a memory operand, and a slot list built from
// instruction length alone will claim those same four bytes as a displacement. Which operand the
// relocation belongs to is not a style question: bind it to the displacement and the object the
// code reaches disappears from the candidate side, so a field the link fills in is reported as an
// operand difference (Docs/x86-32bit-issues.md §37).
//
// Compiling this with any C++ front end for i386 gives the three shapes:
//   store_global   movl $0, (%ecx)            + DIR32 -> the global          (field +0)
//   store_field    movl $0, 8(%esi)           + DIR32 -> the global          (field +8)
//   store_local    movl $0, 0xc(%esp)         + DIR32 -> the global          (a stack slot)
// A constant store (`store_constant`) is here on purpose as the control: it has the same shape
// with no relocation, and must keep its immediate as a literal.

struct Sink
{
	int *p;
	int n;
	int *q;
};

int g_slot;

void store_global(Sink *s) { s->p = &g_slot; }
void store_field(Sink *s) { s->q = &g_slot; }
void store_local(Sink *s) { int *volatile t = &g_slot; (void) t; if (s) s->n = 1; }
void store_constant(Sink *s) { s->n = 0x1234; }
