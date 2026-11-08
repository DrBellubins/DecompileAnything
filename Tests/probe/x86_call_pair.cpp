// Tests/probe/x86_call_pair.cpp - what a call to another function of the same translation unit
// looks like in the object file.
//
// A caller and a callee in one source file are the ordinary shape of a decompilation project: a
// subsystem is recovered file by file, and the functions of a subsystem call each other. The
// linked image then holds a plain `call <address>`. The object does not, and how it differs
// depends on one flag:
//
//   default   every function of the TU shares one `.text$mn`: the call has **no relocation**, and
//             the address in it is final at assembly time, so the callee is found by looking up
//             that address in the section.
//   /Gy       the front end gives every function its own section - and every one of those sections
//             has the same name (`.text$mn` here, plain `.text` from an MSVC 9 driver). The call's
//             relocation record then names the callee's **section symbol**, because this object has
//             no symbol for the callee at all, and the four bytes in the code hold 0, which
//             disassembles as a call to the instruction after it.
//
// /Gy is not exotic: it is what an optimizing build of this era ships, and it is the shape the
// candidate objects of a real 32-bit target have (Docs/x86-32bit-issues.md §39). Reading the
// unfilled field as an address puts the target *inside the caller's own body* - both sections
// start at offset 0 - and a tool that believes the address turns the call into a jump to a label
// inside the unit, then reports an operand difference on a field the link writes.
//
// `calls_itself` is here as the control in the other direction: a self-recursive call really is an
// edge inside the unit, and both sides of a comparison must still see it as one.

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

NOINLINE int inner_of_this_unit(int v)
{
	return v + 3;
}

NOINLINE int calls_its_own_unit(int v)
{
	return inner_of_this_unit(v) + 1;
}

NOINLINE int calls_itself(int v)
{
	return v ? calls_itself(v - 1) + 1 : 0;
}
