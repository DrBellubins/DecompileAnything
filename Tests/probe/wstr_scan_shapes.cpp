// Tests/probe/wstr_scan_shapes.cpp - which C spelling makes VC 9's wide-string length scan.
//
// Several bodies of a 32-bit MSVC target scan for the terminator and then recover a count by
// subtracting, e.g. WinRAR.exe 0x455e10 and 0x455790:
//	movw (%eax),%cx / addl $2,%eax / testw %cx,%cx / jne <loop>
//	subl %esi,%eax / sarl $1,%eax
//The loop *loads, advances, then tests*, with the test at the bottom; and the count comes out of
//`end - (start + 1)` in wide units, not `end - start`. Those two details are what decide whether a
//candidate of that shape matches, so the spellings are tried side by side here and the objects are
//read with llvm-objdump rather than argued about.

#include <windows.h>

wchar_t *scan_pre(wchar_t *p)			// while (*p) ++p;
{
	wchar_t *pEnd = p;
	while (*pEnd)
		pEnd++;
	return pEnd;
}

wchar_t *scan_post(wchar_t *p)		// while (*p++) ;
{
	wchar_t *pEnd = p;
	while (*pEnd++)
		;
	return pEnd;
}

wchar_t *scan_for(wchar_t *p)			// for (; *p; ++p) ;
{
	wchar_t *pEnd;
	for (pEnd = p; *pEnd; ++pEnd)
		;
	return pEnd;
}

int count_minus_one(wchar_t *p)		// the subtraction these bodies do
{
	wchar_t *pEnd = p;
	while (*pEnd)
		pEnd++;
	return (int) (pEnd - (p + 1));
}
