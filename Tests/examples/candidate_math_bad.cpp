// A deliberately imperfect candidate, used to check that the scorer reports the right
// kind of problem. Not part of the benchmark binary.
//
//   .venv/bin/decomp try <address of MATH-02> examples/candidate_math_bad.cpp --fn ClampRangeProbe
//   .venv/bin/decomp try <address of MATH-38> examples/candidate_math_bad.cpp --fn ParityOfProbe
//   .venv/bin/decomp try <address of STR-01>  examples/candidate_math_bad.cpp --fn LengthOfProbe
//
// Tests/tools/check_phase2_try.py runs exactly these three and requires the report to name
// the kind of problem each one is and to refuse them: 6 operand differences plus the 5 lines
// the dropped guard used to have, 14 missing and 8 extra against 1 operand, 2 missing and 3
// extra against 1 opcode.

// Wrong control flow: the inverted-range guard is gone and the bounds are compared with
// the wrong operands. Reported as 6 operand differences plus the 5 lines the removed guard
// had, not just a lower ratio.
int ClampRangeProbe(int value, int low, int high)
{
	if (value < low)
		return high;
	if (value > high)
		return low;
	return value;
}

// Wrong algorithm: parity by counting bits instead of folding. Same result, different
// opcode stream - a behavioural test would pass, this one must not. Reported as 14 missing +
// 8 extra against 1 operand.
int ParityOfProbe(unsigned int value)
{
	int count = 0;
	while (value != 0u)
	{
		count += (int)(value & 1u);
		value >>= 1;
	}
	return count & 1;
}

// Right algorithm, deliberately different loop shape: counted loop instead of the
// sentinel test. Reported as 2 missing + 3 extra against 1 opcode.
int LengthOfProbe(const char *text)
{
	int length = 0;
	for (;;)
	{
		if (text[length] == 0)
			break;
		++length;
	}
	return length;
}
