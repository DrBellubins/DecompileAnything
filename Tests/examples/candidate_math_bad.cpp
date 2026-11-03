// A deliberately imperfect candidate, used to check that the scorer reports the right
// kind of problem. Not part of the benchmark binary.
//
//   python3 eval.py try --unit MATH-02 --src examples/candidate_math_bad.cpp --fn ClampRange
//   python3 eval.py try --unit MATH-38 --src examples/candidate_math_bad.cpp --fn ParityOf
//   python3 eval.py try --unit STR-01  --src examples/candidate_math_bad.cpp --fn LengthOf

// Wrong control flow: the inverted-range guard is gone and the bounds are compared with
// the wrong operands. Expect operand + missing categories, not just a lower ratio.
int ClampRangeProbe(int value, int low, int high)
{
	if (value < low)
		return high;
	if (value > high)
		return low;
	return value;
}

// Wrong algorithm: parity by counting bits instead of folding. Same result, different
// opcode stream - a behavioural test would pass, this one must not.
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
// sentinel test. Expect extra/missing.
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
