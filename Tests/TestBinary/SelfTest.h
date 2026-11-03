// Shared self-check + golden-trace harness used by every test module.
//
// Why it exists:
//   * it *calls* every unit, so every unit is reachable code and survives as its own
//     function body in the -O2 build too (that is what the decompiler is scored on);
//   * it records (inputs -> results) as a golden trace the evaluation harness can diff
//     between builds, and between the original and a candidate;
//   * it hand-checks the results we know off-line (CRC-32 of "123456789", gcd(1071,462),
//     the 27-number Collatz length, ...) so the ground truth of this benchmark is
//     itself tested and not just asserted.
//
// Unit annotation convention, read by Tests/Harness/manifest.py. It goes directly above
// the *definition* of every unit in the module .cpp files:
//
//   // DA-UNIT <ID> level:<easy|medium|hard> tags:<comma,separated,tags>
//
// See Tests/README.md for the tag vocabulary and the evaluation protocol.
#ifndef DA_SELFTEST_H
#define DA_SELFTEST_H

// Units are marked noinline so no caller can absorb them: exactly one body per unit,
// at exactly one address, at every optimisation level. Plain helpers deliberately do
// not carry this, so they get inlined into units at -O2 like in any real binary.
#if defined(_MSC_VER)
#define DA_NOINLINE __declspec(noinline)
#else
#define DA_NOINLINE __attribute__((noinline))
#endif

class CSelfTest
{
public:
	enum EMode
	{
		MODE_REPORT,	// human readable pass/fail summary
		MODE_GOLDEN		// one JSON record per case on stdout
	};

	explicit CSelfTest(EMode mode);

	// Inputs. Deterministic per run, opaque to the compiler, and recorded into the
	// case's argument list so a golden can be replayed.
	int AcceptInt(int lo, int hi);
	unsigned int AcceptBits();
	float AcceptFloat(float lo, float hi);

	// Results of the case currently open.
	void OutInt(const char *tag, long long value);
	void OutUInt(const char *tag, unsigned long long value);
	void OutFloat(const char *tag, float value);
	void OutBool(const char *tag, bool value);
	void OutText(const char *tag, const char *value);
	void OutBlob(const char *tag, const void *value, int length);

	// Optional hand checks against the value last recorded with the same tag.
	void WantInt(const char *tag, long long expected);
	void WantUInt(const char *tag, unsigned long long expected);
	void WantFloat(const char *tag, float expected, float tolerance = 0.0f);
	void WantText(const char *tag, const char *expected);
	void WantBool(const char *tag, bool expected);

	// Case bookkeeping - use the DA_CASE macro rather than calling these directly.
	void BeginCase(const char *unitId);
	void EndCase();

	int Report() const;			// prints the summary, returns the failure count
	int FailureCount() const { return m_failures; }
	int CaseCount() const { return m_cases; }

private:
	struct SValue
	{
		char m_tag[24];
		char m_json[280];		// JSON value as it lands in the golden record
		char m_raw[160];		// unrendered text, for WantText
		double m_num;			// numeric value, for WantFloat tolerances
	};

	unsigned int NextBits();
	void AppendArg(const char *rendered);
	SValue *FindSlot(const char *tag);
	static void EscapeInto(char *out, int capacity, const char *in);
	void Fail(const char *what, const char *tag, const char *want, const char *got);

	EMode m_mode;
	unsigned int m_rng;
	char m_unitId[16];
	int m_caseIndex;
	char m_lastUnitId[16];		// consecutive cases with the same id are numbered
	int m_lastCaseIndex;
	SValue m_slots[12];
	int m_slotCount;
	char m_argsJson[512];		// arguments produced by Accept*, in call order
	int m_argsLen;
	int m_cases;
	int m_failures;
};

// Opens a case for one unit and emits its golden record when the scope ends. Multiple
// cases for the same unit must be written next to each other (they are numbered 0,1,...).
class CCaseScope
{
public:
	CCaseScope(CSelfTest &selfTest, const char *unitId) : m_selfTest(selfTest)
	{
		m_selfTest.BeginCase(unitId);
	}
	~CCaseScope() { m_selfTest.EndCase(); }

private:
	CCaseScope &operator=(const CCaseScope &);
	CCaseScope(const CCaseScope &);

	CSelfTest &m_selfTest;
};

#define DA_CASE(selfTest, unitId) CCaseScope da_caseScope(selfTest, unitId)

#endif // DA_SELFTEST_H
