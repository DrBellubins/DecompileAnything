// A class full of various math equations, which make heavy use of while/for loop comparisons, and vector math.
#ifndef DA_TESTFUNCTIONS_MATH_H
#define DA_TESTFUNCTIONS_MATH_H

#include "SelfTest.h"

class CSelfTest;

// Vector types used by the vector-math units. Plain aggregates on purpose: how a
// 12-byte struct is passed and returned is part of what the decompiler has to recover.
struct CVec2
{
	float m_x;
	float m_y;
};

struct CVec3
{
	float m_x;
	float m_y;
	float m_z;
};

struct CVec4
{
	float m_x;
	float m_y;
	float m_z;
	float m_w;
};

struct CMatrix3
{
	float m_m[3][3];
};

// Running statistics state, exercised by the instance-method units.
class CMathTests
{
public:
	// --- integer loops and comparisons ---
	static DA_NOINLINE int AbsDiff(int a, int b);
	static DA_NOINLINE int ClampRange(int value, int low, int high);
	static DA_NOINLINE int SumTo(int count);
	static DA_NOINLINE int SumSquaresTo(int count);
	static DA_NOINLINE int SumEvenBelow(int limit);
	static DA_NOINLINE int GreatestCommonDivisor(int a, int b);
	static DA_NOINLINE int CollatzSteps(int startValue);
	static DA_NOINLINE int CountSetBits(unsigned int value);
	static DA_NOINLINE unsigned int ReverseBits(unsigned int value);
	static DA_NOINLINE int IntegerSquareRoot(int value);
	static DA_NOINLINE int BinarySearchKey(int key);
	static DA_NOINLINE unsigned int HashMix32(unsigned int value);
	static DA_NOINLINE unsigned int Crc32OfBuffer(const unsigned char *data, int length);
	static DA_NOINLINE int CountPrimesUpTo(int limit);
	static DA_NOINLINE int FibonacciAt(int index);
	static DA_NOINLINE int FibonacciRecursive(int index);
	static DA_NOINLINE int SaturatingAdd(int a, int b);
	static DA_NOINLINE int SignOf(int value);
	static DA_NOINLINE int ParityOf(unsigned int value);
	static DA_NOINLINE int FixedPointMultiply(int a, int b, int shiftAmount);

	// --- float and vector math ---
	static DA_NOINLINE float SquareRootNewton(float value);
	static DA_NOINLINE float WrapAngle180(float angle);
	static DA_NOINLINE float SmoothstepBlend(float a, float b, float t);
	static DA_NOINLINE float SineApprox(float angle);
	static DA_NOINLINE float Atan2Approx(float y, float x);
	static DA_NOINLINE float SolveQuadraticRoot(float a, float b, float c, int whichRoot);
	static DA_NOINLINE float Vec3LengthSq(const CVec3 &v);
	static DA_NOINLINE CVec3 Vec3Cross(const CVec3 &a, const CVec3 &b);
	static DA_NOINLINE CVec3 Vec3Normalize(const CVec3 &v);
	static DA_NOINLINE CVec3 Vec3Reflect(const CVec3 &incident, const CVec3 &normal);
	static DA_NOINLINE float TriangleArea3(const CVec3 &a, const CVec3 &b, const CVec3 &c);
	static DA_NOINLINE bool BoxesOverlap(const CVec3 &aMin, const CVec3 &aMax, const CVec3 &bMin, const CVec3 &bMax);
	static DA_NOINLINE void Matrix3Multiply(const CMatrix3 &a, const CMatrix3 &b, CMatrix3 *out);
	static DA_NOINLINE int NearestTableIndex(float value);

	// --- instance state ---
	CMathTests() { ResetStats(); }
	DA_NOINLINE void ResetStats();
	DA_NOINLINE void PushSample(float sample);
	DA_NOINLINE float MeanOfSamples() const;
	DA_NOINLINE float VarianceOfSamples() const;
	int SampleCount() const { return m_sampleCount; }

	static DA_NOINLINE void RunSelfChecks(CSelfTest &selfTest);

private:
	float m_sum;
	float m_sumSquares;
	float m_largest;
	float m_smallest;
	int m_sampleCount;
};

#endif // DA_TESTFUNCTIONS_MATH_H
