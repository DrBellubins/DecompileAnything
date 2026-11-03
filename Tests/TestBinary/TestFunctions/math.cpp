// Implementation of the math units. See math.h for the unit list.
//
// Every unit marked DA-UNIT is scored by Tests/eval.py, so they are kept short and
// single-purpose: that is the size range the decompiler loop is actually judged on.
#include "math.h"

#include <cmath>

// --- read only data the units search: the values are part of the expected answer ---
static const short k_chokeThresholds[12] = {
	-972, -643, -455, -326, -228, -150, -86, -31, 18, 62, 109, 162
};

static const float k_lodDistances[8] = {
	4.0f, 12.0f, 30.0f, 75.0f, 180.0f, 420.0f, 950.0f, 2100.0f
};

// --- lazily built table in .bss: exercises static state plus an inlined helper ---
static unsigned int g_crcTable[256];
static bool g_crcTableReady = false;

static void BuildCrcTable()
{
	for (int index = 0; index < 256; ++index)
	{
		unsigned int crc = (unsigned int)index;
		for (int bit = 0; bit < 8; ++bit)
		{
			if ((crc & 1u) != 0u)
				crc = 0xEDB88320u ^ (crc >> 1);
			else
				crc = crc >> 1;
		}
		g_crcTable[index] = crc;
	}
	g_crcTableReady = true;
}

// DA-UNIT MATH-01 level:easy tags:cmp,branch,int
int CMathTests::AbsDiff(int a, int b)
{
	int delta = a - b;
	if (delta < 0)
		delta = -delta;
	return delta;
}

// DA-UNIT MATH-02 level:easy tags:cmp,branch,int
int CMathTests::ClampRange(int value, int low, int high)
{
	if (high < low)
		return low;
	if (value < low)
		return low;
	if (value > high)
		return high;
	return value;
}

// DA-UNIT MATH-03 level:easy tags:for,cmp,int
int CMathTests::SumTo(int count)
{
	int total = 0;
	for (int index = 1; index <= count; ++index)
		total += index;
	return total;
}

// DA-UNIT MATH-04 level:easy tags:for,mul,int
int CMathTests::SumSquaresTo(int count)
{
	int total = 0;
	for (int index = 1; index <= count; ++index)
		total += index * index;
	return total;
}

// DA-UNIT MATH-05 level:medium tags:for,guard,bitops,int
int CMathTests::SumEvenBelow(int limit)
{
	int total = 0;
	for (int index = 0; index < limit; ++index)
	{
		if ((index & 1) == 0)
			total += index;
	}
	return total;
}

// DA-UNIT MATH-06 level:medium tags:while,div,int
int CMathTests::GreatestCommonDivisor(int a, int b)
{
	if (a < 0)
		a = -a;
	if (b < 0)
		b = -b;
	while (b != 0)
	{
		int remainder = a % b;
		a = b;
		b = remainder;
	}
	return a;
}

// DA-UNIT MATH-07 level:medium tags:while,bitops,guard,int
int CMathTests::CollatzSteps(int startValue)
{
	if (startValue <= 0)
		return -1;
	int steps = 0;
	int current = startValue;
	while (current != 1)
	{
		if ((current & 1) != 0)
			current = 3 * current + 1;
		else
			current >>= 1;
		++steps;
		if (steps >= 1000)
			return -1;
	}
	return steps;
}

// DA-UNIT MATH-08 level:easy tags:while,bitops,unsigned
int CMathTests::CountSetBits(unsigned int value)
{
	int count = 0;
	while (value != 0u)
	{
		value &= (value - 1u);
		++count;
	}
	return count;
}

// DA-UNIT MATH-09 level:medium tags:bitops,unsigned,const
unsigned int CMathTests::ReverseBits(unsigned int value)
{
	value = ((value & 0x55555555u) << 1) | ((value >> 1) & 0x55555555u);
	value = ((value & 0x33333333u) << 2) | ((value >> 2) & 0x33333333u);
	value = ((value & 0x0F0F0F0Fu) << 4) | ((value >> 4) & 0x0F0F0F0Fu);
	value = ((value & 0x00FF00FFu) << 8) | ((value >> 8) & 0x00FF00FFu);
	return (value << 16) | (value >> 16);
}

// DA-UNIT MATH-10 level:medium tags:while,binary-search,int64
int CMathTests::IntegerSquareRoot(int value)
{
	if (value < 0)
		return -1;
	int low = 0;
	int high = 46341;
	while (low < high)
	{
		int middle = low + ((high - low + 1) >> 1);
		if ((long long)middle * (long long)middle <= (long long)value)
			low = middle;
		else
			high = middle - 1;
	}
	return low;
}

// DA-UNIT MATH-11 level:medium tags:while,binary-search,rdata-table,signed-load
int CMathTests::BinarySearchKey(int key)
{
	int low = 0;
	int high = 11;
	while (low <= high)
	{
		int middle = (low + high) >> 1;
		int probe = k_chokeThresholds[middle];
		if (probe == key)
			return middle;
		if (probe < key)
			low = middle + 1;
		else
			high = middle - 1;
	}
	return -(low + 1);
}

// DA-UNIT MATH-12 level:medium tags:mul,shift,xor,unsigned,const
unsigned int CMathTests::HashMix32(unsigned int value)
{
	unsigned int mixed = value;
	mixed ^= (mixed >> 16);
	mixed *= 0x85ebca6bu;
	mixed ^= (mixed >> 13);
	mixed *= 0xc2b2ae35u;
	mixed ^= (mixed >> 16);
	return mixed;
}

// DA-UNIT MATH-13 level:hard tags:for,table,static-state,unsigned
unsigned int CMathTests::Crc32OfBuffer(const unsigned char *data, int length)
{
	if (!g_crcTableReady)
		BuildCrcTable();
	unsigned int crc = 0xFFFFFFFFu;
	for (int index = 0; index < length; ++index)
		crc = g_crcTable[(crc ^ (unsigned int)data[index]) & 0xFFu] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFFu;
}

// DA-UNIT MATH-14 level:hard tags:nested-loop,while,div,guard
int CMathTests::CountPrimesUpTo(int limit)
{
	if (limit < 2)
		return 0;
	int count = 0;
	for (int candidate = 2; candidate <= limit; ++candidate)
	{
		int divisor = 2;
		int isPrime = 1;
		while (divisor * divisor <= candidate)
		{
			if (candidate % divisor == 0)
			{
				isPrime = 0;
				break;
			}
			++divisor;
		}
		count += isPrime;
	}
	return count;
}

// DA-UNIT MATH-15 level:easy tags:for,int
int CMathTests::FibonacciAt(int index)
{
	if (index < 0)
		return 0;
	int previous = 0;
	int current = 1;
	for (int i = 0; i < index; ++i)
	{
		int next = previous + current;
		previous = current;
		current = next;
	}
	return previous;
}

// DA-UNIT MATH-16 level:medium tags:recursion,frame,guard
int CMathTests::FibonacciRecursive(int index)
{
	if (index < 2)
		return index;
	return FibonacciRecursive(index - 1) + FibonacciRecursive(index - 2);
}

// DA-UNIT MATH-17 level:medium tags:overflow,guard,int64
int CMathTests::SaturatingAdd(int a, int b)
{
	long long sum = (long long)a + (long long)b;
	if (sum > 2147483647LL)
		return 2147483647;
	if (sum < -2147483648LL)
		return (-2147483647 - 1);
	return (int)sum;
}

// DA-UNIT MATH-37 level:easy tags:cmp,bool,int
int CMathTests::SignOf(int value)
{
	return (value > 0) - (value < 0);
}

// DA-UNIT MATH-38 level:easy tags:bitops,xor,unsigned
int CMathTests::ParityOf(unsigned int value)
{
	value ^= (value >> 16);
	value ^= (value >> 8);
	value ^= (value >> 4);
	return (int)((0x6996u >> (value & 0xFu)) & 1u);
}

// DA-UNIT MATH-18 level:medium tags:int64,mul,shift,guard
int CMathTests::FixedPointMultiply(int a, int b, int shiftAmount)
{
	if (shiftAmount < 0)
		shiftAmount = 0;
	if (shiftAmount > 31)
		shiftAmount = 31;
	long long wide = (long long)a * (long long)b;
	if (shiftAmount > 0)
		wide += (1LL << (shiftAmount - 1));
	return (int)(wide >> shiftAmount);
}

// DA-UNIT MATH-19 level:hard tags:while,float,div,guard
float CMathTests::SquareRootNewton(float value)
{
	if (value <= 0.0f)
		return 0.0f;
	float guess = value * 0.5f + 0.5f;
	int guard = 0;
	while (guard < 40)
	{
		float next = (guess + value / guess) * 0.5f;
		float delta = next - guess;
		if (delta < 0.0f)
			delta = -delta;
		guess = next;
		++guard;
		if (delta <= guess * 1.0e-6f)
			break;
	}
	return guess;
}

// DA-UNIT MATH-20 level:hard tags:while,float,const
float CMathTests::WrapAngle180(float angle)
{
	while (angle > 180.0f)
		angle -= 360.0f;
	while (angle < -180.0f)
		angle += 360.0f;
	return angle;
}

// DA-UNIT MATH-21 level:medium tags:float,clamp,poly
float CMathTests::SmoothstepBlend(float a, float b, float t)
{
	float f = t;
	if (f < 0.0f)
		f = 0.0f;
	if (f > 1.0f)
		f = 1.0f;
	return a + (b - a) * (f * f * (3.0f - 2.0f * f));
}

// DA-UNIT MATH-22 level:hard tags:while,for,float,poly
float CMathTests::SineApprox(float angle)
{
	float wrapped = angle;
	while (wrapped > 3.14159274f)
		wrapped -= 6.28318548f;
	while (wrapped < -3.14159274f)
		wrapped += 6.28318548f;
	float term = wrapped;
	float total = wrapped;
	float squared = wrapped * wrapped;
	for (int n = 1; n < 8; ++n)
	{
		int order = (2 * n) * (2 * n + 1);
		term *= -squared / (float)order;
		total += term;
	}
	return total;
}

// DA-UNIT MATH-23 level:hard tags:float,branch,poly,div,const
float CMathTests::Atan2Approx(float y, float x)
{
	const float halfPi = 1.57079637f;
	const float pi = 3.14159274f;
	if (x == 0.0f && y == 0.0f)
		return 0.0f;
	float absX = (x < 0.0f) ? -x : x;
	float absY = (y < 0.0f) ? -y : y;
	bool steep = !(absX > absY);
	float ratio = steep ? (absX / absY) : (absY / absX);
	float s = ratio * ratio;
	float poly = ratio * (1.0f + s * (-0.33333334f + s * (0.2f + s * (-0.14285715f + s * 0.11111111f))));
	float angle = steep ? (halfPi - poly) : poly;
	if (x < 0.0f)
		angle = pi - angle;
	if (y < 0.0f)
		angle = -angle;
	return angle;
}

// DA-UNIT MATH-24 level:hard tags:switch,float,div,call-unit,guard
float CMathTests::SolveQuadraticRoot(float a, float b, float c, int whichRoot)
{
	if (a == 0.0f)
	{
		if (b == 0.0f)
			return 0.0f;
		return -c / b;
	}
	float discriminant = b * b - 4.0f * a * c;
	if (discriminant < 0.0f)
		return 0.0f;
	float root = SquareRootNewton(discriminant);
	float invTwiceA = 0.5f / a;
	switch (whichRoot)
	{
		case 0:
			return (-b - root) * invTwiceA;
		case 1:
			return (-b + root) * invTwiceA;
		default:
			return -b * invTwiceA;
	}
}

// DA-UNIT MATH-25 level:easy tags:sse,struct-arg,float
float CMathTests::Vec3LengthSq(const CVec3 &v)
{
	return v.m_x * v.m_x + v.m_y * v.m_y + v.m_z * v.m_z;
}

// DA-UNIT MATH-26 level:medium tags:sse,struct-return,float
CVec3 CMathTests::Vec3Cross(const CVec3 &a, const CVec3 &b)
{
	CVec3 out;
	out.m_x = a.m_y * b.m_z - a.m_z * b.m_y;
	out.m_y = a.m_z * b.m_x - a.m_x * b.m_z;
	out.m_z = a.m_x * b.m_y - a.m_y * b.m_x;
	return out;
}

// DA-UNIT MATH-27 level:medium tags:sse,struct-return,call-unit,guard,float
CVec3 CMathTests::Vec3Normalize(const CVec3 &v)
{
	CVec3 out = v;
	float lengthSq = Vec3LengthSq(v);
	if (lengthSq < 1.0e-12f)
	{
		out.m_x = 0.0f;
		out.m_y = 0.0f;
		out.m_z = 1.0f;
		return out;
	}
	float invLength = 1.0f / SquareRootNewton(lengthSq);
	out.m_x *= invLength;
	out.m_y *= invLength;
	out.m_z *= invLength;
	return out;
}

// DA-UNIT MATH-28 level:medium tags:sse,struct-return,float
CVec3 CMathTests::Vec3Reflect(const CVec3 &incident, const CVec3 &normal)
{
	float twiceDot = 2.0f * (incident.m_x * normal.m_x + incident.m_y * normal.m_y + incident.m_z * normal.m_z);
	CVec3 out;
	out.m_x = incident.m_x - twiceDot * normal.m_x;
	out.m_y = incident.m_y - twiceDot * normal.m_y;
	out.m_z = incident.m_z - twiceDot * normal.m_z;
	return out;
}

// DA-UNIT MATH-29 level:hard tags:sse,struct-arg,call-unit,float
float CMathTests::TriangleArea3(const CVec3 &a, const CVec3 &b, const CVec3 &c)
{
	CVec3 ab;
	ab.m_x = b.m_x - a.m_x;
	ab.m_y = b.m_y - a.m_y;
	ab.m_z = b.m_z - a.m_z;
	CVec3 ac;
	ac.m_x = c.m_x - a.m_x;
	ac.m_y = c.m_y - a.m_y;
	ac.m_z = c.m_z - a.m_z;
	CVec3 cross = Vec3Cross(ab, ac);
	return SquareRootNewton(Vec3LengthSq(cross)) * 0.5f;
}

// DA-UNIT MATH-30 level:easy tags:cmp-chain,branch,bool,struct-arg
bool CMathTests::BoxesOverlap(const CVec3 &aMin, const CVec3 &aMax, const CVec3 &bMin, const CVec3 &bMax)
{
	if (aMax.m_x < bMin.m_x || bMax.m_x < aMin.m_x)
		return false;
	if (aMax.m_y < bMin.m_y || bMax.m_y < aMin.m_y)
		return false;
	if (aMax.m_z < bMin.m_z || bMax.m_z < aMin.m_z)
		return false;
	return true;
}

// DA-UNIT MATH-31 level:hard tags:nested-loop,sse,out-param,array
void CMathTests::Matrix3Multiply(const CMatrix3 &a, const CMatrix3 &b, CMatrix3 *out)
{
	for (int row = 0; row < 3; ++row)
	{
		for (int column = 0; column < 3; ++column)
		{
			float sum = 0.0f;
			for (int inner = 0; inner < 3; ++inner)
				sum += a.m_m[row][inner] * b.m_m[inner][column];
			out->m_m[row][column] = sum;
		}
	}
}

// DA-UNIT MATH-32 level:medium tags:for,rdata-table,float,abs
int CMathTests::NearestTableIndex(float value)
{
	int best = 0;
	float bestDelta = value - k_lodDistances[0];
	if (bestDelta < 0.0f)
		bestDelta = -bestDelta;
	for (int index = 1; index < 8; ++index)
	{
		float delta = value - k_lodDistances[index];
		if (delta < 0.0f)
			delta = -delta;
		if (delta < bestDelta)
		{
			bestDelta = delta;
			best = index;
		}
	}
	return best;
}

// DA-UNIT MATH-33 level:easy tags:static-state,float,this
void CMathTests::ResetStats()
{
	m_sum = 0.0f;
	m_sumSquares = 0.0f;
	m_largest = 0.0f;
	m_smallest = 0.0f;
	m_sampleCount = 0;
}

// DA-UNIT MATH-34 level:medium tags:static-state,float,cmp,this
void CMathTests::PushSample(float sample)
{
	if (m_sampleCount == 0)
	{
		m_largest = sample;
		m_smallest = sample;
	}
	else
	{
		if (sample > m_largest)
			m_largest = sample;
		if (sample < m_smallest)
			m_smallest = sample;
	}
	m_sum += sample;
	m_sumSquares += sample * sample;
	++m_sampleCount;
}

// DA-UNIT MATH-35 level:easy tags:div,guard,float,this
float CMathTests::MeanOfSamples() const
{
	if (m_sampleCount <= 0)
		return 0.0f;
	return m_sum / (float)m_sampleCount;
}

// DA-UNIT MATH-36 level:medium tags:div,guard,float,static-state,this
float CMathTests::VarianceOfSamples() const
{
	if (m_sampleCount <= 0)
		return 0.0f;
	float mean = m_sum / (float)m_sampleCount;
	float meanOfSquares = m_sumSquares / (float)m_sampleCount;
	float variance = meanOfSquares - mean * mean;
	if (variance < 0.0f)
		variance = 0.0f;
	return variance;
}

void CMathTests::RunSelfChecks(CSelfTest &st)
{
	{
		DA_CASE(st, "MATH-01");
		int a = st.AcceptInt(-200, 200), b = st.AcceptInt(-200, 200);
		st.OutInt("r", CMathTests::AbsDiff(a, b));
		st.OutInt("r", CMathTests::AbsDiff(17, -29));
		st.WantInt("r", 46);
	}
	{
		DA_CASE(st, "MATH-02");
		st.OutInt("c", CMathTests::ClampRange(42, 10, 20));
		st.WantInt("c", 20);
		st.OutInt("inv", CMathTests::ClampRange(5, 20, 10));
		st.WantInt("inv", 20);
	}
	{
		DA_CASE(st, "MATH-03");
		st.OutInt("sum", CMathTests::SumTo(100));
		st.WantInt("sum", 5050);
		st.OutInt("zero", CMathTests::SumTo(0));
		st.WantInt("zero", 0);
	}
	{
		DA_CASE(st, "MATH-04");
		st.OutInt("sum", CMathTests::SumSquaresTo(10));
		st.WantInt("sum", 385);
	}
	{
		DA_CASE(st, "MATH-05");
		st.OutInt("sum", CMathTests::SumEvenBelow(20));
		st.WantInt("sum", 90);
	}
	{
		DA_CASE(st, "MATH-06");
		st.OutInt("gcd", CMathTests::GreatestCommonDivisor(1071, 462));
		st.WantInt("gcd", 21);
		st.OutInt("neg", CMathTests::GreatestCommonDivisor(-48, 18));
		st.WantInt("neg", 6);
	}
	{
		DA_CASE(st, "MATH-07");
		st.OutInt("steps", CMathTests::CollatzSteps(27));
		st.WantInt("steps", 111);
		st.OutInt("bad", CMathTests::CollatzSteps(0));
		st.WantInt("bad", -1);
	}
	{
		DA_CASE(st, "MATH-08");
		st.OutInt("bits", CMathTests::CountSetBits(0x12345678u));
		st.WantInt("bits", 13);
		st.OutInt("bits", CMathTests::CountSetBits(st.AcceptBits()));
	}
	{
		DA_CASE(st, "MATH-09");
		st.OutUInt("rev", CMathTests::ReverseBits(0x00000001u));
		st.WantUInt("rev", 0x80000000u);
		st.OutUInt("rev", CMathTests::ReverseBits(0xF0000000u));
		st.WantUInt("rev", 0x0000000Fu);
	}
	{
		DA_CASE(st, "MATH-10");
		st.OutInt("root", CMathTests::IntegerSquareRoot(1000000));
		st.WantInt("root", 1000);
		st.OutInt("root", CMathTests::IntegerSquareRoot(2147483647));
		st.WantInt("root", 46340);
		st.OutInt("neg", CMathTests::IntegerSquareRoot(-3));
		st.WantInt("neg", -1);
	}
	{
		DA_CASE(st, "MATH-11");
		st.OutInt("hit", CMathTests::BinarySearchKey(18));
		st.WantInt("hit", 8);
		st.OutInt("miss", CMathTests::BinarySearchKey(0));
		st.WantInt("miss", -9);
		st.OutInt("first", CMathTests::BinarySearchKey(-972));
		st.WantInt("first", 0);
	}
	{
		DA_CASE(st, "MATH-12");
		st.OutUInt("zero", CMathTests::HashMix32(0u));
		st.WantUInt("zero", 0u);
		st.OutUInt("mix", CMathTests::HashMix32(st.AcceptBits()));
	}
	{
		DA_CASE(st, "MATH-13");
		st.OutUInt("crc", CMathTests::Crc32OfBuffer((const unsigned char *)"123456789", 9));
		st.WantUInt("crc", 0xCBF43926u);
		st.OutUInt("empty", CMathTests::Crc32OfBuffer((const unsigned char *)"", 0));
		st.WantUInt("empty", 0u);
	}
	{
		DA_CASE(st, "MATH-14");
		st.OutInt("primes", CMathTests::CountPrimesUpTo(100));
		st.WantInt("primes", 25);
		st.OutInt("none", CMathTests::CountPrimesUpTo(1));
		st.WantInt("none", 0);
	}
	{
		DA_CASE(st, "MATH-15");
		st.OutInt("fib", CMathTests::FibonacciAt(30));
		st.WantInt("fib", 832040);
	}
	{
		DA_CASE(st, "MATH-16");
		st.OutInt("fib", CMathTests::FibonacciRecursive(20));
		st.WantInt("fib", 6765);
	}
	{
		DA_CASE(st, "MATH-17");
		st.OutInt("sat", CMathTests::SaturatingAdd(2000000000, 2000000000));
		st.WantInt("sat", 2147483647);
		st.OutInt("sat", CMathTests::SaturatingAdd(-2000000000, -2000000000));
		st.WantInt("sat", (-2147483647 - 1));
		st.OutInt("plain", CMathTests::SaturatingAdd(5, 7));
		st.WantInt("plain", 12);
	}
	{
		DA_CASE(st, "MATH-37");
		st.OutInt("s", CMathTests::SignOf(-9));
		st.WantInt("s", -1);
		st.OutInt("z", CMathTests::SignOf(0));
		st.WantInt("z", 0);
		st.OutInt("p", CMathTests::SignOf(9));
		st.WantInt("p", 1);
	}
	{
		DA_CASE(st, "MATH-38");
		st.OutInt("even", CMathTests::ParityOf(0xF0F0F0F0u));
		st.WantInt("even", 0);
		st.OutInt("odd", CMathTests::ParityOf(0x00000007u));
		st.WantInt("odd", 1);
	}
	{
		DA_CASE(st, "MATH-18");
		st.OutInt("fp", CMathTests::FixedPointMultiply(3072, 4096, 10));
		st.WantInt("fp", 12288);
		st.OutInt("clamped", CMathTests::FixedPointMultiply(12, 5, -4));
		st.WantInt("clamped", 60);
	}
	{
		DA_CASE(st, "MATH-19");
		st.OutFloat("root", CMathTests::SquareRootNewton(2.0f));
		st.WantFloat("root", 1.41421356f, 1e-3f);
		st.OutFloat("root", CMathTests::SquareRootNewton(9.0f));
		st.WantFloat("root", 3.0f, 1e-3f);
		st.OutFloat("zero", CMathTests::SquareRootNewton(0.0f));
		st.WantFloat("zero", 0.0f);
	}
	{
		DA_CASE(st, "MATH-20");
		st.OutFloat("w", CMathTests::WrapAngle180(190.0f));
		st.WantFloat("w", -170.0f);
		st.OutFloat("w", CMathTests::WrapAngle180(-540.0f));
		st.WantFloat("w", -180.0f);
		st.OutFloat("w", CMathTests::WrapAngle180(st.AcceptFloat(-90.0f, 90.0f)));
	}
	{
		DA_CASE(st, "MATH-21");
		st.OutFloat("blend", CMathTests::SmoothstepBlend(1.0f, 5.0f, 0.5f));
		st.WantFloat("blend", 3.0f);
		st.OutFloat("over", CMathTests::SmoothstepBlend(1.0f, 5.0f, 2.0f));
		st.WantFloat("over", 5.0f);
	}
	{
		DA_CASE(st, "MATH-22");
		st.OutFloat("zero", CMathTests::SineApprox(0.0f));
		st.WantFloat("zero", 0.0f);
		st.OutFloat("s", CMathTests::SineApprox(1.0f));
		st.WantFloat("s", 0.84147098f, 1e-3f);
		st.OutFloat("peak", CMathTests::SineApprox(1.5707963f));
		st.WantFloat("peak", 1.0f, 1e-3f);
	}
	{
		DA_CASE(st, "MATH-23");
		st.OutFloat("up", CMathTests::Atan2Approx(1.0f, 0.0f));
		st.WantFloat("up", 1.57079637f);
		st.OutFloat("back", CMathTests::Atan2Approx(0.0f, -1.0f));
		st.WantFloat("back", 3.14159274f);
		st.OutFloat("diag", CMathTests::Atan2Approx(1.0f, 1.0f));
		st.WantFloat("diag", 0.78539816f, 7e-2f);
	}
	{
		DA_CASE(st, "MATH-24");
		st.OutFloat("lo", CMathTests::SolveQuadraticRoot(1.0f, -5.0f, 6.0f, 0));
		st.WantFloat("lo", 2.0f, 1e-3f);
		st.OutFloat("hi", CMathTests::SolveQuadraticRoot(1.0f, -5.0f, 6.0f, 1));
		st.WantFloat("hi", 3.0f, 1e-3f);
		st.OutFloat("linear", CMathTests::SolveQuadraticRoot(0.0f, 2.0f, -4.0f, 0));
		st.WantFloat("linear", 2.0f);
		st.OutFloat("none", CMathTests::SolveQuadraticRoot(1.0f, 0.0f, 4.0f, 0));
		st.WantFloat("none", 0.0f);
	}
	{
		DA_CASE(st, "MATH-25");
		CVec3 v = { 3.0f, 4.0f, 0.0f };
		st.OutFloat("len2", CMathTests::Vec3LengthSq(v));
		st.WantFloat("len2", 25.0f);
	}
	{
		DA_CASE(st, "MATH-26");
		CVec3 a = { 1.0f, 0.0f, 0.0f }, b = { 0.0f, 1.0f, 0.0f };
		CVec3 c = CMathTests::Vec3Cross(a, b);
		st.OutFloat("x", c.m_x);
		st.OutFloat("y", c.m_y);
		st.OutFloat("z", c.m_z);
		st.WantFloat("x", 0.0f);
		st.WantFloat("y", 0.0f);
		st.WantFloat("z", 1.0f);
	}
	{
		DA_CASE(st, "MATH-27");
		CVec3 v = { 3.0f, 0.0f, -4.0f };
		CVec3 n = CMathTests::Vec3Normalize(v);
		st.OutFloat("x", n.m_x);
		st.OutFloat("z", n.m_z);
		st.WantFloat("x", 0.6f, 1e-4f);
		st.WantFloat("z", -0.8f, 1e-4f);
		CVec3 zero = { 0.0f, 0.0f, 0.0f };
		CVec3 up = CMathTests::Vec3Normalize(zero);
		st.OutFloat("fallback", up.m_z);
		st.WantFloat("fallback", 1.0f);
	}
	{
		DA_CASE(st, "MATH-28");
		CVec3 incoming = { 1.0f, -1.0f, 0.0f };
		CVec3 normal = { 0.0f, 1.0f, 0.0f };
		CVec3 r = CMathTests::Vec3Reflect(incoming, normal);
		st.OutFloat("x", r.m_x);
		st.OutFloat("y", r.m_y);
		st.WantFloat("x", 1.0f);
		st.WantFloat("y", 1.0f);
	}
	{
		DA_CASE(st, "MATH-29");
		CVec3 a = { 0.0f, 0.0f, 0.0f }, b = { 4.0f, 0.0f, 0.0f }, c = { 0.0f, 3.0f, 0.0f };
		st.OutFloat("area", CMathTests::TriangleArea3(a, b, c));
		st.WantFloat("area", 6.0f, 1e-3f);
	}
	{
		DA_CASE(st, "MATH-30");
		CVec3 aMin = { 0.0f, 0.0f, 0.0f }, aMax = { 2.0f, 2.0f, 2.0f };
		CVec3 bMin = { 1.0f, 1.0f, 5.0f }, bMax = { 3.0f, 3.0f, 6.0f };
		st.OutBool("hit", CMathTests::BoxesOverlap(aMin, aMax, bMin, bMax));
		st.WantBool("hit", false);
		CVec3 cMin = { 1.5f, 1.5f, 1.5f }, cMax = { 4.0f, 4.0f, 4.0f };
		st.OutBool("yes", CMathTests::BoxesOverlap(aMin, aMax, cMin, cMax));
		st.WantBool("yes", true);
	}
	{
		DA_CASE(st, "MATH-31");
		CMatrix3 ident = { { { 1.0f, 0.0f, 0.0f }, { 0.0f, 1.0f, 0.0f }, { 0.0f, 0.0f, 1.0f } } };
		CMatrix3 m;
		for (int r = 0; r < 3; ++r)
			for (int c = 0; c < 3; ++c)
				m.m_m[r][c] = (float)(r * 3 + c + 1);
		CMatrix3 out;
		CMathTests::Matrix3Multiply(ident, m, &out);
		st.OutFloat("m00", out.m_m[0][0]);
		st.OutFloat("m12", out.m_m[1][2]);
		st.WantFloat("m00", 1.0f);
		st.WantFloat("m12", 6.0f);
	}
	{
		DA_CASE(st, "MATH-32");
		st.OutInt("i", CMathTests::NearestTableIndex(20.0f));
		st.WantInt("i", 1);
		st.OutInt("i", CMathTests::NearestTableIndex(2000.0f));
		st.WantInt("i", 7);
		st.OutInt("i", CMathTests::NearestTableIndex(0.0f));
		st.WantInt("i", 0);
	}
	CMathTests stats;
	{
		DA_CASE(st, "MATH-33");
		stats.PushSample(1.0f);
		stats.PushSample(2.0f);
		stats.ResetStats();
		st.OutInt("count", stats.SampleCount());
		st.WantInt("count", 0);
		st.OutFloat("mean", stats.MeanOfSamples());
		st.WantFloat("mean", 0.0f);
	}
	{
		DA_CASE(st, "MATH-34");
		stats.PushSample(1.0f);
		stats.PushSample(4.0f);
		stats.PushSample(2.0f);
		stats.PushSample(3.0f);
		st.OutInt("count", stats.SampleCount());
		st.WantInt("count", 4);
	}
	{
		DA_CASE(st, "MATH-35");
		st.OutFloat("mean", stats.MeanOfSamples());
		st.WantFloat("mean", 2.5f);
	}
	{
		DA_CASE(st, "MATH-36");
		st.OutFloat("var", stats.VarianceOfSamples());
		st.WantFloat("var", 1.25f);
	}
}
