// Various string related functions, heavy use of strncpy, strcat, strcmp, etc
#ifndef DA_TESTFUNCTIONS_STRINGS_H
#define DA_TESTFUNCTIONS_STRINGS_H

#include "SelfTest.h"

class CSelfTest;

// Fixed size buffers and out params everywhere: that is what the decompiler has to
// recover, since a truncating strncpy and a memcpy look almost the same in the binary.
class CStringTests
{
public:
	static DA_NOINLINE int LengthOf(const char *text);
	static DA_NOINLINE void CopyFixedField(char *field, int capacity, const char *text);
	static DA_NOINLINE int ConcatBounded(char *buffer, int capacity, const char *text);
	static DA_NOINLINE int CompareFold(const char *a, const char *b);
	static DA_NOINLINE bool StartsWith(const char *text, const char *prefix);
	static DA_NOINLINE int FindCharIndex(const char *text, char needle);
	static DA_NOINLINE int FindSubstring(const char *haystack, const char *needle);
	static DA_NOINLINE int CountOccurrences(const char *haystack, const char *needle);
	static DA_NOINLINE int CountWords(const char *text);
	static DA_NOINLINE void TrimWhitespace(const char *text, char *out, int capacity);
	static DA_NOINLINE void ToLowerInPlace(char *text);
	static DA_NOINLINE void CaesarShift(const char *text, int amount, char *out, int capacity);
	static DA_NOINLINE void IntToText(int value, char *out, int capacity);
	static DA_NOINLINE int TextToIntList(const char *text, int *values, int maxValues);
	static DA_NOINLINE int FormatScoreLine(char *out, int capacity, const char *name, int score, float multiplier);
	static DA_NOINLINE int SplitOnChar(const char *text, char separator, int *offsets, int maxParts);
	static DA_NOINLINE void JoinValues(const char *const *values, int count, char separator, char *out, int capacity);
	static DA_NOINLINE int Base64Encode(const unsigned char *input, int length, char *out, int capacity);
	static DA_NOINLINE void HexEncode(const unsigned char *input, int length, char *out, int capacity);
	static DA_NOINLINE bool WildcardMatch(const char *pattern, const char *text);
	static DA_NOINLINE int CompareVersion(const char *a, const char *b);
	static DA_NOINLINE unsigned int HashString(const char *text);
	static DA_NOINLINE void GetFileNameFromPath(const char *path, char *out, int capacity);

	static DA_NOINLINE void RunSelfChecks(CSelfTest &selfTest);
};

#endif // DA_TESTFUNCTIONS_STRINGS_H
