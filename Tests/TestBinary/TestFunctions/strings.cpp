// Implementation of the string units. See strings.h for the unit list.
#include "strings.h"

#include <cstdio>
#include <cstring>

static const char k_base64Alphabet[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char k_hexDigits[17] = "0123456789abcdef";

// Plain helper on purpose: no DA_NOINLINE, so it disappears into its callers at -O2.
static char ToLowerChar(char c)
{
	if (c >= 'A' && c <= 'Z')
		return (char)(c - 'A' + 'a');
	return c;
}

// DA-UNIT STR-01 level:easy tags:while,ptr,libc-shadow
int CStringTests::LengthOf(const char *text)
{
	int length = 0;
	while (text[length] != 0)
		++length;
	return length;
}

// DA-UNIT STR-02 level:medium tags:strncpy,truncate,guard
void CStringTests::CopyFixedField(char *field, int capacity, const char *text)
{
	if (capacity <= 0)
		return;
	std::strncpy(field, text, (size_t)(capacity - 1));
	field[capacity - 1] = 0;
}

// DA-UNIT STR-03 level:medium tags:strncat,strlen,truncate
int CStringTests::ConcatBounded(char *buffer, int capacity, const char *text)
{
	int used = (int)std::strlen(buffer);
	if (used >= capacity - 1)
		return 0;
	int room = capacity - 1 - used;
	int want = (int)std::strlen(text);
	if (want > room)
		want = room;
	std::strncat(buffer, text, (size_t)want);
	return want;
}

// DA-UNIT STR-04 level:medium tags:loop,cmp,branch,char
int CStringTests::CompareFold(const char *a, const char *b)
{
	while (*a != 0 && *b != 0)
	{
		char charA = ToLowerChar(*a);
		char charB = ToLowerChar(*b);
		if (charA != charB)
			return (charA < charB) ? -1 : 1;
		++a;
		++b;
	}
	if (*a == 0 && *b == 0)
		return 0;
	return (*a == 0) ? -1 : 1;
}

// DA-UNIT STR-05 level:easy tags:strncmp,strlen,bool
bool CStringTests::StartsWith(const char *text, const char *prefix)
{
	int length = (int)std::strlen(prefix);
	return std::strncmp(text, prefix, (size_t)length) == 0;
}

// DA-UNIT STR-06 level:easy tags:for,cmp,guard
int CStringTests::FindCharIndex(const char *text, char needle)
{
	for (int index = 0; text[index] != 0; ++index)
	{
		if (text[index] == needle)
			return index;
	}
	return -1;
}

// DA-UNIT STR-07 level:medium tags:nested-loop,call-unit,guard
int CStringTests::FindSubstring(const char *haystack, const char *needle)
{
	int needleLength = LengthOf(needle);
	if (needleLength == 0)
		return 0;
	for (int start = 0; haystack[start] != 0; ++start)
	{
		bool matched = true;
		for (int offset = 0; offset < needleLength; ++offset)
		{
			if (haystack[start + offset] != needle[offset])
			{
				matched = false;
				break;
			}
		}
		if (matched)
			return start;
	}
	return -1;
}

// DA-UNIT STR-08 level:medium tags:while,call-unit,offset
int CStringTests::CountOccurrences(const char *haystack, const char *needle)
{
	int count = 0;
	int at = 0;
	for (;;)
	{
		int found = FindSubstring(haystack + at, needle);
		if (found < 0)
			break;
		++count;
		at += found + 1;
		if (haystack[at] == 0)
			break;
	}
	return count;
}

// DA-UNIT STR-09 level:medium tags:for,bool-state,char
int CStringTests::CountWords(const char *text)
{
	int count = 0;
	bool insideWord = false;
	for (int index = 0; text[index] != 0; ++index)
	{
		char c = text[index];
		if (c == ' ' || c == '\t' || c == '\n')
			insideWord = false;
		else if (!insideWord)
		{
			insideWord = true;
			++count;
		}
	}
	return count;
}

// DA-UNIT STR-10 level:medium tags:whitespace,two-pass,memcpy,truncate
void CStringTests::TrimWhitespace(const char *text, char *out, int capacity)
{
	const char *start = text;
	while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')
		++start;
	int length = (int)std::strlen(start);
	while (length > 0)
	{
		char tail = start[length - 1];
		if (tail != ' ' && tail != '\t' && tail != '\n' && tail != '\r')
			break;
		--length;
	}
	if (length > capacity - 1)
		length = capacity - 1;
	std::memcpy(out, start, (size_t)length);
	out[length] = 0;
}

// DA-UNIT STR-11 level:easy tags:in-place,for,char
void CStringTests::ToLowerInPlace(char *text)
{
	for (int index = 0; text[index] != 0; ++index)
	{
		char c = text[index];
		if (c >= 'A' && c <= 'Z')
			text[index] = (char)(c - 'A' + 'a');
	}
}

// DA-UNIT STR-12 level:medium tags:mod,wrap,char,guard
void CStringTests::CaesarShift(const char *text, int amount, char *out, int capacity)
{
	int shift = ((amount % 26) + 26) % 26;
	int at = 0;
	for (int index = 0; text[index] != 0 && at < capacity - 1; ++index)
	{
		char c = text[index];
		if (c >= 'a' && c <= 'z')
			c = (char)('a' + (c - 'a' + shift) % 26);
		else if (c >= 'A' && c <= 'Z')
			c = (char)('A' + (c - 'A' + shift) % 26);
		out[at++] = c;
	}
	out[at] = 0;
}

// DA-UNIT STR-13 level:medium tags:div,reverse,copy,guard
void CStringTests::IntToText(int value, char *out, int capacity)
{
	char scratch[16];
	int at = 0;
	bool negative = value < 0;
	unsigned int magnitude = negative ? (unsigned int)(-(long long)value) : (unsigned int)value;
	if (magnitude == 0u)
	{
		out[0] = '0';
		out[1] = 0;
		return;
	}
	while (magnitude != 0u && at < 15)
	{
		scratch[at++] = (char)('0' + (magnitude % 10u));
		magnitude /= 10u;
	}
	int written = 0;
	if (negative && written < capacity - 1)
		out[written++] = '-';
	while (at > 0 && written < capacity - 1)
		out[written++] = scratch[--at];
	out[written] = 0;
}

// DA-UNIT STR-14 level:hard tags:parse,sign,accumulate,guard
int CStringTests::TextToIntList(const char *text, int *values, int maxValues)
{
	int count = 0;
	const char *cursor = text;
	while (*cursor != 0 && count < maxValues)
	{
		while (*cursor == ',' || *cursor == ' ' || *cursor == ';')
			++cursor;
		if (*cursor == 0)
			break;
		int sign = 1;
		if (*cursor == '-')
		{
			sign = -1;
			++cursor;
		}
		else if (*cursor == '+')
			++cursor;
		int value = 0;
		bool anyDigit = false;
		while (*cursor >= '0' && *cursor <= '9')
		{
			value = value * 10 + (*cursor - '0');
			anyDigit = true;
			++cursor;
		}
		if (!anyDigit)
			break;
		values[count++] = sign * value;
	}
	return count;
}

// DA-UNIT STR-15 level:medium tags:format,varargs,truncate
int CStringTests::FormatScoreLine(char *out, int capacity, const char *name, int score, float multiplier)
{
	int written = std::snprintf(out, (size_t)capacity, "%s:%d x%.1f", name, score, (double)multiplier);
	if (written >= capacity)
	{
		out[capacity - 1] = 0;
		return capacity - 1;
	}
	return written;
}

// DA-UNIT STR-16 level:hard tags:out-param,index,empty-field
int CStringTests::SplitOnChar(const char *text, char separator, int *offsets, int maxParts)
{
	int count = 0;
	int start = 0;
	for (int index = 0;; ++index)
	{
		if (text[index] == separator || text[index] == 0)
		{
			if (count < maxParts)
				offsets[count++] = start;
			start = index + 1;
			if (text[index] == 0)
				break;
		}
	}
	return count;
}

// DA-UNIT STR-17 level:medium tags:strcat-loop,memcpy,truncate
void CStringTests::JoinValues(const char *const *values, int count, char separator, char *out, int capacity)
{
	int used = 0;
	out[0] = 0;
	for (int index = 0; index < count; ++index)
	{
		if (index > 0)
		{
			if (used >= capacity - 1)
				break;
			out[used++] = separator;
			out[used] = 0;
		}
		int length = (int)std::strlen(values[index]);
		int room = capacity - 1 - used;
		if (room <= 0)
			break;
		if (length > room)
			length = room;
		std::memcpy(out + used, values[index], (size_t)length);
		used += length;
		out[used] = 0;
	}
}

// DA-UNIT STR-18 level:hard tags:bitops,table,rdata,guard,pad
int CStringTests::Base64Encode(const unsigned char *input, int length, char *out, int capacity)
{
	int at = 0;
	int index = 0;
	while (index + 3 <= length)
	{
		if (at + 4 >= capacity)
			break;
		unsigned int triple = ((unsigned int)input[index] << 16) |
			((unsigned int)input[index + 1] << 8) | (unsigned int)input[index + 2];
		out[at++] = k_base64Alphabet[(triple >> 18) & 0x3Fu];
		out[at++] = k_base64Alphabet[(triple >> 12) & 0x3Fu];
		out[at++] = k_base64Alphabet[(triple >> 6) & 0x3Fu];
		out[at++] = k_base64Alphabet[triple & 0x3Fu];
		index += 3;
	}
	int remaining = length - index;
	if (remaining == 1 && at + 4 <= capacity)
	{
		unsigned int triple = (unsigned int)input[index] << 16;
		out[at++] = k_base64Alphabet[(triple >> 18) & 0x3Fu];
		out[at++] = k_base64Alphabet[(triple >> 12) & 0x3Fu];
		out[at++] = '=';
		out[at++] = '=';
	}
	else if (remaining == 2 && at + 4 <= capacity)
	{
		unsigned int triple = ((unsigned int)input[index] << 16) | ((unsigned int)input[index + 1] << 8);
		out[at++] = k_base64Alphabet[(triple >> 18) & 0x3Fu];
		out[at++] = k_base64Alphabet[(triple >> 12) & 0x3Fu];
		out[at++] = k_base64Alphabet[(triple >> 6) & 0x3Fu];
		out[at++] = '=';
	}
	if (at < capacity)
		out[at] = 0;
	return at;
}

// DA-UNIT STR-19 level:medium tags:shift,table,rdata,guard
void CStringTests::HexEncode(const unsigned char *input, int length, char *out, int capacity)
{
	int at = 0;
	for (int index = 0; index < length && at + 2 < capacity; ++index)
	{
		out[at++] = k_hexDigits[(input[index] >> 4) & 0x0Fu];
		out[at++] = k_hexDigits[input[index] & 0x0Fu];
	}
	out[at] = 0;
}

// DA-UNIT STR-20 level:hard tags:recursion,backtrack,branch
bool CStringTests::WildcardMatch(const char *pattern, const char *text)
{
	if (*pattern == 0)
		return *text == 0;
	if (*pattern == '*')
	{
		while (*text != 0)
		{
			if (WildcardMatch(pattern + 1, text))
				return true;
			++text;
		}
		return WildcardMatch(pattern + 1, text);
	}
	if (*pattern == '?')
		return (*text != 0) ? WildcardMatch(pattern + 1, text + 1) : false;
	if (*pattern != *text)
		return false;
	return WildcardMatch(pattern + 1, text + 1);
}

// DA-UNIT STR-21 level:hard tags:parse,multi-stage,cmp
int CStringTests::CompareVersion(const char *a, const char *b)
{
	for (;;)
	{
		int segmentA = 0;
		int segmentB = 0;
		while (*a >= '0' && *a <= '9')
		{
			segmentA = segmentA * 10 + (*a - '0');
			++a;
		}
		while (*b >= '0' && *b <= '9')
		{
			segmentB = segmentB * 10 + (*b - '0');
			++b;
		}
		if (segmentA != segmentB)
			return (segmentA < segmentB) ? -1 : 1;
		if (*a == 0 && *b == 0)
			return 0;
		if (*a == 0)
			return -1;
		if (*b == 0)
			return 1;
		if (*a != *b)
			return (*a < *b) ? -1 : 1;
		++a;
		++b;
	}
}

// DA-UNIT STR-22 level:easy tags:fnv,mul,xor,loop
unsigned int CStringTests::HashString(const char *text)
{
	unsigned int hash = 2166136261u;
	for (int index = 0; text[index] != 0; ++index)
	{
		hash ^= (unsigned int)(unsigned char)text[index];
		hash *= 16777619u;
	}
	return hash;
}

// DA-UNIT STR-23 level:medium tags:last-index,copy,truncate
void CStringTests::GetFileNameFromPath(const char *path, char *out, int capacity)
{
	int start = 0;
	for (int index = 0; path[index] != 0; ++index)
	{
		if (path[index] == '/' || path[index] == '\\')
			start = index + 1;
	}
	int at = 0;
	while (path[start] != 0 && at < capacity - 1)
		out[at++] = path[start++];
	out[at] = 0;
}

void CStringTests::RunSelfChecks(CSelfTest &st)
{
	char buffer[64];

	{
		DA_CASE(st, "STR-01");
		st.OutInt("len", CStringTests::LengthOf("hello world"));
		st.WantInt("len", 11);
		st.OutInt("empty", CStringTests::LengthOf(""));
		st.WantInt("empty", 0);
	}
	{
		DA_CASE(st, "STR-02");
		char field[8];
		std::memset(field, 0x78, sizeof(field));
		CStringTests::CopyFixedField(field, 8, "0123456789");
		st.OutText("field", field);
		st.WantText("field", "0123456");
		CStringTests::CopyFixedField(field, 8, "ab");
		st.OutText("padded", field);
		st.WantText("padded", "ab");
	}
	{
		DA_CASE(st, "STR-03");
		char joined[8];
		std::strcpy(joined, "abc");
		st.OutInt("added", CStringTests::ConcatBounded(joined, 8, "defgh"));
		st.WantInt("added", 4);
		st.OutText("joined", joined);
		st.WantText("joined", "abcdefg");
	}
	{
		DA_CASE(st, "STR-04");
		st.OutInt("fold", CStringTests::CompareFold("Alpha", "aLpH"));
		st.WantInt("fold", 1);
		st.OutInt("same", CStringTests::CompareFold("WEAPON_RIFLE", "weapon_rifle"));
		st.WantInt("same", 0);
	}
	{
		DA_CASE(st, "STR-05");
		st.OutBool("yes", CStringTests::StartsWith("weapon_sword", "weapon_"));
		st.WantBool("yes", true);
		st.OutBool("no", CStringTests::StartsWith("sword", "weapon_"));
		st.WantBool("no", false);
	}
	{
		DA_CASE(st, "STR-06");
		st.OutInt("idx", CStringTests::FindCharIndex("assets\\models\\car.dat", '\\'));
		st.WantInt("idx", 6);
		st.OutInt("none", CStringTests::FindCharIndex("car.dat", '\\'));
		st.WantInt("none", -1);
	}
	{
		DA_CASE(st, "STR-07");
		st.OutInt("idx", CStringTests::FindSubstring("mississippi", "ssi"));
		st.WantInt("idx", 2);
		st.OutInt("none", CStringTests::FindSubstring("mississippi", "zz"));
		st.WantInt("none", -1);
	}
	{
		DA_CASE(st, "STR-08");
		st.OutInt("count", CStringTests::CountOccurrences("mississippi", "ppi"));
		st.WantInt("count", 1);
		st.OutInt("overlap", CStringTests::CountOccurrences("aaaa", "aa"));
		st.WantInt("overlap", 3);
	}
	{
		DA_CASE(st, "STR-09");
		st.OutInt("words", CStringTests::CountWords("  the quick  brown fox "));
		st.WantInt("words", 4);
	}
	{
		DA_CASE(st, "STR-10");
		CStringTests::TrimWhitespace(" \t hi there \n", buffer, sizeof(buffer));
		st.OutText("trimmed", buffer);
		st.WantText("trimmed", "hi there");
		CStringTests::TrimWhitespace("   ", buffer, sizeof(buffer));
		st.OutText("blank", buffer);
		st.WantText("blank", "");
	}
	{
		DA_CASE(st, "STR-11");
		std::strcpy(buffer, "Mix3d Case!");
		CStringTests::ToLowerInPlace(buffer);
		st.OutText("lower", buffer);
		st.WantText("lower", "mix3d case!");
	}
	{
		DA_CASE(st, "STR-12");
		CStringTests::CaesarShift("abcxyz", 3, buffer, sizeof(buffer));
		st.OutText("shift", buffer);
		st.WantText("shift", "defabc");
		CStringTests::CaesarShift("Hello World!", -1, buffer, sizeof(buffer));
		st.OutText("back", buffer);
		st.WantText("back", "Gdkkn Vnqkc!");
	}
	{
		DA_CASE(st, "STR-13");
		CStringTests::IntToText(-1234, buffer, sizeof(buffer));
		st.OutText("text", buffer);
		st.WantText("text", "-1234");
		CStringTests::IntToText(0, buffer, sizeof(buffer));
		st.OutText("zero", buffer);
		st.WantText("zero", "0");
	}
	{
		DA_CASE(st, "STR-14");
		int values[8];
		int count = CStringTests::TextToIntList("10,-20; 30,", values, 8);
		st.OutInt("count", count);
		st.WantInt("count", 3);
		st.OutInt("v0", values[0]);
		st.OutInt("v1", values[1]);
		st.OutInt("v2", values[2]);
		st.WantInt("v0", 10);
		st.WantInt("v1", -20);
		st.WantInt("v2", 30);
		st.OutInt("stop", CStringTests::TextToIntList("7,abc,9", values, 8));
		st.WantInt("stop", 1);
	}
	{
		DA_CASE(st, "STR-15");
		st.OutInt("written", CStringTests::FormatScoreLine(buffer, sizeof(buffer), "Bob", 4200, 1.5f));
		st.WantInt("written", 13);
		st.OutText("line", buffer);
		st.WantText("line", "Bob:4200 x1.5");
		st.OutInt("cut", CStringTests::FormatScoreLine(buffer, 6, "Bob", 4200, 1.5f));
		st.WantInt("cut", 5);
		st.OutText("cuttext", buffer);
		st.WantText("cuttext", "Bob:4");
	}
	{
		DA_CASE(st, "STR-16");
		int offsets[8];
		int parts = CStringTests::SplitOnChar("a,bb,,cccc", ',', offsets, 8);
		st.OutInt("parts", parts);
		st.WantInt("parts", 4);
		st.OutInt("o0", offsets[0]);
		st.OutInt("o1", offsets[1]);
		st.OutInt("o2", offsets[2]);
		st.OutInt("o3", offsets[3]);
		st.WantInt("o0", 0);
		st.WantInt("o1", 2);
		st.WantInt("o2", 5);
		st.WantInt("o3", 6);
	}
	{
		DA_CASE(st, "STR-17");
		const char *values[] = { "one", "two", "three" };
		CStringTests::JoinValues(values, 3, ';', buffer, sizeof(buffer));
		st.OutText("joined", buffer);
		st.WantText("joined", "one;two;three");
		CStringTests::JoinValues(values, 3, ';', buffer, 9);
		st.OutText("cut", buffer);
		st.WantText("cut", "one;two;");
	}
	{
		DA_CASE(st, "STR-18");
		st.OutInt("n", CStringTests::Base64Encode((const unsigned char *)"Man", 3, buffer, sizeof(buffer)));
		st.WantInt("n", 4);
		st.OutText("b64", buffer);
		st.WantText("b64", "TWFu");
		CStringTests::Base64Encode((const unsigned char *)"Ma", 2, buffer, sizeof(buffer));
		st.OutText("pad1", buffer);
		st.WantText("pad1", "TWE=");
		CStringTests::Base64Encode((const unsigned char *)"M", 1, buffer, sizeof(buffer));
		st.OutText("pad2", buffer);
		st.WantText("pad2", "TQ==");
	}
	{
		DA_CASE(st, "STR-19");
		const unsigned char bytes[] = { 0xDE, 0xAD, 0x00, 0xBE };
		CStringTests::HexEncode(bytes, 4, buffer, sizeof(buffer));
		st.OutText("hex", buffer);
		st.WantText("hex", "dead00be");
	}
	{
		DA_CASE(st, "STR-20");
		st.OutBool("hit", CStringTests::WildcardMatch("*.txt", "notes.txt"));
		st.WantBool("hit", true);
		st.OutBool("miss", CStringTests::WildcardMatch("*.txt", "notes.tex"));
		st.WantBool("miss", false);
		st.OutBool("one", CStringTests::WildcardMatch("ca?t", "cart"));
		st.WantBool("one", true);
		st.OutBool("star", CStringTests::WildcardMatch("a*b*c", "abc"));
		st.WantBool("star", true);
	}
	{
		DA_CASE(st, "STR-21");
		st.OutInt("newer", CStringTests::CompareVersion("1.10.2", "1.9.9"));
		st.WantInt("newer", 1);
		st.OutInt("same", CStringTests::CompareVersion("2.0", "2.0"));
		st.WantInt("same", 0);
		st.OutInt("shorter", CStringTests::CompareVersion("2.0", "2.0.1"));
		st.WantInt("shorter", -1);
	}
	{
		DA_CASE(st, "STR-22");
		st.OutUInt("fnv", CStringTests::HashString("hello"));
		st.WantUInt("fnv", 0x4F9F2CABu);
		st.OutUInt("zero", CStringTests::HashString(""));
		st.WantUInt("zero", 2166136261u);
	}
	{
		DA_CASE(st, "STR-23");
		CStringTests::GetFileNameFromPath("c:/data/models\\car.dat", buffer, sizeof(buffer));
		st.OutText("name", buffer);
		st.WantText("name", "car.dat");
		CStringTests::GetFileNameFromPath("plainname", buffer, sizeof(buffer));
		st.OutText("bare", buffer);
		st.WantText("bare", "plainname");
	}
}
