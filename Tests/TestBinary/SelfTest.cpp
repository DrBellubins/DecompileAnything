// Implementation of the self-check + golden-trace harness. See SelfTest.h.
#include "SelfTest.h"

#include <cmath>
#include <cstdio>
#include <cstring>

CSelfTest::CSelfTest(EMode mode)
	: m_mode(mode), m_rng(0x5F3759DFu), m_caseIndex(0), m_lastCaseIndex(-1),
	  m_slotCount(0), m_argsLen(0), m_cases(0), m_failures(0)
{
	m_unitId[0] = 0;
	m_lastUnitId[0] = 0;
	m_argsJson[0] = 0;
}

unsigned int CSelfTest::NextBits()
{
	// xorshift32: fixed sequence, so a golden trace is reproducible across runs.
	m_rng ^= m_rng << 13;
	m_rng ^= m_rng >> 17;
	m_rng ^= m_rng << 5;
	return m_rng;
}

void CSelfTest::AppendArg(const char *rendered)
{
	int n = (int)std::strlen(rendered);
	if (m_argsLen + n >= (int)sizeof(m_argsJson))
		return;
	std::memcpy(m_argsJson + m_argsLen, rendered, (size_t)n);
	m_argsLen += n;
	m_argsJson[m_argsLen] = 0;
}

int CSelfTest::AcceptInt(int lo, int hi)
{
	unsigned int span = (unsigned int)(hi - lo) + 1u;
	int value = lo;
	if (span != 0u)
		value = lo + (int)(NextBits() % span);
	char rendered[32];
	std::snprintf(rendered, sizeof(rendered), "%s%d", m_argsLen == 0 ? "" : ",", value);
	AppendArg(rendered);
	return value;
}

unsigned int CSelfTest::AcceptBits()
{
	unsigned int value = NextBits();
	char rendered[32];
	std::snprintf(rendered, sizeof(rendered), "%s%u", m_argsLen == 0 ? "" : ",", value);
	AppendArg(rendered);
	return value;
}

float CSelfTest::AcceptFloat(float lo, float hi)
{
	float unit = (float)(NextBits() & 0xFFFFFFu) / 16777216.0f;
	float value = lo + (hi - lo) * unit;
	char rendered[64];
	std::snprintf(rendered, sizeof(rendered), "%s%.9g", m_argsLen == 0 ? "" : ",", (double)value);
	AppendArg(rendered);
	return value;
}

void CSelfTest::EscapeInto(char *out, int capacity, const char *in)
{
	int at = 0;
	for (int i = 0; in[i] != 0 && at < capacity - 8; ++i)
	{
		unsigned char c = (unsigned char)in[i];
		if (c == '"' || c == '\\')
			out[at++] = '\\';
		if (c == '\n')
		{
			out[at++] = '\\';
			out[at++] = 'n';
		}
		else if (c == '\t')
		{
			out[at++] = '\\';
			out[at++] = 't';
		}
		else if (c < 32 || c > 126)
			at += std::snprintf(out + at, capacity - at, "\\u%04x", c);
		else
			out[at++] = (char)c;
	}
	out[at] = 0;
}

CSelfTest::SValue *CSelfTest::FindSlot(const char *tag)
{
	for (int i = 0; i < m_slotCount; ++i)
		if (std::strcmp(m_slots[i].m_tag, tag) == 0)
			return &m_slots[i];
	if (m_slotCount >= (int)(sizeof(m_slots) / sizeof(m_slots[0])))
		return &m_slots[m_slotCount - 1];
	SValue &slot = m_slots[m_slotCount++];
	std::strncpy(slot.m_tag, tag, sizeof(slot.m_tag) - 1);
	slot.m_tag[sizeof(slot.m_tag) - 1] = 0;
	slot.m_json[0] = 0;
	slot.m_raw[0] = 0;
	slot.m_num = 0.0;
	return &slot;
}

void CSelfTest::OutInt(const char *tag, long long value)
{
	SValue *slot = FindSlot(tag);
	std::snprintf(slot->m_json, sizeof(slot->m_json), "%lld", value);
	std::snprintf(slot->m_raw, sizeof(slot->m_raw), "%lld", value);
	slot->m_num = (double)value;
}

void CSelfTest::OutUInt(const char *tag, unsigned long long value)
{
	SValue *slot = FindSlot(tag);
	std::snprintf(slot->m_json, sizeof(slot->m_json), "%llu", value);
	std::snprintf(slot->m_raw, sizeof(slot->m_raw), "%llu", value);
	slot->m_num = (double)value;
}

void CSelfTest::OutFloat(const char *tag, float value)
{
	unsigned int bits;
	std::memcpy(&bits, &value, sizeof(bits));
	SValue *slot = FindSlot(tag);
	std::snprintf(slot->m_json, sizeof(slot->m_json), "{\"f\":\"%.9g\",\"bits\":\"%08x\"}",
		(double)value, bits);
	std::snprintf(slot->m_raw, sizeof(slot->m_raw), "%.9g", (double)value);
	slot->m_num = (double)value;
}

void CSelfTest::OutBool(const char *tag, bool value)
{
	SValue *slot = FindSlot(tag);
	std::snprintf(slot->m_json, sizeof(slot->m_json), "%s", value ? "true" : "false");
	std::snprintf(slot->m_raw, sizeof(slot->m_raw), "%s", value ? "true" : "false");
	slot->m_num = value ? 1.0 : 0.0;
}

void CSelfTest::OutText(const char *tag, const char *value)
{
	SValue *slot = FindSlot(tag);
	char escaped[(int)sizeof(slot->m_raw)];
	EscapeInto(escaped, sizeof(escaped), value);
	std::snprintf(slot->m_json, sizeof(slot->m_json), "\"%s\"", escaped);
	std::strncpy(slot->m_raw, value, sizeof(slot->m_raw) - 1);
	slot->m_raw[sizeof(slot->m_raw) - 1] = 0;
	slot->m_num = (double)std::strlen(value);
}

void CSelfTest::OutBlob(const char *tag, const void *value, int length)
{
	const unsigned char *bytes = (const unsigned char *)value;
	SValue *slot = FindSlot(tag);
	int at = std::snprintf(slot->m_json, sizeof(slot->m_json), "\"");
	for (int i = 0; i < length && at < (int)sizeof(slot->m_json) - 4; ++i)
		at += std::snprintf(slot->m_json + at, sizeof(slot->m_json) - at, "%02x", bytes[i]);
	if (at < (int)sizeof(slot->m_json) - 1)
	{
		slot->m_json[at++] = '"';
		slot->m_json[at] = 0;
	}
	std::snprintf(slot->m_raw, sizeof(slot->m_raw), "%d bytes", length);
	slot->m_num = (double)length;
}

void CSelfTest::Fail(const char *what, const char *tag, const char *want, const char *got)
{
	++m_failures;
	if (m_mode == MODE_REPORT)
		std::printf("FAIL %s #%d %s: want %s got %s\n", m_unitId, m_caseIndex, tag, want, got);
	else
		std::fprintf(stderr, "FAIL %s #%d %s: want %s got %s\n", m_unitId, m_caseIndex, tag, want, got);
	(void)what;
}

void CSelfTest::WantInt(const char *tag, long long expected)
{
	SValue *slot = FindSlot(tag);
	char want[32];
	std::snprintf(want, sizeof(want), "%lld", expected);
	if (std::strcmp(slot->m_raw, want) != 0)
		Fail("int", tag, want, slot->m_raw);
}

void CSelfTest::WantUInt(const char *tag, unsigned long long expected)
{
	SValue *slot = FindSlot(tag);
	char want[32];
	std::snprintf(want, sizeof(want), "%llu", expected);
	if (std::strcmp(slot->m_raw, want) != 0)
		Fail("uint", tag, want, slot->m_raw);
}

void CSelfTest::WantFloat(const char *tag, float expected, float tolerance)
{
	SValue *slot = FindSlot(tag);
	char want[48], got[48];
	std::snprintf(want, sizeof(want), "%.9g", (double)expected);
	std::snprintf(got, sizeof(got), "%.9g", slot->m_num);
	float delta = (float)std::fabs(slot->m_num - (double)expected);
	if (tolerance <= 0.0f ? slot->m_num != (double)expected : delta > (double)tolerance)
		Fail("float", tag, want, got);
}

void CSelfTest::WantBool(const char *tag, bool expected)
{
	SValue *slot = FindSlot(tag);
	if (slot->m_num != (double)(expected ? 1 : 0))
		Fail("bool", tag, expected ? "true" : "false", slot->m_raw);
}

void CSelfTest::WantText(const char *tag, const char *expected)
{
	SValue *slot = FindSlot(tag);
	if (std::strcmp(slot->m_raw, expected) != 0)
		Fail("text", tag, expected, slot->m_raw);
}

void CSelfTest::BeginCase(const char *unitId)
{
	if (std::strcmp(m_lastUnitId, unitId) == 0)
		m_caseIndex = m_lastCaseIndex + 1;
	else
		m_caseIndex = 0;
	std::strncpy(m_unitId, unitId, sizeof(m_unitId) - 1);
	m_unitId[sizeof(m_unitId) - 1] = 0;
	std::strncpy(m_lastUnitId, m_unitId, sizeof(m_lastUnitId) - 1);
	m_lastUnitId[sizeof(m_lastUnitId) - 1] = 0;
	m_lastCaseIndex = m_caseIndex;
	m_slotCount = 0;
	m_argsLen = 0;
	m_argsJson[0] = 0;
	++m_cases;
}

void CSelfTest::EndCase()
{
	if (m_mode != MODE_GOLDEN)
		return;
	std::printf("{\"id\":\"%s\",\"case\":%d,\"args\":[%s],\"out\":{", m_unitId, m_caseIndex, m_argsJson);
	for (int i = 0; i < m_slotCount; ++i)
		std::printf("%s\"%s\":%s", i == 0 ? "" : ",", m_slots[i].m_tag, m_slots[i].m_json);
	std::printf("}}\n");
}

int CSelfTest::Report() const
{
	if (m_mode == MODE_GOLDEN)
		return m_failures;
	std::printf("%d cases, %d failures\n", m_cases, m_failures);
	return m_failures;
}
