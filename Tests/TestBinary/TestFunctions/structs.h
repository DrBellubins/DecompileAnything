// Various complex struct related code (actual structs, and functions using said structs)
//
// The layouts below are the point of this module: field offsets, padding, unions,
// bitfields, vtables and RTTI are exactly what a decompiler has to recover, so the
// structs are deliberately mixed-size rather than tidy.
#ifndef DA_TESTFUNCTIONS_STRUCTS_H
#define DA_TESTFUNCTIONS_STRUCTS_H

#include "SelfTest.h"
#include "math.h"

class CSelfTest;

// Bit-packed map stamp: bit order is part of the answer.
struct SMapStampBits
{
	unsigned int m_sector : 6;
	unsigned int m_layer : 3;
	unsigned int m_daylight : 1;
	unsigned int m_paused : 1;
	unsigned int m_reserved : 21;
};

union UMapStamp
{
	SMapStampBits m_bits;
	unsigned int m_raw;
};

struct SRgbColour
{
	union
	{
		unsigned int m_packed;
		struct
		{
			unsigned char m_red;
			unsigned char m_green;
			unsigned char m_blue;
			unsigned char m_alpha;
		} m_channels;
	};
};

// Two overlapping views of the same four ints.
struct CRect
{
	union
	{
		struct
		{
			int m_left;
			int m_top;
			int m_right;
			int m_bottom;
		};
		struct
		{
			int m_x;
			int m_y;
			int m_width;
			int m_height;
		};
	};
};

// Mixed sizes on purpose: padding holes show up as uninitialised bytes.
struct SPlayerStats
{
	char m_name[16];
	int m_score;
	short m_wins;
	unsigned char m_flags;
	int m_bestTimes[4];
	char m_difficulty;
};

// Cross-module type use: the descriptor embeds a CVec3 from math.h.
struct SVehicleDescriptor
{
	char m_name[24];
	CVec3 m_startPosition;
	int m_cost;
	int m_mass;
	float m_grip;
	short m_wheels;
	short m_seats;
	SRgbColour m_tint;
};

// Intrusive list node.
struct SListItem
{
	int m_value;
	SListItem *m_next;
};

// Fixed allocator with an embedded free list.
struct SPoolBlock
{
	int m_value;
	int m_nextFree;
};

struct SPool
{
	SPoolBlock m_blocks[16];
	int m_firstFree;
	int m_allocated;
	int m_generation;
};

struct SCircularQueue
{
	int m_head;
	int m_count;
	int m_items[8];
};

struct SChunkGrid
{
	int m_width;
	int m_height;
	unsigned char *m_cells;
};

// Tagged union: the switch over the tag is a jump table.
struct SVariantValue
{
	enum EKind
	{
		KIND_EMPTY = 0,
		KIND_INT = 1,
		KIND_FLOAT = 2,
		KIND_TEXT = 3
	};

	EKind m_kind;
	union
	{
		int m_number;
		float m_real;
		const char *m_text;
	};
};

// Struct-of-arrays buffer for the vectorised transform unit.
struct SPointBuffer
{
	int m_count;
	float m_x[16];
	float m_y[16];
	float m_z[16];
};

// Virtual hierarchy: vtable, RTTI and dynamic_cast live here.
class CEntityBase
{
public:
	CEntityBase() : m_health(100), m_tag(0) {}
	virtual ~CEntityBase() {}
	virtual float GetHealth() const = 0;
	virtual int Classify() const { return 0; }
	void TakeDamage(int amount)
	{
		m_health -= amount;
		if (m_health < 0)
			m_health = 0;
	}

	int m_health;
	int m_tag;
};

class CVehicleEntity : public CEntityBase
{
public:
	CVehicleEntity() : m_armour(0), m_speed(0.0f) {}
	virtual float GetHealth() const { return (float)m_health + (float)m_armour * 0.5f; }
	virtual int Classify() const { return 2; }

	int m_armour;
	float m_speed;
};

class CCharacterEntity : public CEntityBase
{
public:
	CCharacterEntity() : m_stamina(0) {}
	virtual float GetHealth() const { return (float)m_health * (float)m_stamina * 0.01f; }
	virtual int Classify() const { return 1; }

	int m_stamina;
};

class CStructTests
{
public:
	// --- bit and byte fields ---
	static DA_NOINLINE unsigned int PackMapStamp(int sector, int layer, bool daylight, bool paused);
	static DA_NOINLINE int UnpackMapStamp(unsigned int raw, int *layer, int *daylight);
	static DA_NOINLINE SRgbColour BlendColours(const SRgbColour &a, const SRgbColour &b, int weight);

	// --- structs by value, by pointer, and as arrays ---
	static DA_NOINLINE CRect RectFromCorners(int x0, int y0, int x1, int y1);
	static DA_NOINLINE int RectArea(const CRect &rect);
	static DA_NOINLINE int EntityIsAlive(const CEntityBase *entity);
	static DA_NOINLINE bool RectIntersect(const CRect &a, const CRect &b, CRect *out);
	static DA_NOINLINE int SumPlayerTimes(const SPlayerStats &stats);
	static DA_NOINLINE void InitVehicleDescriptor(SVehicleDescriptor *out, const char *name, const CVec3 &start, int cost, int mass);
	static DA_NOINLINE int FindVehicleByName(const SVehicleDescriptor *list, int count, const char *name);
	static DA_NOINLINE void TranslateDescriptor(SVehicleDescriptor *vehicle, float dx, float dy, float dz);
	static DA_NOINLINE unsigned int ChecksumDescriptorBytes(const SVehicleDescriptor &vehicle);

	// --- pointer chasing ---
	static DA_NOINLINE int ListLength(const SListItem *head);
	static DA_NOINLINE bool RemoveNodeWithValue(SListItem **headRef, int value);
	static DA_NOINLINE void ReverseListInPlace(SListItem **headRef);

	// --- container structs ---
	static DA_NOINLINE void PoolInit(SPool *pool);
	static DA_NOINLINE int PoolAlloc(SPool *pool, int value);
	static DA_NOINLINE bool PoolFree(SPool *pool, int slot);
	static DA_NOINLINE bool QueuePush(SCircularQueue *queue, int value);
	static DA_NOINLINE bool QueuePop(SCircularQueue *queue, int *outValue);
	static DA_NOINLINE bool GridSetCell(SChunkGrid *grid, int x, int y, unsigned char value);

	// --- dispatch through data and through vtables ---
	static DA_NOINLINE void DescribeVariant(const SVariantValue &value, char *out, int capacity);
	static DA_NOINLINE int TickStateMachine(int stateIndex, int ticks);
	static DA_NOINLINE int UpdateEntities(CEntityBase **entities, int count, int damage);
	static DA_NOINLINE float EntityHealthTotal(CEntityBase **entities, int count);
	static DA_NOINLINE int ClassifyEntity(CEntityBase *entity);
	static DA_NOINLINE void SortDescriptorsByCost(SVehicleDescriptor *list, int count);
	static DA_NOINLINE void TransformPointBuffer(SPointBuffer *buffer, float scale, float offsetX, float offsetY);

	static DA_NOINLINE void RunSelfChecks(CSelfTest &selfTest);
};

#endif // DA_TESTFUNCTIONS_STRUCTS_H
