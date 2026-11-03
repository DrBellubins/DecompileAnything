// Implementation of the struct/vtable units. See structs.h for the layouts.
#include "structs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

// --- state machine table: three relocations in .rodata the decompiler must resolve ---
struct SStateEntry
{
	int (*m_onEnter)(void);
	int (*m_onTick)(int tick);
};

static int EnterIdle() { return 10; }
static int TickIdle(int tick) { return 1 + tick; }
static int EnterChase() { return 20; }
static int TickChase(int tick) { return 2 + tick * 2; }
static int EnterFlee() { return 30; }
static int TickFlee(int tick) { return 3 - tick; }

static const SStateEntry g_stateTable[3] = {
	{ EnterIdle, TickIdle },
	{ EnterChase, TickChase },
	{ EnterFlee, TickFlee }
};

// qsort comparator: a file-scope function pointer, i.e. a relocation, not an address.
static int CompareDescriptorCost(const void *leftHandle, const void *rightHandle)
{
	const SVehicleDescriptor *left = (const SVehicleDescriptor *)leftHandle;
	const SVehicleDescriptor *right = (const SVehicleDescriptor *)rightHandle;
	if (left->m_cost < right->m_cost)
		return -1;
	if (left->m_cost > right->m_cost)
		return 1;
	return std::strcmp(left->m_name, right->m_name);
}

// DA-UNIT STRUCT-01 level:medium tags:bitfield,union,guard
unsigned int CStructTests::PackMapStamp(int sector, int layer, bool daylight, bool paused)
{
	UMapStamp stamp;
	stamp.m_raw = 0u;
	if (sector < 0)
		sector = 0;
	if (sector > 63)
		sector = 63;
	if (layer < 0)
		layer = 0;
	if (layer > 7)
		layer = 7;
	stamp.m_bits.m_sector = (unsigned int)sector;
	stamp.m_bits.m_layer = (unsigned int)layer;
	stamp.m_bits.m_daylight = daylight ? 1u : 0u;
	stamp.m_bits.m_paused = paused ? 1u : 0u;
	return stamp.m_raw;
}

// DA-UNIT STRUCT-02 level:medium tags:bitfield,union,out-param
int CStructTests::UnpackMapStamp(unsigned int raw, int *layer, int *daylight)
{
	UMapStamp stamp;
	stamp.m_raw = raw;
	if (layer != 0)
		*layer = (int)stamp.m_bits.m_layer;
	if (daylight != 0)
		*daylight = (int)stamp.m_bits.m_daylight;
	return (int)stamp.m_bits.m_sector;
}

// DA-UNIT STRUCT-03 level:medium tags:union,byte-fields,fixed-point
SRgbColour CStructTests::BlendColours(const SRgbColour &a, const SRgbColour &b, int weight)
{
	int blend = weight;
	if (blend < 0)
		blend = 0;
	if (blend > 256)
		blend = 256;
	SRgbColour out;
	out.m_channels.m_red = (unsigned char)((a.m_channels.m_red * (256 - blend) + b.m_channels.m_red * blend) >> 8);
	out.m_channels.m_green = (unsigned char)((a.m_channels.m_green * (256 - blend) + b.m_channels.m_green * blend) >> 8);
	out.m_channels.m_blue = (unsigned char)((a.m_channels.m_blue * (256 - blend) + b.m_channels.m_blue * blend) >> 8);
	out.m_channels.m_alpha = (unsigned char)((a.m_channels.m_alpha + b.m_channels.m_alpha) >> 1);
	return out;
}

// DA-UNIT STRUCT-04 level:easy tags:struct-return,union,cmp
CRect CStructTests::RectFromCorners(int x0, int y0, int x1, int y1)
{
	CRect out;
	int left = (x0 < x1) ? x0 : x1;
	int right = (x0 < x1) ? x1 : x0;
	int top = (y0 < y1) ? y0 : y1;
	int bottom = (y0 < y1) ? y1 : y0;
	out.m_x = left;
	out.m_y = top;
	out.m_width = right - left;
	out.m_height = bottom - top;
	return out;
}

// DA-UNIT STRUCT-27 level:easy tags:field-offsets,mul,int
int CStructTests::RectArea(const CRect &rect)
{
	int width = rect.m_right - rect.m_left;
	int height = rect.m_bottom - rect.m_top;
	if (width <= 0 || height <= 0)
		return 0;
	return width * height;
}

// DA-UNIT STRUCT-28 level:easy tags:this,field,cmp,bool
int CStructTests::EntityIsAlive(const CEntityBase *entity)
{
	return entity->m_health > 0;
}

// DA-UNIT STRUCT-05 level:medium tags:struct-arg,out-param,cmp-chain
bool CStructTests::RectIntersect(const CRect &a, const CRect &b, CRect *out)
{
	int left = (a.m_left > b.m_left) ? a.m_left : b.m_left;
	int top = (a.m_top > b.m_top) ? a.m_top : b.m_top;
	int right = (a.m_right < b.m_right) ? a.m_right : b.m_right;
	int bottom = (a.m_bottom < b.m_bottom) ? a.m_bottom : b.m_bottom;
	if (left >= right || top >= bottom)
		return false;
	out->m_left = left;
	out->m_top = top;
	out->m_right = right;
	out->m_bottom = bottom;
	return true;
}

// DA-UNIT STRUCT-06 level:medium tags:field-offsets,padding,signed-load
int CStructTests::SumPlayerTimes(const SPlayerStats &stats)
{
	int total = 0;
	for (int index = 0; index < 4; ++index)
	{
		int time = stats.m_bestTimes[index];
		if (time < 0)
			time = 0;
		total += time;
	}
	if (stats.m_wins > 0)
		total += (int)stats.m_wins * 100;
	if (stats.m_difficulty != 0)
		total /= 2;
	return total;
}

// DA-UNIT STRUCT-07 level:hard tags:strncpy,nested-struct,float,branch
void CStructTests::InitVehicleDescriptor(SVehicleDescriptor *out, const char *name, const CVec3 &start, int cost, int mass)
{
	std::strncpy(out->m_name, name, 23);
	out->m_name[23] = 0;
	out->m_startPosition.m_x = start.m_x;
	out->m_startPosition.m_y = start.m_y;
	out->m_startPosition.m_z = start.m_z;
	out->m_cost = cost;
	out->m_mass = mass;
	out->m_grip = (float)mass * 0.001f;
	if (mass > 5000)
		out->m_wheels = 6;
	else
		out->m_wheels = 4;
	if (mass > 8000)
		out->m_seats = 4;
	else
		out->m_seats = 2;
	out->m_tint.m_channels.m_red = 128;
	out->m_tint.m_channels.m_green = 128;
	out->m_tint.m_channels.m_blue = 128;
	out->m_tint.m_channels.m_alpha = 255;
}

// DA-UNIT STRUCT-08 level:medium tags:array-of-struct,stride,strcmp
int CStructTests::FindVehicleByName(const SVehicleDescriptor *list, int count, const char *name)
{
	for (int index = 0; index < count; ++index)
	{
		if (std::strcmp(list[index].m_name, name) == 0)
			return index;
	}
	return -1;
}

// DA-UNIT STRUCT-09 level:easy tags:nested-struct,sse,float
void CStructTests::TranslateDescriptor(SVehicleDescriptor *vehicle, float dx, float dy, float dz)
{
	vehicle->m_startPosition.m_x += dx;
	vehicle->m_startPosition.m_y += dy;
	vehicle->m_startPosition.m_z += dz;
}

// DA-UNIT STRUCT-10 level:hard tags:sizeof,padding,hash,loop
unsigned int CStructTests::ChecksumDescriptorBytes(const SVehicleDescriptor &vehicle)
{
	const unsigned char *bytes = (const unsigned char *)&vehicle;
	unsigned int hash = 5381u;
	for (int index = 0; index < (int)sizeof(SVehicleDescriptor); ++index)
		hash = hash * 33u + (unsigned int)bytes[index];
	return hash;
}

// DA-UNIT STRUCT-11 level:easy tags:ptr-chase,loop
int CStructTests::ListLength(const SListItem *head)
{
	int count = 0;
	const SListItem *node = head;
	while (node != 0)
	{
		++count;
		node = node->m_next;
	}
	return count;
}

// DA-UNIT STRUCT-12 level:hard tags:ptr-chase,double-pointer,unlink
bool CStructTests::RemoveNodeWithValue(SListItem **headRef, int value)
{
	SListItem *previous = 0;
	SListItem *node = *headRef;
	while (node != 0)
	{
		if (node->m_value == value)
		{
			if (previous == 0)
				*headRef = node->m_next;
			else
				previous->m_next = node->m_next;
			node->m_next = 0;
			return true;
		}
		previous = node;
		node = node->m_next;
	}
	return false;
}

// DA-UNIT STRUCT-13 level:hard tags:ptr-chase,in-place,double-pointer
void CStructTests::ReverseListInPlace(SListItem **headRef)
{
	SListItem *previous = 0;
	SListItem *node = *headRef;
	while (node != 0)
	{
		SListItem *next = node->m_next;
		node->m_next = previous;
		previous = node;
		node = next;
	}
	*headRef = previous;
}

// DA-UNIT STRUCT-14 level:easy tags:struct-init,loop,fill
void CStructTests::PoolInit(SPool *pool)
{
	for (int index = 0; index < 16; ++index)
	{
		pool->m_blocks[index].m_value = 0;
		pool->m_blocks[index].m_nextFree = index + 1;
	}
	pool->m_blocks[15].m_nextFree = -1;
	pool->m_firstFree = 0;
	pool->m_allocated = 0;
	pool->m_generation = 0;
}

// DA-UNIT STRUCT-15 level:medium tags:free-list,guard,struct-field
int CStructTests::PoolAlloc(SPool *pool, int value)
{
	int slot = pool->m_firstFree;
	if (slot < 0)
		return -1;
	pool->m_firstFree = pool->m_blocks[slot].m_nextFree;
	pool->m_blocks[slot].m_value = value;
	pool->m_blocks[slot].m_nextFree = -2;
	++pool->m_allocated;
	return slot;
}

// DA-UNIT STRUCT-16 level:medium tags:free-list,guard,double-pointer-free
bool CStructTests::PoolFree(SPool *pool, int slot)
{
	if (slot < 0 || slot >= 16)
		return false;
	if (pool->m_blocks[slot].m_nextFree != -2)
		return false;
	pool->m_blocks[slot].m_value = 0;
	pool->m_blocks[slot].m_nextFree = pool->m_firstFree;
	pool->m_firstFree = slot;
	--pool->m_allocated;
	++pool->m_generation;
	return true;
}

// DA-UNIT STRUCT-17 level:medium tags:mask,wrap,guard
bool CStructTests::QueuePush(SCircularQueue *queue, int value)
{
	if (queue->m_count >= 8)
		return false;
	int slot = (queue->m_head + queue->m_count) & 7;
	queue->m_items[slot] = value;
	++queue->m_count;
	return true;
}

// DA-UNIT STRUCT-18 level:medium tags:mask,wrap,out-param,guard
bool CStructTests::QueuePop(SCircularQueue *queue, int *outValue)
{
	if (queue->m_count <= 0)
		return false;
	*outValue = queue->m_items[queue->m_head];
	queue->m_items[queue->m_head] = 0;
	queue->m_head = (queue->m_head + 1) & 7;
	--queue->m_count;
	return true;
}

// DA-UNIT STRUCT-19 level:medium tags:index-math,bounds,mul
bool CStructTests::GridSetCell(SChunkGrid *grid, int x, int y, unsigned char value)
{
	if (grid->m_cells == 0 || grid->m_width <= 0 || grid->m_height <= 0)
		return false;
	if (x < 0 || y < 0 || x >= grid->m_width || y >= grid->m_height)
		return false;
	grid->m_cells[y * grid->m_width + x] = value;
	return true;
}

// DA-UNIT STRUCT-20 level:hard tags:switch-jump-table,union,format
void CStructTests::DescribeVariant(const SVariantValue &value, char *out, int capacity)
{
	switch (value.m_kind)
	{
		case SVariantValue::KIND_INT:
			std::snprintf(out, (size_t)capacity, "int %d", value.m_number);
			break;
		case SVariantValue::KIND_FLOAT:
			std::snprintf(out, (size_t)capacity, "real %.3f", (double)value.m_real);
			break;
		case SVariantValue::KIND_TEXT:
			if (value.m_text == 0)
				std::snprintf(out, (size_t)capacity, "text null");
			else
				std::snprintf(out, (size_t)capacity, "text %s", value.m_text);
			break;
		default:
			std::snprintf(out, (size_t)capacity, "empty");
			break;
	}
}

// DA-UNIT STRUCT-21 level:hard tags:fnptr,table,guard,call-through
int CStructTests::TickStateMachine(int stateIndex, int ticks)
{
	if (stateIndex < 0 || stateIndex >= 3)
		return -1;
	const SStateEntry &entry = g_stateTable[stateIndex];
	int total = entry.m_onEnter();
	for (int tick = 0; tick < ticks; ++tick)
		total += entry.m_onTick(tick);
	return total;
}

// DA-UNIT STRUCT-22 level:hard tags:vtable,virtual,loop,this
int CStructTests::UpdateEntities(CEntityBase **entities, int count, int damage)
{
	int touched = 0;
	for (int index = 0; index < count; ++index)
	{
		CEntityBase *entity = entities[index];
		if (entity == 0)
			continue;
		if (entity->GetHealth() > 0.0f)
		{
			entity->TakeDamage(damage);
			++touched;
		}
	}
	return touched;
}

// DA-UNIT STRUCT-23 level:hard tags:vtable,virtual,accumulate,float
float CStructTests::EntityHealthTotal(CEntityBase **entities, int count)
{
	float total = 0.0f;
	for (int index = 0; index < count; ++index)
	{
		CEntityBase *entity = entities[index];
		if (entity == 0)
			continue;
		total += entity->GetHealth();
	}
	return total;
}

// DA-UNIT STRUCT-24 level:hard tags:rtti,dynamic-cast,guard
int CStructTests::ClassifyEntity(CEntityBase *entity)
{
	if (entity == 0)
		return -1;
	CVehicleEntity *vehicle = dynamic_cast<CVehicleEntity *>(entity);
	if (vehicle != 0)
		return 100 + vehicle->m_armour;
	CCharacterEntity *character = dynamic_cast<CCharacterEntity *>(entity);
	if (character != 0)
		return 200 + character->m_stamina;
	return entity->Classify();
}

// DA-UNIT STRUCT-25 level:hard tags:qsort,fnptr,stride,array-of-struct
void CStructTests::SortDescriptorsByCost(SVehicleDescriptor *list, int count)
{
	if (count < 2)
		return;
	std::qsort(list, (size_t)count, sizeof(SVehicleDescriptor), CompareDescriptorCost);
}

// DA-UNIT STRUCT-26 level:hard tags:sse,struct-of-arrays,loop,vectorisable
void CStructTests::TransformPointBuffer(SPointBuffer *buffer, float scale, float offsetX, float offsetY)
{
	int count = buffer->m_count;
	if (count < 0)
		count = 0;
	if (count > 16)
		count = 16;
	for (int index = 0; index < count; ++index)
	{
		buffer->m_x[index] = buffer->m_x[index] * scale + offsetX;
		buffer->m_y[index] = buffer->m_y[index] * scale + offsetY;
	}
	buffer->m_count = count;
}

void CStructTests::RunSelfChecks(CSelfTest &st)
{
	char buffer[64];

	{
		DA_CASE(st, "STRUCT-01");
		st.OutUInt("raw", CStructTests::PackMapStamp(5, 3, true, false));
		st.WantUInt("raw", 709u);
		st.OutUInt("max", CStructTests::PackMapStamp(99, 99, false, true));
		st.WantUInt("max", 1535u);
	}
	{
		DA_CASE(st, "STRUCT-02");
		int layer = 0;
		int daylight = 0;
		st.OutInt("sector", CStructTests::UnpackMapStamp(709u, &layer, &daylight));
		st.OutInt("layer", layer);
		st.OutInt("day", daylight);
		st.WantInt("sector", 5);
		st.WantInt("layer", 3);
		st.WantInt("day", 1);
		st.OutInt("nullout", CStructTests::UnpackMapStamp(63u, 0, 0));
		st.WantInt("nullout", 63);
	}
	{
		DA_CASE(st, "STRUCT-03");
		SRgbColour a;
		a.m_channels.m_red = 10;
		a.m_channels.m_green = 20;
		a.m_channels.m_blue = 30;
		a.m_channels.m_alpha = 200;
		SRgbColour b;
		b.m_channels.m_red = 20;
		b.m_channels.m_green = 40;
		b.m_channels.m_blue = 60;
		b.m_channels.m_alpha = 100;
		SRgbColour mixed = CStructTests::BlendColours(a, b, 128);
		st.OutUInt("packed", mixed.m_packed);
		st.WantUInt("packed", 0x962D1E0Fu);
	}
	{
		DA_CASE(st, "STRUCT-04");
		CRect r = CStructTests::RectFromCorners(10, 20, 2, 4);
		st.OutInt("x", r.m_x);
		st.OutInt("y", r.m_y);
		st.OutInt("w", r.m_width);
		st.OutInt("h", r.m_height);
		st.WantInt("x", 2);
		st.WantInt("y", 4);
		st.WantInt("w", 8);
		st.WantInt("h", 16);
		st.OutInt("alias", r.m_bottom);
		st.WantInt("alias", 16);
	}
	{
		DA_CASE(st, "STRUCT-05");
		CRect a;
		a.m_left = 0;
		a.m_top = 0;
		a.m_right = 10;
		a.m_bottom = 10;
		CRect b;
		b.m_left = 5;
		b.m_top = 5;
		b.m_right = 20;
		b.m_bottom = 20;
		CRect out;
		out.m_left = -1;
		st.OutBool("hit", CStructTests::RectIntersect(a, b, &out));
		st.WantBool("hit", true);
		st.OutInt("l", out.m_left);
		st.OutInt("r", out.m_right);
		st.WantInt("l", 5);
		st.WantInt("r", 10);
		CRect far;
		far.m_left = 40;
		far.m_top = 40;
		far.m_right = 50;
		far.m_bottom = 50;
		st.OutBool("miss", CStructTests::RectIntersect(a, far, &out));
		st.WantBool("miss", false);
	}
	{
		DA_CASE(st, "STRUCT-27");
		CRect hit;
		hit.m_left = 5;
		hit.m_top = 5;
		hit.m_right = 10;
		hit.m_bottom = 10;
		st.OutInt("area", CStructTests::RectArea(hit));
		st.WantInt("area", 25);
		// the width/height view of the union has already rewritten the corner view,
		// so this is 7x7 rather than 8x8: the aliasing is part of the answer
		CRect aliased = CStructTests::RectFromCorners(9, 9, 1, 1);
		st.OutInt("aliased", CStructTests::RectArea(aliased));
		st.WantInt("aliased", 49);
		CRect inverted;
		inverted.m_left = 8;
		inverted.m_top = 8;
		inverted.m_right = 2;
		inverted.m_bottom = 2;
		st.OutInt("empty", CStructTests::RectArea(inverted));
		st.WantInt("empty", 0);
	}
	{
		DA_CASE(st, "STRUCT-06");
		SPlayerStats stats;
		std::memset(&stats, 0, sizeof(stats));
		std::strcpy(stats.m_name, "demo");
		stats.m_score = 5000;
		stats.m_wins = 3;
		stats.m_flags = 0x02;
		stats.m_bestTimes[0] = 100;
		stats.m_bestTimes[1] = 200;
		stats.m_bestTimes[2] = -5;
		stats.m_bestTimes[3] = 50;
		stats.m_difficulty = 0;
		st.OutInt("total", CStructTests::SumPlayerTimes(stats));
		st.WantInt("total", 650);
		stats.m_difficulty = 1;
		st.OutInt("halved", CStructTests::SumPlayerTimes(stats));
		st.WantInt("halved", 325);
	}
	SVehicleDescriptor fleet[3];
	{
		DA_CASE(st, "STRUCT-07");
		std::memset(fleet, 0, sizeof(fleet));
		CVec3 start = { 1.5f, -2.25f, 300.0f };
		CStructTests::InitVehicleDescriptor(&fleet[0], "ambulance", start, 4200, 6500);
		CStructTests::InitVehicleDescriptor(&fleet[1], "benny", start, 1200, 3500);
		CStructTests::InitVehicleDescriptor(&fleet[2], "comet", start, 9000, 9500);
		st.OutText("name", fleet[0].m_name);
		st.WantText("name", "ambulance");
		st.OutFloat("grip", fleet[0].m_grip);
		st.WantFloat("grip", 6.5f, 1e-4f);
		st.OutInt("wheels", fleet[0].m_wheels);
		st.WantInt("wheels", 6);
		st.OutInt("seats", fleet[0].m_seats);
		st.WantInt("seats", 2);
		st.OutUInt("tint", fleet[2].m_tint.m_packed);
		st.WantUInt("tint", 0xFF808080u);
		st.OutInt("wheels", fleet[1].m_wheels);
		st.WantInt("wheels", 4);
	}
	{
		DA_CASE(st, "STRUCT-08");
		st.OutInt("hit", CStructTests::FindVehicleByName(fleet, 3, "benny"));
		st.WantInt("hit", 1);
		st.OutInt("miss", CStructTests::FindVehicleByName(fleet, 3, "benson"));
		st.WantInt("miss", -1);
	}
	{
		DA_CASE(st, "STRUCT-09");
		CStructTests::TranslateDescriptor(&fleet[0], 0.5f, -1.25f, 20.0f);
		st.OutFloat("x", fleet[0].m_startPosition.m_x);
		st.OutFloat("y", fleet[0].m_startPosition.m_y);
		st.OutFloat("z", fleet[0].m_startPosition.m_z);
		st.WantFloat("x", 2.0f);
		st.WantFloat("y", -3.5f);
		st.WantFloat("z", 320.0f);
	}
	{
		DA_CASE(st, "STRUCT-10");
		st.OutUInt("hash", CStructTests::ChecksumDescriptorBytes(fleet[1]));
	}
	{
		DA_CASE(st, "STRUCT-11");
		SListItem first = { 10, 0 }, second = { 20, 0 }, third = { 30, 0 };
		first.m_next = &second;
		second.m_next = &third;
		st.OutInt("len", CStructTests::ListLength(&first));
		st.WantInt("len", 3);
		st.OutInt("empty", CStructTests::ListLength(0));
		st.WantInt("empty", 0);
	}
	{
		DA_CASE(st, "STRUCT-12");
		SListItem first = { 10, 0 }, second = { 20, 0 }, third = { 30, 0 };
		first.m_next = &second;
		second.m_next = &third;
		SListItem *head = &first;
		st.OutBool("removed", CStructTests::RemoveNodeWithValue(&head, 20));
		st.WantBool("removed", true);
		st.OutInt("len", CStructTests::ListLength(head));
		st.WantInt("len", 2);
		st.OutInt("tail", head->m_next->m_value);
		st.WantInt("tail", 30);
		st.OutBool("missing", CStructTests::RemoveNodeWithValue(&head, 99));
		st.WantBool("missing", false);
	}
	{
		DA_CASE(st, "STRUCT-13");
		SListItem first = { 10, 0 }, second = { 20, 0 }, third = { 30, 0 };
		first.m_next = &second;
		second.m_next = &third;
		SListItem *head = &first;
		CStructTests::ReverseListInPlace(&head);
		st.OutInt("first", head->m_value);
		st.OutInt("second", head->m_next->m_value);
		st.OutInt("len", CStructTests::ListLength(head));
		st.WantInt("first", 30);
		st.WantInt("second", 20);
		st.WantInt("len", 3);
	}
	SPool pool;
	{
		DA_CASE(st, "STRUCT-14");
		CStructTests::PoolInit(&pool);
		st.OutInt("first", pool.m_firstFree);
		st.WantInt("first", 0);
		st.OutInt("tailNext", pool.m_blocks[15].m_nextFree);
		st.WantInt("tailNext", -1);
	}
	{
		DA_CASE(st, "STRUCT-15");
		st.OutInt("a", CStructTests::PoolAlloc(&pool, 111));
		st.OutInt("b", CStructTests::PoolAlloc(&pool, 222));
		st.WantInt("a", 0);
		st.WantInt("b", 1);
		st.OutInt("value", pool.m_blocks[1].m_value);
		st.WantInt("value", 222);
		st.OutInt("head", pool.m_firstFree);
		st.WantInt("head", 2);
		for (int i = 0; i < 15; ++i)
			CStructTests::PoolAlloc(&pool, i);
		st.OutInt("full", CStructTests::PoolAlloc(&pool, 7));
		st.WantInt("full", -1);
	}
	{
		DA_CASE(st, "STRUCT-16");
		st.OutBool("free", CStructTests::PoolFree(&pool, 1));
		st.WantBool("free", true);
		st.OutBool("twice", CStructTests::PoolFree(&pool, 1));
		st.WantBool("twice", false);
		st.OutBool("oob", CStructTests::PoolFree(&pool, 99));
		st.WantBool("oob", false);
		st.OutInt("reuse", CStructTests::PoolAlloc(&pool, 555));
		st.WantInt("reuse", 1);
		st.OutInt("gen", pool.m_generation);
		st.WantInt("gen", 1);
	}
	SCircularQueue queue;
	{
		DA_CASE(st, "STRUCT-17");
		std::memset(&queue, 0, sizeof(queue));
		for (int i = 0; i < 8; ++i)
			CStructTests::QueuePush(&queue, i * 3);
		st.OutBool("full", CStructTests::QueuePush(&queue, 999));
		st.WantBool("full", false);
		st.OutInt("count", queue.m_count);
		st.WantInt("count", 8);
		st.OutInt("slot7", queue.m_items[7]);
		st.WantInt("slot7", 21);
	}
	{
		DA_CASE(st, "STRUCT-18");
		int value = 0;
		st.OutBool("pop", CStructTests::QueuePop(&queue, &value));
		st.OutInt("v0", value);
		st.WantBool("pop", true);
		st.WantInt("v0", 0);
		CStructTests::QueuePop(&queue, &value);
		st.OutInt("v1", value);
		st.WantInt("v1", 3);
		for (int i = 0; i < 6; ++i)
			CStructTests::QueuePop(&queue, &value);
		st.OutBool("empty", CStructTests::QueuePop(&queue, &value));
		st.WantBool("empty", false);
		st.OutInt("head", queue.m_head);
		st.WantInt("head", 0);
	}
	{
		DA_CASE(st, "STRUCT-19");
		unsigned char cells[24];
		std::memset(cells, 0, sizeof(cells));
		SChunkGrid grid;
		grid.m_width = 6;
		grid.m_height = 4;
		grid.m_cells = cells;
		st.OutBool("ok", CStructTests::GridSetCell(&grid, 5, 3, 0x7F));
		st.WantBool("ok", true);
		st.OutInt("cell", cells[3 * 6 + 5]);
		st.WantInt("cell", 0x7F);
		st.OutBool("oob", CStructTests::GridSetCell(&grid, 6, 0, 1));
		st.WantBool("oob", false);
		st.OutBool("neg", CStructTests::GridSetCell(&grid, -1, 0, 1));
		st.WantBool("neg", false);
		SChunkGrid empty = { 0, 0, 0 };
		st.OutBool("noptr", CStructTests::GridSetCell(&empty, 0, 0, 1));
		st.WantBool("noptr", false);
	}
	{
		DA_CASE(st, "STRUCT-20");
		SVariantValue number;
		number.m_kind = SVariantValue::KIND_INT;
		number.m_number = -4200;
		CStructTests::DescribeVariant(number, buffer, sizeof(buffer));
		st.OutText("int", buffer);
		st.WantText("int", "int -4200");
		SVariantValue real;
		real.m_kind = SVariantValue::KIND_FLOAT;
		real.m_real = 2.5f;
		CStructTests::DescribeVariant(real, buffer, sizeof(buffer));
		st.OutText("real", buffer);
		st.WantText("real", "real 2.500");
		SVariantValue text;
		text.m_kind = SVariantValue::KIND_TEXT;
		text.m_text = "cargo";
		CStructTests::DescribeVariant(text, buffer, sizeof(buffer));
		st.OutText("text", buffer);
		st.WantText("text", "text cargo");
		SVariantValue empty;
		empty.m_kind = SVariantValue::KIND_EMPTY;
		empty.m_number = 0;
		CStructTests::DescribeVariant(empty, buffer, sizeof(buffer));
		st.OutText("empty", buffer);
		st.WantText("empty", "empty");
	}
	{
		DA_CASE(st, "STRUCT-21");
		st.OutInt("chase", CStructTests::TickStateMachine(1, 3));
		st.WantInt("chase", 32);
		st.OutInt("flee", CStructTests::TickStateMachine(2, 3));
		st.WantInt("flee", 36);
		st.OutInt("bad", CStructTests::TickStateMachine(7, 1));
		st.WantInt("bad", -1);
	}
	CVehicleEntity vehicle;
	CCharacterEntity character;
	{
		DA_CASE(st, "STRUCT-22");
		vehicle.m_armour = 40;
		vehicle.m_tag = 7;
		character.m_stamina = 80;
		CEntityBase *roster[3] = { &vehicle, &character, 0 };
		st.OutInt("touched", CStructTests::UpdateEntities(roster, 3, 30));
		st.WantInt("touched", 2);
		st.OutInt("vehicleHealth", vehicle.m_health);
		st.WantInt("vehicleHealth", 70);
		st.OutInt("characterHealth", character.m_health);
		st.WantInt("characterHealth", 70);
	}
	{
		DA_CASE(st, "STRUCT-28");
		st.OutInt("alive", CStructTests::EntityIsAlive(&character));
		st.WantInt("alive", 1);
		CEntityBase *dead = 0;
		(void)dead;
		vehicle.m_health = 0;
		st.OutInt("zeroHealth", CStructTests::EntityIsAlive(&vehicle));
		st.WantInt("zeroHealth", 0);
		vehicle.m_health = 70;	// put it back the way STRUCT-22 left it
	}
	{
		DA_CASE(st, "STRUCT-23");
		CEntityBase *roster[3] = { &vehicle, &character, 0 };
		st.OutFloat("total", CStructTests::EntityHealthTotal(roster, 3));
		st.WantFloat("total", 146.0f, 1e-3f);
	}
	{
		DA_CASE(st, "STRUCT-24");
		st.OutInt("vehicle", CStructTests::ClassifyEntity(&vehicle));
		st.WantInt("vehicle", 140);
		st.OutInt("character", CStructTests::ClassifyEntity(&character));
		st.WantInt("character", 280);
		st.OutInt("null", CStructTests::ClassifyEntity(0));
		st.WantInt("null", -1);
	}
	{
		DA_CASE(st, "STRUCT-25");
		CStructTests::SortDescriptorsByCost(fleet, 3);
		st.OutText("first", fleet[0].m_name);
		st.OutText("second", fleet[1].m_name);
		st.OutText("third", fleet[2].m_name);
		st.WantText("first", "benny");
		st.WantText("second", "ambulance");
		st.WantText("third", "comet");
		st.OutInt("kept", fleet[2].m_mass);
		st.WantInt("kept", 9500);
	}
	{
		DA_CASE(st, "STRUCT-26");
		SPointBuffer points;
		std::memset(&points, 0, sizeof(points));
		points.m_count = 3;
		for (int i = 0; i < 3; ++i)
		{
			points.m_x[i] = (float)i * 2.0f;
			points.m_y[i] = (float)i * -1.0f;
			points.m_z[i] = 5.0f;
		}
		CStructTests::TransformPointBuffer(&points, 2.0f, 1.5f, -0.5f);
		st.OutFloat("x0", points.m_x[0]);
		st.OutFloat("x2", points.m_x[2]);
		st.OutFloat("y1", points.m_y[1]);
		st.OutFloat("zUntouched", points.m_z[2]);
		st.WantFloat("x0", 1.5f);
		st.WantFloat("x2", 9.5f);
		st.WantFloat("y1", -2.5f);
		st.WantFloat("zUntouched", 5.0f);
	}
}
