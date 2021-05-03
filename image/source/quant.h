#pragma once

#include <cstdint>

// We use GQR2 for all our quantization needs.
extern "C"
{

void set_gqr2(uint32_t v);
uint32_t get_gqr2();
float load_gqr2(void *p);
void store_gqr2(void *p, float f);

};

// ppc_750cl.pdf Table 2-20
enum
{
	QuantType_Float = 0,
	QuantType_UInt8 = 4,
	QuantType_UInt16 = 5,
	QuantType_Int8 = 6,
	QuantType_Int16 = 7,
};

void quant_set_scale(int scale)
{
	constexpr uint32_t scale_bits = 6;
	constexpr uint32_t scale_mask = (1 << scale_bits) - 1;
	scale &= scale_mask;

	uint32_t gqr = get_gqr2();
	gqr &= ~((scale_mask << 24) | (scale_mask << 8));
	gqr |= ((scale << 24) | (scale << 8));
	set_gqr2(gqr);
}

void quant_set_type(int type)
{
	constexpr uint32_t type_bits = 3;
	constexpr uint32_t type_mask = (1 << type_bits);
	type &= type_mask;

	uint32_t gqr = get_gqr2();
	gqr &= ~((type_mask << 16) | (type_mask << 0));
	gqr |= ((type << 8) | (type << 0));
	set_gqr2(gqr);
}