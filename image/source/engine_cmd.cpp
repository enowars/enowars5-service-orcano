#include <cstring>

#include "engine.h"
#include "host.h"

const Engine::CommandInfo Engine::s_commands[] = {
	{ "int", &Engine::cmd_int },
	{ "float", &Engine::cmd_float },
	{ "dup", &Engine::cmd_dup },
	{ "rpt", &Engine::cmd_rpt },
	{ "del", &Engine::cmd_del },
	{ "drop", &Engine::cmd_drop },
	{ "stack", &Engine::cmd_stack },

	{ "addi", &Engine::cmd_addi },
	{ "addf", &Engine::cmd_addf },
	{ "muli", &Engine::cmd_muli },
	{ "mulf", &Engine::cmd_mulf },

	{ "poly", &Engine::cmd_poly },
	{ "weight", &Engine::cmd_weight },

	{ "user", &Engine::cmd_user },
	{ "getn", &Engine::cmd_getn },
	{ "setn", &Engine::cmd_setn },
	{ "lockn", &Engine::cmd_lockn },

	{ "inspect", &Engine::cmd_inspect },

#if !OC_FINAL
	{ "dbg_fail", &Engine::cmd_dbg_fail },
#endif

	{ nullptr, nullptr }
};

void Engine::cmd_int()
{
	putInt(getSInt());
}

void Engine::cmd_float()
{
	putFloat(getSFloat());
}

void Engine::cmd_dup()
{
	StackValue sv = getStack();
	putStack(sv);
	putStack(sv);
}

void Engine::cmd_rpt()
{
	int count = getUInt();
	StackValue sv = getStack();
	for (int i = 0; i < count; ++i)
	{
		putStack(sv);
	}
}

void Engine::cmd_del()
{
	getStack();
}

void Engine::cmd_drop()
{
	int count = getUInt();
	for (int i = 0; i < count; ++i)
	{
		getStack();
	}
}

void Engine::cmd_stack()
{
	putStack(getStack());
}

void Engine::cmd_addi()
{
	int lhs = getSInt();
	int rhs = getSInt();
	putInt(lhs + rhs);
}

void Engine::cmd_addf()
{
	float lhs = getSFloat();
	float rhs = getSFloat();
	putFloat(lhs + rhs);
}

void Engine::cmd_muli()
{
	int lhs = getSInt();
	int rhs = getSInt();
	putInt(lhs * rhs);
}

void Engine::cmd_mulf()
{
	float lhs = getSFloat();
	float rhs = getSFloat();
	putFloat(lhs * rhs);
}

void Engine::cmd_poly()
{
	int count = getUInt();

	float x = getSFloat();

	float xp = 1.f;
	float y = 0.f;
	for (int i = 0; i < count; ++i)
	{
		float coeff = getSFloat();
		y += coeff * xp;
		xp *= x;
	}

	putFloat(y);
}

void Engine::cmd_weight()
{
	CustomArgParser p(this);

	// Set up quantizer: 8-bit signed, 6 bits shift
	// range: [-2;2[
	p.setQuantType(QuantType_Int8);
	p.setQuantScale(6);

	// Init arg data
	// TODO: This will change when we do the arg parsing refactor
	const char *arg_end = m_arg_text + strlen(m_arg_text);
	const char *arg_start = m_arg_text + 1;
	p.setText(arg_start, arg_end);
	// Draw remaining args from stack
	m_arg_text = "";

	// Decompress data
	p.decompressBase64();

	float sum = 0.f;
	while (p.getRemaining() > 0)
	{
		float coeff = p.getQuant();
		float value = getSFloat();
		sum += coeff * value;
	}

	putFloat(sum);
}

void Engine::cmd_user()
{
	// Helper to retrieve one half of the key
	auto recv_key = [](int uid0, int uid1, int idx) {
		// Request num
		struct __attribute__((__packed__))
		{
			int uid0;
			int uid1;
			int idx;
		} getn_buffer;
		getn_buffer.uid0 = uid0;
		getn_buffer.uid1 = uid1;
		getn_buffer.idx = idx;
		hostWriteMsg(makeIdent("GTNQ"), sizeof(getn_buffer), &getn_buffer);

		// Read response
		uint32_t answer_ident;
		uint32_t answer_len;
		void *answer_data;
		hostReadMsg(&answer_ident, &answer_len, &answer_data);
		if (answer_ident != makeIdent("GTNA") || answer_len != sizeof(StackValue))
		{
			OC_ERR("user recv_key failure");
			return 0;
		}

		StackValue num;
		memcpy(&num, answer_data, sizeof(num));
		free(answer_data);

		// This may interpret float as int but for auth purposes this is fine.
		return num.i;
	};

	// Get args
	int uid0 = getSInt();
	int uid1 = getSInt();
	int key0 = getSInt();
	int key1 = getSInt();

	constexpr int kKey0Idx = 0x20000000;
	constexpr int kKey1Idx = 0x20000001;

	// Get stored keys
	int stored_key0 = recv_key(uid0, uid1, kKey0Idx);
	int stored_key1 = recv_key(uid0, uid1, kKey1Idx);

	bool success = false;
	if (stored_key0 || stored_key1)
	{
		// Password exists, check for match
		if (key0 == stored_key0 && key1 == stored_key1)
		{
			success = true;
		}
	}
	else
	{
		// Key unset, register
		struct __attribute__((__packed__))
		{
			int uid0;
			int uid1;
			int idx;
			StackValue sv;
		} setn_buffer;
		setn_buffer.uid0 = uid0;
		setn_buffer.uid1 = uid1;
		setn_buffer.sv = { .type = StackValueType_Int };

		// Set lower half
		setn_buffer.idx = kKey0Idx;
		setn_buffer.sv.i = key0;
		hostWriteMsg(makeIdent("STNQ"), sizeof(setn_buffer), &setn_buffer);

		// Set upper half
		setn_buffer.idx = kKey1Idx;
		setn_buffer.sv.i = key1;
		hostWriteMsg(makeIdent("STNQ"), sizeof(setn_buffer), &setn_buffer);

		// Sign in
		success = true;
	}

	if (success)
	{
		putInt(1);
		m_user_authenticated = true;
		m_user_uid0 = uid0;
		m_user_uid1 = uid1;
	}
	else
	{
		putInt(0);
	}
}

void Engine::cmd_setn()
{
	struct __attribute__((__packed__))
	{
		int uid0;
		int uid1;
		int idx;
		StackValue sv;
	} setn_buffer;

	setn_buffer.idx = getSInt();
	setn_buffer.sv = getStack();

	if (!m_user_authenticated)
		return;

	setn_buffer.uid0 = m_user_uid0;
	setn_buffer.uid1 = m_user_uid1;
	
	hostWriteMsg(makeIdent("STNQ"), sizeof(setn_buffer), &setn_buffer);
}

void Engine::cmd_getn()
{
	struct __attribute__((__packed__))
	{
		int uid0;
		int uid1;
		int idx;
	} getn_buffer;

	getn_buffer.idx = getSInt();

	if (!m_user_authenticated)
	{
		// Put a default for stack consistency
		putInt(0);
		return;
	}

	getn_buffer.uid0 = m_user_uid0;
	getn_buffer.uid1 = m_user_uid1;
	
	hostWriteMsg(makeIdent("GTNQ"), sizeof(getn_buffer), &getn_buffer);
	uint32_t gtna_ident, gtna_size;
	void *gtna_data;
	hostReadMsg(&gtna_ident, &gtna_size, &gtna_data);
	if (gtna_ident != makeIdent("GTNA") || gtna_size != 8)
	{
		// TODO should we ERRQ here?
		runtimeError("bad answer for getn command");
		free(gtna_data);
		return;
	}

	StackValue sv;
	memcpy(&sv, gtna_data, sizeof(sv));
	free(gtna_data);
	putStack(sv);
}

void Engine::cmd_lockn()
{
	struct __attribute__((__packed__))
	{
		int uid0;
		int uid1;
		int idx;
	} lockn_buffer;

	lockn_buffer.idx = getUInt();

	if (!m_user_authenticated)
		return;

	lockn_buffer.uid0 = m_user_uid0;
	lockn_buffer.uid1 = m_user_uid1;

	hostWriteMsg(makeIdent("LKNQ"), sizeof(lockn_buffer), &lockn_buffer);
}

void Engine::cmd_inspect()
{
	int num_ints = getUInt();
	int num_floats = getUInt();

	OC_LOG("SPOILER: inspect num_ints=%d, num_floats=%d\n", num_ints, num_floats);

	uint32_t ident = makeIdent("INSQ");
	int size = sizeof(int) + num_ints * sizeof(int) + num_floats * sizeof(float);
	OC_LOG("SPOILER: size=%d\n", size);

	hostWrite(&ident, sizeof(ident));
	hostWrite(&size, sizeof(size));

	hostWrite(&num_ints, sizeof(num_ints));

	for (int i = 0; i < num_ints; ++i)
	{
		int v = getSInt();
		hostWrite(&v, sizeof(int));
	}
	for (int i = 0; i < num_floats; ++i)
	{
		float v = getSFloat();
		hostWrite(&v, sizeof(float));
	}

	hostFlush();
}

#if !OC_FINAL
void Engine::cmd_dbg_fail()
{
	const char *msg = "dbg_fail invoked";
	hostWriteMsg(makeIdent("ERRQ"), strlen(msg), msg);
}
#endif