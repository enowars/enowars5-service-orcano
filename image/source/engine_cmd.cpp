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

	{ "addi", &Engine::cmd_addi },
	{ "addf", &Engine::cmd_addf },
	{ "muli", &Engine::cmd_muli },
	{ "mulf", &Engine::cmd_mulf },

	{ "user", &Engine::cmd_user },
	{ "getn", &Engine::cmd_getn },
	{ "setn", &Engine::cmd_setn },
	{ "lockn", &Engine::cmd_lockn },

	{ "dbg_fail", &Engine::cmd_dbg_fail },

	{ nullptr, nullptr }
};

void Engine::cmd_int()
{
	int v;
	getSInt(&v);
	putInt(v);
}

void Engine::cmd_float()
{
	float v;
	getSFloat(&v);
	putFloat(v);
}

void Engine::cmd_dup()
{
	StackValue sv;
	getStack(&sv);
	putStack(sv);
	putStack(sv);
}

void Engine::cmd_rpt()
{
	int count;
	getUInt(&count);
	StackValue sv;
	getStack(&sv);
	for (int i = 0; i < count; ++i)
	{
		putStack(sv);
	}
}

void Engine::cmd_del()
{
	StackValue sv;
	getStack(&sv);
}

void Engine::cmd_drop()
{
	int count;
	getUInt(&count);
	for (int i = 0; i < count; ++i)
	{
		StackValue sv;
		getStack(&sv);
	}
}

void Engine::cmd_addi()
{
	int lhs, rhs;
	getSInt(&lhs);
	getSInt(&rhs);
	putInt(lhs + rhs);
}

void Engine::cmd_addf()
{
	float lhs, rhs;
	getSFloat(&lhs);
	getSFloat(&rhs);
	putFloat(lhs + rhs);
}

void Engine::cmd_muli()
{
	int lhs, rhs;
	getSInt(&lhs);
	getSInt(&rhs);
	putInt(lhs * rhs);
}

void Engine::cmd_mulf()
{
	float lhs, rhs;
	getSFloat(&lhs);
	getSFloat(&rhs);
	putFloat(lhs * rhs);
}

void Engine::cmd_user()
{
	struct __attribute__((__packed__))
	{
		int uid0;
		int uid1;
		int key0;
		int key1;
	} msg_buffer;
	getSInt(&msg_buffer.uid0);
	getSInt(&msg_buffer.uid1);
	getSInt(&msg_buffer.key0);
	getSInt(&msg_buffer.key1);
	hostWriteMsg(makeIdent("USRQ"), sizeof(msg_buffer), &msg_buffer);

	uint32_t answer_ident;
	uint32_t answer_len;
	void *answer_data;
	hostReadMsg(&answer_ident, &answer_len, &answer_data);

	if (answer_ident != makeIdent("USRA") || answer_len != 4)
	{
		// TODO should we ERRQ here?
		runtimeError("bad answer for user cmd");
		free(answer_data);
		return;
	}

	int success = *(uint32_t *)answer_data;
	free(answer_data);
	putInt(success);

	if (success)
	{
		m_user_authenticated = true;
		m_user_uid0 = msg_buffer.uid0;
		m_user_uid1 = msg_buffer.uid1;
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

	getSInt(&setn_buffer.idx);
	getStack(&setn_buffer.sv);

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

	getSInt(&getn_buffer.idx);

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

	getUInt(&lockn_buffer.idx);

	if (!m_user_authenticated)
		return;

	lockn_buffer.uid0 = m_user_uid0;
	lockn_buffer.uid1 = m_user_uid1;

	hostWriteMsg(makeIdent("LKNQ"), sizeof(lockn_buffer), &lockn_buffer);
}

void Engine::cmd_dbg_fail()
{
	const char *msg = "dbg_fail invoked";
	hostWriteMsg(makeIdent("ERRQ"), strlen(msg), msg);
}