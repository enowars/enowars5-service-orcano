#include "engine.h"
#include "host.h"

const Engine::CommandInfo Engine::s_commands[] = {
	{ "int", &Engine::cmd_int },
	{ "float", &Engine::cmd_float },
	{ "addi", &Engine::cmd_addi },
	{ "addf", &Engine::cmd_addf },
	{ "muli", &Engine::cmd_muli },
	{ "mulf", &Engine::cmd_mulf },
	{ "user", &Engine::cmd_user },
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
	struct
	{
		int uid;
		int pass;
	} msg_buffer;
	getUInt(&msg_buffer.uid);
	getUInt(&msg_buffer.pass);
	hostWriteMsg(makeIdent("USRQ"), sizeof(msg_buffer), &msg_buffer);

	uint32_t answer_ident;
	uint32_t answer_len;
	void *answer_data;
	hostReadMsg(&answer_ident, &answer_len, &answer_data);

	if (answer_ident != makeIdent("USRA") || answer_len != 4)
	{
		runtimeError("bad answer for user cmd");
		free(answer_data);
		return;
	}

	int success = *(uint32_t *)answer_data;
	free(answer_data);
	putInt(success);
}