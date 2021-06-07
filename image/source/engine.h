#pragma once

#include "quant.h"
#include "host.h"
#include "util.h"

#include <cstdlib>
#include <cstring>

enum StackValueType
{
	StackValueType_Int,
	StackValueType_Float,
};

enum ArgumentType
{
	ArgumentType_Int,
	ArgumentType_Float,
	ArgumentType_Paired,
};

struct StackValue
{
	int type;
	union
	{
		float f;
		int i;
	};
} __attribute__((__packed__));

class Engine;

class CustomArgParser
{
public:
	CustomArgParser(Engine *engine)
	{
		m_engine = engine;
	}

	~CustomArgParser()
	{
		if (m_gqr_dirty)
		{
			set_gqr2(m_gqr_saved);
		}
	}

	int getSeek()
	{
		return m_seek;
	}

	int getSize()
	{
		return m_size;
	}

	int getRemaining()
	{
		return m_size - m_seek;
	}

	void setText(const char *start, const char *end);	

	void setQuantScale(int scale)
	{
		setQuantDirty();
		quant_set_scale(scale);
	}

	void setQuantType(int type)
	{
		setQuantDirty();
		quant_set_type(type);
		switch (type)
		{
		case QuantType_Float:
			m_gqr_width = 4;
			break;
		case QuantType_UInt16:
		case QuantType_Int16:
			m_gqr_width = 2;
			break;
		case QuantType_UInt8:
		case QuantType_Int8:
			m_gqr_width = 1;
			break;
		default:
			OC_ERR("bad gqr type");
			break;
		}
	}

	float getQuant();

	void decompressBase64();

private:
	void setQuantDirty()
	{
		if (!m_gqr_dirty)
		{
			m_gqr_dirty = true;
			m_gqr_saved = get_gqr2();
		}
	}

	Engine *m_engine;
	int m_seek;
	int m_size;
	char m_buffer[0x100];
	// SIC: This needs to be after the buffer for the overflow to work out!
	bool m_gqr_dirty = false;
	int m_gqr_width = 2;
	uint32_t m_gqr_saved;
};

class Engine
{
public:
	void run(const char *request);
	const char *getError();

	void dumpStack(char *buffer, int size);
	int getStackSize();

private:
	void runCommand(const char *cmd, const char *arg);

	// Argument and stack handling
	void putStack(StackValue v);
	void putInt(int v);
	void putFloat(float v);

	StackValue getStack();
	int getSInt();
	int getUInt();
	float getSFloat();
	float getUFloat();

	StackValue readStack();
	int readSInt();
	int readUInt();
	float readSFloat();
	float readUFloat();

	void prepareArgs(const char *arg);
	void prepareNextArg();

	void prepareStackArg();
	void prepareDefaultArg();

	// Error handling
	void syntaxError(const char *text);
	void runtimeError(const char *text);

	// Commands
	void cmd_int();
	void cmd_float();
	void cmd_dup();
	void cmd_rpt();
	void cmd_del();
	void cmd_drop();
	void cmd_stack();

	void cmd_addi();
	void cmd_addf();
	void cmd_muli();
	void cmd_mulf();

	void cmd_poly();
	void cmd_weight();

	void cmd_user();
	void cmd_getn();
	void cmd_setn();
	void cmd_lockn();

	void cmd_inspect();

#if !OC_FAIL
	void cmd_dbg_fail();
#endif

private:
	StackValue m_stack[256] = {};
	int m_stack_size = 0;
	int m_stack_arg_size = 0;

	// Data for current command
	const char *m_arg_text;

	constexpr static int k_paired_argument_max = 32;
	int m_arg_type;
	int m_arg_next;
	int m_arg_available;
	union
	{
		StackValue m_arg_value;
		uint16_t m_arg_ps_data[k_paired_argument_max];
	};

	// Authentication
	bool m_user_authenticated = false;
	int m_user_uid0 = 0;
	int m_user_uid1 = 0;

	// Error handling
	const char *m_error_text = nullptr;

	// Command definitions
	struct CommandInfo
	{
		const char *name = nullptr;
		void (Engine::*function)() = nullptr;
	};
	
	const static CommandInfo s_commands[];

	friend class CustomArgParser;
};

char *processRequest(const char *request_data);