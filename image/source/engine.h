#pragma once

#include "quant.h"
#include "host.h"
#include "util.h"

#include <cstdarg>
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
	CustomArgParser(Engine *engine);
	~CustomArgParser();

	void setArgString();
	void setText(const char *start, const char *end);

	int getSeek();
	int getSize();
	int getRemaining();

	void setQuantScale(int scale);
	void setQuantType(int type);

	float getQuant();
	char getChar();
	const char *getText();

	void decompressBase64();

private:

	void setQuantDirty();

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
	bool hasError();
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
	void syntaxError(const char *fmt, ...);
	void runtimeError(const char *fmt, ...);
	void errorv(const char *fmt, va_list args);

	void print(const char *text);

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

	void cmd_otp_init();
	void cmd_otp_auth();
	void cmd_otp_sync();

	void cmd_inspect();
	void cmd_print();
#if !OC_MINIMAL_DOCS
	void cmd_help();
#endif

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

	bool m_otp_touched = false;

	// Error handling
	char m_error_text[256] = "";

	// Command definitions
	struct CommandInfo
	{
		const char *name = nullptr;
		void (Engine::*function)() = nullptr;
#if !OC_MINIMAL_DOCS
		const char *help = nullptr;
#endif
	};
	
	const static CommandInfo s_commands[];

	friend class CustomArgParser;
};

char *processRequest(const char *request_data);