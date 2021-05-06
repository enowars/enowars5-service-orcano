#pragma once

#include <cstdint>

enum StackValueType
{
	StackValueType_Int,
	StackValueType_Float,
};

enum ImmediateType
{
	ImmediateType_Int,
	ImmediateType_Float,
	ImmediateType_Paired,
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
	bool putStack(StackValue v);
	bool putInt(int v);
	bool putFloat(float v);

	bool getStack(StackValue *v);
	bool getSInt(int *v);
	bool getUInt(int *v);
	bool getSFloat(float *v);
	bool getUFloat(float *v);

	bool readStack(StackValue *v);
	bool readSInt(int *v);
	bool readUInt(int *v);
	bool readSFloat(float *v);
	bool readUFloat(float *v);

	void prepareArgs(const char *arg);
	bool prepareNextArg();

	void prepareStackArg();

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

	void cmd_addi();
	void cmd_addf();
	void cmd_muli();
	void cmd_mulf();

	void cmd_user();
	void cmd_getn();
	void cmd_setn();
	void cmd_lockn();

	void cmd_dbg_fail();

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
};

char *processRequest(const char *request_data);