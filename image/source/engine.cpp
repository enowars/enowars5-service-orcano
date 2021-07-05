#include "engine.h"
#include "util.h"
#include "quant.h"
#include "host.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>

void Engine::run(const char *request)
{
	OC_LOG("run(%s)\n", request);

	// Configure GQR2
	quant_set_scale(0);
	quant_set_type(QuantType_UInt16);

	const char *p = request;
	const char *rq_end = request + strlen(request);
	while (*p)
	{
		// Skip whitespace
		if (*p == ' ')
		{
			++p;
			continue;
		}

		// Get one command
		const char *cmd_end = strchr(p, ' ');
		if (!cmd_end)
			cmd_end = rq_end;

		// Extract
		int buf_len = cmd_end - p;
		char *buf = (char *)malloc(buf_len + 1);
		buf[buf_len] = '\0';
		memcpy(buf, p, buf_len);

		// Split off the argument section
		// TODO: This entire section is iffy and should be rewritten.
		char *arg_sep = strchr(buf, ':');

		char *name_buf = nullptr;
		const char *name;
		const char *arg;
		if (arg_sep)
		{
			int name_len = arg_sep - buf;
			name_buf = (char *)malloc(name_len + 1);
			memcpy(name_buf, buf, name_len);
			name_buf[name_len] = '\0';
			name = name_buf;
			arg = arg_sep;
		}
		else
		{
			name = buf;
			arg = "";
		}

		// Run it
		runCommand(name, arg);
		free(buf);
		if (name_buf)
			free(name_buf);

		// Check for errors
		// SIC: This happens before the OTP invalidation!
		if (hasError())
		{
			break;
		}

		// Invalidate OTP if necessary
		if (m_otp_touched)
		{
			hostWriteMsg(makeIdent("OTNQ"), 0, nullptr);
			m_otp_touched = false;
		}

		// Advance
		p = cmd_end;
	}
}

void Engine::runCommand(const char *cmd, const char *arg)
{
	OC_LOG("runCommand(%s,%s)\n", cmd, arg);

	const CommandInfo *matching_ci = nullptr;
	for (const CommandInfo *ci = s_commands; ci->name; ++ci)
	{
		if (!strcmp(ci->name, cmd))
		{
			matching_ci = ci;
			break;
		}
	}

	if (!matching_ci)
	{
		// Fail
		syntaxError("invalid command");
		return;
	}

	// Execute the command
	prepareArgs(arg);

	// Prepare args area
	m_stack_arg_size = m_stack_size;

	(this->*(matching_ci->function))();
}

void Engine::putInt(int v)
{
	putStack(StackValue{ .type = StackValueType_Int, .i = v });
}

void Engine::putFloat(float v)
{
	putStack(StackValue{ .type = StackValueType_Float, .f = v });
}

void Engine::putStack(StackValue v)
{
	if (m_stack_size >= (int)OC_ARRAYSIZE(m_stack))
	{
		if (v.type == StackValueType_Float)
			runtimeError("stack overflow (f%.8g)", v.f);
		else
			runtimeError("stack overflow (i%d)", v.i);
		return;
	}

	m_stack[m_stack_size++] = v;
}

StackValue Engine::getStack()
{
	prepareNextArg();
	return readStack();
}

int Engine::getSInt()
{
	prepareNextArg();
	return readSInt();
}

int Engine::getUInt()
{
	prepareNextArg();
	return readUInt();
}

float Engine::getSFloat()
{
	prepareNextArg();
	return readSFloat();
}

float Engine::getUFloat()
{
	prepareNextArg();
	return readUFloat();
}

StackValue Engine::readStack()
{
	if (m_arg_type == ArgumentType_Paired || m_arg_type == ArgumentType_Float)
	{
		return StackValue{ .type = StackValueType_Float, .f = readSFloat() };
	}
	else if (m_arg_type == ArgumentType_Int)
	{
		return StackValue{ .type = StackValueType_Int, .i = readSInt() };
	}

	OC_ERR("unknown immediate type");
}

int Engine::readSInt()
{
	if (m_arg_type == ArgumentType_Paired)
	{
		return (int)readSFloat();
	}
	else if (m_arg_type == ArgumentType_Int)
	{
		return m_arg_value.i;
	}
	else if (m_arg_type == ArgumentType_Float)
	{
		return (int)m_arg_value.f;
	}

	OC_ERR("unknown immediate type");
}

int Engine::readUInt()
{
	if (m_arg_type == ArgumentType_Paired)
	{
		// SIC: we do not clamp.
		return (int)readUFloat();
	}
	else if (m_arg_type == ArgumentType_Int)
	{
		return m_arg_value.i < 0 ? 0 : m_arg_value.i;
	}
	else if (m_arg_type == ArgumentType_Float)
	{
		return ((int)m_arg_value.f) < 0 ? 0 : (int)m_arg_value.f;
	}
	else
	{
		OC_ERR("unknown immediate type");
	}
}

float Engine::readSFloat()
{
	if (m_arg_type == ArgumentType_Paired)
	{
		quant_set_type(QuantType_Int16);
		float v = load_gqr2(&m_arg_ps_data[m_arg_next]);
		OC_LOG("readSFloat paired: gqr = %08x, sf = %f, raw=%04x\n", get_gqr2(), v, m_arg_ps_data[m_arg_next]);
		quant_set_type(QuantType_UInt16);
		return v;
	}
	else if (m_arg_type == ArgumentType_Int)
	{
		return (float)m_arg_value.i;
	}
	else if (m_arg_type == ArgumentType_Float)
	{
		return m_arg_value.f;
	}

	OC_ERR("unknown immediate type");
}

float Engine::readUFloat()
{
	if (m_arg_type == ArgumentType_Paired)
	{
		float v = load_gqr2(&m_arg_ps_data[m_arg_next]);
		OC_LOG("readUFloat paired: gqr = %08x, sf = %f, raw=%04x\n", get_gqr2(), v, m_arg_ps_data[m_arg_next]);
		return v;
	}
	else if (m_arg_type == ArgumentType_Int)
	{
		return (float)m_arg_value.i < 0.f ? 0.f : (float)m_arg_value.i;
	}
	else if (m_arg_type == ArgumentType_Float)
	{
		return m_arg_value.f < 0.f ? 0.f : m_arg_value.f;
	}
	
	OC_ERR("unkown immediate type");
}

void Engine::prepareArgs(const char *arg)
{
	m_arg_text = arg;
	m_arg_next = 0;
	m_arg_available = 0;

	m_arg_type = ArgumentType_Int; // just some default so it's not floating.
	m_arg_value.i = 0;
}

void Engine::prepareNextArg()
{
	// Continue parsing existing one if multiple available
	if (++m_arg_next < m_arg_available)
	{
		return;
	}

	// Set default available, paired overrides this.
	m_arg_next = 0;
	m_arg_available = 1;

	// Parse new argument. Read the ':'.
	char sep = *m_arg_text;
	if (!sep)
	{
		// No more arguments. Feed from stack.
		prepareStackArg();
		return;
	}
	// Move to next argument.
	++m_arg_text;

	// Check argument code.
	char code = *m_arg_text;
	if (!code)
	{
		syntaxError("invalid argument: expected type code");
		prepareDefaultArg();
		return;
	}
	// Move to contents.
	++m_arg_text;

	// Find the start of the next argument or end of this one
	const char *end = strchr(m_arg_text, ':');
	if (!end)
	{
		end = m_arg_text + strlen(m_arg_text);
	}
	const char *got_end = nullptr;

	if (code == 's')
	{
		prepareStackArg();
		got_end = m_arg_text;
	}
	else if (code == 'i')
	{
		m_arg_type = ArgumentType_Int;
		m_arg_value.i = strtol(m_arg_text, (char **)&got_end, 0);
	}
	else if (code == 'f')
	{
		m_arg_type = ArgumentType_Float;
		m_arg_value.f = strtof(m_arg_text, (char **)&got_end);
	}
	else if (code == 'p')
	{
		m_arg_type = ArgumentType_Paired;
		// Decompress Base64
		void *b64_data;
		int b64_len;

		// Make a null terminated version
		int b64_text_len = end - m_arg_text;
		char *b64_text = (char *)alloca(b64_text_len + 1);
		memcpy(b64_text, m_arg_text, b64_text_len);
		b64_text[b64_text_len] = '\0';
		
		if (!base64Decode(b64_text, &b64_data, &b64_len))
		{
			syntaxError("invalid argument: bad paired text");
			prepareDefaultArg();
			return;
		}

		// One byte for scale, following are pairs for entries
		if (b64_len < 3 || (b64_len - 1) % sizeof(int16_t) != 0)
		{
			free(b64_data);
			syntaxError("invalid argument: bad paired len");
			prepareDefaultArg();
			return;
		}

		// Read scale and payload
		int scale = *(int8_t *)b64_data;
		void *payload = ((uint8_t *)b64_data + 1);
		int count = (b64_len - 1) / sizeof(int16_t);
		OC_LOG("p immediate: scale=%d, count=%d\n", scale, count);

		// Drop any excess
		if (count > (int)OC_ARRAYSIZE(m_arg_ps_data))
			count = (int)OC_ARRAYSIZE(m_arg_ps_data);

		memcpy(m_arg_ps_data, payload, count * sizeof(int16_t));
		free(b64_data);

		m_arg_available = count;
		quant_set_scale(scale);
	}
	else
	{
		syntaxError("invalid argument: unexpected type code");
		prepareDefaultArg();
		return;
	}

	if (got_end && got_end != end)
	{
		syntaxError("invalid argument: unexpected post-immediate text");
		prepareDefaultArg();
		return;
	}

	m_arg_text = end;
}

void Engine::prepareStackArg()
{
	// If the stack is empty, provide a default zero
	if (!m_stack_arg_size)
	{
		prepareDefaultArg();
		return;
	}

	// Pop a value off the stack
	StackValue top = m_stack[--m_stack_arg_size];

	// Move up the rest of the stack
	// TODO: double check this math.
	memmove(
		&m_stack[m_stack_arg_size],
		&m_stack[m_stack_arg_size + 1],
		sizeof(StackValue) * (m_stack_size - (m_stack_arg_size + 1))
	);
	--m_stack_size;

	// Prepare
	if (top.type == StackValueType_Int)
	{
		m_arg_type = ArgumentType_Int;
		m_arg_value.i = top.i;
	}
	else if (top.type == StackValueType_Float)
	{
		m_arg_type = ArgumentType_Float;
		m_arg_value.f = top.f;
	}
	else
	{
		OC_ERR("invalid sv type");
	}
}

void Engine::prepareDefaultArg()
{
	m_arg_type = ArgumentType_Int;
	m_arg_value.i = 0;
}

bool Engine::hasError()
{
	return m_error_text[0] ? true : false;
}

const char *Engine::getError()
{
	return m_error_text;
}

void Engine::syntaxError(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	errorv(fmt, args);
	va_end(args);
}

void Engine::runtimeError(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	errorv(fmt, args);
	va_end(args);
}

void Engine::errorv(const char *fmt, va_list args)
{
	if (m_error_text[0])
		return;
	vsnprintf(m_error_text, OC_ARRAYSIZE(m_error_text), fmt, args);
	m_error_text[OC_ARRAYSIZE(m_error_text) - 1] = '\0';
}

void Engine::print(const char *text)
{
	hostWriteMsg(makeIdent("PRTQ"), strlen(text), text);
}

void Engine::dumpStack(char *buffer, int size)
{
	int left = size;
	buffer[0] = '\0';

	const char *prefix = "out:";
	strncat(buffer, prefix, left);
	left -= strlen(prefix);

	// Entries can take more space than one might think because of big floats
	char item_buffer[64];
	for (int i = m_stack_size; i > 0; --i)
	{
		StackValue sv = m_stack[i - 1];
		if (sv.type == StackValueType_Int)
		{
			snprintf(item_buffer, OC_ARRAYSIZE(item_buffer), " i%d", sv.i);
			item_buffer[OC_ARRAYSIZE(item_buffer) - 1] = '\0';
		}
		else if (sv.type == StackValueType_Float)
		{
			snprintf(item_buffer, OC_ARRAYSIZE(item_buffer), " f%.9g", sv.f);
			item_buffer[OC_ARRAYSIZE(item_buffer) - 1] = '\0';
		}
		else
		{
			OC_ERR("bad sv type");
		}

		// todo: is this safe?
		strncat(buffer, item_buffer, left);
		left -= strlen(item_buffer);
	}

	buffer[size - 1] = '\0';
}

int Engine::getStackSize()
{
	return m_stack_size;
}

char *processRequest(const char *request_data)
{
	// Parse commands
	Engine e;
	e.run(request_data);

	if (e.hasError())
	{
		const char *err_text = e.getError();
		const char *err_prefix = "error: ";
		char *out = (char *)malloc(strlen(err_prefix) + strlen(err_text) + 1);
		out[0] = '\0';
		strcat(out, err_prefix);
		strcat(out, err_text);
		return out;
	}

	// Dump stack
	// Size should be sufficient for everything.
	int buffer_size = 16 + e.getStackSize() * 64;
	char *buffer = (char *)malloc(buffer_size);
	e.dumpStack(buffer, buffer_size);

	return buffer;
}