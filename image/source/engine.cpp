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
			char *name_buf = (char *)malloc(name_len + 1);
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
		if (m_error_text)
		{
			break;
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

bool Engine::putInt(int v)
{
	StackValue sv;
	sv.type = StackValueType_Int;
	sv.i = v;
	return putStack(sv);
}

bool Engine::putFloat(float v)
{
	StackValue sv;
	sv.type = StackValueType_Float;
	sv.f = v;
	return putStack(sv);
}

bool Engine::putStack(StackValue v)
{
	if (m_stack_size >= (int)OC_ARRAYSIZE(m_stack))
	{
		runtimeError("stack overflow");
		return false;
	}

	m_stack[m_stack_size++] = v;
	return true;
}

bool Engine::getStack(StackValue *v)
{
	if (!prepareNextArg())
		return false;
	return readStack(v);
}

bool Engine::getSInt(int *v)
{
	if (!prepareNextArg())
		return false;
	return readSInt(v);
}

bool Engine::getUInt(int *v)
{
	if (!prepareNextArg())
		return false;
	return readUInt(v);
}

bool Engine::getSFloat(float *v)
{
	if (!prepareNextArg())
		return false;
	return readSFloat(v);
}

bool Engine::getUFloat(float *v)
{
	if (!prepareNextArg())
		return false;
	return readUFloat(v);
}

bool Engine::readStack(StackValue *v)
{
	if (m_arg_type == ImmediateType_Paired)
	{
		float f;
		if (!readSFloat(&f))
			return false;
		v->type = StackValueType_Float;
		v->f = f;
		return true;
	}

	if (m_arg_type == ImmediateType_Int)
	{
		v->type = StackValueType_Int;
		if (!readSInt(&v->i))
			return false;
	}
	else if (m_arg_type == ImmediateType_Float)
	{
		v->type = StackValueType_Float;
		if (!readSFloat(&v->f))
			return false;
	}
	return true;
}

bool Engine::readSInt(int *v)
{
	if (m_arg_type == ImmediateType_Paired)
	{
		float f;
		if (!readSFloat(&f))
			return false;
		*v = (int)f;
		return true;
	}

	if (m_arg_type == ImmediateType_Int)
	{
		*v = m_arg_value.i;
	}
	else if (m_arg_type == ImmediateType_Float)
	{
		*v = (int)m_arg_value.f;
	}

	return true;
}

bool Engine::readUInt(int *v)
{
	if (m_arg_type == ImmediateType_Paired)
	{
		float f;
		if (!readUFloat(&f))
			return false;
		*v = (int)f;
		// SIC: we do not clamp.
		return true;
	}

	if (m_arg_type == ImmediateType_Int)
	{
		*v = m_arg_value.i;
	}
	else if (m_arg_type == ImmediateType_Float)
	{
		*v = (int)m_arg_value.f;
	}

	// Clamp
	if (*v < 0)
	{
		*v = 0;
	}

	return true;
}

bool Engine::readSFloat(float *v)
{
	if (m_arg_type == ImmediateType_Paired)
	{
		quant_set_type(QuantType_Int16);
		*v = load_gqr2(&m_arg_ps_data[m_arg_next]);
		OC_LOG("readSFloat paired: gqr = %08x, sf = %f, raw=%04x\n", get_gqr2(), *v, m_arg_ps_data[m_arg_next]);
		quant_set_type(QuantType_UInt16);
		return true;
	}

	if (m_arg_type == ImmediateType_Int)
	{
		*v = (float)m_arg_value.i;
	}
	else if (m_arg_type == ImmediateType_Float)
	{
		*v = m_arg_value.f;
	}

	return true;
}

bool Engine::readUFloat(float *v)
{
	if (m_arg_type == ImmediateType_Paired)
	{
		*v = load_gqr2(&m_arg_ps_data[m_arg_next]);
		OC_LOG("readUFloat paired: gqr = %08x, sf = %f, raw=%04x\n", get_gqr2(), *v, m_arg_ps_data[m_arg_next]);
		return true;
	}

	if (m_arg_type == ImmediateType_Int)
	{
		*v = (float)m_arg_value.i;
	}
	else if (m_arg_type == ImmediateType_Float)
	{
		*v = m_arg_value.f;
	}

	// Clamp
	if (*v < 0)
	{
		*v = 0.f;
	}

	return true;
}

void Engine::prepareArgs(const char *arg)
{
	m_arg_text = arg;
	m_arg_next = 0;
	m_arg_available = 0;

	m_arg_type = ImmediateType_Int; // just some default so it's not floating.
	m_arg_value.i = 0;
}

bool Engine::prepareNextArg()
{
	// Continue parsing existing one if multiple available
	if (++m_arg_next < m_arg_available)
	{
		return true;
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
		return true;
	}
	// Move to next argument.
	++m_arg_text;

	// Check argument code.
	char code = *m_arg_text;
	if (!code)
	{
		syntaxError("invalid argument: expected type code");
		return false;
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
		m_arg_type = ImmediateType_Int;
		m_arg_value.i = strtol(m_arg_text, (char **)&got_end, 0);
	}
	else if (code == 'f')
	{
		m_arg_type = ImmediateType_Float;
		m_arg_value.f = strtof(m_arg_text, (char **)&got_end);
	}
	else if (code == 'p')
	{
		m_arg_type = ImmediateType_Paired;
		// Decompress Base64
		void *b64_data;
		int b64_len;
		if (!base64Decode(m_arg_text, end, &b64_data, &b64_len))
		{
			syntaxError("invalid argument: bad paired text");
			return false;
		}

		// One byte for scale, following are pairs for entries
		if (b64_len < 3 || (b64_len - 1) % sizeof(int16_t) != 0)
		{
			syntaxError("invalid argument: bad paired len");
			return false;
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
		return false;
	}

	if (got_end && got_end != end)
	{
		syntaxError("invalid argument: unexpected post-immediate text");
		return false;
	}

	m_arg_text = end;
	return true;
}

void Engine::prepareStackArg()
{
	// If the stack is empty, provide a default zero
	if (!m_stack_arg_size)
	{
		m_arg_type = ImmediateType_Int;
		m_arg_value.i = 0;
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
		m_arg_type = ImmediateType_Int;
		m_arg_value.i = top.i;
	}
	else if (top.type == StackValueType_Float)
	{
		m_arg_type = ImmediateType_Float;
		m_arg_value.f = top.f;
	}
}

const char *Engine::getError()
{
	return m_error_text;
}

void Engine::syntaxError(const char *text)
{
	if (!m_error_text)
		m_error_text = text;
}

void Engine::runtimeError(const char *text)
{
	if (!m_error_text)
		m_error_text = text;
}

void Engine::dumpStack(char *buffer, int size)
{
	int left = size;
	buffer[0] = '\0';

	char item_buffer[16];
	for (int i = m_stack_size; i > 0; --i)
	{
		StackValue sv = m_stack[i - 1];
		if (sv.type == StackValueType_Int)
		{
			snprintf(item_buffer, OC_ARRAYSIZE(item_buffer), "%d\n", sv.i);
			item_buffer[OC_ARRAYSIZE(item_buffer) - 1] = '\0';
		}
		else if (sv.type == StackValueType_Float)
		{
			snprintf(item_buffer, OC_ARRAYSIZE(item_buffer), "%.7f\n", sv.f);
			item_buffer[OC_ARRAYSIZE(item_buffer) - 1] = '\0';
		}
		else
		{
			OC_HANG();
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

	const char *err_text = e.getError();
	if (err_text)
	{
		char *out = (char *)malloc(strlen(err_text) + 2);
		strcpy(out, err_text);
		strcat(out, "\n");
		return out;
	}

	// Dump stack
	// Size should be sufficient for everything.
	int buffer_size = e.getStackSize() * 16;
	if (!buffer_size)
		buffer_size = 1;
	char *buffer = (char *)malloc(buffer_size);
	e.dumpStack(buffer, buffer_size);

	return buffer;
}