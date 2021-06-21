#include "engine.h"

CustomArgParser::CustomArgParser(Engine *engine)
{
	m_engine = engine;
}

CustomArgParser::~CustomArgParser()
{
	if (m_gqr_dirty)
	{
		set_gqr2(m_gqr_saved);
	}
}

int CustomArgParser::getSeek()
{
	return m_seek;
}

int CustomArgParser::getSize()
{
	return m_size;
}

int CustomArgParser::getRemaining()
{
	return m_size - m_seek;
}

void CustomArgParser::setQuantScale(int scale)
{
	setQuantDirty();
	quant_set_scale(scale);
}

void CustomArgParser::setQuantType(int type)
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

void CustomArgParser::setArgString()
{
	const char *arg_end = m_engine->m_arg_text + strlen(m_engine->m_arg_text);
	const char *arg_start = m_engine->m_arg_text + 1;
	if (arg_end <= arg_start)
	{
		// Empty string
		arg_start = arg_end;
		setText(arg_start, arg_end);
		return;
	}

	setText(arg_start, arg_end);
}

void CustomArgParser::setText(const char *start, const char *end)
{
	m_size = end - start;
	// SIC: This size check is off-by-one
	if (m_size > (int)OC_ARRAYSIZE(m_buffer))
	{
		end = start + (int)OC_ARRAYSIZE(m_buffer) - 1;
		m_size = end - start;
	}
	memcpy(m_buffer, start, m_size);
	m_buffer[m_size] = '\0';
	m_seek = 0;
}

float CustomArgParser::getQuant()
{
	if (getRemaining() < m_gqr_width)
	{
		m_engine->runtimeError("custom immediate quant overrun");
		return 0.f;
	}
	float v = load_gqr2(&m_buffer[m_seek]);
	m_seek += m_gqr_width;
	return v;
}

char CustomArgParser::getChar()
{
	if (getRemaining() < 1)
	{
		m_engine->runtimeError("custom immediate char overrun");
		return '\0';
	}

	return (char)m_buffer[m_seek++];
}

const char *CustomArgParser::getText()
{
	return m_buffer + m_seek;
}

void CustomArgParser::decompressBase64()
{
	// Decode remaining part as null terminated B64
	void *b64_buf;
	int b64_len;
	if (!base64Decode(m_buffer + m_seek, &b64_buf, &b64_len))
	{
		m_engine->runtimeError("invalid custom immediate b64");
		m_size = 0;
		m_seek = 0;
		return;
	}
	if (b64_len > (int)OC_ARRAYSIZE(m_buffer))
		b64_len = (int)OC_ARRAYSIZE(m_buffer);
	memcpy(m_buffer, b64_buf, b64_len);
	free(b64_buf);

	m_size = b64_len;
	m_seek = 0;
}

void CustomArgParser::setQuantDirty()
{
	if (!m_gqr_dirty)
	{
		m_gqr_dirty = true;
		m_gqr_saved = get_gqr2();
	}
}
