#include "engine.h"

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
		m_engine->runtimeError("custom immediate overrun");
		return 0.f;
	}
	float v = load_gqr2(&m_buffer[m_seek]);
	m_seek += m_gqr_width;
	return v;
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