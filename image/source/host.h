#pragma once

#include <cstdint>
#include <cstdlib>

// libogc *needs* this to have some of the above includes, so has to be at the
// bottom.
#include <ogc/usbgecko.h>

constexpr uint32_t makeIdent(const char *text)
{
	char a = text[0];
	char b = text[1];
	char c = text[2];
	char d = text[3];
	return (a << 24 | b << 16 | c << 8 | d);
}

constexpr int kGeckoExiChan = 1;

inline void hostWrite(const void *data, int size)
{
	usb_sendbuffer_safe(kGeckoExiChan, data, size);
}

inline void hostRead(void *data, int size)
{
	usb_recvbuffer_safe(kGeckoExiChan, data, size);
}

// Read all or nothing in one shot.
inline bool hostTryRead(void *data, int size)
{
	uint8_t *data_left = (uint8_t *)data;
	int size_left = size;

	bool first = true;
	while (size_left > 0)
	{
		int got = usb_recvbuffer(kGeckoExiChan, data_left, size_left);

		// Abort if this is the first run through, otherwise we gotta see it
		// through.
		if (first && !got)
		{
			return false;
		}
		first = false;

		data_left += got;
		size_left -= got;
	}
	return true;
}

inline void hostWriteMsg(uint32_t ident, uint32_t len, const void *data)
{
	hostWrite(&ident, sizeof(uint32_t));
	hostWrite(&len, sizeof(uint32_t));
	if (len)
	{
		hostWrite(data, len);
	}
}

inline bool hostTryReadMsg(uint32_t *ident, uint32_t *len, void **data)
{
	// Try to get the ident
	if (!hostTryRead(ident, sizeof(uint32_t)))
	{
		// No message available
		return false;
	}

	// Got the ident, block for the rest.
	hostRead(len, sizeof(uint32_t));
	*data = malloc(*len ? *len : 1);
	if (*len)
	{
		hostRead(*data, *len);
	}
	return true;
}

inline void hostReadMsg(uint32_t *ident, uint32_t *len, void **data)
{
	hostRead(ident, sizeof(uint32_t));
	hostRead(len, sizeof(uint32_t));
	*data = malloc(*len ? *len : 1);
	if (*len)
	{
		hostRead(*data, *len);
	}
}

#define OC_LOG(fmt, ...) \
	do \
	{ \
		char buffer[256]; \
		snprintf(buffer, OC_ARRAYSIZE(buffer), fmt, __VA_ARGS__); \
		buffer[OC_ARRAYSIZE(buffer) - 1] = '\0'; \
		hostWriteMsg(makeIdent("LOGQ"), strlen(buffer), buffer); \
	} while(false)
