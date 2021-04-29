#include "util.h"
#include "sleep.h"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>

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

void hostWriteMsg(uint32_t ident, uint32_t len, const void *data)
{
	usb_sendbuffer_safe(kGeckoExiChan, &ident, sizeof(uint32_t));
	usb_sendbuffer_safe(kGeckoExiChan, &len, sizeof(uint32_t));
	if (len)
	{
		usb_sendbuffer_safe(kGeckoExiChan, data, len);
	}
}

// Read all or nothing in one shot.
bool hostTryRead(void *data, int size)
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

bool hostTryReadMsg(uint32_t *ident, uint32_t *len, void **data)
{
	// Try to get the ident
	if (!hostTryRead(ident, sizeof(uint32_t)))
	{
		// No message available
		return false;
	}

	// Got the ident, block for the rest.
	usb_recvbuffer_safe(kGeckoExiChan, len, sizeof(uint32_t));
	*data = malloc(*len);
	if (*len)
	{
		usb_recvbuffer_safe(kGeckoExiChan, *data, *len);
	}
	return true;
}

void hostReadMsg(uint32_t *ident, uint32_t *len, void **data)
{
	usb_recvbuffer_safe(kGeckoExiChan, ident, sizeof(uint32_t));
	usb_recvbuffer_safe(kGeckoExiChan, len, sizeof(uint32_t));
	*data = malloc(*len);
	if (*len)
	{
		usb_recvbuffer_safe(kGeckoExiChan, *data, *len);
	}
}

int main(int argc, char **argv)
{
	printf("Startup!\n");

	// Run init funcs
	for (const InitFunctionReg *ifr = InitFunctionReg::s_pFirst; ifr; ifr = ifr->pNext)
	{
		ifr->func();
	}

	while (true)
	{
		// Wait for input
		uint32_t request_ident, request_len;
		void *request_data;
		while (!hostTryReadMsg(&request_ident, &request_len, &request_data))
		{
			// Sleep to back off of CPU time while idle
			sleepMs(10);
		}

		if (request_ident != makeIdent("RQST"))
		{
			// TODO: Error handling
			while (1);
		}

		char response_data[] = "Happy bunny!\n";
		int response_len = strlen(response_data);

		hostWriteMsg(
			makeIdent("RESP"),
			response_len,
			response_data
		);
	}
}