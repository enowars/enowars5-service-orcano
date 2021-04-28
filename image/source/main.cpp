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

	while (true)
	{
		uint32_t request_ident, request_len;
		void *request_data;
		hostReadMsg(&request_ident, &request_len, &request_data);

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