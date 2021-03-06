#include "util.h"
#include "sleep.h"
#include "engine.h"
#include "host.h"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>

int main(int argc, char **argv)
{
	printf("Startup!\n");

	// Run init funcs
	for (const InitFunctionReg *ifr = InitFunctionReg::s_pFirst; ifr; ifr = ifr->pNext)
	{
		ifr->func();
	}

	// Signal ready for requests
	hostWriteMsg(makeIdent("RDYQ"), 0, nullptr);

	while (true)
	{
		// Wait for input
		uint32_t request_ident, request_len;
		void *request_data;
#define OC_SLEEP_IDLE 0
#if OC_SLEEP_IDLE
		while (!hostTryReadMsg(&request_ident, &request_len, &request_data))
		{
			// Sleep to back off of CPU time while idle
			sleepMs(10);
		}
#else
		hostReadMsg(&request_ident, &request_len, &request_data);
#endif

		if (request_ident != makeIdent("REQQ"))
		{
			//const char *msg = "invalid request msg\n";
			//hostWriteMsg(makeIdent("ERRQ"), strlen(msg), msg);
			continue;
		}

		// Run the request
		// Attach null terminator
		char *request_text = (char *)request_data;
		request_text = (char *)realloc(request_text, request_len + 1);
		request_text[request_len] = '\0';
		char *response_data = processRequest((char *)request_text);
		free(request_text);
		
		// Respond
		hostWriteMsg(makeIdent("REQA"), strlen(response_data), response_data);
		free(response_data);
	}
}