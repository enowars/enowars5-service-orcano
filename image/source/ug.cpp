#include "ug.h"
#include "util.h"

#include <ogc/exi.h>
#include <ogc/cache.h>

#include <cstring>

bool ugProbe(int chan)
{
	if (!EXI_Probe(chan))
		return false;

	// USB Gecko doesn't use normal IDs; we check that the usual ID command
	// just returns zeros to try and avoid sending random commands to e.g.
	// memory cards.
	uint32_t id;
	if (!EXI_GetID(chan, 0, &id))
		return false;
	if (id != 0)
		return false;

	if (!EXI_Lock(chan, 0, nullptr))
		return false;
	if (!EXI_Select(chan, 0, 5))
	{
		EXI_Unlock(chan);
		return false;
	}

	uint16_t cmd = 0x9000;
	if (!EXI_Imm(chan, &cmd, sizeof(uint16_t), 2, nullptr) || 
	    !EXI_Sync(chan))
	{
		EXI_Deselect(chan);
		EXI_Unlock(chan);
		return false;
	}

	EXI_Deselect(chan);
	EXI_Unlock(chan);
	return (cmd & 0x0fff) == 0x0470;
}

static int ugTransfer(int chan, void *data, int len, bool write)
{
	// Lock device
	if (!EXI_Lock(chan, 0, nullptr))
	{
		return -1;
	}

	// Set speed
	if (!EXI_Select(chan, 0, 5))
	{
		EXI_Unlock(chan);
		return -1;
	}

	bool fail = false;

	uint8_t *p = (uint8_t *)data;

	int xfer_len = 0;
	for (; xfer_len < len; ++xfer_len)
	{
		uint16_t cmd;
		if (write)
			cmd = 0xb000 | p[xfer_len] << 4;
		else
			cmd = 0xa000;

		if (!EXI_Imm(chan, &cmd, sizeof(uint16_t), 2, nullptr) || 
		    !EXI_Sync(chan))
		{
			fail = true;
			break;
		}

		// Exit early if buffers are full
		uint16_t success_mask = write ? 0x0400 : 0x0800;
		if (!(cmd & success_mask))
		{
			break;
		}

		// Read out response byte if reading
		if (!write)
			p[xfer_len] = cmd & 0xff;
	}

	EXI_Deselect(chan);
	EXI_Unlock(chan);

	return fail ? -1 : xfer_len;
}

OC_INIT_FUNCTION()
{
	// Patch EXI_Dma to allow unaligned DMA, which Dolphin can handle.
	uint8_t *dma_code = (u8 *)&EXI_Dma;
	uint32_t *mask_inst = (uint32_t *)(dma_code + 0xfc);
	if (*mask_inst != 0x577b01b4) // rlwinm r27, r27, 0, 6, 26
		OC_HANG();
	*mask_inst = 0x577b01be; // rlwinm r27, r27, 0, 6, 31

	DCFlushRange(mask_inst, 4);
	ICInvalidateRange(mask_inst, 4);
}

static int ugTransferBulk(int chan, void *data, int len, bool write)
{
	// No-op on Dolphin but for correctness
	if (write)
		DCFlushRange(data, len);

	// Lock device
	if (!EXI_Lock(chan, 0, nullptr))
	{
		return -1;
	}

	// Set speed
	if (!EXI_Select(chan, 0, 5))
	{
		EXI_Unlock(chan);
		return -1;
	}

	if (!EXI_Dma(chan, data, len, write ? EXI_WRITE : EXI_READ, nullptr) || 
	    !EXI_Sync(chan))
	{
		EXI_Deselect(chan);
		EXI_Unlock(chan);
		return -1;
	}

	if (!write)
		DCInvalidateRange(data, len);

	EXI_Deselect(chan);
	EXI_Unlock(chan);
	return 0;
}

#define UG_BULK_TRANSFER 1

static int ugTransferBlocking(int chan, void *data, int len, bool write)
{
#if UG_BULK_TRANSFER
	return ugTransferBulk(chan, data, len, write);
#else
	uint8_t *data_left = (uint8_t *)data;
	int size_left = len;
	while (size_left > 0)
	{
		int got = ugTransfer(chan, data_left, size_left, write);
		if (got < 0)
			return -1;
		data_left += got;
		size_left -= got;
	}
	return 0;
#endif
}

bool ugFlush(int chan)
{
	// Lock device
	if (!EXI_Lock(chan, 0, nullptr))
	{
		return false;
	}

	// Set speed
	if (!EXI_Select(chan, 0, 5))
	{
		EXI_Unlock(chan);
		return false;
	}

	uint16_t cmd = 0xe000;
	if (!EXI_Imm(chan, &cmd, sizeof(uint16_t), 2, nullptr) || 
	    !EXI_Sync(chan))
	{
		EXI_Deselect(chan);
		EXI_Unlock(chan);
		return false;
	}

	EXI_Deselect(chan);
	EXI_Unlock(chan);
	return true;
}

int ugSend(int chan, const void *data, int len)
{
	return ugTransfer(chan, (void *)data, len, true);
}

int ugRecv(int chan, void *data, int len)
{
	return ugTransfer(chan, data, len, false);
}

int ugSendBlocking(int chan, const void *data, int len)
{
	return ugTransferBlocking(chan, (void *)data, len, true);
}

int ugRecvBlocking(int chan, void *data, int len)
{
	return ugTransferBlocking(chan, data, len, false);
}
