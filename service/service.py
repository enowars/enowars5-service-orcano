#!/usr/bin/env python3

import sys
import os
import struct
import asyncio

import traceback
import subprocess

SERVICE_PORT = 53273
QUEUE_MAX_LEN = 1024
DOLPHIN_PATH = os.getenv("DOLPHIN_EMU_NOGUI")
IMAGE_PATH = "./image.dol"

MAX_REQUEST_SIZE = 1024 # maximum size for request to be passed into Dolphin
DOL_TIMEOUT = 5.0 # timeout for comms with Dolphin before abort & restart

class OrcanoFrontend:
	async def start_dolphin(self):
		self.dol_proc = await asyncio.create_subprocess_exec(
			#"strace",
			DOLPHIN_PATH,
			"-e", IMAGE_PATH,
			"-p", "headless",
			"-v", "Null", # Disable video
			#stderr=subprocess.PIPE,
			stdout=subprocess.PIPE
		)

		async def runner(proc, future):
			stdout_data, stderr_data = await proc.communicate()
			future.set_result((stdout_data, stderr_data))

			print("Dolphin ended, code={}".format(proc.returncode),flush=True)
			print("stdout:")
			print(stdout_data)
			print("stderr:")
			print(stderr_data)

		# Start the waiter task
		self.dol_fut = asyncio.Future()
		asyncio.create_task(runner(self.dol_proc, self.dol_fut))

		# Open conn to USB Gecko port
		connect_fail = True
		for i in range(30):
			try:
				self.dol_rx, self.dol_tx = await asyncio.open_connection("127.0.0.1", 55020)
				connect_fail = False
				break
			except ConnectionRefusedError:
				pass

			print("Connection failed, retrying ({})...".format(i))
			await asyncio.sleep(2)

		if connect_fail:
			raise ConnectionRefusedError

		print("Dolphin started, pid={}".format(self.dol_proc.pid))

	async def stop_dolphin(self):
		# Clean up process
		print("Stopping Dolphin...")
		self.dol_proc.kill()
		await self.dol_proc.wait()

		self.dol_tx.close()
		# Waiting apparently can throw ConnectionResetError if the connection is remotely terminated
		# await self.dol_tx.wait_closed()

	async def handle_dolphin(self):
		# Start Dolphin
		await self.start_dolphin()

		async def dol_write_msg(ident, data):
			msg_buffer = bytearray(4 + 4 + len(data))
			msg_buffer[0:4] = ident
			msg_buffer[4:8] = struct.pack(">L", len(data))
			msg_buffer[8:] = data
			print("Sending msg: {}".format(msg_buffer))
			self.dol_tx.write(msg_buffer)
			await self.dol_tx.drain()

		async def dol_read_msg():
			msg_header = await self.dol_rx.readexactly(4 + 4)
			print("Got msg header: {}".format(msg_header))
			ident = msg_header[0:4]
			size = struct.unpack(">L", msg_header[4:8])[0]
			data = await self.dol_rx.readexactly(size)
			print("Got msg data: {}".format(data))
			return ident, data

		async def dol_timeout(coro):
			return await asyncio.wait_for(coro, DOL_TIMEOUT)

		class DolphinCommunicationError(Exception): pass

		# Serve requests
		while True:
			task = await self.request_queue.get()

			try:
				# Send the initial request
				await dol_timeout(dol_write_msg(b"RQST", task["data"]))

				# Respond to queries
				while True:
					ident, data = await dol_timeout(dol_read_msg())
					if ident == b"RESP":
						result = data
						break
					elif ident == b"AUTH":
						# TODO
						pass
					elif ident == b"GETN":
						# TODO
						pass
					elif ident == b"SETN":
						# TODO
						pass
					elif ident == b"EROR":
						print("DOL reported error: {}".format(data))
						raise DolphinCommunicationError()
					else:
						print("DOL bad msg: ident={} data={}".format(ident, data))
						raise DolphinCommunicationError()
			except (asyncio.IncompleteReadError, asyncio.TimeoutError, DolphinCommunicationError):
				# Dolphin died or timed out
				print("Request execution failed, traceback:")
				traceback.print_exc()

				# Restart Dolphin
				await self.stop_dolphin()
				print("Shutdown complete, starting...")
				# TODO: Dolphin doesn't use SO_REUSEADDR on the listen socket,
				# so this'll fail to bind. We need to reconfigure the period
				# for that so this works. Even long waiting times like 30s are
				# unfortunately not sufficient by default it seems.
				# *However*, in some circumstances I do believe I recalled this
				# working, so maybe in some shutdown scenarios it works fine.
				await self.start_dolphin()
				print("Restart complete.")

				# Fail the request
				result = b"internal error\n"

			# Return the result
			task["result_fut"].set_result(result)
			self.request_queue.task_done()

	async def handle_connection(self, client_rx, client_tx):
		client_tx.write(b"Hey! Listen!\n")
		await client_tx.drain()

		# TODO: Network timeouts?

		try:
			while True:
				client_tx.write(b"> ")
				await client_tx.drain()
				line = await client_rx.readuntil(b"\n")

				# Assemble our request
				task_data = line.strip()

				# Limit request size
				if len(task_data) > MAX_REQUEST_SIZE:
					client_tx.write(b"request too large\n")
					continue

				# Exit upon empty line
				if not task_data:
					break

				# Assemble request
				task_result_fut = asyncio.Future()
				task = {
					"data": task_data,
					"result_fut": task_result_fut
				}

				# Submit for processing
				await self.request_queue.put(task)

				# Wait for completion
				result = await task_result_fut

				# Write back the result
				client_tx.write(result)
		except (asyncio.IncompleteReadError, asyncio.TimeoutError):
			pass

		client_tx.close()
		await client_tx.wait_closed()

	async def run(self):
		self.request_queue = asyncio.Queue(maxsize=QUEUE_MAX_LEN)
		asyncio.create_task(self.handle_dolphin())
		server = await asyncio.start_server(self.handle_connection, "0.0.0.0", SERVICE_PORT)
		print("Serving requests on {}".format(SERVICE_PORT))
		await server.serve_forever()

async def main():
	fe = OrcanoFrontend()
	await fe.run()

if __name__ == "__main__":
	asyncio.run(main())