#!/usr/bin/env python3

import sys
import os
import struct
import datetime
import asyncio

import traceback
import subprocess

SERVICE_PORT = 53273
QUEUE_MAX_LEN = 1024
DOLPHIN_PATH = os.getenv("DOLPHIN_EMU_NOGUI")
IMAGE_PATH = "./image.dol"
DATA_DIR = "/data"
WORKER_COUNT = 2

MAX_REQUEST_SIZE = 1024 # maximum size for request to be passed into Dolphin
MAX_REQUEST_TIME = 0.25
DOL_TIMEOUT = 2.0 # timeout for comms with Dolphin before abort & restart
DOL_STARTUP_TIME = 20.0 # how long to wait for Dolphin to start up in seconds
DOL_STARTUP_INTERVAL = 0.05 # wait time between successive attempts to get to Dolphin

class OrcanoFrontend:
	async def handle_workers(self):
		workers = []
		while True:
			while len(workers) < WORKER_COUNT:
				workers.append(asyncio.create_task(self.handle_dolphin()))
			done, pending = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
			for d in done: # Trigger exceptions
				await d
			print("Workers: {} died".format(len(done)))
			workers = list(pending)

	async def start_dolphin(self):
		inst = {}
		inst["dol_port"] = await self.port_pool.get()
		inst["dol_proc"] = await asyncio.create_subprocess_exec(
			#"strace",
			DOLPHIN_PATH,
			"-e", IMAGE_PATH,
			"-p", "headless",
			"-v", "Null", # Disable video
			"-C", "Dolphin.Core.GeckoPort={}".format(inst["dol_port"]),
			#stderr=subprocess.PIPE,
			stdout=subprocess.PIPE
		)

		async def runner(inst):
			stdout_data, stderr_data = await inst["dol_proc"].communicate()
			inst["dol_fut"].set_result((stdout_data, stderr_data))
			await self.port_pool.put(inst["dol_port"])

			print("Dolphin ended, port={}, code={}".format(inst["dol_port"], inst["dol_proc"].returncode), flush=True)
			print("stdout:")
			print(stdout_data)
			print("stderr:")
			print(stderr_data)

		# Start the waiter task
		inst["dol_fut"] = asyncio.Future()
		asyncio.create_task(runner(inst))

		# Open conn to USB Gecko port
		connect_fail = True
		tries = int(DOL_STARTUP_TIME / DOL_STARTUP_INTERVAL)
		p = inst["dol_port"]
		for i in range(tries):
			try:
				inst["dol_rx"], inst["dol_tx"] = await asyncio.open_connection("127.0.0.1", p)
				print("Dolphin connected on port {}".format(p))
				connect_fail = False
				break
			except ConnectionRefusedError:
				pass

			print("Dolphin connection failed, retrying ({})...".format(i))
			await asyncio.sleep(DOL_STARTUP_INTERVAL)

		if connect_fail:
			raise ConnectionRefusedError

		print("Dolphin started, port={}, pid={}".format(inst["dol_port"], inst["dol_proc"].pid))
		return inst

	async def stop_dolphin(self, inst):
		# Clean up process
		print("Stopping Dolphin...")
		inst["dol_proc"].kill()
		await inst["dol_proc"].wait()

		inst["dol_tx"].close()
		# Waiting apparently can throw ConnectionResetError if the connection is remotely terminated
		# await inst["dol_tx"].wait_closed()

	async def handle_dolphin(self):
		# Start Dolphin
		inst = await self.start_dolphin()

		async def dol_write_msg(ident, data):
			msg_buffer = bytearray(4 + 4 + len(data))
			msg_buffer[0:4] = ident
			msg_buffer[4:8] = struct.pack(">L", len(data))
			msg_buffer[8:] = data
			print("Sending msg: {}".format(msg_buffer))
			inst["dol_tx"].write(msg_buffer)
			await inst["dol_tx"].drain()

		async def dol_read_msg():
			msg_header = await inst["dol_rx"].readexactly(4 + 4)
			print("Got msg header: {}".format(msg_header))
			ident = msg_header[0:4]
			size = struct.unpack(">L", msg_header[4:8])[0]
			data = await inst["dol_rx"].readexactly(size)
			print("Got msg data: {}".format(data))
			return ident, data

		async def dol_timeout(coro):
			# With global timeout, this is unnecessary
			#return await asyncio.wait_for(coro, DOL_TIMEOUT)
			return await coro

		class DolphinCommunicationError(Exception): pass

		async def process_request(task):
			# Send the initial request
			await dol_timeout(dol_write_msg(b"REQQ", task["data"]))

			# Respond to queries
			result = bytearray()
			while True:
				ident, data = await dol_timeout(dol_read_msg())
				if ident == b"REQA":
					result += data
					result += b"\n"
					break
				elif ident == b"GTNQ":
					if len(data) != 0xc:
						raise DolphinCommunicationError("invalid getn query len 0x{:x}".format(len(data)))

					uid = struct.unpack_from(">Q", data, 0x0)[0]
					idx = struct.unpack_from(">L", data, 0x8)[0]

					# TODO: Should we check that this user exists here?
					num_path = os.path.join(DATA_DIR, "num_{:016x}_{:08x}".format(uid, idx))
					num_data = None
					try:
						with open(num_path, "rb") as f:
							num_data = f.read()
						if len(num_data) != 8:
							print("Invalid number data read from disk for uid={:016x}, idx={:08x}".format(uid, idx))
							num_data = None
					except FileNotFoundError:
						num_data = None

					# Provide default
					if num_data == None:
						num_data = b"\x00" * 8

					await dol_timeout(dol_write_msg(b"GTNA", num_data))
				elif ident == b"STNQ":
					if len(data) != 0x14:
						raise DolphinCommunicationError("invalid setn query len 0x{:x}".format(len(data)))

					uid = struct.unpack_from(">Q", data, 0x0)[0]
					idx = struct.unpack_from(">L", data, 0x8)[0]
					num_data = data[0xc:0x14]
					num_type = struct.unpack_from(">L", num_data, 0)[0]
					if num_type not in [0, 1]:
						raise DolphinCommunicationError("invalid setn number type 0x{:x}".format(num_type))

					# Check for lock
					lock_path = os.path.join(DATA_DIR, "lock_{:016x}_{:08x}".format(uid, idx))
					try:
						with open(lock_path, "rb") as f:
							locked = True
					except FileNotFoundError:
						locked = False

					# TODO: This shares code with GTNQ, maybe we can extract it.
					if not locked:
						num_path = os.path.join(DATA_DIR, "num_{:016x}_{:08x}".format(uid, idx))
						with open(num_path, "wb") as f:
							f.write(num_data)
				elif ident == b"LKNQ":
					if len(data) != 0xc:
						raise DolphinCommunicationError("invalid lockn query len 0x{:x}".format(len(data)))

					# TODO: Should we check that this user exists here?
					uid = struct.unpack_from(">Q", data, 0x0)[0]
					idx = struct.unpack_from(">L", data, 0x8)[0]

					# TODO: This shares code with STNQ
					lock_path = os.path.join(DATA_DIR, "lock_{:016x}_{:08x}".format(uid, idx))

					# Create the lock file if it didn't exist already
					with open(lock_path, "wb") as f:
						pass
				elif ident == b"INSQ":
					if len(data) < 4:
						raise DolphinCommunicationError("invalid inspect query len 0x{:x}".format(len(data)))
					int_count = struct.unpack_from(">L", data, 0x0)[0]
					result += b"inspect:"
					for i in range((len(data) - 4) // 4):
						if i < int_count:
							val = struct.unpack_from(">l", data, 0x4 + i * 4)[0]
							result += " i{}".format(val).encode()
						else:
							val = struct.unpack_from(">f", data, 0x4 + i * 4)[0]
							result += " f{:.9g}".format(val).encode()
					result += b"\n"
				elif ident == b"LOGQ":
					print(data)
				elif ident == b"ERRQ":
					print("DOL reported error: {}".format(data))
					raise DolphinCommunicationError()
				else:
					print("DOL bad msg: ident={} data={}".format(ident, data))
					raise DolphinCommunicationError()
			return result

		# Serve requests
		while True:
			task = await self.request_queue.get()

			request_start = datetime.datetime.utcnow()
			print("Serving request to Dolphin on port {}".format(inst["dol_port"]))
			try:
				result = await asyncio.wait_for(process_request(task), MAX_REQUEST_TIME)
			except (asyncio.IncompleteReadError, asyncio.TimeoutError, DolphinCommunicationError):
				# Dolphin died or timed out
				print("Request execution failed, traceback:")
				traceback.print_exc()

				# Restart Dolphin
				await self.stop_dolphin(inst)
				print("Shutdown complete, starting...")
				inst = await self.start_dolphin()
				print("Restart complete.")

				# Fail the request
				result = b"error: internal\n"

			# For performance estimation
			# TODO: Should probably get rid of this overhead for final
			request_end = datetime.datetime.utcnow()
			request_duration = request_end - request_start
			print("Request took {}us".format(request_duration / datetime.timedelta(microseconds=1)))

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
		self.port_pool = asyncio.Queue()
		for i in range(55020, 55520):
			await self.port_pool.put(i)
		self.request_queue = asyncio.Queue(maxsize=QUEUE_MAX_LEN)
		asyncio.create_task(self.handle_workers())
		server = await asyncio.start_server(self.handle_connection, "0.0.0.0", SERVICE_PORT)
		print("Serving requests on {}".format(SERVICE_PORT))
		await server.serve_forever()

async def main():
	fe = OrcanoFrontend()
	await fe.run()

if __name__ == "__main__":
	asyncio.run(main())