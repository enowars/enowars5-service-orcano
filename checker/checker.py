#!/usr/bin/env python3

from enochecker import BaseChecker, BrokenServiceException, EnoException, run
from enochecker.utils import SimpleSocket, assert_equals, assert_in

import secrets

def rand_uint():
	return secrets.randbits(31)
def rand_sint():
	raw = secrets.randbits(32)
	if raw >= 2**31:
		raw -= 2**32
	return raw
def chunks(l, n):
	for i in range(0, len(l), n):
		yield l[i:i+n]

PROMPT_TEXT = "> "

class OrcanoChecker(BaseChecker):
	flag_variants = 1
	noise_variants = 1
	havoc_variants = 0 # TODO
	exploit_variants = 0
	service_name = "orcano"
	port = 53273

	# Helpers
	def make_cmd(self, cmd, args = []):
		# TODO: Arg layout randomization:
		# push on stack then consume implicitly or with s, use paired, etc.
		text = cmd
		for arg in args:
			text += ":"
			if isinstance(arg, int):
				text += "i{}".format(arg)
			elif isinstance(arg, float):
				text += "f{}".format(arg)
			elif isinstance(arg, str):
				text += arg
			else:
				raise EnoException("make_cmd bad arg type {}".format(type(arg)))
		return text

	def flag_to_nums(self, flag):
		nums = []
		chunk_len = 3;
		flag_data = self.flag.encode()
		for ck in chunks(flag_data, chunk_len):
			num = 0
			for i in range(chunk_len):
				num <<= 8
				if i < len(ck):
					num |= ck[i]
			nums.append(num)
		return nums
	"""def flag_from_nums(self, nums):
		flag_data = b""
		chunk_len = 3
		for n in nums:
			remaining = n
			num_chars = b""
			for i in range(chunk_len):
				d = remaining & 0xff
				remaining >>= 8
				if d == 0:
					break
				num_chars.append(d)
			flag_data.append(remaining[::-1])
		return flag_data.decode()"""

	def gen_creds(self):
		uid0 = rand_sint()
		uid1 = rand_sint()
		key0 = rand_sint()
		key1 = rand_sint()
		return uid0, uid1, key0, key1
	def save_creds(self, creds):
		uid0, uid1, key0, key1 = creds
		return {
			"uid0": uid0,
			"uid1": uid1,
			"key0": key0,
			"key1": key1,
		}
	def load_creds(self):
		uid0 = self.chain_db["uid0"]
		uid1 = self.chain_db["uid1"]
		key0 = self.chain_db["key0"]
		key1 = self.chain_db["key1"]
		return uid0, uid1, key0, key1
	def creds_to_attack_info(self, creds):
		uid0, uid1, key0, key1 = creds
		return ":i{}:i{}".format(uid0, uid1)

	def make_user(self, creds):
		uid0, uid1, key0, key1 = creds
		return self.make_cmd("user", [uid0, uid1, key0, key1])

	def begin_conn(self):
		conn = self.connect()
		welcome = conn.read_until(PROMPT_TEXT.encode())
		self.debug("Got welcome: {}".format(welcome))
		# TODO: Test welcome text
		return conn

	def end_conn(self, conn):
		conn.write("\n")
		conn.close()

	def make_request(self, conn, cmds):
		# TODO: Randomize spacing
		request_text = " ".join(cmds)
		self.debug("make_request: sending {}".format(request_text))
		request_text += "\n"
		conn.write(request_text.encode())

		# Receive response and parse
		response = conn.read_until(PROMPT_TEXT.encode())
		lines = response.split(b"\n")
		try:
			lines = [l.decode() for l in lines]
		except UnicodeError:
			raise BrokenServiceException("Invalid characters returned from request")

		# Check prompt line
		if len(lines) <= 1:
			raise BrokenServiceException("Insufficient output returned from request")
		if lines[-1] != PROMPT_TEXT:
			raise BrokenServiceException("Bad prompt returned from request")
		# Trim off prompt
		lines = lines[:-1]

		# Parse output
		output = []
		for l in lines:
			line_prefix_end = l.find(": ")
			if line_prefix_end < 0:
				self.debug("make_request: Can't find terminator: {}".format(l))
				raise BrokenServiceException("Invalid output format returned from request")
			line_prefix = l[:line_prefix_end]
			line_suffix = l[line_prefix_end + 1:]
			output.append((line_prefix, line_suffix))

		# Validate output
		if len(output) == 0:
			raise BrokenServiceException("No output returned from request")

		# Parse result line
		rl_prefix, rl_suffix = output[-1]
		if rl_prefix == "out":
			# Parse output data
			success = True

			out_data = []
			for num_text in rl_suffix.strip().split(" "):
				if len(num_text) == 0:
					raise BrokenServiceException("Bad output line spacing")
				
				type_char = num_text[0]
				if type_char == "i":
					try:
						out_data.append(int(num_text[1:]))
					except ValueError:
						raise BrokenServiceException("Bad output int data")
				elif type_char == "f":
					try:
						out_data.append(float(num_text[1:]))
					except ValueError:
						raise BrokenServiceException("Bad output float data")
				else:
					raise BrokenServiceException("Bad output number type")

		elif rl_prefix == "error":
			success = False
			err_data = rl_suffix
		else:
			raise BrokenServiceException("Last output line was neither error nor output")

		# Check non-last lines
		for prefix, suffix in output[:-1]:
			if prefix == "log":
				pass # TODO
			elif prefix == "inspect":
				pass # TODO
			else:
				raise BrokenServiceException("Inner output line was neither log nor inspect")

		result = {}
		result["ok"] = success
		if success:
			#self.debug("OK: Got {}".format(out_data))
			result["out"] = out_data
		else:
			#self.debug("ERR: Got \"{}\"".format(out_data))
			result["err"] = err_data
		#result["extra"] = mid # TODO

		return result

	def put_data(self, conn, creds, nums):
		cmds = []
		cmds += [self.make_user(creds)]
		# TODO: We can shuffle these
		cmds += [self.make_cmd("setn", [i, n]) for i, n in enumerate(nums)]
		cmds += [self.make_cmd("lockn", [i]) for i, n in enumerate(nums)]
		return self.make_request(conn, cmds)

	def get_data(self, conn, creds, count):
		cmds = []
		cmds += [self.make_user(creds)]
		cmds += [self.make_cmd("del")]
		# TODO: We can shuffle these
		cmds += [self.make_cmd("getn", [i]) for i in reversed(range(count))]
		return self.make_request(conn, cmds)

	# Entrypoints
	def putflag(self):
		if self.variant_id == 0:
			self.debug("PUTFLAG")
			# Encode flag into numbers
			nums = self.flag_to_nums(self.flag)

			self.debug("Generating creds")
			creds = self.gen_creds()
			self.chain_db = self.save_creds(creds)

			conn = self.begin_conn()
			result = self.put_data(conn, creds, nums)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putflag request error")

			return self.creds_to_attack_info(creds)
		else:
			raise EnoException("putflag bad variant_id")
	def getflag(self):
		if self.variant_id == 0:
			try:
				creds = self.load_creds()
			except:
				raise BrokenServiceException("previous putflag failed")

			expected_nums = self.flag_to_nums(self.flag)

			cmds = []
			cmds += [self.make_user(creds)]
			# TODO: We can shuffle these
			cmds += [self.make_cmd("getn", [i]) for i in range(len(expected_nums))]

			conn = self.begin_conn()
			result = self.get_data(conn, creds, len(expected_nums))
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getflag request error")

			# reverse and drop last (from the user cmd)
			got_nums = result["out"]
			assert_equals(
				tuple(got_nums),
				tuple(expected_nums),
				message="getflag incorrect flag"
			)
		else:
			raise EnoException("getflag bad variant_id")

	def putnoise(self):
		if self.variant_id == 0:
			creds = self.gen_creds()
			# TODO: Other types of noise.
			data = [rand_sint() for i in range(1 + secrets.randbelow(20))]

			db = {}
			db["data"] = data
			db |= self.save_creds(creds)
			self.chain_db = db

			conn = self.begin_conn()
			result = self.put_data(conn, creds, data)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putnoise request error")
		else:
			raise EnoException("putnoise bad variant_id")
	def getnoise(self):
		if self.variant_id == 0:
			try:
				creds = self.load_creds()
				data = self.chain_db["data"]
			except:
				raise BrokenServiceException("previous putnoise failed")

			conn = self.begin_conn()
			result = self.get_data(conn, creds, len(data))
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getnoise request error")

			assert_equals(
				tuple(result["out"]),
				tuple(data),
				message="getnoise incorrect data"
			)
		else:
			raise EnoException("putnoise bad variant_id")

	def havoc(self):
		raise EnoException("havoc bad variant_id")

	def exploit(self):
		raise EnoException("exploit bad variant_id")

app = OrcanoChecker.service
if __name__ == "__main__":
	run(OrcanoChecker)