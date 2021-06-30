def main():
	out = ""
	with open("./image.map", "r") as i:
		out += ".text section layout\n"
		for line in i:
			in_vals = line.strip().split()
			addr = int(in_vals[1], 16)
			size = int(in_vals[2])
			name = in_vals[-1]
			out += "{:08x} {:08x} {:08x} 0 {}\n".format(addr, size, addr, name)
	with open("./image.map", "w") as o:
		o.write(out)

if __name__ == "__main__":
	main()