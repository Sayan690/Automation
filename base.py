#!/usr/bin/python3

from base64 import *
import sys

def b64(s):
	try:
		decode = b64decode(s.encode())
		if b64encode(decode).decode() == s:
			return(decode.decode())

		else:
			return 0

	except Exception as e:
		return 0

def b32(s):
	try:
		decode = b32decode(s.encode())
		if b32encode(decode).decode() == s:
			return(decode.decode())

		else:
			return 0

	except Exception as e:
		return 0

def check(s):
	b1 = b64(s)
	b2 = b32(s)
	if b1 != 0:
		print(f"base64 : {b1}")

	elif b2 != 0:
		print(f"base32 : {b2}")

	else:
		sys.stderr.write("[!] String is Niether base64 nor base32. Try CyberChef...\n")
		sys.stderr.write("[+] CyberChef : https://gchq.github.io/CyberChef/\n")

if __name__ == "__main__":
	usage = "usage: ./{} BASE_ENCODED_STRING\n".format(sys.argv[0].replace("./", ""))
	if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
		sys.stderr.write(usage)
		sys.exit()

	if len(sys.argv) > 2:
		sys.stderr.write("[!] Wrong Arguments.\n")
		sys.exit()
	check(sys.argv[1])