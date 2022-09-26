#!/usr/bin/python3

import sys
import socket
import argparse
import subprocess

def args():
	global args
	global host

	parser = argparse.ArgumentParser(description="RDP Connector.", usage="./%(prog)s [HOST] -u [USERNAME] -p [PASSWORD]", add_help=False)

	parser._positionals.title = "positionals"
	parser._optionals.title = "flags"

	parser.add_argument("-h", "--help", action="help", help="Shows this help message and exits.")
	parser.add_argument(metavar="HOST", dest="host", help="Host domain or ip address.")
	parser.add_argument("-u", metavar="USERNAME", help="Username for authenticating.", dest="user")
	parser.add_argument("-p", metavar="PASSWORD", help="Password for authenticating.", dest="passwd")
	parser.add_argument("--continue", help="Continue trying if error.", dest="cont", metavar="CONTINUE")

	args = parser.parse_args()

	host = socket.gethostbyname(args.host)

def main():
	cmd = "xfreerdp /u:%s /p:%s /v:%s /workarea /smart-sizing /cert:ignore" % (args.user, args.passwd, host)
	try:
		out = subprocess.getoutput('xfreerdp --help')
		if not "command not found" in out:
			print("[+] Trying to connect...")
			if not args.cont:
				subprocess.getoutput(cmd)

			else:
				while True:
					subprocess.getoutput(cmd)
					print("[+] Retrying to connect...")

		else:
			sys.stderr.write("[!] Exception: Install 'xfreerdp' first.\n")
			sys.exit()

	except KeyboardInterrupt:
		print()
		sys.exit()

	except Exception as e:
		sys.stderr.write("[!] Exception: %s\n" % e)
		sys.exit()

if __name__ == '__main__':
	args()
	main()