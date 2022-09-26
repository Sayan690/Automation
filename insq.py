#!/usr/bin/python3

import os
import sys
import argparse
import subprocess

from pwn import *

class Install:
	def __init__(self):
		self.args()
		self.files = []
		self.pacman()
		self.install()

	def args(self):
		parser = argparse.ArgumentParser(description='Arch linux package installer.', usage='./%(prog)s -S [PKG]')
		parser.add_argument('-S', '--sync', metavar="", help="Sync a package.")
		parser.add_argument('-R', '--remove', metavar="", help="Remove a package.")
		self.args = parser.parse_args()

		if len(sys.argv) == 1:
			parser.print_help(sys.stderr)
			sys.exit()

		if self.args.sync and self.args.remove:
			sys.stderr.write('[!] Exception: Cannot install or remove at the same time.')
			sys.exit()

		self.pkg = sys.argv[2]

	def pacman(self):
		cmd = "pacman --help"
		if "command not found" in subprocess.getoutput(cmd):
			error("Arch based distro expected.\nIF Arch, install pacman first.")

	def install(self):
		try:
			# os.system("clear")
			io = process(['pacman', sys.argv[1], self.pkg])
			io.recvuntil(b"[Y/n]")
			io.sendline(b"Y")
			out = io.recvall().decode().split('\n')
			for i in out:
				if "exists in filesystem" in i:
					s = i.split(":")
					file = s[1].replace('exists in filesystem', '').replace(' ', '')
					self.files.append(file)

				elif "exists in filesystem" not in out:
					if self.args.sync:
						print("[+] %s installed successfully." % self.pkg)
					else:
						print("[+] %s uninstalled successfully." % self.pkg)
					break

			if len(self.files) > 0:
				for _ in self.files:
					subprocess.getoutput("rm -rv %s" % _)

				self.install()

		except KeyboardInterrupt:
			sys.exit()

		except EOFError:
			if self.args.remove:
				error("%s is not installed." % self.pkg)

			sys.exit()

def error(s):
	sys.stderr.write('[!] Exception: %s\n' % s)
	sys.exit()

if __name__ == '__main__':
	Install()