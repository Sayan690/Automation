#!/usr/bin/python3

from netifaces import *
from os import *
from sys import *

def args():
	replace = argv[0].replace("./","")
	usage = "./{replace} [NIC]"
	if "-h" in argv or "--help" in argv:
		print(usage)
		exit()

	if len(argv) > 2:
		stderr.write("[!] Wrong Arguments.\n")
		exit()

def find_nic():
	for i in nic:
		try:
			print(f"{i} : {ifaddresses(f'{i}')[AF_INET][0]['addr']}")

		except KeyError:
			continue

def print_ip():
	print(f"{argv[1]} : {ifaddresses(f'{argv[1]}')[AF_INET][0]['addr']}")


if __name__ == "__main__":
	args()
	nic = listdir('/sys/class/net/')
	if len(argv) == 1:
		find_nic()

	else:
		if argv[1] not in nic:
			stderr.write("[!] NIC is invalid.\n")
			exit()
		print_ip()