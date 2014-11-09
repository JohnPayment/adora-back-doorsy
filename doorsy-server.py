from config import *
import os
from scapy.all import *

def main():
	if os.geteuid() != 0:
		print "Program must be run as root"
		return
	if len(password) < 1 and len(knock) < 1:
		print "Check Config: Program must have at least 1 password or knock sequence"
		return
	else:
		

main()

