'''
--------------------------------------------------------------------------------------------
-- SCRIPT: doorsy-client.py
-- 
-- FUNCTIONS: main
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
from scapy.all import *
import os
import random

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: main
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: main()
-- 
-- RETURNS: void
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def main():
	address = "127.0.0.1"
	password = ""
	knock = []
	warnings = ""

	# Making sure we're running in root
	if os.geteuid() != 0:
		print "Program must be run as root"
		return

	while True:
		os.system("clear")
		print warnings
		warnings = ""

		print "Server Address:  " + address
		print "Password:        " + password
		print "Knock Sequence:  " + str(knock)
		print " "
		print "-Commands-"
		print "A - change server address"
		print "P - change password"
		print "K - change knock sequence"
		print "R - Run Connection Sequence"
		print "Input Command: "

		choice = raw_input()
		if choice == 'A' or choice == 'a':
			print "Input new server address: "
			address = raw_input()
		elif choice == 'P' or choice == 'p':
			print "Input new Password: "
			password = raw_input()
		elif choice == 'K' or choice == 'k':
			print "Input new Port Knock sequence."
			print "Each port number should be comma deliminated: "
			ports = raw_input()
			knock[:] = []
			for port in ports.split(","):
				knock.append(int(port))
		elif choice == 'R' or choice == 'r':
			# Making sure we have at least 1 password or knock.
			# We need either a password or a knock in order for remote access to work
			if len(password) < 1 and len(knock) < 1:
				warnings = warnings + "Must have a password or knock sequence to connect to a server\n"
			else:
				try:
					sendKnock(address, password, knock)
				except KeyboardInterrupt:
					print "Shutting Down"
				return
		print "\n"

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: sendKnock
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: sendKnock(address, password, knock)
--              address - The address of the server
--              password - The password, if any, which will be used to autheticate to the server
--              knock - The knock sequence, if any, which will be used to autheticate to the server
-- 
-- RETURNS: Returns true on successful connection, otherwise False
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def sendKnock(address, password, knock):
	seq = random.randint(0, 65535)
	idpass = random.randint(0, 127)
	if len(knock) < 1:
		for c in password:
			port = random.randint(0, 65535)
			knockPacket = IP(dst=address, id=(idpass<<8) + ord(c))/\
			              TCP(dport=port, seq=seq)
			seq += 1
			idpass += 1

			send(knockPacket, verbose=0)
	else:
		ipid = random.randint(0, 65535)
		c = 0
		for port in knock:
			ipHead = IP(dst=address)
			if len(password) > 0 and c < len(password):
				ipHead.id = (idpass<<8) + ord(password[c])
				c += 1
				idpass += 1
				ipid = ipHead.id
			else:
				ipHead.id = ipid
				ipid += 1
			knockPacket = ipHead/\
			              TCP(dport=port, seq=seq)
			seq += 1

			send(knockPacket, verbose=0)

main()

