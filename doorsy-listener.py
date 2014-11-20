'''
--------------------------------------------------------------------------------------------
-- SCRIPT: doorsy-listener.py
-- 
-- FUNCTIONS: main
-- 
-- DATE: 2014-11-18
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
import os
import thread
import time
import subprocess

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: main
-- 
-- DATE: 2014-11-18
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
	if len(knock) < 1:
		print "Check Config: Program must have knock sequence"
		return
	else:
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

			if len(logFile) > 0:
				with open(logFile, "a") as serverLog:
					serverLog.write("Server starting up at " + time.ctime() + "\n")
			print "Server starting up at " + time.ctime()

			# Beginning Packet sniffing
			sniff(filter=packetFilter, prn=server())
		except KeyboardInterrupt:
			if len(logFile) > 0:
				with open(logFile, "a") as serverLog:
					serverLog.write("Server shutting down at " + time.ctime() + "\n")
			print "Server starting shutting down at " + time.ctime()

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
			if port == packet[TCP].dport:
				for src, word in passCheck:
					if src == packet[IP].src:
						passCheck.remove([src, word])
						return
				return

		# Append our knock arrays with the next value for each and, when apropriate,
		# check if they are a valid knock sequence.
		if checkKnock(packet[IP].src, packet[TCP].dport):
			thread.start_new_thread(clientCommands, (packet,))
		
	return getResponse

'''
------------------------------------------------------------------------------
-- 
-- FUNCTION: checkKnock
-- 
-- DATE: 2014-11-18
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
-- DATE: 2014-11-18
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
	commandPacket = sniff(filter="tcp and ip src " + packet[IP].src, count=1, timeout=30)
	if len(logFile) > 0:
		with open(logFile, "a") as serverLog:
			serverLog.write("Connection Established with " + packet[IP].src + " at " + time.ctime() + "\n")
	print "Connection Established with " + packet[IP].src + " at " + time.ctime()

	with open(encrypt(commandPacket[0][Raw].load), "w") as tFile:
		while True:
			dPacket = sniff(filter="tcp and ip src " + packet[IP].src, count=1, timeout=30)
			if len(dPacket) == 0:
				break
			if dPacket[0].haslayer(TCP) != True:
				continue
			if dPacket[0][TCP].flags == 1:
				break
			if dPacket[0].haslayer(Raw) != True:
				continue
			tFile.write(encrypt(dPacket[0][Raw].load))
	if len(logFile) > 0:
		with open(logFile, "a") as serverLog:
			serverLog.write(encrypt(commandPacket[0][Raw].load) + " received from " + commandPacket[0][IP].src + " at " + time.ctime() + "\n")
	print encrypt(commandPacket[0][Raw].load) + " received from " + commandPacket[0][IP].src + " at " + time.ctime()

	if len(logFile) > 0:
		with open(logFile, "a") as serverLog:
			serverLog.write("Connection with " + commandPacket[0][IP].src + " terminated at " + time.ctime() + "\n")
	print "Connection with " + commandPacket[0][IP].src + " terminated at " + time.ctime()

main()
