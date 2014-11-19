# For all variables contained within this file, the corisponding feature will be disabled if that variable is blank, on in the case of arrays empty

# The name which will be used in masking the process name. 
mask = "Bistromath"

# The protocol on which packets are sent and received
# Supported protocols include tcp and udp
protocol = "tcp"

# A list of valid passwords which can be used to autheticate when connecting to this program.
passwords = []
# A list of port numbers which must be used in sequence as a port knock when connecting to this program.
knock = [1,2,3,5]
# 	NOTE: If both password and knock are enabled, the length of the knock and password must be equal, or else the sequence may not be successful.

# A list of ports on which, when a packet is received, the server clears its password and knock que for the IP address which sent the packet.
# 	NOTE: Any knock sequence which contains one of these ports may not work correctly. 
reset = [0]

# A list of IP Addresses which can connect to this server.
sources = []
# A list of ports on which a connection can be established to this server.
ports = []

# The name and directory path of the log file to which log information should be written
logFile = "log"

# The IP Address to which notify responses should be sent
notify = ""

