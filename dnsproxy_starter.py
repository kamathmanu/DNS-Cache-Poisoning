#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
#Default BIND server
bindIP = "127.0.0.1"

if __name__ == '__main__':
	#setup a UDP server to get a DNS request over UDP
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	sock.bind(('', port))
	while True:
		#receive a DNS query request from dig
		print("Waiting for a request")
		clientRequest, addr = sock.recvfrom(4096)
		print(addr)
		print("Received dig request")
		dnsPacket = DNS(clientRequest)
		print ("Sending to BIND")
		sock.sendto(str(dnsPacket), (addr[0], dns_port))
		#Wait for upstream BIND server's response
		print ("Waiting for BIND reply")
		response = sock.recv(4096)
		response = DNS(response)
		print "\n***** Packet Received from Remote Server *****"
		print response.show()
		print "***** End of Remote Server Packet *****\n"
		#forward response back to dig
		print("Forwarding back to dig")
		sock.sendto(str(response), (addr[0], addr[1]))
		"Proxy lookup complete\n"
