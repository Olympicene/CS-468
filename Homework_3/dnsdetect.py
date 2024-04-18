import argparse
import netifaces
from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
import time

global local_ip
global args
global hosts

all_dns_response = {}

def dns_detect(packet):

    if (IP in packet) and (UDP in packet) and (DNS in packet) and packet[DNS].qr == 1:
        
        print(packet)

        # IP info
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # UDP info
        src_port = packet[UDP].sport
        dest_port = packet[UDP].dport

        # DNS infos
        dns_qd = packet[DNS].qd
        dns_id = packet[DNS].id

        # if packet[DNS].rcode == 3:
        #     dns_rdata = None
        # else:
        #     dns_rdata = packet[DNSRR].rdata

        if(dns_qd is not None):
            dns_qname = dns_qd.qname.decode("utf-8")
        else:
            dns_qname = "N/A"

        if dns_id in all_dns_response:
            dns_response = all_dns_response[dns_id]
            if dns_response[IP].src == src_ip and \
               dns_response[IP].dst == dest_ip and \
               dns_response[DNS].id == dns_id and \
               (dns_response[DNS].rcode != packet[DNS].rcode) or (dns_response[DNSRR].rdata != packet[DNSRR].rdata):
                
                if(DNSRR in dns_response):
                    malicious_ip = dns_response[DNSRR].rdata
                else:
                    malicious_ip = "DNE"

                if(DNSRR in packet):
                    legit_ip = packet[DNSRR].rdata
                else:
                    legit_ip = "DNE"
                
                with open('attack_log.txt', 'a+') as file:
                    log = \
                    time.strftime("%B %d %Y %H:%M:%S") + "\n" + \
                    f"TXID {dns_id} Request {dns_qd.qname.decode('utf-8')[:-1]}" + "\n" + \
                    f"Answer1 {legit_ip}" + "\n" + \
                    f"Answer2 {malicious_ip}" + "\n\n"

                    file.write(log)

             
        all_dns_response[dns_id] = packet
    

if __name__ == '__main__':
    parse = argparse.ArgumentParser(add_help=False)
    address_family = netifaces.AF_INET
    interface_ip, network_interface = netifaces.gateways()['default'][address_family]

    parse.add_argument("-i", "--interface", default=network_interface)
    parse.add_argument("-r", "--tracefile", default=None)

    args = parse.parse_args()

    addresses = netifaces.ifaddresses(network_interface)
    local_ip = addresses[address_family][0]['addr']

    if args.tracefile != None:
        sniff(offline=str(args.tracefile), store=0, prn=dns_detect)
    else:
        sniff(iface=str(args.interface), store=0, prn=dns_detect)
