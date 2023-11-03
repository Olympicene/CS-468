import argparse
import netifaces
from scapy import all as scapy

global local_ip

def injection(pkt):
    print(pkt)

if __name__ == '__main__':
    parse = argparse.ArgumentParser(add_help=False)
    address_family = netifaces.AF_INET
    interface_ip, network_interface = netifaces.gateways()['default'][address_family]

    parse.add_argument("-i", "--interface", default=network_interface)
    parse.add_argument("-h", "--hostname")
    args = parse.parse_args()

    addresses = netifaces.ifaddresses(network_interface)
    local_ip = addresses[address_family][0]['addr']

    scapy.sniff(iface = str(args.interface), prn=injection, store=False, count=10)

