from scapy.all import Ether,IP,UDP,Raw, sendp

#https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/creating_packets/index.html
def send_packet(src_ip, dst_ip, dst_port, payload):
	l2 = Ether()
	l3 = IP(dst=dst_ip, src=src_ip)
	l4 = UDP(dport=dst_port)
	data = "This is a thing that is a thing"
	payload = Raw(load=data)

	packet = l2/l3/l4/payload
	sendp(packet)

	return 0

send_packet("185.199.108.153", "162.159.133.234", 6969, 2343)

