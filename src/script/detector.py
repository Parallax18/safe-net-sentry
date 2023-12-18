import scapy.all as scapy
import sys


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        print(packet.show())

def mac(ipadd):
	try:
	    arp_request = scapy.ARP(pdst=ipadd)
	    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	    arp_req_br = br / arp_request
	    list_1 = scapy.srp(arp_req_br, timeout=5, verbose=False)[0]
	    # print(list_1[0][1].hwsrc)
	    return list_1[0][1].hwsrc
	except IndexError:
		print("Detected packet doesn't have needed layer")



def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        originalmac = mac(packet[scapy.ARP].psrc)
        attacker_mac = packet[scapy.ARP].hwsrc
        attacker_ip = packet[scapy.ARP].psrc
        if originalmac != attacker_mac:
        	print(f"[*] ALERT!! User with MAC address: {attacker_mac} is carrying out ARP table poisoning attack!")
        	# with open('example.txt', 'w') as file:
        	# 	file.write(attacker_mac)
        	# 	sys.exit()
			    # Write content to the file
			    # file.write(attacker_mac)
				# sys.exit()
			    


counter = 4
sniff("en0")