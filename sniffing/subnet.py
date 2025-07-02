from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst
        if dst_ip.startswith("192.168.1."):
            print(packet.summary())

sniff(iface="enp0s3", prn=packet_callback)
