import ipaddress
from scapy.all import *

network = ipaddress.ip_network("10.0.2.0/30")  # /30 para pocos IPs

for ip in network.hosts():  # omite network y broadcast
    packet = IP(dst=str(ip))/ICMP()
    send(packet)
