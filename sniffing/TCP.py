from scapy.all import *

ip = IP(dst="10.0.2.3")
tcp = TCP(dport=1234, sport=RandShort(), flags="PA", seq=1000, ack=100)  # PSH+ACK
payload = Raw(load="Hola desde Scapy")
packet = ip/tcp/payload

send(packet)
