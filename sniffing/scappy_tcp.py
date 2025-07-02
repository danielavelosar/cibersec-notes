#!/usr/bin/env python3
from scapy.all import sniff, IP, IPv6, TCP

def handle(pkt):
    if pkt.haslayer(IP):          # IPv4
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):      # IPv6
        ip_layer = pkt[IPv6]
    else:                         # No es IP ni IPv6 → ignora
        return

    tcp = pkt[TCP]
    flags = tcp.sprintf("%flags%")
    print(f"{ip_layer.src}:{tcp.sport} → {ip_layer.dst}:{tcp.dport} "
          f"| flags={flags} seq={tcp.seq} ack={tcp.ack}")

print("[*] Capturando TCP… Ctrl-C para detener")
sniff(
    filter="tcp",        # BPF: paquetes con protocolo TCP (IPv4 o IPv6)
    prn=handle,
    store=False,
    iface="enp0s3"       # ajusta a tu NIC o deja None
)
