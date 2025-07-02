#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Sniffer: captura paquetes TCP cuya IP ­origen == TARGET_IP y dport == 23
# Ejecútalo con sudo.

from scapy.all import sniff, IP, TCP

# ← Cambia esta IP por la que quieras vigilar
TARGET_IP = "192.168.20.1"

def handle(pkt):
    ip  = pkt[IP]
    tcp = pkt[TCP]
    flags = tcp.sprintf("%flags%")
    print(f"{ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} "
          f"| flags={flags} seq={tcp.seq} ack={tcp.ack}")

# Filtro BPF: “solo TCP, origen TARGET_IP y puerto destino 23”
bpf_filter = f"tcp and src host {TARGET_IP} and dst port 23"

print(f"[*] Capturando TCP desde {TARGET_IP} hacia puerto 23 (Telnet)… Ctrl-C para parar")
sniff(
    filter=bpf_filter,   # aplica el filtro a nivel kernel → eficiente
    prn=handle,          # callback por paquete
    store=False,
    iface="enp0s3"       # ajusta al nombre de tu NIC o déjalo None
)
