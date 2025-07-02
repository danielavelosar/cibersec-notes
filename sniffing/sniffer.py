#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Sniffer: captura paquetes que vengan DE o vayan A la red 168.176.0.0/16
# Requiere sudo.

from scapy.all import sniff, IP

TARGET_NET = "168.176.0.0/16"          # la red que queremos vigilar

def handle(pkt):
    """Se ejecuta por cada paquete capturado que pase el filtro BPF."""
    ip = pkt[IP]                        # ya sabemos que SÍ tiene capa IP
    print(f"{ip.src}  →  {ip.dst}  |  proto={ip.proto}  len={ip.len}")

# Filtro BPF: ‘ip net 168.176.0.0/16’ atrapa cualquier paquete (src O dst) en esa red
bpf_filter = f"ip net {TARGET_NET}"

print(f"[*] Capturando tráfico dentro / hacia / desde {TARGET_NET} … Ctrl-C para parar")
sniff(
    filter=bpf_filter,   # se aplica en kernel → eficiente
    prn=handle,          # callback por paquete
    store=False,
    iface="enp0s3"       # tu NIC; pon None si quieres la default
)
