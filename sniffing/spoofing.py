#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Envía un ICMP Echo‐Request (ping) con IP de origen FALSIFICADA.
# Ejecuta con sudo para que Scapy pueda forjar paquetes a bajo nivel.

from scapy.all import IP, ICMP, send
import time

SPOOFED_SRC = "10.10.10.10"        # IP inventada; no debe ser tuya
DEST_IP     = "192.168.20.1"       # IP real del receptor (p.ej. tu host)
COUNT       = 4                    # Nº de eco-requests a enviar
IFACE       = "enp0s3"             # NIC de tu VM (confírmalo con `ip a`)

for seq in range(1, COUNT + 1):
    pkt = (
        IP(src=SPOOFED_SRC, dst=DEST_IP, ttl=64, id=0xBEEF)
        / ICMP(type="echo-request", id=0x1337, seq=seq)
        / b"spoof-test"
    )
    send(pkt, iface=IFACE, verbose=False)
    print(f"[+] Ping #{seq} con origen {SPOOFED_SRC} enviado")
    time.sleep(1)
