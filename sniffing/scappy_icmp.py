#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ICMP sniffer para hosts en 192.168.20.0/24
# Ejecútalo con sudo para que Scapy pueda poner la NIC en modo promiscuo.

from scapy.all import sniff, IP, ICMP

def handle_pkt(pkt):
    """
    Callback que se ejecuta por cada paquete capturado.
    Solo imprimimos resumen cuando hay capa ICMP dentro del paquete.
    """
    ip = pkt[IP]               # Capa IP (origen y destino)
    icmp = pkt[ICMP]           # Capa ICMP (tipo, código, id, secuencia)
    print(f"{ip.src} → {ip.dst} | "
          f"type={icmp.type} code={icmp.code} "
          f"id={icmp.id} seq={icmp.seq}")

print("[*] Escuchando ICMP en la interfaz… (Ctrl-C para parar)")

sniff(
    filter="icmp",    # Filtro BPF: solo paquetes ICMP (echo-request/reply, etc.)
    prn=handle_pkt,   # Función a llamar por cada paquete
    store=False,      # No guardes los paquetes en memoria, solo pásalos al callback
    iface="enp0s3"    # Ajusta al nombre de tu NIC en la VM o deja None para la default
)
