from scapy.all import ARP, Ether, srp

# Escanea la red donde está la VM
arp = ARP(pdst="192.168.20.0/24")
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp

print("[*] Enviando paquetes ARP...")
ans, _ = srp(packet, timeout=3, verbose=1)

print("\n[*] Respuestas recibidas:")
for snd, rcv in ans:
    print(f"IP: {rcv.psrc} | MAC: {rcv.hwsrc}")