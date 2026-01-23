################################################################################
# Script de Detecção de Intrusão L4S (IDS) - Tempo Real
################################################################################
# Este script roda no Roteador e utiliza o modelo de IA treinado para detectar ataques.
# Funcionalidades:
# 1. Carrega o modelo 'l4s_detection_model.pkl' da pasta compartilhada.
# 2. Monitora o tráfego em tempo real via TShark.
# 3. Extrai as features EXATAS usadas no treinamento (analise_dump.py).
# 4. Classifica cada janela de 1s como NORMAL ou ATAQUE.
# 5. Emite alertas visuais.
################################################################################

import subprocess
import time
import pandas as pd
import numpy as np
import joblib
import os
import sys

# --- CONFIGURAÇÕES ---
INTERFACE_WAN = "enp0s16"
MODEL_PATH = "/vagrant/scripts/ml/l4s_detection_model.pkl" # Caminho do modelo treinado
WINDOW_SIZE = 1.0

# --- CARREGAR O CÉREBRO (MODELO TREINADO) ---
print(f"[*] Carregando modelo de IA: {MODEL_PATH}")
try:
    clf = joblib.load(MODEL_PATH)
    print("[OK] Modelo carregado com sucesso!")
except Exception as e:
    print(f"[ERRO] Falha ao carregar modelo: {e}")
    # Se estivermos rodando no Windows para teste, caminhos podem ser diferentes
    if os.path.exists("l4s_detection_model.pkl"):
         clf = joblib.load("l4s_detection_model.pkl")
    else:
        print("Certifique-se de ter rodado o 'train_model.py' primeiro!")
        sys.exit(1)

# Variáveis de Estado (Acumuladores da Janela)
current_stats = {
    "timestamps": [],
    "lengths": [],
    "ce_marks": 0,
    "ect1_marks": 0,
    "cwr_flags": 0,
    "tcp_windows": [],
    "packet_count": 0
}

def reset_stats():
    global current_stats
    current_stats = {
        "timestamps": [],
        "lengths": [],
        "ce_marks": 0,
        "ect1_marks": 0,
        "cwr_flags": 0,
        "tcp_windows": [],
        "packet_count": 0
    }

def process_packet_line(line):
    """ Processa uma linha de output do TShark """
    global current_stats
    try:
        parts = line.strip().split(',')
        if len(parts) < 5: return

        # Campos definidos na command line:
        # frame.time_epoch, frame.len, ip.dsfield.ecn, tcp.flags.cwr, tcp.window_size
        
        ts = float(parts[0])
        length = int(parts[1])
        ecn_val = parts[2]
        cwr_val = parts[3]
        win_val = parts[4]

        # Parse ECN
        # Tshark pode retornar vazio ou hex/int
        if ecn_val.startswith('0x'): ecn = int(ecn_val, 16)
        elif ecn_val.isdigit(): ecn = int(ecn_val)
        else: ecn = 0

        # Parse CWR (1 ou 0)
        cwr = 1 if cwr_val == '1' else 0

        # Parse Window
        win = int(win_val) if win_val.isdigit() else 0

        # Acumular
        current_stats["timestamps"].append(ts)
        current_stats["lengths"].append(length)
        current_stats["packet_count"] += 1
        current_stats["tcp_windows"].append(win)
        
        if ecn == 3: current_stats["ce_marks"] += 1
        elif ecn == 1: current_stats["ect1_marks"] += 1
        
        current_stats["cwr_flags"] += cwr

    except Exception as e:
        # print(f"Erro parse line: {e} | {line}")
        pass

def start_ids():
    # CMD TShark atualizado para pegar as features certas
    # frame.time_epoch, frame.len, ip.dsfield.ecn, tcp.flags.cwr, tcp.window_size
    cmd = [
        "tshark", "-i", INTERFACE_WAN, "-l", "-n", 
        "-T", "fields", "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.dsfield.ecn",
        "-e", "tcp.flags.cwr",
        "-e", "tcp.window_size"
    ]
    
    print(f"[*] Iniciando Monitoramento IDS na interface {INTERFACE_WAN}...")
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    
    last_check = time.time()
    reset_stats()

    for line in process.stdout:
        process_packet_line(line)
        
        now = time.time()
        if now - last_check >= WINDOW_SIZE:
            # --- HORA DA DECISÃO DA IA ---
            
            count = current_stats["packet_count"]
            if count > 0:
                # 1. Calcular Features (Igual ao analise_dump.py)
                
                # Throughput
                total_bytes = sum(current_stats["lengths"])
                throughput = (total_bytes * 8) / WINDOW_SIZE # bps
                
                # IAT Mean
                if count > 1:
                    timestamps = np.array(sorted(current_stats["timestamps"]))
                    iat = np.diff(timestamps)
                    iat_mean = np.mean(iat)
                else:
                    iat_mean = 0

                # Window Mean
                win_mean = np.mean(current_stats["tcp_windows"]) if len(current_stats["tcp_windows"]) > 0 else 0
                
                # Pkt Len Mean
                pkt_len_mean = np.mean(current_stats["lengths"])

                # Ratios
                ratio_ect1 = current_stats["ect1_marks"] / count
                ratio_ce = current_stats["ce_marks"] / count
                ratio_cwr = current_stats["cwr_flags"] / count
                
                # Montar DF
                features = pd.DataFrame([{
                    'flow_throughput_bps': throughput,
                    'ratio_ect1': ratio_ect1,
                    'ratio_ce': ratio_ce,
                    'flag_cwr': current_stats["cwr_flags"],
                    'ratio_cwr': ratio_cwr,
                    'tcp_win_mean': win_mean,
                    'iat_mean': iat_mean,
                    'pkt_len_mean': pkt_len_mean
                }])
                
                # 2. Predição
                try:
                    prediction = clf.predict(features)[0]
                    
                    timestamp_str = time.strftime("%H:%M:%S")
                    if prediction == 1:
                        print(f"\033[91m[{timestamp_str}] [ALERTA] ATAQUE L4S DETECTADO! (CE: {ratio_ce:.2f} | CWR: {current_stats['cwr_flags']})\033[0m")
                    else:
                        print(f"\033[92m[{timestamp_str}] [NORMAL] Rede Ok. (Throughput: {throughput/1e6:.1f} Mbps)\033[0m")
                except Exception as e:
                    print(f"Erro na predição: {e}")
            
            # Reset
            reset_stats()
            last_check = now

if __name__ == "__main__":
    start_ids()
