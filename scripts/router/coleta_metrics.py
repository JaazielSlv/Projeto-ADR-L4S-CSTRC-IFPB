import subprocess
import time
import pandas as pd
import numpy as np
from datetime import datetime
import re
import threading
from collections import deque

# --- CONFIGURAÇÕES ---
INTERFACE_WAN = "enp0s16"   # Interface de SAÍDA para os servidores (onde a fila enche)
INTERFACE_LAN = "enp0s10"   # Interface de onde vem o cliente legitimo (monitoramento passivo)
ATTACKER_IP = "192.168.54.10" # IP do Atacante (Usado para ROTULAR o dado como Malicioso)
WINDOW_SIZE = 1.0           # Janela de agregação em segundos
OUTPUT_FILE = "dataset_l4s_attack.csv"

# Variáveis Globais de Estado
data_buffer = []
is_running = True

# Estrutura para armazenar métricas acumuladas na janela atual
class MetricsWindow:
    def __init__(self):
        self.reset()
        
    def reset(self):
        self.bytes_total = 0
        self.bytes_useful = 0 # TCP Payload
        self.packet_count = 0
        self.retransmissions = 0
        self.ce_marks = 0     # Congestion Experienced
        self.ect1_marks = 0   # L4S Marks
        self.rtt_samples = [] # Lista de RTTs capturados (se disponivel via TCP info)
        self.packet_sizes = []
        self.arrival_times = []
        self.attacker_bytes = 0 # Para rotulagem
        self.tcp_flags = []
        
current_window = MetricsWindow()

# Histórico para métricas deslizantes (Rolling)
history_rtt = deque(maxlen=10) # Ultimos 10 segundos
history_throughput = deque(maxlen=10)

def get_queue_stats():
    """ 
    Executa 'tc -s qdisc' para pegar dados REAIS da fila DualPI2.
    Retorna dicionário com atrasos e ocupação.
    """
    try:
        # Comando para ler estatisticas da interface WAN
        cmd = f"tc -s qdisc show dev {INTERFACE_WAN}"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8')
        
        # Regex simplificado para capturar dados do DualPI2 (ajuste conforme seu output real do TC)
        # Exemplo hipotético de output: "l4s_delay 5ms classic_delay 15ms"
        # Você precisará ajustar estes REGEX baseados no output exato do seu kernel L4S
        l4s_delay = 0
        classic_delay = 0
        drops = 0
        
        # Busca genérica por padrões numéricos comuns no output do tc
        # No seu lab, rode 'tc -s qdisc show dev enp0s16' para ver o padrão exato
        # Aqui simulamos a extração:
        if "dualpi2" in result:
             # Exemplo de parsing (pode precisar de ajuste fino)
             # Procure campos como 'backlog', 'dropped', 'l4s_packets'
             pass 
             
        return {
            "l4s_queue_delay_ms": 0, # Placeholder: Implementar parser do output exato
            "classic_queue_delay_ms": 0,
            "drops": 0
        }
    except:
        return {"l4s_queue_delay_ms": 0, "classic_queue_delay_ms": 0, "drops": 0}

def capture_traffic():
    """
    Usa TShark para capturar campos específicos e alimentar a janela atual.
    Opções: ip.src, ip.len, tcp.len, tcp.analysis.ack_rtt, ip.dsfield.ecn
    """
    # Tshark command line para output CSV em tempo real
    # -l: flush line-buffered
    # -T fields -e ...: extrair campos específicos
    cmd = [
        "tshark", "-i", INTERFACE_WAN, "-l", "-n", 
        "-T", "fields", "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "frame.len",          # Tamanho total
        "-e", "tcp.len",            # Payload TCP (Goodput)
        "-e", "tcp.analysis.ack_rtt", # RTT calculado pelo wireshark
        "-e", "ip.dsfield.ecn",     # ECN Flags (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE)
        "-e", "tcp.analysis.retransmission" # Flag de retransmissão
    ]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    
    for line in process.stdout:
        if not is_running: break
        try:
            # Parsing da linha CSV do Tshark
            cols = line.strip().split(',')
            if len(cols) < 6: continue
            
            ts = float(cols[0])
            ip_src = cols[1]
            pkt_len = int(cols[2]) if cols[2] else 0
            tcp_len = int(cols[3]) if cols[3] else 0
            rtt = float(cols[4]) * 1000 if cols[4] else None # Convertendo p/ ms
            ecn = int(cols[5], 16) if cols[5].startswith('0x') else int(cols[5]) if cols[5] else 0
            is_retrans = True if cols[6] else False

            # Atualiza métricas atômicas (Thread Safe-ish para este escopo simples)
            current_window.packet_count += 1
            current_window.bytes_total += pkt_len
            current_window.bytes_useful += tcp_len
            current_window.packet_sizes.append(pkt_len)
            current_window.arrival_times.append(ts)
            
            if rtt: current_window.rtt_samples.append(rtt)
            if is_retrans: current_window.retransmissions += 1
            
            # Checagem de ECN
            if ecn == 3: # 11 em binário = CE
                current_window.ce_marks += 1
            elif ecn == 1: # 01 em binário = ECT(1) (L4S)
                current_window.ect1_marks += 1
                
            # Checagem de Atacante para Rotulagem
            if ip_src == ATTACKER_IP:
                current_window.attacker_bytes += pkt_len
                
        except Exception as e:
            continue

def process_metrics_loop():
    """ Loop principal que consolida os dados a cada segundo e salva no CSV """
    global current_window
    
    # Headers do CSV
    columns = [
        "timestamp", "label",
        "throughput_bps", "goodput_bps", "packet_rate_pps",
        "packet_loss_rate", "retransmission_rate",
        "jitter_ms", "inter_arrival_time_mean", 
        "packet_size_mean", "packet_size_std",
        "burstiness", "rtt_mean", "rtt_std", "rtt_gradient",
        "ce_count", "ce_mark_rate", "ect1_count",
        "cwnd_growth_rate", # Estimado via throughput
        "rolling_mean_rtt", "rolling_slope_rtt",
        "l4s_queue_delay_ms", "classic_queue_delay_ms"
    ]
    
    # Cria arquivo e escreve header
    pd.DataFrame(columns=columns).to_csv(OUTPUT_FILE, index=False)
    
    while is_running:
        time.sleep(WINDOW_SIZE)
        
        # 1. Captura snapshot da janela e reseta para a próxima
        snapshot = current_window
        current_window = MetricsWindow() # Reseta imediato
        
        # Se não houve pacotes, pular ou registrar zeros
        if snapshot.packet_count == 0:
            continue
            
        # 2. Cálculos Estatísticos
        # Throughput
        throughput = (snapshot.bytes_total * 8) / WINDOW_SIZE
        goodput = (snapshot.bytes_useful * 8) / WINDOW_SIZE
        pps = snapshot.packet_count / WINDOW_SIZE
        
        # Estatísticas de Pacotes
        pkt_sizes = np.array(snapshot.packet_sizes)
        inter_arrival = np.diff(snapshot.arrival_times) if len(snapshot.arrival_times) > 1 else [0]
        jitter = np.std(inter_arrival) * 1000 # ms
        
        # Estatísticas de RTT
        rtt_mean = np.mean(snapshot.rtt_samples) if snapshot.rtt_samples else 0
        rtt_std = np.std(snapshot.rtt_samples) if snapshot.rtt_samples else 0
        
        # Histórico e Gradients
        history_rtt.append(rtt_mean)
        history_throughput.append(throughput)
        
        # Calculo de Gradiente (Tendência)
        # Se RTT está subindo rápido = Gradient Positivo alto
        rtt_gradient = 0
        if len(history_rtt) >= 2:
            rtt_gradient = history_rtt[-1] - history_rtt[-2]
            
        rolling_mean_rtt = np.mean(history_rtt)
        
        # Calculo de Slope (Regressão linear simples nos ultimos pontos)
        rolling_slope_rtt = 0
        if len(history_rtt) > 3:
            y = np.array(history_rtt)
            x = np.arange(len(y))
            rolling_slope_rtt = np.polyfit(x, y, 1)[0] # Inclinação da reta
            
        # 3. Métricas de Fila (TC)
        queue_stats = get_queue_stats()
        
        # 4. ROTULAGEM (O Pulo do Gato)
        # Se mais de 10% do tráfego da janela veio do IP do atacante, é Ataque.
        label = 0
        if snapshot.attacker_bytes > (snapshot.bytes_total * 0.1): 
            label = 1
            
        # 5. Montar Linha
        row = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "label": label,
            "throughput_bps": throughput,
            "goodput_bps": goodput,
            "packet_rate_pps": pps,
            "packet_loss_rate": 0, # Difícil pegar no router sem ver SEQ numbers pulados
            "retransmission_rate": snapshot.retransmissions / snapshot.packet_count if snapshot.packet_count else 0,
            "jitter_ms": jitter,
            "inter_arrival_time_mean": np.mean(inter_arrival),
            "packet_size_mean": np.mean(pkt_sizes),
            "packet_size_std": np.std(pkt_sizes),
            "burstiness": throughput / np.mean(history_throughput) if len(history_throughput) > 0 and np.mean(history_throughput) > 0 else 0,
            "rtt_mean": rtt_mean,
            "rtt_std": rtt_std,
            "rtt_gradient": rtt_gradient,
            "ce_count": snapshot.ce_marks,
            "ce_mark_rate": snapshot.ce_marks / WINDOW_SIZE,
            "ect1_count": snapshot.ect1_marks,
            "cwnd_growth_rate": 0, # Indisponível no Router (apenas estimado)
            "rolling_mean_rtt": rolling_mean_rtt,
            "rolling_slope_rtt": rolling_slope_rtt,
            "l4s_queue_delay_ms": queue_stats["l4s_queue_delay_ms"],
            "classic_queue_delay_ms": queue_stats["classic_queue_delay_ms"]
        }
        
        # Append to CSV
        df_row = pd.DataFrame([row])
        df_row.to_csv(OUTPUT_FILE, mode='a', header=False, index=False)
        print(f"[DATA] Label: {label} | RTT: {rtt_mean:.2f}ms | Throughput: {throughput/1e6:.2f} Mbps")

if __name__ == "__main__":
    print("--- INICIANDO COLETOR L4S INTELLIGENT ---")
    
    # Inicia Thread de Captura
    t_cap = threading.Thread(target=capture_traffic)
    t_cap.daemon = True
    t_cap.start()
    
    # Inicia Processamento Principal
    try:
        process_metrics_loop()
    except KeyboardInterrupt:
        is_running = False
        print("\nParando captura...")