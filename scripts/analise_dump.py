import pandas as pd
import numpy as np
from scapy.all import PcapReader, IP, TCP, UDP

# --- CONFIGURAÇÕES ---
PCAP_FILE = 'fluxo_benigno.pcap'   # Seu arquivo de captura
OUTPUT_CSV = 'fluxo_benigno.csv' # Arquivo final para o Excel/Pandas
TIME_WINDOW = 1.0                   # Janela de 1 segundo

def extract_features_rich(pcap_path):
    print(f" Iniciando extração profunda de: {pcap_path}")
    
    # Dicionário principal.
    # Chave: (SrcIP, DstIP, Sport, Dport, Proto, WindowIndex)
    flows = {}
    
    first_ts = None
    
    with PcapReader(pcap_path) as pcap:
        for i, pkt in enumerate(pcap):
            if i % 50000 == 0:
                print(f"   Processados {i} pacotes...")
            
            # 1. Filtros básicos (Só IPv4 e TCP/UDP)
            if not pkt.haslayer(IP):
                continue
            
            ip = pkt[IP]
            timestamp = float(pkt.time)
            
            if first_ts is None: first_ts = timestamp
            
            # Índice da Janela de Tempo
            window_idx = int((timestamp - first_ts) / TIME_WINDOW)
            
            # Identificação do Fluxo (5-tuple)
            proto = ip.proto
            src = ip.src
            dst = ip.dst
            sport = 0
            dport = 0
            
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            
            key = (src, dst, sport, dport, proto, window_idx)
            
            # Inicializa estrutura se novo fluxo nesta janela
            if key not in flows:
                flows[key] = {
                    # Listas para cálculos estatísticos (serão processadas no final)
                    'lengths': [],
                    'timestamps': [],
                    'tcp_windows': [],
                    
                    # Contadores ECN (IP)
                    'ect0': 0, 'ect1': 0, 'ce': 0, 'non_ect': 0,
                    
                    # Contadores Flags TCP
                    'flags_cwr': 0, 'flags_ece': 0, 'flags_urg': 0,
                    'flags_ack': 0, 'flags_psh': 0, 'flags_rst': 0,
                    'flags_syn': 0, 'flags_fin': 0
                }
            
            f = flows[key]
            
            # --- COLETA DE DADOS BRUTOS ---
            
            # Tamanho e Tempo
            f['lengths'].append(len(pkt))
            f['timestamps'].append(timestamp)
            
            # ECN (IP Header)
            tos = ip.tos
            ecn = tos & 0x03
            if ecn == 0: f['non_ect'] += 1
            elif ecn == 1: f['ect1'] += 1
            elif ecn == 2: f['ect0'] += 1
            elif ecn == 3: f['ce'] += 1
            
            # TCP Flags e Window
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                f['tcp_windows'].append(tcp.window)
                # O Scapy armazena flags como string ou objeto 'Flag'
                # Verificamos a presença de cada letra
                flags = str(tcp.flags) 
                if 'C' in flags: f['flags_cwr'] += 1
                if 'E' in flags: f['flags_ece'] += 1
                if 'U' in flags: f['flags_urg'] += 1
                if 'A' in flags: f['flags_ack'] += 1
                if 'P' in flags: f['flags_psh'] += 1
                if 'R' in flags: f['flags_rst'] += 1
                if 'S' in flags: f['flags_syn'] += 1
                if 'F' in flags: f['flags_fin'] += 1

    # --- CÁLCULOS ESTATÍSTICOS FINAIS ---
    print(" Calculando estatísticas e gerando CSV...")
    
    dataset = []
    
    for key, data in flows.items():
        src, dst, sport, dport, proto, w_idx = key
        
        # Arrays numpy para velocidade
        lengths = np.array(data['lengths'])
        timestamps = np.array(sorted(data['timestamps']))
        windows = np.array(data['tcp_windows'])
        
        count = len(lengths)
        if count == 0: continue
        
        # 1. Volume
        total_bytes = np.sum(lengths)
        throughput = (total_bytes * 8) / TIME_WINDOW
        
        # 2. Estatísticas de Tamanho de Pacote
        pkt_min = np.min(lengths)
        pkt_max = np.max(lengths)
        pkt_mean = np.mean(lengths)
        pkt_std = np.std(lengths)
        
        # 3. Estatísticas de Tempo (IAT - Jitter)
        if count > 1:
            iat = np.diff(timestamps)
            iat_min = np.min(iat)
            iat_max = np.max(iat)
            iat_mean = np.mean(iat)
            iat_std = np.std(iat) # Jitter real
        else:
            iat_min = iat_max = iat_mean = iat_std = 0
            
        # 4. Estatísticas de Janela TCP
        win_mean = np.mean(windows) if len(windows) > 0 else 0
        
        # 5. Ratios (Proporções) para normalizar os dados
        # (Útil para a IA não viciar apenas em fluxos de alto volume)
        ratio_ect1 = data['ect1'] / count
        ratio_ce = data['ce'] / count
        ratio_cwr = data['flags_cwr'] / count
        ratio_ece = data['flags_ece'] / count
        
        row = {
            # Identificadores
            'window_idx': w_idx,
            'src_ip': src,
            'dst_ip': dst,
            'sport': sport,
            'dport': dport,
            'proto': proto,
            
            # --- FEATURES PARA IA ---
            
            # ECN (O Coração do L4S)
            'ecn_ect0': data['ect0'],
            'ecn_ect1': data['ect1'],
            'ecn_ce': data['ce'],
            'ecn_non': data['non_ect'],
            'ratio_ect1': ratio_ect1,
            'ratio_ce': ratio_ce,
            
            # Volume
            'flow_throughput_bps': throughput,
            'flow_packet_count': count,
            
            # Packet Length Stats
            'pkt_len_min': pkt_min,
            'pkt_len_max': pkt_max,
            'pkt_len_mean': pkt_mean,
            'pkt_len_std': pkt_std,
            
            # Inter-Arrival Time Stats (Jitter)
            'iat_min': iat_min,
            'iat_max': iat_max,
            'iat_mean': iat_mean,
            'iat_std': iat_std,
            
            # TCP Flags (Comportamento)
            'flag_cwr': data['flags_cwr'], # Atacante deve ter isso baixo/zero
            'flag_ece': data['flags_ece'], # Vítima deve ter isso alto
            'flag_psh': data['flags_psh'],
            'flag_rst': data['flags_rst'],
            'flag_syn': data['flags_syn'],
            'ratio_cwr': ratio_cwr,
            
            # TCP Window
            'tcp_win_mean': win_mean,
            
            # Label (Deixe vazio ou 0 para preencher depois)
            'label_is_attack': 0 
        }
        dataset.append(row)
        
    df = pd.DataFrame(dataset)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f" Concluído! Dataset salvo em {OUTPUT_CSV} com {len(df)} linhas.")

# Executar
if __name__ == "__main__":
    extract_features_rich(PCAP_FILE)
