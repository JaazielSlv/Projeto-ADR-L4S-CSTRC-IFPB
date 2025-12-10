# Framework Analítico para Detecção de Ataques de ECN Não-Responsivo em Arquiteturas L4S

Este repositório contém o ambiente de experimentação (Testbed), scripts de coleta e dataset para o Projeto Final da disciplina de **Avaliação de Desempenho em Redes de Computadores** (2025.2). O projeto foca na detecção de ataques em redes de baixa latência (L4S) utilizando Aprendizado de Máquina.

## 📖 Visão Geral

A arquitetura L4S (Low Latency, Low Loss, Scalable Throughput) depende da colaboração entre o host e a rede através de marcas ECN (Explicit Congestion Notification). Um **Ataque ECN Não-Responsivo** ocorre quando um host malicioso marca pacotes como prioritários (`ECT(1)`), mas ignora deliberadamente os sinais de congestionamento (`CE`) enviados pelo roteador, saturando a fila de baixa latência e prejudicando usuários legítimos.

O objetivo deste framework é simular este cenário, coletar métricas no gargalo da rede e gerar um dataset rotulado para treinamento de modelos de detecção (ex: Decision Trees).

---

## 🏗️ Topologia da Rede (Testbed)

O ambiente é orquestrado via **Vagrant** com 6 Máquinas Virtuais Ubuntu Focal, conectadas em uma topologia "Star" centrada no roteador.

**Definição das Redes e Interfaces:**

```mermaid
graph LR
    subgraph "Zona de Clientes (Origem)"
        direction TB
        C_L4S("Client L4S<br/>(TCP Prague)<br/>192.168.56.10") -- "enp0s10" --> R
        C_Leg("Classic Client<br/>(TCP Cubic)<br/>192.168.55.10") -- "enp0s9" --> R
        C_Mal("Malicious Client<br/>(UDP Fake L4S)<br/>192.168.54.10") -- "enp0s8" --> R
    end

    subgraph "Núcleo de Rede (Gargalo)"
        R{"Router Central<br/>AQM DualPI2"} 
    end

    subgraph "Zona de Servidores (Destino)"
        direction TB
        R -- "enp0s16<br/>Limit: 100Mbit" --> S_L4S("Server L4S<br/>192.168.57.10")
        R -- "enp0s16" --> S_Leg("Server Classic<br/>192.168.57.20")
    end
```

### Componentes e Configurações:

1.  **Router (Central):**
    * **Função:** Gateway para todas as redes e ponto de extração de dados (Sniffer).
    * **AQM:** Configurado com `DualPI2` (Dual Queue Coupled AQM) para separar filas L (L4S) e C (Classic).
    * **Gargalo:** Interface `enp0s16` (saída para servidores) limitada a **100Mbit** via HTB para forçar congestionamento.
    * **Ferramentas:** Executa `tshark` e script Python para coleta de métricas.

2.  **Client L4S (Vítima):**
    * Usa Kernel `l4s-testing` com `tcp_congestion_control=prague`.
    * Marca pacotes com `ECT(1)` e responde aos sinais de CE.

3.  **Client Classic (Fundo):**
    * Gera tráfego legado (TCP Cubic) para preencher a fila clássica e validar o isolamento.

4.  **Malicious Client (Atacante):**
    * Usa `iptables` para forçar a marca `ECT(1)` (`TOS 0x01/0x03`) em pacotes UDP.
    * **Comportamento:** Não implementa redução de taxa (Non-Responsive), ignorando sinais de congestionamento.

---

## ⏱️ Metodologia de Teste

Cada sessão de experimento para geração do dataset segue um cronograma rigoroso de **200 segundos**, com extração de métricas a cada **1.0 segundo**.

### Cronograma de Injeção de Tráfego

| Tempo (s) | Fase | Ação | Label Esperado |
| :--- | :--- | :--- | :--- |
| **00 - 10** | **Baseline** | Início da captura. Rede ociosa. | `0` (Benigno) |
| **10 - 40** | **Tráfego Legítimo** | `Client L4S` (Prague) e `Classic Client` (Cubic) iniciam transmissão simultânea. | `0` (Benigno) |
| **40 - 140** | **Ataque** | `Malicious Client` inicia inundação UDP (ECT1) contra o Server L4S. | `1` (Malicioso) |
| **140 - 200** | **Recuperação** | Ataque cessa. Observação da drenagem da fila e estabilização. | `0` (Benigno) |

---

## 📊 Dicionário de Métricas

O script de monitoramento extrai as seguintes características (features) no roteador:

### 1. Identificadores
* **`timestamp`**: Momento exato da captura da janela.
* **`label`**: Classificação supervisionada (`0` = Normal, `1` = Ataque).

### 2. Métricas de Impacto (Sintomas)
* **`rtt_mean` (ms)**: Média do tempo de ida e volta na janela. **Métrica principal:** aumenta drasticamente durante o ataque devido à fila L saturada.
* **`rtt_max` (ms)**: Pico de latência observado na janela.
* **`rtt_std`**: Jitter (variação da latência).
* **`rtt_gradient`**: Taxa de variação do RTT (tendência de subida ou descida).

### 3. Métricas de Tráfego
* **`throughput_bps`**: Largura de banda total consumida.
* **`goodput_bps`**: Taxa de dados úteis (apenas payload TCP).
* **`burstiness`**: Índice de rajada (Throughput Atual / Média Histórica).
* **`packet_rate_pps`**: Pacotes por segundo processados.

### 4. Métricas ECN (Marcas de Congestionamento)
* **`ect1_count`**: Número de pacotes marcados como L4S. O ataque infla artificialmente este valor.
* **`ce_count` (Congestion Experienced)**: Número de pacotes marcados pelo roteador indicando congestionamento. Durante o ataque, este valor explode.
* **`ce_mark_rate`**: Taxa de marcas CE por segundo.
* **`ecn_responsiveness_index`**: Relação entre Throughput e CE. Se o CE é alto e o Throughput não cai, o índice sobe (indicador forte de não-responsividade).

### 5. Métricas de Fila (DualPI2)
* **`l4s_queue_occupancy`**: Volume de dados (Bytes) na fila de Baixa Latência.
* **`queue_delay_ratio`**: Comparativo entre o atraso da fila L4S e da fila Classic.

---

## 🚀 Instruções de Execução

### 1. Provisionar Infraestrutura
Na raiz do projeto (onde está o `Vagrantfile`):
```bash
vagrant up
```

### 2. Iniciar o Monitor no Roteador

```bash
vagrant ssh router
sudo python3 coleta_metrics_v2.py
```

### 3. Executar Cargas (Em terminais separados)

Abra terminais SSH para cada máquina e execute na ordem:

**A. Servidores (Ouvindo):**

```bash
# Terminal 1
vagrant ssh server-l4s
iperf3 -s

# Terminal 2
vagrant ssh classic-server
iperf3 -s
```

**B. Clientes Legítimos (Início aos 10s):**

```bash
# Terminal 3 (Tráfego de Fundo)
vagrant ssh classic-client
iperf3 -c 192.168.57.20 -t 200

# Terminal 4 (Vítima L4S)
vagrant ssh client-l4s
iperf3 -c 192.168.57.10 -t 200 -C prague
```

**C. Atacante (Início aos 40s):**

```bash
# Terminal 5 (Ataque)
vagrant ssh malicious-client
sudo python3 ataque_udp.py
```

### 4. Resultados

O arquivo `dataset_l4s_final.csv` será gerado automaticamente e estará disponível na pasta `/vagrant/` (acessível no host).
