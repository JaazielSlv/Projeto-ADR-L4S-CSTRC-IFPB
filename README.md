# ADR L4S — Ambiente de Detecção e Rede com Vagrant/Ansible

Este projeto provisiona um ambiente de rede para experimentos com L4S (Low Latency, Low Loss, Scalable throughput) usando Vagrant + VirtualBox + Ansible, incluindo:

- Topologia com clientes (L4S, classic e malicioso), roteador com `dualpi2` e servidores.
- Playbooks que preparam kernel/testes L4S e `dualpi2`.
- Scripts de análise de tráfego e treino de IA para detecção de ataques.
- IDS em tempo real no roteador baseado nas mesmas features do dataset.


## Integrantes

- Jaaziel Silva
- Lucas Jaiel
- Jose Jantony


## Visão Geral

![Topologia do Projeto](docs/topology.png)

- Infra: Vagrant cria 5 VMs (client-l4s, classic-client, malicious-client, router, server-l4s, classic-server).
- QoS: `dualpi2` no roteador e `fq` nos endpoints com ECN/Prague nos nós L4S.
- Dataset: `docs/dataset/dataset_l4s_final.csv` e arquivos de teste em `docs/dados_testes/`.
- IA: `train_model.py` treina uma Árvore de Decisão e salva `l4s_detection_model.pkl`.
- IDS: `ids_l4s.py` lê tráfego via TShark, extrai features por janela de 1s e classifica.


## Topologia e IPs

Definidos em `Vagrantfile`:
- `client-l4s`: 192.168.56.10 → rede `rede_client_router`
- `classic-client`: 192.168.55.10 → rede `rede_classic_client_router`
- `malicious-client`: 192.168.54.10 → rede `rede_malicious_client_router`
- `router`: 192.168.54.2 / 55.2 / 56.2 / 57.2 (4 NICs)
- `server-l4s`: 192.168.57.10 → rede `rede_router_server`
- `classic-server`: 192.168.57.20 → rede `rede_router_server`

Principais tunings (trechos do `Vagrantfile`):
- Clientes L4S: `tcp_ecn=3`, `tcp_congestion_control=prague`, offloads desativados, `fq`.
- Roteador: `ip_forward=1`, `sch_dualpi2` nas NICs de acesso, HTB+dualpi2 na NIC de servidores.

 Playbooks (Ansible)

- `playbooks/client-l4s.yml` e `playbooks/server-l4s.yml`:
  - Instalam pacotes base.
  - Checam/instalam kernel L4S (Prague) a partir de release `l4s-testing.zip`.
  - Ajustam ECN, congestion control e `fq`.

- `playbooks/router.yml`:
  - Instala pacotes base e libs Python (`numpy`, `pandas`, `scapy`).
  - Verifica/instala kernel L4S apenas se necessário.
  - Carrega módulo `sch_dualpi2`.



## Métricas (Treinamento e IDS)

O treinamento em [scripts/train_model.py](scripts/train_model.py) e o IDS em [scripts/ids_l4s.py](scripts/ids_l4s.py) — utilizam exatamente o mesmo conjunto de features, garantindo consistência entre o que o modelo aprende e o que o IDS classifica em tempo real. As métricas usadas são:

- flow_throughput_bps: taxa de bits por segundo na janela (volume). Ajuda a identificar padrões de tráfego anormais (picos sustentados ou quedas) comuns em cenários de ataque.
- ratio_ect1: proporção de pacotes com marcação ECN ECT(1). Em L4S, o uso de ECN é intensivo; essa razão indica presença e intensidade de marcação L4S no fluxo.
- ratio_ce: proporção de pacotes com ECN CE (Congestion Experienced). Elevações nessa métrica indicam congestionamento efetivamente sinalizado na rede — típico quando há tráfego agressivo ou malicioso.
- flag_cwr: contagem absoluta de flags TCP CWR (Congestion Window Reduced). Captura a reação dos emissores à sinalização ECN; valores anômalos podem indicar comportamento agressivo/reativo em ataques.
- ratio_cwr: versão normalizada da CWR (contagem/total de pacotes). Evita viés por fluxo com mais pacotes, permitindo comparar janelas de tamanhos distintos.
- tcp_win_mean: média da janela TCP observada. Reflete a dinâmica de controle de fluxo e adaptação ao congestionamento; padrões incomuns podem sinalizar tráfego malicioso.
- iat_mean: média do tempo entre chegadas de pacotes (IAT), um proxy de jitter/pacing. Ataques costumam apresentar ritmos de envio diferentes dos fluxos benignos.
- pkt_len_mean: média do tamanho de pacote. Distribuições de tamanho atípicas (muito pequenos ou grandes) podem caracterizar certos tipos de ataques.



## Gráficos e Evidências (IDS)

Evolução de banda medida nos cenários:

![Bandwidth Baseline](docs/imgs/bandwidth_baseline.png)

- Baseline : Mostra um ecossistema competitivo onde os fluxos "Classic I" (Azul) e "Classic II" (Vermelho) oscilam em torno de 40-60 Mbps, dominando o canal, enquanto o "L4S" (Verde) opera em segundo plano.




![Bandwidth Ataque](docs/imgs/bandwidth_malicious.png)

- Ataque: A linha vermelha ("Malicioso"/Atacante) assume o topo do gráfico, mantendo-se alta e estável (platô próximo a 90-100 Mbps). As linhas azul e verde são esmagadas contra o eixo X (zero), visualizando a inanição descrita nos logs. 3 A correlação entre a representação visual e os dados brutos é absoluta

## Execução do IDS em tempo real (prints da console):

![IDS Rodando 1](docs/imgs/Screenshot%20from%202026-02-05%2015-30-20.png)

![IDS Rodando 2](docs/imgs/Screenshot%20from%202026-02-05%2015-33-12.png)

## Dataset e Dados de Teste

- Dataset consolidado: `docs/dataset/dataset_l4s_final.csv`.
- Dumps/indicadores de teste: `docs/dados_testes/` com `baseline_*` e `ataque_*`.
- Geração de CSV a partir de PCAP customizado:
  - Use `scripts/analise_dump.py` (espera `fluxo_benigno.pcap` e gera `fluxo_benigno.csv`).

## Subir Ambiente

```bash
vagrant up
```

Acessar o roteador:

```bash
vagrant ssh router
```



## Treinar o Modelo (Host)

O script [scripts/train_model.py](scripts/train_model.py) treina uma árvore de decisão usando o dataset final e salva [scripts/l4s_detection_model.pkl](scripts/l4s_detection_model.pkl).

1) Verifique o caminho do dataset. Recomenda-se ajustar `DATASET_PATH` para:

```python
DATASET_PATH = os.path.join(SCRIPT_DIR, '..', 'docs', 'dataset', 'dataset_l4s_final.csv')
```

2) Instale dependências (host):

```bash
pip install numpy pandas scikit-learn matplotlib joblib
```

3) Treine o modelo:

```bash
cd scripts
python train_model.py
```

Saída esperada: acurácia, relatório de classificação e salvamento do modelo em `scripts/l4s_detection_model.pkl`.


## Executar o IDS no Roteador

O [scripts/ids_l4s.py](scripts/ids_l4s.py) monitora a interface WAN (`enp0s16`) via TShark, agrega por 1s e classifica as janelas.

1) Copie o modelo para o roteador:

```bash
vagrant ssh router
# dentro da VM
sudo cp /vagrant/scripts/l4s_detection_model.pkl /home/vagrant/
```

2) Instale TShark:

```bash
sudo apt update
sudo apt install -y tshark
```

3) Execute o IDS:

```bash
python3 /vagrant/scripts/ids_l4s.py
```

Mensagens:
- NORMAL: Throughput e métricas dentro do esperado.
- ALERTA: Janela classificada como ataque (ex.: alto `ratio_ce`, `cwr`).



## Estrutura do Repositório

- `Vagrantfile`: Topologia, redes privadas e provisionamento (Ansible + shell).
- `playbooks/`: Playbooks Ansible para clientes, roteador e servidor L4S.
- `scripts/`: Análise de PCAP, treino de modelo e IDS.
- `docs/dataset/`: Dataset final CSV para treino/validação.
- `docs/dados_testes/`: Baselines e traços de ataque (texto).
- `docs/imgs/`: Imagens (se usadas no relatório).
