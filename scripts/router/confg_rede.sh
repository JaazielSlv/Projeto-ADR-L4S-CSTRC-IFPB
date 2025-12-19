############################################
# Script de Configuração da Rede do Roteador
############################################

# Habilita o roteamento de pacotes
sudo sysctl -w net.ipv4.ip_forward=1

# Configura o algoritmo L4S (DualPI2) nas interfaces dos clientes
sudo tc qdisc replace dev enp0s8 root dualpi2
sudo tc qdisc replace dev enp0s9 root dualpi2
sudo tc qdisc replace dev enp0s10 root dualpi2

# Configura o limite de banda (100Mbit) e L4S na interface do servidor
sudo tc qdisc replace dev enp0s16 root handle 1: htb default 10
sudo tc class add dev enp0s16 parent 1: classid 1:10 htb rate 100Mbit ceil 100Mbit burst 1516
sudo tc qdisc add dev enp0s16 parent 1:10 dualpi2