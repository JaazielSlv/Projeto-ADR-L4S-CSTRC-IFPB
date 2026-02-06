# -*- mode: ruby -*-
# vi: set ft=ruby :

################################################################################
# Vagrantfile - Definição da Infraestrutura do Testbed L4S
################################################################################
# Este arquivo define 5 Máquinas Virtuais (VMs) para simular a topologia de rede:
# 1. client-l4s: Cliente legítimo usando TCP Prague (L4S).
# 2. classic-client: Cliente legado usando TCP Cubic/Reno.
# 3. malicious-client: Atacante gerando tráfego UDP não-responsivo.
# 4. router: Roteador central com AQM DualPI2 e gargalo de 100Mbps.
# 5. server-l4s: Servidor de destino para os fluxos.
# 6. classic-server: Servidor de destino para fluxos clássicos.
################################################################################

Vagrant.configure("2") do |config|
  # VM Cliente  (L4S)
  config.vm.define "client-l4s" do |client|
    client.vm.box = "ubuntu/focal64"
    client.vm.hostname = "client-l4s"
    client.vm.network "private_network",
      type: "static",
      ip: "192.168.56.10",
      virtualbox__intnet: "rede_client_router"
    client.vm.provider "virtualbox" do |vb|
      vb.name = "client-l4s"
    end

    # Provisionamento Ansible (configurações iniciais)
    client.vm.provision "shell", inline: <<-SHELL
      sudo apt-get update
      sudo apt-get install -y ansible iperf3 
    SHELL

    
    client.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "playbooks/client-l4s.yml"
    end
    # Provisionamento Shell
    client.vm.provision "shell", inline: <<-SHELL
      # Rota para alcançar a rede dos servidores (192.168.57.x) via Router
      sudo ip route add 192.168.57.0/24 via 192.168.56.2 || true
      
      sudo sysctl -w net.ipv4.tcp_ecn=3
      sudo sysctl -w net.ipv4.tcp_congestion_control=prague
      sudo ethtool -K enp0s8 tso off gso off gro off
      sudo tc qdisc replace dev enp0s8 root handle 1: fq limit 20480 flow_limit 10240
    SHELL
  end
  # VM Classic Client (Subnet 192.168.55.0/24)
  config.vm.define "classic-client" do |classic_client|
    classic_client.vm.box = "ubuntu/focal64"
    classic_client.vm.hostname = "classic-client"
    classic_client.vm.network "private_network",
      type: "static",
      ip: "192.168.55.10",
      virtualbox__intnet: "rede_classic_client_router"
    classic_client.vm.provider "virtualbox" do |vb|
      vb.name = "classic-client" 
    end
    classic_client.vm.provision "shell", inline: <<-SHELL
      # Rota para alcançar a rede dos servidores (192.168.57.x) via Router
      sudo ip route add 192.168.57.0/24 via 192.168.55.2 || true
      
      sudo ip link set enp0s8 up
      sudo sysctl -w net.ipv4.tcp_ecn=0
    SHELL
  end

  # VM Malicious Client (Nova subnet 192.168.54.0/24)
  config.vm.define "malicious-client" do |malicious_client|
    malicious_client.vm.box = "ubuntu/focal64"
    malicious_client.vm.hostname = "malicious-client"
    malicious_client.vm.network "private_network",
      type: "static",
      ip: "192.168.54.10",
      virtualbox__intnet: "rede_malicious_client_router"
    malicious_client.vm.provider "virtualbox" do |vb|
      vb.name = "malicious-client" 
    end

    malicious_client.vm.provision "shell", inline: <<-SHELL
      # Rota para alcançar a rede dos servidores (192.168.57.x) via Router
      sudo ip route add 192.168.57.0/24 via 192.168.54.2 || true
      
      sudo ip link set enp0s8 up
      sudo sysctl -w net.ipv4.tcp_ecn=0
    SHELL
  end

  # VM Roteador (Central de Rotas)
  config.vm.define "router" do |router|
    router.vm.box = "ubuntu/focal64"
    router.vm.hostname = "router"
    # --- Configurações de Hardware ---
    router.vm.provider "virtualbox" do |vb|
      vb.memory = 2096   # Aloca 2 GB de RAM 
      vb.cpus = 1        # Aloca 1 núcleo de CPU
      vb.name = "router" 
    end
    # Interface enp0s8 (Malicious-Client)
    router.vm.network "private_network",
      type: "static",
      ip: "192.168.54.2",
      virtualbox__intnet: "rede_malicious_client_router"

    # Interface enp0s9 (Classic-Client)
    router.vm.network "private_network",
      type: "static",
      ip: "192.168.55.2",
      virtualbox__intnet: "rede_classic_client_router"

    # Interface enp0s10 (Client L4S)
    router.vm.network "private_network",
      type: "static",
      ip: "192.168.56.2",
      virtualbox__intnet: "rede_client_router"

    # Interface enp0s16 (Servidores)
    router.vm.network "private_network",
      type: "static",
      ip: "192.168.57.2",
      virtualbox__intnet: "rede_router_server"

    # Provisionamento Ansible
    router.vm.provision "shell", inline: <<-SHELL
      sudo apt-get update
      
      # Evita que o Wireshark pergunte configurações interativas
      echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
      
      # Instalação com modo não-interativo forçado
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ansible iperf3 python3-pip tshark
      
      # Corrige compatibilidade de versões (Python 3.8 em Ubuntu Focal)
      sudo -H pip3 install --upgrade pip
      sudo -H pip3 install \
        numpy==1.24.4 \
        pandas==1.5.3 \
        scikit-learn==1.2.2 \
        psutil==5.9.8 \
        joblib==1.3.2
    SHELL

    
    router.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "playbooks/router.yml"
    end
      # Provisionamento Shell (configurações iniciais)
    router.vm.provision "shell", inline: <<-SHELL
      # Habilita roteamento
      echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
      sudo sysctl -w net.ipv4.ip_forward=1

      # Configurações de QoS para cada interface
      sudo tc qdisc replace dev enp0s8 root dualpi2 
      sudo tc qdisc replace dev enp0s9 root dualpi2 
      sudo tc qdisc replace dev enp0s10 root dualpi2 

      # Interface enp0s16 (Servidores - 100Mbit)
      sudo tc qdisc replace dev enp0s16 root handle 1: htb default 10
      sudo tc class add dev enp0s16 parent 1: classid 1:10 htb rate 100Mbit ceil 100Mbit burst 1516
      sudo tc qdisc add dev enp0s16 parent 1:10 dualpi2 
    SHELL

  end

  # VM Servidor (L4S)
  config.vm.define "server-l4s" do |server|
    server.vm.box = "ubuntu/focal64"
    server.vm.hostname = "server-l4s"
    server.vm.network "private_network",
      type: "static",
      ip: "192.168.57.10",
      virtualbox__intnet: "rede_router_server"
    server.vm.provider "virtualbox" do |vb|
      vb.name = "servidor-l4s" 
    end
    # Provisionamento Ansible
    server.vm.provision "shell", inline: <<-SHELL
      sudo apt-get update
      sudo apt-get install -y ansible iperf3
    SHELL

    
    server.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "playbooks/server-l4s.yml"
    end

    server.vm.provision "shell", inline: <<-SHELL
      # Rotas de retorno para os clientes
      sudo ip route add 192.168.56.0/24 via 192.168.57.2 || true # Client L4S
      sudo ip route add 192.168.54.0/24 via 192.168.57.2 || true # Malicious Client
      
      sudo ip link set enp0s8 up
      sudo sysctl -w net.ipv4.tcp_ecn=3
      sudo sysctl -w net.ipv4.tcp_congestion_control=prague
      sudo ethtool -K enp0s8 tso off gso off gro off
      sudo tc qdisc replace dev enp0s8 root handle 1: fq limit 20480 flow_limit 10240

      # Inicia servidores iperf3 em background para receber tráfego
      # Porta 5201: Tráfego Legítimo
      # Porta 5202: Tráfego Malicioso (TCP)
      nohup iperf3 -s -p 5201 > /dev/null 2>&1 &
      nohup iperf3 -s -p 5202 > /dev/null 2>&1 &
    SHELL
  end

  # VM Classic Server
  config.vm.define "classic-server" do |classic_server|
    classic_server.vm.box = "ubuntu/focal64"
    classic_server.vm.hostname = "classic-server"
    classic_server.vm.network "private_network",
      type: "static",
      ip: "192.168.57.20",
      virtualbox__intnet: "rede_router_server"
    classic_server.vm.provider "virtualbox" do |vb|
      vb.name = "classic-server"
    end 

    # Instalação básica
    classic_server.vm.provision "shell", inline: <<-SHELL
      sudo apt-get update
      sudo apt-get install -y ansible iperf3
      # Rota de retorno para o cliente clássico
      sudo ip route add 192.168.55.0/24 via 192.168.57.2 || true
      
      sudo ip link set enp0s8 up
    SHELL

    # Provisionamento Ansible para service iperf3
    classic_server.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "playbooks/classic-server.yml"
    end
  end
end

