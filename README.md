# PACKET_ANALYZER

# Analisador de Redes e Pacotes (network_analyzer.py)

Analisador de pacotes de rede em tempo real, rodando no terminal, no estilo do Wireshark — porém simples, leve e sem interface gráfica. Escrito em Python com [Scapy](https://scapy.net/).

## Funcionalidades

- Captura pacotes ao vivo em qualquer interface de rede
- Reconhece e destaca com cores os protocolos: **ARP, TCP, UDP, ICMP, DNS, HTTP, IPv6**
- Identifica serviços comuns por porta (HTTP, HTTPS, SSH, FTP, DNS, RDP, MySQL, SMB etc.)
- Mostra flags do TCP de forma legível (SYN, ACK, FIN, RST...)
- Extrai consultas e respostas DNS (nome consultado e IP retornado)
- Opção de exibir uma prévia do payload em ASCII
- Estatísticas ao final da captura: total de pacotes, contagem por protocolo e top 5 IPs de origem
- Exportação da captura para arquivo `.pcap` (compatível com Wireshark)
- Listagem das interfaces de rede disponíveis

## Requisitos

- Python 3.7+
- [Scapy](https://scapy.net/)
- Permissões de administrador/root (captura de pacotes exige acesso privilegiado)
- No Windows: [Npcap](https://npcap.com/) instalado
- No Linux/macOS: `libpcap` (geralmente já presente no sistema)

### Instalação

```bash
pip install scapy
```

## Uso

```bash
# Captura básica na interface padrão (Ctrl+C para parar e ver o resumo)
sudo python3 network_analyzer.py

# Listar interfaces disponíveis
python3 network_analyzer.py --list-interfaces

# Capturar em uma interface específica
sudo python3 network_analyzer.py -i eth0

# Aplicar um filtro BPF (sintaxe do tcpdump)
sudo python3 network_analyzer.py -f "tcp port 80"
sudo python3 network_analyzer.py -f "arp"
sudo python3 network_analyzer.py -f "icmp"

# Capturar um número limitado de pacotes
sudo python3 network_analyzer.py -c 100

# Salvar a captura em um arquivo .pcap
sudo python3 network_analyzer.py -o captura.pcap

# Mostrar prévia do payload (dados) em ASCII
sudo python3 network_analyzer.py -p

# Desativar cores no terminal (útil ao redirecionar a saída para um arquivo)
python3 network_analyzer.py --sem-cor
```

> No Windows, execute o terminal como Administrador em vez de usar `sudo`.

### Opções (`-h` / `--help`)

| Opção | Descrição |
|---|---|
| `-i`, `--interface` | Interface de rede a usar (padrão: interface padrão do sistema) |
| `-f`, `--filter` | Filtro BPF, ex: `"tcp port 80"`, `"arp"`, `"icmp"` |
| `-c`, `--count` | Número de pacotes a capturar (0 = infinito, até Ctrl+C) |
| `-o`, `--output` | Salva os pacotes capturados em um arquivo `.pcap` |
| `-p`, `--payload` | Mostra uma prévia do payload (dados) em ASCII |
| `--sem-cor` | Desativa cores no terminal |
| `--list-interfaces` | Lista as interfaces de rede disponíveis e sai |

## Exemplo de saída

```
Analisador de Redes e Pacotes
Interface: eth0
Filtro BPF: (nenhum, captura tudo)
Pressione Ctrl+C para parar e ver o resumo.

[14:32:10.123] TCP    (   66B)  192.168.0.10:54321 -> 142.250.0.1:443(HTTPS) [SYN] seq=123456 win=64240
[14:32:10.145] DNS    (   78B)  DNS consulta: example.com. -> 93.184.216.34
[14:32:10.200] ARP    (   42B)  ARP resposta: 192.168.0.1 está em aa:bb:cc:dd:ee:ff
^C
============================================================
RESUMO DA CAPTURA
============================================================
Duração: 5.3s   |   Total de pacotes: 3

Por protocolo:
  TCP      1
  DNS      1
  ARP      1

Top 5 IPs de origem:
  192.168.0.10         1 pacote(s)
  93.184.216.34        1 pacote(s)
  192.168.0.1          1 pacote(s)
============================================================
```

## Estrutura do código

- `Cor` — códigos ANSI para colorir a saída no terminal (pode ser desativada com `--sem-cor`)
- `EstatisticasCaptura` — acumula contagens por protocolo e por IP de origem, e gera o resumo final
- `formatar_flags_tcp()` — converte as flags TCP (`S`, `A`, `F`...) em nomes legíveis
- `analisar_pacote()` — identifica o protocolo de cada pacote capturado e monta a linha de exibição
- `listar_interfaces()` — lista as interfaces de rede do sistema
- `main()` — parsing de argumentos, configuração do sniffer e tratamento de `Ctrl+C`

## Avisos

- Este script captura tráfego de rede real. Use apenas em redes e dispositivos sob sua responsabilidade ou autorização.
- Requer privilégios elevados (root/administrador) porque a captura de pacotes brutos (raw sockets) exige isso no sistema operacional.
