import argparse
import sys
import signal
import threading
from collections import Counter
from datetime import datetime

try:
    import msvcrt  
    _PLATAFORMA_WINDOWS = True
except ImportError:
    import termios
    import tty
    import select
    _PLATAFORMA_WINDOWS = False

try:
    from scapy.all import (
        sniff, wrpcap, get_if_list, conf,
        Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
    )
except ImportError:
    print("[ERRO] O pacote 'scapy' não está instalado.")
    print("Instale com: pip install scapy")
    sys.exit(1)

class Cor:
    RESET = "\033[0m"
    CINZA = "\033[90m"
    VERDE = "\033[92m"
    AMARELO = "\033[93m"
    AZUL = "\033[94m"
    MAGENTA = "\033[95m"
    CIANO = "\033[96m"
    VERMELHO = "\033[91m"
    NEGRITO = "\033[1m"

    @staticmethod
    def desativar():
        for attr in ["RESET", "CINZA", "VERDE", "AMARELO", "AZUL",
                     "MAGENTA", "CIANO", "VERMELHO", "NEGRITO"]:
            setattr(Cor, attr, "")


CORES_PROTOCOLO = {
    "ARP": Cor.MAGENTA,
    "TCP": Cor.AZUL,
    "UDP": Cor.CIANO,
    "ICMP": Cor.AMARELO,
    "DNS": Cor.VERDE,
    "HTTP": Cor.VERDE,
    "IPv6": Cor.CINZA,
    "OUTRO": Cor.CINZA,
}

PORTAS_CONHECIDAS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP-ALT",
}


class EstatisticasCaptura:

    def __init__(self):
        self.total = 0
        self.por_protocolo = Counter()
        self.por_ip_origem = Counter()
        self.inicio = datetime.now()

    def registrar(self, protocolo, ip_origem=None):
        self.total += 1
        self.por_protocolo[protocolo] += 1
        if ip_origem:
            self.por_ip_origem[ip_origem] += 1

    def resumo(self):
        duracao = (datetime.now() - self.inicio).total_seconds()
        linhas = []
        linhas.append(f"\n{Cor.NEGRITO}{'='*60}{Cor.RESET}")
        linhas.append(f"{Cor.NEGRITO}RESUMO DA CAPTURA{Cor.RESET}")
        linhas.append(f"{'='*60}")
        linhas.append(f"Duração: {duracao:.1f}s   |   Total de pacotes: {self.total}")
        linhas.append("\nPor protocolo:")
        for proto, qtd in self.por_protocolo.most_common():
            cor = CORES_PROTOCOLO.get(proto, Cor.RESET)
            linhas.append(f"  {cor}{proto:<8}{Cor.RESET} {qtd}")
        if self.por_ip_origem:
            linhas.append("\nTop 5 IPs de origem:")
            for ip, qtd in self.por_ip_origem.most_common(5):
                linhas.append(f"  {ip:<20} {qtd} pacote(s)")
        linhas.append(f"{'='*60}")
        return "\n".join(linhas)


def formatar_flags_tcp(flags):
    mapa = {
        "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
        "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
    }
    return ",".join(mapa.get(c, c) for c in str(flags))


def analisar_pacote(pacote, stats: EstatisticasCaptura, mostrar_payload: bool):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    protocolo = "OUTRO"
    ip_origem = None
    linha_principal = ""
    detalhes_extra = []

    if pacote.haslayer(ARP):
        protocolo = "ARP"
        arp = pacote[ARP]
        tipo = "quem-tem" if arp.op == 1 else "resposta"
        linha_principal = (
            f"ARP {tipo}: {arp.psrc} está em {arp.hwsrc}"
            if arp.op == 2 else
            f"ARP {tipo}: quem tem {arp.pdst}? avise {arp.psrc}"
        )
        ip_origem = arp.psrc

    elif pacote.haslayer(IP):
        ip = pacote[IP]
        ip_origem = ip.src
        proto_num = ip.proto

        if pacote.haslayer(TCP):
            protocolo = "TCP"
            tcp = pacote[TCP]
            servico_o = PORTAS_CONHECIDAS.get(tcp.sport, "")
            servico_d = PORTAS_CONHECIDAS.get(tcp.dport, "")

            if pacote.haslayer(Raw) and (tcp.sport == 80 or tcp.dport == 80):
                protocolo = "HTTP"

            flags = formatar_flags_tcp(tcp.flags)
            linha_principal = (
                f"{ip.src}:{tcp.sport}{f'({servico_o})' if servico_o else ''} -> "
                f"{ip.dst}:{tcp.dport}{f'({servico_d})' if servico_d else ''} "
                f"[{flags}] seq={tcp.seq} win={tcp.window}"
            )

        elif pacote.haslayer(UDP):
            protocolo = "UDP"
            udp = pacote[UDP]
            servico_o = PORTAS_CONHECIDAS.get(udp.sport, "")
            servico_d = PORTAS_CONHECIDAS.get(udp.dport, "")

            if pacote.haslayer(DNS):
                protocolo = "DNS"
                dns = pacote[DNS]
                qd = getattr(dns, "qd", None)
                primeira_pergunta = (qd[0] if (isinstance(qd, list) and qd) else
                                     (qd if not isinstance(qd, list) else None))
                if primeira_pergunta is not None:
                    nome = primeira_pergunta.qname.decode(errors="ignore")
                    tipo_consulta = "consulta" if dns.qr == 0 else "resposta"
                    linha_principal = f"DNS {tipo_consulta}: {nome}"
                    an = getattr(dns, "an", None)
                    primeira_resposta = (an[0] if (isinstance(an, list) and an) else
                                         (an if not isinstance(an, list) else None))
                    if primeira_resposta is not None:
                        try:
                            linha_principal += f" -> {primeira_resposta.rdata}"
                        except Exception:
                            pass
                else:
                    linha_principal = f"DNS: {ip.src} -> {ip.dst}"
            else:
                linha_principal = (
                    f"{ip.src}:{udp.sport}{f'({servico_o})' if servico_o else ''} -> "
                    f"{ip.dst}:{udp.dport}{f'({servico_d})' if servico_d else ''}"
                )

        elif pacote.haslayer(ICMP):
            protocolo = "ICMP"
            icmp = pacote[ICMP]
            tipos_icmp = {0: "echo-reply (pong)", 8: "echo-request (ping)",
                          3: "destino inalcançável", 11: "TTL excedido"}
            descricao = tipos_icmp.get(icmp.type, f"tipo={icmp.type}")
            linha_principal = f"{ip.src} -> {ip.dst}  ICMP {descricao}"

        else:
            linha_principal = f"{ip.src} -> {ip.dst}  IP proto={proto_num}"

    elif pacote.haslayer(IPv6):
        protocolo = "IPv6"
        ip6 = pacote[IPv6]
        ip_origem = ip6.src
        linha_principal = f"{ip6.src} -> {ip6.dst}  (IPv6, next-header={ip6.nh})"

    else:
        linha_principal = pacote.summary()

    tamanho = len(pacote)

    if mostrar_payload and pacote.haslayer(Raw):
        cru = bytes(pacote[Raw].load)[:64]
        texto = "".join(chr(b) if 32 <= b < 127 else "." for b in cru)
        detalhes_extra.append(f"    payload: {texto}")

    stats.registrar(protocolo, ip_origem)

    cor = CORES_PROTOCOLO.get(protocolo, Cor.RESET)
    print(f"{Cor.CINZA}[{timestamp}]{Cor.RESET} "
          f"{cor}{protocolo:<6}{Cor.RESET} "
          f"({tamanho:>5}B)  {linha_principal}")
    for linha in detalhes_extra:
        print(f"{Cor.CINZA}{linha}{Cor.RESET}")


def escutar_tecla_q(evento_parar: threading.Event):
    try:
        if _PLATAFORMA_WINDOWS:
            while not evento_parar.is_set():
                if msvcrt.kbhit():
                    tecla = msvcrt.getch().decode(errors="ignore").lower()
                    if tecla == "q":
                        evento_parar.set()
                        break
                evento_parar.wait(0.1)
        else:
            fd = sys.stdin.fileno()
            config_original = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                while not evento_parar.is_set():
                    pronto, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if pronto:
                        tecla = sys.stdin.read(1).lower()
                        if tecla == "q":
                            evento_parar.set()
                            break
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, config_original)
    except Exception:
        pass


def montar_menu():
    print(f"{Cor.NEGRITO}{'='*60}{Cor.RESET}")
    print(f"{Cor.NEGRITO}Analisador de Redes e Pacotes — Menu{Cor.RESET}")
    print(f"{'='*60}")
    print("1) Iniciar captura (interface padrão, sem filtro)")
    print("2) Iniciar captura em uma interface específica")
    print("3) Iniciar captura com filtro BPF (ex: tcp port 80, arp, icmp)")
    print("4) Listar interfaces de rede disponíveis")
    print("5) Sair")
    print(f"{'='*60}")

    while True:
        escolha = input("Escolha uma opção [1-5]: ").strip()

        if escolha == "1":
            return {"interface": None, "filter": None}

        if escolha == "2":
            listar_interfaces()
            iface = input("Digite o nome da interface: ").strip()
            return {"interface": iface or None, "filter": None}

        if escolha == "3":
            filtro = input('Digite o filtro BPF (ex: "tcp port 80"): ').strip()
            return {"interface": None, "filter": filtro or None}

        if escolha == "4":
            listar_interfaces()
            continue

        if escolha == "5":
            print("Saindo...")
            sys.exit(0)

        print(f"{Cor.VERMELHO}Opção inválida.{Cor.RESET} Escolha um número de 1 a 5.")


def listar_interfaces():
    print("Interfaces de rede disponíveis:")
    for nome in get_if_list():
        print(f"  - {nome}")


def main():
    parser = argparse.ArgumentParser(
        description="Analisador de redes e pacotes (ARP, TCP/IP, UDP, ICMP, DNS, HTTP).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default=None,
                         help="Interface de rede a usar (padrão: interface padrão do sistema)")
    parser.add_argument("-f", "--filter", default=None,
                         help='Filtro BPF, ex: "tcp port 80", "arp", "icmp"')
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Número de pacotes a capturar (0 = infinito, até Ctrl+C)")
    parser.add_argument("-o", "--output", default=None,
                         help="Salva os pacotes capturados num arquivo .pcap")
    parser.add_argument("-p", "--payload", action="store_true",
                         help="Mostra uma prévia do payload (dados) em ASCII")
    parser.add_argument("--sem-cor", action="store_true",
                         help="Desativa cores no terminal")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="Lista as interfaces de rede disponíveis e sai")
    parser.add_argument("--menu", action="store_true",
                         help="Abre o menu interativo mesmo passando outras opções")
    args = parser.parse_args()

    if args.sem_cor:
        Cor.desativar()

    if args.list_interfaces:
        listar_interfaces()
        return

    if args.menu or len(sys.argv) == 1:
        escolha = montar_menu()
        args.interface = escolha["interface"] or args.interface
        args.filter = escolha["filter"] or args.filter

    stats = EstatisticasCaptura()
    pacotes_capturados = []

    def callback(pacote):
        analisar_pacote(pacote, stats, args.payload)
        if args.output:
            pacotes_capturados.append(pacote)

    def encerrar(sig, frame):
        print(stats.resumo())
        if args.output and pacotes_capturados:
            wrpcap(args.output, pacotes_capturados)
            print(f"\n[+] {len(pacotes_capturados)} pacote(s) salvos em '{args.output}'")
        sys.exit(0)

    signal.signal(signal.SIGINT, encerrar)

    evento_parar = threading.Event()
    thread_tecla = threading.Thread(
        target=escutar_tecla_q, args=(evento_parar,), daemon=True
    )
    thread_tecla.start()

    iface = args.interface or conf.iface
    print(f"{Cor.NEGRITO}Analisador de Redes e Pacotes{Cor.RESET}")
    print(f"Interface: {iface}")
    print(f"Filtro BPF: {args.filter or '(nenhum, captura tudo)'}")
    print("Pressione Q ou Ctrl+C para parar e ver o resumo.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=callback,
            count=args.count if args.count > 0 else 0,
            store=False,
            stop_filter=lambda pacote: evento_parar.is_set(),
        )
    except PermissionError:
        print(f"{Cor.VERMELHO}[ERRO] Permissão negada.{Cor.RESET} "
              f"Rode este script como root/administrador (ex: sudo python3 network_analyzer.py)")
        sys.exit(1)
    except OSError as e:
        print(f"{Cor.VERMELHO}[ERRO] {e}{Cor.RESET}")
        print("Verifique se a interface existe (use --list-interfaces) "
              "e se o Npcap/libpcap está instalado.")
        sys.exit(1)

    evento_parar.set()
    print(stats.resumo())
    if args.output and pacotes_capturados:
        wrpcap(args.output, pacotes_capturados)
        print(f"\n[+] {len(pacotes_capturados)} pacote(s) salvos em '{args.output}'")


if __name__ == "__main__":
    main()
