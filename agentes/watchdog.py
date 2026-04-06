from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from datetime import datetime

class Watchdog:
    def __init__(self):
        self.conexoes = []

    def processar_pacote(self, pkt):
        if pkt.haslayer(IP):
            origem = pkt[IP].src
            destino = pkt[IP].dst
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Outro"
            
            porta_orig = pkt.sport if hasattr(pkt, 'sport') else 0
            porta_dest = pkt.dport if hasattr(pkt, 'dport') else 0

            info = {
                "Horário": datetime.now().strftime("%H:%M:%S"),
                "Origem": origem,
                "Porta Orig.": porta_orig,
                "Destino": destino,
                "Porta Dest.": porta_dest,
                "Protocolo": proto,
                "Tamanho": len(pkt)
            }
            self.conexoes.append(info)
            # Mantém apenas os últimos 50 pacotes na memória para não travar
            if len(self.conexoes) > 50:
                self.conexoes.pop(0)

    def capturar(self, interface=None, timeout=5):
        self.conexoes = []
        sniff(iface=interface, prn=self.processar_pacote, timeout=timeout, store=0)
        return self.conexoes