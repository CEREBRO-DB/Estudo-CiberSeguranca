import nmap
import os
import socket
import requests
import threading


PERFIS_SCAN = {
    "Normal (Rápido)":              "-sS -sV --open -T4",
    "Médio (Vulnerabilidades)":     "-sS -sV -O --open -T3 --script=vuln",
    "Máximo (Agressivo ao Extremo)":"-sS -sV -O --open -T5 --script=vuln,exploit,auth",
}


class Orion:
    def __init__(self, shodan_key: str, abuse_key: str):
        self.shodan_key = shodan_key.strip() if shodan_key else None
        self.abuse_key = abuse_key.strip() if abuse_key else None
        self.nm = None
        self._resultado = None
        self._erro = None
        self._concluido = False

    def obter_rede_automatica(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
            s.close()
            return ".".join(ip.split('.')[:-1]) + ".0/24"
        except:
            return "192.168.1.0/24"

    def get_geo_info(self, ip: str) -> dict:
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
            if res.get('status') == 'success':
                return {"local": f"{res.get('city')}, {res.get('country')}", "isp": res.get('isp')}
            return {"local": "Rede Local", "isp": "N/A"}
        except:
            return {"local": "Privado", "isp": "N/A"}

    def _inicializar_nmap(self):
        paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap"
        ]
        exe = next((p for p in paths if os.path.exists(p)), None)
        try:
            self.nm = nmap.PortScanner(nmap_search_path=(exe,) if exe else None)
            return True
        except Exception:
            return False

    def _executar_scan_thread(self, faixa_ip: str, args: str):
        """Executa o scan em background thread."""
        try:
            self.nm.scan(hosts=faixa_ip, arguments=args)

            if not self.nm.all_hosts():
                self._erro = "Nenhum host encontrado ou acesso negado (Tente rodar como Administrador)."
                return

            resultados = {}

            for host in self.nm.all_hosts():
                servicos = []
                addresses = self.nm[host].get('addresses', {})
                mac = addresses.get('mac', 'Desconhecido')
                osmatch = self.nm[host].get('osmatch', [])
                os_nome = osmatch[0].get('name', 'Desconhecido') if osmatch else 'Desconhecido'

                for proto in self.nm[host].all_protocols():
                    for porta in self.nm[host][proto].keys():
                        info_porta = self.nm[host][proto][porta]
                        servicos.append({
                            "porta": porta,
                            "protocolo": proto,
                            "estado": info_porta.get('state', 'unknown'),
                            "servico": info_porta.get('name', 'unknown'),
                            "versao": info_porta.get('version', ''),
                        })

                geo = self.get_geo_info(host)

                resultados[host] = {
                    "mac": mac,
                    "os": os_nome,
                    "servicos": servicos,
                    "local": geo.get("local", "N/A"),
                    "isp": geo.get("isp", "N/A"),
                    "hostname": self.nm[host].hostname() or "N/A",
                    "estado": self.nm[host].state(),
                }

            self._resultado = resultados

        except Exception as e:
            self._erro = str(e)
        finally:
            self._concluido = True

    def iniciar_scan(self, faixa_ip: str = None, args: str = "-sS -sV --open -T4") -> threading.Thread | None:
        """Inicia o scan e retorna a thread para monitoramento externo."""
        if not self._inicializar_nmap():
            self._erro = "Nmap não encontrado. Instale o Nmap e tente novamente."
            self._concluido = True
            return None

        if not faixa_ip:
            faixa_ip = self.obter_rede_automatica()

        self._resultado = None
        self._erro = None
        self._concluido = False

        t = threading.Thread(
            target=self._executar_scan_thread,
            args=(faixa_ip, args),
            daemon=True
        )
        t.start()
        return t

    def scan_rede_local_stealth(self, faixa_ip: str = None, intensidade: str = "Normal (Rápido)") -> threading.Thread | None:
        """Scan stealth — mapeia perfil de intensidade para flags nmap e retorna a thread."""
        args = PERFIS_SCAN.get(intensidade, PERFIS_SCAN["Normal (Rápido)"])
        return self.iniciar_scan(faixa_ip=faixa_ip, args=args)

    def esta_concluido(self) -> bool:
        return self._concluido

    def obter_resultado(self) -> dict | None:
        return self._resultado

    def obter_erro(self) -> str | None:
        return self._erro