import requests
import json
import os
import socket
from datetime import datetime

# Mapa de inteligência por porta/serviço
INTEL_MAP = {
    21:  {
        "scripts": ["ftp-anon", "ftp-brute", "ftp-vuln-cve2010-4221"],
        "exploits": {"ftp_generic": {"script": "ftp_anon_access.py", "tool": "Hydra/Metasploit"}},
        "remediacoes": ["Desativar FTP e migrar para SFTP.", "Bloquear porta 21 no firewall.", "Desabilitar acesso anônimo."]
    },
    22:  {
        "scripts": ["ssh-brute", "ssh-auth-methods", "ssh2-enum-algos"],
        "exploits": {"ssh_brute": {"script": "ssh_bruteforce.py", "tool": "Hydra"}},
        "remediacoes": ["Trocar porta 22 por porta alta.", "Desativar login root via SSH.", "Usar autenticação por chave RSA."]
    },
    23:  {
        "scripts": ["telnet-brute", "telnet-ntlm-info"],
        "exploits": {"telnet_generic": {"script": "telnet_brute.py", "tool": "Hydra"}},
        "remediacoes": ["Desativar Telnet imediatamente.", "Substituir por SSH.", "Bloquear porta 23 no firewall."]
    },
    80:  {
        "scripts": ["http-vuln-cve2021-41773", "http-sql-injection", "http-csrf", "http-shellshock"],
        "exploits": {"http_generic": {"script": "web_scanner.py", "tool": "Nikto/Sqlmap"}},
        "remediacoes": ["Redirecionar tráfego para HTTPS.", "Instalar WAF (ModSecurity).", "Ocultar versão do servidor."]
    },
    135: {
        "scripts": ["msrpc-enum"],
        "exploits": {"msrpc_enum": {"script": "msrpc_enum.py", "tool": "Metasploit"}},
        "remediacoes": ["Bloquear porta 135 no firewall perimetral.", "Restringir acesso RPC à rede interna.", "Monitorar chamadas RPC suspeitas."]
    },
    139: {
        "scripts": ["smb-vuln-ms17-010", "smb-enum-shares", "smb-brute"],
        "exploits": {"netbios_smb": {"script": "eternalblue.py", "tool": "Metasploit"}},
        "remediacoes": ["Desativar NetBIOS sobre TCP/IP.", "Bloquear porta 139 externamente.", "Habilitar SMB Signing."]
    },
    443: {
        "scripts": ["ssl-poodle", "ssl-heartbleed", "ssl-ccs-injection", "tls-alpn"],
        "exploits": {"ssl_weak": {"script": "ssl_audit.py", "tool": "Sslscan/Burp Suite"}},
        "remediacoes": ["Verificar expiração do certificado SSL.", "Desativar cifras fracas (RC4, DES).", "Ativar HSTS.", "Usar TLS 1.3."]
    },
    445: {
        "scripts": ["smb-vuln-ms17-010", "smb-vuln-cve2020-0796", "smb-enum-shares", "smb-brute"],
        "exploits": {"eternalblue": {"script": "smb_exploit_ms17_010.py", "tool": "Metasploit (EternalBlue)"}},
        "remediacoes": ["Desativar SMBv1 via registro do Windows.", "Bloquear porta 445 no firewall perimetral.", "Habilitar SMB Signing.", "Aplicar patch KB4013389."]
    },
    3306: {
        "scripts": ["mysql-brute", "mysql-empty-password", "mysql-vuln-cve2012-2122"],
        "exploits": {"mysql_brute": {"script": "mysql_audit.py", "tool": "Sqlmap/Hydra"}},
        "remediacoes": ["Restringir MySQL ao IP da aplicação.", "Desativar acesso root remoto.", "Habilitar criptografia de dados em repouso."]
    },
    3389: {
        "scripts": ["rdp-vuln-ms12-020", "rdp-enum-encryption", "rdp-brute"],
        "exploits": {"bluekeep": {"script": "rdp_exploit_cve_2019_0708.py", "tool": "Metasploit (BlueKeep)"}},
        "remediacoes": ["Habilitar autenticação NLA.", "Bloquear porta 3389 externamente.", "Aplicar patches de segurança RDP."]
    },
    5357: {
        "scripts": ["http-vuln-cve2024", "http-methods", "http-wdav-guillotine"],
        "exploits": {"wsdapi": {"script": "wsdapi_scan.py", "tool": "Nmap NSE / Metasploit"}},
        "remediacoes": ["Bloquear porta 5357 no firewall.", "Desativar WSD (Web Services on Devices) se não necessário.", "Restringir acesso à rede local."]
    },
    8080: {
        "scripts": ["http-vuln-cve2021-41773", "http-open-proxy", "http-brute"],
        "exploits": {"http_proxy": {"script": "proxy_scan.py", "tool": "Burp Suite"}},
        "remediacoes": ["Autenticar acesso ao proxy.", "Desativar listagem de diretórios.", "Atualizar servidor web."]
    },
}

class BrainSync:
    def __init__(self):
        self.db_path = "data/intelligence_core.json"
        self.last_update = None

        self.github_token = os.getenv("GITHUB_TOKEN")
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")

        if not os.path.exists("data"):
            os.makedirs("data")

        if not os.path.exists(self.db_path):
            self._gerar_db_vazio()

    def _gerar_db_vazio(self):
        init_data = {
            "ultima_sincronizacao": "Nenhuma",
            "nmap_scripts": [],
            "exploits": {},
            "remediacoes": {},
            "scan_correlacionado": False
        }
        with open(self.db_path, "w") as f:
            json.dump(init_data, f, indent=4)

    def sincronizar_tudo(self, orion, vektor, aegis):
        """Sincronização global padrão (sem scan)."""
        log_atualizacao = []
        try:
            novos_dados = self._fetch_global_threats()

            if orion:
                orion.scripts_adicionais = novos_dados.get("nmap_scripts", [])
                log_atualizacao.append(f"🛰️ Orion: {len(novos_dados['nmap_scripts'])} scripts vinculados.")
            if vektor:
                if not hasattr(vektor, 'mapping_expansao'):
                    vektor.mapping_expansao = {}
                vektor.mapping_expansao.update(novos_dados.get("exploits", {}))
                log_atualizacao.append(f"💣 Vektor: {len(novos_dados['exploits'])} payloads mapeados.")
            if aegis:
                if not hasattr(aegis, 'database_remediacao'):
                    aegis.database_remediacao = {}
                aegis.database_remediacao.update(novos_dados.get("remediacoes", {}))
                log_atualizacao.append("🛡️ Aegis: Protocolos de Defesa Sincronizados.")

            self.last_update = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            with open(self.db_path, "w") as f:
                json.dump({"ultima_sincronizacao": self.last_update, "scan_correlacionado": False, **novos_dados}, f, indent=4)

            return log_atualizacao
        except Exception as e:
            return [f"❌ Erro Crítico na Sincronização: {str(e)}"]

    def sincronizar_com_scan(self, dados_scan: dict):
        """Gera inteligência relevante baseada no resultado real do scan."""
        scripts_relevantes = set()
        exploits_relevantes = {}
        remediacoes_relevantes = {}

        for ip, host_info in dados_scan.items():
            for servico in host_info.get("servicos", []):
                porta = servico.get("porta")
                if porta in INTEL_MAP:
                    intel = INTEL_MAP[porta]
                    scripts_relevantes.update(intel["scripts"])
                    exploits_relevantes.update(intel["exploits"])
                    remediacoes_relevantes[str(porta)] = intel["remediacoes"]

        resultado = {
            "ultima_sincronizacao": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "scan_correlacionado": True,
            "nmap_scripts": list(scripts_relevantes),
            "exploits": exploits_relevantes,
            "remediacoes": remediacoes_relevantes
        }

        with open(self.db_path, "w") as f:
            json.dump(resultado, f, indent=4)

        return resultado

    # --- INTELIGÊNCIA EXTERNA (OSINT) ---

    def rastrear_ip_externo(self, ip):
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            if res.get('status') == 'success':
                return {
                    "local": f"{res.get('city')}, {res.get('country')}",
                    "isp": res.get('isp'),
                    "lat_lon": f"{res.get('lat')}, {res.get('lon')}",
                    "as": res.get('as'),
                    "organizacao": res.get('org')
                }
            return None
        except Exception:
            return None

    def verificar_reputacao(self, ip):
        if not self.abuse_key:
            return {"erro": "ABUSEIPDB_API_KEY ausente"}
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        try:
            res = requests.get(url, headers=headers, params=params, timeout=5).json()
            data = res.get('data', {})
            return {
                "score_abuso": data.get('abuseConfidenceScore', 0),
                "total_reportes": data.get('totalReports', 0),
                "tipo_uso": data.get('usageType', 'Desconhecido'),
                "dominio": data.get('domain')
            }
        except Exception:
            return None

    def analisar_ameaca_rede(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,mobile"
            res = requests.get(url, timeout=5).json()
            if res.get('status') == 'success':
                return {
                    "e_proxy_vpn": "Sim" if res.get('proxy') else "Não",
                    "e_data_center": "Sim" if res.get('hosting') else "Não",
                    "e_movel": "Sim" if res.get('mobile') else "Não"
                }
            return None
        except Exception:
            return None

    def consultar_shodan(self, ip):
        dados = {"portas": [], "vulnerabilidades": [], "os": "Não identificado", "hostnames": []}
        if self.shodan_key:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
                res = requests.get(url, timeout=5).json()
                if 'ports' in res:
                    dados["portas"] = res.get('ports', [])
                    dados["vulnerabilidades"] = res.get('vulns', [])
                    dados["os"] = res.get('os', 'Não identificado')
                    dados["hostnames"] = res.get('hostnames', [])
                    return dados
            except Exception:
                pass
        portas_ativas = self.scan_ativo_emergencia(ip)
        if portas_ativas:
            dados["portas"] = portas_ativas
            dados["os"] = "Detectado via Direct Socket"
        return dados

    def scan_ativo_emergencia(self, ip):
        portas_comuns = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080, 8443]
        abertas = []
        for porta in portas_comuns:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    if s.connect_ex((ip, porta)) == 0:
                        abertas.append(porta)
            except:
                continue
        return abertas

    def carregar_inteligencia_local(self):
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, "r") as f:
                    return json.load(f)
            return {"erro": "DB não encontrado."}
        except Exception as e:
            return {"erro": str(e)}

    def _fetch_global_threats(self):
        return {
            "nmap_scripts": ["http-vuln-cve2024", "smb-vuln-ms17-010"],
            "exploits": {
                "apache_2.4.50": {"script": "cve_2021_41773.py", "tool": "Metasploit"}
            },
            "remediacoes": {
                "80": ["Configurar WAF", "Ocultar versão do servidor"],
                "443": ["Usar TLS 1.3", "Habilitar HSTS"],
                "http-csrf": ["Implementar Tokens Anti-CSRF"]
            }
        }