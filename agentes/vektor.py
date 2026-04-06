import requests
import os

class Vektor:
    def __init__(self, vt_key: str):
        self.vt_key = vt_key.strip() if vt_key else None
        self.nvd_key = os.getenv("NVD_API_KEY", "").strip()

    def consultar_virustotal(self, ip_ou_url: str) -> str:
        if not self.vt_key: return "VirusTotal: Chave ausente."
        alvo = ip_ou_url.strip()
        is_ip = all(c.isdigit() or c == '.' for c in alvo)
        endpoint = "ip_addresses" if is_ip else "urls"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{alvo}"
        headers = {"x-apikey": self.vt_key}
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                stats = res.json()['data']['attributes']['last_analysis_stats']
                return f"🔍 VirusTotal: {stats['malicious']} MALICIOSO | {stats['suspicious']} SUSPEITO"
            elif res.status_code == 404:
                return "ℹ️ VirusTotal: Alvo nunca analisado anteriormente."
            return f"Erro VT: {res.status_code}"
        except: return "Erro de conexão VirusTotal."

    def analisar_cve(self, cve_id: str) -> str:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
        headers = {"User-Agent": "CerebroV3/1.0"}
        if self.nvd_key: headers["apiKey"] = self.nvd_key
        try:
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                vulns = res.json().get('vulnerabilities', [])
                if not vulns: return "CVE não encontrada."
                cve = vulns[0]['cve']
                desc = cve['descriptions'][0]['value']
                return f"=== {cve_id} ===\n\n{desc}"
            return f"Erro NVD: {res.status_code}"
        except: return "Erro de conexão NVD."

    def _mapear_arsenal(self, porta: int, servico: str) -> dict:
        """Mapeia ferramentas e scripts com base na porta e nome do serviço."""
        arsenal = {
            "ferramentas": "Nmap Scripts, Metasploit Framework",
            "scripts": ["generic_recon.py"],
            "payloads": ["cmd/unix/reverse_python"]
        }
        mapping = {
            21:   {"f": "Hydra, FTP-Audit",         "s": ["ftp_brute.py", "ftp_anonymous_check.sh"],      "p": ["ftp/payload_upload"]},
            22:   {"f": "Hydra, SSH-Audit",           "s": ["ssh_enum_users.py", "ssh_bruteforce.rb"],       "p": ["linux/x64/shell_reverse_tcp"]},
            80:   {"f": "Sqlmap, Nikto, Dirb",        "s": ["web_crawler.py", "rce_scanner.py"],             "p": ["php/meterpreter/reverse_tcp"]},
            443:  {"f": "Sslscan, Burp Suite",        "s": ["ssl_vulnerability_test.py"],                    "p": ["windows/x64/meterpreter/reverse_https"]},
            445:  {"f": "Metasploit, Enum4Linux",     "s": ["smb_exploit_ms17_010.py", "eternalblue.rb"],    "p": ["windows/x64/shell/reverse_tcp"]},
            3306: {"f": "Sqlmap, Hydra",              "s": ["mysql_audit.py", "sql_injection_test.sh"],      "p": ["linux/x86/mysql_payload"]},
            3389: {"f": "RDP-Scan, BlueKeep-Check",   "s": ["rdp_exploit_cve_2019_0708.py"],                 "p": ["windows/rdp/meterpreter"]}
        }
        if porta in mapping:
            arsenal["ferramentas"] = mapping[porta]["f"]
            arsenal["scripts"]     = mapping[porta]["s"]
            arsenal["payloads"]    = mapping[porta]["p"]
        return arsenal

    def buscar_exploits_locais(self, dados_orion: dict) -> str:
        if not dados_orion or "erro" in dados_orion:
            return "❌ Realize um scan no Orion primeiro."

        relatorio = ["=== ANÁLISE DE EXPLOITS & ARSENAL DE ATAQUE (VEKTOR v3.8) ==="]

        for ip, host_info in dados_orion.items():
            relatorio.append(f"\n🎯 ALVO: {ip}")
            relatorio.append(f"    OS: {host_info.get('os', 'N/A')} | MAC: {host_info.get('mac', 'N/A')}")
            relatorio.append("=" * 40)

            servicos = host_info.get('servicos', [])
            if not servicos:
                relatorio.append("    Nenhuma porta aberta detectada.")
                continue

            for s in servicos:
                porta   = s.get('porta', 0)
                servico = s.get('servico', 'unknown')
                versao  = s.get('versao', '')

                label = f"{servico} {versao}".strip()
                relatorio.append(f"\n[*] Porta {porta}/{s.get('protocolo','tcp')}: {label}")

                arsenal = self._mapear_arsenal(porta, servico)
                relatorio.append(f"    > Ferramentas: {arsenal['ferramentas']}")

                relatorio.append("    > Scripts/Exploits sugeridos:")
                for script in arsenal['scripts']:
                    relatorio.append(f"      - [FILE] {script}")

                relatorio.append("    > Payloads recomendados:")
                for payload in arsenal['payloads']:
                    relatorio.append(f"      - [PAYLOAD] {payload}")

                if servico:
                    relatorio.append(f"    [!] Pesquisa Global: 'exploit {label}'")

                if s.get('vulnerabilidades'):
                    relatorio.append("    ⚠️ Vulnerabilidades Confirmadas pelo Nmap:")
                    for v_id in s['vulnerabilidades'].keys():
                        relatorio.append(f"      - Correlacionar: exploit/windows/smb/{v_id.replace('-', '_')}")

            relatorio.append("-" * 40)

        return "\n".join(relatorio)