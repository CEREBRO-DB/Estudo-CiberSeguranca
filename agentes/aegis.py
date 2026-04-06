import datetime

class Aegis:
    def __init__(self):
        self.database_remediacao = {}

    def gerar_guia_correcao(self, dados_scan: dict) -> str:
        if not dados_scan or "erro" in dados_scan:
            return "❌ Erro: Nenhum dado de scan disponível para o Aegis analisar."

        agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
        guia = [
            f"=== RELATÓRIO DE REMEDIAÇÃO TÉCNICA (AEGIS v1.0) ===",
            f"Gerado em: {agora}",
            "Prioridade: Alta (Baseado em Vulnerabilidades Ativas)",
            "=" * 55 + "\n"
        ]

        for ip, host_info in dados_scan.items():
            guia.append(f"🛡️ ENDURECIMENTO DO HOST: {ip}")
            guia.append(f"    OS: {host_info.get('os', 'N/A')} | MAC: {host_info.get('mac', 'N/A')}")
            guia.append("-" * 55)

            servicos = host_info.get('servicos', [])
            if not servicos:
                guia.append("    Nenhuma porta aberta detectada.")
                guia.append("\n" + "=" * 55 + "\n")
                continue

            for s in servicos:
                porta   = s.get('porta')
                servico = s.get('servico', 'desconhecido')
                versao  = s.get('versao', 'N/A')
                vulns   = s.get('vulnerabilidades', {})

                guia.append(f"\n[!] ALVO: Porta {porta}/{s.get('protocolo', 'tcp')} ({servico})")
                guia.append(f"    Versão Detectada: {versao}")

                if vulns:
                    guia.append("    ⚠️ FALHAS CRÍTICAS ENCONTRADAS:")
                    for v_id in vulns.keys():
                        fix = self._consultar_fix_especifico(v_id)
                        guia.append(f"    - ID: {v_id}")
                        guia.append(f"      CORREÇÃO: {fix}")

                guia.append("    🛠️ PASSOS DE REMEDIAÇÃO:")
                passos = self._mapear_passos_por_servico(porta, servico)
                for i, passo in enumerate(passos, 1):
                    guia.append(f"      {i}. {passo}")

            guia.append("\n" + "=" * 55 + "\n")

        return "\n".join(guia)

    def _consultar_fix_especifico(self, vuln_id):
        conhecimento_base = {
            "ms17-010": "Aplicar patch de segurança Microsoft KB4013389 e desativar SMBv1.",
            "ssl-poodle": "Desabilitar suporte a SSLv3 e habilitar TLS 1.2/1.3.",
            "slowloris": "Instalar mod_qos ou aumentar o limite de conexões simultâneas (MaxClients).",
            "anon": "Editar o arquivo de config do serviço e definir 'Anonymous_Enable=NO'.",
            "brute": "Implementar bloqueio temporário de IP após 3 tentativas falhas (Fail2Ban)."
        }
        for k, v in conhecimento_base.items():
            if k in vuln_id.lower(): return v
        return "Atualizar o binário do serviço para a versão estável mais recente (Patching)."

    def _mapear_passos_por_servico(self, porta, servico):
        fix_brain = self.database_remediacao.get(str(porta))
        if fix_brain: return fix_brain

        mapa_padrao = {
            21:   ["Desativar FTP e migrar para SFTP.", "Bloquear porta 21 no firewall perimetral.", "Habilitar logs de transferência."],
            22:   ["Alterar porta 22 para uma porta alta.", "Desativar login de ROOT via SSH.", "Forçar uso de chaves RSA (Proibir senhas)."],
            80:   ["Redirecionar todo tráfego para 443 (HTTPS).", "Remover banners de versão (ServerTokens Prod).", "Instalar WAF (ModSecurity)."],
            443:  ["Verificar expiração do certificado SSL.", "Desativar cifras fracas (RC4, DES).", "Ativar HSTS Header."],
            445:  ["Bloquear acesso SMB vindo da Internet.", "Desativar SMBv1 via registro do Windows.", "Habilitar SMB Signing."],
            3306: ["Restringir acesso apenas ao IP da aplicação.", "Renomear usuário admin padrão.", "Habilitar criptografia de dados em repouso."]
        }
        return mapa_padrao.get(porta, ["Isolar o serviço em uma VLAN protegida.", "Restringir acesso via Whitelist de IP.", "Habilitar auditoria de logs."])