import re

class Phantom:
    def analisar_social(self, texto: str) -> str:
        if not texto: return "Erro: Texto vazio."
        gatilhos = ["urgente", "senha", "banco", "clique", "vencimento", "promoção", "suspensa"]
        encontrados = [g for g in gatilhos if g in texto.lower()]
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', texto)
        
        res = [
            "=== PHANTOM SOCIAL ANALYSIS ===",
            f"Gatilhos de Urgência: {', '.join(encontrados) if encontrados else 'Nenhum'}",
            f"E-mails Detectados: {len(emails)}",
            "\nVEREDITO:",
            "⚠️ RISCO ALTO DE PHISHING" if len(encontrados) > 1 else "✅ RISCO BAIXO"
        ]
        return "\n".join(res)