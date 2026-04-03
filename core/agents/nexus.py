class Nexus:
    def analyze(self, services):
        print("\n[NEXUS] IA analisando serviços...\n")

        report = []

        for s in services:
            risk = 10
            reason = "unknown service"

            if s["port"] == 21:
                risk = 80
                reason = "FTP insecure"
            elif s["port"] == 22:
                risk = 50
                reason = "SSH remote access"
            elif s["port"] == 80:
                risk = 60
                reason = "HTTP unencrypted"
            elif s["port"] == 3306:
                risk = 95
                reason = "Database exposed"

            report.append({
                "port": s["port"],
                "risk": risk,
                "reason": reason,
                "banner": s["banner"]
            })

            print(f"[NEXUS-IA] port={s['port']} risk={risk} reason={reason}")

        return report