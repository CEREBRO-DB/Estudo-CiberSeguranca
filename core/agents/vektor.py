class Vektor:
    def decide(self, report):
        print("\n[VEKTOR] Motor de decisão ativo...\n")

        actions = []

        for r in report:
            if r["risk"] >= 80:
                action = "ALERT_CRITICAL"
            elif r["risk"] >= 50:
                action = "MONITOR"
            else:
                action = "IGNORE"

            actions.append({
                "port": r["port"],
                "action": action
            })

            print(f"[VEKTOR] port={r['port']} -> {action}")

        return actions