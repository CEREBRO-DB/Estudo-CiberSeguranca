import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agents.orion import Orion
from core.agents.nexus import Nexus
from core.agents.vektor import Vektor
from core.utils.logger import save, load, diff


class Cerebro:
    def __init__(self, target):
        self.target = target
        self.orion = Orion(target)
        self.nexus = Nexus()
        self.vektor = Vektor()

    def run(self):
        print("\n🧠 CÉREBRO 2.0 ATIVO\n")

        services = self.orion.scan_services()
        analysis = self.nexus.analyze(services)
        actions = self.vektor.decide(analysis)

        snapshot = {
            "target": self.target,
            "services": services,
            "analysis": analysis,
            "actions": actions
        }

        history = load()
        last = history[-1] if history else None

        changes = diff(last, snapshot)

        snapshot["changes"] = changes

        save(snapshot)

        print("\n🧠 CHANGES:", changes)
        print("\n✔ Snapshot salvo")


if __name__ == "__main__":
    target = "10.1.1.1"
    cerebro = Cerebro(target)
    cerebro.run()