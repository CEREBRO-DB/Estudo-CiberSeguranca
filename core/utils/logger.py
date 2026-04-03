import json
import os
from datetime import datetime

DB = "core/memory/db.json"


def load():
    if not os.path.exists(DB):
        return []

    try:
        with open(DB, "r") as f:
            return json.load(f)
    except:
        return []


def save(entry):
    data = load()

    clean_entry = {
        "target": entry.get("target"),
        "services": entry.get("services", []),
        "analysis": entry.get("analysis", []),
        "actions": entry.get("actions", []),
        "changes": entry.get("changes", {}),
        "timestamp": str(datetime.now())
    }

    data.append(clean_entry)

    with open(DB, "w") as f:
        json.dump(data, f, indent=4)


# 🧠 FUNÇÃO QUE ESTAVA FALTANDO (ERRO PRINCIPAL)
def diff(last, current):
    if not last:
        return {
            "new_ports": [p.get("port") for p in current.get("services", [])],
            "closed_ports": []
        }

    last_ports = {p.get("port") for p in last.get("services", []) if isinstance(p, dict)}
    curr_ports = {p.get("port") for p in current.get("services", []) if isinstance(p, dict)}

    return {
        "new_ports": list(curr_ports - last_ports),
        "closed_ports": list(last_ports - curr_ports)
    }