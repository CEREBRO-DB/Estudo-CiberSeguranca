from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import threading

from core.engine.sniffer import start_sniffer, get_traffic

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("core/dashboard/templates/index.html", "r", encoding="utf-8") as f:
    html = f.read()

@app.get("/")
def home():
    return HTMLResponse(html)


# 🚀 inicia captura de rede em background
threading.Thread(target=start_sniffer, daemon=True).start()


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()

    while True:
        traffic = get_traffic()

        # top IPs
        sorted_ips = sorted(traffic.items(), key=lambda x: x[1], reverse=True)

        top = sorted_ips[:10]

        alerts = []

        for ip, count in top:
            if count > 50:
                alerts.append(f"🚨 tráfego suspeito em {ip}")

        await websocket.send_json({
            "top_ips": top,
            "alerts": alerts
        })

        await asyncio.sleep(2)