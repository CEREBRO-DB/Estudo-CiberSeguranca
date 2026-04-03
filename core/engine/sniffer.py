from collections import defaultdict
import threading
import random
import time

traffic_log = defaultdict(int)

FAKE_IPS = [
    "192.168.1.10", "192.168.1.45", "10.0.0.23", "172.16.0.5",
    "45.33.32.156", "104.21.14.200", "8.8.8.8", "1.1.1.1",
    "185.220.101.47", "91.108.4.15", "198.51.100.22", "203.0.113.5"
]

def _simulate():
    while True:
        for ip in FAKE_IPS:
            traffic_log[ip] += random.randint(1, 30)
        # simula pico suspeito em IP aleatório
        suspect = random.choice(FAKE_IPS)
        traffic_log[suspect] += random.randint(40, 120)
        time.sleep(2)

def start_sniffer():
    _simulate()

def get_traffic():
    return dict(traffic_log)