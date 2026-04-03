import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("CLAUDE_API_KEY")

def ask_claude(prompt):
    url = "https://api.anthropic.com/v1/messages"

    headers = {
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }

    data = {
        "model": "claude-3-haiku-20240307",
        "max_tokens": 300,
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    response = requests.post(url, headers=headers, json=data)

    return response.json()


from core.engine.cerebro import Cerebro

if __name__ == "__main__":
    cerebro = Cerebro("10.1.1.100")
    cerebro.run()