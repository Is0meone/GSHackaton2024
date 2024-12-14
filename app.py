import os
from flask import Flask, request, jsonify, render_template
from zapv2 import ZAPv2
import requests
import time
import json
import dotenv



dotenv.load_dotenv()
GROK_API = os.getenv("GROK_API")

app = Flask(__name__, template_folder="templates", static_folder="static")

# Konfiguracja połączenia z ZAP
zap = ZAPv2(proxies={"http": "http://127.0.0.1:7071", "https": "http://127.0.0.1:7071"})


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    print("Dzialamy")
    data = request.get_json()
    openapi_url = data.get('openapi_url')
    base_url = data.get('base_url')
    print(openapi_url)
    print(base_url)
    if not openapi_url or not base_url:
        return jsonify({"error": "Both 'openapi_url' and 'base_url' are required."}), 400

    try:
        # Import OpenAPI URL
        final_url = f"http://localhost:7071/JSON/openapi/action/importUrl/?url={openapi_url}&hostOverride=&contextId=&userId="
        response = requests.get(final_url)

        if response.status_code != 200:
            return jsonify({"error": "Failed to import OpenAPI URL."}), 500

        time.sleep(5)  # Poczekaj na przetworzenie definicji

        # Uruchomienie skanowania
        zap.ascan.scan(url=base_url)
        time.sleep(10)  # Poczekaj na zakończenie skanowania

        # Pobranie alertów
        alerts = zap.core.alerts()

        return jsonify({"alerts": alerts})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/send-to-llama', methods=['POST'])
def send_to_llama():
    data = request.get_json()
    prompt = data.get('prompt')
    alerts = data.get('alerts')

    if not prompt or not alerts:
        return jsonify({"error": "Both 'prompt' and 'alerts' are required."}), 400

    try:
        

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROK_API}"
        }
        data = {
            "model": "llama3-8b-8192",
            "messages": [{
                "role": "user",
                "content": f"You are world known cybersecurity expert. Sort those vulnerabilities by its relevance, impact and risk combined. For comparison use fields 'confidence', 'risk' and 'description'. Return sorted list of vulnerabilities. Formulate your respond in HTML. DATA:  {alert_list}"
            }]
        }
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data)


        if response.status_code != 200:
            return jsonify({"error": "Failed to send data to LLaMA."}), 500

        return jsonify(response.json())

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
