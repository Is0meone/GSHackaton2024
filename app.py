from flask import Flask, request, jsonify, render_template
from zapv2 import ZAPv2
import requests
import time
import json

app = Flask(__name__, template_folder="templates")

# Konfiguracja połączenia z ZAP
zap = ZAPv2(proxies={"http": "http://127.0.0.1:7071", "https": "http://127.0.0.1:7071"})

@app.route('/')
def index():
    return jsonify({"message": "Welcome to Flask ZAP Analyzer. Use /analyze or /send-to-llama endpoints."})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    openapi_url = data.get('openapi_url')
    base_url = data.get('base_url')

    if not openapi_url or not base_url:
        return jsonify({"error": "Both 'openapi_url' and 'base_url' are required."}), 400

    try:
        # Import OpenAPI URL
        final_url = f"http://localhost:7071/JSON/openapi/action/importUrl/?url={openapi_url}&hostOverride=&contextId=&userId="
        response = requests.get(final_url)

        if response.status_code != 200:
            return jsonify({"error": "Failed to import OpenAPI URL."}), 500

        time.sleep(5)  # Poczekaj na przetworzenie definicji

        # Pobranie listy skanerów
        scanners = zap.ascan.scanners()
        dom_xss_ids = []
        for scanner in scanners:
            if "DOM XSS" in scanner['name']:
                dom_xss_ids.append(scanner['id'])

        if dom_xss_ids:
            dom_xss_str = ",".join(dom_xss_ids)
            print("Disabling DOM XSS scanners:", dom_xss_str)
            zap.ascan.disable_scanners(ids=dom_xss_str)
        else:
            print("No DOM XSS scanners found. Skipping...")

        # Uruchomienie skanowania
        zap.ascan.scan(url=base_url)
        time.sleep(100)  # Poczekaj na zakończenie skanowania

        # Pobranie alertów
        alerts = zap.core.alerts()

        # Filtrowanie alertów - tylko te z ryzykiem >= "Medium"
        filtered_alerts = [
            alert for alert in alerts if alert.get('risk') in ['Medium', 'High', 'Critical']
        ]

        # Sortowanie alertów po ryzyku ("risk")
        sorted_alerts = sorted(
            filtered_alerts, key=lambda alert: ['Low', 'Medium', 'High', 'Critical'].index(alert.get('risk'))
        )

        return jsonify({"alerts": sorted_alerts})

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
        llama_url = "http://localhost:8000/predict"  # Zakładamy, że model działa na porcie 8000

        payload = {
            "prompt": f"{prompt}\nAlerts:\n{json.dumps(alerts, indent=2)}"
        }

        llama_response = requests.post(llama_url, json=payload)

        if llama_response.status_code != 200:
            return jsonify({"error": "Failed to send data to LLaMA."}), 500

        return jsonify(llama_response.json())

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
