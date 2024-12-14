from flask import Flask, request, jsonify, render_template, send_file
from zapv2 import ZAPv2
import requests
import time
import json
import dotenv
import os
dotenv.load_dotenv()
GROK_API = "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"
app = Flask(__name__, template_folder="templates")


ZAP_IP = "http://127.0.0.1:8090"

# Konfiguracja połączenia z ZAP
zap = ZAPv2(proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    openapi_url = data.get('openapi_url')
    base_url = data.get('base_url')
    time_sleep = int(data.get('slider'))
    print(openapi_url)
    print(base_url)

    if not openapi_url or not base_url:
        return jsonify({"error": "Both 'openapi_url' and 'base_url' are required."}), 400

    try:
        # Import OpenAPI URL
        final_url = f"http://localhost:8090/JSON/openapi/action/importUrl/?url={openapi_url}&hostOverride=&contextId=&userId="
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
        time.sleep(time_sleep)  # Poczekaj na zakończenie skanowania

        # Pobranie a lertów
        alerts = zap.core.alerts()
        # Filtrowanie alertów - tylko te z ryzykiem >= "Medium"
        filtered_alerts = [
            alert for alert in alerts if alert.get('risk') in ['Critical', 'High', 'Medium']
        ]

        # Sortowanie alertów po ryzyku ("risk")
        sorted_alerts = sorted(
            filtered_alerts, key=lambda alert: ['Low', 'Medium', 'High', 'Critical'].index(alert.get('risk'))
        )


        filtered_for_grok = [
            {
            "method": alert.get("method"),
            "confidence": alert.get("confidence"),
            "description": alert.get("description"),
            "inputVector": alert.get("inputVector"),
            "attack": alert.get("attack"),
            "risk": alert.get("risk"),
            "name": alert.get("name")
            }
            for alert in sorted_alerts
        ]

        alerts_file = "alerts.json"
        with open(alerts_file, 'w') as f:
            json.dump({"alerts": sorted_alerts}, f, indent=4)

        return jsonify({"alerts": sorted_alerts, "grok": send_to_llama(filtered_for_grok)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download_alerts', methods=['GET'])
def download_alerts():
    try:
        alerts_file = "alerts.json"
        if os.path.exists(alerts_file):
            return send_file(alerts_file, as_attachment=True)
        else:
            return jsonify({"error": "Alerts file not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

def send_to_llama(alert_list):

    if not alert_list:
        raise ValueError("No alerts to send to LLaMA.")

    try:
        data = {
            "model": "llama3-8b-8192",
            "messages": [{
                "role": "user",
                "content": f"You are world known cybersecurity expert. Those are security scan results of some application in Goldman Sachs application network, made with ZAP scanner. It is CRUCIAL for you to place assessed security level in range from 0 to 100 in the first word of your anwser. Then point key risks from a bussiness point of view. Here are scan results: {alert_list}"
            }]
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROK_API}"
        }
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data)


        if response.status_code != 200:
            raise ValueError(f"Failed to send data to LLaMA: {response.text}")

        return response.json()['choices'][0]['message']['content']

    except Exception as e:
        raise ValueError(f"Failed to send data to LLaMA: {str(e)}")
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
