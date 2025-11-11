import google.generativeai as genai
import datetime
import requests
import subprocess

# Konfigurasi API Gemini
genai.configure(api_key=" AIzaSyB0cO9dUN8sa1Qn50978sotvq2dxs_uu2o")

model = genai.GenerativeModel(model_name="gemini-1.5-flash")

def get_ssh_attempts():
    result = subprocess.check_output("grep 'Failed password' /var/log/auth.log | tail -n 10", shell=True)
    return result.decode()

def get_gemini_analysis(log_text):
    try:
        response = model.generate_content(f"Ada percobaan login brute force:\n{log_text}\n\nApa yang sebaiknya saya lakukan? (responnya jangan terlalu panjang)")
        return response.text
    except Exception as e:
        return f"🚨 Gagal mendapatkan analisis dari Gemini: {e}"

def send_whatsapp(message):
    token = "9CLzM1EFKzAHsETYDcpb"
    payload = {
        "target": "nomor hp yang akan digunakan",
        "message": message,
    }
    headers = {"Authorization": token}
    r = requests.post("https://api.fonnte.com/send", data=payload, headers=headers)
    return r.status_code

# Eksekusi semua
log = get_ssh_attempts()
ai_response = get_gemini_analysis(log)
full_message = f"[{datetime.datetime.now()}] ⚠ Percobaan Login Detected!\n\n{log}\n\nGemini says:\n{ai_response}"
send_whatsapp(full_message)