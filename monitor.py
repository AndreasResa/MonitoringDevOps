import os
import re
import google.generativeai as genai
import requests
from datetime import datetime, timedelta
from collections import defaultdict

# --- 1. KONFIGURASI ---
# (Nilai-nilai ini telah diisi sesuai permintaan Anda)

# Lokasi file log SSH
# Ubuntu/Debian: '/var/log/auth.log'
# CentOS/RHEL/Fedora: '/var/log/secure'
LOG_FILE_PATH = '/var/log/auth.log' 

# Jendela waktu untuk diperiksa (dalam menit)
TIME_WINDOW_MINUTES = 5

# Ambang batas kegagalan sebelum memicu peringatan
FAILURE_THRESHOLD = 2

# Kunci API dan Konfigurasi
GEMINI_API_KEY = 'AIzaSyB0cO9dUN8sa1Qn50978sotvq2dxs_uu2o'  
FONNTE_API_TOKEN = '9CLzM1EFKzAHsETYDcpb'     
YOUR_PHONE_NUMBER = '6285342888992'

LOG_PATTERN = re.compile(
    # Pola ini mencari format log rsyslog default (ISO 8601)
    # Contoh: 2025-11-11T03:30:01.123456+00:00 server-name sshd[pid]: Failed password...
    # Disederhanakan untuk mencocokkan timestamp ISO dan IP
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password .* from ([\d\.]+) port'
)

# --- 2. FUNGSI API (GEMINI & FONNTE) ---

def setup_gemini():
    """Mengkonfigurasi dan menginisialisasi model Gemini."""
    if not GEMINI_API_KEY:
        print("Error: GEMINI_API_KEY tidak ditemukan.")
        return None
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.5-flash') # Model yang umum digunakan
        return model
    except Exception as e:
        print(f"Error konfigurasi Gemini: {e}")
        return None

def analyze_with_gemini(model, log_entries_str):
    """Mengirim log ke Gemini untuk analisis."""
    if not model:
        return "Analisis Gemini tidak tersedia (model gagal dimuat)."

    prompt = f"""
    Analisis log SSH berikut dari server saya. 
    Berikan ringkasan ancaman dalam satu paragraf singkat dan sarankan satu tindakan spesifik (misalnya, format perintah firewall/fail2ban).
    Target audiens adalah admin sistem yang sedang bepergian.

    Log:
    {log_entries_str}
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error saat memanggil Gemini API: {e}")
        return f"Gagal menganalisis log. Serangan terdeteksi dari log berikut:\n{log_entries_str}"

def send_whatsapp_notification(message):
    """Mengirim pesan ke WhatsApp menggunakan Fonnte."""
    if not FONNTE_API_TOKEN or not YOUR_PHONE_NUMBER:
        print("Error: FONNTE_API_TOKEN atau YOUR_PHONE_NUMBER tidak ditemukan.")
        return

    url = "https://api.fonnte.com/send"
    payload = {
        'target': YOUR_PHONE_NUMBER,
        'message': message,
    }
    headers = {
        'Authorization': FONNTE_API_TOKEN
    }
    
    try:
        response = requests.post(url, headers=headers, data=payload, timeout=10)
        response.raise_for_status() # Cek jika ada HTTP error
        print(f"Notifikasi WhatsApp terkirim ke {YOUR_PHONE_NUMBER}.")
    except requests.exceptions.RequestException as e:
        print(f"Error mengirim notifikasi Fonnte: {e}")

# --- 3. FUNGSI UTAMA (MAIN) ---

def parse_log_time(timestamp_str):
    """Mengubah format waktu log (ISO 8601) ke objek datetime."""
    # timestamp_str akan terlihat seperti: '2025-11-10T12:46:20'
    # Kita potong jika ada sub-detik, cth: 2025-11-10T12:46:20.123456...
    try:
        return datetime.fromisoformat(timestamp_str.split('.')[0])
    except ValueError:
        print(f"Format timestamp tidak dikenal: {timestamp_str}")
        return None

def main():
    print(f"Memulai monitor SSH pada {datetime.now()}...")
    gemini_model = setup_gemini()
    
    time_threshold = datetime.now() - timedelta(minutes=TIME_WINDOW_MINUTES)
    
    ip_failures = defaultdict(int)
    ip_log_entries = defaultdict(list)

    try:
        with open(LOG_FILE_PATH, 'r') as f:
            for line in f:
                match = LOG_PATTERN.search(line)
                
                if match:
                    timestamp_str, ip_address = match.groups()
                    log_time = parse_log_time(timestamp_str)
                    
                    if log_time and log_time > time_threshold:
                        ip_failures[ip_address] += 1
                        ip_log_entries[ip_address].append(line.strip())

    except FileNotFoundError:
        print(f"Error: File log tidak ditemukan di {LOG_FILE_PATH}")
        print("Pastikan path ini benar untuk server tempat skrip ini berjalan.")
        return
    except PermissionError:
        print(f"Error: Tidak memiliki izin untuk membaca {LOG_FILE_PATH}.")
        print("Pastikan Jenkins (atau user yang menjalankan skrip) memiliki izin baca.")
        return
    except Exception as e:
        print(f"Error saat membaca file log: {e}")
        return

    # --- 4. PEMROSESAN HASIL & PEMBERITAHUAN ---
    
    print(f"Pengecekan selesai. Menemukan {len(ip_failures)} IP dengan kegagalan dalam {TIME_WINDOW_MINUTES} menit terakhir.")
    
    alert_triggered = False
    for ip, count in ip_failures.items():
        if count >= FAILURE_THRESHOLD:
            alert_triggered = True
            print(f"AMBANG BATAS TERLAMPAUI! IP: {ip}, Percobaan: {count}")
            
            log_str = "\n".join(ip_log_entries[ip])
            
            print(f"Mendapatkan analisis dari Gemini untuk IP {ip}...")
            analysis_result = analyze_with_gemini(gemini_model, log_str)
            
            header = f"PERINGATAN DARI SERVER\n\n"
            details = f"IP Asal: {ip}\nJumlah Percobaan: {count}\nRentang Waktu: {TIME_WINDOW_MINUTES} menit terakhir\n\n"
            gemini_section = f"🤖 Analisis Gemini:\n{analysis_result}"
            
            final_message = header + details + gemini_section
            
            send_whatsapp_notification(final_message)

    if not alert_triggered:
        print(f"Sistem aman. Tidak ada IP yang melampaui ambang batas {FAILURE_THRESHOLD} percobaan.")

if __name__ == "__main__":
    main()