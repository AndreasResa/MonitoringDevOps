import google.generativeai as genai
import datetime
import requests
import paramiko  # Untuk koneksi SSH
import os        # Untuk membaca kredensial
from datetime import datetime, timedelta # Untuk memeriksa waktu

# --- Ambil Kredensial & Konfigurasi API (Cara Aman) ---
# Ambil dari Jenkins Environment Variables. 
# Jika tidak ada, pakai "default" (tapi ini tidak aman untuk produksi)
GEMINI_API_KEY = os.environ.get('GEMINI_KEY', " AIzaSyB0cO9dUN8sa1Qn50978sotvq2dxs_uu2o")
FONNTE_TOKEN = os.environ.get('FONNTE_TOKEN', "9CLzM1EFKzAHsETYDcpb")
TARGET_WA = os.environ.get('TARGET_WA', "NOMOR_HP_ANDA") # GANTI DENGAN NOMOR HP ANDA

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(model_name="gemini-1.5-flash")

# --- Fungsi Baru yang Lebih Pintar ---
def get_ssh_attempts(minutes_to_check=10, failure_threshold=3):
    """
    Menghubungkan ke server dan memeriksa log.
    Hanya mengembalikan log jika jumlah kegagalan > threshold dalam X menit terakhir.
    """
    host = "103.59.94.80"
    username = os.environ.get('SSH_USER') # Dari Jenkins Credentials
    password = os.environ.get('SSH_PASS') # Dari Jenkins Credentials
    
    # Perintah ini mengambil 100 kegagalan terakhir untuk dianalisis
    command = "grep 'Failed password' /var/log/auth.log | tail -n 100"

    if not username or not password:
        return None, "Error: SSH_USER atau SSH_PASS tidak diatur di Jenkins."

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"Mencoba terhubung ke {host} sebagai {username}...")
        client.connect(host, username=username, password=password, timeout=10)
        
        stdin, stdout, stderr = client.exec_command(command)
        
        log_data = stdout.read().decode()
        error_data = stderr.read().decode()
        client.close()
        
        if error_data:
            return None, f"Error saat eksekusi perintah di server: {error_data}"
        if not log_data:
            return None, "(Tidak ada percobaan login yang gagal)"

        # --- LOGIKA BARU: PARSING DAN HITUNG ---
        recent_failures_lines = []
        failure_count = 0
        now = datetime.now()
        time_threshold = now - timedelta(minutes=minutes_to_check)
        current_year = now.year

        for line in log_data.strip().split('\n'):
            try:
                # Format log: "Nov 11 14:10:30 lionkingserver sshd[...]: Failed password..."
                # Ambil bagian timestamp-nya saja
                timestamp_str = " ".join(line.split()[:3]) # "Nov 11 14:10:30"
                
                # auth.log tidak menyertakan tahun, jadi kita tambahkan secara manual
                log_time = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")

                # Cek jika log adalah dari tahun lalu (misal sekarang Jan, log masih Des)
                if log_time > now:
                    log_time = log_time.replace(year=current_year - 1)
                    
                # Hitung jika terjadi dalam X menit terakhir
                if log_time >= time_threshold:
                    failure_count += 1
                    recent_failures_lines.append(line)
                    
            except Exception as e:
                # Lewati baris jika formatnya aneh
                print(f"Gagal mem-parsing baris: {line} | Error: {e}")
                continue
        # --- AKHIR LOGIKA BARU ---

        # Periksa apakah jumlahnya melebihi batas
        if failure_count >= failure_threshold:
            # Jika YA, kembalikan log untuk dikirim
            log_output = "\n".join(recent_failures_lines)
            return log_output, f"TERDETEKSI! {failure_count} kegagalan dalam {minutes_to_check} menit terakhir."
        else:
            # Jika TIDAK, kembalikan 'None'
            return None, f"Aman. Hanya {failure_count} kegagalan (di bawah batas {failure_threshold})."

    except Exception as e:
        return None, f"🚨 Gagal terhubung ke server SSH {host}: {e}"

def get_gemini_analysis(log_text):
    try:
        response = model.generate_content(f"Ada serangan brute force terdeteksi dengan log:\n{log_text}\n\nApa yang sebaiknya saya lakukan? (responnya singkat dan jelas)")
        return response.text
    except Exception as e:
        return f"🚨 Gagal mendapatkan analisis dari Gemini: {e}"

def send_whatsapp(message):
    payload = {
        "target": TARGET_WA,
        "message": message,
    }
    headers = {"Authorization": FONNTE_TOKEN}
    try:
        r = requests.post("https://api.fonnte.com/send", data=payload, headers=headers)
        return r.status_code
    except Exception as e:
        return f"Gagal mengirim WA: {e}"

# --- EKSEKUSI UTAMA (DIMODIFIKASI) ---
print("Memulai skrip monitor...")

# Jalankan fungsi dengan batas 3 kegagalan dalam 1 menit
# Anda bisa ubah angkanya: (minutes_to_check=10, failure_threshold=3)
log_lines, status_message = get_ssh_attempts(minutes_to_check=1, failure_threshold=3)

print(status_message) # Ini akan mencetak "Aman..." atau "TERDETEKSI!..."

# Hanya kirim notifikasi jika 'log_lines' TIDAK kosong
# (artinya batas 3 kegagalan terlampaui)
if log_lines:
    print("Batas terlampaui. Menganalisis dengan Gemini...")
    ai_response = get_gemini_analysis(log_lines)
    
    full_message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⚠ DETEKSI BRUTE FORCE! (>{failure_threshold}x Gagal)\n\n{log_lines}\n\nGemini says:\n{ai_response}"
    
    print("Mengirim notifikasi WhatsApp...")
    status = send_whatsapp(full_message)
    print(f"Status pengiriman WhatsApp: {status}")
else:
    print("Melewatkan notifikasi (level ancaman rendah).")