import time
import subprocess
import psycopg2
import os

# Postgres Veritabanına Bağlan (Docker'da çalışan DB'ye dışarıdan bağlanıyoruz)
DB_HOST = "localhost" # Windows'tan localhost üzerinden Docker DB'ye erişilir
DB_NAME = "tls_db"
DB_USER = "user"
DB_PASS = "pass"

def get_config(cursor, key):
    cursor.execute("SELECT value FROM system_config WHERE key = %s", (key,))
    res = cursor.fetchone()
    return res[0] if res else ""

def run_agent():
    print("🛡️ Windows Capture Agent Başlatıldı. Komut bekleniyor...")
    tshark_process = None

    while True:
        try:
            with psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS) as conn:
                with conn.cursor() as cur:
                    cmd = get_config(cur, "sniffing_command")
                    
                    if cmd == "START" and tshark_process is None:
                        print("🔴 START komutu alındı! TShark başlatılıyor...")
                        
                        # Arayüzdeki ayarları DB'den çek
                        tshark_path = get_config(cur, "tshark_path") or r"C:\Program Files\Wireshark\tshark.exe"
                        interface = get_config(cur, "capture_interface")
                        ring_dur = get_config(cur, "ring_duration") or "30"
                        ring_files = get_config(cur, "ring_files") or "10"
                        
                        # Verilerin kaydedileceği klasör
                        out_file = os.path.join(os.getcwd(), "data", "live_capture.pcap")
                        
                        # TShark Komutu (Halka arabelleği - Ring Buffer mantığıyla)
                        command = [
                            tshark_path, 
                            "-i", interface if interface else "1", 
                            "-b", f"duration:{ring_dur}", 
                            "-b", f"files:{ring_files}"
                        ]
                        
                        print(f"Çalıştırılan komut: {' '.join(command)}")
                        tshark_process = subprocess.Popen(command)
                        
                        # Komutu IDLE yap ki sürekli tetiklenmesin
                        cur.execute("UPDATE system_config SET value = 'IDLE' WHERE key = 'sniffing_command'")
                        conn.commit()
                        
                    elif cmd == "STOP" and tshark_process is not None:
                        print("⏹ STOP komutu alındı! TShark durduruluyor...")
                        tshark_process.terminate()
                        tshark_process = None
                        cur.execute("UPDATE system_config SET value = 'IDLE' WHERE key = 'sniffing_command'")
                        conn.commit()
                        
        except Exception as e:
            print(f"Agent Hatası: {e}")
            
        time.sleep(2) # 2 saniyede bir DB'yi kontrol et

if __name__ == "__main__":
    # pip install psycopg2 Eğer yüklü değilse Windows CMD'sine bu komutu yaz
    run_agent()