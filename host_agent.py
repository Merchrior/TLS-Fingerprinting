import time
import subprocess
import psycopg2
import os
import json # <-- YENİ EKLENDİ

DB_HOST = "localhost"
DB_NAME = "tls_db"
DB_USER = "user"
DB_PASS = "pass"

def get_config(cursor, key):
    cursor.execute("SELECT value FROM system_config WHERE key = %s", (key,))
    res = cursor.fetchone()
    return res[0] if res else ""

# --- YENİ FONKSİYON: Ağ kartlarını bulup DB'ye yazar ---
def update_interfaces_in_db(cursor, tshark_path):
    try:
        print("🔍 Ağ kartları (Interfaces) taranıyor...")
        result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line: continue
                parts = line.split(". ", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    interfaces.append({"index": parts[0], "display": line})
            
            # DB'ye kaydet
            cursor.execute("""
                INSERT INTO system_config (key, value) VALUES (%s, %s)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
            """, ("available_interfaces", json.dumps(interfaces)))
            print(f"✅ {len(interfaces)} adet ağ kartı bulundu ve arayüze gönderildi.")
    except Exception as e:
        print(f"⚠️ Ağ kartları taranamadı: {e}")
# -------------------------------------------------------

def run_agent():
    print("🛡️ Windows Capture Agent Başlatıldı. Komut bekleniyor...")
    tshark_process = None
    interfaces_updated = False # Sadece ilk açılışta bir kez tarasın

    while True:
        try:
            with psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS) as conn:
                with conn.cursor() as cur:
                    
                    # --- YENİ: Başlangıçta arayüze listeyi gönder ---
                    if not interfaces_updated:
                        tshark_path = get_config(cur, "tshark_path") or r"C:\Program Files\Wireshark\tshark.exe"
                        update_interfaces_in_db(cur, tshark_path)
                        conn.commit()
                        interfaces_updated = True
                    # ------------------------------------------------

                    cmd = get_config(cur, "sniffing_command")
                    
                    if cmd == "START" and tshark_process is None:
                        print("🔴 START komutu alındı! TShark başlatılıyor...")
                        tshark_path = get_config(cur, "tshark_path") or r"C:\Program Files\Wireshark\tshark.exe"
                        interface = get_config(cur, "capture_interface")
                        capture_filter = get_config(cur, "capture_filter")
                        ring_dur = get_config(cur, "ring_duration") or "30"
                        ring_files = get_config(cur, "ring_files") or "10"
                        out_file = os.path.join(os.getcwd(), "data", "live_capture.pcap")
                        
                        command = [
                            tshark_path, 
                            "-i", interface if interface else "1", 
                            "-b", f"duration:{ring_dur}", 
                            "-b", f"files:{ring_files}"
                        ]
                        if capture_filter:
                            command.extend(["-f", capture_filter])
                        command.extend(["-w", out_file])
                        
                        print(f"Çalıştırılan komut: {' '.join(command)}")
                        tshark_process = subprocess.Popen(command)
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
            
        time.sleep(2)

if __name__ == "__main__":
    run_agent()