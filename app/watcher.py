import time
import os
import logging
import threading # Ensure threading is imported
from pathlib import Path
from app.extractor import process_pcap_file
from app.models.predictor import TrafficClassifier
from app.utils.db_handler import DatabaseManager
from app.utils.rag import KnowledgeBase
from app.sniffer.collector import start_sniffer

AI_PREDICTION_CACHE = {}

def parse_ja4_metadata(ja4_hash):
    """Translates JA4 Part A into plain English for the AI."""
    if not ja4_hash or "_" not in ja4_hash or ja4_hash == "None":
        return "Standard encrypted traffic"
        
    part_a = ja4_hash.split('_')[0]
    
    try:
        proto = "TCP" if part_a[0] == 't' else "QUIC/UDP"
        
        # FIX: Look at the 3rd character for the version (t12 -> 2, t13 -> 3)
        tls_ver = "TLS 1.3" if part_a[1:3] == "13" else "TLS 1.2"
        
        sni = "with a Server Name (SNI)" if part_a[3] == 'd' else "using direct IP routing"
        
        return f"{proto} connection using {tls_ver} {sni}"
    except:
        return "Standard TLS connection"

# Initialize singletons outside so they can be reused
db = DatabaseManager()
classifier = TrafficClassifier() 
rag_db = KnowledgeBase()

def on_packet_received(features, dst_ip):
    """Callback function executed whenever the sniffer catches a TLS packet."""
    try:
        logging.info("=" * 50)
        logging.info(f"LIVE PACKET CAPTURED -> Dest: {dst_ip}")
        logging.info(f"DEBUG - Extracted Pattern: {features}")
        logging.info("=" * 50)

        # Note: Live packet capture from Scapy doesn't automatically generate JA3/JA4 
        # in the current collector.py setup. We'll use the pattern for RAG/AI.
        
        # 1. SEARCH RAG DATABASE FIRST
        candidates = rag_db.search(discovered_pattern=features)
        logging.info(f"DEBUG - RAG Found Candidates: {candidates}")
        
        # 2. FEED CANDIDATES TO AI
        label, conf = classifier.classify_traffic(
            features, 
            candidate_apps=candidates, 
            ja4_hint="Standard TLS connection" # Default hint for live packets
        )
        
        logging.info(f"DEBUG - AI Verdict: {label} ({conf*100:.1f}%)")
        
        # 3. APPLY CONFIDENCE THRESHOLD
        if conf < 0.20:
            final_pred = "Unknown Traffic"
        else:
            final_pred = label

        # 4. LOG TO POSTGRES
        db.log_event(
            src="Live Capture", # Or extract src_ip if available in collector.py
            dst=dst_ip, 
            ja3="N/A (Live)",
            pred=final_pred,           
            threat="Safe"              
        )
        
    except Exception as e:
        logging.error(f"Error processing live packet: {e}")

def start_pcap_watcher(directory="/app/data"):
    logging.info(f"PCAP Watcher started. Monitoring: {directory}")
    processed_files = set()

    while True:
        # --- NEW: UI Command Checker ---
        cmd = db.get_config("sniffing_command")
        if cmd == "START":
            logging.info("!!! UI üzerinden BAŞLAT komutu alındı. Sniffer devreye giriyor...")
            # Komutu hemen sıfırlayalım ki sürekli başlamasın
            db.set_config("sniffing_command", "IDLE")
            # Sniffer'ı ayrı bir işlem olarak başlat
            threading.Thread(target=start_sniffer, args=("eth0", on_packet_received), daemon=True).start()
        # --------------------------------

        pcap_files = [f for f in os.listdir(directory) if f.endswith(".pcap")]
        
        for file_name in pcap_files:
            file_path = os.path.join(directory, file_name)
            
            if file_name in processed_files:
                continue
                
            try:
                # Dosya biz bakarken silinmiş mi diye kontrol et
                if not os.path.exists(file_path):
                    continue
                    
                if time.time() - os.path.getmtime(file_path) > 2:
                    records = process_pcap_file(file_path)
                    
                    for record in records:
                        pattern = record.get('discovered_pattern', [])
                        logging.info(f"DEBUG - Extracted Pattern: {pattern}")
                        logging.info("=" * 50)
                        logging.info(f"MY JA3 HASH IS: {record.get('ja3_hash')}")
                        logging.info(f"MY JA4 HASH IS: {record.get('ja4_hash')}")
                        logging.info("=" * 50)
                        
                        candidates = rag_db.search(
                            discovered_pattern=pattern,
                            ja3=record.get('ja3_hash'),
                            ja4=record.get('ja4_hash')
                        )
                        
                        logging.info(f"DEBUG - RAG Found Candidates: {candidates}")
                        
                        ja4_hint = parse_ja4_metadata(record.get('ja4_hash')) if record.get('ja4_hash') else "Unknown"
                        
                        # --- YENİ MANTIK KONTROLÜ ---
                        if candidates and "(Demo Verified)" in candidates[0]:
                            label = candidates[0]
                            conf = 0.99  
                            logging.info(f"FAST-PATH: Exact match found in DB.")
                        else:
                            sorted_pattern = sorted(pattern) 
                            pattern_str = str(sorted_pattern)
                            
                            # AI'a sor
                            label, conf = classifier.classify_traffic(
                                pattern, 
                                candidate_apps=candidates, 
                                ja4_hint=ja4_hint,
                            )
                            
                            # Eğer AI, RAG'ın adaylarını reddedip kendi sonucunu %80+ güvenle bulduysa, 
                            # RAG'ın aday listesini loglarda "ez" ki kafa karışıklığı olmasın.
                            if candidates and label not in candidates and conf > 0.80:
                                logging.info(f"AI OVERRIDE: RAG candidates ignored due to multi-dimensional mismatch. AI is confident.")
                                candidates = [label] # Arayüzde sadece AI'ın bulduğu görünsün
                        
                        
                        logging.info(f"DEBUG - AI Verdict: {label} ({conf*100:.1f}%)")
                        
                        if conf < 0.20:
                            final_pred = "Unknown Traffic"
                        else:
                            final_pred = label

                        db.log_event(
                            src=record.get('src_ip'), 
                            dst=record.get('dst_ip'), 
                            dst_port=record.get('dst_port'),
                            ja3=record.get('ja3_hash'),
                            pred=final_pred,           
                            threat="Safe"              
                        )
                    
                    logging.info(f"Successfully processed {len(records)} records from {file_name}")
                    db.log_system_message("INFO", "watcher", f"Processed PCAP: {file_name} ({len(records)} events)")
                    processed_files.add(file_name)
                    
            except Exception as e:
                    logging.error(f"Error processing {file_name}: {e}")

        time.sleep(5)