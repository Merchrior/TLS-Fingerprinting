import time
import os
import logging
import threading
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

        label, conf = classifier.classify_traffic(
            features, 
            sni="Unknown", 
            ja4_hint="Standard TLS connection"
        )
        
        logging.info(f"DEBUG - AI Verdict: {label} ({conf*100:.1f}%)")
        
        final_pred = "Unknown Traffic" if conf < 0.20 else label

        # 🚀 HATA DÜZELTİLDİ: sni="Unknown" ve dst_port=0 eklendi
        db.log_event(
            src="Live Capture", 
            dst=dst_ip,
            dst_port=0,
            ja3="N/A (Live)",
            pred=final_pred,           
            threat="Safe",       
            sni="Unknown",       
            confidence=conf       
        )
        
    except Exception as e:
        logging.error(f"Error processing live packet: {e}")

def start_pcap_watcher(directory="/app/data"):
    logging.info(f"PCAP Watcher started. Monitoring: {directory}")
    processed_files = set()

    while True:
        pcap_files = [f for f in os.listdir(directory) if f.endswith(".pcap")]
        
        for file_name in pcap_files:
            file_path = os.path.join(directory, file_name)
            
            if file_name in processed_files:
                continue
                
            try:
                if not os.path.exists(file_path):
                    continue
                    
                if time.time() - os.path.getmtime(file_path) > 2:
                    records = process_pcap_file(file_path)
                    
                    for record in records:
                        # 🚀 CATCH TSHARK FORMAT: Reconstruct pattern from ja3_string if discovered_pattern is missing
                        pattern = record.get('discovered_pattern')
                        if not pattern:
                            ja3_str = str(record.get('ja3_string', ''))
                            # Convert TShark's numeric JA3 string (e.g., "771,4865-4866...") into a feature list for the AI
                            pattern = [p.strip() for p in ja3_str.replace(',', '-').split('-') if p.strip()]
                        
                        sni_val = record.get('sni', 'Unknown')
                        
                        # Fallback gracefully if JA4 is missing in TShark version
                        ja4_raw = record.get('ja4_hash')
                        ja4_hint = parse_ja4_metadata(ja4_raw) if ja4_raw else "Standard encrypted traffic"
                        
                        logging.info(f"DEBUG - Extracted Pattern: {pattern}")
                        logging.info("=" * 50)
                        logging.info(f"MY JA3 HASH IS: {record.get('ja3_hash')}")
                        logging.info(f"MY JA4 HASH IS: {record.get('ja4_hash')}")
                        logging.info(f"SNI HEDEFİ: {sni_val}")
                        logging.info("=" * 50)
                        
                        label, conf = classifier.classify_traffic(
                            pattern, 
                            ja4_hint=ja4_hint,
                            sni=sni_val 
                        )
                        
                        logging.info(f"DEBUG - AI Verdict: {label} ({conf*100:.1f}%)")
                        final_pred = "Unknown Traffic" if conf < 0.20 else label

                        db.log_event(
                            src=record.get('src_ip'), 
                            dst=record.get('dst_ip'), 
                            dst_port=record.get('dst_port'),
                            ja3=record.get('ja3_hash'),
                            pred=final_pred,     
                            threat="Safe",
                            sni=sni_val,
                            confidence=conf
                        )
                    
                    logging.info(f"Successfully processed {len(records)} records from {file_name}")
                    db.log_system_message("INFO", "watcher", f"Processed PCAP: {file_name} ({len(records)} events)")
                    processed_files.add(file_name)
                    
            except Exception as e:
                    logging.error(f"Error processing {file_name}: {e}")

        time.sleep(5)