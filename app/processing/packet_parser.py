import os
import logging
from scapy.all import rdpcap, load_layer
from app.processing.ja3_engine import JA3Engine
from app.database.sqlite_manager import SQLiteManager
from app.ai_node.k8s_orchestrator import AIOrchestrator

load_layer("tls")
from scapy.layers.tls.all import TLSClientHello
from scapy.layers.inet import IP # IP Adreslerini okumak için eklendi

db = SQLiteManager()
ai_node = AIOrchestrator()
engine = JA3Engine()

def process_pcap_file(file_path: str):
    try:
        packets = rdpcap(file_path)
        for packet in packets:
            if packet.haslayer(TLSClientHello):
                _execute_pipeline(packet)
        os.remove(file_path)
    except Exception as e:
        logging.error(f"Error processing PCAP {file_path}: {e}")

def _execute_pipeline(packet):
    ja3_string, ja3_hash = engine.calculate(packet)
    if not ja3_hash:
        return

    # IP Adreslerini Çıkar
    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"

    # 1. Fast-Path Check
    app_label = db.check_fast_path(ja3_hash)
    if app_label:
        db.log_live_traffic(src_ip, dst_ip, ja3_hash, f"Verified: {app_label}")
        return 
        
    # 2. Unknown Hash -> Log as Analyzing and trigger AI
    db.log_live_traffic(src_ip, dst_ip, ja3_hash, "Analyzing in K8s AI Node ⏳")
    ai_result = ai_node.trigger_discovery_job(ja3_string)
    
    # 3. Autonomous Verification
    db.autonomous_update(ja3_hash, ai_result['label'], ai_result['confidence'])