import threading
import subprocess
import logging
import sys
import os
import queue
from collections import defaultdict
from threading import Thread
from app.watcher import start_pcap_watcher

# Setup professional logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log"), # Writes logs to a file
        logging.StreamHandler()         # Also prints to terminal
    ]
)

# --- YOUR AI IMPORTS (Updated to match his folder structure) ---
from app.sniffer.collector import start_sniffer 
from app.processing.miner import PatternMiner
from app.utils.rag import KnowledgeBase
from app.models.predictor import TrafficClassifier
from app.utils.db_handler import DatabaseManager# His Database script

INTERFACE = "any" # Use 'any' for Docker compatibility
BATCH_SIZE = 5
MIN_SUPPORT = 0.6

class SystemController:
    def __init__(self):
        logging.info("Initializing AI System Modules...")
        self.miner = PatternMiner(min_support=MIN_SUPPORT)
        self.kb = KnowledgeBase()
        self.classifier = TrafficClassifier()
        self.db = DatabaseManager() # Connect to his PostgreSQL database
        
        self.packet_queue = queue.Queue()
        self.sessions = defaultdict(list)
        self.running = True

    def start(self):
        worker_thread = threading.Thread(target=self.ai_worker_loop)
        worker_thread.daemon = True
        worker_thread.start()
        
        try:
            start_sniffer(INTERFACE, self.on_packet_received)
        except PermissionError:
            logging.error("Root/Sudo privileges required for sniffing!")
            self.running = False
            sys.exit(1)

    def on_packet_received(self, features, dst_ip):
        self.packet_queue.put((features, dst_ip))

    def ai_worker_loop(self):
        logging.info("AI Background Worker Running...")
        while self.running:
            try:
                features, dst_ip = self.packet_queue.get(timeout=1.0)
                self.sessions[dst_ip].append(features)
                current_len = len(self.sessions[dst_ip])

                if current_len >= BATCH_SIZE:
                    buffer_to_analyze = self.sessions[dst_ip][:]
                    self.sessions[dst_ip] = []
                    self.analyze_batch(buffer_to_analyze, dst_ip)
                    
                self.packet_queue.task_done()
            except queue.Empty:
                continue

    def analyze_batch(self, buffer, ip_label):
        mining_result = self.miner.mine_patterns(buffer)
        if not mining_result: return
        
        pattern = mining_result['pattern']
        candidates = self.kb.search(pattern)
        label, conf = self.classifier.classify_traffic(pattern, candidates)

        print(f"\n   ██████████████████████████████████████")
        print(f"   █  TARGET: {ip_label}")
        print(f"   █  IDENTIFIED: {label}")
        print(f"   █  CONFIDENCE: {conf*100:.2f}%")
        print(f"   ██████████████████████████████████████\n")
        
        # KEY STEP: Send your AI results to his Database so the UI can see it!
        try:
            self.db.log_event(ip_label, "N/A", "N/A", pred=label, threat="Unknown")
        except Exception as e:
            pass # Failsafe if DB isn't ready yet

watcher_thread = Thread(target=start_pcap_watcher, daemon=True)
watcher_thread.start()

def start_backend():
    system = SystemController()
    system.start()

def start_frontend():
    logging.info("Launching UI...")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    # Modify this slightly if Streamlit is installed globally in his Docker
    subprocess.run([
        "streamlit", 
        "run", 
        "app/ui/dashboard.py", 
        "--server.port=8501", 
        "--server.address=0.0.0.0"
    ], env=env)

if __name__ == "__main__":
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()
    start_frontend()