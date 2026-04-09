import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from app.core.config_loader import Config
from app.processing.packet_parser import process_pcap_file

class PcapHandler(FileSystemEventHandler):
    """Event handler for directory monitoring."""
    def on_closed(self, event):
        if event.src_path.endswith(".pcap"):
            logging.info(f"New PCAP segmentation ready: {event.src_path}")
            process_pcap_file(event.src_path)

def start_watcher():
    """Starts the watchdog observer on the PCAP directory."""
    path = Config().data['system']['pcap_directory']
    os.makedirs(path, exist_ok=True)
    
    event_handler = PcapHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    logging.info(f"Watcher Module active on directory: {path}")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()