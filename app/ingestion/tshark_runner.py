import subprocess
import logging
from app.core.config_loader import Config

def start_continuous_capture():
    """Executes TShark with strict ring-buffer segmentation."""
    interface = Config().data['system']['interface']
    pcap_dir = Config().data['system']['pcap_directory']
    size_kb = Config().data['system'].get('tshark_file_size_kb', 1000)
    duration = Config().data['system'].get('tshark_duration_sec', 3) # Sihirli dokunuş
    
    # -b duration:3 komutu her 3 saniyede bir trafiği kesip Watcher'a atar
    command = [
        "tshark", "-i", interface, "-I", 
        "-f", "tcp port 443", 
        "-b", f"filesize:{size_kb}",
        "-b", f"duration:{duration}", 
        "-w", f"{pcap_dir}/traffic.pcap"
    ]
    logging.info(f"Initiating TShark Ring Buffer on {interface} (Rotating every {duration} seconds)...")
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)