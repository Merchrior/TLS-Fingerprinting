import sys
import os
import logging
import hashlib
from scapy.all import sniff, load_layer, IP

# Suppress Scapy Warnings (Cleaner Console)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Load TLS support
load_layer("tls")
# Add to app/utils/db_handler.py (or separate file)

from scapy.layers.tls.handshake import TLSClientHello
try:
    # Scapy 2.5.0+
    from scapy.layers.tls.crypto.suites import _tls_cipher_suites_cls as cipher_suites
except ImportError:
    # Older Scapy versions
    from scapy.layers.tls.crypto.suites import cipher_suites

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- THE TRANSLATOR (IANA Standard IDs) ---
# This ensures we always get a String, not a Hex number.
CIPHER_MAP = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    # TLS 1.2 (ECDHE)
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # TLS 1.2 (RSA - Older)
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
}

class JA3Processor:
    """Encapsulates the logic for JA3 fingerprint generation."""
    
    @staticmethod
    def _is_grease(val):
        """Filters out GREASE values as per RFC 8701."""
        return (val & 0x0f0f) == 0x0a0a

    def get_hash(self, packet):
        """Generates a JA3 MD5 hash from a TLS Client Hello packet."""
        try:
            tls_layer = packet[TLSClientHello]
            
            # 1. SSL/TLS Version
            version = str(tls_layer.version)
            
            # 2. Accepted Ciphers (excluding GREASE)
            ciphers = "-".join([str(c) for c in tls_layer.ciphers if not self._is_grease(c)])
            
            # 3. Extensions, 4. Elliptic Curves, 5. EC Point Formats
            # Note: Production parsing requires iterating through tls_layer.extensions
            extensions = "" 
            curves = ""
            point_formats = ""

            ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
            return hashlib.md5(ja3_string.encode()).hexdigest()
        except Exception as e:
            logging.debug(f"Parsing failed: {e}")
            return None

def extract_features(packet):
    """
    Turns a raw Scapy packet into a list of feature strings for the AI.
    Returns: (features, dst_ip) or (None, None)
    """
    try:
        if packet.haslayer(TLSClientHello):
            layer = packet[TLSClientHello]
            features = []
            
            # 1. Get Destination IP
            dst_ip = packet[IP].dst if packet.haslayer(IP) else None
            packet_size = len(packet)
            
            # 2. Extract Ciphers (With Translation)
            if hasattr(layer, 'ciphers'):
                for val in layer.ciphers:
                    # Check our manual map first
                    if val in CIPHER_MAP:
                        features.append(CIPHER_MAP[val])
                    else:
                        # Fallback to Scapy internal logic or Hex
                        try:
                            name = cipher_suites.get(val, hex(val))
                            if hasattr(name, 'name'):
                                features.append(name.name)
                            else:
                                features.append(str(name))
                        except:
                            features.append(hex(val))

            # 3. Extract Extensions
            if hasattr(layer, 'extensions'):
                for ext in layer.extensions:
                    features.append(ext.name)
                    
            return features, dst_ip
            
    except Exception as e:
        logging.debug(f"[Extractor Error] {e}")
        return None, None

    return None, None

class NetworkSniffer:
    # Notice we removed db_manager and predictor from __init__
    def __init__(self, callback):
        self.callback = callback # This will be system.on_packet_received from main.py

    def _packet_callback(self, packet):
        """Enhanced packet callback with full feature extraction."""
        if packet.haslayer(TLSClientHello):
            features, dst_ip = extract_features(packet)
            
            if features and dst_ip:
                # Send the raw data back to main.py to handle the queue!
                self.callback(features, dst_ip)

def start_sniffer(interface, callback):
    """The entry point called by main.py"""
    if interface is None or interface == "any":
        import platform
        system = platform.system()
        if system == "Darwin":  
            interface = "en0"
        elif system == "Windows":
            interface = "Wi-Fi"
        else:  
            interface = "eth0"
            
    logging.info(f"Enhanced TLS Sniffer active on {interface}...")
    
    sniffer = NetworkSniffer(callback)
    sniff(iface=interface, prn=sniffer._packet_callback, store=0, filter="tcp")