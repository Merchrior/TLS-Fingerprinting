import hashlib
import json
from pathlib import Path
from typing import Dict, List
import logging
import hashlib
import re

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP
from scapy.layers.tls.all import TLSClientHello

# THE SOURCE OF TRUTH: Maps decimal/hex from Scapy to the exact strings in your 3GB Database
CIPHER_MAP = {
    # TLS 1.3 Ciphers
    4865: "TLS_AES_128_GCM_SHA256",            # 0x1301
    4866: "TLS_AES_256_GCM_SHA384",            # 0x1302
    4867: "TLS_CHACHA20_POLY1305_SHA256",      # 0x1303
    
    # TLS 1.2 ECDHE Ciphers (The ones in your logs!)
    49195: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", # 0xc02b
    49196: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", # 0xc02c
    49199: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   # 0xc02f
    49200: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   # 0xc030
    52392: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", # 0xcca9
    52393: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",   # 0xcca8
    49171: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      # 0xc013
    49172: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      # 0xc014

    49188: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", # 0xc024
    49187: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", # 0xc023
    49192: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   # 0xc028
    49191: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   # 0xc027
    49162: "TLS_ECDSA_WITH_AES_256_CBC_SHA",          # 0xc00a
    49161: "TLS_ECDSA_WITH_AES_128_CBC_SHA",          # 0xc009
    159:   "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",     # 0x9f
    158:   "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",     # 0x9e
    107:   "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",     # 0x6b
    103:   "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",     # 0x67
    61:    "TLS_RSA_WITH_AES_256_CBC_SHA256",         # 0x3d
    60:    "TLS_RSA_WITH_AES_128_CBC_SHA256",         # 0x3c
    
    # Older Fallback Ciphers
    156: "TLS_RSA_WITH_AES_128_GCM_SHA256",           # 0x9c
    157: "TLS_RSA_WITH_AES_256_GCM_SHA384",           # 0x9d
    47:  "TLS_RSA_WITH_AES_128_CBC_SHA",              # 0x2f
    53:  "TLS_RSA_WITH_AES_256_CBC_SHA",              # 0x35
    10:  "TLS_RSA_WITH_3DES_EDE_CBC_SHA",             # 0x0a
    9:   "TLS_RSA_WITH_DES_CBC_SHA"                   # 0x09
}

# GREASE values - We ignore these!
GREASE = {2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250}

def md5hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()

def process_pcap_file(pcap_file: str) -> List[Dict]:
    pcap_path = Path(pcap_file)
    if not pcap_path.exists():
        return []

    records = []
    try:
        packets = rdpcap(str(pcap_path))
        
        for pkt in packets:
            if pkt.haslayer(TLSClientHello) and pkt.haslayer(IP) and pkt.haslayer(TCP):
                hello = pkt[TLSClientHello]
                
                # 1. Extract and Translate Ciphers safely
                ciphers = []
                if hasattr(hello, 'ciphers'):
                    for c in hello.ciphers:
                        if c in GREASE:
                            continue
                        # Use our hardcoded map. If it's missing, output the hex so we can add it later.
                        ciphers.append(CIPHER_MAP.get(c, hex(c)))
                        
                # 2. Extract and Clean Extensions
                # 2. Extract and Clean Extensions
                exts = []
                sni_value = "Unknown"
                
                if hasattr(hello, 'ext'):
                    for ext in hello.ext:
                        raw_name = str(getattr(ext, 'name', ''))
                        if "Scapy Unknown" in raw_name or "GREASE" in raw_name:
                            continue
                            
                        clean_name = raw_name.replace("TLS Extension - ", "").split(" (")[0].strip().lower().replace(" ", "_")
                        exts.append(clean_name)
                        
                        # 🚀 KESİN ÇÖZÜM: ID (0), boşluklu isim ve alt tireli ismi aynı anda kontrol et!
                        if getattr(ext, 'type', -1) == 0 or "server name" in raw_name.lower() or "server_name" in clean_name:
                            try:
                                # Yöntem 1: Standart Scapy Objesinden Oku
                                if hasattr(ext, 'servernames') and len(ext.servernames) > 0:
                                    s_raw = ext.servernames[0].servername
                                    sni_value = s_raw.decode('utf-8', errors='ignore') if isinstance(s_raw, bytes) else str(s_raw)
                                    
                                # Yöntem 2: (Fallback) Eğer obje eksikse, direkt baytların (hex) içinde Domain formatı ara
                                if sni_value == "Unknown" or sni_value == "":
                                    import re
                                    raw_bytes = bytes(ext)
                                    match = re.search(rb'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', raw_bytes)
                                    if match:
                                        sni_value = match.group(1).decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                            
                discovered_pattern = ciphers + exts
                ja3_raw = "-".join([str(c) for c in (getattr(hello, 'ciphers', []))])
                
                
                records.append({
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "dst_port": pkt[TCP].dport,
                    "tls_version": str(getattr(hello, 'version', 'Unknown')),
                    "ja3_hash": md5hex(ja3_raw),
                    "ja4_hash": generate_ja4(hello),
                    "discovered_pattern": discovered_pattern,
                    "raw_metadata": json.dumps({"pattern": discovered_pattern}),
                    "sni": sni_value
                })
    
                
    except Exception as e:
        logging.error(f"Error parsing PCAP: {e}")
        
    return records

def generate_ja4(hello, protocol="t"):
    # GREASE values to ignore
    GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 
              0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

    ciphers = [c for c in getattr(hello, 'ciphers', []) if c not in GREASE]
    
    # Extract clean extension names directly to check for SNI and ALPN
    ext_types = []
    has_sni = False
    alpn_val = "00"
    
    for ext in getattr(hello, 'ext', []):
        if ext.type in GREASE: continue
        ext_types.append(ext.type)
        
        raw_name = str(ext.name).lower()
        if "server_name" in raw_name or "server name" in raw_name:
            has_sni = True
        if "alpn" in raw_name or "application_layer_protocol" in raw_name:
            try:
                alpn_val = ext.alpn_protocols[0].decode()[:2]
            except: pass

    # TLS 1.3 is often negotiated via the 'supported_versions' extension (type 43)
    is_tls13 = any(e == 43 for e in ext_types)
    ver = "13" if is_tls13 else "12"
    sni = "d" if has_sni else "i"

    part_a = f"{protocol}{ver}{sni}{len(ciphers):02d}{len(ext_types):02d}{alpn_val}"

    # Sorted Ciphers
    cipher_hex = ",".join([f"{c:04x}" for c in sorted(ciphers)])
    part_b = hashlib.sha256(cipher_hex.encode()).hexdigest()[:12]

    # Sorted Extensions
    ext_hex = ",".join([f"{e:04x}" for e in sorted(ext_types)])
    part_c = hashlib.sha256(ext_hex.encode()).hexdigest()[:12]

    return f"{part_a}_{part_b}_{part_c}"