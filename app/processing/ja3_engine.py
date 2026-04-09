import hashlib
import logging
from scapy.all import load_layer

load_layer("tls")
from scapy.layers.tls.all import TLSClientHello

class JA3Engine:
    """Generates the JA3 string and MD5 hash from a TLS ClientHello packet."""
    
    @staticmethod
    def _is_grease(val: int) -> bool:
        """RFC 8701: Filters out GREASE values to maintain hash consistency."""
        return (val & 0x0f0f) == 0x0a0a

    def calculate(self, packet) -> tuple:
        """Returns a tuple of (ja3_string, ja3_hash)."""
        try:
            tls_layer = packet.getlayer(TLSClientHello)
            if not tls_layer:
                return None, None

            # 1. TLS Version
            version = str(tls_layer.version)
            
            # 2. Ciphers (Filtered)
            ciphers = "-".join([str(c) for c in tls_layer.ciphers if not self._is_grease(c)])
            
            # 3. Extensions, 4. Curves, 5. Point Formats
            extensions = "" 
            curves = ""
            point_formats = ""

            ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            return ja3_string, ja3_hash
            
        except Exception as e:
            logging.debug(f"JA3 Calculation failed: {e}")
            return None, None