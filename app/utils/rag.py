import os
import logging
import sqlite3
from typing import List, Optional, Dict, Any
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# THE FULL REVERSE MAP: Translates ALL strings back to the exact Decimal IDs your DB expects
# Translates Scapy (IANA) Strings to Database (OpenSSL) Strings
REVERSE_CIPHER_MAP = {
    "TLS_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
    "TLS_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
    "TLS_CHACHA20_POLY1305_SHA256": "CHACHA20-POLY1305-SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHE-RSA-AES128-SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": "ECDHE-RSA-AES256-SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": "ECDHE-ECDSA-AES256-SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": "ECDHE-ECDSA-AES128-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": "ECDHE-RSA-AES256-SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": "ECDHE-RSA-AES128-SHA256",
    "TLS_ECDSA_WITH_AES_256_CBC_SHA": "ECDH-ECDSA-AES256-SHA",
    "TLS_ECDSA_WITH_AES_128_CBC_SHA": "ECDH-ECDSA-AES128-SHA",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": "DHE-RSA-AES256-GCM-SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": "DHE-RSA-AES128-GCM-SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": "DHE-RSA-AES256-SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": "DHE-RSA-AES128-SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256": "AES256-SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "DES-CBC3-SHA",
    "TLS_RSA_WITH_DES_CBC_SHA": "DES-CBC-SHA"
}

class KnowledgeBase:
    DEV_LIBRARY_FILTERS = [
        '%node%', '%python%', '%jdk%', '%apache%', '%requests%',
        '%curl%', '%wget%', '%library%', '%sdk%', '%framework%',
        '%go%', '%rust%', '%java%', '%client%', '%agent%'
    ]
    
    def __init__(self, db_path: str = '/app/data/fingerprints.db'):
        self.db_path = db_path
        self._validate_connection()
    
    def _validate_connection(self):
        if not os.path.exists(self.db_path):
            logger.warning(f"Database file NOT FOUND at {self.db_path}")
            return
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='signatures'")
                if cursor.fetchone()[0] > 0:
                    cursor.execute("SELECT COUNT(*) FROM signatures")
                    logger.info(f"RAG DB ready with {cursor.fetchone()[0]:,} records")
        except Exception as e:
            logger.error(f"DB Error: {e}")

    @contextmanager
    def _get_connection(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row 
            yield conn
        finally:
            if conn:
                conn.close()

    def search(self, discovered_pattern: List[str], ja3: str = None, ja4: str = None) -> List[str]:
        all_candidates = []

        # TIER 1: Modern JA4 (Most stable in 2026)
        if ja4:
            all_candidates.extend(self._db_lookup("ja4_hash", ja4))
            if all_candidates:
                logger.info(f"🎯 RAG HIT: Modern JA4 Match -> {all_candidates[0]}")

        # TIER 2: Legacy JA3 (Salesforce/Trisul lists)
        if not all_candidates and ja3:
            all_candidates.extend(self._db_lookup("ja3_hash", ja3))
            if all_candidates:
                logger.info(f"RAG HIT: Legacy JA3 Match -> {all_candidates[0]}")

        # TIER 3: AI Inference Fallback (Pattern similarity - ŞİMDİ AKTİF!)
        if not all_candidates:
            logger.warning("RAG MISS: No hash hits. Falling back to AI pattern analysis.")
            
            # 1. Gelen paketin içinden şifreleme (cipher) listesini çıkar
            ciphers = self._extract_cipher_suites(discovered_pattern)
            
            # 2. Veritabanında bu şifrelemelere benzeyen (LIKE) uygulamaları ara
            for cipher in ciphers:
                # Eğer IANA formatındaysa OpenSSL'e çevir, değilse doğrudan ara
                mapped_cipher = REVERSE_CIPHER_MAP.get(cipher, cipher)
                matches = self._search_cipher(mapped_cipher)
                all_candidates.extend(matches)
                
            if all_candidates:
                logger.warning(" RAG HIT: Pattern Match Found (Semantic Search)")

        # Bulunan adayları frekansına göre (en çok eşleşenden en aza) sıralayıp ilk 10'unu döndür
        return list(dict.fromkeys(all_candidates))[:10] if all_candidates else []

    def _db_lookup(self, column, value):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT app_label FROM signatures WHERE {column} = ? LIMIT 5", (value,))
            return [row['app_label'] for row in cursor.fetchall()]
    
    def _extract_cipher_suites(self, pattern: List[str]) -> List[str]:
        cipher_indicators = ['TLS_', 'SSL_', 'AES', 'CHACHA20', 'ECDHE', 'RSA_', 'DHE_']
        ciphers = []
        for item in pattern:
            if any(ind in item.upper() for ind in cipher_indicators):
                ciphers.append(item.split()[0] if ' ' in item else item)
        return list(dict.fromkeys(ciphers))
    
    def _search_cipher(self, cipher: str) -> List[str]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                exclude_conditions = " AND ".join(["app_label NOT LIKE ?" for _ in self.DEV_LIBRARY_FILTERS])
                
                query = f"""
                    SELECT app_label, COUNT(*) as frequency 
                    FROM signatures
                    WHERE ciphers LIKE ?
                    AND {exclude_conditions}
                    GROUP BY app_label
                    ORDER BY frequency DESC LIMIT 10
                """
                
                params = [f'%{cipher}%'] + self.DEV_LIBRARY_FILTERS
                cursor.execute(query, params)
                results = cursor.fetchall()
                
                return [row['app_label'] for row in results] if results else []
        except Exception as e:
            return []

    def advanced_search(self, pattern: List[str], min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        return []

    def cleanup(self):
        pass

def create_knowledge_base() -> KnowledgeBase:
    return KnowledgeBase()