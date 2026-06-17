import os
import logging
import psycopg2
from psycopg2 import pool
from psycopg2.extras import DictCursor
from typing import List, Optional, Dict, Any
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# ADD this class at the top or in a separate file
class DatabaseManager:
    """Handles thread-safe database operations using connection pooling."""
    
    def __init__(self):
        # Using connection pool for high-concurrency packet logging
        try:
            self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                1, 10,
                host=os.getenv("DB_HOST", "localhost"),
                database=os.getenv("DB_NAME", "tls_db"),
                user=os.getenv("DB_USER", "user"),
                password=os.getenv("DB_PASS", "pass")
            )
            self._create_schema()
        except Exception as e:
            logging.error(f"Could not connect to PostgreSQL: {e}")

    def _create_schema(self):
        """Initializes the database tables if they don't exist."""
        # 1. Update existing table to include dst_port
        query_events = """
        CREATE TABLE IF NOT EXISTS tls_events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            src_ip VARCHAR(45),
            dst_ip VARCHAR(45),
            dst_port INTEGER,
            ja3_hash VARCHAR(32),
            prediction VARCHAR(50),
            threat_level VARCHAR(20),
            sni VARCHAR(255),       
            confidence FLOAT
        );
        """
        # Try to add dst_port if the table already exists from earlier
        try:
            self.execute_query("ALTER TABLE tls_events ADD COLUMN dst_port INTEGER;")
            
        except:
            pass # Column already exists, ignore error
        try: self.execute_query("ALTER TABLE tls_events ADD COLUMN sni VARCHAR(255);")
        except: pass
        try: self.execute_query("ALTER TABLE tls_events ADD COLUMN confidence FLOAT;")
        except: pass
            
        # 2. Add System Logs table for the UI Console
        query_logs = """
        CREATE TABLE IF NOT EXISTS system_logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            level VARCHAR(20),
            component VARCHAR(50),
            message TEXT
        );
        """
        # 3. Add system_config (from our previous fix)
        query_config = """
        CREATE TABLE IF NOT EXISTS system_config (
            key VARCHAR(50) PRIMARY KEY,
            value TEXT
        );
        """
        self.execute_query(query_events)
        self.execute_query(query_logs)
        self.execute_query(query_config)

    def log_system_message(self, level, component, message):
        """Writes backend logs to Postgres so the UI can display them."""
        query = "INSERT INTO system_logs (level, component, message) VALUES (%s, %s, %s)"
        self.execute_query(query, (level, component, message))

    def log_event(self, src, dst, dst_port, ja3, pred="Analyzing", threat="Unknown",sni="Unknown", confidence=0.0):
        """Logs a single TLS event to the database (Updated to include port)."""
        query = "INSERT INTO tls_events (src_ip, dst_ip, dst_port, ja3_hash, prediction, threat_level, sni, confidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        self.execute_query(query, (src, dst, dst_port, ja3, pred, threat, sni, confidence))

    def execute_query(self, query, params=None):
        """Thread-safe query execution."""
        conn = self.connection_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                conn.commit()
        except Exception as e:
            logging.error(f"Database Query Error: {e}")
            conn.rollback()
        finally:
            self.connection_pool.putconn(conn)

    def set_config(self, key, value):
        query = """
    INSERT INTO system_config (key, value) VALUES (%s, %s)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
    """
        self.execute_query(query, (key, value))

    def get_config(self, key, default=None):
        query = "SELECT value FROM system_config WHERE key = %s"
    # Not: Bu kısım için fetch_one benzeri bir yardımcı metot gerekebilir 
    # veya doğrudan execute_query içinde sonuç döndüren bir yapı kullanılmalı.
        conn = self.connection_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(query, (key,))
                res = cur.fetchone()
            return res[0] if res else default
        finally:
            self.connection_pool.putconn(conn)

class KnowledgeBase:
    """
    PostgreSQL-based RAG (Retrieval-Augmented Generation) search module.
    Searches an 800k+ row fingerprint database to identify applications from TLS patterns.
    
    Features:
    - PostgreSQL connection pooling for high performance
    - Smart pattern matching with fallback logic
    - Filters out backend development libraries
    - Thread-safe connection management
    """
    
    # Development library filters to exclude from results
    DEV_LIBRARY_FILTERS = [
        '%node%', '%python%', '%jdk%', '%apache%', '%requests%',
        '%curl%', '%wget%', '%library%', '%sdk%', '%framework%',
        '%go%', '%rust%', '%java%', '%client%', '%agent%'
    ]
    
    def __init__(self, connection_pool: Optional[psycopg2.pool.SimpleConnectionPool] = None):
        """
        Initialize the KnowledgeBase with PostgreSQL connection.
        
        Args:
            connection_pool: Optional existing connection pool.
                           If not provided, creates a new one using environment variables.
        """
        self.connection_pool = connection_pool or self._create_connection_pool()
        self._validate_connection()
        
        logger.info("PostgreSQL RAG KnowledgeBase initialized")
    
    def _create_connection_pool(self) -> psycopg2.pool.SimpleConnectionPool:
        """
        Create a PostgreSQL connection pool using environment variables.
        
        Returns:
            psycopg2.pool.SimpleConnectionPool instance
            
        Raises:
            RuntimeError: If database connection fails
        """
        try:
            # Get database configuration from environment (Docker-friendly)
            db_config = {
                'host': os.getenv("DB_HOST", "localhost"),
                'database': os.getenv("DB_NAME", "tls_db"),
                'user': os.getenv("DB_USER", "user"),
                'password': os.getenv("DB_PASS", "pass"),
                'port': os.getenv("DB_PORT", "5432")
            }
            
            logger.info(f"Connecting to PostgreSQL: {db_config['host']}/{db_config['database']}")
            
            # Create connection pool
            pool_instance = psycopg2.pool.SimpleConnectionPool(
                minconn=1,  # Minimum connections
                maxconn=10,  # Maximum connections (adjust based on expected load)
                **db_config
            )
            
            return pool_instance
            
        except Exception as e:
            logger.error(f"Failed to create PostgreSQL connection pool: {e}")
            raise RuntimeError(f"Database connection failed: {e}")
    
    def _validate_connection(self):
        """Test the database connection and verify required tables exist."""
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cursor:
                    # Check if the signatures table exists
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_name = 'signatures'
                        );
                    """)
                    table_exists = cursor.fetchone()[0]
                    
                    if not table_exists:
                        logger.warning("'signatures' table not found in database")
                    else:
                        # Get table statistics
                        cursor.execute("SELECT COUNT(*) FROM signatures;")
                        row_count = cursor.fetchone()[0]
                        logger.info(f"KnowledgeBase loaded with {row_count:,} fingerprint records")
                        
        except Exception as e:
            logger.error(f"Database validation failed: {e}")
            raise
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for safe database connection handling.
        
        Yields:
            psycopg2 connection object
            
        Raises:
            RuntimeError: If connection pool is exhausted or connection fails
        """
        conn = None
        try:
            conn = self.connection_pool.getconn()
            yield conn
        except psycopg2.pool.PoolError as e:
            logger.error(f"Connection pool error: {e}")
            raise RuntimeError("Connection pool exhausted")
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def search(self, discovered_pattern: List[str]) -> List[str]:
        """
        Smart RAG search that iterates through discovered patterns to find matching applications.
        
        Args:
            discovered_pattern: List of TLS features (cipher suites, extensions, etc.)
            
        Returns:
            List of candidate application names (empty list if no matches found)
        """
        if not discovered_pattern:
            logger.warning("Empty pattern provided to RAG search")
            return []
        
        logger.debug(f"RAG search initiated for pattern: {discovered_pattern[:3]}...")
        
        # Extract cipher suites for targeted search
        cipher_suites = self._extract_cipher_suites(discovered_pattern)
        
        if not cipher_suites:
            logger.info("No cipher suites found in pattern for RAG search")
            return []
        
        logger.info(f"Searching for {len(cipher_suites)} cipher suites: {cipher_suites[:3]}...")
        
        # SMART LOOP: Try each cipher suite until we find matches
        for cipher in cipher_suites:
            candidates = self._search_cipher(cipher)
            if candidates:
                logger.info(f"RAG found {len(candidates)} matches for cipher: {cipher}")
                return candidates
        
        # No matches found for any cipher
        logger.info("RAG exhausted all ciphers. No matches found.")
        return []
    
    def _extract_cipher_suites(self, pattern: List[str]) -> List[str]:
        """
        Extract cipher suites from pattern for targeted search.
        
        Args:
            pattern: List of TLS features
            
        Returns:
            List of cipher suite strings
        """
        cipher_indicators = ['TLS_', 'SSL_', 'AES', 'CHACHA20', 'ECDHE', 'RSA_', 'DHE_']
        ciphers = []
        
        for item in pattern:
            item_upper = item.upper()
            # Check if this looks like a cipher suite
            if any(indicator in item_upper for indicator in cipher_indicators):
                # Extract just the cipher name (remove version info if present)
                cipher_name = item.split()[0] if ' ' in item else item
                ciphers.append(cipher_name)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_ciphers = []
        for cipher in ciphers:
            if cipher not in seen:
                seen.add(cipher)
                unique_ciphers.append(cipher)
        
        logger.debug(f"Extracted {len(unique_ciphers)} cipher suites")
        return unique_ciphers
    
    def _search_cipher(self, cipher: str) -> List[str]:
        """
        Search for applications using a specific cipher suite.
        
        Args:
            cipher: Cipher suite string to search for
            
        Returns:
            List of matching application names (empty if no matches)
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=DictCursor) as cursor:
                    # Build WHERE clause for development library exclusion
                    exclude_conditions = " AND ".join([
                        f"app_label NOT ILIKE %s"
                        for _ in self.DEV_LIBRARY_FILTERS
                    ])
                    
                    # Parameterized query with LIKE pattern matching
                    query = f"""
                        SELECT 
                            app_label, 
                            COUNT(*) as frequency,
                            STRING_AGG(DISTINCT ciphers, '; ') as cipher_list
                        FROM signatures
                        WHERE ciphers ILIKE %s
                        {('AND ' + exclude_conditions) if exclude_conditions else ''}
                        GROUP BY app_label
                        ORDER BY frequency DESC, app_label ASC
                        LIMIT 10
                    """
                    
                    # Prepare parameters
                    cipher_pattern = f'%{cipher}%'
                    params = [cipher_pattern] + self.DEV_LIBRARY_FILTERS
                    
                    cursor.execute(query, params)
                    results = cursor.fetchall()
                    
                    if results:
                        candidates = []
                        for row in results:
                            app_label = row['app_label']
                            frequency = row['frequency']
                            cipher_list = row['cipher_list']
                            
                            logger.debug(f"  {app_label}: {frequency} occurrences")
                            candidates.append(app_label)
                        
                        return candidates
                    else:
                        return []
                        
        except Exception as e:
            logger.error(f"Error searching for cipher '{cipher}': {e}")
            return []
    
    def advanced_search(self, pattern: List[str], min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        """
        Advanced RAG search with detailed scoring and confidence metrics.
        
        Args:
            pattern: List of TLS features
            min_confidence: Minimum confidence score (0.0 to 1.0)
            
        Returns:
            List of dictionaries with application details and confidence scores
        """
        cipher_suites = self._extract_cipher_suites(pattern)
        
        if not cipher_suites:
            return []
        
        try:
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=DictCursor) as cursor:
                    # Find all applications matching any of the ciphers
                    query = """
                        WITH cipher_matches AS (
                            SELECT 
                                app_label,
                                ciphers,
                                CASE 
                                    WHEN ciphers ILIKE ANY(%s) THEN 1
                                    ELSE 0
                                END as has_cipher
                            FROM signatures
                            WHERE app_label NOT ILIKE ANY(%s)
                        ),
                        scored_apps AS (
                            SELECT 
                                app_label,
                                COUNT(*) as total_records,
                                SUM(has_cipher) as matching_records,
                                ROUND(SUM(has_cipher)::DECIMAL / COUNT(*)::DECIMAL, 3) as confidence_score
                            FROM cipher_matches
                            GROUP BY app_label
                            HAVING SUM(has_cipher) > 0
                        )
                        SELECT 
                            app_label,
                            total_records,
                            matching_records,
                            confidence_score
                        FROM scored_apps
                        WHERE confidence_score >= %s
                        ORDER BY confidence_score DESC, total_records DESC
                        LIMIT 20
                    """
                    
                    # Prepare cipher patterns for ILIKE ANY
                    cipher_patterns = [f'%{cipher}%' for cipher in cipher_suites]
                    dev_filters = self.DEV_LIBRARY_FILTERS
                    
                    cursor.execute(query, (cipher_patterns, dev_filters, min_confidence))
                    results = cursor.fetchall()
                    
                    return [
                        {
                            'app_label': row['app_label'],
                            'total_records': row['total_records'],
                            'matching_records': row['matching_records'],
                            'confidence_score': float(row['confidence_score'])
                        }
                        for row in results
                    ]
                    
        except Exception as e:
            logger.error(f"Advanced search failed: {e}")
            return []
    
    def get_app_details(self, app_label: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific application.
        
        Args:
            app_label: Application name
            
        Returns:
            Dictionary with application details or None if not found
        """
        try:
            with self._get_connection() as conn:
                with conn.cursor(cursor_factory=DictCursor) as cursor:
                    query = """
                        SELECT 
                            app_label,
                            COUNT(*) as total_occurrences,
                            STRING_AGG(DISTINCT ciphers, '; ') as common_ciphers,
                            MIN(created_at) as first_seen,
                            MAX(created_at) as last_seen
                        FROM signatures
                        WHERE app_label = %s
                        GROUP BY app_label
                    """
                    
                    cursor.execute(query, (app_label,))
                    result = cursor.fetchone()
                    
                    if result:
                        return {
                            'app_label': result['app_label'],
                            'total_occurrences': result['total_occurrences'],
                            'common_ciphers': result['common_ciphers'].split('; ') if result['common_ciphers'] else [],
                            'first_seen': result['first_seen'],
                            'last_seen': result['last_seen']
                        }
                    else:
                        return None
                        
        except Exception as e:
            logger.error(f"Failed to get app details for '{app_label}': {e}")
            return None
    
    def cleanup(self):
        """Clean up database connections."""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("KnowledgeBase connection pool closed")


# Factory function for easy instantiation
def create_knowledge_base(connection_pool: Optional[psycopg2.pool.SimpleConnectionPool] = None) -> KnowledgeBase:
    """
    Factory function to create a KnowledgeBase instance.
    
    Args:
        connection_pool: Optional existing connection pool
        
    Returns:
        KnowledgeBase instance
    """
    return KnowledgeBase(connection_pool)


if __name__ == "__main__":
    # Test the RAG module
    print("=== Testing PostgreSQL RAG KnowledgeBase ===")
    
    try:
        # Create knowledge base
        kb = create_knowledge_base()
        
        # Test patterns
        test_patterns = [
            ["TLS_AES_128_GCM_SHA256", "server_name", "application_layer_protocol_negotiation"],
            ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "x25519"],
            ["TLS_CHACHA20_POLY1305_SHA256", "quic_transport_parameters"]
        ]
        
        for i, pattern in enumerate(test_patterns):
            print(f"\nTest Pattern {i+1}: {pattern}")
            candidates = kb.search(pattern)
            
            if candidates:
                print(f"  Found {len(candidates)} candidates:")
                for candidate in candidates[:5]:  # Show first 5
                    print(f"    - {candidate}")
                if len(candidates) > 5:
                    print(f"    ... and {len(candidates) - 5} more")
            else:
                print("  No candidates found")
        
        # Test advanced search
        print("\n=== Advanced Search Test ===")
        advanced_results = kb.advanced_search(test_patterns[0], min_confidence=0.1)
        if advanced_results:
            print(f"Found {len(advanced_results)} applications with confidence scores:")
            for result in advanced_results[:3]:
                print(f"  {result['app_label']}: {result['confidence_score']:.1%} confidence")
        
        # Clean up
        kb.cleanup()
        print("\n✅ RAG KnowledgeBase test completed successfully!")
        
    except Exception as e:
        print(f"\n❌ RAG KnowledgeBase test failed: {e}")