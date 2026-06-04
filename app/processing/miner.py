"""
FP-Growth Pattern Miner for TLS Fingerprint Analysis

This module uses the FP-Growth algorithm to identify significant patterns in TLS traffic.
It processes batches of packets to find stable fingerprints that can identify applications.

Designed for Dockerized production environments with no local path dependencies.
"""

import logging
from typing import List, Dict, Any, Optional, Union
import pandas as pd
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import fpgrowth

# Configure module-level logger
logger = logging.getLogger(__name__)


class PatternMiner:
    """
    Pattern miner that uses FP-Growth algorithm to identify significant TLS patterns.
    
    This class processes batches of raw traffic data to find the most frequent
    and stable patterns that can be used for application identification.
    
    Attributes:
        min_support (float): Minimum support threshold (0.0 to 1.0).
                            Default 0.5 means pattern must appear in at least 50%
                            of the traffic to be considered significant.
        logger (logging.Logger): Logger instance for this miner.
    """
    
    def __init__(self, min_support: float = 0.5):
        """
        Initialize the PatternMiner with configuration.
        
        Args:
            min_support: The pattern must appear in at least this percentage
                        of the traffic to be considered "Significant".
                        This filters out random noise and transient patterns.
                        Range: 0.0 to 1.0.
                        
        Raises:
            ValueError: If min_support is not between 0.0 and 1.0
        """
        if not 0.0 <= min_support <= 1.0:
            raise ValueError(f"min_support must be between 0.0 and 1.0, got {min_support}")
        
        self.min_support = min_support
        self.logger = logger
        
        self.logger.info(
            f"PatternMiner initialized with min_support={min_support} "
            f"(pattern must appear in at least {min_support*100:.0f}% of traffic)"
        )
    
    def mine_patterns(self, raw_traffic_buffer: List[List[str]]) -> Optional[Dict[str, Any]]:
        """
        Mine the most dominant pattern from a batch of traffic data.
        
        This method processes raw packet data using FP-Growth algorithm
        to find the single most significant pattern.
        
        Args:
            raw_traffic_buffer: List of lists containing feature sets from raw packets.
                               Each inner list represents features from one packet.
                               Example: [
                                   ["TLS_AES_128_GCM_SHA256", "server_name"],
                                   ["TLS_AES_128_GCM_SHA256", "application_layer_protocol_negotiation"],
                                   ...
                               ]
        
        Returns:
            Dictionary containing pattern details or None if no significant pattern found:
            {
                "pattern": List[str] - The most dominant pattern (list of feature strings),
                "confidence": float - Support score (0.0 to 1.0)
            }
            Returns None if:
                - Input is empty
                - No patterns meet min_support threshold
                - No valid patterns with length >= 2
        
        Raises:
            ValueError: If raw_traffic_buffer is empty or invalid
        """
        # Validate input
        if not raw_traffic_buffer:
            self.logger.warning("PatternMiner received empty traffic buffer")
            return None
        
        if not isinstance(raw_traffic_buffer, list) or not isinstance(raw_traffic_buffer[0], list):
            raise ValueError(
                f"raw_traffic_buffer must be list of lists, got {type(raw_traffic_buffer)}"
            )
        
        self.logger.info(
            f"Processing traffic buffer with {len(raw_traffic_buffer)} packets, "
            f"average features per packet: {sum(len(p) for p in raw_traffic_buffer)/len(raw_traffic_buffer):.1f}"
        )
        
        try:
            # Step 1: One-Hot Encoding
            # Convert list data into a True/False matrix for the algorithm
            te = TransactionEncoder()
            te_ary = te.fit(raw_traffic_buffer).transform(raw_traffic_buffer)
            df = pd.DataFrame(te_ary, columns=te.columns_)
            
            # Log encoding statistics
            self.logger.debug(
                f"Encoded {df.shape[0]} transactions with {df.shape[1]} unique features"
            )
            
            # Step 2: Run FP-Growth Algorithm
            # use_colnames=True gives us feature names like 'x25519' instead of column indices
            frequent_patterns = fpgrowth(
                df, 
                min_support=self.min_support, 
                use_colnames=True
            )
            
            if frequent_patterns.empty:
                self.logger.info(
                    f"No patterns found with minimum support of {self.min_support}"
                )
                return None
            
            self.logger.info(
                f"Found {len(frequent_patterns)} candidate patterns "
                f"with support >= {self.min_support}"
            )
            
            # Step 3: Filter "Rich" Patterns
            # We want patterns that contain at least 2 items (e.g., Cipher + Extension).
            # A pattern of 1 item is too generic to identify an application.
            frequent_patterns['length'] = frequent_patterns['itemsets'].apply(lambda x: len(x))
            valid_patterns = frequent_patterns[frequent_patterns['length'] >= 2]
            
            if valid_patterns.empty:
                self.logger.info(
                    "No patterns found with at least 2 features (filtering out generic patterns)"
                )
                return None
            
            self.logger.info(
                f"Filtered to {len(valid_patterns)} patterns with at least 2 features"
            )
            
            # Step 4: Sort by Support (Frequency) and Length
            # We want the most frequent, longest pattern for maximum confidence.
            valid_patterns = valid_patterns.sort_values(
                by=['support', 'length'], 
                ascending=[False, False]
            )
            
            # Extract the top result
            top_itemset = list(valid_patterns.iloc[0]['itemsets'])
            support_score = float(valid_patterns.iloc[0]['support'])
            
            # Log top patterns for debugging
            if self.logger.isEnabledFor(logging.DEBUG):
                top_n = min(5, len(valid_patterns))
                self.logger.debug(f"Top {top_n} patterns:")
                for i in range(top_n):
                    pattern = valid_patterns.iloc[i]
                    self.logger.debug(
                        f"  {i+1}. Support: {pattern['support']:.3f}, "
                        f"Length: {pattern['length']}, "
                        f"Pattern: {list(pattern['itemsets'])}"
                    )
            
            # Build result
            result = {
                "pattern": top_itemset,
                "confidence": support_score,
                "metadata": {
                    "total_packets": len(raw_traffic_buffer),
                    "pattern_length": len(top_itemset),
                    "support_percentage": support_score * 100
                }
            }
            
            self.logger.info(
                f"Discovered dominant pattern with {len(top_itemset)} features, "
                f"confidence: {support_score:.1%} "
                f"({int(support_score * len(raw_traffic_buffer))}/{len(raw_traffic_buffer)} packets)"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Pattern mining failed: {e}", exc_info=True)
            return None
    
    def analyze_patterns(self, raw_traffic_buffer: List[List[str]]) -> Dict[str, Any]:
        """
        Extended pattern analysis with detailed statistics.
        
        This method provides comprehensive analysis including:
        - Top N patterns
        - Pattern distribution
        - Feature frequency statistics
        
        Args:
            raw_traffic_buffer: List of lists containing feature sets from raw packets.
        
        Returns:
            Dictionary with detailed pattern analysis
        """
        if not raw_traffic_buffer:
            return {"error": "Empty traffic buffer"}
        
        try:
            # One-Hot Encoding
            te = TransactionEncoder()
            te_ary = te.fit(raw_traffic_buffer).transform(raw_traffic_buffer)
            df = pd.DataFrame(te_ary, columns=te.columns_)
            
            # Get frequent patterns with a lower threshold for comprehensive analysis
            frequent_patterns = fpgrowth(
                df, 
                min_support=0.1,  # Lower threshold for comprehensive analysis
                use_colnames=True
            )
            
            if frequent_patterns.empty:
                return {"analysis": "No frequent patterns found"}
            
            # Calculate additional metrics
            frequent_patterns['length'] = frequent_patterns['itemsets'].apply(lambda x: len(x))
            
            # Calculate feature frequencies
            feature_freq = df.sum().sort_values(ascending=False)
            
            # Build analysis result
            analysis = {
                "summary": {
                    "total_packets": len(raw_traffic_buffer),
                    "unique_features": len(feature_freq),
                    "patterns_found": len(frequent_patterns)
                },
                "top_patterns": [
                    {
                        "pattern": list(row['itemsets']),
                        "support": float(row['support']),
                        "length": int(row['length'])
                    }
                    for idx, row in frequent_patterns.head(10).iterrows()
                ],
                "feature_frequency": {
                    feature: int(freq)
                    for feature, freq in feature_freq.head(20).items()
                },
                "statistics": {
                    "avg_pattern_length": float(frequent_patterns['length'].mean()),
                    "max_support": float(frequent_patterns['support'].max()),
                    "min_support": float(frequent_patterns['support'].min())
                }
            }
            
            self.logger.info(
                f"Pattern analysis completed: {analysis['summary']['patterns_found']} patterns, "
                f"{analysis['summary']['unique_features']} unique features"
            )
            
            return {"analysis": analysis}
            
        except Exception as e:
            self.logger.error(f"Pattern analysis failed: {e}", exc_info=True)
            return {"error": f"Analysis failed: {str(e)}"}


# Factory function for easy instantiation
def create_pattern_miner(min_support: float = 0.5) -> PatternMiner:
    """
    Factory function to create a PatternMiner instance.
    
    Args:
        min_support: Minimum support threshold (0.0 to 1.0).
        
    Returns:
        PatternMiner instance
    """
    return PatternMiner(min_support=min_support)


# For backwards compatibility
PatternMiner = PatternMiner


if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=== Testing PatternMiner Module ===")
    
    try:
        # Create miner
        miner = create_pattern_miner(min_support=0.4)
        
        # Test data
        test_traffic = [
            ["TLS_AES_128_GCM_SHA256", "server_name", "application_layer_protocol_negotiation"],
            ["TLS_AES_128_GCM_SHA256", "server_name", "x25519"],
            ["TLS_AES_128_GCM_SHA256", "server_name", "application_layer_protocol_negotiation"],
            ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "x25519"],
            ["TLS_AES_128_GCM_SHA256", "server_name", "application_layer_protocol_negotiation"],
        ]
        
        print(f"\nProcessing {len(test_traffic)} test packets...")
        
        # Test pattern mining
        result = miner.mine_patterns(test_traffic)
        
        if result:
            print(f"\n✅ Pattern discovered:")
            print(f"  Features: {result['pattern']}")
            print(f"  Confidence: {result['confidence']:.1%}")
            print(f"  Length: {len(result['pattern'])} features")
            print(f"  Metadata: {result.get('metadata', {})}")
        else:
            print("\n❌ No significant pattern found")
        
        # Test extended analysis
        print("\n=== Extended Analysis Test ===")
        analysis = miner.analyze_patterns(test_traffic)
        
        if "analysis" in analysis:
            summary = analysis["analysis"]["summary"]
            print(f"Analysis Summary:")
            print(f"  Packets: {summary['total_packets']}")
            print(f"  Unique Features: {summary['unique_features']}")
            print(f"  Patterns Found: {summary['patterns_found']}")
        
        print("\n✅ PatternMiner test completed successfully!")
        
    except Exception as e:
        print(f"\n❌ PatternMiner test failed: {e}")
        import traceback
        traceback.print_exc()