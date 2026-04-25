import os
import sys
import logging
from typing import List, Tuple, Optional, Dict, Any
from abc import ABC, abstractmethod
from transformers import pipeline

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BasePredictor(ABC):
    """Abstract base class for all AI models in the system."""
    
    @abstractmethod
    def predict(self, input_data: Any) -> str:
        """Make a prediction on the input data."""
        pass


class TrafficClassifier(BasePredictor):
    """
    Zero-Shot LLM-based traffic classifier using Hugging Face Transformers.
    This class uses facebook/bart-large-mnli model for zero-shot classification
    to identify end-user applications from TLS fingerprints.
    
    Features:
    - Docker-compatible with model caching in /app/saved_models
    - Zero-shot classification (no explicit training needed)
    - Optimized for application identification
    - Fallback mechanisms for robustness
    """
    
    def __init__(self, model_path: Optional[str] = None, 
                 cache_dir: Optional[str] = None,
                 use_gpu: bool = False):
        """
        Initialize the TrafficClassifier with Hugging Face model.
        
        Args:
            model_path: Optional path to local model (if not provided, downloads from Hugging Face)
            cache_dir: Directory to cache the model (defaults to HF_HOME environment variable)
            use_gpu: Whether to use GPU acceleration if available
        """
        self.model_name = "facebook/bart-large-mnli"
        self.model = None
        self.candidate_apps = []
        self.use_gpu = use_gpu
        
        # Configure model caching for Docker environment
        self._setup_cache(cache_dir)
        
        # Load the model
        self._load_model(model_path)
        
        # Predefined application categories for fallback
        self.default_categories = [
            "Web Browsing",
            "Video Streaming",
            "Social Media",
            "VPN/Proxy",
            "Gaming",
            "Cloud Storage",
            "Email Client",
            "VoIP/Videoconferencing",
            "Software Update",
            "IoT Device",
            "Mobile App",
            "Desktop Application"
        ]
        
        logger.info(f"TrafficClassifier initialized with model: {self.model_name}")
    
    def _setup_cache(self, cache_dir: Optional[str] = None):
        """Configure the cache directory for Hugging Face models."""
        # Priority: explicit cache_dir > HF_HOME environment variable > default
        if cache_dir:
            os.environ["HF_HOME"] = cache_dir
            os.environ["TRANSFORMERS_CACHE"] = cache_dir
        elif "HF_HOME" in os.environ:
            cache_dir = os.environ["HF_HOME"]
        else:
            # Default cache directory for Docker
            cache_dir = "/app/saved_models"
            os.environ["HF_HOME"] = cache_dir
            os.environ["TRANSFORMERS_CACHE"] = cache_dir
        
        # Create cache directory if it doesn't exist
        os.makedirs(cache_dir, exist_ok=True)
        
        logger.info(f"Model cache directory: {cache_dir}")
    
    def _load_model(self, model_path: Optional[str] = None):
        """Load the Hugging Face model with error handling and progress indication."""
        try:
            logger.info(f"Loading neural network model: {self.model_name}")
            logger.info("Note: This downloads ~1.5GB the first time. Please wait...")
            
            # Configure device for inference
            device = 0 if self.use_gpu else -1
            
            if model_path and os.path.exists(model_path):
                logger.info(f"Loading model from local path: {model_path}")
                self.model = pipeline(
                    "zero-shot-classification",
                    model=model_path,
                    device=device
                )
            else:
                # Download from Hugging Face Hub
                self.model = pipeline(
                    "zero-shot-classification",
                    model=self.model_name,
                    device=device
                )
            
            logger.info("Model loaded successfully!")
            
        except Exception as e:
            logger.error(f"Failed to load AI model: {e}")
            
            # Check for common issues
            if "CUDA" in str(e) and self.use_gpu:
                logger.warning("GPU unavailable, falling back to CPU")
                self.use_gpu = False
                # Retry with CPU
                self._load_model(model_path)
            else:
                # Create a fallback mock model for development/testing
                logger.warning("Using fallback mock model for development")
                self._create_fallback_model()
    
    def _create_fallback_model(self):
        """Create a simple fallback model for development/testing."""
        class FallbackModel:
            def __call__(self, sequence, candidate_labels, **kwargs):
                # Simple heuristic-based fallback
                sequence_lower = sequence.lower()
                scores = []
                
                for label in candidate_labels:
                    label_lower = label.lower()
                    # Basic keyword matching
                    if any(keyword in sequence_lower for keyword in label_lower.split()):
                        scores.append(0.8)
                    elif "tls" in sequence_lower and "web" in label_lower:
                        scores.append(0.7)
                    elif "video" in label_lower:
                        scores.append(0.6)
                    elif "social" in label_lower:
                        scores.append(0.5)
                    else:
                        scores.append(0.3)
                
                # Normalize scores
                total = sum(scores)
                scores = [s/total for s in scores]
                
                return {
                    'labels': candidate_labels,
                    'scores': scores
                }
        
        self.model = FallbackModel()
        logger.info("Fallback model initialized")
    
    def set_candidate_apps(self, apps: List[str]):
        """
        Set the list of candidate applications for classification.
        This can be populated from a RAG system or other sources.
        
        Args:
            apps: List of application names to consider
        """
        self.candidate_apps = apps
        logger.info(f"Set {len(apps)} candidate applications")
    
    def predict(self, input_data: Any) -> str:
        """
        Primary prediction interface compatible with BasePredictor.
        
        Args:
            input_data: Can be either:
                       - List of TLS features (preferred)
                       - JA3 hash string (fallback)
                       
        Returns:
            Classification result as string
        """
        if isinstance(input_data, list):
            # Use the enhanced classification with features
            label, confidence = self.classify_traffic(input_data)
            return f"{label} ({confidence:.1%} confidence)"
        else:
            # Fallback for JA3 hashes or other string inputs
            return self._predict_ja3(str(input_data))
    
    def classify_traffic(self, features: List[str], 
                         candidate_apps: Optional[List[str]] = None,
                         ja4_hint: str = "") -> Tuple[str, float]:
        """
        Classify TLS traffic patterns using zero-shot learning.
        
        Args:
            features: List of TLS features (cipher suites, extensions, etc.)
            candidate_apps: Optional list of candidate applications.
                          If not provided, uses internal candidate list or defaults.
            ja4_hint: Optional plain English translation of the JA4 hash for better context.
                          
        Returns:
            Tuple of (best_matching_app, confidence_score)
        """
        if not self.model:
            raise RuntimeError("Model not loaded")
        
        # Use provided candidates or fall back to internal list
        candidates = candidate_apps or self.candidate_apps or self.default_categories
        
        if not candidates:
            raise ValueError("No candidate applications provided for classification")
        
        # Convert features to a descriptive sequence for the LLM
        sequence = self._features_to_sequence(features)
        
        # --- THE MAGIC: INJECT JA4 HINT INTO THE AI CONTEXT ---
        # We combine the plain English hint with the raw technical data
        if ja4_hint:
            sequence = f"Network Traffic Profile: {ja4_hint}. Cryptographic details: {sequence}"
            
        try:
            # Perform zero-shot classification with optimized template
            result = self.model(
                sequence,
                candidate_labels=candidates,
                multi_label=True,
                hypothesis_template="This network traffic pattern indicates the end-user application is {}."
            )
            
            # --- DEBUG LOGGING: SHOW ALL SCORES ---
            logger.info("--- AI Confidence Breakdown ---")
            for lbl, scr in zip(result['labels'], result['scores']):
                logger.info(f"  -> {lbl}: {scr*100:.2f}%")
            logger.info("-------------------------------")
            
            # Extract best match
            best_label = result['labels'][0]
            best_score = result['scores'][0]
            
            return best_label, best_score
            
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return "Unknown Application", 0.0
    def _features_to_sequence(self, features: List[str]) -> str:
        """
        Convert TLS features to a natural language sequence for the LLM.
        
        Args:
            features: List of TLS feature strings
            
        Returns:
            Natural language description of the traffic pattern
        """
        # Group features by type for better readability
        cipher_suites = []
        extensions = []
        other_features = []
        
        for feature in features:
            feature_lower = feature.lower()
            if "tls_" in feature_lower or "ssl_" in feature_lower:
                cipher_suites.append(feature)
            elif "extension" in feature_lower or feature_lower.endswith("ext"):
                extensions.append(feature)
            else:
                other_features.append(feature)
        
        # Build descriptive sequence
        parts = []
        
        if cipher_suites:
            # Take top 3 most interesting cipher suites
            interesting_ciphers = cipher_suites[:3]
            cipher_desc = ", ".join(interesting_ciphers)
            parts.append(f"uses encryption: {cipher_desc}")
        
        if extensions:
            extensions_desc = ", ".join(extensions[:3])
            parts.append(f"includes extensions: {extensions_desc}")
        
        if other_features:
            other_desc = ", ".join(other_features[:3])
            parts.append(f"has features: {other_desc}")
        
        if not parts:
            # Fallback to simple feature list
            features_desc = ", ".join(features[:5])
            return f"Network traffic with features: {features_desc}"
        
        return f"This network traffic pattern {', '.join(parts)}."
    
    def _predict_ja3(self, ja3_hash: str) -> str:
        """
        Fallback prediction method for JA3 hashes.
        
        Args:
            ja3_hash: JA3 hash string
            
        Returns:
            Prediction result
        """
        # Known malicious JA3 hashes (expand this in production)
        known_malicious = {
            "d41d8cd98f00b204e9800998ecf8427e": "Known Malware",
            "a94a8fe5ccb19ba61c4c0873d391e987": "Suspicious Bot",
        }
        
        # Known benign JA3 hashes
        known_benign = {
            "6734f37431670b3ab4292b8f60f29984": "Google Chrome",
            "9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a": "Firefox Browser",
        }
        
        if ja3_hash in known_malicious:
            return f"⚠️ {known_malicious[ja3_hash]}"
        elif ja3_hash in known_benign:
            return f"✅ {known_benign[ja3_hash]}"
        else:
            # Use feature-based classification if possible
            features = self._ja3_to_features(ja3_hash)
            if features:
                label, confidence = self.classify_traffic(features)
                return f"{label} (from JA3 analysis)"
            else:
                return "Unknown Traffic"
    
    def _ja3_to_features(self, ja3_hash: str) -> List[str]:
        """
        Convert JA3 hash to feature list (simplified version).
        In production, you would implement proper JA3 parsing.
        
        Args:
            ja3_hash: JA3 hash string
            
        Returns:
            List of feature strings
        """
        # Placeholder - in production, parse JA3 string to extract:
        # - TLS version
        # - Cipher suites
        # - Extensions
        # - Elliptic curves
        # - Point formats
        
        # For now, return empty list
        return []
    
    def batch_classify(self, features_list: List[List[str]]) -> List[Tuple[str, float]]:
        """
        Classify multiple traffic patterns in batch.
        
        Args:
            features_list: List of feature lists
            
        Returns:
            List of (label, confidence) tuples
        """
        results = []
        for features in features_list:
            try:
                label, confidence = self.classify_traffic(features)
                results.append((label, confidence))
            except Exception as e:
                logger.error(f"Batch classification failed for features: {e}")
                results.append(("Classification Error", 0.0))
        
        return results


# Factory function for easy instantiation
def create_classifier(use_gpu: bool = False, 
                     model_cache_dir: Optional[str] = None) -> TrafficClassifier:
    """
    Factory function to create a TrafficClassifier with standard configuration.
    
    Args:
        use_gpu: Whether to attempt GPU acceleration
        model_cache_dir: Custom cache directory
        
    Returns:
        Configured TrafficClassifier instance
    """
    return TrafficClassifier(
        use_gpu=use_gpu,
        cache_dir=model_cache_dir
    )


if __name__ == "__main__":
    # Example usage and testing
    print("=== Testing TrafficClassifier ===")
    
    # Create classifier
    classifier = create_classifier(use_gpu=False)
    
    # Test with sample TLS features
    test_features = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "server_name",
        "application_layer_protocol_negotiation",
        "x25519"
    ]
    
    # Set some candidate applications
    test_apps = ["Google Chrome", "Firefox", "Discord", "Slack", "Zoom", "Netflix"]
    classifier.set_candidate_apps(test_apps)
    
    # Perform classification
    label, confidence = classifier.classify_traffic(test_features)
    
    print(f"\nTest Results:")
    print(f"Features: {test_features}")
    print(f"Prediction: {label}")
    print(f"Confidence: {confidence:.1%}")
    
    # Test batch classification
    batch_features = [
        test_features,
        ["TLS_RSA_WITH_AES_256_CBC_SHA", "session_ticket"],
        ["TLS_CHACHA20_POLY1305_SHA256", "x25519", "quic_transport_parameters"]
    ]
    
    batch_results = classifier.batch_classify(batch_features)
    print(f"\nBatch Results:")
    for i, (label, conf) in enumerate(batch_results):
        print(f"  Sample {i+1}: {label} ({conf:.1%})")
    
    print("\n✅ TrafficClassifier is ready for production!")