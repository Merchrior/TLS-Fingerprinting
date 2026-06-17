import os
import logging
from transformers import pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrafficClassifier:
    def __init__(self, model_dir: str = 'saved_models', **kwargs):
        if os.path.exists('/app/saved_models'):
            self.model_dir = '/app/saved_models'
        else:
            self.model_dir = model_dir
            
        self.pipe = None
        self.inference_cache = {}
        self._load_models()

    def _load_models(self):
        try:
            if not os.path.exists(self.model_dir):
                logger.warning("Model directory not found. Please run train_ai.py.")
                return
            
            self.pipe = pipeline(
                "text-classification", 
                model=self.model_dir, 
                tokenizer=self.model_dir,
                truncation=True,
                max_length=128
            )
            logger.info("Transformer (SecBERT) model loaded successfully.")
        except Exception as e:
            logger.error(f"Model loading error: {e}")

    def predict(self, input_data: any) -> str:
        label, _ = self.classify_traffic(input_data)
        return label

    def classify_traffic(self, pattern: list, ja4_hint: str = "", sni: str = "", **kwargs) -> tuple:
        if not self.pipe:
            return "Unknown Traffic (Model Not Loaded)", 0.0

        try:
            # 1. Convert cipher list to string
            pattern_str = ", ".join(pattern)
            
            # 2. Cache Check (0.5ms fast-path lookup)
            if pattern_str in self.inference_cache:
                cached_label, cached_conf = self.inference_cache[pattern_str]
                logger.info(f"CACHE HIT: Pattern remembered. Time: 0.5ms -> {cached_label} ({cached_conf*100:.2f}%)")
                return cached_label, cached_conf

            # 3. Query SecBERT
            result = self.pipe(pattern_str)[0]
            best_label = result['label']
            confidence = result['score']

            # 4. Save result to cache
            self.inference_cache[pattern_str] = (best_label, float(confidence))

            # 5. Logging Output
            logger.info("--- SecBERT Semantic Breakdown ---")
            logger.info(f"  -> AI Cryptographic Decision: {best_label} ({confidence*100:.2f}%)")
            
            if sni and sni != "Unknown":
                logger.info(f"  -> Context Engine (SNI Target): {sni}")
            
            return best_label, float(confidence)

        except Exception as e:
            logger.error(f"Critical error during prediction: {e}")
            return "Unknown Traffic", 0.0

def create_classifier(**kwargs):
    return TrafficClassifier(**kwargs)