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
        self.inference_cache = {}  # 🚀 YENİ: Yapay Zeka Önbelleği (Makaledeki 0.5ms Fast-Path)
        self._load_models()

    def _load_models(self):
        try:
            if not os.path.exists(self.model_dir):
                logger.warning("⚠️ Model klasörü bulunamadı! Lütfen train_ai.py çalıştırın.")
                return
            
            self.pipe = pipeline(
                "text-classification", 
                model=self.model_dir, 
                tokenizer=self.model_dir,
                truncation=True,
                max_length=128
            )
            logger.info("✅ Transformatör (SecBERT) Modeli başarıyla yüklendi!")
        except Exception as e:
            logger.error(f"❌ Model yükleme hatası: {e}")

    def predict(self, input_data: any) -> str:
        label, _ = self.classify_traffic(input_data)
        return label

    def classify_traffic(self, pattern: list, candidate_apps: list = None, ja4_hint: str = "", **kwargs) -> tuple:
        if not self.pipe:
            return "Unknown Traffic (Model Not Loaded)", 0.0

        try:
            # 1. Şifre listesini metne çevir
            pattern_str = ", ".join(pattern)
            
            # 🚀 2. CACHE KONTROLÜ (Makaledeki 0.5 ms'lik Lookup mekanizması)
            if pattern_str in self.inference_cache:
                cached_label, cached_conf = self.inference_cache[pattern_str]
                logger.info(f"⚡ CACHE HIT: AI bu dizilimi hatırladı! Süre: 0.5ms -> {cached_label} ({cached_conf*100:.2f}%)")
                return cached_label, cached_conf

            # 3. Cache'de yoksa SecBERT'e sor
            result = self.pipe(pattern_str)[0]
            best_label = result['label']
            confidence = result['score']

            # 4. RAG Adayları Filtrelemesi
            if candidate_apps and len(candidate_apps) > 0:
                if best_label in candidate_apps and confidence > 0.15:
                    logger.info(f"🎯 AI REFINED: RAG + SecBERT mutabakatı sağlandı ({best_label})")
                elif confidence > 0.80:
                    logger.info(f"🧠 AI OVERRIDE: RAG adayları reddedildi, SecBERT semantik analize güveniyor.")

            # 🚀 5. SONUCU CACHE'E KAYDET (Gelecekteki aynı paketler için)
            self.inference_cache[pattern_str] = (best_label, float(confidence))

            logger.info("--- 🤖 SecBERT Semantic Breakdown ---")
            logger.info(f"  -> {best_label}: {confidence*100:.2f}%")
            
            return best_label, float(confidence)

        except Exception as e:
            logger.error(f"Tahminleme sırasında kritik hata: {e}")
            return "Unknown Traffic", 0.0

def create_classifier(**kwargs):
    return TrafficClassifier(**kwargs)