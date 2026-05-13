import os
import logging
import joblib
import numpy as np
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BasePredictor(ABC):
    @abstractmethod
    def predict(self, input_data: Any) -> str:
        pass

class TrafficClassifier(BasePredictor):
    def __init__(self, model_dir: str = 'saved_models', **kwargs):
        # Docker ve Lokal ortam yollarını yönet
        if os.path.exists('/app/saved_models'):
            self.model_dir = '/app/saved_models'
        else:
            self.model_dir = model_dir
            
        self.vectorizer_path = os.path.join(self.model_dir, 'tls_vectorizer.pkl')
        self.model_path = os.path.join(self.model_dir, 'tls_rf_model.pkl')
        
        self.vectorizer = None
        self.model = None
        self._load_models()

    def _load_models(self):
        try:
            if not os.path.exists(self.vectorizer_path) or not os.path.exists(self.model_path):
                logger.warning("⚠️ Model dosyaları bulunamadı! Lütfen train_ai.py çalıştırın.")
                return
            self.vectorizer = joblib.load(self.vectorizer_path)
            self.model = joblib.load(self.model_path)
            logger.info("✅ ML Modeli milisaniyeler içinde başarıyla yüklendi!")
        except Exception as e:
            logger.error(f"❌ Model yükleme hatası: {e}")

    def predict(self, input_data: Any) -> str:
        label, _ = self.classify_traffic(input_data)
        return label

    def classify_traffic(self, pattern: list, candidate_apps: list = None, ja4_hint: str = "", sizes: list = None) -> tuple:
        """
        Gelişmiş AI Sınıflandırma: 
        1. Sıralama Duyarlı (Pattern)
        2. Hacimsel Analiz (Sizes)
        3. RAG Aday Filtreleme (Candidates)
        """
        if not self.model or not self.vectorizer:
            return "Unknown Traffic (Model Not Loaded)", 0.0

        try:
            # 1. Metinsel Özellikler (Sıralama Korunarak)
            pattern_str = ", ".join(pattern)
            X_text = self.vectorizer.transform([pattern_str]).toarray() # Vektöre çevir
            
            # 2. Sayısal Özellikler (Paket Boyutları)
            if not sizes:
                sizes = [0, 0, 0]
            X_sizes = np.array([sizes])
            
            # 3. İki Veri Tipini Birleştir (Hybrid Input)
            # Not: Modelin bu birleşik yapıya göre eğitilmiş olması gerekir!
            X_combined = np.hstack((X_text, X_sizes))
            
            # 4. Ham Olasılıkları Hesapla
            probs = self.model.predict_proba(X_combined)[0]
            classes = self.model.classes_
            
            raw_max_idx = np.argmax(probs)
            best_label = classes[raw_max_idx]
            confidence = probs[raw_max_idx]

            # 5. RAG Adayları Filtrelemesi (Senin Mevcut Mantığın)
            if candidate_apps and len(candidate_apps) > 0:
                candidate_mask = np.isin(classes, candidate_apps)
                if np.any(candidate_mask):
                    candidate_probs = probs * candidate_mask
                    candidate_max_idx = np.argmax(candidate_probs)
                    
                    # Eğer model adaya en az %15 güveniyorsa odaklan
                    if probs[candidate_max_idx] > 0.15:
                        best_label = classes[candidate_max_idx]
                        confidence = probs[candidate_max_idx]
                        logger.info(f"🎯 AI REFINED: RAG + Hacim Analizi ile aday onaylandı ({best_label})")

            # İlk 3 Tahmini Logla
            top3_indices = np.argsort(probs)[-3:][::-1]
            logger.info("--- 🤖 ML Multi-Dimensional Breakdown ---")
            for idx in top3_indices:
                if probs[idx] > 0.01:
                    logger.info(f"  -> {classes[idx]}: {probs[idx]*100:.2f}%")
            
            return best_label, float(confidence)

        except Exception as e:
            logger.error(f"Tahminleme sırasında kritik hata: {e}")
            return "Unknown Traffic", 0.0

def create_classifier(**kwargs):
    return TrafficClassifier(**kwargs)