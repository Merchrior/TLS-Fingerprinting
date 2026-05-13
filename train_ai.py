import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import GradientBoostingClassifier # Daha güçlü bir model (XGBoost alternatifi)
import joblib
import os

MODEL_DIR = "saved_models/"

def train_advanced_model():
    print("🚀 Çok Boyutlu (Sıralama + Boyut) AI Eğitimi Başlıyor...")
    
    # DEMO VERİ SETİ (Gerçek DB'ye bu sütunları eklediğini varsayıyoruz)
    # Cipher sırası korunmuş string + İlk 3 paket boyutu
   # GERÇEK DÜNYA DEĞERLERİ: 
    # Chrome (Çok eklentisi var = ~500-600 byte)
    # VPN (Orta eklenti = ~250-350 byte)
    # IoT (Eski/Az eklenti = ~100-150 byte)
    
    demo_data = [
        {"pattern": "TLS_AES_256, server_name, key_share", "sizes": [512, 0, 0], "label": "Google Chrome (Demo Verified)"},
        {"pattern": "TLS_AES_256, key_share, server_name", "sizes": [512, 0, 0], "label": "Google Chrome (Demo Verified)"},
        {"pattern": "ECDHE-RSA, session_ticket", "sizes": [300, 0, 0], "label": "Kurumsal VPN Istemcisi (High Match)"},
        {"pattern": "AES128-SHA, padding", "sizes": [120, 0, 0], "label": "Eski Bir IoT Cihazi (Low Match)"}
    ]
    df = pd.DataFrame(demo_data * 500)

    # 1. Sıralama Duyarlı Vektörizasyon (N-gram kullanarak)
    # ngram_range=(1, 3) hem tekli şifreleri hem de 2'li-3'lü dizilim sıralarını yakalar
    vectorizer = TfidfVectorizer(token_pattern=r"[^, ]+", ngram_range=(1, 3))
    X_text = vectorizer.fit_transform(df['pattern']).toarray()

    # 2. Paket Boyutlarını Sayısal Özellik Olarak Ekle
    X_sizes = np.array(df['sizes'].tolist())

    # İki veri tipini birleştir (Text + Numeric)
    X_combined = np.hstack((X_text, X_sizes))
    y = df['label']

    # 3. Model: Gradient Boosting (Daha keskin tahminler için)
    print("🔥 Model eğitiliyor (Sıralama ve Boyut korelasyonu kuruluyor)...")
    model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    model.fit(X_combined, y)

    # 4. Kaydet
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(vectorizer, MODEL_DIR + 'tls_vectorizer.pkl')
    joblib.dump(model, MODEL_DIR + 'tls_rf_model.pkl')
    
    print(f"✅ Eğitim tamamlandı. Accuracy: %{model.score(X_combined, y)*100:.2f}")

if __name__ == "__main__":
    train_advanced_model()