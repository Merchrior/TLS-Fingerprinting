import sqlite3
import pandas as pd

def analyze_db():
    print("🔍 Veritabanı Analizi Başlıyor...")
    
    # Docker içindeki klasör yapısına göre veritabanı yolu
    db_path = '/app/data/fingerprints.db'
    
    try:
        # SQLite'a bağlan
        conn = sqlite3.connect(db_path)
        
        table_name = "signatures" 
        print(f"📊 '{table_name}' tablosu okunuyor...")
        
        # 'pattern' yerine veritabanındaki 'raw_fingerprint' sütununu okuyoruz
        query = f"SELECT raw_fingerprint as pattern, app_label FROM {table_name} WHERE raw_fingerprint IS NOT NULL"
        df = pd.read_sql(query, conn)
        
        print(f"📦 Ham Satır Sayısı: {len(df)}")
        
        if len(df) > 0:
            print("\n👀 ÖRNEK VERİ İNCELEMESİ (İlk Satır):")
            print(f"Etiket (App Label): {df['app_label'].iloc[0]}")
            print(f"İçerik (Raw Fingerprint): {df['pattern'].iloc[0][:200]}...") # İlk 200 karakteri göster
            
        # Temizlik ve Tekilleştirme (Deduplication)
        df_clean = df.dropna(subset=['pattern', 'app_label'])
        
        # Aynı parmak izine sahip olanları grupla ve en çok geçen etiketi al
        df_unique = df_clean.groupby('pattern')['app_label'].agg(lambda x: x.value_counts().index[0]).reset_index()
        
        print(f"\n📉 Tekilleştirme Sonrası EŞSİZ Satır Sayısı: {len(df_unique)}")
        
        # En popüler 10 etiketi görelim
        top_apps = df_unique['app_label'].value_counts().head(10)
        print(f"\n🏆 En Popüler 10 Uygulama Sınıfı:\n{top_apps}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")

if __name__ == "__main__":
    analyze_db()