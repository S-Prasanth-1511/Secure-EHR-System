import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from feature_extractor import extract_features
import data_generator

DATA_PATH = 'ai/synthetic_logs.csv'
MODEL_DIR = 'model_store'
MODEL_PATH = os.path.join(MODEL_DIR, 'anomaly_model.pkl')

def train():
    data_generator.generate_synthetic_data() # Generate new ratio data
    print("🚀 Training Ratio-Aware AI...")
    df = pd.read_csv(DATA_PATH)
    
    X = extract_features(df)
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    acc = accuracy_score(y_test, model.predict(X_test))
    print(f"📊 Accuracy: {acc*100:.2f}%")
    
    if not os.path.exists(MODEL_DIR): os.makedirs(MODEL_DIR)
    with open(MODEL_PATH, 'wb') as f: pickle.dump(model, f)
    print(f"✅ Model saved.")

if __name__ == "__main__":
    train()