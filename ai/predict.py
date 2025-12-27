import pickle
import os
import datetime
import pytz # NEW
from .feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'model_store', 'anomaly_model.pkl')

_model = None

def load_model():
    global _model
    if _model is None:
        try:
            with open(MODEL_PATH, 'rb') as f: _model = pickle.load(f)
        except: return None
    return _model

def detect_anomaly(user_gid, action, status, failure_ratio=0.0, download_count=0):
    model = load_model()
    if not model: return False, 0.0
    
    # FIX: FORCE IST TIME FOR PREDICTION
    # This ensures "2 AM India" is treated as "2 AM" by the model.
    ist = pytz.timezone('Asia/Kolkata')
    now_ist = datetime.datetime.now(ist)
    
    data = {
        'timestamp': now_ist, # Used for 'hour' feature
        'action': action,
        'status': status,
        'failure_ratio': failure_ratio,
        'recent_download_count': download_count
    }
    
    try:
        features = extract_features(data)
        risk_prob = model.predict_proba(features)[0][1]
        
        is_anomaly = risk_prob > 0.5
        score = -risk_prob if is_anomaly else (1 - risk_prob)
        return is_anomaly, float(score)
    except: return False, 0.0