import pandas as pd
import numpy as np

# Mappings
ACTION_MAP = {'LOGIN': 0, 'LOGOUT': 1, 'DOWNLOAD': 2, 'UPLOAD': 3, 'VIEW_KEYS': 4, 'ISSUE_KEY': 5, 'REVOKE_KEY': 6, 'REGISTER': 7}
STATUS_MAP = {'SUCCESS': 0, 'FAILURE': 1}

def extract_features(input_data):
    """
    Features: [hour, is_weekend, action, status, failure_ratio, download_count]
    """
    # CASE A: Real-time (Dict)
    if isinstance(input_data, dict):
        ts = input_data.get('timestamp', pd.Timestamp.now())
        if isinstance(ts, str):
            try: ts = pd.to_datetime(ts)
            except: ts = pd.Timestamp.now()
            
        hour = ts.hour
        is_weekend = 1 if ts.weekday() >= 5 else 0
        act = ACTION_MAP.get(input_data.get('action'), -1)
        stat = STATUS_MAP.get(input_data.get('status'), -1)
        
        # NEW: Ratio (0.0 to 1.0)
        fail_ratio = float(input_data.get('failure_ratio', 0.0))
        dl_count = int(input_data.get('recent_download_count', 0))
        
        return np.array([[hour, is_weekend, act, stat, fail_ratio, dl_count]])

    # CASE B: Training (DataFrame)
    elif isinstance(input_data, pd.DataFrame):
        df = input_data.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        df['hour'] = df['timestamp'].dt.hour
        df['is_weekend'] = (df['timestamp'].dt.weekday >= 5).astype(int)
        df['action_code'] = df['action'].map(ACTION_MAP).fillna(-1)
        df['status_code'] = df['status'].map(STATUS_MAP).fillna(-1)
        
        if 'failure_ratio' not in df.columns: df['failure_ratio'] = 0.0
        if 'recent_download_count' not in df.columns: df['recent_download_count'] = 0
            
        return df[['hour', 'is_weekend', 'action_code', 'status_code', 'failure_ratio', 'recent_download_count']].values