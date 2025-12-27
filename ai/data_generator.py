import pandas as pd
import numpy as np
from datetime import datetime, timedelta

ACTIONS = ['LOGIN', 'LOGOUT', 'DOWNLOAD', 'UPLOAD', 'VIEW_KEYS']
STATUSES = ['SUCCESS', 'FAILURE']
USERS = ['doctor@hosp.com', 'nurse@hosp.com', 'admin@hosp.com']

def generate_synthetic_data(num_samples=15000):
    data = []
    start_time = datetime(2025, 1, 1)
    
    print(f"Generating RATIO-BASED training samples...")
    print("   1. SAFE: High Success Rate (Failure Ratio < 0.2)")
    print("   2. ATTACK A: Fishing/Brute Force (Failure Ratio > 0.3)")
    print("   3. ATTACK B: Midnight Exfiltration (High Downloads)")
    
    for _ in range(num_samples):
        is_anomaly = np.random.random() < 0.50
        
        if not is_anomaly:
            # === SAFE USER ===
            hour = int(np.random.randint(0, 24))
            action = np.random.choice(ACTIONS, p=[0.3, 0.3, 0.2, 0.1, 0.1])
            status = 'SUCCESS'
            
            # Normal: Mostly 0% failure ratio. Occasionally up to 15% (3/20 failed)
            fail_ratio = 0.0
            if np.random.random() < 0.1:
                fail_ratio = np.random.uniform(0.05, 0.15)
                status = 'FAILURE' # Current action likely part of that mess
                
            # Normal Downloads
            dl_count = 0
            if action == 'DOWNLOAD': dl_count = int(np.random.randint(0, 4))
                
            label = 0 # SAFE
            
        else:
            label = 1 # ANOMALY
            attack_type = np.random.choice(['RATIO', 'EXFIL'])
            
            if attack_type == 'RATIO':
                # === THREAT A: BAD SUCCESS RATE ===
                # "I tried 20 files, got 2 right." -> Failure Ratio 0.9
                # "I tried 20 files, got 10 right." -> Failure Ratio 0.5 (Still suspicious!)
                hour = int(np.random.randint(0, 24))
                action = 'DOWNLOAD'
                status = 'FAILURE'
                
                # Attackers have 30% to 100% failure rate
                fail_ratio = np.random.uniform(0.30, 1.0)
                dl_count = 0
                
            elif attack_type == 'EXFIL':
                # === THREAT B: MIDNIGHT EXFIL ===
                # High downloads, good success rate, but WRONG TIME/VOLUME
                hour = int(np.random.choice([22, 23, 0, 1, 2, 3, 4]))
                action = 'DOWNLOAD'
                status = 'SUCCESS'
                fail_ratio = 0.0 # They have keys, so no failures
                dl_count = int(np.random.randint(5, 30))

        # Generate TS
        days_offset = int(np.random.randint(0, 60))
        minutes_offset = int(np.random.randint(0, 60))
        timestamp = start_time + timedelta(days=days_offset, hours=hour, minutes=minutes_offset)
        
        data.append({
            'timestamp': timestamp,
            'user_gid': np.random.choice(USERS),
            'action': action,
            'status': status,
            'failure_ratio': round(fail_ratio, 2),
            'recent_download_count': dl_count,
            'label': label
        })
        
    df = pd.DataFrame(data)
    df.to_csv('ai/synthetic_logs.csv', index=False)
    print("✅ Ratio-Based Data Generated.")

if __name__ == "__main__":
    generate_synthetic_data()