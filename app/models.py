from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# app/models.py

class User(db.Model):
    gid = db.Column(db.String(100), primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    
    # --- NEW: Freeze Account Flag ---
    is_frozen = db.Column(db.Boolean, default=False) 
    
    def set_password(self, password):
        self.password_hash = password 
    
    def check_password(self, password):
        return self.password_hash == password

# ... (Keep AttributeKey, EhrFile, AuditLog unchanged) ...

class AttributeKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_gid = db.Column(db.String(100), db.ForeignKey('user.gid'), nullable=False)
    attribute_name = db.Column(db.String(100), nullable=False)
    # Using 'key_component' as confirmed by your previous logs
    key_component = db.Column(db.LargeBinary, nullable=False)

class EhrFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)       
    policy = db.Column(db.String(500), nullable=False)         # Hashed Policy (For Math)
    original_policy = db.Column(db.String(500), nullable=True) # Readable Policy (For Admin UI)
    
    abe_ciphertext = db.Column(db.LargeBinary, nullable=False)
    aes_iv = db.Column(db.LargeBinary, nullable=False)
    aes_ciphertext = db.Column(db.LargeBinary, nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user_gid = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    file_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(500), nullable=True)
    
    # --- NEW AI FIELDS ---
    anomaly_score = db.Column(db.Float, default=0.0) # Raw score (e.g. -0.65)
    is_anomaly = db.Column(db.Boolean, default=False) # Flag (True/False)