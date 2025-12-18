from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    gid = db.Column(db.String(100), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    keys = db.relationship('AttributeKey', backref='user', lazy=True)

class AttributeKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_gid = db.Column(db.String(100), db.ForeignKey('user.gid'), nullable=False)
    attribute_name = db.Column(db.String(255), nullable=False)
    key_component = db.Column(db.LargeBinary, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_gid', 'attribute_name', name='_user_attr_uc'),)

class EhrFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    policy = db.Column(db.String(1000), nullable=False)
    abe_ciphertext = db.Column(db.LargeBinary, nullable=False)
    aes_iv = db.Column(db.LargeBinary, nullable=False)
    aes_ciphertext = db.Column(db.LargeBinary, nullable=False)

# --- NEW: AUDIT LOG MODEL ---
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_gid = db.Column(db.String(100), nullable=True) # Can be null if unknown user
    action = db.Column(db.String(50), nullable=False)    # e.g., "DOWNLOAD_ATTEMPT"
    file_id = db.Column(db.String(50), nullable=True)     # Which file?
    status = db.Column(db.String(20), nullable=False)     # "SUCCESS" or "FAILURE"
    details = db.Column(db.String(500), nullable=True)    # Error message or details
