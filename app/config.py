import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

AUTHORITIES = {
    "MA": {
        "id": "MA",
        "name": "Medical Licensing Board",
        "attributes": [
            "DOCTOR",
            "NURSE",
            "RESEARCHER",
            "CARDIOLOGY",
            "ONCOLOGY",
            "SURGERY"
        ]
    },
    "HA": {
        "id": "HA",
        "name": "General Hospital Administration",
        "attributes": [
            "STAFF",
            "NOSTAFF",
            "CARDIO_DEPT",
            "ONCO_DEPT",
            "EMERGENCY",
            "SURGERY_DEPT",
            "GEN_HOSP"
        ]
    }
}

class Config:
    # --- ADD THIS LINE ---
    SECRET_KEY = 'my-super-secret-key-change-this-in-production' 
    
    # Keep your existing database config
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False