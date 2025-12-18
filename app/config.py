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
