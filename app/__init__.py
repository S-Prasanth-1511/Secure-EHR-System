import os
from flask import Flask, render_template
from .config import Config, AUTHORITIES
from .models import db

# Import our crypto components
from .core_crypto.abe_core import CryptoCore
from .authorities.medical_authority import MedicalAuthority
from .authorities.hospital_authority import HospitalAuthority

# This dictionary will hold our globally initialized crypto objects
GLOBAL_SETUP = {}

# Calculate the project's root directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def create_app():
    app = Flask(__name__,
                template_folder=os.path.join(PROJECT_ROOT, 'templates'),
                static_folder=os.path.join(PROJECT_ROOT, 'static')
               )
    app.config.from_object(Config)
    
    db.init_app(app)

    with app.app_context():
        print("--- INITIALIZING SYSTEM ---")
        
        # 1. Initialize Crypto
        crypto_core = CryptoCore()
        crypto_core.setup_global()

        # 2. Initialize Authorities (using new classes that look for MA/HA)
        medical_auth = MedicalAuthority(crypto_core, AUTHORITIES)
        hospital_auth = HospitalAuthority(crypto_core, AUTHORITIES)

        # 3. Generate Keys
        medical_auth.setup()
        hospital_auth.setup()

        # 4. Store in Global Setup (UPDATED KEYS: MA and HA)
        GLOBAL_SETUP['crypto_core'] = crypto_core
        GLOBAL_SETUP['authorities'] = {
            "MA": medical_auth,
            "HA": hospital_auth
        }

        GLOBAL_SETUP['public_keys'] = {
            "MA": medical_auth.get_public_key(),
            "HA": hospital_auth.get_public_key()
        }
        print("--- SYSTEM INITIALIZED AND READY ---")

        db.create_all()
        print("Database tables created.")

    from . import routes
    app.register_blueprint(routes.bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    return app
