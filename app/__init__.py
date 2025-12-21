from flask import Flask, jsonify
from .models import db
import os

# Global Cryptographic Setup
GLOBAL_SETUP = {
    'crypto_core': None,
    'authorities': {}
}

def create_app():
    # Correctly point to the outer templates folder
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # --- FIX: Generate a RANDOM key on every start ---
    # This ensures that whenever you restart the server, all old login sessions are invalidated immediately.
    app.config['SECRET_KEY'] = os.urandom(24) 
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)

    # Global Error Handlers (Keep these)
    @app.errorhandler(500)
    def internal_server_error(e):
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

    @app.errorhandler(404)
    def not_found_error(e):
        return jsonify({"error": "Resource not found (404)"}), 404

    # Initialize Crypto (Keep this)
    from .core_crypto.abe_core import CryptoCore
    if GLOBAL_SETUP['crypto_core'] is None:
        print("⚡ Initializing Cryptographic Core...")
        core = CryptoCore()
        core.setup_global()
        GLOBAL_SETUP['crypto_core'] = core
        
        for auth in ['MA', 'HA']:
            print(f"🔑 Initializing Authority: {auth}")
            pk_bytes, sk_bytes = core.setup_authority(auth)
            GLOBAL_SETUP['authorities'][auth] = {
                'pk': core.deserialize(pk_bytes),
                'sk': core.deserialize(sk_bytes)
            }

    with app.app_context():
        db.create_all()
        from . import routes
        app.register_blueprint(routes.bp)

    return app