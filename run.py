from app import create_app, db
from app.models import User

app = create_app()

if __name__ == "__main__":
    with app.app_context():
        # 1. Ensure all tables exist (creates app.db if missing)
        db.create_all()

        # 2. AUTOMATIC ADMIN CREATION
        # Check if any admin exists. If not, create the default one.
        existing_admin = User.query.filter_by(role='admin').first()
        
        if not existing_admin:
            print("⚡ Database is empty. Creating Default Admin Account...")
            
            # --- FIXED ADMIN CREDENTIALS ---
            admin = User(
                gid='admin@hospital.com', 
                username='System Admin', 
                role='admin'
            )
            admin.set_password('admin123')  # Hardcoded password
            # -------------------------------
            
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin Created Successfully!")
            print("   Login ID: admin@hospital.com")
            print("   Password: admin123")
        else:
            print("ℹ️  Admin account already exists. Skipping creation.")

    # 3. Start the Server
    app.run(debug=True, host='0.0.0.0', port=5000)