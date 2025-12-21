from flask import Blueprint, request, jsonify, send_file, session, redirect, url_for, render_template
from . import db, GLOBAL_SETUP
from .models import User, AttributeKey, EhrFile, AuditLog
import io
import datetime
from functools import wraps
import csv


bp = Blueprint('views', __name__)

# --- DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_gid' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_gid' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Admin Access Required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- LOGGING HELPER ---
def log_event(user_gid, action, status, file_id=None, details=None):
    try:
        log = AuditLog(
            user_gid=user_gid,
            action=action,
            status=status,
            file_id=file_id,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"LOGGING ERROR: {e}")

# --- CORE ROUTES ---

@bp.route('/')
def home():
    if 'user_gid' in session:
        return redirect(url_for('views.dashboard'))
    return redirect(url_for('views.login_page'))

# UNIFIED LOGIN ROUTE
@bp.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        if 'user_gid' in session: 
            return redirect(url_for('views.dashboard'))
        return render_template('login.html')
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
            
        gid = data.get('gid', '').strip().lower()
        password = data.get('password')

        user = User.query.get(gid)
        if user and user.check_password(password):
            session['user_gid'] = user.gid
            session['role'] = user.role
            log_event(user.gid, "LOGIN", "SUCCESS")
            return jsonify({"message": "Login successful", "redirect": "/dashboard"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": f"Server Error: {str(e)}"}), 500

@bp.route('/api/logout', methods=['POST'])
def logout():
    u = session.get('user_gid')
    if u: log_event(u, "LOGOUT", "SUCCESS")
    session.clear()
    return jsonify({"message": "Logged out"}), 200

@bp.route('/dashboard')
def dashboard():
    # 1. Check if session cookie exists
    if 'user_gid' not in session: 
        return redirect(url_for('views.login_page'))
    
    user_gid = session['user_gid']
    
    # 2. CRITICAL FIX: Query the DB to see if this user actually exists
    user = User.query.get(user_gid)
    
    # 3. If user is NOT in DB (e.g. after DB reset), destroy session & redirect
    if not user:
        print(f"⚠️ Ghost Session Detected for '{user_gid}'. Clearing session.")
        session.clear()
        return redirect(url_for('views.login_page'))
    
    # 4. User exists -> Render Dashboard
    if session.get('role') == 'admin':
        return render_template('admin_dashboard.html', user=user_gid)
    else:
        return render_template('user_dashboard.html', user=user_gid, username=user.username, hide_nav=True)

# --- ADMIN API ENDPOINTS ---

@bp.route('/api/register_user', methods=['POST'])
@admin_required
def register_user():
    data = request.get_json()
    gid = data.get('gid').strip().lower()
    username = data.get('username').strip()
    password = data.get('password') or 'password123'
    role = data.get('role')

    if User.query.get(gid):
        return jsonify({"error": "User already exists"}), 400

    user = User(gid=gid, username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    log_event(session['user_gid'], "REGISTER", "SUCCESS", details=f"Created {gid}")
    db.session.commit()
    return jsonify({"message": f"User {gid} registered successfully"}), 201

@bp.route('/api/issue_key', methods=['POST'])
@admin_required
def issue_key():
    data = request.get_json()
    gid = data.get('gid').strip().lower()
    auth = data.get('authority_id')
    attr = data.get('attribute')

    user = User.query.get(gid)
    if not user: return jsonify({"error": "User not found"}), 404

    core = GLOBAL_SETUP['crypto_core']
    auth_keys = GLOBAL_SETUP['authorities']
    
    try:
        user_key_blob = core.generate_user_key(auth_keys[auth]['sk'], gid, f"{auth}_{attr}")
        
        new_key = AttributeKey(
            user_gid=gid,
            attribute_name=f"{auth}_{attr}",
            key_component=user_key_blob
        )
        db.session.add(new_key)
        db.session.commit()
        
        log_event(session['user_gid'], "ISSUE_KEY", "SUCCESS", details=f"Issued {auth}_{attr} to {gid}")
        return jsonify({"message": "Key issued successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/api/revoke_key', methods=['POST'])
@admin_required
def revoke_key():
    data = request.get_json()
    gid = data.get('gid').strip().lower()
    auth = data.get('authority_id')
    attr = data.get('attribute')
    full_attr = f"{auth}_{attr}"

    key_to_delete = AttributeKey.query.filter_by(user_gid=gid, attribute_name=full_attr).first()
    
    if key_to_delete:
        db.session.delete(key_to_delete)
        db.session.commit()
        log_event(session['user_gid'], "REVOKE_KEY", "SUCCESS", details=f"Revoked {full_attr} from {gid}")
        return jsonify({"message": f"Revoked {full_attr}"}), 200
    else:
        return jsonify({"error": "Key not found"}), 404

# --- UPDATED: Save 'original_policy' ---
@bp.route('/api/upload_ehr', methods=['POST'])
@admin_required
def upload_ehr():
    file = request.files['file']
    filename = request.form['filename']
    policy = request.form['policy']
    
    if not file or not policy: return jsonify({"error": "Missing data"}), 400

    file_bytes = file.read()
    
    core = GLOBAL_SETUP['crypto_core']
    pks = {
        'MA': core.serialize(GLOBAL_SETUP['authorities']['MA']['pk']),
        'HA': core.serialize(GLOBAL_SETUP['authorities']['HA']['pk'])
    }
    
    try:
        enc_result = core.encrypt_file(pks, policy, file_bytes, real_filename=filename)
        
        new_file = EhrFile(
            filename=filename,
            policy=enc_result['policy'],    # Hashed
            original_policy=policy,         # Readable (NEW)
            abe_ciphertext=enc_result['abe_ciphertext'],
            aes_iv=enc_result['aes_iv'],
            aes_ciphertext=enc_result['aes_ciphertext']
        )
        db.session.add(new_file)
        db.session.commit()
        
        log_event(session['user_gid'], "UPLOAD", "SUCCESS", file_id=new_file.id, details=f"Policy: {policy}")
        return jsonify({"message": "File uploaded", "file_id": new_file.id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- UPDATED: Return 'original_policy' ---
@bp.route('/api/get_all_files', methods=['GET'])
@admin_required
def get_all_files():
    files = EhrFile.query.all()
    file_list = []
    for f in files:
        file_list.append({
            "id": f.id,
            "filename": f.filename,
            "policy": f.original_policy if f.original_policy else f.policy 
        })
    return jsonify(file_list), 200

@bp.route('/api/get_logs', methods=['GET'])
@login_required
def get_logs():
    user_gid = session.get('user_gid')
    role = session.get('role')
    target_user = request.args.get('user')

    if role == 'admin':
        query = AuditLog.query
        if target_user and target_user.strip():
            query = query.filter(AuditLog.user_gid.ilike(f"%{target_user.strip()}%"))
        logs = query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    else:
        logs = AuditLog.query.filter_by(user_gid=user_gid).order_by(AuditLog.timestamp.desc()).limit(50).all()

    log_list = []
    for l in logs:
        log_list.append({
            "time": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"), 
            "user": l.user_gid, 
            "action": l.action, 
            "status": l.status, 
            "file": l.file_id, 
            "details": l.details
        })
    return jsonify(log_list), 200

@bp.route('/api/my_keys')
@login_required
def my_keys():
    keys = AttributeKey.query.filter_by(user_gid=session['user_gid']).all()
    return jsonify([k.attribute_name for k in keys])

@bp.route('/api/my_files')
@login_required
def my_files():
    files = EhrFile.query.all()
    return jsonify([{
        "id": f.id, 
        "filename": f"patient_record_{f.id}.enc", 
        "policy": f.policy
    } for f in files])

@bp.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    user = User.query.get(session['user_gid'])
    
    if not user.check_password(data.get('old_password')):
        return jsonify({"error": "Incorrect current password"}), 400
        
    user.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({"message": "Password updated successfully"}), 200

# --- FIX: Added '/api' to the start of the URL ---
@bp.route('/api/download_ehr/<int:file_id>', methods=['POST'])
@login_required
def download_ehr(file_id):
    try:
        user_gid = session['user_gid']
        
        # 1. Fetch File
        file_record = EhrFile.query.get(file_id)
        if not file_record:
            log_event(user_gid, "DOWNLOAD", "FAILURE", details=f"File ID {file_id} not found")
            return jsonify({"error": "File not found"}), 404
            
        # 2. Fetch User Keys
        user_keys = {}
        keys_found = AttributeKey.query.filter_by(user_gid=user_gid).all()
        
        for key_record in keys_found:
            if hasattr(key_record, 'key_component'):
                user_keys[key_record.attribute_name] = key_record.key_component
            elif hasattr(key_record, 'key'):
                user_keys[key_record.attribute_name] = key_record.key
            elif hasattr(key_record, 'key_blob'):
                 user_keys[key_record.attribute_name] = key_record.key_blob

        # 3. Prepare Encrypted Package
        encrypted_package = {
            "policy": file_record.policy,
            "abe_ciphertext": file_record.abe_ciphertext,
            "aes_iv": file_record.aes_iv,
            "aes_ciphertext": file_record.aes_ciphertext
        }
        
        # 4. Attempt Decryption
        core = GLOBAL_SETUP['crypto_core']
        result = core.decrypt_file(user_gid, user_keys, encrypted_package)
        
        if result and 'data' in result:
            log_event(user_gid, "DOWNLOAD", "SUCCESS", file_id=file_id, details=f"Decryption successful for File ID: {file_id}")
            return send_file(
                io.BytesIO(result['data']),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=result['filename']
            )
        else:
            error_msg = result.get('error', 'Policy Mismatch') if result else 'Policy Mismatch'
            log_event(user_gid, "DOWNLOAD", "FAILURE", file_id=file_id, details=f"Access Denied: {error_msg} (File ID: {file_id})")
            return jsonify({"error": f"Decryption failed: {error_msg}"}), 403

    except Exception as e:
        log_event(user_gid, "DOWNLOAD", "FAILURE", file_id=file_id, details=f"System Error on File ID: {file_id}")
        print(f"Decryption Exception: {e}")
        return jsonify({"error": f"System Error: {str(e)}"}), 500


@bp.route('/api/download_logs', methods=['GET'])
@login_required 
def download_logs():
    current_user_gid = session['user_gid']
    role = session.get('role')
    
    target_user = request.args.get('user')
    
    # SECURITY: If not admin, FORCE them to only see their own logs
    if role != 'admin':
        target_user = current_user_gid

    # 1. Fetch Data
    query = AuditLog.query
    if target_user and target_user.strip():
        query = query.filter(AuditLog.user_gid.ilike(f"%{target_user.strip()}%"))
    
    if role != 'admin' and (not target_user or not target_user.strip()):
         query = query.filter(AuditLog.user_gid == current_user_gid)

    logs = query.order_by(AuditLog.timestamp.desc()).all()
    
    # 2. Create CSV in Memory
    proxy = io.StringIO()
    writer = csv.writer(proxy)
    
    writer.writerow(['Timestamp', 'User GID', 'Action', 'Status', 'File ID', 'Details'])
    
    for l in logs:
        writer.writerow([
            l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            l.user_gid,
            l.action,
            l.status,
            l.file_id if l.file_id else '-',
            l.details or ''
        ])
    
    mem = io.BytesIO()
    mem.write(proxy.getvalue().encode('utf-8'))
    mem.seek(0)
    proxy.close()
    
    # --- FILENAME CHANGE HERE ---
    if target_user:
        # split('@')[0] takes 'prasanth@hospital.com' and keeps only 'prasanth'
        short_name = target_user.split('@')[0]
        filename = f"audit_logs_{short_name}.csv"
    else:
        filename = "audit_logs_full.csv"
    
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )