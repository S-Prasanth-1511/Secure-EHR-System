from flask import Blueprint, request, jsonify, send_file, session, redirect, url_for, render_template
from . import db, GLOBAL_SETUP
from .models import User, AttributeKey, EhrFile, AuditLog
from ai.predict import detect_anomaly
import io
import datetime
from datetime import timedelta
from functools import wraps
import csv
import pytz # NEW: Timezone Library

bp = Blueprint('views', __name__)

# --- HELPER: GET IST TIME ---
def get_ist_time():
    # Get current UTC time, convert to IST, and remove timezone info for DB compatibility
    utc_now = datetime.datetime.now(pytz.utc)
    ist_now = utc_now.astimezone(pytz.timezone('Asia/Kolkata'))
    return ist_now.replace(tzinfo=None)

# --- DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_gid' not in session: return jsonify({"error": "Unauthorized"}), 401
        
        user = User.query.get(session['user_gid'])
        if user and user.is_frozen:
            # Log the blocked attempt so Admin sees it (Using IST)
            try:
                new_log = AuditLog(
                    timestamp=get_ist_time(), # Explicit IST
                    user_gid=user.gid,
                    action="BLOCKED_ACTION",
                    status="FAILURE",
                    details="Attempted action while Account Frozen",
                    is_anomaly=True,
                    anomaly_score=-0.5
                )
                db.session.add(new_log)
                db.session.commit()
            except: pass
            
            session.clear()
            return jsonify({"error": "CRITICAL: Account Frozen"}), 403
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_gid' not in session or session.get('role') != 'admin':
            return jsonify({"error": "Admin Access Required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- INTELLIGENT LOGGING (IST ENABLED) ---
def log_event(user_gid, action, status, file_id=None, details=None):
    try:
        # 1. GET CURRENT TIME IN IST
        now_ist = get_ist_time()

        # 2. TIME WINDOW (Last 10 Minutes in IST)
        time_threshold = now_ist - timedelta(minutes=10)
        
        recent_logs = AuditLog.query.filter(
            AuditLog.user_gid == user_gid,
            AuditLog.timestamp >= time_threshold
        ).all()
        
        # 3. CALCULATE METRICS
        window_failures = 0
        window_total = 0
        
        for log in recent_logs:
            window_total += 1
            if log.status == 'FAILURE':
                window_failures += 1
        
        # Add current event
        window_total += 1
        if status == 'FAILURE':
            window_failures += 1
            
        # Minimum Evidence Rule (Need 5 failures to trigger ratio check)
        if window_failures < 5:
            failure_ratio = 0.0
        else:
            failure_ratio = window_failures / window_total

        # 4. DOWNLOAD VELOCITY
        recent_downloads = 0
        if action == 'DOWNLOAD' and status == 'SUCCESS':
            for log in recent_logs:
                if log.action == 'DOWNLOAD' and log.status == 'SUCCESS':
                    recent_downloads += 1
            recent_downloads += 1 

        # 5. AI PREDICTION (Pass IST metrics)
        is_risk, score = detect_anomaly(
            user_gid=user_gid, 
            action=action, 
            status=status, 
            failure_ratio=failure_ratio, 
            download_count=recent_downloads
        )
        
        # 6. ACTION
        if is_risk:
            u = User.query.get(user_gid)
            if u and u.role != 'admin' and not u.is_frozen:
                u.is_frozen = True
                db.session.add(u)
                print(f"❄️ ACCOUNT FROZEN: {user_gid} (Time: {now_ist})")
                details = f"[AI-FROZEN] {details or ''}"

        # 7. SAVE (Explicitly use IST timestamp)
        new_log = AuditLog(
            timestamp=now_ist, # <--- KEY FIX
            user_gid=user_gid, 
            action=action, 
            status=status,
            file_id=file_id, 
            details=details,
            is_anomaly=is_risk, 
            anomaly_score=score
        )
        db.session.add(new_log)
        db.session.commit()
        
    except Exception as e:
        print(f"LOGGING ERROR: {e}")

# --- ROUTES ---

@bp.route('/')
def home():
    if 'user_gid' in session: return redirect(url_for('views.dashboard'))
    return redirect(url_for('views.login_page'))

@bp.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        if 'user_gid' in session: return redirect(url_for('views.dashboard'))
        return render_template('login.html')
    try:
        data = request.get_json()
        gid = data.get('gid', '').strip().lower()
        password = data.get('password')
        user = User.query.get(gid)
        if user and user.check_password(password):
            if user.is_frozen: return jsonify({"error": "Account Frozen"}), 403
            session['user_gid'] = user.gid
            session['role'] = user.role
            log_event(user.gid, "LOGIN", "SUCCESS")
            return jsonify({"message": "Success", "redirect": "/dashboard"}), 200
        else: return jsonify({"error": "Invalid"}), 401
    except: return jsonify({"error": "Server Error"}), 500

@bp.route('/api/logout', methods=['POST'])
def logout():
    u = session.get('user_gid')
    if u: log_event(u, "LOGOUT", "SUCCESS")
    session.clear()
    return jsonify({"message": "Logged out"}), 200

@bp.route('/api/heartbeat', methods=['GET'])
def heartbeat():
    if 'user_gid' not in session: return jsonify({"status": "logged_out"}), 200
    user = User.query.get(session['user_gid'])
    if not user or user.is_frozen:
        session.clear()
        return jsonify({"status": "frozen"}), 200
    return jsonify({"status": "active"}), 200

@bp.route('/dashboard')
def dashboard():
    if 'user_gid' not in session: return redirect(url_for('views.login_page'))
    user_gid = session['user_gid']
    user = User.query.get(user_gid)
    if not user or user.is_frozen:
        session.clear()
        return redirect(url_for('views.login_page'))
    if session.get('role') == 'admin': return render_template('admin_dashboard.html', user=user_gid)
    return render_template('user_dashboard.html', user=user_gid, username=user.username, hide_nav=True)

@bp.route('/api/register_user', methods=['POST'])
@admin_required
def register_user():
    data = request.get_json()
    gid, username, password, role = data.get('gid'), data.get('username'), data.get('password', 'password123'), data.get('role')
    if User.query.get(gid): return jsonify({"error": "User exists"}), 400
    user = User(gid=gid, username=username, role=role, is_frozen=False)
    user.set_password(password)
    db.session.add(user)
    log_event(session['user_gid'], "REGISTER", "SUCCESS", details=f"Created {gid}")
    db.session.commit()
    return jsonify({"message": "Registered"}), 201

@bp.route('/api/unfreeze_user', methods=['POST'])
@admin_required
def unfreeze_user():
    data = request.get_json()
    gid = data.get('gid')
    u = User.query.get(gid)
    if u: 
        u.is_frozen = False
        db.session.commit()
        log_event(session['user_gid'], "UNFREEZE", "SUCCESS", details=gid)
    return jsonify({"message": "Unfrozen"}), 200

@bp.route('/api/get_users_status', methods=['GET'])
@admin_required
def get_users_status():
    users = User.query.filter(User.role != 'admin').all()
    return jsonify([{"gid": u.gid, "username": u.username, "is_frozen": u.is_frozen} for u in users]), 200

@bp.route('/api/issue_key', methods=['POST'])
@admin_required
def issue_key():
    data = request.get_json()
    gid, auth, attr = data.get('gid'), data.get('authority_id'), data.get('attribute')
    core, auth_keys = GLOBAL_SETUP['crypto_core'], GLOBAL_SETUP['authorities']
    try:
        key = core.generate_user_key(auth_keys[auth]['sk'], gid, f"{auth}_{attr}")
        db.session.add(AttributeKey(user_gid=gid, attribute_name=f"{auth}_{attr}", key_component=key))
        db.session.commit()
        log_event(session['user_gid'], "ISSUE_KEY", "SUCCESS", details=f"{auth}_{attr}")
        return jsonify({"message": "Key Issued"}), 200
    except: return jsonify({"error": "Error"}), 500

@bp.route('/api/revoke_key', methods=['POST'])
@admin_required
def revoke_key():
    data = request.get_json()
    key = AttributeKey.query.filter_by(user_gid=data.get('gid'), attribute_name=f"{data.get('authority_id')}_{data.get('attribute')}").first()
    if key:
        db.session.delete(key)
        db.session.commit()
        log_event(session['user_gid'], "REVOKE_KEY", "SUCCESS")
        return jsonify({"message": "Revoked"}), 200
    return jsonify({"error": "Not found"}), 404

@bp.route('/api/upload_ehr', methods=['POST'])
@admin_required
def upload_ehr():
    f, name, pol = request.files['file'], request.form['filename'], request.form['policy']
    core = GLOBAL_SETUP['crypto_core']
    pks = {'MA': core.serialize(GLOBAL_SETUP['authorities']['MA']['pk']), 'HA': core.serialize(GLOBAL_SETUP['authorities']['HA']['pk'])}
    try:
        enc = core.encrypt_file(pks, pol, f.read(), real_filename=name)
        new_file = EhrFile(filename=name, policy=enc['policy'], original_policy=pol, abe_ciphertext=enc['abe_ciphertext'], aes_iv=enc['aes_iv'], aes_ciphertext=enc['aes_ciphertext'])
        db.session.add(new_file)
        db.session.commit()
        log_event(session['user_gid'], "UPLOAD", "SUCCESS", file_id=new_file.id)
        return jsonify({"message": "Uploaded"}), 201
    except: return jsonify({"error": "Error"}), 500

@bp.route('/api/get_all_files', methods=['GET'])
@admin_required
def get_all_files():
    return jsonify([{"id": f.id, "filename": f.filename, "policy": f.original_policy} for f in EhrFile.query.all()])

@bp.route('/api/my_keys')
@login_required
def my_keys():
    return jsonify([k.attribute_name for k in AttributeKey.query.filter_by(user_gid=session['user_gid']).all()])

@bp.route('/api/my_files')
@login_required
def my_files():
    return jsonify([{"id": f.id, "filename": f"rec_{f.id}.enc", "policy": f.policy} for f in EhrFile.query.all()])

@bp.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    u = User.query.get(session['user_gid'])
    if not u.check_password(data.get('old_password')): return jsonify({"error": "Wrong password"}), 400
    u.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({"message": "Updated"}), 200

@bp.route('/api/download_ehr/<int:file_id>', methods=['POST'])
@login_required
def download_ehr(file_id):
    user_gid = session['user_gid']
    try:
        f = EhrFile.query.get(file_id)
        if not f: return jsonify({"error": "Not found"}), 404
        keys = {k.attribute_name: k.key_component for k in AttributeKey.query.filter_by(user_gid=user_gid).all()}
        pkg = {"policy": f.policy, "abe_ciphertext": f.abe_ciphertext, "aes_iv": f.aes_iv, "aes_ciphertext": f.aes_ciphertext}
        res = GLOBAL_SETUP['crypto_core'].decrypt_file(user_gid, keys, pkg)
        if res and 'data' in res:
            log_event(user_gid, "DOWNLOAD", "SUCCESS", file_id=file_id)
            return send_file(io.BytesIO(res['data']), as_attachment=True, download_name=res['filename'])
        else:
            log_event(user_gid, "DOWNLOAD", "FAILURE", file_id=file_id, details="Access Denied")
            return jsonify({"error": "Access Denied"}), 403
    except:
        log_event(user_gid, "DOWNLOAD", "FAILURE", file_id=file_id)
        return jsonify({"error": "Error"}), 500

@bp.route('/api/get_logs', methods=['GET'])
@login_required
def get_logs():
    gid, role, target = session['user_gid'], session['role'], request.args.get('user')
    q = AuditLog.query
    if role == 'admin' and target: q = q.filter(AuditLog.user_gid.ilike(f"%{target}%"))
    elif role != 'admin': q = q.filter_by(user_gid=gid)
    logs = q.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([{"time": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "user": l.user_gid, "action": l.action, "status": l.status, "details": l.details, "is_anomaly": l.is_anomaly} for l in logs])

@bp.route('/api/download_logs', methods=['GET'])
@login_required
def download_logs():
    gid, role, target = session['user_gid'], session['role'], request.args.get('user')
    q = AuditLog.query
    if role == 'admin' and target: q = q.filter(AuditLog.user_gid.ilike(f"%{target}%"))
    elif role != 'admin': q = q.filter_by(user_gid=gid)
    logs = q.order_by(AuditLog.timestamp.desc()).all()
    
    proxy = io.StringIO()
    writer = csv.writer(proxy)
    writer.writerow(['Timestamp', 'User GID', 'Action', 'Status', 'Risk?', 'Score', 'Details'])
    for l in logs:
        writer.writerow([l.timestamp.strftime("%Y-%m-%d %H:%M:%S"), l.user_gid, l.action, l.status, "YES" if l.is_anomaly else "No", f"{l.anomaly_score:.4f}" if l.anomaly_score else "0", l.details])
    
    mem = io.BytesIO()
    mem.write(proxy.getvalue().encode('utf-8'))
    mem.seek(0)
    proxy.close()
    
    fname = f"{target.split('@')[0]}_logs.csv" if target else "full_logs.csv"
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name=fname)