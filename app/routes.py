from flask import Blueprint, request, jsonify, send_file
from . import db, GLOBAL_SETUP
from .models import User, AttributeKey, EhrFile, AuditLog
import io
import datetime

bp = Blueprint('api', __name__, url_prefix='/api')

def get_crypto_core(): return GLOBAL_SETUP.get('crypto_core')
def get_authorities(): return GLOBAL_SETUP.get('authorities')
def get_public_keys(): return GLOBAL_SETUP.get('public_keys')

def log_event(user_gid, action, status, file_id=None, details=""):
    try:
        new_log = AuditLog(user_gid=user_gid, action=action, status=status, file_id=str(file_id) if file_id else None, details=str(details))
        db.session.add(new_log)
        db.session.commit()
    except Exception as e: print(f"LOGGING FAILED: {e}")

@bp.route('/status', methods=['GET'])
def get_status(): return jsonify({"status": "Server running"}), 200

@bp.route('/get_logs', methods=['GET'])
def get_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    log_list = []
    for l in logs:
        log_list.append({"time": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "user": l.user_gid, "action": l.action, "status": l.status, "file": l.file_id, "details": l.details})
    return jsonify(log_list), 200

@bp.route('/register_user', methods=['POST'])
def register_user():
    data = request.get_json()
    try:
        if not data or 'gid' not in data: return jsonify({"error": "Missing GID"}), 400
        if User.query.get(data['gid']): return jsonify({"error": "User exists"}), 400
        new_user = User(gid=data['gid'], username=data.get('username', 'Unknown'))
        db.session.add(new_user); db.session.commit()
        log_event(data['gid'], "REGISTER", "SUCCESS")
        return jsonify({"message": "User registered"}), 201
    except Exception as e: return jsonify({"error": str(e)}), 500

@bp.route('/issue_key', methods=['POST'])
def issue_key():
    data = request.get_json()
    gid = data.get('gid')
    attr = data.get('attribute')
    try:
        user = User.query.get(gid)
        if not user: return jsonify({"error": "User not found"}), 404
        authorities = get_authorities()
        authority = authorities.get(data['authority_id'])
        crypto_core = get_crypto_core()
        full_attribute_name = f"{data['authority_id']}_{attr}"
        
        key_comp_bytes = crypto_core.generate_user_key(authority.secret_key, gid, full_attribute_name)
        
        attr_key_name = full_attribute_name
        existing_key = AttributeKey.query.filter_by(user_gid=gid, attribute_name=attr_key_name).first()
        if existing_key: existing_key.key_component = key_comp_bytes
        else:
            new_key = AttributeKey(user_gid=gid, attribute_name=attr_key_name, key_component=key_comp_bytes)
            db.session.add(new_key)
        db.session.commit()
        
        # --- FIX: Log as SYSTEM action ---
        log_event("SYSTEM", "ISSUE_KEY", "SUCCESS", details=f"Issued {attr_key_name} to {gid}")
        
        return jsonify({"message": f"Key issued: {attr_key_name}"}), 200
    except Exception as e:
        log_event("SYSTEM", "ISSUE_KEY", "FAILURE", details=str(e))
        return jsonify({"error": str(e)}), 500

@bp.route('/revoke_key', methods=['POST'])
def revoke_key():
    data = request.get_json()
    gid = data.get('gid')
    try:
        full_attribute_name = f"{data['authority_id']}_{data['attribute']}"
        key_to_delete = AttributeKey.query.filter_by(user_gid=gid, attribute_name=full_attribute_name).first()
        if key_to_delete:
            db.session.delete(key_to_delete)
            db.session.commit()
            
            # --- FIX: Log as SYSTEM action ---
            log_event("SYSTEM", "REVOKE_KEY", "SUCCESS", details=f"Revoked {full_attribute_name} from {gid}")
            
            return jsonify({"message": "Key revoked"}), 200
        else:
            log_event("SYSTEM", "REVOKE_KEY", "FAILURE", details="Key not found")
            return jsonify({"error": "Key not found"}), 404
    except Exception as e: return jsonify({"error": str(e)}), 500

@bp.route('/upload_ehr', methods=['POST'])
def upload_ehr():
    filename = request.form.get('filename')
    try:
        file = request.files['file']
        policy_str = request.form.get('policy')
        file_bytes = file.read()
        crypto_core = get_crypto_core()
        public_keys = get_public_keys()
        encrypted_package = crypto_core.encrypt_file(public_keys, policy_str, file_bytes, filename)
        new_ehr_file = EhrFile(
            filename=encrypted_package['safe_db_name'],
            policy=encrypted_package['policy'],
            abe_ciphertext=encrypted_package['abe_ciphertext'],
            aes_iv=encrypted_package['aes_iv'],
            aes_ciphertext=encrypted_package['aes_ciphertext']
        )
        db.session.add(new_ehr_file)
        db.session.commit()
        log_event("SYSTEM", "UPLOAD", "SUCCESS", file_id=new_ehr_file.id, details=filename)
        return jsonify({"message": "File encrypted", "file_id": new_ehr_file.id}), 201
    except Exception as e:
        log_event("SYSTEM", "UPLOAD", "FAILURE", details=str(e))
        return jsonify({"error": str(e)}), 500

@bp.route('/download_ehr/<int:file_id>', methods=['POST'])
def download_ehr(file_id):
    data = request.get_json()
    user_gid = data.get('gid')
    try:
        user = User.query.get(user_gid)
        if not user: return jsonify({"error": "User not found"}), 404
        ehr_file = EhrFile.query.get(file_id)
        if not ehr_file: return jsonify({"error": "File not found"}), 404

        user_keys = AttributeKey.query.filter_by(user_gid=user_gid).all()
        user_key_dict = {key.attribute_name: key.key_component for key in user_keys}

        encrypted_package = {
            "policy": ehr_file.policy,
            "abe_ciphertext": ehr_file.abe_ciphertext,
            "aes_iv": ehr_file.aes_iv,
            "aes_ciphertext": ehr_file.aes_ciphertext
        }
        
        crypto_core = get_crypto_core()
        result = crypto_core.decrypt_file(user_gid, user_key_dict, encrypted_package)
        
        if result is None or 'error' in result:
            error_msg = result['error'] if result and 'error' in result else "Decryption failed"
            log_event(user_gid, "DOWNLOAD", "FAILURE", file_id=file_id, details=error_msg)
            return jsonify({"error": error_msg}), 403
            
        log_event(user_gid, "DOWNLOAD", "SUCCESS", file_id=file_id, details=result['filename'])
        
        return send_file(
            io.BytesIO(result['data']),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=result['filename']
        )
    except Exception as e:
        log_event(user_gid, "DOWNLOAD", "CRASH", file_id=file_id, details=str(e))
        return jsonify({"error": str(e)}), 500