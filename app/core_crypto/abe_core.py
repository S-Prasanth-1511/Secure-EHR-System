from charm.toolbox.pairinggroup import PairingGroup, GT, ZR, G1, G2
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes, bytesToObject
from .hybrid_aes import encrypt_aes, decrypt_aes
import re
import hashlib
import pickle
import json
import base64
import uuid
import os
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class CryptoCore:
    def __init__(self):
        print("--- CRYPTO CORE v114.0 (FULL RAM FIX) LOADED ---")
        self.group = PairingGroup('SS512')
        self.maabe = MaabeRW15(self.group)
        self.gp = None
        self.storage_path = "crypto_storage"
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)

    def _deep_serialize(self, obj):
        if isinstance(obj, dict):
            return {k: self._deep_serialize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_serialize(v) for v in obj]
        if callable(obj): return None
        try:
            return objectToBytes(obj, self.group)
        except:
            return obj

    def _deep_deserialize(self, obj):
        if obj is None: return None
        if isinstance(obj, dict):
            return {k: self._deep_deserialize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_deserialize(v) for v in obj]
        elif isinstance(obj, bytes):
            try:
                return bytesToObject(obj, self.group)
            except:
                return obj
        return obj

    def serialize(self, charm_object):
        safe_obj = self._deep_serialize(charm_object)
        return pickle.dumps(safe_obj)

    def deserialize(self, object_bytes):
        safe_obj = pickle.loads(object_bytes)
        return self._deep_deserialize(safe_obj)

    def setup_global(self):
        print("GENERATING FRESH Global Parameters (RAM Mode)...")
        self.gp = self.maabe.setup()
        print("Global Setup Complete.")

    def setup_authority(self, authority_id):
        if self.gp is None: raise Exception("GP not setup")
        if isinstance(authority_id, bytes): authority_id = authority_id.decode('utf-8')
        
        print(f"GENERATING Fresh Keys for: {authority_id}")
        (pk, sk) = self.maabe.authsetup(self.gp, authority_id)
        
        if 'F' not in sk: sk['F'] = {}
        if 'F' not in pk: pk['F'] = {}

        sk.update(pk) # Merge
        
        pk_safe = self._deep_serialize(pk)
        sk_safe = self._deep_serialize(sk)
        
        return pickle.dumps(pk_safe), pickle.dumps(sk_safe)

    def _process_attribute_string(self, full_attr_name):
        if isinstance(full_attr_name, bytes): full_attr_name = full_attr_name.decode('utf-8')
        full_attr_name = full_attr_name.strip()
        if '_' in full_attr_name:
            parts = full_attr_name.split('_')
            auth_id, attr_val = parts[0], parts[1]
        elif '@' in full_attr_name:
            parts = full_attr_name.split('@')
            attr_val, auth_id = parts[0], parts[1]
        else: return full_attr_name
        hashed_val = hashlib.sha256(attr_val.encode('utf-8')).hexdigest()[:16].upper()
        return f"{hashed_val}@{auth_id}"

    def generate_user_key(self, auth_secret_key, user_gid, user_attribute):
        if self.gp is None: raise Exception("GP not setup")
        gp = self.gp
        if 'H' not in gp: gp['H'] = self.group.hash
        if 'F' not in gp: gp['F'] = self.group.hash

        if isinstance(auth_secret_key, dict):
             ask = self._deep_deserialize(auth_secret_key)
        else:
             ask = self._deep_deserialize(pickle.loads(auth_secret_key))
        
        if isinstance(ask, dict):
            for k, v in ask.items():
                if isinstance(v, bytes):
                    try:
                        decoded = v.decode('utf-8')
                        if decoded in ['MA', 'HA']: ask[k] = decoded
                    except: pass

        hashed_attribute = self._process_attribute_string(user_attribute)
        if isinstance(user_gid, bytes): user_gid = user_gid.decode('utf-8')
        
        print(f"DEBUG: Keygen GID: '{user_gid}' | Attr: '{hashed_attribute}'")
        
        # RAM-Only: Generate F params on the fly
        if 'F' not in ask: ask['F'] = {}
        if hashed_attribute not in ask['F']:
            print(f"DEBUG: Generating new secret param for '{hashed_attribute}'")
            ask['F'][hashed_attribute] = self.group.random(G1) 

        user_key_comp = self.maabe.keygen(gp, ask, user_gid, hashed_attribute)
        return self.serialize(user_key_comp)

    def encrypt_file(self, public_keys_dict, policy_str, file_bytes, real_filename="unknown.txt"):
        if self.gp is None: raise Exception("GP not setup")
        gp = self.gp
        if 'H' not in gp: gp['H'] = self.group.hash
        if 'F' not in gp: gp['F'] = self.group.hash
        
        session_key_element = self.group.random(GT)
        session_key_bytes = objectToBytes(session_key_element, self.group)
        aes_key = hashlib.sha256(session_key_bytes).digest()

        file_b64 = base64.b64encode(file_bytes).decode('utf-8')
        envelope = { "filename": real_filename, "content": file_b64 }
        envelope_bytes = json.dumps(envelope).encode('utf-8')

        cipher = AES.new(aes_key, AES.MODE_CBC)
        aes_iv = cipher.iv
        aes_ciphertext = cipher.encrypt(pad(envelope_bytes, 16))

        # --- RAM FIX: Use passed public_keys_dict directly ---
        # Do not try to load from disk.
        final_pks = {}
        for k, v in public_keys_dict.items():
            # Deserialize from pickle
            pk_obj = self._deep_deserialize(pickle.loads(v))
            key_id = k.decode('utf-8') if isinstance(k, bytes) else str(k)
            final_pks[key_id] = pk_obj
        
        def hash_match(match):
            full_attr = f"{match.group(1)}_{match.group(2)}"
            return self._process_attribute_string(full_attr)
        
        hashed_policy = re.sub(r'([A-Z]+)_([A-Z]+)', hash_match, policy_str)
        print(f"Encrypting Policy: {hashed_policy}")
        
        abe_ciphertext_dict = self.maabe.encrypt(gp, final_pks, session_key_element, hashed_policy)
        
        packed_ct = self._deep_serialize(abe_ciphertext_dict)
        packed_ct['policy'] = hashed_policy 
        
        abe_ciphertext_blob = pickle.dumps(packed_ct)
        safe_db_name = str(uuid.uuid4()) + ".enc"
        
        return {
            "policy": hashed_policy, 
            "abe_ciphertext": abe_ciphertext_blob,
            "aes_iv": aes_iv,
            "aes_ciphertext": aes_ciphertext,
            "safe_db_name": safe_db_name
        }

    def _sanitize_keys(self, d):
        if not isinstance(d, dict): return d
        new_d = {}
        for k, v in d.items():
            new_k = k.decode('utf-8') if isinstance(k, bytes) else k
            if isinstance(v, dict): new_d[new_k] = self._sanitize_keys(v)
            else: new_d[new_k] = v
        return new_d

    def _unpack_ciphertext(self, packed_ct):
        unpacked = {}
        for k, v in packed_ct.items():
            if k == 'policy':
                unpacked[k] = v
            elif isinstance(v, dict):
                unpacked[k] = {}
                for sub_k, sub_v in v.items():
                    if isinstance(sub_v, bytes):
                        try: unpacked[k][sub_k] = bytesToObject(sub_v, self.group)
                        except: unpacked[k][sub_k] = sub_v
                    else:
                        unpacked[k][sub_k] = sub_v
            elif isinstance(v, bytes):
                try: unpacked[k] = bytesToObject(v, self.group)
                except: unpacked[k] = v
            else:
                unpacked[k] = v
        return unpacked

    def decrypt_file(self, user_gid, user_key_dict, encrypted_package):
        if self.gp is None: raise Exception("GP not setup")
        gp = self.gp
        if 'H' not in gp: gp['H'] = self.group.hash
        if 'F' not in gp: gp['F'] = self.group.hash
        if isinstance(user_gid, bytes): user_gid = user_gid.decode('utf-8')

        deserialized_keys = {}
        for k, v in user_key_dict.items():
            raw_name = k.decode('utf-8') if isinstance(k, bytes) else str(k)
            hashed_name = self._process_attribute_string(raw_name)
            key_obj = self._deep_deserialize(pickle.loads(v))
            deserialized_keys[hashed_name] = key_obj

        try:
            packed_ct = pickle.loads(encrypted_package['abe_ciphertext'])
            real_ct = self._unpack_ciphertext(packed_ct)
        except Exception as e: raise Exception(f"Pickle Error: {e}")
             
        real_ct['policy'] = encrypted_package['policy']
        
        sk_wrapper = { 'keys': deserialized_keys, 'GID': user_gid }
        sk_wrapper = self._sanitize_keys(sk_wrapper)

        print("Decrypting Session Key...")
        try:
            session_key_element = self.maabe.decrypt(gp, sk_wrapper, real_ct) 
        except Exception as e:
            print(f"ABE Decryption Failed: {e}")
            # Return error message instead of None for debugging
            return {"error": str(e)}
        
        if not session_key_element: return None

        session_key_bytes = objectToBytes(session_key_element, self.group)
        aes_key = hashlib.sha256(session_key_bytes).digest()
        
        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, encrypted_package['aes_iv'])
            decrypted_padded = cipher.decrypt(encrypted_package['aes_ciphertext'])
            envelope_bytes = unpad(decrypted_padded, 16)
            envelope = json.loads(envelope_bytes.decode('utf-8'))
            return { "filename": envelope['filename'], "data": base64.b64decode(envelope['content']) }
        except Exception as e:
            print(f"AES Error: {e}")
            return None