# app/core_crypto/hybrid_aes.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import io

# We will use AES-256 in CBC mode
KEY_SIZE = 32  # 32 bytes = 256 bits
BLOCK_SIZE = 16 # 16 bytes = 128 bits

def encrypt_aes(data_bytes):
    """
    Encrypts raw bytes using AES-256-CBC.
    
    Args:
        data_bytes (bytes): The raw data to encrypt.
        
    Returns:
        tuple: (aes_key, iv, ciphertext)
               - aes_key (bytes): The 32-byte symmetric key (this is what we will encrypt with ABE).
               - iv (bytes): The 16-byte initialization vector.
               - ciphertext (bytes): The encrypted data.
    """
    try:
        # 1. Generate a secure, random AES key
        aes_key = get_random_bytes(KEY_SIZE)
        
        # 2. Create an AES cipher object in CBC mode
        cipher = AES.new(aes_key, AES.MODE_CBC)
        
        # 3. Get the initialization vector (IV)
        iv = cipher.iv # The cipher generates a random 16-byte IV
        
        # 4. Encrypt the data
        # We must pad the data to be a multiple of the block size
        padded_data = pad(data_bytes, BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded_data)
        
        return aes_key, iv, ciphertext
        
    except Exception as e:
        print(f"AES Encryption Error: {e}")
        return None, None, None

def decrypt_aes(aes_key, iv, ciphertext):
    """
    Decrypts AES-256-CBC ciphertext.
    
    Args:
        aes_key (bytes): The 32-byte symmetric key.
        iv (bytes): The 16-byte initialization vector.
        ciphertext (bytes): The encrypted data.
        
    Returns:
        bytes: The original, decrypted raw data.
    """
    try:
        # 1. Create the AES cipher object with the same key and IV
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # 2. Decrypt the data
        decrypted_padded_data = cipher.decrypt(ciphertext)
        
        # 3. Unpad the data to get the original
        original_data = unpad(decrypted_padded_data, BLOCK_SIZE)
        
        return original_data
        
    except (ValueError, KeyError) as e:
        print(f"AES Decryption Error: {e}. Check if key is correct or data is corrupt.")
        return None