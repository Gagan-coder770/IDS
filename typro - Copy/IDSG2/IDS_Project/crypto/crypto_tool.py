from flask import Blueprint, render_template, request, flash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import re

crypto_bp = Blueprint('crypto', __name__)

def is_valid_base64(s):
    """Check if a string is valid base64"""
    try:
        if isinstance(s, str):
            # Check if string is valid base64
            if re.match('^[A-Za-z0-9+/]*={0,2}$', s):
                base64.b64decode(s)
                return True
        return False
    except Exception:
        return False

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[-1])]

def unpad_bytes(data):
    """Remove PKCS7 padding from bytes"""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    padding_length = data[-1]
    if padding_length > len(data) or padding_length > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def aes_encrypt(plain_text, key):
    key = key.ljust(16)[:16].encode()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text).encode())
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def aes_decrypt(iv, ct, key):
    try:
        key = key.ljust(16)[:16].encode()
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = cipher.decrypt(ct)
        # First unpad the bytes, then decode to UTF-8
        unpadded_bytes = unpad_bytes(decrypted_bytes)
        pt = unpadded_bytes.decode('utf-8')
        return pt
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

@crypto_bp.route('/crypto', methods=['GET', 'POST'])
def crypto_home():
    encrypted_text = None
    encrypted_key = None
    decrypted_text = None
    error = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        key = request.form.get('key', '').strip()
        
        if not key:
            error = 'Key is required.'
        else:
            try:
                if action == 'encrypt':
                    text = request.form.get('text', '').strip()
                    if not text:
                        error = 'Text is required for encryption.'
                    else:
                        iv, ct = aes_encrypt(text, key)
                        # Combine IV and ciphertext for display
                        encrypted_text = f"{iv}:{ct}"
                        encrypted_key = base64.b64encode(key.encode()).decode('utf-8')
                        
                elif action == 'decrypt':
                    encrypted_data = request.form.get('encrypted_text', '').strip()
                    
                    if not encrypted_data:
                        error = 'Encrypted text is required for decryption.'
                    else:
                        # Check if the encrypted data contains IV:ciphertext format
                        if ':' in encrypted_data:
                            iv, ct = encrypted_data.split(':', 1)
                        else:
                            error = 'Invalid encrypted text format. Expected IV:Ciphertext format.'
                            return render_template('crypto_enhanced.html', 
                                                 encrypted_text=encrypted_text, 
                                                 encrypted_key=encrypted_key,
                                                 decrypted_text=decrypted_text, 
                                                 error=error)
                        
                        if not is_valid_base64(iv):
                            error = 'Invalid IV format. Must be valid base64.'
                        elif not is_valid_base64(ct):
                            error = 'Invalid ciphertext format. Must be valid base64.'
                        else:
                            # Try to decode the key if it appears to be Base64 encoded
                            decrypt_key = key
                            if is_valid_base64(key) and len(key) > 16:
                                try:
                                    decrypt_key = base64.b64decode(key).decode('utf-8')
                                except:
                                    decrypt_key = key  # Use original key if decoding fails
                            
                            pt = aes_decrypt(iv, ct, decrypt_key)
                            decrypted_text = pt
                        
            except Exception as e:
                error = f"Error: {str(e)}"
    
    return render_template('crypto_enhanced.html', 
                         encrypted_text=encrypted_text, 
                         encrypted_key=encrypted_key,
                         decrypted_text=decrypted_text, 
                         error=error)
