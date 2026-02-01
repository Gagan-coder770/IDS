from flask import Blueprint, render_template, request
from flask_login import login_required
import os
import json
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet, InvalidToken

password_manager_bp = Blueprint('password_manager', __name__)

PASSWORD_FILE = 'passwords.json'
SALT_FILE = 'pm_salt.bin'
FERNET_KEY_FILE = 'pm_fernet.key'

def get_pm_salt():
    if not os.path.exists(SALT_FILE):
        salt = secrets.token_bytes(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt

def get_fernet_key():
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, 'wb') as f:
            f.write(key)
    return key

def load_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return []
    with open(PASSWORD_FILE, 'r') as f:
        return json.load(f)

def save_passwords(data):
    with open(PASSWORD_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def encrypt_password(password, fernet):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(enc_password, fernet):
    return fernet.decrypt(enc_password.encode()).decode()

@password_manager_bp.route('/', methods=['GET', 'POST'])
@login_required
def password_manager():
    error = None
    fernet = Fernet(get_fernet_key())
    passwords = load_passwords()

    if request.method == "POST":
        action = request.form.get("action")
        site = request.form.get("site", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if action == "add":
            if not site or not username or not password:
                error = "All fields are required."
            else:
                enc_pw = encrypt_password(password, fernet)
                for entry in passwords:
                    if entry["site"].lower() == site.lower():
                        error = "Account for this site already exists."
                        break
                if not error:
                    passwords.append({"site": site, "username": username, "password": enc_pw})
                    save_passwords(passwords)
        elif action == "update":
            found = False
            for entry in passwords:
                if entry["site"].lower() == site.lower():
                    entry["password"] = encrypt_password(password, fernet)
                    found = True
                    break
            if found:
                save_passwords(passwords)
            else:
                error = "Account not found."
        elif action == "delete":
            orig_len = len(passwords)
            passwords = [entry for entry in passwords if entry["site"].lower() != site.lower()]
            if len(passwords) < orig_len:
                save_passwords(passwords)
            else:
                error = "Account not found."
        elif action == "retrieve":
            for entry in passwords:
                if entry["site"].lower() == site.lower():
                    try:
                        entry["password"] = decrypt_password(entry["password"], fernet)
                    except Exception:
                        error = "Decryption failed."
                    break
            else:
                error = "Account not found."

    display_passwords = []
    for entry in passwords:
        display_passwords.append({
            "site": entry["site"],
            "username": entry["username"],
            "password": "********"
        })

    return render_template("password_manager.html", passwords=display_passwords, error=error)
