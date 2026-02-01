import os
import json
import base64
import getpass
import hashlib
import secrets
from cryptography.fernet import Fernet, InvalidToken

PASSWORD_FILE = 'passwords.json'
MASTER_FILE = 'master.hash'
SALT_FILE = 'salt.bin'

# --- Utility Functions ---
def get_salt():
    if not os.path.exists(SALT_FILE):
        salt = secrets.token_bytes(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt

def hash_master_password(password, salt):
    return hashlib.sha256(salt + password.encode()).hexdigest()

def load_master_hash():
    if not os.path.exists(MASTER_FILE):
        return None
    with open(MASTER_FILE, 'r') as f:
        return f.read().strip()

def save_master_hash(hashval):
    with open(MASTER_FILE, 'w') as f:
        f.write(hashval)

def get_fernet_key(master_password, salt):
    # Derive a Fernet key from the master password and salt
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100_000, dklen=32)
    return base64.urlsafe_b64encode(key)

# --- Password Data Functions ---
def load_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return {}
    with open(PASSWORD_FILE, 'r') as f:
        return json.load(f)

def save_passwords(data):
    with open(PASSWORD_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# --- Password Generator ---
def generate_password(length=12):
    import string
    chars = string.ascii_letters + string.digits + '!@#$%^&*()_+-='
    return ''.join(secrets.choice(chars) for _ in range(length))

# --- CLI Menu Functions ---
def add_account(fernet, passwords):
    service = input('Service name: ').strip()
    username = input('Username: ').strip()
    pw_choice = input('Enter password or leave blank to generate: ')
    if not pw_choice:
        password = generate_password()
        print(f'Generated password: {password}')
    else:
        password = pw_choice
    enc_pw = fernet.encrypt(password.encode()).decode()
    passwords[service] = {'username': username, 'password': enc_pw}
    save_passwords(passwords)
    print('Account added.')

def view_accounts(passwords):
    if not passwords:
        print('No accounts saved.')
        return
    print('Saved accounts:')
    for service in passwords:
        print(f'- {service}')

def retrieve_password(fernet, passwords):
    service = input('Service name: ').strip()
    if service not in passwords:
        print('Account not found.')
        return
    try:
        enc_pw = passwords[service]['password']
        password = fernet.decrypt(enc_pw.encode()).decode()
        print(f'Password for {service}: {password}')
    except InvalidToken:
        print('Decryption failed. Wrong master password?')

def update_password(fernet, passwords):
    service = input('Service name: ').strip()
    if service not in passwords:
        print('Account not found.')
        return
    new_pw = input('Enter new password (leave blank to generate): ')
    if not new_pw:
        new_pw = generate_password()
        print(f'Generated password: {new_pw}')
    enc_pw = fernet.encrypt(new_pw.encode()).decode()
    passwords[service]['password'] = enc_pw
    save_passwords(passwords)
    print('Password updated.')

def delete_account(passwords):
    service = input('Service name: ').strip()
    if service not in passwords:
        print('Account not found.')
        return
    del passwords[service]
    save_passwords(passwords)
    print('Account deleted.')

# --- Main Program ---
def main():
    salt = get_salt()
    master_hash = load_master_hash()
    if master_hash is None:
        print('No master password set. Please create one.')
        while True:
            pw1 = getpass.getpass('Create master password: ')
            pw2 = getpass.getpass('Confirm master password: ')
            if pw1 != pw2:
                print('Passwords do not match. Try again.')
            elif not pw1:
                print('Password cannot be empty.')
            else:
                break
        hashval = hash_master_password(pw1, salt)
        save_master_hash(hashval)
        print('Master password set.')
        master_password = pw1
    else:
        for _ in range(3):
            pw = getpass.getpass('Enter master password: ')
            if hash_master_password(pw, salt) == master_hash:
                master_password = pw
                break
            else:
                print('Incorrect password.')
        else:
            print('Too many failed attempts. Exiting.')
            return
    fernet = Fernet(get_fernet_key(master_password, salt))
    passwords = load_passwords()
    while True:
        print('\n--- Password Manager ---')
        print('1. Add new password')
        print('2. View all accounts')
        print('3. Retrieve password')
        print('4. Update password')
        print('5. Delete account')
        print('6. Exit')
        choice = input('Select an option: ').strip()
        if choice == '1':
            add_account(fernet, passwords)
        elif choice == '2':
            view_accounts(passwords)
        elif choice == '3':
            retrieve_password(fernet, passwords)
        elif choice == '4':
            update_password(fernet, passwords)
        elif choice == '5':
            delete_account(passwords)
        elif choice == '6':
            print('Goodbye!')
            break
        else:
            print('Invalid option.')

if __name__ == '__main__':
    main()
