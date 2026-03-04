import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# =========================
# LAB CONFIGURATION
# =========================
TARGET_DIR = "./lab_test_data"   
KEY_FILE = "key.enc"

MODE = "encrypt"                
PASSWORD = "lab-password-123"   

SALT_SIZE = 16
PBKDF2_ITERS = 200_000

# =========================
# KEY MANAGEMENT
# =========================
def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_and_store_file_key(password: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    master_key = derive_master_key(password, salt)

    file_key = secrets.token_bytes(32)  # AES-256
    aesgcm = AESGCM(master_key)

    nonce = secrets.token_bytes(12)
    encrypted_key = aesgcm.encrypt(nonce, file_key, None)

    with open(KEY_FILE, "wb") as f:
        f.write(salt + nonce + encrypted_key)

    return file_key

def load_file_key(password: str) -> bytes:
    with open(KEY_FILE, "rb") as f:
        blob = f.read()

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + 12]
    encrypted_key = blob[SALT_SIZE + 12:]

    master_key = derive_master_key(password, salt)
    aesgcm = AESGCM(master_key)

    return aesgcm.decrypt(nonce, encrypted_key, None)

# =========================
# FILE OPERATIONS
# =========================
def encrypt_file(path: str, key: bytes):
    with open(path, "rb") as f:
        data = f.read()

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    enc_path = path + ".enc"

    # Write encrypted file
    with open(enc_path, "wb") as f:
        f.write(nonce + ciphertext)

    # Verification before deletion (realistic behavior)
    try:
        test = aesgcm.decrypt(nonce, ciphertext, None)
        if test == data and os.path.getsize(enc_path) > 0:
            os.remove(path)
            print(f"[+] Encrypted & removed: {path}")
    except Exception:
        print(f"[!] Verification failed, original kept: {path}")

def decrypt_file(path: str, key: bytes):
    with open(path, "rb") as f:
        blob = f.read()

    nonce = blob[:12]
    ciphertext = blob[12:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    original_path = path.replace(".enc", "")

    with open(original_path, "wb") as f:
        f.write(plaintext)

    os.remove(path)
    print(f"[+] Decrypted: {original_path}")

# =========================
# DIRECTORY WALK
# =========================
def encrypt_directory(password: str):
    key = generate_and_store_file_key(password)

    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if not file.endswith(".enc"):
                encrypt_file(os.path.join(root, file), key)

def decrypt_directory(password: str):
    key = load_file_key(password)

    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if file.endswith(".enc"):
                decrypt_file(os.path.join(root, file), key)

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    if MODE == "encrypt":
        encrypt_directory(PASSWORD)
    elif MODE == "decrypt":
        try:
            decrypt_directory(PASSWORD)
        except InvalidTag:
            print("[!] Decryption failed: wrong password or corrupted files")
