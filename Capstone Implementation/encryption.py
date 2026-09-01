import os
import shutil
from datetime import datetime
from cryptography.fernet import Fernet
from database import get_connection, SECURE_FILES_DIR, ENCRYPTED_FILES_DIR, TRANSFERRED_FILES_DIR
from audit import log_audit

# Module-level static key for Fernet symmetric encryption session
_SESSION_FERNET_KEY = Fernet.generate_key()
_FERNET_CIPHER = Fernet(_SESSION_FERNET_KEY)

def format_file_size(size_bytes):
    """Format file size in human readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"

def encrypt_bytes(data_bytes, file_name, user):
    """
    Encrypt raw file bytes using authenticated Fernet (AES-128-CBC + HMAC-SHA256).
    Saves encrypted output into encrypted_files/ directory and returns encrypted bytes.
    """
    encrypted_filename = f"enc_{file_name}.pqc"
    encrypted_dest_path = os.path.join(ENCRYPTED_FILES_DIR, encrypted_filename)

    try:
        encrypted_data = _FERNET_CIPHER.encrypt(data_bytes)

        with open(encrypted_dest_path, 'wb') as f:
            f.write(encrypted_data)

        # Register file in database
        conn = get_connection()
        cursor = conn.cursor()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO files (filename, original_path, encrypted_path, owner, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (file_name, file_name, encrypted_dest_path, user, created_at))
        file_id = cursor.lastrowid

        # Grant owner full permissions
        for perm in ["Read", "Write", "Download", "Delete"]:
            cursor.execute("""
                INSERT INTO permissions (file_id, filename, user_or_role, permission, granted_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (file_id, file_name, user, perm, user, created_at))

        conn.commit()
        conn.close()

        log_audit(user, "File Encryption", file_name=file_name, status="SUCCESS")
        return True, f"File '{file_name}' encrypted successfully.", encrypted_data, encrypted_filename

    except Exception as e:
        log_audit(user, "File Encryption", file_name=file_name, status=f"FAILED - {str(e)}")
        return False, f"Encryption failed: {str(e)}", None, None

def decrypt_bytes(encrypted_bytes, enc_filename, user):
    """
    Decrypt encrypted raw bytes back to plaintext.
    """
    if enc_filename.startswith("enc_") and enc_filename.endswith(".pqc"):
        original_name = enc_filename[4:-4]
    else:
        original_name = "decrypted_" + enc_filename

    try:
        decrypted_data = _FERNET_CIPHER.decrypt(encrypted_bytes)

        # Also save local copy in secure_files/
        decrypted_dest_path = os.path.join(SECURE_FILES_DIR, original_name)
        with open(decrypted_dest_path, 'wb') as f:
            f.write(decrypted_data)

        log_audit(user, "File Decryption", file_name=original_name, status="SUCCESS")
        return True, f"File decrypted successfully as '{original_name}'.", decrypted_data, original_name

    except Exception as e:
        log_audit(user, "File Decryption", file_name=enc_filename, status=f"FAILED - {str(e)}")
        return False, f"Decryption failed: {str(e)}", None, None

def transfer_bytes(encrypted_bytes, filename, user):
    """
    Simulate secure PQC file transfer by saving file bytes into transferred_files/ directory.
    """
    transferred_path = os.path.join(TRANSFERRED_FILES_DIR, filename)
    try:
        with open(transferred_path, 'wb') as f:
            f.write(encrypted_bytes)
        log_audit(user, "File Transfer", file_name=filename, status="SUCCESS")
        return True, f"Transfer Successful! Saved to '{transferred_path}'."
    except Exception as e:
        log_audit(user, "File Transfer", file_name=filename, status=f"FAILED - {str(e)}")
        return False, f"Transfer failed: {str(e)}"
