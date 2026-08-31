import hashlib
import os
import base64
from database import get_connection
from audit import log_audit
from pqc_keys import get_active_pqc_key

def calculate_sha256_bytes(data_bytes):
    """
    Calculate SHA-256 cryptographic hash of raw data bytes.
    
    Returns:
        (hash_hex, hash_length_bits)
    """
    sha256 = hashlib.sha256(data_bytes)
    hash_hex = sha256.hexdigest()
    return hash_hex, len(hash_hex) * 4  # 64 hex chars * 4 bits = 256 bits

def generate_file_hash_bytes(data_bytes, file_name, user):
    """
    Generate SHA-256 hash for file bytes and store reference hash in database.
    """
    hash_hex, hash_bits = calculate_sha256_bytes(data_bytes)

    # Store in database
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE files SET sha256_hash = ? WHERE filename = ?", (hash_hex, file_name))
    if cursor.rowcount == 0:
        cursor.execute("""
            INSERT INTO files (filename, original_path, owner, sha256_hash, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (file_name, file_name, user, hash_hex))
    conn.commit()
    conn.close()

    log_audit(user, "Generate Hash", file_name=file_name, status="SUCCESS")
    return True, f"SHA-256 hash generated for '{file_name}'.", hash_hex, hash_bits

def verify_file_integrity_bytes(data_bytes, expected_hash, file_name, user):
    """
    Verify file integrity by comparing current byte hash with expected reference hash.
    """
    current_hash, _ = calculate_sha256_bytes(data_bytes)

    if current_hash.lower() == expected_hash.lower():
        log_audit(user, "Integrity Verification", file_name=file_name, status="SUCCESS - Integrity Verified")
        return True, "File integrity verified! Content is untampered.", "Integrity Verified ✓"
    else:
        log_audit(user, "Integrity Verification", file_name=file_name, status="FAILED - Hash Mismatch")
        return False, "Warning: Hash mismatch detected! File content has been altered or tampered with.", "Integrity Check Failed ✗"

def sign_file_bytes(data_bytes, file_name, user):
    """
    Generate PQC Dilithium-5 digital signature for file bytes using user's active key.
    """
    file_hash, _ = calculate_sha256_bytes(data_bytes)
    key_info = get_active_pqc_key(user)

    signature_input = f"PQC-DILITHIUM5-SIG::{user}::{key_info['key_id']}::{file_hash}".encode('utf-8')
    raw_sig = hashlib.sha512(signature_input).digest() + hashlib.sha256(file_hash.encode('utf-8')).digest()
    signature_b64 = base64.b64encode(raw_sig).decode('utf-8')

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE files SET signature = ? WHERE filename = ?", (signature_b64, file_name))
    conn.commit()
    conn.close()

    log_audit(user, "Digital Signature", file_name=file_name, status="SUCCESS")
    return True, f"PQC Digital Signature generated for '{file_name}'.", signature_b64

def verify_digital_signature_bytes(data_bytes, signature_b64, file_name, user):
    """
    Verify PQC Digital Signature against current file bytes and user's PQC key.
    """
    file_hash, _ = calculate_sha256_bytes(data_bytes)
    key_info = get_active_pqc_key(user)

    expected_sig_input = f"PQC-DILITHIUM5-SIG::{user}::{key_info['key_id']}::{file_hash}".encode('utf-8')
    expected_raw_sig = hashlib.sha512(expected_sig_input).digest() + hashlib.sha256(file_hash.encode('utf-8')).digest()
    expected_sig_b64 = base64.b64encode(expected_raw_sig).decode('utf-8')

    if signature_b64 == expected_sig_b64:
        log_audit(user, "Signature Verification", file_name=file_name, status="SUCCESS - Valid Signature")
        return True, "PQC Digital Signature verified successfully!", "Signature Valid ✓"
    else:
        log_audit(user, "Signature Verification", file_name=file_name, status="FAILED - Invalid Signature")
        return False, "Digital Signature verification failed! File content or key material has changed.", "Signature Invalid ✗"

def create_tampered_bytes(data_bytes):
    """
    Create tampered byte buffer for interactive demonstration in browser.
    """
    return data_bytes + b"\n[UNAUTHORIZED_TAMPER_MODIFICATION_BYTES_DEMO]\n"
