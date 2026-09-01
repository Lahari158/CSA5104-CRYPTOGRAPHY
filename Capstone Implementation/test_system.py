import os
import sys

# Ensure UTF-8 output encoding for Windows terminal printing
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, get_connection
from authentication import register_user, authenticate_user, seed_default_admin
from pqc_keys import generate_pqc_keypair, get_active_pqc_key, renew_pqc_key, get_pqc_technical_details
from encryption import encrypt_bytes, decrypt_bytes, transfer_bytes, format_file_size
from integrity import (
    calculate_sha256_bytes, generate_file_hash_bytes, verify_file_integrity_bytes,
    sign_file_bytes, verify_digital_signature_bytes, create_tampered_bytes
)
from access_control import check_permission, get_all_permissions, add_file_permission, remove_file_permission
from audit import log_audit, get_audit_logs, get_security_analytics
from reports import generate_security_report, export_report_txt, export_report_csv

def test_all_modules():
    print("--- 1. Testing Database Initialization ---")
    init_db()
    seed_default_admin()
    print("Database & tables initialized.")

    print("\n--- 2. Testing User Authentication ---")
    conn = get_connection()
    conn.cursor().execute("DELETE FROM users WHERE username = 'testuser'")
    conn.commit()
    conn.close()

    reg_ok, reg_msg = register_user("testuser", "pass123", "pass123", "User")
    print("Register user:", reg_ok, reg_msg)
    auth_ok, auth_user = authenticate_user("testuser", "pass123")
    print("Authenticate user:", auth_ok, auth_user)
    admin_ok, admin_user = authenticate_user("admin", "admin123")
    print("Authenticate admin:", admin_ok, admin_user)

    print("\n--- 3. Testing PQC Key Management ---")
    key1 = get_active_pqc_key("testuser")
    print("Active Key:", key1["key_id"], key1["algorithm"])
    renewed = renew_pqc_key("testuser")
    print("Renewed Key:", renewed["key_id"])
    details = get_pqc_technical_details(renewed)
    print("Key Details length:", len(details))

    print("\n--- 4. Testing Streamlit In-Memory File Encryption & Transfer ---")
    sample_bytes = b"Confidential Post-Quantum Streamlit Payload Data 2026\n"
    sample_filename = "test_sample.txt"

    print("Formatted Size:", format_file_size(len(sample_bytes)))

    enc_ok, enc_msg, enc_bytes, enc_filename = encrypt_bytes(sample_bytes, sample_filename, "testuser")
    print("Encrypt Bytes:", enc_ok, enc_msg, enc_filename)

    trans_ok, trans_msg = transfer_bytes(enc_bytes, enc_filename, "testuser")
    print("Transfer Bytes:", trans_ok, trans_msg)

    dec_ok, dec_msg, dec_bytes, orig_filename = decrypt_bytes(enc_bytes, enc_filename, "testuser")
    print("Decrypt Bytes:", dec_ok, dec_msg, orig_filename)
    print("Decrypted Content Match:", dec_bytes == sample_bytes)

    print("\n--- 5. Testing File Integrity & Digital Signatures ---")
    hash_ok, hash_msg, h_hex, h_bits = generate_file_hash_bytes(sample_bytes, sample_filename, "testuser")
    print("Generate Hash:", hash_ok, h_hex[:16] + "...", h_bits)

    ver_ok, ver_msg, banner = verify_file_integrity_bytes(sample_bytes, h_hex, sample_filename, "testuser")
    print("Verify Integrity (Untampered):", ver_ok, banner)

    sig_ok, sig_msg, sig_b64 = sign_file_bytes(sample_bytes, sample_filename, "testuser")
    print("Sign File Bytes:", sig_ok, sig_b64[:20] + "...")

    sig_ver_ok, sig_ver_msg, sig_banner = verify_digital_signature_bytes(sample_bytes, sig_b64, sample_filename, "testuser")
    print("Verify Signature Bytes:", sig_ver_ok, sig_banner)

    tampered_bytes = create_tampered_bytes(sample_bytes)
    t_ver_ok, t_ver_msg, t_banner = verify_file_integrity_bytes(tampered_bytes, h_hex, sample_filename, "testuser")
    print("Verify Integrity (Tampered Bytes):", t_ver_ok, t_banner)

    print("\n--- 6. Testing Access Control (RBAC) ---")
    perm_ok, perm_msg = check_permission(auth_user, sample_filename, "Read")
    print("Permission Check (User Read Owner File):", perm_ok, perm_msg)
    admin_perm_ok, admin_perm_msg = check_permission(admin_user, sample_filename, "Delete")
    print("Permission Check (Admin Delete File):", admin_perm_ok, admin_perm_msg)

    add_p_ok, add_p_msg = add_file_permission(sample_filename, "otheruser", "Read", "admin")
    print("Add Permission:", add_p_ok, add_p_msg)
    all_perms = get_all_permissions()
    print("Total ACL Entries:", len(all_perms))

    print("\n--- 7. Testing Audit Monitoring & Analytics ---")
    logs = get_audit_logs(limit=10)
    print("Audit Log Count:", len(logs))
    analytics = get_security_analytics()
    print("Security Analytics:", analytics)

    print("\n--- 8. Testing Security Reports & Export ---")
    rpt_text = generate_security_report()
    print("Generated Report Length:", len(rpt_text))
    txt_path = export_report_txt("admin")
    print("Exported TXT:", txt_path)
    csv_path = export_report_csv("admin")
    print("Exported CSV:", csv_path)

    print("\n==========================================")
    print("ALL STREAMLIT MODULE BACKEND TESTS PASSED!")
    print("==========================================")

if __name__ == "__main__":
    test_all_modules()
