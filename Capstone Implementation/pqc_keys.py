import hashlib
import os
from datetime import datetime, timedelta
from database import get_connection
from audit import log_audit

DEFAULT_PQC_ALGORITHM = "CRYSTALS-Dilithium5 / CRYSTALS-Kyber1024 (Lattice-Based PQC Simulation)"

def generate_pqc_keypair(user):
    """
    Generate a Post-Quantum Cryptography (PQC) key pair for the user.
    Simulates NIST Level 5 Quantum-Resistant Lattice Key Parameters (Dilithium-5 / Kyber-1024).
    """
    timestamp = datetime.now()
    key_id = f"PQC-{user.upper()}-{int(timestamp.timestamp())}"
    creation_date = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    expiry_date = (timestamp + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")

    # Generate pseudo-random lattice key matrices & PEM representations
    seed = os.urandom(32)
    pub_key_hash = hashlib.sha256(b"PQC_PUBKEY_" + seed).hexdigest()
    priv_key_hash = hashlib.sha512(b"PQC_PRIVKEY_" + seed).hexdigest()

    public_key_pem = (
        "-----BEGIN POST-QUANTUM PUBLIC KEY-----\n"
        f"Algorithm: CRYSTALS-Dilithium5 (NIST Security Category 5)\n"
        f"Lattice-Params: n=1024, q=8380417, k=8, l=7\n"
        f"KeyHash: {pub_key_hash}\n"
        f"Matrix-A-Seed: {seed.hex()[:32]}\n"
        "-----END POST-QUANTUM PUBLIC KEY-----\n"
    )

    private_key_pem = (
        "-----BEGIN POST-QUANTUM PRIVATE KEY-----\n"
        f"Algorithm: CRYSTALS-Dilithium5 / Kyber1024\n"
        f"SecretVector-s1: {priv_key_hash[:64]}\n"
        f"SecretVector-s2: {priv_key_hash[64:]}\n"
        "-----END POST-QUANTUM PRIVATE KEY-----\n"
    )

    conn = get_connection()
    cursor = conn.cursor()

    # Deactivate existing active keys for this user
    cursor.execute("""
        UPDATE keys SET status = 'EXPIRED' WHERE user = ? AND status = 'ACTIVE'
    """, (user,))

    # Insert new key
    cursor.execute("""
        INSERT INTO keys (key_id, user, algorithm, status, creation_date, expiry_date, public_key_pem, private_key_pem)
        VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?, ?)
    """, (key_id, user, DEFAULT_PQC_ALGORITHM, creation_date, expiry_date, public_key_pem, private_key_pem))

    conn.commit()
    conn.close()

    log_audit(user, "PQC Key Generation", file_name=key_id, status="SUCCESS")
    return {
        "key_id": key_id,
        "user": user,
        "algorithm": DEFAULT_PQC_ALGORITHM,
        "status": "ACTIVE",
        "creation_date": creation_date,
        "expiry_date": expiry_date,
        "public_key_pem": public_key_pem,
        "private_key_pem": private_key_pem
    }

def get_active_pqc_key(user):
    """Retrieve active PQC key for a user, auto-generating one if missing."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT key_id, user, algorithm, status, creation_date, expiry_date, public_key_pem, private_key_pem
        FROM keys
        WHERE user = ? AND status = 'ACTIVE'
        ORDER BY id DESC LIMIT 1
    """, (user,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    else:
        return generate_pqc_keypair(user)

def renew_pqc_key(user):
    """Renew/Rotate PQC Key pair for current user."""
    key_info = generate_pqc_keypair(user)
    log_audit(user, "PQC Key Renewal", file_name=key_info["key_id"], status="SUCCESS")
    return key_info

def get_pqc_technical_details(key_info):
    """Get formatted technical explanation of the PQC key parameters for demo modal."""
    return (
        "Post-Quantum Cryptography (PQC) Key Specification\n"
        "--------------------------------------------------\n"
        f"Key Identifier : {key_info['key_id']}\n"
        f"User / Owner   : {key_info['user']}\n"
        f"Algorithm Suite: CRYSTALS-Dilithium5 / CRYSTALS-Kyber1024\n"
        f"NIST Standard  : FIPS 204 (Module-Lattice Digital Signatures)\n"
        f"Security Level : NIST Security Category 5 (Quantum Equivalent: AES-256)\n\n"
        "Lattice Mathematics Parameters:\n"
        "  - Polynomial Degree (n) : 1024\n"
        "  - Prime Modulus (q)     : 8380417\n"
        "  - Vector Dimensions     : k=8, l=7\n"
        "  - Public Key Size       : 2,592 Bytes\n"
        "  - Secret Key Size       : 4,864 Bytes\n"
        "  - Quantum Resistance    : Shor's & Grover's Algorithm Proof\n\n"
        "Public Key Material:\n"
        f"{key_info['public_key_pem']}"
    )
