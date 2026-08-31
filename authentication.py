import hashlib
import os
from datetime import datetime
from database import get_connection
from audit import log_audit

def hash_password(password, salt=None):
    """Hash password using PBKDF2 HMAC SHA-256 with salt."""
    if salt is None:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        bytes.fromhex(salt),
        100000
    ).hex()
    return hashed, salt

def register_user(username, password, confirm_password, role="User"):
    """
    Register a new user in the system.
    
    Returns:
        (bool, str): (Success flag, Message)
    """
    username = username.strip()
    if not username or not password:
        return False, "Username and password cannot be empty."

    if password != confirm_password:
        return False, "Passwords do not match."

    if len(password) < 4:
        return False, "Password must be at least 4 characters long."

    if role not in ["Admin", "User"]:
        role = "User"

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        log_audit(username, "Registration", status="FAILED - User Exists")
        return False, f"Username '{username}' is already taken."

    pwd_hash, salt = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO users (username, password_hash, salt, role, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (username, pwd_hash, salt, role, created_at))

    conn.commit()
    conn.close()

    log_audit(username, "User Registration", status="SUCCESS")
    return True, f"User '{username}' registered successfully as {role}."

def authenticate_user(username, password):
    """
    Authenticate user with username and password.
    
    Returns:
        (bool, dict/str): (Success flag, user dict or error message)
    """
    username = username.strip()
    if not username or not password:
        log_audit(username or "Unknown", "User Login", status="FAILED - Empty Input")
        return False, "Username and password are required."

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        log_audit(username, "User Login", status="FAILED - Invalid User")
        return False, "Invalid username or password."

    stored_hash = user["password_hash"]
    salt = user["salt"]

    calculated_hash, _ = hash_password(password, salt)

    if calculated_hash != stored_hash:
        log_audit(username, "User Login", status="FAILED - Wrong Password")
        return False, "Invalid username or password."

    log_audit(username, "User Login", status="SUCCESS")
    return True, {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": user["created_at"]
    }

def seed_default_admin():
    """Ensure at least one admin account exists on startup."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'Admin'")
    admin_count = cursor.fetchone()[0]
    conn.close()

    if admin_count == 0:
        register_user("admin", "admin123", "admin123", role="Admin")

def get_all_users():
    """Get list of registered users."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
    users = cursor.fetchall()
    conn.close()
    return [dict(u) for u in users]
