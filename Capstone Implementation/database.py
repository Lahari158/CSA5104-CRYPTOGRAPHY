import sqlite3
import os

DB_PATH = "pqc_system.db"

# System directories
SECURE_FILES_DIR = "secure_files"
ENCRYPTED_FILES_DIR = "encrypted_files"
TRANSFERRED_FILES_DIR = "transferred_files"
REPORTS_DIR = "reports"

def ensure_directories():
    """Ensure all required system directories exist."""
    for folder in [SECURE_FILES_DIR, ENCRYPTED_FILES_DIR, TRANSFERRED_FILES_DIR, REPORTS_DIR]:
        os.makedirs(folder, exist_ok=True)

def get_connection():
    """Get SQLite database connection with WAL mode and 10s timeout to prevent locking."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and create required directories."""
    ensure_directories()
    conn = get_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Files Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_path TEXT,
            encrypted_path TEXT,
            owner TEXT NOT NULL,
            sha256_hash TEXT,
            signature TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # Permissions Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            filename TEXT NOT NULL,
            user_or_role TEXT NOT NULL,
            permission TEXT NOT NULL,
            granted_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Audit Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            file_name TEXT,
            status TEXT NOT NULL
        )
    """)

    # PQC Keys Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT UNIQUE NOT NULL,
            user TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            status TEXT NOT NULL,
            creation_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            public_key_pem TEXT,
            private_key_pem TEXT
        )
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
