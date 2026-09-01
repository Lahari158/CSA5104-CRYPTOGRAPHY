from datetime import datetime
from database import get_connection

def log_audit(user, action, file_name=None, status="SUCCESS"):
    """
    Log an event to the audit_logs table.
    
    Parameters:
        user (str): Username performing action
        action (str): Description of action (e.g. Login, File Encryption)
        file_name (str): Associated file name (optional)
        status (str): Outcome status (e.g. SUCCESS, FAILED, ACCESS GRANTED, ACCESS DENIED)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, user, action, file_name, status)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, user, action, file_name or "N/A", status))
    conn.commit()
    conn.close()

def get_audit_logs(limit=50):
    """Retrieve audit log entries ordered by timestamp descending."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, user, action, file_name, status 
        FROM audit_logs 
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    logs = cursor.fetchall()
    conn.close()
    return logs

def get_security_analytics():
    """Compute aggregate security metrics for dashboard and analytics display."""
    conn = get_connection()
    cursor = conn.cursor()

    # Counts from database
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files")
    total_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%Login%' AND status = 'SUCCESS'")
    successful_logins = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%Login%' AND status != 'SUCCESS'")
    failed_logins = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%Encryption%' AND status = 'SUCCESS'")
    files_encrypted = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%Transfer%' AND status = 'SUCCESS'")
    files_transferred = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%Integrity%' OR action LIKE '%Hash%'")
    integrity_checks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%Integrity%' AND status LIKE '%FAILED%'")
    integrity_failures = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status LIKE '%DENIED%'")
    access_denied_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_events = cursor.fetchone()[0]

    conn.close()

    return {
        "total_users": total_users,
        "total_files": total_files,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "files_encrypted": files_encrypted,
        "files_transferred": files_transferred,
        "integrity_checks": integrity_checks,
        "integrity_failures": integrity_failures,
        "access_denied_events": access_denied_events,
        "total_events": total_events
    }
