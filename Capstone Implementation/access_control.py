from datetime import datetime
from database import get_connection
from audit import log_audit

def check_permission(user_dict, filename, required_permission):
    """
    Check if user has permission to perform action on filename.
    
    Rules:
    - Admin users have full access to all operations.
    - Owners have full access to their files.
    - Other users must have an explicit entry in permissions table for (user or role) and required_permission.
    
    Returns:
        (bool, str): (Allowed flag, Status message)
    """
    username = user_dict["username"]
    role = user_dict["role"]

    # Admin superuser override
    if role == "Admin":
        log_audit(username, f"Access Check ({required_permission})", file_name=filename, status="ACCESS GRANTED (Admin)")
        return True, "Access Granted ✓ (Admin Override)"

    conn = get_connection()
    cursor = conn.cursor()

    # Check file ownership
    cursor.execute("SELECT owner FROM files WHERE filename = ?", (filename,))
    file_row = cursor.fetchone()

    if file_row and file_row["owner"] == username:
        conn.close()
        log_audit(username, f"Access Check ({required_permission})", file_name=filename, status="ACCESS GRANTED (Owner)")
        return True, "Access Granted ✓ (File Owner)"

    # Check explicit permissions table
    cursor.execute("""
        SELECT permission FROM permissions 
        WHERE filename = ? AND (user_or_role = ? OR user_or_role = ? OR user_or_role = 'All')
        AND permission = ?
    """, (filename, username, role, required_permission))

    perm_row = cursor.fetchone()
    conn.close()

    if perm_row:
        log_audit(username, f"Access Check ({required_permission})", file_name=filename, status="ACCESS GRANTED")
        return True, "Access Granted ✓"
    else:
        log_audit(username, f"Access Check ({required_permission})", file_name=filename, status="ACCESS DENIED")
        return False, "Access Denied ✗ (Insufficient Permissions)"

def get_all_permissions():
    """Retrieve full matrix of file permissions for access control page."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.id, p.filename, f.owner, p.user_or_role, p.permission, p.granted_by, p.created_at
        FROM permissions p
        LEFT JOIN files f ON p.filename = f.filename
        ORDER BY p.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "filename": r["filename"],
            "owner": r["owner"] or "System",
            "user_or_role": r["user_or_role"],
            "permission": r["permission"],
            "granted_by": r["granted_by"],
            "status": "Active"
        })
    return result

def add_file_permission(filename, target_user_or_role, permission, granted_by_user):
    """Admin function to grant file permission to user or role."""
    if not filename or not target_user_or_role or not permission:
        return False, "All fields are required."

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    cursor = conn.cursor()

    # Get file_id if exists
    cursor.execute("SELECT id FROM files WHERE filename = ?", (filename,))
    file_row = cursor.fetchone()
    file_id = file_row["id"] if file_row else None

    cursor.execute("""
        INSERT INTO permissions (file_id, filename, user_or_role, permission, granted_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (file_id, filename, target_user_or_role, permission, granted_by_user, created_at))

    conn.commit()
    conn.close()

    log_audit(granted_by_user, "Add Permission", file_name=filename, status=f"GRANTED {permission} to {target_user_or_role}")
    return True, f"Permission '{permission}' granted to '{target_user_or_role}' for file '{filename}'."

def remove_file_permission(permission_id, admin_user):
    """Admin function to revoke a permission entry."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, user_or_role, permission FROM permissions WHERE id = ?", (permission_id,))
    perm = cursor.fetchone()

    if not perm:
        conn.close()
        return False, "Permission record not found."

    filename, target, perm_name = perm["filename"], perm["user_or_role"], perm["permission"]
    cursor.execute("DELETE FROM permissions WHERE id = ?", (permission_id,))
    conn.commit()
    conn.close()

    log_audit(admin_user, "Remove Permission", file_name=filename, status=f"REVOKED {perm_name} from {target}")
    return True, f"Permission '{perm_name}' revoked from '{target}' for file '{filename}'."
