import os
import csv
from datetime import datetime
from audit import get_security_analytics, get_audit_logs, log_audit
from database import REPORTS_DIR

def generate_security_report():
    """
    Generate text string representation of the full security report.
    """
    analytics = get_security_analytics()
    logs = get_audit_logs(limit=25)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines = [
        "==========================================================================",
        "          POST-QUANTUM CRYPTOGRAPHY (PQC) FILE TRANSFER SYSTEM            ",
        "                        SECURITY AUDIT REPORT                             ",
        "==========================================================================",
        f"Report Generated At : {now_str}",
        f"Classification      : RESTRICTED SECURITY REPORT",
        "--------------------------------------------------------------------------",
        "1. SYSTEM METRICS & SECURITY ANALYTICS",
        "--------------------------------------------------------------------------",
        f"  Total System Users          : {analytics['total_users']}",
        f"  Total Tracked Files         : {analytics['total_files']}",
        f"  Successful User Logins      : {analytics['successful_logins']}",
        f"  Failed User Logins          : {analytics['failed_logins']}",
        f"  Files Encrypted (PQC/AES)   : {analytics['files_encrypted']}",
        f"  Files Transferred           : {analytics['files_transferred']}",
        f"  Integrity Verifications     : {analytics['integrity_checks']}",
        f"  Integrity Check Failures    : {analytics['integrity_failures']}",
        f"  Access Denied Events        : {analytics['access_denied_events']}",
        f"  Total Logged Audit Events   : {analytics['total_events']}",
        "--------------------------------------------------------------------------",
        "2. RECENT SECURITY AUDIT TRAIL (Last 25 Events)",
        "--------------------------------------------------------------------------",
        f"{'Date/Time':<20} | {'User':<12} | {'Action':<22} | {'File':<18} | {'Status':<15}",
        "-" * 95
    ]

    for log in logs:
        ts = log["timestamp"]
        user = log["user"]
        act = log["action"]
        fn = log["file_name"] or "N/A"
        st = log["status"]
        report_lines.append(f"{ts:<20} | {user:<12} | {act:<22} | {fn:<18} | {st:<15}")

    report_lines.extend([
        "=" * 95,
        "End of Security Report."
    ])

    return "\n".join(report_lines)

def export_report_txt(user):
    """Export security report to a text file in reports/ directory."""
    report_text = generate_security_report()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"security_report_{timestamp_str}.txt"
    file_path = os.path.join(REPORTS_DIR, file_name)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    log_audit(user, "Report Export (TXT)", file_name=file_name, status="SUCCESS")
    return file_path

def export_report_csv(user):
    """Export audit log records to a CSV file in reports/ directory."""
    logs = get_audit_logs(limit=100)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"audit_logs_{timestamp_str}.csv"
    file_path = os.path.join(REPORTS_DIR, file_name)

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "User", "Action", "File Name", "Status"])
        for log in logs:
            writer.writerow([log["timestamp"], log["user"], log["action"], log["file_name"], log["status"]])

    log_audit(user, "Report Export (CSV)", file_name=file_name, status="SUCCESS")
    return file_path
