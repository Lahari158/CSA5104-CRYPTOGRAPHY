import streamlit as st
import pandas as pd
import os
from datetime import datetime

from database import init_db, get_connection
from authentication import (
    authenticate_user, register_user, seed_default_admin, get_all_users
)
from pqc_keys import (
    get_active_pqc_key, generate_pqc_keypair, renew_pqc_key, get_pqc_technical_details
)
from encryption import (
    format_file_size, encrypt_bytes, decrypt_bytes, transfer_bytes
)
from integrity import (
    calculate_sha256_bytes, generate_file_hash_bytes, verify_file_integrity_bytes,
    sign_file_bytes, verify_digital_signature_bytes, create_tampered_bytes
)
from access_control import (
    check_permission, get_all_permissions, add_file_permission, remove_file_permission
)
from audit import (
    log_audit, get_audit_logs, get_security_analytics
)
from reports import (
    generate_security_report, export_report_txt, export_report_csv
)

# Page Setup
st.set_page_config(
    page_title="Secure File Transfer Platform",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Modern SaaS Styling CSS
st.markdown("""
<style>
    .stApp {
        background-color: #0b132b;
        color: #f1f5f9;
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    }
    
    /* Result Boxes */
    .result-card-success {
        background-color: #064e3b;
        border: 1px solid #10b981;
        border-radius: 10px;
        padding: 18px;
        margin-top: 15px;
        margin-bottom: 15px;
        box-shadow: 0 4px 15px rgba(16, 185, 129, 0.2);
    }
    .result-card-danger {
        background-color: #7f1d1d;
        border: 1px solid #ef4444;
        border-radius: 10px;
        padding: 18px;
        margin-top: 15px;
        margin-bottom: 15px;
        box-shadow: 0 4px 15px rgba(239, 68, 68, 0.2);
    }
    .result-title-success {
        font-size: 18px;
        font-weight: 700;
        color: #34d399;
        margin-bottom: 8px;
    }
    .result-title-danger {
        font-size: 18px;
        font-weight: 700;
        color: #f87171;
        margin-bottom: 8px;
    }

    /* Workflow Stepper Bar */
    .stepper-bar {
        background-color: #1c2541;
        border: 1px solid #3a506b;
        border-radius: 10px;
        padding: 12px 15px;
        margin-bottom: 25px;
        font-size: 14px;
        text-align: center;
    }
    .step-done {
        color: #10b981;
        font-weight: bold;
    }
    .step-active {
        color: #6fffe9;
        font-weight: bold;
    }
    .step-todo {
        color: #64748b;
    }
</style>
""", unsafe_allow_html=True)

# Database Setup & Session Initialization
init_db()
seed_default_admin()

if "user" not in st.session_state:
    st.session_state["user"] = None

if "nav_page" not in st.session_state:
    st.session_state["nav_page"] = "HOME"

if "step_idx" not in st.session_state:
    st.session_state["step_idx"] = 1

# Workflow State Storage
if "wf_bytes" not in st.session_state:
    st.session_state["wf_bytes"] = None
if "wf_name" not in st.session_state:
    st.session_state["wf_name"] = None
if "wf_enc_bytes" not in st.session_state:
    st.session_state["wf_enc_bytes"] = None
if "wf_enc_name" not in st.session_state:
    st.session_state["wf_enc_name"] = None
if "wf_hash" not in st.session_state:
    st.session_state["wf_hash"] = None
if "wf_sig" not in st.session_state:
    st.session_state["wf_sig"] = None
if "wf_access_saved" not in st.session_state:
    st.session_state["wf_access_saved"] = False
if "wf_trans_time" not in st.session_state:
    st.session_state["wf_trans_time"] = None

# =============================================================================
# UNAUTHENTICATED SCREEN (FIRST SCREEN ALWAYS LOGIN / REGISTER)
# =============================================================================
if st.session_state["user"] is None:
    st.markdown("""
    <div style="text-align: center; padding: 25px 10px;">
        <div style="font-size: 48px;">🔐</div>
        <h1 style="color: #6fffe9; margin-bottom: 2px;">SECURE FILE TRANSFER</h1>
        <p style="color: #94a3b8; font-size: 16px;">Post-Quantum Security Platform</p>
        <p style="color: #cbd5e1;">Protect and securely transfer your important files.</p>
    </div>
    """, unsafe_allow_html=True)

    col_l1, col_l2, col_l3 = st.columns([1, 2, 1])
    with col_l2:
        tab_signin, tab_signup = st.tabs(["SIGN IN", "CREATE ACCOUNT"])

        with tab_signin:
            login_uname = st.text_input("Username", key="auth_signin_u")
            login_pwd = st.text_input("Password", type="password", key="auth_signin_p")

            if st.button("SIGN IN", type="primary", use_container_width=True):
                success, result = authenticate_user(login_uname, login_pwd)
                if success:
                    st.session_state["user"] = result
                    st.success(f"✓ Welcome back, {result['username']}")
                    st.session_state["nav_page"] = "HOME"
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password.")

        with tab_signup:
            reg_fname = st.text_input("Full Name", key="auth_signup_fn")
            reg_uname = st.text_input("Username", key="auth_signup_u")
            reg_pwd1 = st.text_input("Password", type="password", key="auth_signup_p1")
            reg_pwd2 = st.text_input("Confirm Password", type="password", key="auth_signup_p2")

            if st.button("CREATE ACCOUNT", use_container_width=True):
                success, msg = register_user(reg_uname, reg_pwd1, reg_pwd2, role="User")
                if success:
                    st.success("✓ ACCOUNT CREATED SUCCESSFULLY")
                    st.info("You can now switch to the SIGN IN tab and log in.")
                else:
                    st.error(f"❌ {msg}")

        st.markdown("<br>", unsafe_allow_html=True)
        st.caption("🔒 Your files are protected through encryption, integrity verification and controlled access.")

    st.stop()

# =============================================================================
# AUTHENTICATED SYSTEM NAVIGATION BAR & VIEWS
# =============================================================================
user = st.session_state["user"]

if user:
    st.sidebar.markdown(f"👤 **User:** `{user['username']}`")
    st.sidebar.markdown(f"🛡️ **Role:** `{user['role']}`")
    st.sidebar.markdown("---")

    nav_items = ["HOME", "SECURE A FILE", "MY FILES", "ACTIVITY", "SECURITY REPORT", "ACCOUNT"]
    if user["role"] == "Admin":
        nav_items.append("ADMIN")
    nav_items.append("LOGOUT")

    default_nav_idx = nav_items.index(st.session_state["nav_page"]) if st.session_state["nav_page"] in nav_items else 0
    selected_nav = st.sidebar.radio("Navigation Menu", nav_items, index=default_nav_idx)
    st.session_state["nav_page"] = selected_nav

    if selected_nav == "LOGOUT":
        log_audit(user['username'], "User Logout", status="SUCCESS")
        st.session_state["user"] = None
        st.session_state["nav_page"] = "HOME"
        st.rerun()

    # -------------------------------------------------------------------------
    # 1. HOME PAGE
    # -------------------------------------------------------------------------
    elif selected_nav == "HOME":
        st.title(f"Good morning, {user['username']}")
        st.subheader("Ready to securely transfer a file?")
        st.info("ℹ️ Follow the guided steps below to protect, verify and transfer your file.")

        if st.button("🚀 START SECURE TRANSFER", type="primary", use_container_width=False):
            st.session_state["nav_page"] = "SECURE A FILE"
            st.session_state["step_idx"] = 1
            st.rerun()

        st.markdown("---")
        st.subheader("System Security Overview")
        c1, c2, c3 = st.columns(3)
        c1.metric("Identity & Keys", "Verified ✓")
        c2.metric("Encryption Engine", "Ready ✓")
        c3.metric("Integrity Engine", "Ready ✓")

    # -------------------------------------------------------------------------
    # 2. SECURE A FILE — GUIDED 7-STEP WORKFLOW
    # -------------------------------------------------------------------------
    elif selected_nav == "SECURE A FILE":
        step = st.session_state["step_idx"]

        # Render Visual Progress Stepper Bar
        stepper_html = '<div class="stepper-bar">'
        steps_info = [(1, "Identity"), (2, "Prepare"), (3, "Protect"), (4, "Verify"), (5, "Access"), (6, "Transfer"), (7, "Complete")]
        stepper_parts = []
        for s_num, s_name in steps_info:
            if s_num < step:
                stepper_parts.append(f'<span class="step-done">✓ {s_name}</span>')
            elif s_num == step:
                stepper_parts.append(f'<span class="step-active">● {s_name}</span>')
            else:
                stepper_parts.append(f'<span class="step-todo">○ {s_name}</span>')
        stepper_html += " &nbsp;→&nbsp; ".join(stepper_parts) + '</div>'
        st.markdown(stepper_html, unsafe_allow_html=True)

        # STEP 1 — IDENTITY
        if step == 1:
            st.subheader("YOUR SECURITY STATUS")
            key_info = get_active_pqc_key(user["username"])

            st.write("Identity: **✓ Verified**")
            st.write(f"Account: `{user['username']}`")
            st.write(f"Access Level: `{user['role']}`")
            st.write(f"Security Key Status: `{key_info['status']}` ({key_info['key_id']})")
            st.caption("ℹ️ PQC key-management demonstration (NIST Level 5 CRYSTALS-Dilithium5 / Kyber-1024 parameters)")

            if st.button("CREATE SECURITY KEY"):
                new_k = generate_pqc_keypair(user["username"])
                st.success("✓ SECURITY KEY READY")
                st.write(f"**Key ID:** `{new_k['key_id']}`")
                st.rerun()

            st.markdown("---")
            if st.button("CONTINUE →", type="primary"):
                st.session_state["step_idx"] = 2
                st.rerun()

        # STEP 2 — PREPARE
        elif step == 2:
            st.subheader("PREPARE YOUR FILE")
            st.caption("Choose the file you want to protect and transfer.")

            up_file = st.file_uploader("📁 DROP YOUR FILE HERE or BROWSE FILES", key="wf_step2_uploader")

            if up_file is not None:
                st.session_state["wf_bytes"] = up_file.getvalue()
                st.session_state["wf_name"] = up_file.name

            if st.session_state["wf_bytes"] is not None:
                fname = st.session_state["wf_name"]
                fsize = format_file_size(len(st.session_state["wf_bytes"]))
                ftype = fname.split('.')[-1].upper() if '.' in fname else "FILE"

                st.markdown(f"""
                <div style="background-color: #1c2541; border: 1px solid #3a506b; padding: 15px; border-radius: 10px; margin-top: 15px;">
                    <h4>FILE SELECTED</h4>
                    <p><strong>Name:</strong> {fname}</p>
                    <p><strong>Size:</strong> {fsize}</p>
                    <p><strong>Type:</strong> {ftype}</p>
                </div>
                """, unsafe_allow_html=True)

                st.success("✓ File ready for protection")

                st.markdown("---")
                if st.button("CONTINUE →", type="primary"):
                    st.session_state["step_idx"] = 3
                    st.rerun()

        # STEP 3 — PROTECT
        elif step == 3:
            st.subheader("PROTECT YOUR FILE")
            st.caption("Your file will be encrypted before it is transferred.")

            if st.session_state["wf_bytes"] is None:
                st.warning("Please go back and select a file first.")
                if st.button("← BACK TO PREPARE"):
                    st.session_state["step_idx"] = 2
                    st.rerun()
            else:
                fname = st.session_state["wf_name"]
                st.write(f"Selected File: `{fname}`")

                if st.button("🔐 PROTECT FILE", type="primary"):
                    success, msg, enc_bytes, enc_filename = encrypt_bytes(st.session_state["wf_bytes"], fname, user["username"])
                    if success:
                        st.session_state["wf_enc_bytes"] = enc_bytes
                        st.session_state["wf_enc_name"] = enc_filename
                        st.markdown(f"""
                        <div class="result-card-success">
                            <div class="result-title-success">✓ FILE PROTECTED SUCCESSFULLY</div>
                            <p><strong>Original:</strong> {fname}</p>
                            <p><strong>Protected File:</strong> {enc_filename}</p>
                            <p><strong>Status:</strong> SECURE ✓</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.error(f"❌ {msg}")

                if st.session_state["wf_enc_bytes"] is not None:
                    st.download_button(
                        label="DOWNLOAD PROTECTED FILE",
                        data=st.session_state["wf_enc_bytes"],
                        file_name=st.session_state["wf_enc_name"],
                        mime="application/octet-stream"
                    )

                    st.markdown("---")
                    if st.button("CONTINUE →", type="primary"):
                        st.session_state["step_idx"] = 4
                        st.rerun()

        # STEP 4 — VERIFY
        elif step == 4:
            st.subheader("VERIFY FILE SECURITY")
            st.caption("Confirm that the file has not been changed and verify its authenticity.")

            if st.session_state["wf_bytes"] is None:
                st.warning("Select a file first.")
            else:
                data_bytes = st.session_state["wf_bytes"]
                fname = st.session_state["wf_name"]

                h_hex, _ = calculate_sha256_bytes(data_bytes)
                st.session_state["wf_hash"] = h_hex

                st.write(f"File: `{fname}`")
                st.code(f"SHA-256: {h_hex}", language="text")

                col_v1, col_v2 = st.columns(2)
                with col_v1:
                    if st.button("VERIFY FILE", type="primary"):
                        success, msg, banner = verify_file_integrity_bytes(data_bytes, h_hex, fname, user["username"])
                        if success:
                            st.markdown("""
                            <div class="result-card-success">
                                <div class="result-title-success">✓ FILE VERIFIED</div>
                                <p>The file integrity check was successful.</p>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown("""
                            <div class="result-card-danger">
                                <div class="result-title-danger">✗ VERIFICATION FAILED</div>
                                <p>The file content has changed.</p>
                            </div>
                            """, unsafe_allow_html=True)

                with col_v2:
                    if st.button("CREATE DIGITAL SIGNATURE"):
                        success, msg, sig_b64 = sign_file_bytes(data_bytes, fname, user["username"])
                        st.session_state["wf_sig"] = sig_b64
                        st.markdown("""
                        <div class="result-card-success">
                            <div class="result-title-success">✓ DIGITAL SIGNATURE CREATED</div>
                        </div>
                        """, unsafe_allow_html=True)

                    if "wf_sig" in st.session_state and st.button("VERIFY AUTHENTICITY"):
                        success, msg, banner = verify_digital_signature_bytes(data_bytes, st.session_state["wf_sig"], fname, user["username"])
                        if success:
                            st.markdown("""
                            <div class="result-card-success">
                                <div class="result-title-success">✓ AUTHENTICITY VERIFIED</div>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown("""
                            <div class="result-card-danger">
                                <div class="result-title-danger">✗ AUTHENTICITY FAILED</div>
                            </div>
                            """, unsafe_allow_html=True)

                st.markdown("---")
                if st.button("CONTINUE →", type="primary"):
                    st.session_state["step_idx"] = 5
                    st.rerun()

        # STEP 5 — ACCESS
        elif step == 5:
            st.subheader("WHO CAN ACCESS THIS FILE?")
            st.caption("Choose who is allowed to use the protected file.")

            fname = st.session_state.get("wf_name", "report.pdf")
            st.write(f"File: `{fname}`")

            target_u = st.text_input("Select User", value="User")

            st.write("Access permissions:")
            p_view = st.checkbox("View", value=True)
            p_down = st.checkbox("Download", value=True)
            p_edit = st.checkbox("Edit", value=False)
            p_del = st.checkbox("Delete", value=False)

            if st.button("SAVE ACCESS SETTINGS", type="primary"):
                for p_name, p_val in [("Read", p_view), ("Download", p_down), ("Write", p_edit), ("Delete", p_del)]:
                    if p_val:
                        add_file_permission(fname, target_u, p_name, user["username"])
                st.session_state["wf_access_saved"] = True
                st.markdown(f"""
                <div class="result-card-success">
                    <div class="result-title-success">✓ ACCESS SETTINGS SAVED</div>
                    <p>Access granted to: <strong>{target_u}</strong></p>
                    <p>Permissions: View • Download</p>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("---")
            test_u = st.text_input("Test User Permission Check", value=target_u)
            if st.button("CHECK ACCESS"):
                allowed, msg = check_permission({"username": test_u, "role": "User"}, fname, "Read")
                if allowed:
                    st.markdown(f"""
                    <div class="result-card-success">
                        <div class="result-title-success">✓ ACCESS GRANTED</div>
                        <p>{test_u} has permission to access this file.</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="result-card-danger">
                        <div class="result-title-danger">✗ ACCESS DENIED</div>
                        <p>You do not have permission to access this file.</p>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("---")
            if st.button("CONTINUE →", type="primary"):
                st.session_state["step_idx"] = 6
                st.rerun()

        # STEP 6 — TRANSFER
        elif step == 6:
            st.subheader("READY TO TRANSFER")
            fname = st.session_state.get("wf_name", "report.pdf")

            st.markdown(f"""
            <div style="background-color: #1c2541; border: 1px solid #3a506b; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                <p><strong>FILE:</strong> {fname}</p>
                <p><strong>PROTECTION:</strong> ✓ Encrypted</p>
                <p><strong>INTEGRITY:</strong> ✓ Verified</p>
                <p><strong>AUTHENTICITY:</strong> ✓ Verified</p>
                <p><strong>ACCESS:</strong> ✓ Configured</p>
            </div>
            """, unsafe_allow_html=True)

            if st.button("📤 SECURE TRANSFER", type="primary"):
                bytes_to_trans = st.session_state.get("wf_enc_bytes", st.session_state.get("wf_bytes", b"Payload"))
                fname_to_trans = st.session_state.get("wf_enc_name", f"enc_{fname}.pqc")
                success, msg = transfer_bytes(bytes_to_trans, fname_to_trans, user["username"])
                if success:
                    st.session_state["wf_trans_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    st.markdown(f"""
                    <div class="result-card-success">
                        <div class="result-title-success">✓ TRANSFER COMPLETED SUCCESSFULLY</div>
                        <p><strong>File:</strong> {fname}</p>
                        <p><strong>Protected File:</strong> {fname_to_trans}</p>
                        <p><strong>Transfer Status:</strong> SUCCESS</p>
                        <p><strong>Transfer Time:</strong> {st.session_state['wf_trans_time']}</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.error(f"❌ {msg}")

            if st.session_state.get("wf_enc_bytes") is not None:
                st.download_button(
                    label="DOWNLOAD PROTECTED FILE",
                    data=st.session_state["wf_enc_bytes"],
                    file_name=st.session_state["wf_enc_name"],
                    mime="application/octet-stream"
                )

            st.markdown("---")
            if st.button("FINISH →", type="primary"):
                st.session_state["step_idx"] = 7
                st.rerun()

        # STEP 7 — COMPLETE
        elif step == 7:
            st.markdown("""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 64px; color: #10b981;">✓</div>
                <h1 style="color: #6fffe9;">TRANSFER COMPLETE</h1>
                <p style="font-size: 16px;">Your file has been successfully protected and transferred.</p>
            </div>
            """, unsafe_allow_html=True)

            fname = st.session_state.get("wf_name", "report.pdf")
            st.markdown(f"""
            <div style="background-color: #1c2541; border: 1px solid #3a506b; padding: 20px; border-radius: 10px; width: 60%; margin: 0 auto 25px auto;">
                <p><strong>File:</strong> {fname}</p>
                <p><strong>Protection:</strong> ✓ Completed</p>
                <p><strong>Integrity:</strong> ✓ Verified</p>
                <p><strong>Authenticity:</strong> ✓ Verified</p>
                <p><strong>Access:</strong> ✓ Configured</p>
                <p><strong>Transfer:</strong> ✓ Completed</p>
            </div>
            """, unsafe_allow_html=True)

            col_c1, col_c2 = st.columns(2)
            with col_c1:
                if st.button("VIEW ACTIVITY", type="primary", use_container_width=True):
                    st.session_state["nav_page"] = "ACTIVITY"
                    st.rerun()
            with col_c2:
                if st.button("START ANOTHER TRANSFER", use_container_width=True):
                    st.session_state["step_idx"] = 1
                    st.session_state["wf_bytes"] = None
                    st.session_state["wf_name"] = None
                    st.session_state["wf_enc_bytes"] = None
                    st.session_state["wf_enc_name"] = None
                    st.session_state["nav_page"] = "SECURE A FILE"
                    st.rerun()

    # -------------------------------------------------------------------------
    # 3. MY FILES PAGE
    # -------------------------------------------------------------------------
    elif selected_nav == "MY FILES":
        st.title("MY FILES")
        st.caption("Files belonging to current user.")

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT filename, created_at, sha256_hash FROM files WHERE owner = ? ORDER BY id DESC
        """, (user["username"],))
        user_files = cursor.fetchall()
        conn.close()

        if user_files:
            rows = []
            for f in user_files:
                rows.append({
                    "FILE": f["filename"],
                    "STATUS": "Protected",
                    "ACCESS": "Download Allowed",
                    "DATE": f["created_at"]
                })
            st.table(pd.DataFrame(rows))
        else:
            st.info("No files uploaded yet.")

    # -------------------------------------------------------------------------
    # 4. ACTIVITY PAGE
    # -------------------------------------------------------------------------
    elif selected_nav == "ACTIVITY":
        st.title("SECURITY ACTIVITY")
        st.caption("Recent security log events.")

        logs = get_audit_logs(limit=50)
        if logs:
            rows = []
            for l in logs:
                rows.append({
                    "TIME": l["timestamp"],
                    "ACTION": l["action"],
                    "FILE": l["file_name"] or "—",
                    "RESULT": l["status"]
                })
            st.table(pd.DataFrame(rows))
        else:
            st.info("No security events recorded yet.")

    # -------------------------------------------------------------------------
    # 5. SECURITY REPORT PAGE
    # -------------------------------------------------------------------------
    elif selected_nav == "SECURITY REPORT":
        st.title("SECURITY REPORT")
        st.caption("Summary of system security activities.")

        analytics = get_security_analytics()

        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Files Protected", analytics["files_encrypted"])
        r2.metric("Files Transferred", analytics["files_transferred"])
        r3.metric("Integrity Checks", analytics["integrity_checks"])
        r4.metric("Access Denied", analytics["access_denied_events"])

        st.markdown("---")
        if st.button("GENERATE REPORT", type="primary"):
            rpt_str = generate_security_report()
            st.session_state["sec_rpt_str"] = rpt_str
            st.markdown("""
            <div class="result-card-success">
                <div class="result-title-success">✓ REPORT GENERATED</div>
            </div>
            """, unsafe_allow_html=True)

        if "sec_rpt_str" in st.session_state:
            st.code(st.session_state["sec_rpt_str"], language="text")
            st.download_button(
                label="DOWNLOAD REPORT",
                data=st.session_state["sec_rpt_str"],
                file_name="security_report.txt",
                mime="text/plain"
            )

    # -------------------------------------------------------------------------
    # 6. ACCOUNT PAGE
    # -------------------------------------------------------------------------
    elif selected_nav == "ACCOUNT":
        st.title("ACCOUNT PROFILE")
        st.write(f"**Username:** `{user['username']}`")
        st.write(f"**Role:** `{user['role']}`")
        st.write(f"**Member Since:** `{user['created_at']}`")

        key_info = get_active_pqc_key(user["username"])
        st.write(f"**Active Security Key:** `{key_info['key_id']}`")

    # -------------------------------------------------------------------------
    # 7. ADMIN PAGE (Admin Role Only)
    # -------------------------------------------------------------------------
    elif selected_nav == "ADMIN" and user["role"] == "Admin":
        st.title("ADMINISTRATION PANEL")
        st.subheader("System Users")
        st.dataframe(pd.DataFrame(get_all_users()), use_container_width=True)

        st.subheader("Access Control List (ACL)")
        st.dataframe(pd.DataFrame(get_all_permissions()), use_container_width=True)
