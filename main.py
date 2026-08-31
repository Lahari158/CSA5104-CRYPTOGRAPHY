import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from database import init_db, SECURE_FILES_DIR
from authentication import (
    authenticate_user, register_user, seed_default_admin, get_all_users
)
from pqc_keys import (
    get_active_pqc_key, generate_pqc_keypair, renew_pqc_key, get_pqc_technical_details
)
from encryption import (
    get_file_info, encrypt_file, decrypt_file, transfer_file
)
from integrity import (
    calculate_sha256, generate_file_hash, verify_file_integrity,
    sign_file, verify_digital_signature, create_tampered_file_copy
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

# Colors & Styling
THEME_BG = "#0f172a"          # Slate 900
SIDEBAR_BG = "#1e293b"        # Slate 800
CARD_BG = "#1e293b"           # Slate 800
HEADER_BG = "#0284c7"         # Sky 600
TEXT_LIGHT = "#f8fafc"        # Slate 50
TEXT_MUTED = "#94a3b8"        # Slate 400
ACCENT_BLUE = "#38bdf8"       # Sky 400
ACCENT_GREEN = "#10b981"      # Emerald 500
ACCENT_RED = "#ef4444"        # Red 500
ACCENT_AMBER = "#f59e0b"      # Amber 500
BUTTON_BG = "#0369a1"         # Sky 700

class PQCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Post-Quantum Cryptography (PQC) File Transfer System")
        self.geometry("1150x720")
        self.minsize(950, 650)
        self.configure(bg=THEME_BG)

        # Initialize Database & Seed Default Admin
        init_db()
        seed_default_admin()

        self.current_user = None  # User dict when logged in
        self.active_frame = None

        # Build Container Layout
        self.setup_ui_styles()
        self.show_login_screen()

    def setup_ui_styles(self):
        """Configure ttk widget styles."""
        style = ttk.Style(self)
        style.theme_use('clam')

        # Treeview styling
        style.configure("Treeview",
                        background="#1e293b",
                        foreground="#f8fafc",
                        fieldbackground="#1e293b",
                        rowheight=26,
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                        background="#334155",
                        foreground="#38bdf8",
                        font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[('selected', '#0284c7')])

    # =========================================================================
    # LOGIN & REGISTRATION VIEW
    # =========================================================================
    def show_login_screen(self):
        """Display Login Screen."""
        if self.active_frame:
            self.active_frame.destroy()

        self.active_frame = tk.Frame(self, bg=THEME_BG)
        self.active_frame.pack(fill=tk.BOTH, expand=True)

        box = tk.Frame(self.active_frame, bg=SIDEBAR_BG, bd=2, relief=tk.GROOVE, padx=30, pady=30)
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Header
        tk.Label(box, text="Post-Quantum Cryptography (PQC)", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=SIDEBAR_BG).pack(pady=(0, 2))
        tk.Label(box, text="File Transfer System - User Login", font=("Segoe UI", 12), fg=TEXT_MUTED, bg=SIDEBAR_BG).pack(pady=(0, 20))

        # Username
        tk.Label(box, text="Username", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=SIDEBAR_BG, anchor="w").pack(fill=tk.X)
        username_entry = tk.Entry(box, font=("Segoe UI", 11), bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
        username_entry.pack(fill=tk.X, pady=(2, 10))
        username_entry.focus()

        # Password
        tk.Label(box, text="Password", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=SIDEBAR_BG, anchor="w").pack(fill=tk.X)
        password_entry = tk.Entry(box, font=("Segoe UI", 11), show="*", bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
        password_entry.pack(fill=tk.X, pady=(2, 5))

        # Show / Hide Password Checkbox
        show_pass_var = tk.BooleanVar(value=False)
        def toggle_password():
            password_entry.config(show="" if show_pass_var.get() else "*")
        tk.Checkbutton(box, text="Show Password", variable=show_pass_var, command=toggle_password,
                       fg=TEXT_MUTED, bg=SIDEBAR_BG, selectcolor="#334155", activebackground=SIDEBAR_BG, activeforeground=TEXT_LIGHT).pack(anchor="w", pady=(0, 15))

        # Login Action
        def do_login():
            uname = username_entry.get().strip()
            pwd = password_entry.get()
            success, result = authenticate_user(uname, pwd)
            if success:
                self.current_user = result
                messagebox.showinfo("Login Successful", f"Welcome back, {self.current_user['username']}! ({self.current_user['role']})")
                self.show_main_layout()
            else:
                messagebox.showerror("Authentication Failed", result)

        # Submit on Enter key
        password_entry.bind("<Return>", lambda e: do_login())

        btn_frame = tk.Frame(box, bg=SIDEBAR_BG)
        btn_frame.pack(fill=tk.X, pady=10)

        tk.Button(btn_frame, text="Login", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT,
                  activebackground="#0284c7", activeforeground=TEXT_LIGHT, cursor="hand2", padx=20, pady=5, command=do_login).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        tk.Button(btn_frame, text="Register", font=("Segoe UI", 10), bg="#475569", fg=TEXT_LIGHT,
                  activebackground="#64748b", activeforeground=TEXT_LIGHT, cursor="hand2", padx=20, pady=5, command=self.show_register_screen).pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

    def show_register_screen(self):
        """Display Registration Screen."""
        if self.active_frame:
            self.active_frame.destroy()

        self.active_frame = tk.Frame(self, bg=THEME_BG)
        self.active_frame.pack(fill=tk.BOTH, expand=True)

        box = tk.Frame(self.active_frame, bg=SIDEBAR_BG, bd=2, relief=tk.GROOVE, padx=30, pady=25)
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(box, text="User Registration", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=SIDEBAR_BG).pack(pady=(0, 15))

        # Username
        tk.Label(box, text="Username", font=("Segoe UI", 9, "bold"), fg=TEXT_LIGHT, bg=SIDEBAR_BG, anchor="w").pack(fill=tk.X)
        u_entry = tk.Entry(box, font=("Segoe UI", 10), bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
        u_entry.pack(fill=tk.X, pady=(2, 8))

        # Password
        tk.Label(box, text="Password", font=("Segoe UI", 9, "bold"), fg=TEXT_LIGHT, bg=SIDEBAR_BG, anchor="w").pack(fill=tk.X)
        p1_entry = tk.Entry(box, font=("Segoe UI", 10), show="*", bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
        p1_entry.pack(fill=tk.X, pady=(2, 8))

        # Confirm Password
        tk.Label(box, text="Confirm Password", font=("Segoe UI", 9, "bold"), fg=TEXT_LIGHT, bg=SIDEBAR_BG, anchor="w").pack(fill=tk.X)
        p2_entry = tk.Entry(box, font=("Segoe UI", 10), show="*", bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
        p2_entry.pack(fill=tk.X, pady=(2, 8))

        # Role Selection
        tk.Label(box, text="Account Role", font=("Segoe UI", 9, "bold"), fg=TEXT_LIGHT, bg=SIDEBAR_BG, anchor="w").pack(fill=tk.X)
        role_var = tk.StringVar(value="User")
        role_combo = ttk.Combobox(box, textvariable=role_var, values=["User", "Admin"], state="readonly")
        role_combo.pack(fill=tk.X, pady=(2, 15))

        def do_register():
            uname = u_entry.get().strip()
            p1 = p1_entry.get()
            p2 = p2_entry.get()
            role = role_var.get()

            success, msg = register_user(uname, p1, p2, role)
            if success:
                messagebox.showinfo("Registration Successful", msg)
                self.show_login_screen()
            else:
                messagebox.showerror("Registration Error", msg)

        btn_frame = tk.Frame(box, bg=SIDEBAR_BG)
        btn_frame.pack(fill=tk.X, pady=5)

        tk.Button(btn_frame, text="Submit Registration", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT,
                  activebackground="#0284c7", activeforeground=TEXT_LIGHT, cursor="hand2", padx=15, pady=5, command=do_register).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        tk.Button(btn_frame, text="Back to Login", font=("Segoe UI", 10), bg="#475569", fg=TEXT_LIGHT,
                  activebackground="#64748b", activeforeground=TEXT_LIGHT, cursor="hand2", padx=15, pady=5, command=self.show_login_screen).pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

    # =========================================================================
    # MAIN LAYOUT (HEADER + SIDEBAR + CONTENT AREA)
    # =========================================================================
    def show_main_layout(self):
        """Construct Header, Sidebar, and View Container."""
        if self.active_frame:
            self.active_frame.destroy()

        self.active_frame = tk.Frame(self, bg=THEME_BG)
        self.active_frame.pack(fill=tk.BOTH, expand=True)

        # 1. HEADER
        header = tk.Frame(self.active_frame, bg=HEADER_BG, height=50)
        header.pack(side=tk.TOP, fill=tk.X)
        header.pack_propagate(False)

        tk.Label(header, text="Post-Quantum Cryptography (PQC) File Transfer System",
                 font=("Segoe UI", 13, "bold"), fg=TEXT_LIGHT, bg=HEADER_BG).pack(side=tk.LEFT, padx=15)

        user_info_str = f"Logged in: {self.current_user['username']} | Role: {self.current_user['role']}"
        tk.Label(header, text=user_info_str, font=("Segoe UI", 10), fg=TEXT_LIGHT, bg=HEADER_BG).pack(side=tk.RIGHT, padx=15)

        # 2. SIDEBAR & CONTENT BODY
        body = tk.Frame(self.active_frame, bg=THEME_BG)
        body.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        sidebar = tk.Frame(body, bg=SIDEBAR_BG, width=220)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        self.content_area = tk.Frame(body, bg=THEME_BG)
        self.content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Sidebar Buttons
        menu_items = [
            ("Dashboard", self.view_dashboard),
            ("User Authentication", self.view_user_auth),
            ("PQC Key Management", self.view_pqc_keys),
            ("Secure File Transfer", self.view_file_transfer),
            ("Integrity & Digital Auth", self.view_integrity),
            ("Access Control", self.view_access_control),
            ("Audit & Security Analytics", self.view_audit_analytics),
            ("Reports", self.view_reports),
            ("Logout", self.do_logout)
        ]

        for label, cmd in menu_items:
            bg_col = "#dc2626" if label == "Logout" else SIDEBAR_BG
            btn = tk.Button(sidebar, text=label, font=("Segoe UI", 10, "bold" if label != "Logout" else "normal"),
                            fg=TEXT_LIGHT, bg=bg_col, activebackground="#334155", activeforeground=ACCENT_BLUE,
                            bd=0, anchor="w", padx=20, pady=8, cursor="hand2", command=cmd)
            btn.pack(fill=tk.X, pady=1)

        # Default View: Dashboard
        self.view_dashboard()

    def do_logout(self):
        """Logout user and return to login screen."""
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            log_audit(self.current_user['username'], "User Logout", status="SUCCESS")
            self.current_user = None
            self.show_login_screen()

    def clear_content_area(self):
        """Utility to clear content area for new view."""
        for child in self.content_area.winfo_children():
            child.destroy()

    # =========================================================================
    # MODULE 2: DASHBOARD VIEW
    # =========================================================================
    def view_dashboard(self):
        self.clear_content_area()

        # Page Header
        tk.Label(self.content_area, text="Security Operations Dashboard", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        # System Status Bar
        status_frame = tk.LabelFrame(self.content_area, text=" System Security Subsystems Status ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=10, pady=10)
        status_frame.pack(fill=tk.X, pady=(0, 15))

        subsystems = [
            "Authentication", "PQC Key Management", "Encryption",
            "Integrity Verification", "Access Control", "Audit Monitoring"
        ]

        grid_frame = tk.Frame(status_frame, bg=CARD_BG)
        grid_frame.pack(fill=tk.X)

        for i, sub in enumerate(subsystems):
            col = i % 3
            row = i // 3
            item_box = tk.Frame(grid_frame, bg="#334155", padx=10, pady=6)
            item_box.grid(row=row, column=col, sticky="ew", padx=5, pady=4)
            grid_frame.columnconfigure(col, weight=1)

            tk.Label(item_box, text=f"{sub}:", font=("Segoe UI", 9), fg=TEXT_LIGHT, bg="#334155").pack(side=tk.LEFT)
            tk.Label(item_box, text=" Active ✓ ", font=("Segoe UI", 9, "bold"), fg="#10b981", bg="#064e3b").pack(side=tk.RIGHT)

        # Metric Stat Cards
        analytics = get_security_analytics()
        cards_frame = tk.Frame(self.content_area, bg=THEME_BG)
        cards_frame.pack(fill=tk.X, pady=(0, 15))

        metrics = [
            ("Total Users", analytics["total_users"], "#38bdf8"),
            ("Files Encrypted", analytics["files_encrypted"], "#10b981"),
            ("Files Transferred", analytics["files_transferred"], "#f59e0b"),
            ("Integrity Checks", analytics["integrity_checks"], "#8b5cf6"),
            ("Security Events", analytics["total_events"], "#ec4899")
        ]

        for i, (title, val, color) in enumerate(metrics):
            cbox = tk.Frame(cards_frame, bg=CARD_BG, bd=1, relief=tk.SOLID, padx=12, pady=12)
            cbox.grid(row=0, column=i, sticky="ew", padx=4)
            cards_frame.columnconfigure(i, weight=1)

            tk.Label(cbox, text=str(val), font=("Segoe UI", 18, "bold"), fg=color, bg=CARD_BG).pack()
            tk.Label(cbox, text=title, font=("Segoe UI", 8, "bold"), fg=TEXT_MUTED, bg=CARD_BG).pack()

        # Recent Activity Table
        act_frame = tk.LabelFrame(self.content_area, text=" Recent Security Activity ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=10, pady=10)
        act_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Timestamp", "User", "Action", "File Name", "Status")
        tree = ttk.Treeview(act_frame, columns=columns, show="headings", height=8)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor="center")

        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(act_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        logs = get_audit_logs(limit=15)
        for log in logs:
            tree.insert("", tk.END, values=(log["timestamp"], log["user"], log["action"], log["file_name"], log["status"]))

    # =========================================================================
    # MODULE 1: USER AUTHENTICATION VIEW
    # =========================================================================
    def view_user_auth(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="User Authentication & Role Management", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        # Current User Card
        user_card = tk.Frame(self.content_area, bg=CARD_BG, padx=15, pady=12)
        user_card.pack(fill=tk.X, pady=(0, 15))

        tk.Label(user_card, text=f"Active Session: {self.current_user['username']} | Role: {self.current_user['role']} | Registered: {self.current_user['created_at']}",
                 font=("Segoe UI", 10, "bold"), fg=ACCENT_GREEN, bg=CARD_BG).pack(anchor="w")

        # Admin User Management Box
        if self.current_user['role'] == "Admin":
            admin_box = tk.LabelFrame(self.content_area, text=" Register New System User (Admin Function) ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=15, pady=10)
            admin_box.pack(fill=tk.X, pady=(0, 15))

            f_inputs = tk.Frame(admin_box, bg=CARD_BG)
            f_inputs.pack(fill=tk.X)

            tk.Label(f_inputs, text="Username:", fg=TEXT_LIGHT, bg=CARD_BG).grid(row=0, column=0, padx=5, pady=5, sticky="e")
            new_u_entry = tk.Entry(f_inputs, width=15, bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
            new_u_entry.grid(row=0, column=1, padx=5, pady=5)

            tk.Label(f_inputs, text="Password:", fg=TEXT_LIGHT, bg=CARD_BG).grid(row=0, column=2, padx=5, pady=5, sticky="e")
            new_p_entry = tk.Entry(f_inputs, width=15, show="*", bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
            new_p_entry.grid(row=0, column=3, padx=5, pady=5)

            tk.Label(f_inputs, text="Role:", fg=TEXT_LIGHT, bg=CARD_BG).grid(row=0, column=4, padx=5, pady=5, sticky="e")
            new_role_var = tk.StringVar(value="User")
            ttk.Combobox(f_inputs, textvariable=new_role_var, values=["User", "Admin"], width=10, state="readonly").grid(row=0, column=5, padx=5, pady=5)

            def admin_add_user():
                u = new_u_entry.get().strip()
                p = new_p_entry.get()
                r = new_role_var.get()
                success, msg = register_user(u, p, p, r)
                if success:
                    messagebox.showinfo("User Created", msg)
                    self.view_user_auth()
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(f_inputs, text="Add User", bg=BUTTON_BG, fg=TEXT_LIGHT, command=admin_add_user).grid(row=0, column=6, padx=10, pady=5)

        # Registered Users List Table
        users_frame = tk.LabelFrame(self.content_area, text=" Registered System Users ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=10, pady=10)
        users_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("ID", "Username", "Role", "Created At")
        tree = ttk.Treeview(users_frame, columns=cols, show="headings", height=8)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True)

        for u in get_all_users():
            tree.insert("", tk.END, values=(u["id"], u["username"], u["role"], u["created_at"]))

    # =========================================================================
    # MODULE 3: PQC KEY MANAGEMENT VIEW
    # =========================================================================
    def view_pqc_keys(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="Post-Quantum Cryptography (PQC) Key Management", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 5))

        banner = tk.Label(self.content_area, text=" [DEMONSTRATION MODULE] NIST Level 5 Quantum-Resistant Lattice Key Suite (CRYSTALS-Dilithium5 / Kyber-1024) ",
                          font=("Segoe UI", 9, "bold"), fg="#0f172a", bg=ACCENT_AMBER, pady=4)
        banner.pack(fill=tk.X, pady=(0, 15))

        key_info = get_active_pqc_key(self.current_user["username"])

        # Key Specs Card
        card = tk.LabelFrame(self.content_area, text=" Active Post-Quantum Key Credentials ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=20, pady=15)
        card.pack(fill=tk.X, pady=(0, 15))

        fields = [
            ("Current User", key_info["user"]),
            ("Key ID", key_info["key_id"]),
            ("Key Algorithm", key_info["algorithm"]),
            ("Key Status", key_info["status"]),
            ("Key Creation Date", key_info["creation_date"]),
            ("Key Expiry Date", key_info["expiry_date"])
        ]

        for i, (label, val) in enumerate(fields):
            row = i // 2
            col = (i % 2) * 2
            tk.Label(card, text=f"{label}:", font=("Segoe UI", 10, "bold"), fg=TEXT_MUTED, bg=CARD_BG, anchor="e").grid(row=row, column=col, sticky="e", padx=(10, 5), pady=6)
            fg_col = ACCENT_GREEN if label == "Key Status" else TEXT_LIGHT
            tk.Label(card, text=val, font=("Segoe UI", 10, "bold" if label in ["Key ID", "Key Status"] else "normal"), fg=fg_col, bg=CARD_BG, anchor="w").grid(row=row, column=col+1, sticky="w", padx=(0, 20), pady=6)

        # Action Buttons
        btn_box = tk.Frame(self.content_area, bg=THEME_BG)
        btn_box.pack(fill=tk.X, pady=10)

        def do_generate():
            new_key = generate_pqc_keypair(self.current_user["username"])
            messagebox.showinfo("PQC Key Generated", f"New PQC Key Pair generated successfully!\nKey ID: {new_key['key_id']}")
            self.view_pqc_keys()

        def do_view_details():
            details_win = tk.Toplevel(self)
            details_win.title("PQC Key Technical Specifications")
            details_win.geometry("600x480")
            details_win.configure(bg=CARD_BG)

            txt = tk.Text(details_win, bg="#0f172a", fg=ACCENT_BLUE, font=("Consolas", 10), padx=10, pady=10)
            txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            txt.insert(tk.END, get_pqc_technical_details(key_info))
            txt.config(state=tk.DISABLED)

        def do_renew():
            renewed_key = renew_pqc_key(self.current_user["username"])
            messagebox.showinfo("PQC Key Renewed", f"PQC Key successfully renewed!\nNew Key ID: {renewed_key['key_id']}")
            self.view_pqc_keys()

        tk.Button(btn_box, text="Generate PQC Key", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=do_generate).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_box, text="View Key Details", font=("Segoe UI", 10, "bold"), bg="#475569", fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=do_view_details).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_box, text="Renew Key", font=("Segoe UI", 10, "bold"), bg="#d97706", fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=do_renew).pack(side=tk.LEFT, padx=5)

    # =========================================================================
    # MODULE 4: SECURE FILE ENCRYPTION & TRANSFER VIEW
    # =========================================================================
    def view_file_transfer(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="Secure File Encryption & Local Transfer", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        self.selected_file_path = None
        self.encrypted_file_path = None

        # File Selection Card
        sel_card = tk.LabelFrame(self.content_area, text=" File Operations Panel ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=15, pady=15)
        sel_card.pack(fill=tk.X, pady=(0, 15))

        top_sel = tk.Frame(sel_card, bg=CARD_BG)
        top_sel.pack(fill=tk.X, pady=(0, 10))

        tk.Button(top_sel, text="Select File", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT, padx=15, pady=5, cursor="hand2", command=self.do_select_file).pack(side=tk.LEFT)

        self.lbl_file_path = tk.Label(top_sel, text="No file selected.", font=("Segoe UI", 9, "italic"), fg=TEXT_MUTED, bg=CARD_BG)
        self.lbl_file_path.pack(side=tk.LEFT, padx=15)

        # File Specs Frame
        info_frame = tk.Frame(sel_card, bg="#334155", padx=10, pady=10)
        info_frame.pack(fill=tk.X)

        self.lbl_fname = tk.Label(info_frame, text="File Name: N/A", font=("Segoe UI", 9), fg=TEXT_LIGHT, bg="#334155")
        self.lbl_fname.grid(row=0, column=0, sticky="w", padx=10, pady=2)

        self.lbl_fsize = tk.Label(info_frame, text="File Size: N/A", font=("Segoe UI", 9), fg=TEXT_LIGHT, bg="#334155")
        self.lbl_fsize.grid(row=0, column=1, sticky="w", padx=10, pady=2)

        self.lbl_enc_status = tk.Label(info_frame, text="Encryption Status: Plaintext", font=("Segoe UI", 9, "bold"), fg=ACCENT_AMBER, bg="#334155")
        self.lbl_enc_status.grid(row=1, column=0, sticky="w", padx=10, pady=2)

        self.lbl_transfer_status = tk.Label(info_frame, text="Transfer Status: Not Transferred", font=("Segoe UI", 9, "bold"), fg=TEXT_MUTED, bg="#334155")
        self.lbl_transfer_status.grid(row=1, column=1, sticky="w", padx=10, pady=2)

        # Action Buttons Frame
        act_box = tk.Frame(self.content_area, bg=THEME_BG)
        act_box.pack(fill=tk.X, pady=10)

        tk.Button(act_box, text="Encrypt File", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=self.do_encrypt_file).pack(side=tk.LEFT, padx=5)
        tk.Button(act_box, text="Decrypt File", font=("Segoe UI", 10, "bold"), bg="#059669", fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=self.do_decrypt_file).pack(side=tk.LEFT, padx=5)
        tk.Button(act_box, text="Send / Transfer File", font=("Segoe UI", 10, "bold"), bg="#7c3aed", fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=self.do_transfer_file).pack(side=tk.LEFT, padx=5)
        tk.Button(act_box, text="Download File", font=("Segoe UI", 10, "bold"), bg="#475569", fg=TEXT_LIGHT, padx=15, pady=8, cursor="hand2", command=self.do_download_file).pack(side=tk.LEFT, padx=5)

    def do_select_file(self):
        fp = filedialog.askopenfilename()
        if fp:
            self.selected_file_path = fp
            info = get_file_info(fp)
            self.lbl_file_path.config(text=fp, fg=TEXT_LIGHT)
            self.lbl_fname.config(text=f"File Name: {info['file_name']}")
            self.lbl_fsize.config(text=f"File Size: {info['formatted_size']}")
            self.lbl_enc_status.config(text="Encryption Status: Plaintext", fg=ACCENT_AMBER)
            self.lbl_transfer_status.config(text="Transfer Status: Not Transferred", fg=TEXT_MUTED)

    def do_encrypt_file(self):
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please select a file first.")
            return

        fn = os.path.basename(self.selected_file_path)
        allowed, msg = check_permission(self.current_user, fn, "Write")
        if not allowed:
            messagebox.showerror("Access Denied ✗", msg)
            return

        success, msg, enc_path = encrypt_file(self.selected_file_path, self.current_user["username"])
        if success:
            self.encrypted_file_path = enc_path
            messagebox.showinfo("Success", "File encrypted successfully.")
            self.lbl_enc_status.config(text="Encryption Status: Encrypted (Fernet/AES)", fg=ACCENT_GREEN)
        else:
            messagebox.showerror("Error", msg)

    def do_decrypt_file(self):
        target = self.encrypted_file_path or self.selected_file_path
        if not target:
            messagebox.showwarning("Warning", "Please select or encrypt a file first.")
            return

        fn = os.path.basename(target)
        allowed, msg = check_permission(self.current_user, fn, "Read")
        if not allowed:
            messagebox.showerror("Access Denied ✗", msg)
            return

        success, msg, dec_path = decrypt_file(target, SECURE_FILES_DIR, self.current_user["username"])
        if success:
            messagebox.showinfo("Success", msg)
            self.lbl_enc_status.config(text="Encryption Status: Decrypted", fg=ACCENT_GREEN)
        else:
            messagebox.showerror("Error", msg)

    def do_transfer_file(self):
        target = self.encrypted_file_path or self.selected_file_path
        if not target:
            messagebox.showwarning("Warning", "Please select a file to transfer.")
            return

        fn = os.path.basename(target)
        allowed, msg = check_permission(self.current_user, fn, "Write")
        if not allowed:
            messagebox.showerror("Access Denied ✗", msg)
            return

        success, msg = transfer_file(target, self.current_user["username"])
        if success:
            messagebox.showinfo("Transfer Successful", msg)
            self.lbl_transfer_status.config(text="Transfer Status: Transfer Successful ✓", fg=ACCENT_GREEN)
        else:
            messagebox.showerror("Error", msg)

    def do_download_file(self):
        target = self.encrypted_file_path or self.selected_file_path
        if not target:
            messagebox.showwarning("Warning", "Please select a file first.")
            return

        fn = os.path.basename(target)
        allowed, msg = check_permission(self.current_user, fn, "Download")
        if not allowed:
            messagebox.showerror("Access Denied ✗", msg)
            return

        save_path = filedialog.asksaveasfilename(initialfile=fn)
        if save_path:
            import shutil
            shutil.copy2(target, save_path)
            log_audit(self.current_user["username"], "File Download", file_name=fn, status="SUCCESS")
            messagebox.showinfo("Success", f"File downloaded successfully to:\n{save_path}")

    # =========================================================================
    # MODULE 5: FILE INTEGRITY VERIFICATION & DIGITAL AUTHENTICATION VIEW
    # =========================================================================
    def view_integrity(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="File Integrity Verification & Digital Authentication", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        self.integrity_file_path = None
        self.reference_hash = None
        self.current_signature = None

        # Main Panel
        panel = tk.LabelFrame(self.content_area, text=" Cryptographic Integrity Inspector ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=15, pady=15)
        panel.pack(fill=tk.X, pady=(0, 15))

        top_f = tk.Frame(panel, bg=CARD_BG)
        top_f.pack(fill=tk.X, pady=(0, 10))

        tk.Button(top_f, text="Select Target File", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT, padx=15, pady=5, cursor="hand2", command=self.do_select_integrity_file).pack(side=tk.LEFT)
        self.lbl_int_fname = tk.Label(top_f, text="File Name: None Selected", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=CARD_BG)
        self.lbl_int_fname.pack(side=tk.LEFT, padx=15)

        # Hash & Signature Display Box
        disp_box = tk.Frame(panel, bg="#334155", padx=10, pady=10)
        disp_box.pack(fill=tk.X, pady=(0, 10))

        tk.Label(disp_box, text="SHA-256 Hash:", font=("Segoe UI", 9, "bold"), fg=TEXT_MUTED, bg="#334155").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        self.lbl_hash_val = tk.Label(disp_box, text="N/A", font=("Consolas", 9), fg=ACCENT_BLUE, bg="#334155")
        self.lbl_hash_val.grid(row=0, column=1, sticky="w", padx=5, pady=3)

        tk.Label(disp_box, text="Hash Length:", font=("Segoe UI", 9, "bold"), fg=TEXT_MUTED, bg="#334155").grid(row=1, column=0, sticky="e", padx=5, pady=3)
        self.lbl_hash_len = tk.Label(disp_box, text="N/A", font=("Segoe UI", 9), fg=TEXT_LIGHT, bg="#334155")
        self.lbl_hash_len.grid(row=1, column=1, sticky="w", padx=5, pady=3)

        tk.Label(disp_box, text="PQC Signature:", font=("Segoe UI", 9, "bold"), fg=TEXT_MUTED, bg="#334155").grid(row=2, column=0, sticky="e", padx=5, pady=3)
        self.lbl_sig_val = tk.Label(disp_box, text="N/A", font=("Consolas", 8), fg=TEXT_LIGHT, bg="#334155")
        self.lbl_sig_val.grid(row=2, column=1, sticky="w", padx=5, pady=3)

        # Status Banner
        self.lbl_integrity_banner = tk.Label(panel, text="Integrity Status: Awaiting Hash Generation", font=("Segoe UI", 11, "bold"), fg=TEXT_MUTED, bg="#1e293b", pady=8)
        self.lbl_integrity_banner.pack(fill=tk.X, pady=5)

        # Buttons
        btn_box = tk.Frame(self.content_area, bg=THEME_BG)
        btn_box.pack(fill=tk.X, pady=10)

        tk.Button(btn_box, text="Generate Hash", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT, padx=12, pady=7, cursor="hand2", command=self.do_gen_hash).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_box, text="Verify Integrity", font=("Segoe UI", 10, "bold"), bg="#059669", fg=TEXT_LIGHT, padx=12, pady=7, cursor="hand2", command=self.do_verify_integrity).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_box, text="Sign File (PQC)", font=("Segoe UI", 10, "bold"), bg="#7c3aed", fg=TEXT_LIGHT, padx=12, pady=7, cursor="hand2", command=self.do_sign_file).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_box, text="Verify Signature", font=("Segoe UI", 10, "bold"), bg="#2563eb", fg=TEXT_LIGHT, padx=12, pady=7, cursor="hand2", command=self.do_verify_signature).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_box, text="Simulate File Tampering Demo", font=("Segoe UI", 10, "bold"), bg="#dc2626", fg=TEXT_LIGHT, padx=12, pady=7, cursor="hand2", command=self.do_tamper_demo).pack(side=tk.LEFT, padx=4)

    def do_select_integrity_file(self):
        fp = filedialog.askopenfilename()
        if fp:
            self.integrity_file_path = fp
            fn = os.path.basename(fp)
            self.lbl_int_fname.config(text=f"File Name: {fn}")
            self.lbl_hash_val.config(text="N/A")
            self.lbl_hash_len.config(text="N/A")
            self.lbl_sig_val.config(text="N/A")
            self.lbl_integrity_banner.config(text="Integrity Status: Awaiting Hash Generation", fg=TEXT_MUTED)

    def do_gen_hash(self):
        if not self.integrity_file_path:
            messagebox.showwarning("Warning", "Select a file first.")
            return
        success, msg, h_hex, h_bits = generate_file_hash(self.integrity_file_path, self.current_user["username"])
        if success:
            self.reference_hash = h_hex
            self.lbl_hash_val.config(text=h_hex)
            self.lbl_hash_len.config(text=f"{len(h_hex)} Hex Characters ({h_bits} bits)")
            self.lbl_integrity_banner.config(text="Integrity Status: SHA-256 Hash Generated", fg=ACCENT_BLUE)
            messagebox.showinfo("Hash Generated", msg)

    def do_verify_integrity(self):
        if not self.integrity_file_path or not self.reference_hash:
            messagebox.showwarning("Warning", "Please generate a hash for the file first.")
            return
        success, msg, banner_text = verify_file_integrity(self.integrity_file_path, self.reference_hash, self.current_user["username"])
        if success:
            self.lbl_integrity_banner.config(text=f"Integrity Status: {banner_text}", fg=ACCENT_GREEN)
            messagebox.showinfo("Integrity Check Passed", msg)
        else:
            self.lbl_integrity_banner.config(text=f"Integrity Status: {banner_text}", fg=ACCENT_RED)
            messagebox.showerror("Integrity Check Failed", msg)

    def do_sign_file(self):
        if not self.integrity_file_path:
            messagebox.showwarning("Warning", "Select a file first.")
            return
        success, msg, sig_b64 = sign_file(self.integrity_file_path, self.current_user["username"])
        if success:
            self.current_signature = sig_b64
            self.lbl_sig_val.config(text=sig_b64[:45] + "...")
            messagebox.showinfo("Digital Signature Created", msg)

    def do_verify_signature(self):
        if not self.integrity_file_path or not self.current_signature:
            messagebox.showwarning("Warning", "Please sign the file first.")
            return
        success, msg, banner_text = verify_digital_signature(self.integrity_file_path, self.current_signature, self.current_user["username"])
        if success:
            messagebox.showinfo("Signature Verified", msg)
        else:
            messagebox.showerror("Signature Invalid", msg)

    def do_tamper_demo(self):
        if not self.integrity_file_path or not self.reference_hash:
            messagebox.showwarning("Warning", "Generate SHA-256 hash on original file first.")
            return
        tampered_path, msg = create_tampered_file_copy(self.integrity_file_path)
        if tampered_path:
            self.integrity_file_path = tampered_path
            fn = os.path.basename(tampered_path)
            self.lbl_int_fname.config(text=f"File Name: {fn} (TAMPERED COPY)")
            current_h, _ = calculate_sha256(tampered_path)
            self.lbl_hash_val.config(text=current_h)

            success, ver_msg, banner_text = verify_file_integrity(tampered_path, self.reference_hash, self.current_user["username"])
            self.lbl_integrity_banner.config(text=f"Integrity Status: {banner_text}", fg=ACCENT_RED)
            messagebox.showwarning("Tamper Demo Triggered", f"Created tampered copy at '{tampered_path}'.\n\n{ver_msg}")

    # =========================================================================
    # MODULE 6: ACCESS CONTROL VIEW
    # =========================================================================
    def view_access_control(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="Access Control & Secure File Management (RBAC)", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        # Admin Manage Permissions Box
        if self.current_user["role"] == "Admin":
            admin_card = tk.LabelFrame(self.content_area, text=" Grant File Access Permission (Admin Only) ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=15, pady=10)
            admin_card.pack(fill=tk.X, pady=(0, 15))

            f_grid = tk.Frame(admin_card, bg=CARD_BG)
            f_grid.pack(fill=tk.X)

            tk.Label(f_grid, text="File Name:", fg=TEXT_LIGHT, bg=CARD_BG).grid(row=0, column=0, padx=5, pady=5, sticky="e")
            e_fn = tk.Entry(f_grid, width=15, bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
            e_fn.grid(row=0, column=1, padx=5, pady=5)

            tk.Label(f_grid, text="Target User / Role:", fg=TEXT_LIGHT, bg=CARD_BG).grid(row=0, column=2, padx=5, pady=5, sticky="e")
            e_target = tk.Entry(f_grid, width=15, bg="#334155", fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT)
            e_target.insert(0, "User")
            e_target.grid(row=0, column=3, padx=5, pady=5)

            tk.Label(f_grid, text="Permission:", fg=TEXT_LIGHT, bg=CARD_BG).grid(row=0, column=4, padx=5, pady=5, sticky="e")
            perm_var = tk.StringVar(value="Read")
            ttk.Combobox(f_grid, textvariable=perm_var, values=["Read", "Write", "Download", "Delete"], width=10, state="readonly").grid(row=0, column=5, padx=5, pady=5)

            def do_add_perm():
                fn = e_fn.get().strip()
                tg = e_target.get().strip()
                pm = perm_var.get()
                success, msg = add_file_permission(fn, tg, pm, self.current_user["username"])
                if success:
                    messagebox.showinfo("Success", msg)
                    self.view_access_control()
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(f_grid, text="Grant Permission", bg=BUTTON_BG, fg=TEXT_LIGHT, command=do_add_perm).grid(row=0, column=6, padx=10, pady=5)

        # Permissions Matrix Table
        matrix_frame = tk.LabelFrame(self.content_area, text=" Active File Access Control List (ACL) ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=10, pady=10)
        matrix_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("ID", "File Name", "Owner", "Target User/Role", "Permission", "Granted By", "Status")
        tree = ttk.Treeview(matrix_frame, columns=cols, show="headings", height=10)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=130, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        sb = ttk.Scrollbar(matrix_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        perms = get_all_permissions()
        for p in perms:
            tree.insert("", tk.END, values=(p["id"], p["filename"], p["owner"], p["user_or_role"], p["permission"], p["granted_by"], p["status"]))

        if self.current_user["role"] == "Admin":
            def do_revoke_perm():
                sel = tree.selection()
                if not sel:
                    messagebox.showwarning("Warning", "Select a permission entry to revoke.")
                    return
                item = tree.item(sel[0])
                perm_id = item["values"][0]
                success, msg = remove_file_permission(perm_id, self.current_user["username"])
                if success:
                    messagebox.showinfo("Revoked", msg)
                    self.view_access_control()
                else:
                    messagebox.showerror("Error", msg)

            tk.Button(self.content_area, text="Revoke Selected Permission", font=("Segoe UI", 9, "bold"), bg="#dc2626", fg=TEXT_LIGHT, padx=10, pady=5, command=do_revoke_perm).pack(anchor="e", pady=10)

    # =========================================================================
    # MODULE 7: AUDIT MONITORING & SECURITY ANALYTICS VIEW
    # =========================================================================
    def view_audit_analytics(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="Audit Monitoring & Security Analytics", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        # Analytics Overview Cards
        analytics = get_security_analytics()
        cards = tk.Frame(self.content_area, bg=THEME_BG)
        cards.pack(fill=tk.X, pady=(0, 15))

        stats = [
            ("Successful Logins", analytics["successful_logins"], "#10b981"),
            ("Failed Logins", analytics["failed_logins"], "#ef4444"),
            ("Files Encrypted", analytics["files_encrypted"], "#38bdf8"),
            ("Files Transferred", analytics["files_transferred"], "#8b5cf6"),
            ("Integrity Failures", analytics["integrity_failures"], "#f59e0b"),
            ("Access Denied", analytics["access_denied_events"], "#dc2626")
        ]

        for i, (title, val, color) in enumerate(stats):
            c = tk.Frame(cards, bg=CARD_BG, padx=10, pady=10)
            c.grid(row=0, column=i, sticky="ew", padx=3)
            cards.columnconfigure(i, weight=1)
            tk.Label(c, text=str(val), font=("Segoe UI", 16, "bold"), fg=color, bg=CARD_BG).pack()
            tk.Label(c, text=title, font=("Segoe UI", 8, "bold"), fg=TEXT_MUTED, bg=CARD_BG).pack()

        # Audit Logs Table
        audit_frame = tk.LabelFrame(self.content_area, text=" Security Audit Trail ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=10, pady=10)
        audit_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("Date/Time", "User", "Action", "File Name", "Status")
        tree = ttk.Treeview(audit_frame, columns=cols, show="headings", height=10)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=150, anchor="center")
        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        sb = ttk.Scrollbar(audit_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        logs = get_audit_logs(limit=50)
        for log in logs:
            tree.insert("", tk.END, values=(log["timestamp"], log["user"], log["action"], log["file_name"], log["status"]))

    # =========================================================================
    # MODULE 8: REPORTING VIEW
    # =========================================================================
    def view_reports(self):
        self.clear_content_area()

        tk.Label(self.content_area, text="Security Reports & Export", font=("Segoe UI", 16, "bold"), fg=ACCENT_BLUE, bg=THEME_BG).pack(anchor="w", pady=(0, 10))

        # Top Button Bar
        btn_bar = tk.Frame(self.content_area, bg=THEME_BG)
        btn_bar.pack(fill=tk.X, pady=(0, 10))

        def do_generate_report():
            rpt = generate_security_report()
            report_text_area.config(state=tk.NORMAL)
            report_text_area.delete("1.0", tk.END)
            report_text_area.insert(tk.END, rpt)
            report_text_area.config(state=tk.DISABLED)

        def do_export_txt():
            fp = export_report_txt(self.current_user["username"])
            messagebox.showinfo("Report Exported", f"Security Report exported to TXT:\n{fp}")

        def do_export_csv():
            fp = export_report_csv(self.current_user["username"])
            messagebox.showinfo("Logs Exported", f"Audit Logs exported to CSV:\n{fp}")

        tk.Button(btn_bar, text="Generate Security Report", font=("Segoe UI", 10, "bold"), bg=BUTTON_BG, fg=TEXT_LIGHT, padx=15, pady=6, cursor="hand2", command=do_generate_report).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_bar, text="Export Report (.txt)", font=("Segoe UI", 10, "bold"), bg="#059669", fg=TEXT_LIGHT, padx=15, pady=6, cursor="hand2", command=do_export_txt).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_bar, text="Export Audit Logs (.csv)", font=("Segoe UI", 10, "bold"), bg="#7c3aed", fg=TEXT_LIGHT, padx=15, pady=6, cursor="hand2", command=do_export_csv).pack(side=tk.LEFT, padx=5)

        # Report Viewer Box
        box = tk.LabelFrame(self.content_area, text=" Report Preview ", font=("Segoe UI", 10, "bold"), fg=TEXT_LIGHT, bg=CARD_BG, padx=10, pady=10)
        box.pack(fill=tk.BOTH, expand=True)

        report_text_area = tk.Text(box, bg="#0f172a", fg=ACCENT_BLUE, font=("Consolas", 9), padx=10, pady=10)
        report_text_area.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        sb = ttk.Scrollbar(box, orient=tk.VERTICAL, command=report_text_area.yview)
        report_text_area.configure(yscroll=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Auto-generate initial preview
        do_generate_report()

if __name__ == "__main__":
    app = PQCApp()
    app.mainloop()
