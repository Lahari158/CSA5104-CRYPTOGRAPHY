# Post-Quantum Cryptography (PQC) File Transfer System

A clean, modern, and fully functional **Python Web Application** built with **Streamlit** for post-quantum cryptographic key management, secure file encryption, integrity verification, digital signatures, role-based access control (RBAC), security audit logging, and reporting.

---

## 1. Project Overview & Objectives

This web application demonstrates a **Post-Quantum Cryptography (PQC) File Transfer System** accessible directly through a web browser. The system showcases how modern cryptographic algorithms protect file confidentiality, data integrity, digital authenticity, and access management against quantum and classical threats.

---

## 2. Project Directory Structure

```text
Crypto/
├── app.py                      # Main Streamlit Web Interface & Page Navigation
├── database.py                 # SQLite Database Engine & Connection Helper
├── authentication.py           # User Registration, Login & PBKDF2 Password Hashing
├── pqc_keys.py                 # Post-Quantum Key Lifecycle (Dilithium / Kyber Parameters)
├── encryption.py               # File Encryption (Fernet/AES), Decryption & Transfer
├── integrity.py                # SHA-256 Hashing, PQC Digital Signatures & Tamper Demo
├── access_control.py           # Role-Based Access Control (RBAC: Admin vs User)
├── audit.py                    # Security Audit Event Logger & Analytics Engine
├── reports.py                  # Security Audit Report Generator & Export
├── requirements.txt            # Streamlit Community Cloud Dependencies
├── README.md                   # Public Deployment & Demonstration Walkthrough
└── .gitignore                  # Git Repository Exclusion Rules
```

---

## 3. Required Packages (`requirements.txt`)

- `streamlit`
- `cryptography`
- `pandas`

---

## 4. How to Run Locally

1. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   streamlit run app.py
   ```

3. Open your web browser at `http://localhost:8501`.

---

## 5. Public Web Deployment Steps (Streamlit Community Cloud)

Follow these steps to deploy your application so anyone can open it from a web browser without installing Python or software:

### Step 1: Push Code to GitHub
1. Create a public repository on [GitHub](https://github.com).
2. Push all project files (`app.py`, `database.py`, `authentication.py`, `encryption.py`, `integrity.py`, `pqc_keys.py`, `access_control.py`, `audit.py`, `reports.py`, `requirements.txt`, `README.md`, `.gitignore`) to the repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of PQC File Transfer System Streamlit Web App"
   git branch -M main
   git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/PQC_File_Transfer_System.git
   git push -u origin main
   ```

### Step 2: Deploy on Streamlit Community Cloud
1. Sign in to [Streamlit Community Cloud](https://share.streamlit.io/).
2. Click **"Create app"** / **"New app"**.
3. Select your GitHub repository (`PQC_File_Transfer_System`) and branch (`main`).
4. Set **Main file path** to `app.py`.
5. Click **"Deploy!"**.

### Step 3: Share the Public URL
Once deployed, Streamlit will provide a public link formatted as:
```text
https://<YOUR_APP_NAME>.streamlit.app
```
Share this URL with your project guide, faculty, reviewers, or peers. They can test all 5 modules directly in their web browser!

---

## 6. Pre-Seeded Administrator Account

- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `Admin`

---

## 7. Module-by-Module Demonstration Walkthrough (5-10 Minutes)

1. **User Registration & Login**:
   - Open the web application URL.
   - Click **Register New Account**, create a user `alice` with password `user123` and role `User`.
   - Switch to **User Login** and sign in as `alice`.

2. **Module 1: PQC Key Management**:
   - Navigate to **🔑 PQC Key Management** in the sidebar.
   - Click **Generate PQC Key** to generate a CRYSTALS-Dilithium5 / Kyber-1024 lattice key pair.
   - Expand **View Technical PQC Lattice Specifications** to inspect polynomial degree ($n=1024$), prime modulus ($q=8380417$), and public key PEM.

3. **Module 2: Secure File Encryption & Transfer**:
   - Navigate to **📁 Secure File Transfer**.
   - Upload any document or text file.
   - Click **Encrypt File** (displays **Encryption Successful ✓**).
   - Click **Download Encrypted File (.pqc)** to save the encrypted file locally.
   - Click **Send / Transfer File** (displays **Transfer Successful ✓**).
   - Test decryption by uploading the `.pqc` file under *Decryption Inspector* and clicking **Decrypt File**.

4. **Module 3: File Integrity Verification & Digital Authentication**:
   - Navigate to **🛡️ Integrity & Digital Authentication**.
   - Upload a file and click **Generate Hash** to compute the 256-bit SHA-256 hash.
   - Click **Verify Integrity** (returns **Integrity Verified ✓**).
   - Click **Sign File (PQC)** to create a Dilithium digital signature.
   - Click **Download Tampered File Copy (Demo)** to download a modified copy. Re-uploading this tampered file and clicking **Verify Integrity** displays **Integrity Check Failed ✗**.

5. **Module 4: Access Control (RBAC)**:
   - Navigate to **👥 Access Control**.
   - Review the Active Access Control List (ACL).
   - Log out, sign in as `admin` (`admin` / `admin123`), and assign or revoke file permissions (`Read`, `Write`, `Download`, `Delete`).

6. **Module 5: Audit Monitoring & Security Analytics**:
   - Navigate to **📊 Audit & Security Analytics**.
   - View real-time metric counters (Successful Logins, Failed Logins, Files Encrypted, Transferred, Failures, Denials) and the audit trail table.

7. **Reports & Export**:
   - Navigate to **📄 Reports**.
   - Click **Download Security Report (.txt)** and **Download Audit Logs (.csv)**.

---

## 8. Real Cryptography vs. Demonstration Simulations

| Component | Implementation Details | Classification |
| :--- | :--- | :--- |
| **User Password Protection** | PBKDF2-HMAC-SHA256 with 100,000 iterations & 16-byte random salt | **Actual Production Cryptography** |
| **Symmetric Encryption** | Fernet (AES-128-CBC + HMAC-SHA256 authenticated encryption) | **Actual Production Cryptography** |
| **Integrity & Hashing** | SHA-256 (256-bit cryptographic digest) | **Actual Production Cryptography** |
| **Post-Quantum Key Suite** | NIST Level 5 parameters (CRYSTALS-Dilithium5 / Kyber-1024 lattice parameter & public key structures) | **PQC Parameters Demonstration Suite** |
| **Digital Signatures** | Key-based SHA-512 + SHA-256 Dilithium-structured signature scheme | **PQC Digital Signature Demonstration** |
| **Network Transfer** | In-memory byte buffer transfer & local storage in `transferred_files/` | **Simulated Secure Transfer** |
