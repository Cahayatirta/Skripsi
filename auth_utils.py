"""
auth_utils.py
-------------
Modular Authentication Helper for DCT Steganography Suite:
- User database persistence via SQLite (users.db).
- Password hashing with salted SHA-256 / PBKDF2.
- OTP generation with 5-minute expiration.
- Gmail SMTP dispatch with graceful fallback development mode.
- Pre-seeded default admin account (admin@gmail.com / admin).
"""

import hashlib
import os
import secrets
import smtplib
import sqlite3
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional, Tuple

_DEFAULT_DB_PATH = Path(__file__).parent / "users.db"
OTP_EXPIRY_SECONDS = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Database Management
# ---------------------------------------------------------------------------
def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return a connection to the SQLite user database."""
    path = Path(db_path) if db_path else _DEFAULT_DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize user table and pre-seed default admin account if absent."""
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

        # Check and pre-seed admin@gmail.com
        cur = conn.execute("SELECT email FROM users WHERE email = ?", ("admin@gmail.com",))
        if not cur.fetchone():
            admin_hash = hash_password("admin")
            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            conn.execute(
                """
                INSERT INTO users (email, password_hash, is_verified, created_at)
                VALUES (?, ?, 1, ?)
                """,
                ("admin@gmail.com", admin_hash, now_ts),
            )
            conn.commit()


# ---------------------------------------------------------------------------
# Cryptographic Password Hashing
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Generate a salted PBKDF2-HMAC-SHA256 password hash."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return f"{salt}${key.hex()}"


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against stored salted hash."""
    try:
        salt, expected_hex = stored_hash.split("$")
        computed_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )
        return secrets.compare_digest(computed_key.hex(), expected_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# OTP Generation & Email Dispatch
# ---------------------------------------------------------------------------
def generate_otp() -> Tuple[str, float]:
    """
    Generate a 6-digit random OTP and expiration timestamp (epoch).
    """
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    expires_at = time.time() + OTP_EXPIRY_SECONDS
    return code, expires_at


def is_otp_valid(entered_otp: str, expected_otp: str, expires_at: float) -> Tuple[bool, str]:
    """
    Check if entered OTP matches expected OTP and has not expired.
    """
    if not entered_otp or not expected_otp:
        return False, "Kode OTP tidak boleh kosong."
    if time.time() > expires_at:
        return False, "Kode OTP telah kadaluarsa (melebihi 5 menit)."
    if not secrets.compare_digest(str(entered_otp).strip(), str(expected_otp).strip()):
        return False, "Kode OTP salah atau tidak cocok."
    return True, "Kode OTP valid."


def send_otp_email(to_email: str, otp_code: str) -> Tuple[bool, str]:
    """
    Send OTP code to recipient's Gmail via SMTP.
    Falls back to development simulation mode if SMTP credentials are not set.
    """
    smtp_email = os.environ.get("SMTP_EMAIL", "").strip()
    smtp_password = os.environ.get("SMTP_APP_PASSWORD", "").strip()

    # Development fallback mode
    if not smtp_email or not smtp_password:
        dev_msg = f"[DEV MODE] SMTP belum dikonfigurasi. Kode OTP simulasi Anda: {otp_code}"
        print(f"\n{dev_msg}\n")
        return True, dev_msg

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Kode Verifikasi OTP DCT Stega: {otp_code}"
        msg["From"] = f"DCT Steganography Suite <{smtp_email}>"
        msg["To"] = to_email

        text_content = (
            f"Halo,\n\n"
            f"Kode verifikasi pendaftaran akun Anda adalah: {otp_code}\n"
            f"Kode ini berlaku selama 5 menit. Jangan berikan kode ini kepada siapapun.\n\n"
            f"Salam,\nTim DCT Steganography"
        )
        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
            <h2 style="color: #1e3a8a; text-align: center;">Verifikasi Akun DCT Steganography</h2>
            <p>Terima kasih telah mendaftar. Gunakan kode OTP 6-digit berikut untuk memverifikasi akun Anda:</p>
            <div style="text-align: center; margin: 25px 0;">
                <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #2563eb; background: #eff6ff; padding: 10px 20px; border-radius: 6px; border: 1px dashed #2563eb;">
                    {otp_code}
                </span>
            </div>
            <p style="color: #64748b; font-size: 13px;">Kode OTP ini berlaku selama <strong>5 menit</strong>. Jangan berikan kode ini kepada pihak manapun.</p>
        </div>
        """
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, to_email, msg.as_string())

        return True, "Kode OTP berhasil dikirimkan ke kotak masuk Gmail Anda."
    except Exception as exc:
        err = f"Gagal mengirim email OTP: {exc}"
        print(f"[auth_utils] {err}")
        return False, err


# ---------------------------------------------------------------------------
# User Registration and Authentication Flow
# ---------------------------------------------------------------------------
def register_user(
    email: str,
    password: str,
    db_path: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Validate and save a newly registered unverified user into database.
    """
    clean_email = (email or "").strip().lower()
    if not clean_email.endswith("@gmail.com") or len(clean_email) <= len("@gmail.com"):
        return False, "Format email tidak valid. Pendaftaran wajib menggunakan akun Gmail (@gmail.com)."
    if len(password) < 4:
        return False, "Password minimal 4 karakter."

    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cur = conn.execute("SELECT email, is_verified FROM users WHERE email = ?", (clean_email,))
        row = cur.fetchone()
        if row and row["is_verified"] == 1:
            return False, "Alamat Gmail ini sudah terdaftar dan terverifikasi. Silakan langsung login."

        pwd_hash = hash_password(password)
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if row:
            # Update password for previously unverified entry
            conn.execute(
                "UPDATE users SET password_hash = ?, is_verified = 0, created_at = ? WHERE email = ?",
                (pwd_hash, now_ts, clean_email),
            )
        else:
            conn.execute(
                "INSERT INTO users (email, password_hash, is_verified, created_at) VALUES (?, ?, 0, ?)",
                (clean_email, pwd_hash, now_ts),
            )
        conn.commit()

    return True, "Akun berhasil didaftarkan. Silakan masukkan kode OTP yang telah dikirim."


def mark_user_verified(email: str, db_path: Optional[str] = None) -> bool:
    """Set is_verified = 1 for user upon successful OTP entry."""
    clean_email = (email or "").strip().lower()
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        conn.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (clean_email,))
        conn.commit()
    return True


def authenticate_user(
    email: str,
    password: str,
    db_path: Optional[str] = None,
) -> Tuple[bool, str, bool]:
    """
    Authenticate user against SQLite database.
    Returns: (success: bool, message: str, is_admin: bool)
    """
    clean_email = (email or "").strip().lower()
    if not clean_email:
        return False, "Silakan masukkan email Anda.", False

    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT email, password_hash, is_verified FROM users WHERE email = ?",
            (clean_email,),
        )
        row = cur.fetchone()

        if not row:
            return False, "Akun tidak ditemukan. Silakan lakukan registrasi terlebih dahulu.", False

        if not verify_password(row["password_hash"], password):
            return False, "Password tidak sesuai.", False

        if row["is_verified"] == 0:
            return False, "Akun belum diverifikasi. Silakan masukkan kode OTP.", False

        is_admin = (clean_email == "admin@gmail.com")
        return True, "Login berhasil.", is_admin


def get_user_record(email: str, db_path: Optional[str] = None) -> Optional[dict]:
    """Fetch user record dict or None."""
    clean_email = (email or "").strip().lower()
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT email, is_verified, created_at FROM users WHERE email = ?",
            (clean_email,),
        )
        row = cur.fetchone()
        if row:
            return dict(row)
        return None

